import asyncio
import hmac
from json import loads
from urllib.parse import parse_qs, urlencode

import aiohttp
import aiohttp_jinja2
from aiohttp import web
from aiohttp_session import get_session

routes = web.RouteTableDef()


def sign(key, msg):
    return hmac.new(key.encode("ascii"),
                    msg=msg.encode("ascii"),
                    digestmod="sha1").hexdigest()


@routes.view("/")
@aiohttp_jinja2.template("base.html")
async def index(request):
    session = await get_session(request)
    access_token = session.get("access_token")
    if access_token:
        post = await request.post()
        async with aiohttp.ClientSession() as session:
            async with session.get(
                    "https://api.github.com/user/repos",
                    headers=dict(Authorization="token " + access_token[0]),
            ) as response:
                repos = await response.json()
                repo = post.get("repo")
                if repo:
                    for r in repos:
                        if repo == r['full_name']:
                            id = sign(request.app["config"]["SECRET_KEY"],
                                      msg=repo)
                            url = (request.scheme + "://" + request.host +
                                   "/hook")
                            async with session.post(
                                    "https://api.github.com/repos/{0}/hooks".
                                    format(repo),
                                    headers=dict(Authorization="token " +
                                                 access_token[0]),
                                    json=dict(config=dict(
                                        url=url,
                                        secret=id,
                                        content_type='json',
                                    )),
                            ) as resp:
                                json = loads(await resp.text())
                                if json.get('active'):
                                    raise web.HTTPFound(
                                        "/instructions?" +
                                        urlencode(dict(repo=repo)))
                                return dict(repos=repos, error=json)
                    raise web.HTTPForbidden(
                        text='This repository does not belong to you.')
                return dict(repos=repos)
    return dict(auth="https://github.com/login/oauth/authorize?" + urlencode(
        dict(client_id=request.app['config']['GITHUB_CLIENT_ID'],
             scope='repo admin:repo_hook')))


@routes.view("/auth")
async def auth(request):
    code = request.query.get("code")
    if code:
        payload = dict(
            code=code,
            client_id=request.app['config']['GITHUB_CLIENT_ID'],
            client_secret=request.app['config']['GITHUB_CLIENT_SECRET'])
        async with aiohttp.ClientSession() as session:
            async with session.post(
                    "https://github.com/login/oauth/access_token",
                    data=payload) as resp:
                session = await get_session(request)
                text = await resp.text()
                session["access_token"] = parse_qs(text)["access_token"]
                return web.HTTPFound("/")
    return web.Response(text="Authentication code missing.")


@routes.view("/logout")
async def logout(request):
    session = await get_session(request)
    del session["access_token"]
    return web.HTTPFound("/")


@routes.view("/instructions")
@aiohttp_jinja2.template("instructions.html")
async def instructions(request):
    # make sure user owns this repo
    repo = request.query.get("repo")
    session = await get_session(request)
    access_token = session.get("access_token")
    if access_token:
        async with aiohttp.ClientSession() as session:
            async with session.get(
                    "https://api.github.com/user/repos",
                    headers=dict(Authorization="token " + access_token[0]),
            ) as response:
                repos = await response.json()
                for r in repos:
                    if repo == r['full_name']:
                        return dict(
                            repo=repo,
                            poll=request.url.with_path('/poll/%s/%s/' % (
                                sign(request.app["config"]["SECRET_KEY"],
                                     msg=repo),
                                repo,
                            )))
    raise web.HTTPForbidden(text='This repository does not belong to you.')


@routes.view("/hook")
async def hook(request):
    redis = request.app["redis"]
    post = await request.read()
    json = loads(post)
    repo = json['repository']['full_name']
    secret = sign(request.app["config"]["SECRET_KEY"], msg=repo)
    signature = request.headers.get('X-Hub-Signature')
    if not signature:
        raise web.HTTPForbidden(text='Signature missing.')
    if signature != 'sha1=' + hmac.new(
            secret.encode('ascii'), msg=post, digestmod="sha1").hexdigest():
        raise web.HTTPForbidden(text='Signature does not match')
    await redis.publish("hook:" + json['repository']['full_name'], post)
    return web.Response(text="OK")


@routes.view("/poll/{id}/{owner}/{repo}/")
async def poll(request):
    id = request.match_info.get('id')
    owner = request.match_info.get('owner')
    repo = request.match_info.get('repo')
    if not hmac.compare_digest(
            id,
            sign(request.app["config"]["SECRET_KEY"], msg=owner + '/' + repo)):
        return web.HTTPNotFound()
    response = web.StreamResponse(headers={
        'Content-Type': 'application/json',
    })
    response.enable_chunked_encoding()
    await response.prepare(request)
    await response.write(b"")
    redis = request.app["redis"]
    channel, = await redis.subscribe("hook:%s/" % owner + repo)
    get = asyncio.ensure_future(channel.get())
    # has to write something at least every 55 seconds to avoid request timeout
    # https://devcenter.heroku.com/articles/request-timeout#long-polling-and-streaming-responses
    while True:
        done, pending = await asyncio.wait({asyncio.sleep(50), get},
                                           return_when=asyncio.FIRST_COMPLETED)
        if get in done:
            await response.write(get.result())
            break
        await response.write(b"\r")
    return response
