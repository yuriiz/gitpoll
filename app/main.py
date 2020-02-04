import os
from sys import argv

import aiohttp_jinja2
import aiohttp_session
import aioredis
import jinja2
from aiohttp import web
from aiohttp_session.cookie_storage import EncryptedCookieStorage
from cryptography import fernet
from decouple import UndefinedValueError, config

from . import views


async def init(app):
    try:
        app["config"] = dict(
            SECRET_KEY=config("SECRET_KEY"),
            GITHUB_CLIENT_ID=config('GITHUB_CLIENT_ID'),
            GITHUB_CLIENT_SECRET=config('GITHUB_CLIENT_SECRET'),
            REDIS_URL=config("REDIS_URL", "redis://localhost"),
        )
    except UndefinedValueError:
        print("Random SECRET_KEY is required. For example:",
              fernet.Fernet.generate_key())
        raise
    app["redis"] = await aioredis.create_redis_pool(app["config"]["REDIS_URL"])
    aiohttp_session.setup(app,
                          EncryptedCookieStorage(app["config"]["SECRET_KEY"]))


async def close(app):
    app["redis"].close()
    await app["redis"].wait_closed()


app = web.Application()
app.router.add_routes(views.routes)
app.on_startup.append(init)
app.on_cleanup.append(close)
aiohttp_jinja2.setup(app, loader=jinja2.PackageLoader("app", "templates"))

if __name__ == "__main__":
    if '--genkey' in argv:
        print(fernet.Fernet.generate_key())
    else:
        web.run_app(app, port=os.getenv("PORT"))
