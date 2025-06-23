import click
import uvicorn
from prometheus_client import make_asgi_app
from starlette.applications import Starlette
from starlette.requests import Request
from starlette.responses import JSONResponse
from starlette.routing import Mount, Route


@click.pass_context
def create_http_server(ctx: click.Context) -> uvicorn.Server:
    """
    Simple webserver to expose metrics and a status check.
    """
    config = ctx.obj.config
    prometheus_app = make_asgi_app()
    routes = [
        Route("/", endpoint=status),
        Mount(config.daemon.metrics.mount, app=prometheus_app),
    ]
    app = Starlette(routes=routes)
    # make the context available to the app
    app.state.ctx_obj = ctx.obj
    server_config = uvicorn.Config(
        app,
        host=str(config.daemon.http.host),
        port=config.daemon.http.port,
        log_level=ctx.obj.log_level.name,
        server_header=False,
        headers=[
            ("server", config.daemon.http.server_name),
        ],
        log_config={
            "version": 1,
            "disable_existing_loggers": False,
        },
        ssl_keyfile=config.daemon.http.ssl_key_file,
        ssl_keyfile_password=config.daemon.http.ssl_key_password,
        ssl_certfile=config.daemon.http.ssl_cert_file,
        ssl_ca_certs=config.daemon.http.ssl_ca_certs_file,
    )
    return uvicorn.Server(server_config)


async def status(request: Request) -> JSONResponse:
    """
    Quick status check that returns if the daemon threads are running.
    """
    return JSONResponse(
        {
            thread.name: thread.is_alive()
            for thread in request.app.state.ctx_obj.daemon.threads
        }
    )
