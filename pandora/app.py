"""FastAPI composition: security middleware, background jobs, live events, routers.

Operator UI/API is localhost-only; devices may only reach the PnP/ZTP/config endpoints, from the
provisioning subnet. Domain routes live in `pandora.api.*`, background work in `pandora.monitor`.
"""
import asyncio
import contextlib
import ipaddress
import json
import logging
from pathlib import Path

from fastapi import FastAPI, Request, WebSocket, WebSocketDisconnect
from fastapi.responses import FileResponse, JSONResponse
from fastapi.staticfiles import StaticFiles

from . import alerts, monitor, snmp
from .api import LOCAL, routers, ui_ok
from .net import pnp

log = logging.getLogger("pandora.app")
WEB = Path(__file__).parent / "web"
DEVICE_PATHS = ("/pnp/", "/ztp/", "/cfg/")


def create_app(ctx, background=True) -> FastAPI:
    clients: set[asyncio.Queue] = set()
    subnet = ipaddress.ip_network(f"{ctx.cfg['server_ip']}/{ctx.cfg['netmask']}", strict=False)
    state = {"loop": None}

    @contextlib.asynccontextmanager
    async def lifespan(_app):
        state["loop"] = asyncio.get_running_loop()
        tasks = []
        if background and all(len(ctx.cfg.get(k) or "") >= 8 for k in ("snmp_auth", "snmp_priv")):
            try:
                snmp.start_receiver(ctx.cfg, lambda src, name, vbs: monitor.on_trap(ctx, src, name, vbs))
            except Exception as e:
                log.warning("SNMP inform receiver not started: %s", e)
            tasks += [asyncio.create_task(monitor.poll_forever(ctx)), asyncio.create_task(monitor.backup_forever(ctx))]
        yield
        for t in tasks:
            t.cancel()

    app = FastAPI(title="PandoraBox", lifespan=lifespan)
    from . import api as api_pkg
    api_pkg.EXTRA_UI_NETS[:] = [ipaddress.ip_network(n, strict=False) for n in ctx.cfg.get("ui_allow", [])]

    def emit(kind, data):
        if kind == "device":  # provisioning state changes feed the problem list
            alerts.on_device(ctx, data)
        lp = state["loop"]
        if lp:
            msg = json.dumps({"type": kind, "data": data}, default=str)
            for q in list(clients):
                lp.call_soon_threadsafe(q.put_nowait, msg)

    ctx.emit = emit

    @app.middleware("http")
    async def who_may_call(request: Request, call_next):
        host = request.client.host if request.client else ""
        if request.url.path.startswith(DEVICE_PATHS):
            ok = host in LOCAL or _in(host, subnet)
        else:
            ok = ui_ok(host, request.headers)
        if not ok:
            return JSONResponse({"error": "forbidden"}, 403)
        response = await call_next(request)
        if request.url.path == "/" or request.url.path.startswith("/web/"):
            response.headers["Cache-Control"] = "no-cache"  # revalidate: no stale UI after an upgrade
        return response

    app.include_router(pnp.router(ctx))
    for r in routers(ctx):
        app.include_router(r)
    app.mount("/web", StaticFiles(directory=WEB), name="web")

    @app.get("/")
    def index():
        return FileResponse(WEB / "index.html")

    @app.websocket("/ws")
    async def events(ws: WebSocket):
        if not ui_ok(ws.client.host, ws.headers):
            return await ws.close()
        await ws.accept()
        q = asyncio.Queue()
        clients.add(q)

        async def until_closed():  # the browser sends nothing: without this a closed page (or a shutting-down
            with contextlib.suppress(WebSocketDisconnect, RuntimeError):  # server) went unnoticed and Ctrl+C
                while True:  # waited on it forever, leaving the old copy holding ports 69/162
                    await ws.receive_text()
            q.put_nowait(None)

        closed = asyncio.create_task(until_closed())
        try:
            while (msg := await q.get()) is not None:
                await ws.send_text(msg)
        except (WebSocketDisconnect, RuntimeError):
            pass
        finally:
            closed.cancel()
            clients.discard(q)

    return app


def _in(host, net):
    try:
        return ipaddress.ip_address(host) in net
    except ValueError:
        return False
