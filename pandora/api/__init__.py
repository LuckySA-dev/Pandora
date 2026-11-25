"""HTTP API, one router per domain (NetBox's "one app per domain" layout):

    inventory   devices, filters, CSV export, onboarding (preview / provision / credentials), events
    configs     pushes history, extra config, backups + diff, compliance + remediation
    monitoring  SNMP sweep / poll / samples, traps, problems, dashboard, topology
    agent       AI agent runs and approvals
    terminal    web terminal websocket (SSH / console)
"""
from urllib.parse import urlsplit

LOCAL = {"127.0.0.1", "::1", "localhost", "testclient"}
UI_HOSTS = {"127.0.0.1", "localhost", "::1", "testserver"}  # testserver = FastAPI TestClient


EXTRA_UI_NETS: list = []  # cfg "ui_allow": e.g. the Docker gateway when PandoraBox runs in a container


def ui_ok(client_host, headers) -> bool:
    """Operator UI/API: client on this laptop, AND a localhost Host header (blocks DNS rebinding),
    AND a localhost Origin when a browser sends one (blocks cross-site requests / WebSocket hijacking)."""
    import ipaddress
    if client_host not in LOCAL:
        try:
            if not any(ipaddress.ip_address(client_host) in n for n in EXTRA_UI_NETS):
                return False
        except ValueError:
            return False
    if urlsplit("//" + headers.get("host", "")).hostname not in UI_HOSTS:
        return False
    origin = headers.get("origin")
    return origin is None or urlsplit(origin).hostname in UI_HOSTS


def routers(ctx):
    from . import agent, configs, inventory, monitoring, terminal
    return [m.router(ctx) for m in (inventory, configs, monitoring, agent, terminal)]
