"""Shared test fixtures: an in-memory PandoraBox context with secrets set, and a device helper."""
import pytest

from pandora import config
from pandora.db import DB
from pandora.deliver import Ctx


@pytest.fixture
def ctx():
    cfg = config.load("does-not-exist.toml")
    cfg.update(admin_password="Adm1nPass!", snmp_auth="AuthKey123", snmp_priv="PrivKey123",
               mgmt_range="10.99.0.10-10.99.0.40")
    c = Ctx(DB(), cfg)
    c.events = []
    c.emit = lambda kind, data: c.events.append((kind, data))
    return c


def add(ctx, n, pid="C9300-24P", **kw):
    return ctx.db.upsert(mac=f"00:00:00:00:00:{n:02x}", pid=pid, **kw)
