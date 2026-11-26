"""SSH host keys, trust on first use: the first key a device shows is pinned to that device (not its address,
so the management design moving it to a new IP keeps the pin). A different key later is refused before the
password is sent, and opens a problem. A box PandoraBox itself re-provisions from factory (it generates a new
RSA key) forgets its pin first; a replaced box is forgotten by the user (`POST /api/devices/{id}/forget-host-key`).
"""
import time

import paramiko

from . import alerts

PROBLEM = "ssh-host-key"
# What classic IOS 12.x/15.x SSH offers (real 2960X 15.2(2)E7): nothing newer. paramiko 5 dropped all of these.
LEGACY_KEX = ("diffie-hellman-group14-sha1", "diffie-hellman-group-exchange-sha1", "diffie-hellman-group1-sha1")


def legacy_ssh_missing() -> list[str]:
    """Algorithms classic IOS needs that this paramiko can't do (empty = fine)."""
    t = paramiko.Transport
    return [k for k in LEGACY_KEX if k not in t._preferred_kex] + \
        ([] if "ssh-rsa" in t._preferred_keys else ["ssh-rsa host keys"])


class HostKeyChanged(paramiko.SSHException):
    pass


def text(key) -> str:
    return f"{key.get_name()} {key.get_base64()}"


def pinned(db, device_id) -> str | None:
    rows = db.q("SELECT key FROM host_keys WHERE device_id=?", device_id)
    return rows[0]["key"] if rows else None


def remember(db, device_id, key_text):
    db.x("INSERT OR IGNORE INTO host_keys (device_id, key, ts) VALUES (?,?,?)", device_id, key_text, time.time())


def forget(ctx, device_id, why, resolve=True):
    """resolve: only the user's explicit "Trust new key" closes an open key-changed problem."""
    if ctx.db.x("DELETE FROM host_keys WHERE device_id=?", device_id).rowcount:
        ctx.db.audit("system", "host_key:forget", {"id": device_id, "why": why})
    if resolve:
        alerts.resolve(ctx, device_id, PROBLEM)


def mismatch(ctx, device_id, where, detail=""):
    msg = (f"SSH host key of {where} changed{detail}: refused. If the box was replaced or reset, "
           "forget its key on the device page.")
    alerts.raise_(ctx, device_id, PROBLEM, "high", msg)
    return msg


class Pin(paramiko.MissingHostKeyPolicy):
    """paramiko asks this for every connection (no known_hosts is loaded), after key exchange, before auth."""

    def __init__(self, ctx, device_id):
        self.ctx, self.device_id, self.seen = ctx, device_id, None

    def missing_host_key(self, client, hostname, key):
        self.seen = text(key)
        if self.device_id is None:
            return  # a device not in the inventory yet: the caller pins it once it has an id
        want = pinned(self.ctx.db, self.device_id)
        if want is None:
            remember(self.ctx.db, self.device_id, self.seen)
            self.ctx.db.audit("system", "host_key:pin", {"id": self.device_id, "ip": hostname})
        elif want != self.seen:
            raise HostKeyChanged(mismatch(self.ctx, self.device_id, hostname,
                                          f" ({key.get_name()} {key.get_fingerprint().hex(':')})"))
