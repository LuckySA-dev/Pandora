"""SSH host keys, trust on first use: the first key a device shows is pinned to that device (not its address,
so the management design moving it to a new IP keeps the pin). A different key later is refused before the
password is sent, and opens a problem. A box PandoraBox itself re-provisions from factory (it generates a new
RSA key) forgets its pin first; a replaced box is forgotten by the user (`POST /api/devices/{id}/forget-host-key`).
"""
import time

import paramiko

from . import alerts

PROBLEM = "ssh-host-key"


class HostKeyChanged(paramiko.SSHException):
    pass


def text(key) -> str:
    return f"{key.get_name()} {key.get_base64()}"


def pinned(db, device_id) -> str | None:
    rows = db.q("SELECT key FROM host_keys WHERE device_id=?", device_id)
    return rows[0]["key"] if rows else None


def remember(db, device_id, key_text):
    db.x("INSERT OR IGNORE INTO host_keys (device_id, key, ts) VALUES (?,?,?)", device_id, key_text, time.time())


def forget(ctx, device_id, why):
    if ctx.db.x("DELETE FROM host_keys WHERE device_id=?", device_id).rowcount:
        ctx.db.audit("system", "host_key:forget", {"id": device_id, "why": why})
    alerts.resolve(ctx, device_id, PROBLEM)


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
            msg = (f"SSH host key of {hostname} changed ({key.get_name()} {key.get_fingerprint().hex(':')}): "
                   "refused. If the box was replaced or reset, forget its key on the device page.")
            alerts.raise_(self.ctx, self.device_id, PROBLEM, "high", msg)
            raise HostKeyChanged(msg)
