"""Config backup with history and diff (Oxidized, with SQLite instead of git).

A new version is stored only when the cleaned config actually changed (sha256), so the history
is a list of real changes, not of fetches.
"""
import difflib
import hashlib
import time

from . import platforms
from .db import mask_secrets


def fetch(ctx, device_id) -> dict:
    d = ctx.db.device(device_id)
    if not d or not d["ip"]:
        raise ValueError("device has no IP yet")
    p = platforms.get(d["os_type"])
    text = mask_secrets(platforms.clean(d["os_type"], ctx.ssh_command(d, p["backup"])))
    sha = hashlib.sha256(text.encode()).hexdigest()
    last = latest(ctx.db, device_id)
    if last and last["sha"] == sha:
        ctx.db.x("UPDATE backups SET checked=? WHERE id=?", time.time(), last["id"])
        return {"changed": False, "id": last["id"], "sha": sha}
    cur = ctx.db.x("INSERT INTO backups (device_id, ts, checked, sha, text) VALUES (?,?,?,?,?)",
                   device_id, time.time(), time.time(), sha, text)
    ctx.db.audit("backup", "config:changed" if last else "config:first", {"device": device_id, "sha": sha[:12]})
    ctx.emit("backup", {"device_id": device_id, "id": cur.lastrowid, "changed": True})
    return {"changed": True, "id": cur.lastrowid, "sha": sha}


def latest(db, device_id):
    rows = db.q("SELECT * FROM backups WHERE device_id=? ORDER BY id DESC LIMIT 1", device_id)
    return rows[0] if rows else None


def history(db, device_id):
    rows = db.q("SELECT id, ts, checked, sha, text FROM backups WHERE device_id=? ORDER BY id DESC", device_id)
    for older, newer in zip(rows[1:], rows[:-1], strict=True):  # each version vs the one before it
        newer["added"], newer["removed"] = _counts(older["text"], newer["text"])
    for r in rows:
        r["lines"] = r.pop("text").count("\n")
        r.setdefault("added", r["lines"])
        r.setdefault("removed", 0)
    return rows


def get(db, backup_id):
    rows = db.q("SELECT * FROM backups WHERE id=?", backup_id)
    return rows[0] if rows else None


def diff(db, old_id, new_id) -> str:
    a, b = get(db, old_id), get(db, new_id)
    if not a or not b or a["device_id"] != b["device_id"]:
        raise ValueError("pick two backups of the same device")
    return "\n".join(difflib.unified_diff(a["text"].splitlines(), b["text"].splitlines(),
                                          f"#{old_id}", f"#{new_id}", lineterm="", n=2))


def _counts(old, new):
    added = removed = 0
    for l in difflib.ndiff(old.splitlines(), new.splitlines()):
        added += l.startswith("+ ")
        removed += l.startswith("- ")
    return added, removed
