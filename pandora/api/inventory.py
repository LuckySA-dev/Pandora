"""Devices: list with filters (NetBox filtersets), detail, CSV export, onboarding steps, event log."""
import csv
import io
import ipaddress
import json
from collections import Counter

from fastapi import APIRouter, Response
from fastapi.responses import JSONResponse

from .. import alerts, alloc, backup, compliance, hostkeys, monitor

FILTERS = ("state", "path", "role", "source", "os_type")
SEARCH = ("hostname", "alloc_hostname", "serial", "pid", "ip", "mgmt_ip", "mac", "console_port", "version")
CSV_COLS = ("id", "state", "hostname", "alloc_hostname", "mgmt_ip", "ip", "serial", "pid", "os_type", "version",
            "path", "role", "source", "mac", "console_port", "reserved")


# Paging adapted from NetBox's EnhancedPaginator (Apache-2.0): fixed page-length choices, a requested size
# outside them is added to the list, and the size is clamped to a maximum.
PAGE_LENGTHS = (20, 50, 100, 250, 500)
DEFAULT_PER_PAGE, MAX_PER_PAGE = 20, 500
_SEV = {s: i for i, s in enumerate(alerts.SEVERITIES)}
_STATE = {s: i for i, s in enumerate(("failed", "needs_credentials", "provisioning", "queued", "identified",
                                       "discovered", "provisioned"))}


def _ip_key(v):
    try:
        return (0, int(ipaddress.ip_address(v)))
    except ValueError:
        return (1, 0)


SORTS = {
    "name": lambda d: (d.get("hostname") or d.get("alloc_hostname") or d.get("serial") or "~").lower(),
    "state": lambda d: _STATE.get(d["state"], 99),
    "severity": lambda d: -_SEV.get(d.get("severity") or "", -1),
    "pid": lambda d: (d.get("pid") or "~").lower(),
    "ip": lambda d: _ip_key(d.get("ip") or d.get("mgmt_ip") or ""),  # the address in use, as the Bench shows it
    "path": lambda d: d.get("path") or "~",
    "role": lambda d: d.get("role") or "~",
    "ports": lambda d: -(d.get("ports_up") or 0),
    "updated": lambda d: -(d.get("updated") or 0),
    "id": lambda d: d["id"],
}


def device_rows(ctx, q="", **filters):
    worst = alerts.worst(ctx.db)
    comp = {r["device_id"]: json.loads(r["result"])["compliant"] for r in ctx.db.q("SELECT * FROM compliance")}
    rows = []
    for d in ctx.db.devices():
        if any(v and str(d.get(k)) != v for k, v in filters.items()):
            continue
        if q and not any(q.lower() in str(d.get(k) or "").lower() for k in SEARCH):
            continue
        last = monitor.LAST.get(d["id"], {})
        d.update(severity=worst.get(d["id"]), compliant=comp.get(d["id"]), polled=last.get("_ts"),
                 ports_up=last.get("_up", 0), ports_total=last.get("_total", 0))
        rows.append(d)
    return rows


def paginate(rows, page: int, per_page: int) -> dict:
    per_page = min(max(per_page if per_page > 0 else DEFAULT_PER_PAGE, 1), MAX_PER_PAGE)
    pages = max(1, -(-len(rows) // per_page))
    page = min(max(page, 1), pages)
    lengths = sorted({*PAGE_LENGTHS, per_page})
    return {"items": rows[(page - 1) * per_page: page * per_page], "total": len(rows), "page": page,
            "per_page": per_page, "pages": pages, "page_lengths": lengths}


def router(ctx):
    r = APIRouter(prefix="/api")

    def missing(device_id):
        return None if ctx.db.device(device_id) else JSONResponse({"error": "no such device"}, 404)

    @r.get("/devices")
    def devices(q: str = "", state: str = "", path: str = "", role: str = "", source: str = "", os_type: str = "",
                sort: str = "", order: str = "asc", page: int | None = None, per_page: int = DEFAULT_PER_PAGE):
        """Without `page`: the full list (small callers). With `page`: one page + totals, for big benches."""
        base = device_rows(ctx, q, path=path, role=role, source=source, os_type=os_type)
        rows = [d for d in base if not state or d["state"] == state]
        if sort in SORTS:
            rows.sort(key=SORTS[sort], reverse=order == "desc")
        if page is None:
            return rows
        out = paginate(rows, page, per_page)
        out["states"] = dict(Counter(d["state"] for d in base))
        return out

    @r.post("/devices")
    def add_device(body: dict):
        """Add an existing device by IP + login (for boxes that run config but no SNMP)."""
        try:
            ip = str(ipaddress.ip_address((body.get("ip") or "").strip()))
        except ValueError:
            return JSONResponse({"error": "enter a valid IPv4 or IPv6 address"}, 400)
        if not body.get("username") or not body.get("password"):
            return JSONResponse({"error": "username and password required"}, 400)
        creds = {k: body.get(k) for k in ("username", "password", "secret")}
        try:
            return ctx.add_by_ssh(ip, creds)
        except Exception as e:
            return JSONResponse({"error": f"could not log in to {ip}: {type(e).__name__}: {e}"[:400]}, 502)

    @r.get("/devices.csv")
    def devices_csv(q: str = "", state: str = ""):
        buf = io.StringIO()
        w = csv.DictWriter(buf, CSV_COLS, extrasaction="ignore")
        w.writeheader()
        w.writerows(device_rows(ctx, q, state=state))
        return Response(buf.getvalue(), media_type="text/csv",
                        headers={"Content-Disposition": "attachment; filename=pandorabox-inventory.csv"})

    @r.get("/devices/{device_id}")
    def device(device_id: int):
        if err := missing(device_id):
            return err
        d = ctx.db.devices(device_id)[0]
        last = monitor.LAST.get(device_id, {})
        ifaces = sorted({k[:-5] for k in last if k.endswith(":oper")})
        return {
            "device": d,
            "interfaces": [{"name": i, "oper": last.get(f"{i}:oper"), "in": last.get(f"{i}:in"),
                            "out": last.get(f"{i}:out")} for i in ifaces],
            "cpu": last.get("cpu5min"), "polled": last.get("_ts"),
            "problems": alerts.open_problems(ctx.db, device_id),
            "compliance": compliance.get(ctx.db, device_id),
            "backups": len(ctx.db.q("SELECT id FROM backups WHERE device_id=?", device_id)),
            "last_backup": (backup.latest(ctx.db, device_id) or {}).get("ts"),
        }

    @r.patch("/devices/{device_id}")
    def edit_device(device_id: int, body: dict):
        if err := missing(device_id):
            return err
        for k in ("path", "role"):
            if body.get(k):
                ctx.db.x(f"UPDATE devices SET {k}=? WHERE id=?", body[k], device_id)
        if body.get("ports"):
            alloc.allocate(ctx.db, ctx.cfg, device_id, [p.strip() for p in body["ports"].split(",") if p.strip()])
        ctx.emit("device", ctx.db.device(device_id))
        return ctx.db.device(device_id)

    # ---- onboarding (Catalyst Center: select -> template -> review -> claim) ----------------
    @r.post("/preview")
    def preview(body: dict):
        ids = [i for i in body["ids"] if ctx.db.device(i)]
        return ctx.preview(ids, body.get("role"), body.get("ports"), body.get("vars"))

    @r.post("/provision")
    def provision(body: dict):
        return ctx.queue([i for i in body["ids"] if ctx.db.device(i)])

    @r.post("/devices/{device_id}/forget-host-key")
    def forget_host_key(device_id: int):
        """The user says the box was replaced or reset: the next SSH login pins whatever key it shows."""
        if err := missing(device_id):
            return err
        hostkeys.forget(ctx, device_id, "user: box replaced or reset")
        ctx.db.audit("user", "host_key:forget", {"id": device_id})
        return {"ok": True}

    @r.post("/devices/{device_id}/credentials")
    def credentials(device_id: int, body: dict):
        if err := missing(device_id):
            return err
        if not body.get("username") or not body.get("password"):
            return JSONResponse({"error": "username and password required"}, 400)
        ctx.set_credentials(device_id, {k: body.get(k) for k in ("username", "password", "secret")})
        return {"ok": True}

    @r.get("/events")
    def events(limit: int = 200, device_id: int | None = None):
        rows = ctx.db.q("SELECT * FROM audit ORDER BY ts DESC LIMIT ?", min(limit, 2000))
        if device_id is not None:
            rows = [e for e in rows if f'"id": {device_id}' in e["detail"] or f'"device": {device_id}' in e["detail"]]
        return rows

    return r
