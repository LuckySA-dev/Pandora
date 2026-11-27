"""Devices: list with filters (NetBox filtersets), detail, CSV export, onboarding steps, event log."""
import csv
import io
import ipaddress
import json
from collections import Counter

from fastapi import APIRouter, Response
from fastapi.responses import JSONResponse

from .. import alerts, alloc, backbone, backup, compliance, hostkeys, monitor, ports, status, upgrade
from ..deliver import ios_errors

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
    "status": lambda d: status.ORDER.index(d["status"]) if d.get("status") in status.ORDER else 99,
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
        d["status"] = status.of(d, d["severity"], d["compliant"], last)
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
        try:  # telnet: the user ticked "this box has no SSH" (IOS without crypto); cleartext, their call
            return ctx.add_by_ssh(ip, creds, telnet=body.get("telnet") is True)
        except Exception as e:
            return JSONResponse({"error": f"could not log in to {ip}: {type(e).__name__}: {e}"[:400]}, 502)

    @r.get("/devices.csv")
    def devices_csv(q: str = "", state: str = ""):
        buf = io.StringIO()
        w = csv.DictWriter(buf, CSV_COLS, extrasaction="ignore")
        w.writeheader()
        # Excel / LibreOffice run a cell starting with = + - @ (or tab / CR) as a formula, and hostnames, models and
        # serials come from the devices themselves: such a cell gets a leading ' so it stays text (OWASP CSV injection)
        def cell(v):
            return "'" + v if isinstance(v, str) and v[:1] in ("=", "+", "-", "@", "\t", "\r") else v
        w.writerows({k: cell(v) for k, v in d.items()} for d in device_rows(ctx, q, state=state))
        return Response(buf.getvalue(), media_type="text/csv",
                        headers={"Content-Disposition": "attachment; filename=pandorabox-inventory.csv"})

    @r.get("/devices/{device_id}")
    def device(device_id: int):
        if err := missing(device_id):
            return err
        d = ctx.db.devices(device_id)[0]
        last = monitor.LAST.get(device_id, {})
        comp = compliance.get(ctx.db, device_id)
        d["status"] = status.of(d, alerts.worst(ctx.db).get(device_id), comp["compliant"] if comp else None, last)
        names = sorted({k[:-5] for k in last if k.endswith(":oper")}, key=ports.sort_key)
        kinds = ports.classify(names, d["pid"])
        guard = protected_ports(device_id)

        def port(i):
            errs = [last.get(f"{i}:{x}") for x in ("inerr", "outerr")]
            return {"name": i, "kind": kinds.get(i, "other"), "oper": last.get(f"{i}:oper"),
                    "admin": last.get(f"{i}:admin"), "speed": last.get(f"{i}:speed"), "alias": last.get(f"{i}:alias"),
                    "in": last.get(f"{i}:in"), "out": last.get(f"{i}:out"),
                    "in_bps": last.get(f"{i}:in_bps"), "out_bps": last.get(f"{i}:out_bps"),
                    "errors": sum(int(e) for e in errs if str(e).isdigit()) if any(errs) else None,
                    "protected": guard.get(alloc.normalize_if(i))}
        return {
            "device": d,
            "interfaces": [port(i) for i in names],
            "health": {"mem_pct": last.get("mem_pct"), "uptime": last.get("uptime"),
                       "env": [{"kind": k.split(":", 2)[1], "name": k.split(":", 2)[2], "state": v,
                                "value": last.get(f"temp:{k.split(':', 2)[2]}")}
                               for k, v in sorted(last.items()) if k.startswith("env:")]},
            "cpu": last.get("cpu5min"), "polled": last.get("_ts"),
            "problems": alerts.open_problems(ctx.db, device_id),
            "compliance": compliance.get(ctx.db, device_id),
            "backups": len(ctx.db.q("SELECT id FROM backups WHERE device_id=?", device_id)),
            "last_backup": (backup.latest(ctx.db, device_id) or {}).get("ts"),
            "access": {k: ctx.db.vars(device_id).get(k) for k in ("telnet", "cap_ssh", "upgrade")},
            "backbone": backbone.active(ctx, device_id),
            "behind": behind(device_id),
        }

    def behind(device_id):
        """The provisioning backbone port this box is plugged into, if a backbone saw it."""
        b = ctx.db.vars(device_id).get("behind")
        sw = b and ctx.db.device(b["switch"])
        return {**b, "switch_name": sw["hostname"] or f"#{sw['id']}"} if sw else None

    @r.get("/devices/{device_id}/backbone")
    def backbone_get(device_id: int, candidates: bool = False):
        """A backbone: who is on each provisioning port now. Another switch (or `candidates`): the free ports."""
        if err := missing(device_id):
            return err
        try:
            if backbone.active(ctx, device_id) and not candidates:
                return {"active": True, "ports": backbone.scan(ctx, device_id)}
            return {"active": False, "candidates": backbone.candidates(ctx, device_id)}
        except ValueError as e:
            return JSONResponse({"error": str(e)}, 400)
        except Exception as e:
            return JSONResponse({"error": f"{type(e).__name__}: {e}"[:400]}, 502)

    @r.post("/devices/{device_id}/backbone")
    def backbone_on(device_id: int, body: dict):
        """Make these free front-panel ports provisioning ports (VLAN 99, portfast, up): pushed and saved."""
        if err := missing(device_id):
            return err
        if body.get("confirm") is not True:
            return JSONResponse({"error": "confirm: true required"}, 400)
        try:
            return {"ok": True, "ports": backbone.enable(ctx, device_id, [str(p) for p in body.get("ports") or []])}
        except ValueError as e:
            return JSONResponse({"error": str(e)}, 400)
        except Exception as e:
            return JSONResponse({"error": f"{type(e).__name__}: {e}"[:400]}, 502)

    @r.post("/devices/{device_id}/backbone/stop")
    def backbone_off(device_id: int, body: dict):
        if err := missing(device_id):
            return err
        if body.get("confirm") is not True:
            return JSONResponse({"error": "confirm: true required: its provisioning ports go back to defaults"}, 400)
        try:
            return {"ok": True, "ports": backbone.disable(ctx, device_id)}
        except ValueError as e:
            return JSONResponse({"error": str(e)}, 400)
        except Exception as e:
            return JSONResponse({"error": f"{type(e).__name__}: {e}"[:400]}, 502)

    def protected_ports(device_id) -> dict[str, str]:
        """Ports PandoraBox reaches the box through: shutting one would cut it off. {normalized name: why}."""
        out = {alloc.normalize_if(r["port"]): "PandoraBox's management port"
               for r in ctx.db.q("SELECT port FROM reserved_ports WHERE device_id=?", device_id)}
        for row in ctx.db.q("SELECT lines FROM mgmt_config WHERE device_id=?", device_id):
            for ln in row["lines"].splitlines():
                if ln.startswith("interface ") and ports.parse(ln.split(None, 1)[1].split(".")[0]):
                    out.setdefault(alloc.normalize_if(ln.split(None, 1)[1].split(".")[0]), "a management network link")
        if seen := ctx.db.vars(device_id).get("seen_port"):
            out.setdefault(alloc.normalize_if(seen), "the port it reaches PandoraBox on")
        dev, last = ctx.db.device(device_id), monitor.LAST.get(device_id, {})
        if dev and (port := (last.get("_ipif") or {}).get(dev["ip"] or "")):  # the port holding the address in use
            out.setdefault(alloc.normalize_if(port), f"where its address {dev['ip']} lives, the one PandoraBox uses")
        return out

    @r.post("/devices/{device_id}/ports/admin")
    def port_admin(device_id: int, body: dict):
        """Shut a port or bring it back (`shutdown` / `no shutdown` over SSH, saved). Never a port PandoraBox needs
        to reach the box. An explicit yes, like every change pushed to a device."""
        if err := missing(device_id):
            return err
        if body.get("confirm") is not True:
            return JSONResponse({"error": "confirm: true required"}, 400)
        name, up = str(body.get("port") or "").strip(), body.get("up") is True
        if not ports.parse(name):
            return JSONResponse({"error": f"{name!r} is not a physical port"}, 400)
        if why := protected_ports(device_id).get(alloc.normalize_if(name)):
            return JSONResponse({"error": f"{name} is {why}: shutting it would cut PandoraBox off"}, 400)
        dev = ctx.db.device(device_id)
        try:
            out = ctx.ssh_config(dev, [f"interface {name}", " no shutdown" if up else " shutdown"])
        except Exception as e:
            return JSONResponse({"error": f"{type(e).__name__}: {e}"[:400]}, 502)
        if bad := ios_errors(out):
            return JSONResponse({"error": "; ".join(bad)}, 502)
        ctx.db.audit("user", "port:" + ("up" if up else "shut"), {"id": device_id, "port": name})
        return {"ok": True, "port": name, "up": up}

    @r.patch("/devices/{device_id}")
    def edit_device(device_id: int, body: dict):
        if err := missing(device_id):
            return err
        if body.get("path"):
            ctx.db.x("UPDATE devices SET path=? WHERE id=?", body["path"], device_id)
        if body.get("role"):
            ctx.set_role(device_id, body["role"])  # renames the box too while nothing was sent to it
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

    @r.post("/devices/{device_id}/reset")
    def reset(device_id: int, body: dict):
        """The box was wiped (or will be): onboard it again. Keeps its name and address unless release."""
        if err := missing(device_id):
            return err
        if not body.get("confirm"):
            return JSONResponse({"error": "confirm required"}, 400)
        dev = ctx.factory_again(ctx.db.device(device_id), "user: reset to factory", release=bool(body.get("release")))
        ctx.emit("device", dev)
        return dev

    @r.post("/devices/{device_id}/remove")
    def remove(device_id: int, body: dict):
        """Forget the device completely (replaced, a duplicate row). Nothing is sent to it."""
        if err := missing(device_id):
            return err
        if not body.get("confirm"):
            return JSONResponse({"error": "confirm required"}, 400)
        try:
            ctx.remove(device_id)
        except ValueError as e:
            return JSONResponse({"error": str(e)}, 409)
        ctx.emit("device", {"id": device_id, "removed": True})
        return {"ok": True}

    @r.post("/devices/{device_id}/telnet")
    def telnet(device_id: int, body: dict):
        """Allow (or stop) Telnet for this one box: cleartext logins, for an image without crypto on the isolated
        provisioning segment, until it is upgraded to a K9 image. An explicit yes, like remediate."""
        if err := missing(device_id):
            return err
        if body.get("confirm") is not True:
            return JSONResponse({"error": "confirm: true required"}, 400)
        if body.get("allow") is True:
            if why := ctx.enable_telnet(device_id):  # logs in over Telnet and checks the image first
                return JSONResponse({"error": why}, 400)
        else:
            ctx.allow_telnet(device_id, False, "user")
        return {"ok": True, "telnet": body.get("allow") is True}

    @r.get("/images")
    def images():
        return {"folder": str(upgrade.FOLDER.resolve()), "images": upgrade.images()}

    @r.post("/devices/{device_id}/upgrade")
    def upgrade_image(device_id: int, body: dict):
        """Copy a K9 image, check it, boot it and RELOAD the box, then SSH on and Telnet off (upgrade.py)."""
        if err := missing(device_id):
            return err
        if body.get("confirm") is not True:
            return JSONResponse({"error": "confirm: true required: the box reloads"}, 400)
        ctx.db.audit("user", "upgrade:start", {"id": device_id, "image": body.get("image")})
        if why := upgrade.start(ctx, device_id, str(body.get("image") or "")):
            return JSONResponse({"error": why}, 400)
        return {"ok": True}

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
