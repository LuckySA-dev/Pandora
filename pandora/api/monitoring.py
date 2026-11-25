"""Monitoring: SNMP sweep/poll/samples, traps, problems (Zabbix), dashboard, topology (maps)."""
from fastapi import APIRouter
from fastapi.responses import JSONResponse

from .. import alerts, monitor, snmp, topology
from ..alloc import normalize_if


def router(ctx):
    r = APIRouter(prefix="/api")

    @r.post("/snmp/sweep")
    async def sweep(body: dict):
        a = snmp.auth(ctx.cfg, body.get("community") or None)
        found = await snmp.sweep(body["subnet"], a)
        rows = [ctx.db.upsert(**f) for f in found]
        for row in rows:
            if not row["path"]:
                ctx.db.x("UPDATE devices SET path='ssh' WHERE id=?", row["id"])
            ctx.emit("device", ctx.db.device(row["id"]))
        return rows

    @r.post("/snmp/poll/{device_id}")
    async def poll(device_id: int):
        d = ctx.db.device(device_id)
        if not d or not d["ip"]:
            return JSONResponse({"error": "no such device or no IP yet"}, 404)
        try:
            return await monitor.poll_one(ctx, d)
        except Exception as e:  # unreachable / wrong creds: say so instead of a bare 500
            alerts.on_poll_failed(ctx, d)
            return JSONResponse({"error": f"SNMP poll failed: {e}"}, 502)

    @r.get("/snmp/samples/{device_id}")
    def samples(device_id: int, name: str = "", limit: int = 2000):
        if name:
            return ctx.db.q("SELECT ts, name, value FROM snmp_samples WHERE device_id=? AND name=? "
                            "ORDER BY ts DESC LIMIT ?", device_id, name, min(limit, 5000))
        return ctx.db.q("SELECT ts, name, value FROM snmp_samples WHERE device_id=? ORDER BY ts DESC LIMIT ?",
                        device_id, min(limit, 5000))

    @r.get("/traps")
    def traps():
        return ctx.db.q("SELECT * FROM traps ORDER BY ts DESC LIMIT 200")

    # ---- problems (Zabbix) --------------------------------------------------------------------
    @r.get("/problems")
    def problems(device_id: int | None = None, severity: str = "", include_closed: bool = False):
        if include_closed:
            rows = ctx.db.q("""SELECT p.*, d.hostname, d.ip FROM problems p LEFT JOIN devices d ON d.id=p.device_id
                               ORDER BY p.opened DESC LIMIT 500""")
        else:
            rows = alerts.open_problems(ctx.db, device_id)
        return [p for p in rows if (not severity or p["severity"] == severity)
                and (device_id is None or p["device_id"] == device_id)]

    @r.post("/problems/{problem_id}/ack")
    def ack(problem_id: int, body: dict):
        alerts.ack(ctx, problem_id, (body.get("note") or "")[:500])
        ctx.emit("problem", {"id": problem_id, "state": "acked"})
        return {"ok": True}

    @r.get("/dashboard")
    def dashboard():
        return monitor.dashboard(ctx)

    # ---- topology (Zabbix maps / LibreNMS neighbours) -------------------------------------------
    cache = {"graph": None, "ts": 0.0}

    @r.get("/topology")
    async def topo(fresh: bool = False):
        """Neighbour discovery can take seconds (SNMP timeouts, then SSH). Serve the last map right away
        unless the caller asks for a fresh one; problem colours are always current."""
        import copy
        import time
        known = {n["id"] for n in (cache["graph"] or {}).get("nodes", []) if isinstance(n["id"], int)}
        if known != {d["id"] for d in ctx.db.devices()}:  # devices added or removed since: the cached map is stale
            fresh = True
        if fresh or cache["graph"] is None:
            cache["graph"], cache["ts"] = await topology.collect(ctx), time.time()
        g = copy.deepcopy(cache["graph"])
        g["collected"] = cache["ts"]
        worst = alerts.worst(ctx.db)
        for n in g["nodes"]:
            n["severity"] = worst.get(n["id"]) if isinstance(n["id"], int) else None
        down = {}  # per device, built once: O(links + ports), not O(links x ports)
        for e in g["edges"]:
            if e["from"] not in down:
                last = monitor.LAST.get(e["from"], {}) if isinstance(e["from"], int) else {}
                down[e["from"]] = {normalize_if(p) for p in last.get("_down", ())}
            e["down"] = normalize_if(e.get("from_port", "")) in down[e["from"]]
        return g

    return r
