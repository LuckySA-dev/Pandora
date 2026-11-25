"""Background jobs: SNMP polling, trap handling, scheduled backups + compliance.

Kept out of the HTTP layer (LibreNMS keeps poller/discovery separate from the web app too).
"""
import asyncio
import json
import logging
import threading
import time

from . import alerts, compliance, snmp

log = logging.getLogger("pandora.monitor")
LAST: dict[int, dict] = {}  # device_id -> last SNMP sample (for "went down" transitions + dashboard)


async def poll_one(ctx, d) -> dict:
    sample, now = await snmp.poll(d["ip"], snmp.auth(ctx.cfg, dev=d)), time.time()
    for k, v in sample.items():
        ctx.db.x("INSERT INTO snmp_samples VALUES (?,?,?,?)", d["id"], now, k, v)
    alerts.on_sample(ctx, d, sample, LAST.get(d["id"]))
    LAST[d["id"]] = {**sample, "_ts": now}
    ctx.emit("snmp", {"id": d["id"], "ts": now, "sample": sample})
    return sample


async def poll_forever(ctx, every=60, parallel=16):
    sem = asyncio.Semaphore(parallel)  # devices at once; a dead one only costs its own timeout

    async def one(d):
        async with sem:
            try:
                await poll_one(ctx, d)
            except Exception as e:
                log.debug("poll %s: %s", d["ip"], e)
                alerts.on_poll_failed(ctx, d)

    while True:
        await asyncio.gather(*(one(d) for d in ctx.db.devices() if d["state"] == "provisioned" and d["ip"]))
        await asyncio.sleep(every)


def on_trap(ctx, src, name, varbinds):
    ctx.db.x("INSERT INTO traps VALUES (?,?,?,?)", time.time(), src, name, json.dumps(varbinds))
    ctx.emit("trap", {"src": src, "name": name, "varbinds": varbinds, "ts": time.time()})
    dev = ctx.db.find(ip=src)
    alerts.on_trap(ctx, dev, name, varbinds)
    if name == "configChange" and dev:  # Oxidized-style: fetch right after the change
        threading.Thread(target=_backup_and_check, args=(ctx, dev["id"]), daemon=True).start()


def _backup_and_check(ctx, device_id):
    try:
        compliance.run(ctx, device_id)  # fetches a fresh backup first
    except Exception as e:
        log.info("backup/compliance %s: %s", device_id, e)


async def backup_forever(ctx, every=6 * 3600):
    while True:
        await asyncio.sleep(every)
        for d in ctx.db.devices():
            if d["state"] == "provisioned" and d["ip"]:
                await asyncio.to_thread(_backup_and_check, ctx, d["id"])


def dashboard(ctx) -> dict:
    devs = ctx.db.devices()
    states = {}
    for d in devs:
        states[d["state"]] = states.get(d["state"], 0) + 1
    problems = alerts.open_problems(ctx.db)
    by_sev = {s: 0 for s in alerts.SEVERITIES}
    for p in problems:
        by_sev[p["severity"]] += 1
    prov = [d for d in devs if d["state"] == "provisioned"]
    down = {p["device_id"] for p in problems if p["key"] == "unreachable"}
    cpu = sorted(((int(LAST[d["id"]]["cpu5min"]), d) for d in prov
                  if str(LAST.get(d["id"], {}).get("cpu5min", "")).isdigit()), key=lambda t: -t[0])[:5]
    comp = {r["device_id"]: json.loads(r["result"])["compliant"] for r in ctx.db.q("SELECT * FROM compliance")}
    return {
        "states": states, "total": len(devs),
        "problems": by_sev, "open_problems": problems[:8],
        "availability": {"up": len(prov) - len(down & {d["id"] for d in prov}), "down": len(down), "total": len(prov)},
        "top_cpu": [{"id": d["id"], "hostname": d["hostname"], "cpu": c} for c, d in cpu],
        "compliance": {"compliant": sum(comp.values()), "drift": len(comp) - sum(comp.values()),
                       "unchecked": len(prov) - len(comp)},
        "events": ctx.db.q("SELECT * FROM audit ORDER BY ts DESC LIMIT 12"),
    }
