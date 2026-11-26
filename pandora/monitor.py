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
    with ctx.db.lock:  # one transaction per poll, not one commit per value
        ctx.db.conn.execute("BEGIN")
        try:
            ctx.db.conn.executemany("INSERT INTO snmp_samples VALUES (?,?,?,?)",
                                    [(d["id"], now, k, v) for k, v in sample.items()])
        except Exception:
            ctx.db.conn.execute("ROLLBACK")
            raise
        ctx.db.conn.execute("COMMIT")
    alerts.on_sample(ctx, d, sample, LAST.get(d["id"]))
    down = {k[:-5] for k, v in sample.items() if k.endswith(":oper") and v == "down"}
    total = sum(k.endswith(":oper") for k in sample)
    # counted once per poll, so every inventory request reads them in O(1) per row
    LAST[d["id"]] = {**sample, "_ts": now, "_up": total - len(down), "_total": total, "_down": down}
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
    if name == "configChange" and dev and config_written(varbinds):  # Oxidized-style: fetch right after the change
        schedule_backup(ctx, dev["id"])


# CISCO-CONFIG-MAN-MIB ccmHistoryEventConfigDestination: 3 running, 4 startup are writes; 2 = commandSource is a read.
_CCM_DEST = "1.3.6.1.4.1.9.9.43.1.1.6.1.5."


def config_written(varbinds) -> bool:
    """IOS sends ciscoConfigManEvent for reads too: `show running-config` is running -> commandSource. Answering that
    with a backup (which runs `show running-config`) looped on a real 2960X: 180 informs and 370 SSH sessions in 30
    minutes. Only a copy *into* running or startup is a change; an event we can't read counts as one."""
    dest = [str(v) for n, v in varbinds if str(n).startswith(_CCM_DEST)]
    return not dest or any(d in ("3", "4") for d in dest)


_BACKUPS: dict[int, bool] = {}  # device_id -> "changed again while a backup ran"
_BACKUPS_LOCK = threading.Lock()


def schedule_backup(ctx, device_id, settle=10.0):
    """One backup per device at a time; changes arriving meanwhile (a config session sends several) are folded
    into one more run after `settle` seconds, never a thread each."""
    with _BACKUPS_LOCK:
        if device_id in _BACKUPS:
            _BACKUPS[device_id] = True
            return
        _BACKUPS[device_id] = False

    def run():
        while True:
            _backup_and_check(ctx, device_id)
            with _BACKUPS_LOCK:
                if not _BACKUPS[device_id]:
                    del _BACKUPS[device_id]
                    return
                _BACKUPS[device_id] = False
            time.sleep(settle)
    threading.Thread(target=run, daemon=True, name=f"backup-{device_id}").start()


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
