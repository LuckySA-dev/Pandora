"""Background jobs: SNMP polling, trap handling, scheduled backups + compliance.

Kept out of the HTTP layer (LibreNMS keeps poller/discovery separate from the web app too).
"""
import asyncio
import json
import logging
import threading
import time

from . import alerts, compliance, snmp, status

log = logging.getLogger("pandora.monitor")
LAST: dict[int, dict] = {}  # device_id -> last SNMP sample (for "went down" transitions + dashboard)
OFFLINE_RETRY = 300.0  # s between polls of an offline device (cfg offline_retry): a few timeouts, not one a minute
_LAST_TRY: dict[int, float] = {}


def mark_online(ctx, d, now=None):
    """The device answered (SNMP poll, or an inform it sent): online, seen now. Tell the UI only on a change."""
    now = now or time.time()
    was = d.get("reach")
    ctx.db.set_reach(d["id"], "online", now)
    if was != "online":
        if was == "offline":
            gone = f", offline for {round((now - d['seen']) / 60)} min" if d.get("seen") else ""
            ctx.db.audit("monitor", "reach:online", {"id": d["id"], "note": f"answers SNMP again{gone}"})
        alerts.resolve(ctx, d["id"], "unreachable")
        ctx.emit("device", ctx.db.devices(d["id"])[0])


async def poll_one(ctx, d) -> dict:
    _LAST_TRY[d["id"]] = time.time()
    sample, now = await snmp.poll(d["ip"], snmp.auth(ctx.cfg, dev=d)), time.time()
    mark_online(ctx, d, now)
    keep = [(k, v) for k, v in sample.items() if k.endswith(_HISTORY) or k in ("cpu5min", "mem_pct", "uptime")
            or k.startswith("temp:")]  # numbers worth a history; names, descriptions and speeds only in LAST
    with ctx.db.lock:  # one transaction per poll, not one commit per value
        ctx.db.conn.execute("BEGIN")
        try:
            ctx.db.conn.executemany("INSERT INTO snmp_samples VALUES (?,?,?,?)", [(d["id"], now, k, v) for k, v in keep])
        except Exception:
            ctx.db.conn.execute("ROLLBACK")
            raise
        ctx.db.conn.execute("COMMIT")
    prev = LAST.get(d["id"]) or {}
    alerts.on_sample(ctx, d, sample, prev or None)
    down = {k[:-5] for k, v in sample.items() if k.endswith(":oper") and v == "down"}
    total = sum(k.endswith(":oper") for k in sample)
    # counted once per poll, so every inventory request reads them in O(1) per row
    LAST[d["id"]] = {**sample, **rates(sample, prev, now), "_ts": now, "_up": total - len(down), "_total": total,
                     "_down": down}
    ctx.emit("snmp", {"id": d["id"], "ts": now, "sample": sample})
    return sample


_HISTORY = (":oper", ":in", ":out", ":inerr", ":outerr")


def rates(sample: dict, prev: dict, now: float) -> dict:
    """Bits per second per port from the 64-bit counters of two polls ('Gi1/0/1:in_bps'). A counter that went back
    (the box restarted, the counter was cleared) gives no rate for that poll rather than a nonsense one."""
    dt = now - prev.get("_ts", 0)
    if not prev or not 0 < dt < 3600:
        return {}
    out = {}
    for k, v in sample.items():
        if k.endswith((":in", ":out")) and str(v).isdigit() and str(prev.get(k, "")).isdigit():
            delta = int(v) - int(prev[k])
            if delta >= 0:
                out[f"{k}_bps"] = round(delta * 8 / dt)
    return out


async def backbones_forever(ctx, every=30):
    """Provisioning backbones: read who is plugged into their provisioning ports (CDP + MAC table, backbone.scan),
    so a box plugged in there gets its model, its management port and "behind <switch> <port>" without a click."""
    from . import backbone
    while True:
        await asyncio.sleep(every)
        for d in ctx.db.devices():
            if d["state"] == "provisioned" and d["reach"] != "offline" and backbone.active(ctx, d["id"]):
                try:
                    await asyncio.to_thread(backbone.scan, ctx, d["id"])
                except Exception as e:
                    log.info("backbone scan of %s: %s", d["id"], e)


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
        retry, now = float(ctx.cfg.get("offline_retry", OFFLINE_RETRY)), time.time()
        # an offline box (a single-NIC laptop cabled to another one, say) is asked again every few minutes only
        due = [d for d in ctx.db.devices() if d["state"] == "provisioned" and d["ip"]
               and (d["reach"] != "offline" or now - _LAST_TRY.get(d["id"], 0) >= retry)]
        for d in due:
            _LAST_TRY[d["id"]] = now
        await asyncio.gather(*(one(d) for d in due))
        await asyncio.sleep(every)


def on_trap(ctx, src, name, varbinds):
    ctx.db.x("INSERT INTO traps VALUES (?,?,?,?)", time.time(), src, name, json.dumps(varbinds))
    ctx.emit("trap", {"src": src, "name": name, "varbinds": varbinds, "ts": time.time()})
    dev = ctx.db.find(ip=src)
    if dev and dev["state"] == "provisioned":
        mark_online(ctx, dev)  # it just reached us: no need to wait for the next poll
    index = next((str(v) for n, v in varbinds if str(n).startswith("1.3.6.1.2.1.2.2.1.1.")), "")
    port = (LAST.get(dev["id"], {}).get("_ifindex") or {}).get(index) if dev else None
    alerts.on_trap(ctx, dev, name, varbinds, port=port)
    if name == "configChange" and dev and config_written(varbinds):  # Oxidized-style: fetch right after the change
        if getattr(ctx, "probed_until", {}).get(dev["id"], 0) > time.time():
            return  # our own `?` capability probe, which classic IOS reports as a config write: nothing changed
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
            if d["state"] == "provisioned" and d["ip"] and d["reach"] != "offline":  # no SSH timeouts on absent boxes
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
    down = {d["id"] for d in prov if d["reach"] == "offline"}
    cpu = sorted(((int(LAST[d["id"]]["cpu5min"]), d) for d in prov
                  if str(LAST.get(d["id"], {}).get("cpu5min", "")).isdigit()), key=lambda t: -t[0])[:5]
    comp = {r["device_id"]: json.loads(r["result"])["compliant"] for r in ctx.db.q("SELECT * FROM compliance")}
    worst = alerts.worst(ctx.db)
    statuses = {}
    for d in devs:
        s = status.of(d, worst.get(d["id"]), comp.get(d["id"]), LAST.get(d["id"]))
        statuses[s] = statuses.get(s, 0) + 1
    return {
        "states": states, "statuses": statuses, "total": len(devs),
        "problems": by_sev, "open_problems": problems[:8],
        "availability": {"up": len(prov) - len(down & {d["id"] for d in prov}), "down": len(down), "total": len(prov)},
        "top_cpu": [{"id": d["id"], "hostname": d["hostname"], "cpu": c} for c, d in cpu],
        "compliance": {"compliant": sum(comp.values()), "drift": len(comp) - sum(comp.values()),
                       "unchecked": len(prov) - len(comp)},
        "events": ctx.db.q("SELECT * FROM audit ORDER BY ts DESC LIMIT 12"),
    }
