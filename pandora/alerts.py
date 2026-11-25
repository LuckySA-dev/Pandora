"""Problems with severity, acknowledge and auto-recovery (Zabbix triggers -> problems).

A problem is keyed by (device, key). Raising an open key again only refreshes its message;
resolving closes it. Every open/close is pushed to the UI as a `problem` event.
"""
import time

from .alloc import normalize_if

SEVERITIES = ("info", "warning", "average", "high", "disaster")
CPU_HIGH = 80          # % (5 min), like Zabbix's default "High CPU utilization" trigger
UNREACHABLE_AFTER = 3  # consecutive failed polls

_fails: dict[int, int] = {}


def raise_(ctx, device_id, key, severity, message):
    assert severity in SEVERITIES, severity
    row = ctx.db.q("SELECT * FROM problems WHERE device_id IS ? AND key=? AND closed IS NULL", device_id, key)
    if row:
        if row[0]["message"] != message or row[0]["severity"] != severity:
            ctx.db.x("UPDATE problems SET message=?, severity=? WHERE id=?", message, severity, row[0]["id"])
        return row[0]["id"]
    cur = ctx.db.x("INSERT INTO problems (device_id, key, severity, message, opened) VALUES (?,?,?,?,?)",
                   device_id, key, severity, message, time.time())
    ctx.db.audit("alerts", f"problem:{severity}", {"device": device_id, "key": key, "message": message})
    ctx.emit("problem", {"id": cur.lastrowid, "device_id": device_id, "severity": severity, "message": message,
                         "state": "open"})
    return cur.lastrowid


def resolve(ctx, device_id, key, prefix=False):
    match = "key LIKE ?" if prefix else "key=?"
    rows = ctx.db.q(f"SELECT id FROM problems WHERE device_id IS ? AND {match} AND closed IS NULL",
                    device_id, key + "%" if prefix else key)
    for r in rows:
        ctx.db.x("UPDATE problems SET closed=? WHERE id=?", time.time(), r["id"])
        ctx.emit("problem", {"id": r["id"], "device_id": device_id, "state": "resolved"})


def ack(ctx, problem_id, note=""):
    ctx.db.x("UPDATE problems SET acked=?, note=? WHERE id=?", time.time(), note, problem_id)
    ctx.db.audit("user", "problem:ack", {"id": problem_id, "note": note})


def open_problems(db, device_id=None):
    sql = """SELECT p.*, d.hostname, d.ip FROM problems p LEFT JOIN devices d ON d.id=p.device_id
             WHERE p.closed IS NULL""" + (" AND p.device_id=?" if device_id else "") + " ORDER BY p.opened DESC"
    rows = db.q(sql, *([device_id] if device_id else []))
    rank = {s: i for i, s in enumerate(SEVERITIES)}
    return sorted(rows, key=lambda r: -rank[r["severity"]])


def worst(db) -> dict[int, str]:
    """{device_id: worst open severity}: colours the topology and inventory."""
    rank = {s: i for i, s in enumerate(SEVERITIES)}
    out = {}
    for p in open_problems(db):
        cur = out.get(p["device_id"])
        if cur is None or rank[p["severity"]] > rank[cur]:
            out[p["device_id"]] = p["severity"]
    return out


# ---- triggers -----------------------------------------------------------------------------
def on_sample(ctx, device, sample: dict, prev: dict | None):
    """Evaluate one SNMP poll (dict 'Gi1/0/1:oper' -> 'up'/'down', 'cpu5min' -> '7')."""
    did = device["id"]
    _fails.pop(did, None)
    resolve(ctx, did, "unreachable")
    reserved = {normalize_if(r["port"]) for r in ctx.db.q("SELECT port FROM reserved_ports WHERE device_id=?", did)}
    for k, v in sample.items():
        if not k.endswith(":oper"):
            continue
        port = k[:-5]
        key = f"if:{normalize_if(port)}"
        was_up = prev is not None and prev.get(k) == "up"
        if v == "down" and normalize_if(port) in reserved:
            raise_(ctx, did, key, "high", f"Management port {port} is down")
        elif v == "down" and was_up:
            raise_(ctx, did, key, "warning", f"Interface {port} went down")
        elif v == "up":
            resolve(ctx, did, key)
    cpu = sample.get("cpu5min")
    if cpu is not None and str(cpu).isdigit():
        if int(cpu) >= CPU_HIGH:
            raise_(ctx, did, "cpu", "average", f"CPU {cpu}% (5 min)")
        else:
            resolve(ctx, did, "cpu")


def on_poll_failed(ctx, device):
    n = _fails[device["id"]] = _fails.get(device["id"], 0) + 1
    if n >= UNREACHABLE_AFTER:
        raise_(ctx, device["id"], "unreachable", "high", f"No SNMP answer for {n} polls")


def on_trap(ctx, device, name, varbinds):
    if device is None:
        return
    ifindex = next((v for n, v in varbinds if n.startswith("1.3.6.1.2.1.2.2.1.1.")), "?")
    if name == "linkDown":
        raise_(ctx, device["id"], f"trap:if{ifindex}", "warning", f"linkDown trap (ifIndex {ifindex})")
    elif name == "linkUp":
        resolve(ctx, device["id"], f"trap:if{ifindex}")
    elif name == "coldStart":
        raise_(ctx, device["id"], "reboot", "info", "Device restarted (coldStart)")


def on_device(ctx, device):
    """Provisioning state -> problems (failed pushes are the operator's most important signal)."""
    if not device:
        return
    if device["state"] == "failed":
        raise_(ctx, device["id"], "provision", "high", f"Pre-config failed: {device.get('note') or ''}"[:300])
    else:
        resolve(ctx, device["id"], "provision")
    if device["state"] == "needs_credentials":
        raise_(ctx, device["id"], "creds", "info", "Waiting for credentials")
    else:
        resolve(ctx, device["id"], "creds")


def on_compliance(ctx, device_id, result):
    if result["compliant"]:
        resolve(ctx, device_id, "drift")
    else:
        names = {"hostname": "hostname", "mgmt-vlan": "management VLAN", "mgmt-ports": "management ports",
                 "access": "login and SSH", "snmp": "SNMP", "role": "role configuration"}
        bad = ", ".join(names.get(f["name"], f["name"]) for f in result["features"] if not f["compliant"])
        raise_(ctx, device_id, "drift", "warning", f"Config drifted: {bad}")
