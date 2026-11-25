"""Golden-config compliance per feature + remediation (Nautobot Golden Config / hier_config idea).

intended = what PandoraBox renders for the device; actual = the latest backup. Both are parsed into
blocks (top-level line + indented children) and compared block by block. Each block belongs to a
"feature" so the UI can say *what* drifted (mgmt ports, SNMP, ...) instead of dumping a diff.
"""
import json
import re
import time

from . import alerts, backup
from .alloc import expand_range, normalize_if
from .db import mask_secrets

FEATURES = ("hostname", "mgmt-vlan", "mgmt-ports", "access", "snmp", "role")
STRICT = {"mgmt-vlan", "mgmt-ports"}  # extra lines here are drift too (someone shut our port)
# Never visible in a running-config, or only as a hash: compare can't judge them.
_SKIP = re.compile(r"^(crypto key generate|snmp-server user |event manager applet PANDORA-SAVE|end$)")
# Normalised to a prefix for the compare; pushing that prefix alone would be wrong (user with no secret).
_NO_PUSH = re.compile(r"^username ")

# ---- Cisco IOS rules adapted from hier_config's driver (MIT, Copyright (c) 2018 netdevops; see NOTICE) ----
# Lines IOS adds or shows on its own: ignored on both sides of the compare.
_IGNORE = [re.compile(p) for p in (
    r"^Building configuration.*", r"^Current configuration.*", r"^! Last configuration change.*",
    r"^! NVRAM config last updated.*", r"^ntp clock-period .*", r"^version.*", r"^ logging event link-status$",
    r"^ logging event subif-link-status$", r"^\s*ipv6 unreachables disable$", r"^end$", r"^\s*[#!].*",
    r"^ no ip address", r"^ exit-peer-policy", r"^ exit-peer-session", r"^ exit-address-family",
    r"^crypto key generate rsa general-keys.*$",
    r"^ip ssh version 2$")]  # IOS-XE 17.x has only v2 and no longer prints it
# Commands where a new value replaces the old one, so no "no <old value>" is needed first.
_IDEMPOTENT = [(r"^vlan", r"^name "), (r"^interface ", r"^description "), (r"^interface ", r"^ip address "),
               (r"^interface ", r"^switchport mode "), (r"^interface ", r"^authentication host-mode "),
               (r"^interface ", r"^authentication event server dead action authorize vlan "),
               (None, r"^errdisable recovery interval "), (None, r"^(?:no )?logging console")]


def _idem_key(parent: str, child: str) -> str | None:
    for pp, cp in _IDEMPOTENT:
        if (pp is None or re.match(pp, parent)) and (m := re.match(cp, child)):
            return m.group(0)
    return None


def _weight(parent: str, line: str) -> int:
    """Order inside a block: switchport mode first, no shutdown last (hier_config weights)."""
    t = line.strip()
    if parent.startswith("interface") and t.startswith("switchport mode "):
        return -10
    if (parent.startswith("interface") and t == "no shutdown") or t.startswith("no vlan filter"):
        return 200
    return 0


def _blocks(text: str) -> dict[str, list[str]]:
    out: dict[str, list[str]] = {}
    parent = None
    for raw in text.replace("\r", "").split("\n"):
        line = raw.rstrip()
        if any(rx.match(line) for rx in _IGNORE):
            continue
        if not line.strip() or line.lstrip().startswith("!"):
            continue
        if line.startswith(" "):
            if parent is not None and not _SKIP.match(line.strip()):
                out[parent].append(_norm(line.strip()))
            continue
        if _SKIP.match(line):
            parent = None
            continue
        m = re.match(r"^interface range (.+)$", line, re.I)
        names = [f"interface {p}" for p in expand_range(m.group(1))] if m else [_norm(line)]
        for n in names:
            out.setdefault(n, [])
        parent = names[-1]
        if m:  # children of a range apply to every member
            parent = ("__range__", tuple(names))
            out.setdefault(parent, [])
    # fan range children out to their members
    for key in [k for k in out if isinstance(k, tuple)]:
        for n in key[1]:
            out[n] += out[key]
        del out[key]
    return out


def _norm(line: str) -> str:
    line = re.sub(r"\s+", " ", line.strip())
    line = re.sub(r"^ip domain-name ", "ip domain name ", line)
    if m := re.match(r"^(username \S+)", line):
        return m.group(1)
    if m := re.match(r"^interface (.+)$", line):
        return "interface " + normalize_if(m.group(1))
    return line


def _feature(parent: str, reserved: set[str], vlan: int) -> str:
    if parent.startswith("hostname "):
        return "hostname"
    if parent in (f"vlan {vlan}", f"interface Vlan{vlan}") or parent.startswith(("ip default-gateway", "ip route 0.0.0.0")):
        return "mgmt-vlan"
    if parent in reserved:
        return "mgmt-ports"
    if parent.startswith(("ip ssh", "line vty", "ip domain", "no ip domain", "username ", "service password")):
        return "access"
    if parent.startswith("snmp-server"):
        return "snmp"
    return "role"


def _covered(parent: str, have: dict) -> bool:
    """IOS merges trap keywords with its defaults: 'traps snmp linkdown linkup coldstart' shows up as
    'traps snmp authentication linkdown linkup coldstart warmstart'. Same trap group + superset = present."""
    m = re.match(r"^(snmp-server enable traps \S+)(.*)$", parent)
    return bool(m) and any(h.startswith(m.group(1) + " ") and set(m.group(2).split()) <= set(h.split()) for h in have)


def _vtp_vlans(ctx, dev) -> str:
    """VTP server/client keep VLANs in vlan.dat, not the running-config: read them from `show vlan brief`."""
    try:
        out = ctx.ssh_command(dev, "show vlan brief")
    except Exception:
        return ""
    return "".join(f"\nvlan {m[1]}\n name {m[2]}" for m in re.finditer(r"^(\d+)\s+(\S+)\s+(?:active|act/)", out, re.M))


def compare(intended: str, running: str, reserved_ports: list[str], mgmt_vlan: int) -> dict:
    want, have = _blocks(intended), _blocks(running)
    reserved = {f"interface {normalize_if(p)}" for p in reserved_ports}
    feats = {f: {"name": f, "missing": [], "extra": []} for f in FEATURES}
    remediation = []
    for parent, kids in want.items():
        f = feats[_feature(parent, reserved, mgmt_vlan)]
        if parent not in have and not _covered(parent, have):
            f["missing"] += [parent] + [f" {k}" for k in kids]
            if not _NO_PUSH.match(parent):
                remediation += [parent] + [f" {k}" for k in kids]
            continue
        # IOS never prints "no shutdown" (the default): it holds unless the box shows "shutdown"
        if parent not in have:
            continue  # covered by a wider line IOS printed instead
        missing = [k for k in kids if k not in have[parent] and not (k == "no shutdown" and "shutdown" not in have[parent])]
        extra = [k for k in have[parent] if k not in kids] if f["name"] in STRICT else []
        if missing or extra:
            f["missing"] += [f"{parent} > {k}" for k in missing]
            f["extra"] += [f"{parent} > {k}" for k in extra]
            # Remove wrong lines first, then set the right ones (e.g. access vlan 10 -> 99). Commands IOS replaces
            # in place (description, ip address, switchport mode...) need no "no <old>" (hier_config idea).
            replaced = {_idem_key(parent, k) for k in missing} - {None}
            negate = [k for k in extra if _idem_key(parent, k) not in replaced or _idem_key(parent, k) is None]
            lines = [f" {k[3:]}" if k.startswith("no ") else f" no {k}" for k in negate] + [f" {k}" for k in missing]
            lines.sort(key=lambda line: _weight(parent, line))  # stable: keeps "no" before "set" at equal weight
            remediation += [parent] + lines
    used = [f for f in feats.values() if f["missing"] or f["extra"] or
            any(_feature(p, reserved, mgmt_vlan) == f["name"] for p in want)]
    for f in used:
        f["compliant"] = not f["missing"] and not f["extra"]
    return {"compliant": all(f["compliant"] for f in used), "features": used, "remediation": remediation}


# ---- stored results ---------------------------------------------------------------------------
def run(ctx, device_id, refresh=True) -> dict:
    if refresh or not backup.latest(ctx.db, device_id):
        backup.fetch(ctx, device_id)
    b = backup.latest(ctx.db, device_id)
    intended, _, a = ctx.render(device_id)
    # backups are stored masked: mask the intended config the same way so secrets compare equal
    running = b["text"]
    if re.search(r"^vlan \d+$", intended, re.M) and not re.search(r"^vlan \d+$", running, re.M):
        running += _vtp_vlans(ctx, ctx.db.device(device_id))
    res = compare(mask_secrets(intended), running, a["reserved_ports"], ctx.cfg["mgmt_vlan"])
    res.update(ts=time.time(), backup_id=b["id"])
    ctx.db.x("INSERT OR REPLACE INTO compliance (device_id, ts, result) VALUES (?,?,?)",
             device_id, res["ts"], json.dumps(res))
    alerts.on_compliance(ctx, device_id, res)
    ctx.emit("compliance", {"device_id": device_id, "compliant": res["compliant"]})
    return res


def get(db, device_id) -> dict | None:
    rows = db.q("SELECT result FROM compliance WHERE device_id=?", device_id)
    return json.loads(rows[0]["result"]) if rows else None


def remediate(ctx, device_id) -> dict:
    """Push the remediation plan of the last compliance run, then re-check.
    The plan restores PandoraBox's own intended config, so the mgmt-port guard does not apply here."""
    res = get(ctx.db, device_id)
    if not res or res["compliant"] or not res["remediation"]:
        return {"pushed": False, "result": res}
    d = ctx.db.device(device_id)
    out = ctx.ssh_config(d, res["remediation"])
    ctx.db.save_config(device_id, "remediation", "\n".join(res["remediation"]), "ok")
    ctx.db.audit("user", "remediation", {"device": device_id, "lines": len(res["remediation"])})
    return {"pushed": True, "output": out[-3000:], "result": run(ctx, device_id)}
