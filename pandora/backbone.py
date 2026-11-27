"""Provisioning backbone: one switch PandoraBox already configured becomes the patch point for the others.

A PC has one LAN card. Instead of re-cabling it to every new box, it stays in the backbone switch's management
port (VLAN 99, the provisioning segment) and the backbone's free front-panel ports join that segment too:
access VLAN 99, portfast, up. A box plugged into one of them reaches PandoraBox's DHCP / PnP / AutoInstall exactly
as if it were cabled to the PC, and PandoraBox reaches it over SSH the same way, through the backbone.

What a PC would hear on its own cable (CDP, which no switch forwards) the backbone hears on each port: its CDP and
MAC tables, read over SSH, say which box sits on which port, its model and the name of its port facing us (the
port to keep as its management port). Uplinks, PandoraBox's own port, management-design links and trunks are never
offered; ports facing an already configured switch are offered unticked.
"""
import logging
import re

from . import alloc, ports
from .deliver import ios_errors

log = logging.getLogger("pandora.backbone")
DESC = "PANDORA-PROVISION"
_MAC = re.compile(r"^\s*\*?\s*(\d+)\s+([0-9a-f]{4}\.[0-9a-f]{4}\.[0-9a-f]{4})\s+\S+\s+(?:\S+\s+)*?(\S+)\s*$", re.I | re.M)


def active(ctx, device_id) -> list[str]:
    return ctx.db.vars(device_id).get("backbone_ports") or []


def _mac(dotted: str) -> str:
    h = dotted.replace(".", "").lower()
    return ":".join(h[i:i + 2] for i in range(0, 12, 2))


def parse_macs(text: str) -> dict[str, list[str]]:
    """`show mac address-table dynamic vlan 99` -> {port: [mac, ...]} (IOS and IOS-XE layouts)."""
    out: dict[str, list[str]] = {}
    for m in _MAC.finditer(text):
        port = m.group(3)
        if ports.parse(port):
            out.setdefault(alloc.normalize_if(port), []).append(_mac(m.group(2)))
    return out


def _check(ctx, device_id):
    dev = ctx.db.device(device_id)
    if not dev or dev["state"] != "provisioned":
        raise ValueError("only a switch PandoraBox has pre-configured can be a provisioning backbone")
    if dev["role"] != "switch_access":
        raise ValueError("a provisioning backbone must be a switch (its ports join the provisioning VLAN)")
    return dev


def _taken(ctx, device_id) -> dict[str, str]:
    """Ports that must never become provisioning ports: {normalized name: why}."""
    out = {alloc.normalize_if(r["port"]): "PandoraBox's management port"
           for r in ctx.db.q("SELECT port FROM reserved_ports WHERE device_id=?", device_id)}
    for row in ctx.db.q("SELECT lines FROM mgmt_config WHERE device_id=?", device_id):
        for ln in row["lines"].splitlines():
            if ln.startswith("interface ") and ports.parse(ln.split(None, 1)[1].split(".")[0]):
                out.setdefault(alloc.normalize_if(ln.split(None, 1)[1].split(".")[0]), "a management network link")
    return out


def candidates(ctx, device_id) -> list[dict]:
    """The switch's front-panel ports that may become provisioning ports, read from the box now."""
    dev = _check(ctx, device_id)
    with ctx.session(dev) as c:
        c.enable()
        brief = c.send_command("show ip interface brief")
        names = alloc.parse_ifnames(brief)
        # a port with an address is a routed port (`no switchport`, an out-of-band or lab management port: IOL e0/0
        # in containerlab was offered and would have cut the box off): never a provisioning port
        routed = {alloc.normalize_if(m.group(1)) for m in re.finditer(
            r"^(\S+?\d+(?:/\d+)*)\s+\d+\.\d+\.\d+\.\d+\s+(?:YES|NO)\s", brief, re.M)}
        trunks = {alloc.normalize_if(m) for m in re.findall(r"^(\S+\d)\s+(?:on|auto|desirable)\s", c.send_command(
            "show interfaces trunk"), re.M)}
        cdp = c.send_command("show cdp neighbors detail", use_textfsm=True)
    kinds, taken = ports.classify(names, dev["pid"]), _taken(ctx, device_id)
    nb = {alloc.normalize_if(r.get("local_port") or r.get("local_interface") or ""): r
          for r in (cdp if isinstance(cdp, list) else [])}
    known = {(d["hostname"] or "").lower(): d for d in ctx.db.devices() if d["state"] == "provisioned"}
    out = []
    for n in sorted(names, key=ports.sort_key):
        kind = kinds.get(n)
        if kind != "access" or n in taken or n in trunks or n in routed or n in active(ctx, device_id):
            continue  # uplinks, PandoraBox's own port, design links, trunks and ports already provisioning
        r = nb.get(n) or {}
        peer = (r.get("destination_host") or r.get("neighbor_name") or "").split(".")[0]
        configured = known.get(peer.lower())
        out.append({"port": n, "neighbor": peer or None, "platform": r.get("platform"),
                    "suggest": not configured, "why": f"faces {peer}, a configured device" if configured else None})
    return out


def lines_for(ports_: list[str], vlan) -> list[str]:
    out = ["cdp run"]  # its CDP table is how PandoraBox learns what is plugged where
    for p in ports_:
        out += [f"interface {p}", f" description {DESC}", " switchport mode access", f" switchport access vlan {vlan}",
                " spanning-tree portfast", " no shutdown"]
    return out


def enable(ctx, device_id, wanted: list[str]) -> list[str]:
    """Turn these ports into provisioning ports. Only ports candidates() offers; returns the ones configured."""
    offered = {c["port"] for c in candidates(ctx, device_id)}
    chosen = [alloc.normalize_if(p) for p in wanted]
    if bad := [p for p in chosen if p not in offered]:
        raise ValueError(f"not a free front-panel port of this switch: {', '.join(bad)}")
    if not chosen:
        raise ValueError("choose at least one port")
    dev = ctx.db.device(device_id)
    out = ctx.ssh_config(dev, lines_for(chosen, ctx.cfg["mgmt_vlan"]))
    if bad := ios_errors(out):
        raise RuntimeError("; ".join(bad))
    keep = sorted(set(active(ctx, device_id)) | set(chosen), key=ports.sort_key)
    ctx.db.set_vars(device_id, {**ctx.db.vars(device_id), "backbone_ports": keep})
    ctx.db.save_config(device_id, "backbone", "\n".join(lines_for(chosen, ctx.cfg["mgmt_vlan"])), "ok")
    ctx.db.audit("user", "backbone:on", {"id": device_id, "ports": chosen})
    ctx.emit("device", ctx.db.device(device_id))
    return chosen


def disable(ctx, device_id) -> list[str]:
    """Provisioning ports back to factory defaults (`default interface`), the switch is a plain switch again."""
    dev, was = _check(ctx, device_id), active(ctx, device_id)
    if was:
        out = ctx.ssh_config(dev, [f"default interface {p}" for p in was])
        if bad := ios_errors(out):
            raise RuntimeError("; ".join(bad))
    v = ctx.db.vars(device_id)
    v.pop("backbone_ports", None)
    ctx.db.set_vars(device_id, v)
    ctx.db.audit("user", "backbone:off", {"id": device_id, "ports": was})
    ctx.emit("device", ctx.db.device(device_id))
    return was


def scan(ctx, device_id) -> list[dict]:
    """Who is on each provisioning port now (CDP + MAC table of the backbone). A box being onboarded learns its
    model and its port facing us (its management port) from it; every box found gets `behind` = this port."""
    dev = ctx.db.device(device_id)
    want = active(ctx, device_id)
    if not want:
        return []
    with ctx.session(dev) as c:
        c.enable()
        macs = parse_macs(c.send_command(f"show mac address-table dynamic vlan {ctx.cfg['mgmt_vlan']}"))
        cdp = c.send_command("show cdp neighbors detail", use_textfsm=True)
        status = {alloc.normalize_if(m.group(1)): m.group(2) for m in re.finditer(
            r"^(\S+?\d+(?:/\d+)*)\s+\S+\s+(?:YES|NO)\s+\S+\s+(up|down|administratively down)\s", c.send_command(
                "show ip interface brief"), re.M)}
    nb = {alloc.normalize_if(r.get("local_port") or r.get("local_interface") or ""): r
          for r in (cdp if isinstance(cdp, list) else [])}
    rows = []
    for p in want:
        r = nb.get(p) or {}
        found = next((d for m in macs.get(p, []) if (d := ctx.db.find(mac=m))), None)
        ip = r.get("management_ip") or r.get("mgmt_address")
        found = found or (ctx.db.find(ip=ip) if ip else None)
        if found:
            n = {"via": "cdp", "remote_port": r.get("remote_port") or r.get("neighbor_interface"),
                 "platform": r.get("platform")} if r else None
            if n:
                ctx.learn_from_neighbor(n, dev=found)  # its model + the port it faces us on (= its mgmt port)
            v = ctx.db.vars(found["id"])
            behind = {"switch": device_id, "port": p}
            if v.get("behind") != behind:
                ctx.db.set_vars(found["id"], {**ctx.db.vars(found["id"]), "behind": behind})
                ctx.emit("device", ctx.db.device(found["id"]))
            found = ctx.db.devices(found["id"])[0]
        rows.append({"port": p, "link": status.get(p), "macs": macs.get(p, []),
                     "cdp": {"name": (r.get("destination_host") or r.get("neighbor_name") or "").split(".")[0] or None,
                             "platform": r.get("platform"), "port": r.get("remote_port") or r.get("neighbor_interface")}
                     if r else None,
                     "device": {k: found[k] for k in ("id", "hostname", "alloc_hostname", "serial", "state", "ip", "pid")}
                     if found else None})
    return rows
