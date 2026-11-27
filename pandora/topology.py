"""Topology graph: SNMP first (CISCO-CDP-MIB / LLDP-MIB), SSH `show cdp neighbors detail` as fallback."""
import asyncio
import logging

from . import ports, snmp
from .alloc import normalize_if

log = logging.getLogger("pandora.topology")
ME = "PandoraBox"


def build(devices: list[dict], neighbors: dict, sniffed: list[dict], backbones=frozenset()) -> dict:
    """devices + {device_id: [neighbor]} -> {"nodes": [...], "edges": [...]} for vis-network."""
    by_name = {(d.get("hostname") or "").lower(): d for d in devices if d.get("hostname")}
    by_ip = {d["ip"]: d for d in devices if d.get("ip")}
    nodes = {ME: {"id": ME, "label": ME, "group": "me"}}
    for d in devices:
        nodes[d["id"]] = {"id": d["id"], "label": d.get("hostname") or d.get("serial") or f"#{d['id']}",
                          "title": f"{d.get('pid') or ''} {d.get('ip') or ''}", "group": d["state"],
                          "role": d.get("role"), "backbone": d["id"] in backbones}
    edges, seen = [], set()

    def node_for(n):
        d = by_name.get(n["remote_name"].lower()) or by_ip.get(n.get("remote_ip"))
        if d:
            return d["id"]
        key = f"ext:{n['remote_name']}"
        nodes.setdefault(key, {"id": key, "label": n["remote_name"], "title": n.get("platform", ""), "group": "external"})
        return key

    def add(a, a_port, b, b_port, via):
        a_port, b_port = normalize_if(a_port), normalize_if(b_port)
        # between two inventory devices the design may write both names into config: plain port names only. An
        # outside neighbour's LLDP "port" (often a MAC or a description) is only drawn, and the UI escapes it.
        if isinstance(a, int) and isinstance(b, int) and not all(ports.safe_name(p) for p in (a_port, b_port)):
            log.warning("dropped a link with a port name that isn't one: %r / %r", a_port[:60], b_port[:60])
            return  # neighbours advertise these names; the design writes them into `interface <name>` lines
        k = frozenset([(str(a), a_port), (str(b), b_port)])  # both ends report the same link once
        if k not in seen:
            seen.add(k)
            edges.append({"from": a, "to": b, "from_port": a_port, "to_port": b_port,
                          "label": f"{a_port} - {b_port}", "title": via})

    for dev_id, nbrs in neighbors.items():
        for n in nbrs:
            add(dev_id, n["local_port"], node_for(n), n["remote_port"], n["via"])
    for n in sniffed:
        add(ME, "nic", node_for(n), n["remote_port"], n["via"])
    edges, shared = point_to_point(edges)
    return {"nodes": list(nodes.values()), "edges": edges, "shared": shared}


def point_to_point(edges: list[dict]) -> tuple[list[dict], int]:
    """Cabled links only. A port that hears several neighbours sits on a shared segment (an out-of-band management
    switch, a hub, a dumb switch in between; on IOL every e0/0 shares one bridge, which drew a 66-line mesh for
    12 boxes). Such a "link" is no cable and can't carry a trunk. Returns (links, how many were dropped)."""
    hears = {}
    for e in edges:
        hears.setdefault((e["from"], e["from_port"]), set()).add(e["to"])
        hears.setdefault((e["to"], e["to_port"]), set()).add(e["from"])
    keep = [e for e in edges
            if len(hears[(e["from"], e["from_port"])]) == 1 and len(hears[(e["to"], e["to_port"])]) == 1]
    return keep, len(edges) - len(keep)


def _ssh_neighbors(ctx, dev) -> list[dict]:
    rows = ctx.ssh_command(dev, "show cdp neighbors detail", use_textfsm=True)
    if not isinstance(rows, list):
        return []
    return [{"local_port": r.get("local_port") or r.get("local_interface", ""),
             "remote_name": (r.get("destination_host") or r.get("neighbor_name") or "").split(".")[0],
             "remote_port": r.get("remote_port") or r.get("neighbor_interface", ""),
             "platform": r.get("platform", ""),
             "remote_ip": r.get("management_ip") or r.get("mgmt_address"), "via": "cdp-ssh"} for r in rows]


async def collect(ctx) -> dict:
    devices = [d for d in ctx.db.devices() if d["ip"]]
    async def one(d):
        try:
            return d["id"], await snmp.neighbors(d["ip"], snmp.auth(ctx.cfg, dev=d))
        except Exception:
            try:
                return d["id"], await asyncio.to_thread(_ssh_neighbors, ctx, d)
            except Exception as e:
                log.info("no neighbors for %s: %s", d["ip"], e)
                return d["id"], []

    results = dict(await asyncio.gather(*(one(d) for d in devices if d["state"] in ("provisioned", "identified"))))
    backbones = {r["backbone_id"] for r in ctx.db.q("SELECT backbone_id FROM mgmt_domains")}
    return build(ctx.db.devices(), results, ctx.sniffed, backbones)
