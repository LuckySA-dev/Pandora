"""Management network design, after pre-config: one or more L3 backbones, each owning a management domain
(VLAN + subnet, its SVI is the gateway); every other device gets its own SSH address in its backbone's domain.

    PC (ops VLAN, e.g. 99) ── backbone A (ip routing, SVI in A's VLAN = gateway) ── members of A (SVI / subif)
                           └─ backbone B (same, + routes to A's domain via A's ops IP) ── members of B

The ops VLAN is the pre-config management VLAN: every device already has an address there, so the PC keeps
reaching everything while the design is pushed (make-before-break: nothing is removed). Which ports become
trunks comes from the real CDP topology (shortest path from each member to its backbone, through switches).
"""
import ipaddress
import logging
import re
import time
from collections import deque
from concurrent.futures import ThreadPoolExecutor

from . import access, alloc, backup, config, topology

log = logging.getLogger("pandora.mgmt")
# Any IOS "%" answer is a failure except a warning ("% Command rejected", "% Invalid input", "% ... overlaps ...")
ERROR = re.compile(r"^\s*%(?!\s*Warning)", re.I)


def ops_net(cfg):
    """The pre-config management subnet (where mgmt_range lives): the PC's network."""
    return ipaddress.ip_network(f"{config.ip_range(cfg['mgmt_range'])[0]}/{cfg['netmask']}", strict=False)


def is_router(d) -> bool:
    return d.get("role") == "router_edge"


def graph(edges) -> dict:
    """CDP edges between known devices -> {device: [(neighbor, my_port, its_port)]}, point-to-point links only.
    A port that hears several neighbors is a shared segment (an out-of-band management switch, a hub, a dumb
    switch in between): seen on real IOL, where every e0/0 sits on one bridge. It can't be a trunk link."""
    g = {}
    for e in topology.point_to_point(edges)[0]:
        if isinstance(e["from"], int) and isinstance(e["to"], int):
            g.setdefault(e["from"], []).append((e["to"], e["from_port"], e["to_port"]))
            g.setdefault(e["to"], []).append((e["from"], e["to_port"], e["from_port"]))
    return g


def bfs(g, start, through=lambda n: True) -> dict:
    """Shortest paths from `start`: {node: [(u, u_port, v, v_port), ...] hops from node back to start}."""
    paths, q = {start: []}, deque([start])
    while q:
        u = q.popleft()
        if u != start and not through(u):
            continue  # reachable, but the management VLAN can't be bridged on through it
        for v, pu, pv in sorted(g.get(u, []), key=lambda t: (str(t[0]), t[1])):
            if v not in paths:
                paths[v] = [(v, pv, u, pu)] + paths[u]
                q.append(v)
    return paths


def _switch(devs):
    return lambda n: n in devs and not is_router(devs[n])


def suggest(devices, backbones, edges) -> dict:
    """Each device under its nearest backbone (fewest CDP hops, bridging only through switches)."""
    g, devs = graph(edges), {d["id"]: d for d in devices}
    best = {}
    for b in backbones:
        for n, hops in bfs(g, b, _switch(devs)).items():
            if n not in backbones and n in devs and (n not in best or len(hops) < best[n][1]):
                best[n] = (b, len(hops))
    return {n: b for n, (b, _) in best.items()}


def ensure_caps(ctx, ids) -> None:
    """Backbones must route. Boxes pre-configured over SSH/console were already asked (cap_ip_routing); a PnP or
    AutoInstall box never was: ask it now, over SSH. A box that doesn't answer stays unknown (plan says so).
    Every box is also asked whether it routes right now (ip_routing_on): `ip routing` is hidden from the
    running-config when it is the image's default (IOL L2 has it on), and a routing box ignores
    `ip default-gateway`. Seen on IOL: members only answered through the old ops-VLAN connected route."""
    def one(i):
        try:
            if "cap_ip_routing" not in ctx.db.vars(i):
                _, caps = ctx.probe(ctx.db.device(i))
                ctx.db.set_vars(i, {**ctx.db.vars(i), **caps})
            out = ctx.ssh_command(ctx.db.device(i), "show ip route | include Default gateway|Gateway of last resort")
            if "ateway" in out:
                ctx.db.set_vars(i, {**ctx.db.vars(i), "ip_routing_on": "Gateway of last resort" in out})
        except Exception as e:
            log.info("capability probe of device %s failed: %s", i, e)
    with ThreadPoolExecutor(max_workers=16) as ex:
        list(ex.map(one, ids))


def plan(ctx, domains: list[dict], members: dict, edges: list[dict]) -> dict:
    """domains: [{backbone, vlan, subnet}], members: {device_id: backbone_id}. Nothing is pushed here."""
    cfg, db = ctx.cfg, ctx.db
    devs = {d["id"]: d for d in db.devices()}
    ops, ops_vlan = ops_net(cfg), int(cfg["mgmt_vlan"])
    problems, out = [], {}
    members = {int(k): int(v) for k, v in members.items() if v not in (None, "")}

    def ops_ip(i):
        r = db.q("SELECT mgmt_ip FROM allocations WHERE device_id=?", i)
        return r[0]["mgmt_ip"] if r else None

    def name(i):
        return devs[i]["hostname"] if i in devs and devs[i]["hostname"] else f"#{i}"

    dom, seen_nets = {}, [ops]
    for d in domains:
        b, vlan = int(d["backbone"]), int(d["vlan"])
        try:
            net = ipaddress.ip_network(str(d["subnet"]), strict=False)
        except ValueError as e:
            problems.append(f"{name(b)}: subnet {d['subnet']!r}: {e}")
            continue
        if b not in devs or devs[b]["state"] != "provisioned":
            problems.append(f"backbone {name(b)} is not a pre-configured device")
        elif is_router(devs[b]):
            problems.append(f"{name(b)} is an edge router: a backbone must be an L3 switch (VLANs + SVIs)")
        elif not ops_ip(b):
            problems.append(f"{name(b)} has no address in the management VLAN {ops_vlan}")
        elif (l3 := db.vars(b).get("cap_ip_routing")) is False:
            problems.append(f"{name(b)} is a layer-2-only switch (its IOS has no `ip routing`): pick an L3 switch")
        elif l3 is None:
            problems.append(f"could not check whether {name(b)} can route (no SSH answer): check it, then try again")
        if not 2 <= vlan <= 4094 or vlan == ops_vlan or vlan in {x["vlan"] for x in dom.values()}:
            problems.append(f"{name(b)}: VLAN {vlan} is not free (1, {ops_vlan} and the other domains' VLANs are taken)")
        if any(net.overlaps(n) for n in seen_nets):
            problems.append(f"{name(b)}: {net} overlaps the PC's network {ops} or another domain")
        if net.num_addresses < 16:
            problems.append(f"{name(b)}: {net} is too small (use /28 or bigger)")
        seen_nets.append(net)
        dom[b] = {"backbone": b, "vlan": vlan, "subnet": str(net), "net": net, "gateway": str(next(net.hosts())),
                  "ops_ip": ops_ip(b)}
    if not dom:
        problems.append("choose at least one backbone")
        return {"ok": False, "problems": problems, "devices": [], "pc_routes": [], "domains": [], "members": {}}

    # addresses: the gateway is the first host; members from the 10th up, keeping what an earlier design gave them
    kept = {r["device_id"]: r["ip"] for r in db.q("SELECT device_id, ip FROM mgmt_members")}
    taken = {b: {x["gateway"]} for b, x in dom.items()}
    ips = {}
    for m, b in sorted(members.items()):
        if b not in dom:
            problems.append(f"{name(m)}: its backbone #{b} is not in the design")
            continue
        if m in dom:
            problems.append(f"{name(m)} is a backbone and can't be a member too")
            continue
        net, old = dom[b]["net"], kept.get(m)
        if old and ipaddress.ip_address(old) in net and old not in taken[b]:
            ips[m] = old
        else:
            others = {v for k, v in kept.items() if k != m}
            ips[m] = next((str(h) for h in list(net.hosts())[9:] if str(h) not in taken[b] | others), None)
            if not ips[m]:
                problems.append(f"{net} has no free address left for {name(m)}")
                del ips[m]
                continue
        taken[b].add(ips[m])

    # trunks along CDP paths: member -> its backbone (domain VLAN + ops VLAN), backbone -> first backbone (ops)
    g = graph(edges)
    trunk: dict[int, dict[str, set]] = {}
    subif: dict[int, tuple] = {}
    reserved = {r["device_id"]: {alloc.normalize_if(r["port"]) for r in db.q(
        "SELECT * FROM reserved_ports WHERE device_id=?", r["device_id"])} for r in db.q(
        "SELECT DISTINCT device_id FROM reserved_ports")}

    def carry(hops, vlans, member=None):
        for k, (u, pu, v, pv) in enumerate(hops):
            for x, p in ((u, pu), (v, pv)):
                if alloc.normalize_if(p) in reserved.get(x, set()):
                    problems.append(f"{name(x)} {p} is a reserved PC port but sits on a management path")
                if x in devs and is_router(devs[x]):
                    if x == member and k == 0 and x == u:
                        subif[x] = (p, vlans[0])  # the router itself, on its uplink: a dot1Q subinterface
                    else:
                        problems.append(f"the path for {name(member or x)} crosses router {name(x)}: routers "
                                        "can't carry the management VLAN on; cable it to a switch")
                    continue
                trunk.setdefault(x, {}).setdefault(p, set()).update(vlans)

    for m, b in members.items():
        if m not in ips:
            continue
        hops = bfs(g, b, _switch(devs)).get(m)
        if hops is None:
            problems.append(f"{name(m)} has no CDP path to {name(b)} through switches: check the cabling")
            continue
        carry(hops, [dom[b]["vlan"], ops_vlan], member=m)
    first = next(iter(dom))
    for b in dom:
        if b != first:
            hops = bfs(g, first, _switch(devs)).get(b)
            if hops is None:
                problems.append(f"backbone {name(b)} has no CDP path to {name(first)}")
            else:
                carry(hops, [ops_vlan])

    def routes(gw, own):
        nets = [ops] + [x["net"] for x in dom.values() if x["net"] != own]
        return [f"ip route {n.network_address} {n.netmask} {gw}" for n in nets]

    def routing(i):  # a member with ip routing on ignores ip default-gateway (ensure_caps asked it)
        if "ip_routing_on" in db.vars(i):
            return db.vars(i)["ip_routing_on"]
        b = backup.latest(db, i)
        return bool(b and "\nip routing" in "\n" + b["text"])

    def vlan_lines(vlans):
        return sum(([f"vlan {v}", f" name PANDORA-MGMT-{v}"] for v in vlans), [])

    for i in sorted(set(dom) | set(ips) | set(trunk) | set(subif)):
        lines, role, new_ip = [], "transit", None
        vlans = sorted({v for ps in trunk.get(i, {}).values() for v in ps} - {ops_vlan})
        if i in dom:
            x, role, new_ip = dom[i], "backbone", dom[i]["gateway"]
            lines += ["ip routing"] + vlan_lines(sorted(set(vlans) | {x["vlan"]}))
            lines += [f"interface Vlan{x['vlan']}", " description PANDORA-MGMT domain gateway",
                      f" ip address {x['gateway']} {x['net'].netmask}", " no shutdown"]
            lines += [f"ip route {o['net'].network_address} {o['net'].netmask} {o['ops_ip']}"
                      for o in dom.values() if o is not x]
            lines += [f"snmp-server source-interface informs Vlan{x['vlan']}"]  # informs from its PandoraBox address
        elif i in ips:
            x, role, new_ip = dom[members[i]], "member", ips[i]
            if i in subif:
                port, v = subif[i]
                lines += [f"interface {port}.{v}", f" description PANDORA-MGMT via {name(x['backbone'])}",
                          f" encapsulation dot1Q {v}", f" ip address {new_ip} {x['net'].netmask}"]
                lines += routes(x["gateway"], x["net"]) + [f"snmp-server source-interface informs {port}.{v}"]
            else:
                lines += vlan_lines(sorted(set(vlans) | {x["vlan"]}))
                lines += [f"interface Vlan{x['vlan']}", f" description PANDORA-MGMT via {name(x['backbone'])}",
                          f" ip address {new_ip} {x['net'].netmask}", " no shutdown"]
                lines += routes(x["gateway"], x["net"]) if routing(i) else [f"ip default-gateway {x['gateway']}"]
                lines += [f"snmp-server source-interface informs Vlan{x['vlan']}"]
        else:
            lines += vlan_lines(vlans)
        for p, vs in sorted(trunk.get(i, {}).items()):
            lines += [f"interface {p}", " switchport mode trunk",
                      f" switchport trunk allowed vlan add {','.join(map(str, sorted(vs)))}"]
        out[i] = {"id": i, "hostname": name(i), "role": role, "new_ip": new_ip, "lines": lines,
                  "trunks": sorted(trunk.get(i, {})), "backbone": members.get(i, i if i in dom else None)}
    pc = [{"subnet": x["subnet"], "via": x["ops_ip"], "backbone": name(b)} for b, x in dom.items()]
    return {"ok": not problems, "problems": sorted(set(problems)), "devices": list(out.values()), "pc_routes": pc,
            "domains": [{k: v for k, v in x.items() if k != "net"} for x in dom.values()], "members": ips,
            "ops_subnet": str(ops), "ops_vlan": ops_vlan}


def _trunk_extras(ctx, dev, port) -> list[str]:
    """What a switch port needs before `switchport mode trunk`: dot1q where ISL is possible, and the data VLAN it
    carried as an access port kept untagged (native), so the link's own traffic doesn't move to VLAN 1."""
    out = ctx.ssh_command(dev, f"show interfaces {port} switchport")
    extra = []
    if re.search(r"Trunking Encapsulation: (negotiate|isl)", out):
        extra.append(" switchport trunk encapsulation dot1q")
    if "Administrative Mode: static access" in out and (m := re.search(r"Access Mode VLAN: (\d+)", out)):
        if m.group(1) != "1":
            extra.append(f" switchport trunk native vlan {m.group(1)}")
    return extra


def _push(ctx, d) -> dict:
    dev = ctx.db.device(d["id"])
    lines = []
    try:
        for ln in d["lines"]:
            lines.append(ln)
            if ln.startswith("interface ") and ln[len("interface "):] in d["trunks"]:
                lines += _trunk_extras(ctx, dev, ln[len("interface "):])
        out = ctx.ssh_config(dev, lines)
    except Exception as e:
        return {"id": d["id"], "pushed": False, "error": f"{type(e).__name__}: {e}", "lines": d["lines"]}
    errors = [ln.strip() for ln in out.splitlines() if ERROR.match(ln)]
    ctx.db.save_config(d["id"], "mgmt", "\n".join(lines), "; ".join(errors) or "ok")
    return {"id": d["id"], "pushed": not errors, "error": "; ".join(errors), "lines": lines}


def _stp_settled(ctx, d) -> bool:
    """No port of this switch still listening/learning (classic PVST takes ~30 s per newly allowed VLAN). Asked over
    the address PandoraBox already uses, which the new trunks don't touch. Routers and errors don't block."""
    if not d["trunks"]:
        return True
    try:
        out = ctx.ssh_command(ctx.db.device(d["id"]), "show spanning-tree | include  LIS | LRN ")
    except Exception:
        return True
    return not re.search(r"\s(LIS|LRN)\s", out)


def apply(ctx, p: dict, verify_timeout=None) -> list[dict]:
    """Backbones first (the gateways must exist), then everyone else in parallel; then check SSH on every new
    address and only then make it the device's address in PandoraBox."""
    res = {}
    with ThreadPoolExecutor(max_workers=16) as ex:
        for wave in ([d for d in p["devices"] if d["role"] == "backbone"],
                     [d for d in p["devices"] if d["role"] != "backbone"]):
            for r in ex.map(lambda d: _push(ctx, d), wave):
                res[r["id"]] = r
    with ctx.db.lock:
        ctx.db.x("DELETE FROM mgmt_domains")
        ctx.db.x("DELETE FROM mgmt_members")
        ctx.db.x("DELETE FROM mgmt_config")
        for i, r in res.items():  # what compliance expects from now on (also when a push failed: that's drift)
            ctx.db.x("INSERT INTO mgmt_config (device_id, lines) VALUES (?,?)", i, "\n".join(r.pop("lines")))
        for x in p["domains"]:
            ctx.db.x("INSERT INTO mgmt_domains (backbone_id, vlan, subnet, gateway) VALUES (?,?,?,?)",
                     x["backbone"], x["vlan"], x["subnet"], x["gateway"])
        backbone_of = {d["id"]: d["backbone"] for d in p["devices"]}
        for m, ip in p["members"].items():
            ctx.db.x("INSERT INTO mgmt_members (device_id, backbone_id, ip) VALUES (?,?,?)",
                     int(m), backbone_of[int(m)], ip)

    # Stable, not lucky: right after the design, spanning tree is still settling on the new trunks and SYNs or
    # whole seconds of a session get lost (seen on real IOL; steady state afterwards: 60/60 logins clean). A member's
    # path crosses other switches, so wait until *every* switch in the design is settled before judging anyone.
    # 40 IOL / 76 trunks took longer than 150 s; the window grows with the design.
    end = time.time() + (verify_timeout or 150 + 5 * len(p["devices"]))
    pending = [d for d in p["devices"] if res[d["id"]]["pushed"]]
    while pending and time.time() < end:
        with ThreadPoolExecutor(max_workers=16) as ex:
            pending = [d for d, ok in zip(pending, ex.map(lambda d: _stp_settled(ctx, d), pending), strict=True) if not ok]
        if pending:
            time.sleep(5)

    def verify(d):
        r = res[d["id"]]
        if not d["new_ip"] or not r["pushed"]:
            return
        good, stop = 0, max(end, time.time() + 60)  # still a fair try if the settle wait used the window up
        while time.time() < stop and good < 3:
            good = good + 1 if access.ssh_open(d["new_ip"]) else 0
            time.sleep(3)
        r["reachable"] = good >= 3
        if r["reachable"]:  # from now on PandoraBox talks to it through its management domain
            ctx.db.update(d["id"], ip=d["new_ip"], note=f"management design: SSH on {d['new_ip']}")
            ctx.emit("device", ctx.db.device(d["id"]))
    with ThreadPoolExecutor(max_workers=16) as ex:
        list(ex.map(verify, p["devices"]))
    ctx.db.audit("user", "mgmt-design", {"domains": p["domains"], "results": list(res.values())})
    return [{**res[d["id"]], "hostname": d["hostname"], "new_ip": d["new_ip"], "role": d["role"]} for d in p["devices"]]


def retire(ctx) -> list[dict]:
    """Remove the old ops-VLAN address from members that already answer on their domain address (PandoraBox talks
    to them there: devices.ip == mgmt_members.ip). Backbones keep theirs: it is the PC's way in. The reserved PC
    ports stay in the ops VLAN. From then on compliance expects `no ip address` there (vars ops_retired).

    Not optional in practice: while a member still has its ops address, the PC's packets reach it through the
    backbone (domain VLAN) but its replies leave on the connected ops VLAN. No switch then learns the member's
    domain-VLAN MAC and every packet to it is flooded through the whole domain (asymmetric-routing unicast
    flood; on IOL it collapsed the emulated links: lost BPDUs, RSTP churn, 17-47 % loss). Before removing, the
    member must reach its own gateway over the domain VLAN, or it keeps the old address."""
    def one(m):
        i, r = m["device_id"], {"id": m["device_id"], "hostname": m["hostname"]}
        if m["now"] != m["ip"] or not access.ssh_open(m["ip"]):
            return {**r, "retired": False, "error": f"not reached on {m['ip']} yet: kept its old address"}
        try:
            out = ctx.ssh_command(ctx.db.device(i), f"ping {m['gateway']} repeat 3 timeout 1")
        except Exception as e:
            out = f"{type(e).__name__}: {e}"
        if not re.search(r"Success rate is [1-9]", out):
            return {**r, "retired": False, "error": f"can't reach its gateway {m['gateway']}: kept its old address"}
        ports = alloc.allocate(ctx.db, ctx.cfg, i)["reserved_ports"]
        gw = ctx.cfg.get("mgmt_gateway")
        if is_router(m):
            lines = [f"interface {ports[0]}", " no ip address"] + ([f"no ip route 0.0.0.0 0.0.0.0 {gw}"] if gw else [])
        else:
            lines = [f"interface Vlan{ctx.cfg['mgmt_vlan']}", " no ip address"] + (["no ip default-gateway"] if gw else [])
        try:
            res = ctx.ssh_config(ctx.db.device(i), lines)
            errors = [ln.strip() for ln in res.splitlines() if ERROR.match(ln)]
        except Exception as e:
            errors = [f"{type(e).__name__}: {e}"]
        if not errors:
            ctx.db.set_vars(i, {**ctx.db.vars(i), "ops_retired": True})
            ctx.db.save_config(i, "mgmt-retire", "\n".join(lines), "ok")
        return {**r, "retired": not errors, "error": "; ".join(errors)}

    rows = [m for m in ctx.db.q("SELECT m.device_id, m.ip, d.role, d.hostname, d.ip AS now, x.gateway FROM mgmt_members m "
                                "JOIN devices d ON d.id=m.device_id JOIN mgmt_domains x ON x.backbone_id=m.backbone_id")
            if not ctx.db.vars(m["device_id"]).get("ops_retired")]
    with ThreadPoolExecutor(max_workers=16) as ex:
        out = list(ex.map(one, rows))
    ctx.db.audit("user", "mgmt-retire", out)
    return out


def current(db) -> dict:
    rows = db.q("SELECT * FROM mgmt_members")
    return {"domains": db.q("SELECT * FROM mgmt_domains"),
            "members": {str(r["device_id"]): r["backbone_id"] for r in rows},
            "ips": {str(r["device_id"]): r["ip"] for r in rows}}
