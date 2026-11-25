"""Day-2 checks against real Cisco IOL-XE nodes in containerlab.

Runs inside the lab's PandoraBox container, reading the lab's topology file:
    docker exec -it clab-pandora-small-pandora python scripts/clab_check.py [lab/small.clab.yml] [--serve]
    docker exec -it clab-pandora-medium-pandora python scripts/clab_check.py lab/medium.clab.yml
Every check talks to the real devices: SSH login, merge pre-config, backup, compliance + fix,
SNMPv3, CDP topology (every cabled link), web terminal. Devices are handled in parallel, as an operator
selecting a whole rack would. Prints PASS/FAIL and, on failure, what the device said.
"""
import asyncio
import json
import socket
import sys
import tempfile
import threading
import time
import traceback
from concurrent.futures import ThreadPoolExecutor
from pathlib import Path

import yaml

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))

import uvicorn  # noqa: E402

from pandora import access, backup, compliance, config, monitor, topology  # noqa: E402
from pandora.app import create_app  # noqa: E402
from pandora.db import DB  # noqa: E402
from pandora.deliver import Ctx  # noqa: E402

LOGIN = {"username": "admin", "password": "admin", "secret": "admin"}  # containerlab IOL default
PORT = 8099
RESULTS = []


def load_lab(path: Path) -> dict:
    """Nodes, roles, cabled links and one free port per node, straight from the containerlab file."""
    topo = yaml.safe_load(path.read_text())
    nodes = {n: v for n, v in topo["topology"]["nodes"].items() if v.get("kind", "cisco_iol") == "cisco_iol"}
    links, used, pc = set(), {n: set() for n in nodes}, {}
    for link in topo["topology"]["links"]:
        (a, pa), (b, pb) = (e.split(":") for e in link["endpoints"])
        if "pandora" in (a, b):  # PandoraBox's own cable: that port is the node's mgmt port (PC side)
            n, p = (b, pb) if a == "pandora" else (a, pa)
            pc[n] = p
            used[n].add(p)
        elif a in nodes and b in nodes:
            links.add(frozenset({(a, pa), (b, pb)}))
            used[a].add(pa)
            used[b].add(pb)

    def index(port):  # Ethernet<slot>/<port> -> ethN, the way the IOL container numbers them
        s, p = port.removeprefix("Ethernet").split("/")
        return int(s) * 4 + int(p)

    free = {}
    for n in nodes:  # the container starts with (highest eth + 4) // 4 slots; e0/0 is the clab mgmt port
        slots = (max([index(p) for p in used[n]] + [1]) + 4) // 4
        ports = [f"Ethernet{i // 4}/{i % 4}" for i in range(1, slots * 4)]
        free[n] = pc.get(n) or next(p for p in ports if p not in used[n])
    server = topo["topology"]["nodes"]["pandora"]["mgmt-ipv4"]
    return {"name": topo["name"], "server": server, "ips": {n: v["mgmt-ipv4"] for n, v in nodes.items()},
            "router": {n for n, v in nodes.items() if v.get("type") != "L2"}, "links": links, "used": used,
            "mgmt_port": free, "pc": pc,
            "backbones": {n: v["labels"]["pandora.backbone"].split() for n, v in nodes.items()
                          if "pandora.backbone" in (v.get("labels") or {})}}


def check(name):
    def deco(fn):
        t0 = time.time()
        try:
            detail = fn() or ""
            RESULTS.append((True, name))
            print(f"PASS  {name}  {detail}  ({time.time() - t0:.1f}s)", flush=True)
        except Exception as e:
            RESULTS.append((False, name))
            print(f"FAIL  {name}  {type(e).__name__}: {e}", flush=True)
            traceback.print_exc(limit=2)
        return fn
    return deco


def wait_for(pred, timeout, step=2, what="condition"):
    end = time.time() + timeout
    while time.time() < end:
        if v := pred():
            return v
        time.sleep(step)
    raise TimeoutError(what)


def pmap(fn, items):
    with ThreadPoolExecutor(max_workers=16) as ex:
        return list(ex.map(fn, items))


def main():
    args = [a for a in sys.argv[1:] if not a.startswith("--")]
    serve = "--serve" in sys.argv
    lab = load_lab(ROOT / (args[0] if args else "lab/small.clab.yml"))
    nodes, n_all = lab["ips"], len(lab["ips"])
    switch = next(n for n in nodes if n not in lab["router"])  # the L2 box used for the drift test
    router = next(n for n in nodes if n in lab["router"])
    print(f"      lab {lab['name']}: {n_all} IOL nodes, {len(lab['links'])} cabled links", flush=True)

    work = Path(tempfile.mkdtemp(prefix="pandora-clab-"))
    cfg = config.load(work / "none.toml")
    cfg.update(server_ip=lab["server"], netmask="255.255.255.0", http_port=PORT, site="clab",
               mgmt_range="10.99.0.10-10.99.0.99", admin_password="Adm1nPass!", snmp_auth="AuthKey123",
               snmp_priv="PrivKey123", ui_allow=["172.16.0.0/12"],
               snmp_allow_auth_nopriv=True)  # the IOL L2 image has no AES: authNoPriv on the switches
    ctx = Ctx(DB(str(work / "pandora.db")), cfg)
    app = create_app(ctx, background=False)
    server = uvicorn.Server(uvicorn.Config(app, host="0.0.0.0", port=PORT, log_level="warning"))
    threading.Thread(target=server.run, daemon=True).start()
    ids = {}

    @check("lab: every IOL node answers SSH")
    def _():
        pmap(lambda n: wait_for(lambda: access.ssh_open(nodes[n]), 900, 5, f"SSH on {n} {nodes[n]}"), nodes)
        # Lab prep, not PandoraBox: the IOL router image re-runs first-boot setup after containerlab's config
        # and shuts its "new" ports again, so the cabled router links would carry no CDP.
        from netmiko import ConnectHandler

        def up(n):
            with ConnectHandler(device_type="cisco_xe", host=nodes[n], **LOGIN) as c:
                c.send_config_set(sum(([f"interface {p}", " no shutdown"] for p in sorted(lab["used"][n])), []))
        pmap(up, lab["router"])
        return f"{n_all} nodes; cabled ports brought up on {', '.join(sorted(lab['router']))}"

    @check("add by IP + login, all nodes at once: logs in, reads model and IOS-XE version")
    def _():
        def add(n):
            return n, wait_for(lambda: _try(lambda: ctx.add_by_ssh(nodes[n], dict(LOGIN))), 300, 10, f"login {n}")
        for n, d in pmap(add, nodes):
            ids[n] = d["id"]
        assert all(ctx.db.device(i)["os_type"] == "iosxe" for i in ids.values()), "IOS type not recognised"
        d = ctx.db.device(ids[router])
        return f"{len(ids)} added; e.g. {router}={d['os_type']} {d['version']}"

    @check("preview: names/IPs unique, chosen mgmt port, no conflicts")
    def _():
        for n in lab["router"]:
            ctx.db.x("UPDATE devices SET role='router_edge' WHERE id=?", ids[n])
        rows = ctx.preview(list(ids.values()), ports={str(ids[n]): lab["mgmt_port"][n] for n in nodes})
        bad = {r["id"]: r["problems"] for r in rows if r["problems"]}
        assert not bad, bad
        assert len({r["hostname"] for r in rows}) == n_all and len({r["mgmt_ip"] for r in rows}) == n_all
        return ", ".join(f"{r['hostname']}={r['mgmt_ip']}" for r in rows[:4]) + (" ..." if n_all > 4 else "")

    @check("SSH merge pre-config on every node in parallel (hostname change, mgmt port, SNMPv3)")
    def _():
        t0 = time.time()
        res = ctx.queue(list(ids.values()))
        assert all(r["queued"] for r in res), res
        wait_for(lambda: all(ctx.db.device(i)["state"] in ("provisioned", "failed") for i in ids.values()), 900, 3,
                 "pushes to finish")
        took = time.time() - t0
        failed = {n: ctx.db.device(i)["note"] for n, i in ids.items() if ctx.db.device(i)["state"] != "provisioned"}
        assert not failed, failed
        run = ctx.ssh_command(ctx.db.device(ids[switch]), "show running-config")
        assert "description PANDORA-MGMT reserved" in run and "snmp-server group PANDORA v3 auth" in run, run[-1500:]
        assert "cap_snmp_priv" in ctx.db.vars(ids[switch]), "image caps were not probed"
        return f"{len(ids)} provisioned in {took:.0f}s"

    @check("backup + compliance on every real running-config")
    def _():
        res = dict(pmap(lambda n: (n, compliance.run(ctx, ids[n])), nodes))
        drift = {n: [f for f in r["features"] if not f["compliant"]] for n, r in res.items() if not r["compliant"]}
        for n, bad in drift.items():
            print(f"      {n}: DRIFT {json.dumps(bad)[:600]}", flush=True)
        assert not drift, f"real IOS output differs from intended on {sorted(drift)}"
        return f"{len(res)} compliant; {len(backup.history(ctx.db, ids[switch]))} backup(s) on {switch}"

    @check("drift on a real switch -> fix plan -> pushed -> compliant again")
    def _():
        i = ids[switch]
        ctx.ssh_config(ctx.db.device(i), [f"interface {lab['mgmt_port'][switch]}", " shutdown"])
        res = compliance.run(ctx, i)
        assert not res["compliant"] and " no shutdown" in res["remediation"], res
        fix = compliance.remediate(ctx, i)
        assert fix["result"]["compliant"], fix["result"]
        return f"{switch}: plan {len(res['remediation'])} lines"

    @check("SNMPv3 poll of every node with the user PandoraBox configured")
    def _():
        async def all_polls():
            return await asyncio.gather(*(monitor.poll_one(ctx, ctx.db.device(i)) for i in ids.values()))
        t0 = time.time()
        samples = asyncio.run(all_polls())
        ups = [sum(v == "up" for k, v in s.items() if k.endswith(":oper")) for s in samples]
        assert all(ups), dict(zip(ids, ups, strict=True))
        return f"{len(samples)} answered in {time.time() - t0:.1f}s, {sum(ups)} interfaces up"

    @check("topology from real CDP: every cabled link, on the right ports")
    def _():
        # every e0/0 sits on the containerlab mgmt bridge and sees all nodes: only cabled ports count
        want = {frozenset((ids[n], p) for n, p in link) for link in lab["links"]}

        def links():
            g = asyncio.run(topology.collect(ctx))
            got = {frozenset({(e["from"], e["from_port"]), (e["to"], e["to_port"])}) for e in g["edges"]}
            links.missing = want - got
            return g if not links.missing else None
        links.missing = want
        try:
            g = wait_for(links, 180, 10, "CDP on every cabled link")  # CDP speaks every 60 s
        except TimeoutError:
            name = {i: n for n, i in ids.items()}
            raise AssertionError(f"missing: {[sorted((name[a], p) for a, p in m) for m in links.missing]}") from None
        cabled = [e for e in g["edges"] if "0/0" not in e["label"]]
        return f"{len(cabled)}/{len(want)} cabled links seen, {len(g['nodes'])} nodes"

    @check("web terminal: real IOS prompt, backspace, show clock")
    def _():
        return asyncio.run(_terminal(ids[router]))

    if lab["backbones"] and lab["pc"]:
        mgmt_checks(ctx, lab, ids)

    ok = sum(r[0] for r in RESULTS)
    print(f"\n{ok}/{len(RESULTS)} checks passed against containerlab IOL ({lab['name']})", flush=True)
    if serve:
        print(f"UI on http://localhost:{PORT} (from Windows too)", flush=True)
        threading.Event().wait()
    return 0 if ok == len(RESULTS) else 1


def mgmt_checks(ctx, lab, ids):
    """The management design wizard's job, on real IOL: L3 backbones, members under them, SSH on new addresses."""
    import subprocess

    from netmiko import ConnectHandler

    from pandora import mgmt
    nodes, st = lab["ips"], {}
    bb = {ids[n]: v for n, v in lab["backbones"].items()}

    @check("management design: every node suggested under its nearest backbone (from CDP)")
    def _():
        # Lab prep, not PandoraBox: the routers' reserved mgmt ports aren't cabled here, but IOL shows unplugged
        # ports as up; shut them so they behave like real empty ports.
        def shut(n):
            with ConnectHandler(device_type="cisco_xe", host=nodes[n], **LOGIN) as c:
                c.send_config_set([f"interface {lab['mgmt_port'][n]}", " shutdown"])
        pmap(shut, [n for n in lab["router"] if n not in lab["pc"]])
        st["edges"] = asyncio.run(topology.collect(ctx))["edges"]
        st["members"] = mgmt.suggest(ctx.db.devices(), list(bb), st["edges"])
        name = {i: n for n, i in ids.items()}
        missing = [n for n in nodes if ids[n] not in bb and ids[n] not in st["members"]]
        assert not missing, f"no backbone suggested for {missing}"
        return "; ".join(f"{name[b]}: {', '.join(sorted(name[m] for m, x in st['members'].items() if x == b))}"
                         for b in bb)

    @check("management design: plan has no problems (domains, trunks from CDP, router subinterfaces)")
    def _():
        doms = [{"backbone": b, "vlan": int(v[0]), "subnet": v[1]} for b, v in bb.items()]
        st["plan"] = p = mgmt.plan(ctx, doms, st["members"], st["edges"])
        assert p["ok"], p["problems"]
        for r in p["pc_routes"]:  # what the wizard tells the operator to run on the PC
            subprocess.run(["ip", "route", "replace", r["subnet"], "via", r["via"], "dev", "eth1"], check=True)
        roles = [d["role"] for d in p["devices"]]
        return (f"{roles.count('backbone')} backbones, {roles.count('member')} members, "
                f"{sum(len(d['trunks']) for d in p['devices'])} trunk ports; PC routes " +
                ", ".join(f"{r['subnet']} via {r['via']}" for r in p["pc_routes"]))

    @check("management design applied: every device answers SSH on its new address in its domain")
    def _():
        t0 = time.time()
        res = mgmt.apply(ctx, st["plan"])
        bad = {r["hostname"]: r.get("error") or "not reachable" for r in res
               if not r["pushed"] or (r["new_ip"] and not r.get("reachable"))}
        assert not bad, bad
        moved = [d for d in ctx.db.devices() if d["ip"] and not d["ip"].startswith("172.30.")]
        assert len(moved) == len(nodes), [d["ip"] for d in ctx.db.devices()]
        return f"{len(res)} devices in {time.time() - t0:.0f}s, PandoraBox now reaches all of them through the domains"

    @check("after the design: login works through the domains and every node is still compliant")
    def _():
        out = pmap(lambda n: ctx.ssh_command(ctx.db.device(ids[n]), "show ip interface brief | include Vlan|[.]"),
                   nodes)
        assert all(out), "empty answer"
        res = dict(pmap(lambda n: (n, compliance.run(ctx, ids[n])), nodes))
        # the routers' only drift is the lab prep above (their unplugged reserved port shut): anything else is real
        drift = {n: [f["name"] for f in r["features"] if not f["compliant"]] for n, r in res.items() if not r["compliant"]}
        drift = {n: f for n, f in drift.items() if not (n in lab["router"] and f == ["mgmt-ports"])}
        assert not drift, drift
        designed = sum(any(f["name"] == "mgmt-design" for f in r["features"]) for r in res.values())
        assert designed == len(nodes), f"only {designed} nodes have their design lines checked"
        return (f"{len(nodes)} logins over the management domains; compliant incl. the design lines on all "
                f"{designed} (routers: only the lab's shut port)")

    @check("drift in the management design (a member lost its default gateway) -> detected -> fixed")
    def _():
        m = next(n for n in nodes if ids[n] not in bb and n not in lab["router"])
        gw = next(x["gateway"] for x in st["plan"]["domains"] if x["backbone"] == st["members"][ids[m]])
        ctx.ssh_config(ctx.db.device(ids[m]), [f"no ip default-gateway {gw}"])
        res = compliance.run(ctx, ids[m])
        bad = [f["name"] for f in res["features"] if not f["compliant"]]
        assert bad == ["mgmt-design"] and f"ip default-gateway {gw}" in res["remediation"], (bad, res["remediation"])
        fix = compliance.remediate(ctx, ids[m])
        assert fix["result"]["compliant"], fix["result"]
        return f"{m}: drift seen as mgmt-design, plan {res['remediation']}, compliant again"


def _try(fn):
    try:
        return fn()
    except Exception:
        return None


async def _terminal(device_id):
    import websockets
    async with websockets.connect(f"ws://127.0.0.1:{PORT}/ws/term/{device_id}?cols=120&rows=30",
                                  origin=f"http://127.0.0.1:{PORT}") as ws:
        out = ""
        t0 = time.time()
        await ws.send(json.dumps({"data": "\r"}))
        await ws.send(json.dumps({"data": "show clokc"}))
        await ws.send(json.dumps({"data": "\x7f\x7fck\r"}))
        end = time.time() + 15
        while time.time() < end and not ("UTC" in out or "Invalid" in out):
            try:
                m = await asyncio.wait_for(ws.recv(), 5)
            except asyncio.TimeoutError:
                break
            out += m.decode(errors="replace") if isinstance(m, bytes) else m
    assert "#" in out and "Invalid" not in out and ("UTC" in out or ":" in out), out[-400:]
    return f"answered in {time.time() - t0:.2f}s: {out.strip().splitlines()[-2][:60]!r}"


if __name__ == "__main__":
    socket.setdefaulttimeout(30)
    sys.exit(main())
