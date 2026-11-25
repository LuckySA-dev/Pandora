"""Zero-touch checks against factory-blank Cisco IOL in containerlab (lab/ztp.clab.yml).

Runs inside the PandoraBox container, right after a fresh deploy (blank boxes boot only once this
script starts the console relay, i.e. after DHCP/TFTP/PnP are listening):
    docker exec -it clab-pandora-ztp-pandora python scripts/ztp_check.py
Nobody touches a console until PandoraBox decides to: a keypress aborts PnP on IOS-XE.
"""
import asyncio
import importlib.util
import json
import logging
import sys
import tempfile
import threading
import time
import traceback
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))

import uvicorn  # noqa: E402

from pandora import access, compliance, config, console  # noqa: E402
from pandora.app import create_app  # noqa: E402
from pandora.db import DB  # noqa: E402
from pandora.deliver import Ctx  # noqa: E402
from pandora.net import dhcp, tftp  # noqa: E402

BLANKS = {"blank1": 21, "blank2": 22, "blank3": 23}  # IOL_PID: console socket://127.0.0.1:50NN
PORT = 8099
RESULTS = []


def check(name):
    def deco(fn):
        t0 = time.time()
        try:
            detail = fn() or ""
            RESULTS.append((True, name))
            print(f"PASS  {name}  {detail}  ({time.time() - t0:.0f}s)", flush=True)
        except Exception as e:
            RESULTS.append((False, name))
            print(f"FAIL  {name}  {type(e).__name__}: {e}", flush=True)
            traceback.print_exc(limit=2)
        return fn
    return deco


def wait_for(pred, timeout, step=3, what="condition"):
    end = time.time() + timeout
    while time.time() < end:
        if v := pred():
            return v
        time.sleep(step)
    raise TimeoutError(what)


def start_relay():
    spec = importlib.util.spec_from_file_location("relay", ROOT / "lab/ztp/console_relay.py")
    relay = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(relay)
    threading.Thread(target=lambda: asyncio.run(relay.main(list(BLANKS.values()))), daemon=True).start()


def main():
    logging.basicConfig(level=logging.INFO, format="      %(asctime)s %(name)s %(message)s", datefmt="%X")
    logging.getLogger("tftpy").setLevel(logging.WARNING)
    work = Path(tempfile.mkdtemp(prefix="pandora-ztp-"))
    cfg = config.load(work / "none.toml")
    cfg.update(server_ip="10.99.0.1", netmask="255.255.255.0", http_port=PORT, site="ztp", iface="eth1",
               mgmt_range="10.99.0.10-10.99.0.40", dhcp_range="10.99.0.100-10.99.0.150", mgmt_gateway="",
               admin_password="Adm1nPass!", snmp_auth="AuthKey123", snmp_priv="PrivKey123",
               snmp_allow_auth_nopriv=True)
    ctx = Ctx(DB(str(work / "pandora.db")), cfg)
    app = create_app(ctx, background=False)
    threading.Thread(target=uvicorn.Server(uvicorn.Config(app, host="0.0.0.0", port=PORT, log_level="warning")).run,
                     daemon=True).start()
    dhcp.DhcpServer(cfg["server_ip"], cfg["netmask"], config.ip_range(cfg["dhcp_range"]),
                    ctx.dhcp_decide, cfg["iface"]).start()
    tftp.start(cfg["server_ip"], work / "tftp", ctx.tftp_lookup)
    time.sleep(1)
    ids = {}

    def mac(pid):  # IOL derives its MAC from IOL_PID
        return f"aa:bb:cc:00:{pid:02x}:00"

    def until_done(i, timeout, what):
        d = wait_for(lambda: (x := ctx.db.device(i))["state"] in ("provisioned", "failed") and x, timeout, 5, what)
        assert d["state"] == "provisioned", d["note"]
        assert wait_for(lambda: access.ssh_open(d["ip"]), 120, 5, f"SSH on {d['ip']}"), d["ip"]
        return d

    # The operator pre-staged blank3 by MAC for AutoInstall (before power-on): DHCP then offers it
    # option 150/67 instead of PnP's option 43.
    staged = ctx.db.upsert(mac=mac(BLANKS["blank3"]), path="autoinstall")
    rows = ctx.preview([staged["id"]], role="router_edge", ports={str(staged["id"]): "Ethernet0/0"})
    assert not rows[0]["problems"], rows[0]["problems"]
    assert ctx.queue([staged["id"]])[0]["queued"]
    ids["autoinstall"] = staged["id"]

    start_relay()  # = power on the blank boxes
    t_on = time.time()
    print(f"      services up, blank boxes powered on at {time.strftime('%X')}", flush=True)

    @check("discovery: blank routers ask for DHCP as PnP clients; nothing configured unasked")
    def _():
        d = wait_for(lambda: ctx.db.find(mac=mac(BLANKS["blank1"])), 300, 3, "DHCP from blank1")
        assert d["state"] in ("discovered", "identified") and d["path"] == "pnp", dict(d)
        ids["pnp"] = d["id"]
        return f"blank1 vc={d['vendor_class']!r} path={d['path']} after {time.time() - t_on:.0f}s"

    @check("PnP: the IOS-XE agent says HELLO and reports its UDI, gets backoff until selected")
    def _():
        d = wait_for(lambda: (x := ctx.db.device(ids["pnp"]))["serial"] and x, 300, 3, "PnP device-info")
        assert d["state"] == "identified", d["state"]
        return f"serial={d['serial']} pid={d['pid']} version={d['version']} os={d['os_type']}"

    @check("PnP: selected -> config-upgrade -> box applies it -> SSH on its new mgmt IP")
    def _():
        i = ids["pnp"]
        rows = ctx.preview([i], role="router_edge", ports={str(i): "Ethernet0/0"})
        assert not rows[0]["problems"], rows[0]["problems"]
        assert ctx.queue([i])[0]["queued"]
        d = until_done(i, 600, "PnP provisioning")
        return f"{d['hostname']} @ {d['ip']}: {d['note']}"

    @check("AutoInstall: pre-staged blank router gets option 150/67 -> TFTP config -> SSH on its new mgmt IP")
    def _():
        d = until_done(ids["autoinstall"], 600, "AutoInstall provisioning")
        return f"{d['hostname']} @ {d['ip']}: {d['note']}"

    @check("after PnP / AutoInstall: PandoraBox asks the image over SSH and merges the full config; compliant")
    def _():
        out = []
        for k in ("pnp", "autoinstall"):
            i = ids[k]
            row = wait_for(lambda i=i: ctx.db.q("SELECT result FROM configs WHERE device_id=? AND method='ssh-complete'",
                                            i), 180, 5, f"{k}: completion over SSH")[0]
            assert row["result"].startswith("capability"), row["result"]
            v = ctx.db.vars(i)
            assert "cap_vty_last" in v and "cap_traps_config" in v, v
            r = compliance.run(ctx, i)
            assert r["compliant"], [f for f in r["features"] if not f["compliant"]]
            out.append(f"{k}: vty 0-{v['cap_vty_last']}, traps config {v['cap_traps_config']}, compliant")
        return "; ".join(out)

    @check("console: blank L2 switch (no DHCP from this image) pre-configured over socket:// console")
    def _():
        url = f"socket://127.0.0.1:50{BLANKS['blank2']}"
        r = wait_for(lambda: (x := console.probe(url))["console_state"] != "unknown" and x, 120, 5, "console state")
        dev = ctx.db.upsert(console_port=url, source="console", path="console", note=f"console: {r['console_state']}",
                            **{k: v for k, v in r.items() if k != "console_state"})
        rows = ctx.preview([dev["id"]], role="switch_access", ports={str(dev["id"]): "Ethernet0/0"})
        assert not rows[0]["problems"], rows[0]["problems"]
        assert ctx.queue([dev["id"]])[0]["queued"]
        d = until_done(dev["id"], 600, "console provisioning")
        return f"state was {r['console_state']!r}; {d['hostname']} @ {d['ip']}: {d['note']}"

    ok = sum(r[0] for r in RESULTS)
    print("\n      inventory: " + json.dumps([{k: d[k] for k in ("id", "mac", "serial", "pid", "path", "state", "ip",
                                                                "vendor_class", "note")} for d in ctx.db.devices()],
                                          default=str), flush=True)
    print(f"\n{ok}/{len(RESULTS)} zero-touch checks passed against blank IOL", flush=True)
    return 0 if ok == len(RESULTS) else 1


if __name__ == "__main__":
    sys.exit(main())
