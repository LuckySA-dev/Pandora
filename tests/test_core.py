import socket
import threading
import time

import pytest
from conftest import add

from pandora import access, alloc, config, identify, snmp, topology
from pandora.agent import loop as agent_loop
from pandora.agent import tools as agent_tools
from pandora.db import DB, mask_secrets
from pandora.deliver import Ctx
from pandora.net import dhcp


# ---- allocation / guard ---------------------------------------------------------
def test_allocation_unique_even_in_parallel(ctx):
    devs = [add(ctx, i) for i in range(10)]
    threads = [threading.Thread(target=alloc.allocate, args=(ctx.db, ctx.cfg, d["id"])) for d in devs]
    [t.start() for t in threads]
    [t.join() for t in threads]
    rows = ctx.db.q("SELECT * FROM allocations")
    assert len(rows) == 10
    assert len({r["mgmt_ip"] for r in rows}) == 10 and len({r["hostname"] for r in rows}) == 10
    assert ctx.cfg["server_ip"] not in {r["mgmt_ip"] for r in rows}
    again = alloc.allocate(ctx.db, ctx.cfg, devs[0]["id"])  # idempotent
    assert again["mgmt_ip"] == next(r["mgmt_ip"] for r in rows if r["device_id"] == devs[0]["id"])


def test_pool_exhaustion(ctx):
    ctx.cfg["mgmt_range"] = "10.99.0.10-10.99.0.11"
    a, b, c = (add(ctx, i) for i in range(3))
    alloc.allocate(ctx.db, ctx.cfg, a["id"])
    alloc.allocate(ctx.db, ctx.cfg, b["id"])
    with pytest.raises(alloc.AllocError):
        alloc.allocate(ctx.db, ctx.cfg, c["id"])


def test_reserved_ports_by_pid():
    assert alloc.default_ports("C9300-24P", "switch_access", 2) == ["GigabitEthernet1/0/23", "GigabitEthernet1/0/24"]
    assert alloc.default_ports("WS-C2960-24TT-L", "switch_access", 1) == ["FastEthernet0/24"]
    assert alloc.default_ports("ISR4331/K9", "router_edge", 2) == ["GigabitEthernet0/0/1"]
    assert alloc.default_ports("UNKNOWN", "switch_access", 2) is None


def test_guard():
    res = ["GigabitEthernet1/0/23", "GigabitEthernet1/0/24"]
    g = lambda *lines: alloc.guard(list(lines), res, 99, ["pandora"])
    assert g("interface Gi1/0/5", " switchport access vlan 20") == []
    assert g("interface gi1/0/24")
    assert g("interface range Gi1/0/1 - 24")
    assert g("default interface GigabitEthernet1/0/23")
    assert g("interface Vlan99")
    assert g("no vlan 90-100")
    assert g("no username pandora")
    assert g("no snmp-server")
    assert g("no vlan 20") == []


# ---- existing access -------------------------------------------------------------
def test_access_checks():
    assert access.console_needs_login("\r\nUser Access Verification\r\n\r\nUsername: ")
    assert access.console_needs_login("Password:")
    assert not access.console_needs_login("Switch>")
    assert not access.console_needs_login("Would you like to enter the initial configuration dialog? [yes/no]: ")
    srv = socket.socket()
    srv.bind(("127.0.0.1", 0))
    srv.listen()
    port = srv.getsockname()[1]
    assert access.ssh_open("127.0.0.1", port)
    srv.close()
    assert not access.ssh_open("127.0.0.1", port, timeout=0.5)


# ---- DHCP: only queued devices get boot options ------------------------------------------
def discover(mac, vendor=b""):
    hdr = dhcp.HDR.pack(1, 1, 6, 0, 0x1234, 0, 0, *(b"\0" * 4,) * 4, bytes.fromhex(mac.replace(":", "")) + b"\0" * 10,
                        b"\0" * 64, b"\0" * 128, dhcp.MAGIC)
    opts = b"\x35\x01\x01" + (bytes([60, len(vendor)]) + vendor if vendor else b"") + b"\xff"
    return hdr + opts


def test_dhcp_gating(ctx):
    srv = dhcp.DhcpServer(ctx.cfg["server_ip"], "255.255.255.0", config.ip_range("10.99.0.100-10.99.0.110"),
                          ctx.dhcp_decide)
    # factory classic-IOS box, not selected: seen, no answer
    assert srv.handle(discover("aa:bb:cc:00:00:01")) is None
    dev = ctx.db.find(mac="aa:bb:cc:00:00:01")
    assert dev and dev["state"] == "discovered" and dev["path"] == "autoinstall"
    # PnP box: gets option 43 so it can identify itself, even unselected
    offer = dhcp.parse(srv.handle(discover("aa:bb:cc:00:00:02", b"ciscopnp")))
    assert offer["options"][43] == b"5A1N;B2;K4;I10.99.0.1;J80"
    # queued ZTP box: gets option 67
    ctx.db.x("UPDATE devices SET path='ztp' WHERE id=?", dev["id"])
    ctx.db.set_state(dev["id"], "queued")
    offer = dhcp.parse(srv.handle(discover("aa:bb:cc:00:00:01")))
    assert offer["options"][67].endswith(b"/ztp/bootstrap.py")
    assert offer["options"][53] == bytes([dhcp.OFFER])


# ---- PnP end to end -----------------------------------------------------------------------
UDI = "PID:C9300-24P,VID:V01,SN:FOC1111X0AA"


def wr(c="c1"):
    return (f'<?xml version="1.0"?><pnp xmlns="urn:cisco:pnp" version="1.0" udi="{UDI}">'
            f'<info xmlns="urn:cisco:pnp:work-info" correlator="{c}"><deviceId><udi>{UDI}</udi></deviceId></info></pnp>')


def resp(ok=True, extra=""):
    return (f'<pnp xmlns="urn:cisco:pnp" version="1.0" udi="{UDI}"><response correlator="c" success="{int(ok)}" '
            f'xmlns="urn:cisco:pnp:device-info">{extra}</response></pnp>')


def test_pnp_flow(ctx):
    from fastapi.testclient import TestClient

    from pandora.app import create_app
    c = TestClient(create_app(ctx))
    ctx.emit = lambda *a: None
    assert c.get("/pnp/HELLO").status_code == 200
    assert "urn:cisco:pnp:device-info" in c.post("/pnp/WORK-REQUEST", content=wr()).text
    c.post("/pnp/WORK-RESPONSE", content=resp(extra="<hardwareInfo><platformName>C9300-24P</platformName></hardwareInfo>"
                                                    "<imageInfo><versionString>17.9.4a</versionString></imageInfo>"))
    dev = ctx.db.find(serial="FOC1111X0AA")
    assert dev["os_type"] == "iosxe" and dev["state"] == "identified"
    assert "callbackAfter" in c.post("/pnp/WORK-REQUEST", content=wr()).text  # not selected: backoff only
    assert c.get("/cfg/FOC1111X0AA").status_code == 404                     # and no config for it
    ctx.db.set_state(dev["id"], "queued")
    r = c.post("/pnp/WORK-REQUEST", content=wr()).text
    assert "config-upgrade" in r and "/cfg/FOC1111X0AA" in r
    cfg = c.get("/cfg/FOC1111X0AA").text
    assert "hostname lab-sw-01" in cfg and "interface Vlan1\n no ip address" in cfg
    c.post("/pnp/WORK-RESPONSE", content=resp(True))
    assert "write memory" in c.post("/pnp/WORK-REQUEST", content=wr()).text
    c.post("/pnp/WORK-RESPONSE", content=resp(True))
    assert "<terminate/>" in c.post("/pnp/WORK-REQUEST", content=wr()).text
    dev = ctx.db.device(dev["id"])
    assert dev["state"] == "provisioned" and dev["hostname"] == "lab-sw-01"
    stored = ctx.db.q("SELECT text FROM configs WHERE device_id=?", dev["id"])[0]["text"]
    assert "Adm1nPass!" not in stored and "AuthKey123" not in stored


def test_ui_is_localhost_only(ctx):
    from fastapi.testclient import TestClient

    from pandora.app import create_app
    c = TestClient(create_app(ctx), client=("10.99.0.150", 5000))
    assert c.get("/api/devices").status_code == 403
    assert c.get("/pnp/HELLO").status_code == 200
    assert TestClient(create_app(ctx), client=("192.168.1.5", 5000)).get("/pnp/HELLO").status_code == 403


# ---- render ------------------------------------------------------------------------------
def test_render_and_conflicts(ctx):
    d = add(ctx, 1)
    ctx.db.set_vars(d["id"], {"vlans": [{"id": 10, "name": "USERS"}], "access_ports": [{"ports": "Gi1/0/1 - 20", "vlan": 10}]})
    text, problems, a = ctx.render(d["id"])
    assert problems == []
    assert "snmp-server user pandora PANDORA v3 auth sha AuthKey123 priv aes 128 PrivKey123" in text
    assert "interface GigabitEthernet1/0/24\n description PANDORA-MGMT reserved" in text
    assert "interface Vlan1\n" not in text  # not a factory bootstrap
    ctx.db.set_vars(d["id"], {"access_ports": [{"ports": "Gi1/0/1 - 24", "vlan": 10}]})
    assert any("reserved" in p for p in ctx.render(d["id"])[1])
    m = mask_secrets(text)
    assert "Adm1nPass!" not in m and "AuthKey123" not in m and "PrivKey123" not in m
    u = ctx.db.upsert(mac="00:00:00:00:00:99", pid="ODD-BOX")
    assert any("reserved ports" in p for p in ctx.render(u["id"])[1])


# ---- parsers ----------------------------------------------------------------------------------
XE = """Cisco IOS XE Software, Version 17.09.04a
Cisco IOS Software [Cupertino], Catalyst L3 Switch Software (CAT9K_IOSXE), Version 17.9.4a, RELEASE SOFTWARE
sw1 uptime is 1 hour
Model Number                       : C9300-24P
System Serial Number               : FOC1111X0AA"""
IOS = """Cisco IOS Software, C2960 Software (C2960-LANBASEK9-M), Version 15.0(2)SE11, RELEASE SOFTWARE (fc3)
Switch uptime is 5 minutes
cisco WS-C2960-24TT-L (PowerPC405) processor (revision B0) with 65536K bytes of memory.
Processor board ID FOC0000Y1BB"""


def test_parsers():
    assert identify.parse_show_version(XE) == {"os_type": "iosxe", "version": "17.09.04a", "hostname": "sw1",
                                               "serial": "FOC1111X0AA", "pid": "C9300-24P"}
    v = identify.parse_show_version(IOS)
    assert v["os_type"] == "ios" and v["pid"] == "WS-C2960-24TT-L" and v["serial"] == "FOC0000Y1BB"
    assert identify.parse_udi(UDI) == {"pid": "C9300-24P", "serial": "FOC1111X0AA"}
    assert identify.parse_inventory('NAME: "1", DESCR: "x"\nPID: C9300-24P  , VID: V01  , SN: FOC1') == \
        {"pid": "C9300-24P", "serial": "FOC1"}


def test_snmp_cdp_and_topology():
    b = snmp.CDP_CACHE
    walked = {f"{b}.6.10.1": "sw2.pandora.local", f"{b}.7.10.1": "GigabitEthernet1/0/1",
              f"{b}.8.10.1": "cisco C9200", f"{b}.4.10.1": bytes([10, 99, 0, 11])}
    nb = snmp.parse_cdp(walked, {"10": "Gi1/0/48"})
    assert nb == [{"local_port": "Gi1/0/48", "remote_name": "sw2", "remote_port": "GigabitEthernet1/0/1",
                   "platform": "cisco C9200", "remote_ip": "10.99.0.11", "via": "cdp"}]
    devs = [{"id": 1, "hostname": "sw1", "ip": "10.99.0.10", "state": "provisioned"},
            {"id": 2, "hostname": "sw2", "ip": "10.99.0.11", "state": "provisioned"}]
    # sw2 reports the same cable from its side, with the other naming style: still one edge
    back = [{"local_port": "Gi1/0/1", "remote_name": "sw1", "remote_port": "GigabitEthernet1/0/48", "via": "cdp"}]
    g = topology.build(devs, {1: nb, 2: back}, [])
    assert len(g["edges"]) == 1 and (g["edges"][0]["from"], g["edges"][0]["to"]) == (1, 2)
    g = topology.build(devs, {1: nb}, [{"remote_name": "core", "remote_port": "Te1/1/1", "via": "lldp"}])
    assert {n["id"] for n in g["nodes"]} >= {"PandoraBox", "ext:core"}


# ---- agent ---------------------------------------------------------------------------------------
# ---- review fixes ----------------------------------------------------------------------------------
def test_ui_rejects_foreign_origin_and_host(ctx):
    from fastapi.testclient import TestClient
    from starlette.websockets import WebSocketDisconnect

    from pandora.app import create_app
    c = TestClient(create_app(ctx))
    assert c.get("/api/devices").status_code == 200
    assert c.get("/api/devices", headers={"Origin": "https://evil.example"}).status_code == 403
    assert c.post("/api/provision", json={"ids": []}, headers={"Host": "rebind.evil.example"}).status_code == 403
    with pytest.raises(WebSocketDisconnect):
        with c.websocket_connect("/ws/term/1", headers={"Origin": "https://evil.example"}) as ws:
            ws.receive_text()


def test_newline_injection_blocked(ctx):
    d = add(ctx, 1, ip="10.99.0.10")
    with pytest.raises(ValueError):
        agent_tools.Tools(ctx).t_show(d["id"], "show clock\nconfigure terminal\ninterface Gi1/0/24\nshutdown")
    assert alloc.guard(["interface Gi1/0/5\ninterface Gi1/0/24"], ["Gi1/0/24"], 99, [])


def test_dhcp_lease_reuse_does_not_merge_devices(ctx):
    old = ctx.db.upsert(mac="aa:aa:aa:aa:aa:01", ip="10.99.0.100", serial="OLD1")
    srv = dhcp.DhcpServer(ctx.cfg["server_ip"], "255.255.255.0", ["10.99.0.100"], ctx.dhcp_decide)  # "restarted"
    srv.handle(discover("bb:bb:bb:bb:bb:02"))
    assert ctx.db.device(old["id"])["mac"] == "aa:aa:aa:aa:aa:01" and ctx.db.device(old["id"])["serial"] == "OLD1"
    new = ctx.db.find(mac="bb:bb:bb:bb:bb:02")
    assert new["id"] != old["id"] and new["ip"] == "10.99.0.100"


def test_existing_device_gets_no_guessed_ports_and_no_key_regen(ctx):
    d = add(ctx, 1)
    alloc.allocate(ctx.db, ctx.cfg, d["id"])  # factory guess: last two ports
    ctx.db.x("UPDATE devices SET path='ssh' WHERE id=?", d["id"])
    alloc.drop_default_ports(ctx.db, d["id"])
    assert any("reserved ports" in p for p in ctx.render(d["id"])[1])  # user must choose
    alloc.allocate(ctx.db, ctx.cfg, d["id"], ["Gi1/0/10"])
    alloc.drop_default_ports(ctx.db, d["id"])  # user-chosen ports survive
    text, problems, a = ctx.render(d["id"])
    assert problems == [] and a["reserved_ports"] == ["GigabitEthernet1/0/10"]
    assert "crypto key generate" not in text and "interface Vlan1\n" not in text
    assert "crypto key generate" in ctx.render(d["id"], factory=True)[0]


def test_pnp_requeue_after_failure(ctx):
    from fastapi.testclient import TestClient

    from pandora.app import create_app
    c = TestClient(create_app(ctx))
    ctx.emit = lambda *a: None
    c.post("/pnp/WORK-REQUEST", content=wr())
    c.post("/pnp/WORK-RESPONSE", content=resp(extra="<imageInfo><versionString>17.9.4a</versionString></imageInfo>"))
    dev = ctx.db.find(serial="FOC1111X0AA")
    ctx.db.set_state(dev["id"], "queued")
    assert "config-upgrade" in c.post("/pnp/WORK-REQUEST", content=wr()).text
    c.post("/pnp/WORK-RESPONSE", content=resp(False))
    assert ctx.db.device(dev["id"])["state"] == "failed"
    assert "callbackAfter" in c.post("/pnp/WORK-REQUEST", content=wr()).text
    ctx.db.set_state(dev["id"], "queued")  # user fixed it and pressed Pre-config again
    assert "config-upgrade" in c.post("/pnp/WORK-REQUEST", content=wr()).text


def test_iface_check_and_snmp_values():
    from pandora.__main__ import check_iface
    assert check_iface("Disabled", 0, "x")[0]
    assert not check_iface("Enabled", 0, "x")[0] and not check_iface("Disabled", 1, "x")[0]
    with snmp.engine() as e1, snmp.engine() as e2:
        assert e1 is not e2  # never shared: a dead host can't poison later requests
    # 10.x addresses start with 0x0a ("\n"): must stay bytes and decode as an IP
    assert snmp._text_or_bytes(bytes([10, 99, 0, 11])) == bytes([10, 99, 0, 11])
    assert snmp._ip(snmp._text_or_bytes(bytes([10, 99, 0, 11]))) == "10.99.0.11"
    assert snmp._ip(snmp._text_or_bytes(b"ABCD")) == "65.66.67.68"
    assert snmp._text_or_bytes(b"Cisco IOS XE\r\nVersion 17") == "Cisco IOS XE\r\nVersion 17"


class FakeProvider:
    def __init__(self, script):
        self.script, self.seen = script, []

    def step(self, user_text=None, results=None):
        self.seen.append(results)
        return self.script.pop(0)


def test_agent_loop_blocks_reserved_port_without_asking(ctx):
    d = add(ctx, 1, ip="10.99.0.10")
    p = FakeProvider([
        ("Looking.", [{"id": "1", "name": "list_devices", "args": {}}]),
        ("", [{"id": "2", "name": "apply_config",
               "args": {"device_id": d["id"], "lines": ["interface Gi1/0/24", "shutdown"], "reason": "test"}}]),
        ("Blocked, stopping.", []),
    ])
    agent_loop.run(ctx, "shut the mgmt port", provider=p)
    assert '"applied": false' in p.seen[2][0][2] and "reserved" in p.seen[2][0][2]
    kinds = [e[1]["kind"] for e in ctx.events if e[0] == "agent"]
    assert kinds[-1] == "done" and not any(e[0] == "approval" for e in ctx.events)


def test_approval_waits_for_human(ctx):
    got = {}
    t = threading.Thread(target=lambda: got.setdefault("ok", agent_tools.request_approval(ctx, {"lines": []}, 5)))
    t.start()
    time.sleep(0.2)
    assert "ok" not in got  # still waiting
    aid = next(e[1]["id"] for e in ctx.events if e[0] == "approval")
    agent_tools.answer(aid, True)
    t.join(2)
    assert got["ok"] is True


# ---- round 3: scenarios not covered before ---------------------------------------------------------
def test_claude_provider_tool_loop_shapes(monkeypatch):
    from types import SimpleNamespace as NS

    from pandora.agent import providers
    monkeypatch.setenv("ANTHROPIC_API_KEY", "sk-test-not-used")
    p = providers.Claude("claude-opus-5-5", "sys", [{"name": "list_devices", "description": "d", "input_schema": {}}])
    sent = []
    replies = [NS(stop_reason="tool_use", content=[NS(type="text", text="Looking."),
                                                     NS(type="tool_use", id="tu1", name="list_devices", input={})]),
               NS(stop_reason="end_turn", content=[NS(type="text", text="Done.")])]

    def create(**kw):
        sent.append({**kw, "messages": list(kw["messages"])})
        return replies.pop(0)
    p.client = NS(beta=NS(messages=NS(create=create)))
    text, calls = p.step(user_text="go")
    assert text == "Looking." and calls == [{"id": "tu1", "name": "list_devices", "args": {}}]
    text, calls = p.step(results=[("tu1", "list_devices", "[]", False)])
    assert text == "Done." and calls == []
    last = sent[1]["messages"]
    assert last[1]["role"] == "assistant" and last[1]["content"][1].type == "tool_use"  # full content kept
    assert last[2] == {"role": "user", "content": [{"type": "tool_result", "tool_use_id": "tu1",
                                                     "content": "[]", "is_error": False}]}
    assert sent[0]["extra_body"]["fallbacks"] == "default" and sent[0]["model"] == "claude-opus-5-5"


def test_claude_provider_refusal_and_missing_key(monkeypatch):
    from types import SimpleNamespace as NS

    from pandora.agent import providers
    for k in ("ANTHROPIC_API_KEY", "ANTHROPIC_AUTH_TOKEN"):
        monkeypatch.delenv(k, raising=False)
    monkeypatch.setenv("ANTHROPIC_PROFILE", "pandora-test-no-such-profile")
    with pytest.raises(RuntimeError, match="ANTHROPIC_API_KEY"):  # at creation (new SDKs) or first send (old)
        providers.Claude("claude-opus-5-5", "sys", []).step(user_text="x")
    monkeypatch.setenv("ANTHROPIC_API_KEY", "sk-test-not-used")
    p = providers.Claude("claude-opus-5-5", "sys", [])
    p.client = NS(beta=NS(messages=NS(create=lambda **kw: NS(stop_reason="refusal", content=[]))))
    assert p.step(user_text="x") == ("The model declined this request.", [])


def test_ollama_provider_shapes(monkeypatch):
    from pandora.agent import providers
    posts = []
    answers = [{"message": {"role": "assistant", "content": "",
                            "tool_calls": [{"function": {"name": "show", "arguments": '{"device_id": 1, "command": "show clock"}'}}]}},
               {"message": {"role": "assistant", "content": "It is noon."}}]

    class R:
        def __init__(self, data):
            self.data = data

        def raise_for_status(self):
            pass

        def json(self):
            return self.data

    def post(url, json, timeout):
        posts.append({**json, "messages": list(json["messages"])})  # snapshot: the list keeps growing
        return R(answers.pop(0))
    monkeypatch.setattr(providers.httpx, "post", post)
    p = providers.Ollama("qwen", "sys", [{"name": "show", "description": "d", "input_schema": {"type": "object"}}],
                         "http://127.0.0.1:11434/")
    text, calls = p.step(user_text="time?")
    assert calls[0]["name"] == "show" and calls[0]["args"] == {"device_id": 1, "command": "show clock"}
    assert posts[0]["tools"][0]["function"]["parameters"] == {"type": "object"}
    text, calls = p.step(results=[(calls[0]["id"], "show", "12:00", False)])
    assert text == "It is noon." and calls == []
    assert posts[1]["messages"][-1] == {"role": "tool", "content": "12:00", "tool_name": "show"}


def test_agent_rejected_change_is_not_applied(ctx):
    d = add(ctx, 1, ip="10.99.0.10")
    applied = []
    ctx.ssh_config = lambda dev, lines: applied.append(lines) or ""

    def reject_all():
        for _ in range(50):
            for aid in list(agent_tools.APPROVALS):
                agent_tools.answer(aid, False)
            time.sleep(0.05)
    threading.Thread(target=reject_all, daemon=True).start()
    out = agent_tools.Tools(ctx).run("apply_config", {"device_id": d["id"], "lines": ["interface Gi1/0/5", " shutdown"],
                                                       "reason": "test"})
    assert '"applied": false' in out and applied == []


def test_router_role_render(ctx):
    d = ctx.db.upsert(mac="00:00:00:00:01:01", pid="ISR4331/K9")
    ctx.db.x("UPDATE devices SET role='router_edge' WHERE id=?", d["id"])
    ctx.db.set_vars(d["id"], {"wan_port": "GigabitEthernet0/0/0", "wan_ip": "203.0.113.2 255.255.255.252",
                              "lan_port": "GigabitEthernet0/0/2", "lan_ip": "192.168.10.1 255.255.255.0"})
    text, problems, a = ctx.render(d["id"])
    assert problems == [] and a["reserved_ports"] == ["GigabitEthernet0/0/1"]
    assert "interface GigabitEthernet0/0/1\n description PANDORA-MGMT reserved\n ip address" in text
    assert "vlan 99" not in text and "interface Vlan" not in text
    assert "interface GigabitEthernet0/0/0\n description WAN\n ip address 203.0.113.2" in text
    ctx.db.set_vars(d["id"], {"lan_port": "Gi0/0/1", "lan_ip": "1.1.1.1 255.0.0.0"})  # the mgmt port!
    assert any("reserved" in p for p in ctx.render(d["id"])[1])


def test_restart_keeps_inventory_and_never_reuses_ips():
    import tempfile
    from pathlib import Path
    tmp_path = Path(tempfile.mkdtemp(prefix="pandora-test-"))
    cfg = config.load("does-not-exist.toml")
    cfg.update(admin_password="Adm1nPass!", snmp_auth="AuthKey123", snmp_priv="PrivKey123")
    path = str(tmp_path / "p.db")
    c1 = Ctx(DB(path), cfg)
    d1 = c1.db.upsert(mac="00:00:00:00:02:01", pid="C9300-24P")
    a1 = alloc.allocate(c1.db, cfg, d1["id"])
    c2 = Ctx(DB(path), cfg)  # "restart"
    assert c2.db.device(d1["id"])["mac"] == "00:00:00:00:02:01"
    d2 = c2.db.upsert(mac="00:00:00:00:02:02", pid="C9300-24P")
    a2 = alloc.allocate(c2.db, cfg, d2["id"])
    assert a2["mgmt_ip"] != a1["mgmt_ip"] and a2["hostname"] != a1["hostname"]
    assert alloc.allocate(c2.db, cfg, d1["id"]) == a1


def test_api_errors_are_clean(ctx):
    from fastapi.testclient import TestClient

    from pandora.app import create_app
    c = TestClient(create_app(ctx), raise_server_exceptions=False)
    d = add(ctx, 1)  # discovered, no IP yet
    r = c.post(f"/api/devices/{d['id']}/config", json={"text": "interface Gi1/0/5", "dry_run": True})
    assert r.status_code == 400 and "IP" in r.json()["error"]
    assert c.post("/api/devices/999/credentials", json={"username": "u", "password": "p"}).status_code == 404
    assert c.post("/api/snmp/poll/999").status_code in (404, 502)
