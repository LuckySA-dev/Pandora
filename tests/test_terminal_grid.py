"""Terminal protocol, paged/sorted device list, and the code adapted from Oxidized / hier_config."""
import json
import threading

from conftest import add

from pandora import alerts, compliance
from pandora.db import mask_secrets


class FakeLink:
    """Stands in for the SSH channel / console: records what the browser sent, answers like IOS."""

    def __init__(self):
        self.written, self.sizes, self.breaks, self.out = [], [], 0, [b"Switch#"]
        self.ev = threading.Event()

    def read(self):
        if self.out:
            return self.out.pop(0)
        self.ev.wait(0.05)
        return b""

    def write(self, b):
        self.written.append(b)
        if b.endswith(b"\r"):
            self.out.append(b"\r\n*12:00:00.000 UTC Tue Nov 24 2026\r\nSwitch#")

    def resize(self, cols, rows):
        self.sizes.append((cols, rows))

    def send_break(self):
        self.breaks += 1


def test_terminal_protocol_keys_resize_break_and_binary_output(ctx, monkeypatch):
    from fastapi.testclient import TestClient

    from pandora.api import terminal
    from pandora.app import create_app
    link = FakeLink()
    monkeypatch.setattr(terminal, "_open", lambda ctx, d, stack, cols, rows: (link.sizes.append((cols, rows)), link)[1])
    d = add(ctx, 1, ip="10.99.0.50")
    c = TestClient(create_app(ctx, background=False))
    with c.websocket_connect(f"/ws/term/{d['id']}?cols=132&rows=40") as ws:
        assert ws.receive_bytes() == b"Switch#"                          # raw bytes, binary frame
        ws.send_text(json.dumps({"data": "show clokc\x7f\x7fck\r"}))  # backspaces go to the device untouched
        out = ws.receive_bytes()
        ws.send_text(json.dumps({"resize": [200, 50]}))
        ws.send_text(json.dumps({"resize": [9999, -3]}))               # clamped, never passed through raw
        ws.send_text(json.dumps({"break": True}))
        ws.send_text(json.dumps({"data": "\x03"}))                     # Ctrl+C reaches the device
        ws.receive_bytes() if link.out else None
    assert b"UTC" in out
    assert link.written[0] == "show clokc\x7f\x7fck\r".encode()
    assert link.sizes[0] == (132, 40) and (200, 50) in link.sizes and (400, 5) in link.sizes
    assert link.breaks == 1 and b"\x03" in link.written


def test_terminal_without_ip_uses_console_or_says_why(ctx, monkeypatch):
    """Real 2960X found on COM7, delivery PnP, no IP yet: the terminal must not SSH to ip=None (10 s hang)."""
    import contextlib

    from pandora.api import terminal
    opened = []
    monkeypatch.setattr(terminal.console, "session", lambda port: (opened.append(port), contextlib.nullcontext(
        type("C", (), {"s": type("S", (), {"timeout": 1})()})()))[1])
    d = add(ctx, 1)
    ctx.db.x("UPDATE devices SET ip=NULL, path='pnp', console_port='COM7' WHERE id=?", d["id"])
    with contextlib.ExitStack() as stack:
        assert isinstance(terminal._open(ctx, ctx.db.device(d["id"]), stack, 80, 24), terminal._Console)
    assert opened == ["COM7"]
    ctx.db.x("UPDATE devices SET console_port=NULL WHERE id=?", d["id"])
    try:
        terminal._open(ctx, ctx.db.device(d["id"]), contextlib.ExitStack(), 80, 24)
        raise AssertionError("expected LookupError")
    except LookupError as e:
        assert "no IP address" in str(e)


def test_router_role_on_a_switch_pid_is_refused(ctx):
    d = add(ctx, 1)
    ctx.db.x("UPDATE devices SET pid='WS-C2960X-24PD-L', role='router_edge' WHERE id=?", d["id"])
    ctx.db.x("INSERT INTO reserved_ports VALUES (?, 'GigabitEthernet0/0', 'mgmt')", d["id"])
    _, problems, _ = ctx.render(d["id"])
    assert any("is a switch" in p for p in problems)
    ctx.db.x("UPDATE devices SET role='switch_access' WHERE id=?", d["id"])
    assert not any("is a switch" in p for p in ctx.render(d["id"])[1])


def test_console_error_note_quotes_ios_not_the_prompt():
    from pandora import console
    con = console.Console.__new__(console.Console)
    replies = {"interface GigabitEthernet0/0": "interface GigabitEthernet0/0\r\n"
               "                   ^\r\n% Invalid input detected at '^' marker.\r\n\r\nsw(config)#"}
    con.send = lambda line, quiet=1.0: replies.get(line, "sw(config)#")
    errors = con.configure("interface GigabitEthernet0/0\n description x\n")
    assert errors == ["interface GigabitEthernet0/0 -> % Invalid input detected at '^' marker."]


def test_failed_console_paste_is_not_saved():
    from pandora import console
    con, sent = console.Console.__new__(console.Console), []
    con.send = lambda line, quiet=1.0: (sent.append(line), "% Invalid input detected" if "Gi0/0" in line else "#")[1]
    assert con.configure("interface Gi0/0\nhostname x\n")
    assert "write memory" not in sent
    sent.clear()
    assert con.configure("hostname x\n") == [] and "write memory" in sent


def test_boot_path_queue_note_says_when_a_config_was_already_saved(ctx):
    d = add(ctx, 1)
    assert "no startup-config" in ctx._boot_hint(d, "pnp") and ctx._boot_hint(d, "ssh") == ""
    ctx.db.save_config(d["id"], "console", "hostname x", "failed")
    assert "write erase" in ctx._boot_hint(d, "pnp")


def test_terminal_open_failure_after_browser_left_is_quiet(ctx, monkeypatch):
    from fastapi.testclient import TestClient

    from pandora.api import terminal
    from pandora.app import create_app

    def boom(*a):
        raise TimeoutError("timed out")
    monkeypatch.setattr(terminal, "_open", boom)
    d = add(ctx, 1, ip="10.99.0.50")
    with TestClient(create_app(ctx, background=False)).websocket_connect(f"/ws/term/{d['id']}") as ws:
        assert b"TimeoutError: timed out" in ws.receive_bytes()


def test_busy_dhcp_or_tftp_port_stops_startup(tmp_path):
    """An old PandoraBox that never exited held 69 (TFTP thread died silently) while the new one shared 67."""
    import socket

    import pytest

    from pandora.net import dhcp, tftp
    first = dhcp.DhcpServer("127.0.0.1", "255.0.0.0", ["127.0.0.100"], lambda *a: None)
    try:
        first.bind()
    except PermissionError:
        pytest.skip("ports below 1024 need privileges here")
    try:
        with pytest.raises(OSError):
            dhcp.DhcpServer("127.0.0.1", "255.0.0.0", ["127.0.0.100"], lambda *a: None).bind()
    finally:
        first.sock.close()
    held = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    held.bind(("127.0.0.1", 69))
    try:
        with pytest.raises(OSError):
            tftp.start("127.0.0.1", tmp_path, lambda *a: None)
    finally:
        held.close()


def test_pnp_details_classic_ios_needs():
    """From a packet capture of a real 2960X (IOS 15.2(2)E7) doing PnP."""
    from pandora.net import dhcp, pnp
    for minutes in (1, None):
        assert "<reason>" in pnp.req_backoff("PID:X,SN:Y", "c1", minutes)   # else: fault, 5 s polling
    req = {"xid": 1, "flags": 0, "giaddr": b"\0" * 4, "chaddr": b"\0" * 16}
    siaddr = lambda pkt: pkt[20:24]
    assert siaddr(dhcp.build(req, dhcp.OFFER, "10.99.0.100", "10.99.0.1", {43: b"x"})) == b"\0\0\0\0"
    assert siaddr(dhcp.build(req, dhcp.OFFER, "10.99.0.100", "10.99.0.1", {150: b"x"})) == bytes([10, 99, 0, 1])


def test_pnp_config_download_closes_the_connection(ctx):
    from fastapi.testclient import TestClient

    from pandora.app import create_app
    d = ctx.db.upsert(serial="FOC2246V0W5", pid="WS-C2960X-24PD-L", ip="testclient", path="pnp")
    ctx.db.set_state(d["id"], "queued")
    r = TestClient(create_app(ctx, background=False)).get("/cfg/FOC2246V0W5")
    assert r.status_code == 200 and "hostname" in r.text and r.headers["connection"] == "close"


def test_ssh_can_still_talk_to_classic_ios():
    """A paramiko upgrade that drops SHA-1 kex / ssh-rsa locks PandoraBox out of IOS 15.x (seen with paramiko 5.1)."""
    import paramiko

    from pandora.hostkeys import legacy_ssh_missing
    assert legacy_ssh_missing() == []
    kex = paramiko.Transport._preferred_kex
    assert kex.index("diffie-hellman-group14-sha1") > kex.index("diffie-hellman-group14-sha256")  # modern first


def test_console_cable_does_not_change_a_known_boxs_delivery(ctx):
    from pandora.__main__ import remember_console
    d = ctx.db.upsert(serial="FOC2246V0W5", mac="70:18:a7:95:df:c0", source="dhcp", path="ssh")
    dev = remember_console(ctx.db, "COM7", {"console_state": "priv", "serial": "FOC2246V0W5"})
    assert dev["id"] == d["id"] and dev["path"] == "ssh" and dev["source"] == "dhcp" and dev["console_port"] == "COM7"
    new = remember_console(ctx.db, "COM8", {"console_state": "dialog"})
    assert new["id"] != d["id"] and new["path"] == "console" and new["source"] == "console"


def test_config_read_event_does_not_trigger_a_backup_loop(ctx, monkeypatch):
    """Real 2960X: `show running-config` (our own backup) sends ciscoConfigManEvent running -> commandSource."""
    import time

    from pandora import monitor
    base = "1.3.6.1.4.1.9.9.43.1.1.6.1."
    read = [("1.3.6.1.6.3.1.1.4.1.0", "1.3.6.1.4.1.9.9.43.2.0.1"), (base + "3.183", "1"), (base + "4.183", "3"),
            (base + "5.183", "2")]
    write = read[:3] + [(base + "5.184", "3")]
    assert not monitor.config_written(read) and monitor.config_written(write) and monitor.config_written([])
    runs, gate = [], threading.Event()
    monkeypatch.setattr(monitor, "_backup_and_check", lambda c, i: (runs.append(i), gate.wait(2)))
    d = add(ctx, 1, ip="10.99.0.10")
    monitor.on_trap(ctx, "10.99.0.10", "configChange", read)
    assert runs == []                                            # a read starts nothing
    for _ in range(10):                                          # a burst of real changes
        monitor.schedule_backup(ctx, d["id"], settle=0)
    time.sleep(0.2)
    gate.set()
    for _ in range(50):
        if d["id"] not in monitor._BACKUPS:
            break
        time.sleep(0.05)
    assert runs == [d["id"], d["id"]]                            # one run + one folded re-run, not ten threads


def test_compliance_reads_classic_ios_spellings():
    """Real 2960X 15.2(2)E7 running-config: split vty blocks and the hyphenated domain-lookup."""
    intended = "no ip domain lookup\nline vty 0 15\n login local\n transport input ssh\n"
    running = ("no ip domain-lookup\nline vty 0 4\n login local\n transport input ssh\n"
               "line vty 5 15\n login local\n transport input ssh\n")
    assert compliance.compare(intended, running, [], 99)["compliant"]
    res = compliance.compare(intended, running.replace("line vty 5 15\n login local", "line vty 5 15\n login"), [], 99)
    assert not res["compliant"] and "line vty 7 > login local" in res["features"][0]["missing"]


def test_paged_sorted_device_list(ctx):
    from fastapi.testclient import TestClient

    from pandora.app import create_app
    for i in range(1, 46):
        add(ctx, i, ip=f"10.99.0.{i + 100}")
    ctx.db.set_state(3, "failed", "boom")
    alerts.raise_(ctx, 7, "cpu", "average", "CPU 95%")
    c = TestClient(create_app(ctx, background=False))
    p1 = c.get("/api/devices", params={"page": 1, "per_page": 20, "sort": "ip"}).json()
    assert (p1["total"], p1["pages"], len(p1["items"])) == (45, 3, 20)
    assert p1["items"][0]["ip"] == "10.99.0.101" and p1["page_lengths"] == [20, 50, 100, 250, 500]
    p3 = c.get("/api/devices", params={"page": 3, "per_page": 20, "sort": "ip"}).json()
    assert len(p3["items"]) == 5 and p3["items"][-1]["ip"] == "10.99.0.145"
    desc = c.get("/api/devices", params={"page": 1, "per_page": 50, "sort": "ip", "order": "desc"}).json()
    assert desc["items"][0]["ip"] == "10.99.0.145" and desc["pages"] == 1
    worst = c.get("/api/devices", params={"page": 1, "sort": "severity"}).json()["items"][0]
    assert worst["id"] == 7 and worst["severity"] == "average"
    odd = c.get("/api/devices", params={"page": 99, "per_page": 10000}).json()
    assert odd["per_page"] == 500 and odd["page"] == 1                       # clamped like NetBox
    failed = c.get("/api/devices", params={"page": 1, "state": "failed"}).json()
    assert failed["total"] == 1 and failed["states"]["failed"] == 1 and failed["states"]["identified"] == 44
    assert isinstance(c.get("/api/devices").json(), list)                    # unpaged callers unchanged


def test_oxidized_secret_masking():
    cfg = "\n".join([
        "username admin privilege 15 secret 9 $9$abcdef", "enable secret 5 $1$xyz", "snmp-server community public RO",
        "snmp-server host 10.0.0.1 version 2c public", "snmp-server host 10.99.0.1 informs version 3 priv pandora",
        "line vty 0 4", " password 7 0822455D0A16", "tacacs-server key s3cret", "interface Gi1/0/1",
        " ip ospf authentication-key k3y", " standby 1 authentication md5 key-string hsrpk3y timeout 30",
        "key chain K", " key 1", "  key-string chainkey", " description keep me"])
    m = mask_secrets(cfg)
    for secret in ("$9$abcdef", "$1$xyz", "public", "0822455D0A16", "s3cret", "k3y", "hsrpk3y", "chainkey"):
        assert secret not in m, secret
    assert "snmp-server host 10.99.0.1 informs version 3 priv pandora" in m  # SNMPv3 host line untouched
    assert " description keep me" in m and "timeout 30" in m


def test_hier_config_rules_in_remediation():
    intended = "interface GigabitEthernet1/0/24\n description PANDORA-MGMT reserved\n switchport mode access\n no shutdown\n"
    running = "version 17.9\ninterface GigabitEthernet1/0/24\n description old text\n switchport mode trunk\n shutdown\nend\n"
    res = compliance.compare(intended, running, ["Gi1/0/24"], 99)
    rem = res["remediation"]
    assert rem[0] == "interface GigabitEthernet1/0/24"
    assert " no description old text" not in rem and " no switchport mode trunk" not in rem  # replaced in place
    assert rem[1] == " switchport mode access" and rem[-1] == " no shutdown"                 # hier_config order
    assert not any("version" in f"{f['missing']}{f['extra']}" for f in res["features"])       # noise ignored
