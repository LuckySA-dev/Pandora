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


def test_switch_role_on_a_router_pid_is_refused(ctx):
    from pandora import alloc
    assert [alloc.model_kind(p) for p in ("CISCO1941/K9", "ISR4331/K9", "C1111-8P", "C1000-24T-4G-L",
                                          "WS-C2960X-24PD-L", "C9300-24P", None)] == \
        ["router", "router", "router", "switch", "switch", "switch", None]
    d = add(ctx, 1, pid="CISCO1941/K9")                       # default role: switch_access
    assert any("is a router" in p for p in ctx.render(d["id"])[1])
    ctx.db.x("UPDATE devices SET role='router_edge' WHERE id=?", d["id"])
    text, problems, a = ctx.render(d["id"])
    assert not problems and a["reserved_ports"] == ["GigabitEthernet0/1"] and "switchport" not in text


def test_role_menu_renames_the_box_before_anything_was_sent(ctx):
    """Real 1941: previewed as an Access switch (kmutnb-sw-02 reserved), role changed in the Devices list: it kept
    the switch name. The list's role menu now renames like the wizard does."""
    from fastapi.testclient import TestClient

    from pandora.app import create_app
    d = add(ctx, 1, pid="CISCO1941/K9")
    assert ctx.preview([d["id"]])[0]["hostname"] == "lab-sw-01"
    c = TestClient(create_app(ctx, background=False))
    c.patch(f"/api/devices/{d['id']}", json={"role": "router_edge"})
    assert ctx.preview([d["id"]])[0]["hostname"] == "lab-rtr-01"


def test_pnp_save_refused_is_saved_over_ssh(ctx, monkeypatch):
    """Real 1941 15.4(3)M3: config-upgrade OK, cli-exec "write memory" refused (Insufficient PnP CLI-Exec Service
    Privilege). The config is applied, so PandoraBox saves it over SSH; provisioned only if that worked."""
    import time

    from fastapi.testclient import TestClient

    from pandora.app import create_app
    udi = "PID:CISCO1941/K9,VID:V05,SN:FGL224230RL"

    def msg(kind, body):
        return f'<pnp xmlns="urn:cisco:pnp" version="1.0" udi="{udi}"><{kind} correlator="c" {body}</pnp>'
    wr = msg("info", 'xmlns="urn:cisco:pnp:work-info"><deviceId><udi>x</udi></deviceId></info>')
    ok = msg("response", 'success="1" xmlns="urn:cisco:pnp:config-upgrade"></response>')
    refused = msg("response", 'success="0" xmlns="urn:cisco:pnp:cli-exec"><errorInfo><errorMessage>Insufficient PnP '
                              'CLI-Exec Service Privilege</errorMessage></errorInfo></response>')
    saved = []
    monkeypatch.setattr(ctx, "complete", lambda i: (saved.append(i), "capability-dependent lines added over SSH")[1])
    c = TestClient(create_app(ctx, background=False))
    ctx.emit = lambda *a: None
    c.post("/pnp/WORK-REQUEST", content=wr)                                   # device-info
    dev = ctx.db.find(serial="FGL224230RL")
    ctx.db.x("UPDATE devices SET role='router_edge', path='pnp' WHERE id=?", dev["id"])
    ctx.db.set_state(dev["id"], "queued")
    assert "config-upgrade" in c.post("/pnp/WORK-REQUEST", content=wr).text
    c.post("/pnp/WORK-RESPONSE", content=ok)
    assert "write memory" in c.post("/pnp/WORK-REQUEST", content=wr).text
    c.post("/pnp/WORK-RESPONSE", content=refused)
    for _ in range(50):
        if ctx.db.device(dev["id"])["state"] != "provisioning":
            break
        time.sleep(0.05)
    dev = ctx.db.device(dev["id"])
    assert saved == [dev["id"]] and dev["state"] == "provisioned" and "saved over SSH" in dev["note"]
    monkeypatch.setattr(ctx, "complete", lambda i: "not completed over SSH: TimeoutError: timed out")
    assert not ctx.save_over_ssh(dev["id"], "PnP refused write memory")
    assert ctx.db.device(dev["id"])["state"] == "failed" and "NOT saved" in ctx.db.device(dev["id"])["note"]


def test_allocation_keeps_the_box_own_address(ctx):
    """Real 1941 after Reset (address freed) still answered on 10.99.0.11: it must get .11 again, not .12."""
    from pandora import alloc
    other = add(ctx, 1, ip="10.99.0.10")
    alloc.allocate(ctx.db, ctx.cfg, other["id"])
    d = add(ctx, 2, pid="CISCO1941/K9", ip="10.99.0.11")
    assert alloc.allocate(ctx.db, ctx.cfg, d["id"])["mgmt_ip"] == "10.99.0.11"
    f = add(ctx, 3, ip="10.99.0.105")                          # a DHCP lease (outside mgmt_range): next free one
    assert alloc.allocate(ctx.db, ctx.cfg, f["id"])["mgmt_ip"] == "10.99.0.12"


def test_ssh_merge_survives_re_addressing_its_own_session(ctx, monkeypatch):
    """The merge moves the box to its mgmt address over the very link it uses: session lost -> merge again there."""
    from pandora import access, alloc, deliver
    d = add(ctx, 1, pid="CISCO1941/K9", ip="10.99.0.101", path="ssh", role="router_edge")
    mgmt = alloc.allocate(ctx.db, ctx.cfg, d["id"], ["Gi0/1"])["mgmt_ip"]   # SSH path: the user picks the port
    calls = []

    def ssh_config(dev, lines):
        calls.append(dev["ip"])
        if dev["ip"] == "10.99.0.101":
            raise deliver.NeedCredentials()  # stands in for netmiko's ReadTimeout after `ip address`
        return "[OK]"
    monkeypatch.setattr(access, "ssh_open", lambda ip, *a, **k: True)
    monkeypatch.setattr(ctx, "probe", lambda dev: ("", {}))
    monkeypatch.setattr(ctx, "ssh_config", ssh_config)
    ctx._push_ssh(ctx.db.device(d["id"]))
    dev = ctx.db.device(d["id"])
    assert calls == ["10.99.0.101", mgmt] and dev["state"] == "provisioned" and dev["ip"] == mgmt
    assert "moved from 10.99.0.101" in dev["note"]


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
    dev = remember_console(ctx, "COM7", {"console_state": "priv", "serial": "FOC2246V0W5"})
    assert dev["id"] == d["id"] and dev["path"] == "ssh" and dev["source"] == "dhcp" and dev["console_port"] == "COM7"
    new = remember_console(ctx, "COM8", {"console_state": "dialog"})
    assert new["id"] != d["id"] and new["path"] == "console" and new["source"] == "console"
    ctx.db.set_state(d["id"], "provisioned")                       # wiped box at the setup dialog: factory again
    dev = remember_console(ctx, "COM7", {"console_state": "dialog"})
    assert dev["id"] == d["id"] and dev["state"] == "discovered" and "factory" in dev["note"]


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


def test_router_mgmt_port_defaults_are_not_drift():
    """Real 1941: `duplex auto` / `speed auto` printed under the mgmt port made it "drifted" (strict feature)."""
    intended = "interface GigabitEthernet0/1\n description PANDORA-MGMT reserved\n ip address 10.99.0.12 255.255.255.0\n"
    running = intended + " duplex auto\n speed auto\n"
    assert compliance.compare(intended, running, ["Gi0/1"], 99)["compliant"]
    assert not compliance.compare(intended, running + " duplex half\n", ["Gi0/1"], 99)["compliant"]


def test_snmp_group_notify_view_added_by_ios_is_not_drift():
    """Real 3560G (12.2): the group shows with the notify view IOS made for the informs host."""
    intended = "snmp-server group PANDORA v3 priv\n"
    running = "snmp-server group PANDORA v3 priv notify *tv.FFFFFFFF.FFFFFFFF.FFFFFFFF.FFFFFFFF0F\n"
    assert compliance.compare(intended, running, [], 99)["compliant"]
    assert not compliance.compare(intended, "snmp-server group PANDORA v3 auth\n", [], 99)["compliant"]


def test_compliance_reads_classic_ios_spellings():
    """Real 2960X 15.2(2)E7 running-config: split vty blocks and the hyphenated domain-lookup."""
    intended = "no ip domain lookup\nline vty 0 15\n login local\n transport input ssh\n"
    running = ("no ip domain-lookup\nline vty 0 4\n login local\n transport input ssh\n"
               "line vty 5 15\n login local\n transport input ssh\n")
    assert compliance.compare(intended, running, [], 99)["compliant"]
    res = compliance.compare(intended, running.replace("line vty 5 15\n login local", "line vty 5 15\n login"), [], 99)
    assert not res["compliant"] and "line vty 7 > login local" in res["features"][0]["missing"]


def test_wiped_provisioned_box_is_identified_again(ctx):
    """Real 2960X: write erase + reload; it asked for DHCP as a PnP agent but stayed Provisioned + "unreachable"."""
    pnp = {"vendor_class": "ciscopnp", "client_id": "", "hostname": "", "requested_ip": None}
    d = ctx.db.upsert(mac="70:18:a7:95:df:c0", serial="FOC2246V0W5", pid="WS-C2960X-24PD-L", ip="10.99.0.10",
                      path="ssh", console_port="COM7")
    ctx.db.set_state(d["id"], "provisioned")
    alerts.raise_(ctx, d["id"], "unreachable", "high", "No SNMP answer for 3 polls")
    alerts.raise_(ctx, d["id"], "if:GigabitEthernet1/0/23", "high", "Management port Gi1/0/23 is down")
    ctx.dhcp_decide("70:18:a7:95:df:c0", {**pnp, "vendor_class": ""}, "10.99.0.100")
    dev = ctx.db.device(d["id"])
    assert dev["state"] == "provisioned" and dev["ip"] == "10.99.0.10"  # merged box, own DHCP client: untouched
    opts = ctx.dhcp_decide("70:18:a7:95:df:c0", pnp, "10.99.0.100")
    dev = ctx.db.device(d["id"])
    assert dev["state"] == "identified" and dev["path"] == "pnp" and "factory" in dev["note"]
    assert dev["ip"] == "10.99.0.100"                                # reachable on its lease while factory
    assert alerts.open_problems(ctx.db, d["id"]) == [] and 43 in opts   # stale alarms gone; PnP discovery offered
    ctx.db.set_state(d["id"], "failed", "config-upgrade failed")
    ctx.dhcp_decide("70:18:a7:95:df:c0", pnp, "10.99.0.100")
    assert ctx.db.device(d["id"])["state"] == "failed"               # a failure stays visible


def test_autoinstall_box_wiped_and_dhcp_renewal_after_restart(ctx):
    """A legacy box PandoraBox configured by AutoInstall (no PnP agent) DHCPing again = wiped; and a renewal sent to a
    restarted PandoraBox is answered instead of ignored until the lease runs out."""
    from pandora.net import dhcp
    legacy = {"vendor_class": "", "client_id": "", "hostname": "", "requested_ip": None}
    d = ctx.db.upsert(mac="00:1e:4a:00:00:01", pid="WS-C2960-24TT-L", ip="10.99.0.11", path="autoinstall")
    ctx.db.set_state(d["id"], "provisioned")
    ctx.dhcp_decide("00:1e:4a:00:00:01", legacy, "10.99.0.101")
    dev = ctx.db.device(d["id"])
    assert dev["state"] == "identified" and dev["path"] == "autoinstall"
    # renewal (RENEWING: ciaddr set, no option 50) of a PnP box after a restart, leases seeded from the inventory
    srv = dhcp.DhcpServer("10.99.0.1", "255.255.255.0", ["10.99.0.100", "10.99.0.101"], ctx.dhcp_decide,
                          leases={"00:1e:4a:00:00:01": "10.99.0.101"})
    def renew(mac, ciaddr):
        return (dhcp.HDR.pack(1, 1, 6, 0, 7, 0, 0, bytes(map(int, ciaddr.split("."))), *(b"\0" * 4,) * 3,
                              bytes.fromhex(mac.replace(":", "")) + b"\0" * 10, b"\0" * 64, b"\0" * 128, dhcp.MAGIC)
                + b"\x35\x01\x03" + bytes([60, 8]) + b"ciscopnp" + b"\xff")
    ack = srv.handle(renew("70:18:a7:95:df:c0", "10.99.0.100"))
    assert ack and dhcp.parse(ack)["options"][53] == bytes([dhcp.ACK])
    assert srv.leases["70:18:a7:95:df:c0"] == "10.99.0.100"
    assert srv.handle(renew("aa:bb:cc:dd:ee:ff", "10.99.0.101")) is None   # held by another box: not ours to give


def test_reset_and_remove_device(ctx):
    from fastapi.testclient import TestClient

    from pandora import alloc
    from pandora.app import create_app
    d = add(ctx, 1, ip="10.99.0.10", path="ssh")
    alloc.allocate(ctx.db, ctx.cfg, d["id"])
    ctx.db.set_state(d["id"], "provisioned")
    alerts.raise_(ctx, d["id"], "unreachable", "high", "No SNMP answer for 3 polls")
    c = TestClient(create_app(ctx, background=False))
    assert c.post(f"/api/devices/{d['id']}/reset", json={}).status_code == 400          # needs an explicit yes
    r = c.post(f"/api/devices/{d['id']}/reset", json={"confirm": True}).json()
    assert r["state"] == "identified" and alerts.open_problems(ctx.db, d["id"]) == []
    assert ctx.db.q("SELECT 1 FROM allocations WHERE device_id=?", d["id"])            # keeps its name and address
    c.post(f"/api/devices/{d['id']}/reset", json={"confirm": True, "release": True})
    assert not ctx.db.q("SELECT 1 FROM allocations WHERE device_id=?", d["id"])
    assert c.post(f"/api/devices/{d['id']}/remove", json={"confirm": True}).json() == {"ok": True}
    assert ctx.db.device(d["id"]) is None and c.get(f"/api/devices/{d['id']}").status_code == 404


def test_boot_file_commits_the_mgmt_vlan_before_ports_use_it(ctx):
    """Real 2960X PnP: "% Access VLAN does not exist. Creating vlan 99" -> VLAN0099, a mgmt-vlan drift."""
    d = add(ctx, 1, pid="WS-C2960X-24PD-L")
    text, problems, a = ctx.render(d["id"], factory=True)
    lines = text.splitlines()
    assert lines[lines.index(" name PANDORA-MGMT") + 1] == "exit"
    assert lines.index("exit") < lines.index("interface GigabitEthernet1/0/23")
    from pandora.db import mask_secrets
    running = "\n".join(lines) + "\n"                          # the box shows everything except the exit line
    assert compliance.compare(mask_secrets(text), mask_secrets(running.replace("exit\n", "")),
                              a["reserved_ports"], 99)["features"][1]["compliant"]


def test_offline_is_a_status_not_an_alarm(ctx, monkeypatch):
    """Single-NIC laptop cabled to the router: the switch stops answering. Offline (info), polled every few
    minutes, back online on the next answer or inform; a restart shows as uptime going back."""
    import asyncio

    from pandora import monitor, snmp
    d = add(ctx, 1, ip="10.99.0.10")
    ctx.db.set_state(d["id"], "provisioned")
    for _ in range(3):
        alerts.on_poll_failed(ctx, ctx.db.devices(d["id"])[0])
    dev = ctx.db.device(d["id"])
    probs = alerts.open_problems(ctx.db, d["id"])
    assert dev["reach"] == "offline" and [(p["key"], p["severity"]) for p in probs] == [("unreachable", "info")]
    assert monitor.dashboard(ctx)["availability"]["down"] == 1
    ctx.cfg["offline_severity"] = "high"
    alerts.on_poll_failed(ctx, ctx.db.devices(d["id"])[0])
    assert alerts.open_problems(ctx.db, d["id"])[0]["severity"] == "high"      # a permanently cabled site can say so
    # an inform from it: online right away, problem closed, event says how long it was gone
    ctx.db.x("UPDATE devices SET seen=? WHERE id=?", __import__("time").time() - 600, d["id"])
    monitor.on_trap(ctx, "10.99.0.10", "linkUp", [])
    dev = ctx.db.device(d["id"])
    assert dev["reach"] == "online" and dev["seen"] and alerts.open_problems(ctx.db, d["id"]) == []
    assert "offline for 10 min" in ctx.db.q("SELECT detail FROM audit WHERE action='reach:online'")[0]["detail"]
    # uptime going backwards between two polls = restarted
    polls = iter([{"uptime": "500000"}, {"uptime": "1200"}])

    async def fake_poll(ip, a):
        return next(polls)
    monkeypatch.setattr(snmp, "poll", fake_poll)
    for _ in range(2):
        asyncio.run(monitor.poll_one(ctx, ctx.db.devices(d["id"])[0]))
    assert [p["key"] for p in alerts.open_problems(ctx.db, d["id"])] == ["reboot"]


def test_offline_device_is_polled_less_often(ctx, monkeypatch):
    import asyncio
    import time

    from pandora import monitor, snmp
    asked = []

    async def fake_poll(ip, a):
        asked.append(ip)
        raise TimeoutError("No SNMP response received before timeout")
    monkeypatch.setattr(snmp, "poll", fake_poll)
    for n, ip in ((1, "10.99.0.10"), (2, "10.99.0.12")):
        add(ctx, n, ip=ip)
        ctx.db.set_state(n, "provisioned")
    ctx.db.set_reach(1, "offline")
    monitor._LAST_TRY[1] = time.time()                         # tried a moment ago

    async def one_round():
        task = asyncio.create_task(monitor.poll_forever(ctx, every=3600))
        await asyncio.sleep(0.2)
        task.cancel()
    asyncio.run(one_round())
    assert asked == ["10.99.0.12"]                             # the offline one waits for offline_retry


def test_existing_database_gets_the_new_columns(tmp_path):
    import sqlite3

    from pandora.db import DB
    old = tmp_path / "old.db"
    c = sqlite3.connect(old)
    c.execute("CREATE TABLE devices (id INTEGER PRIMARY KEY, serial TEXT UNIQUE, mac TEXT UNIQUE, console_port TEXT "
              "UNIQUE, ip TEXT, pid TEXT, os_type TEXT, version TEXT, hostname TEXT, source TEXT, vendor_class TEXT, "
              "path TEXT, role TEXT DEFAULT 'switch_access', state TEXT DEFAULT 'discovered', vars TEXT DEFAULT '{}', "
              "note TEXT, created REAL, updated REAL)")
    c.execute("INSERT INTO devices (serial) VALUES ('FOC2246V0W5')")
    c.commit()
    c.close()
    db = DB(str(old))
    dev = db.find(serial="FOC2246V0W5")
    assert "reach" in dev and "seen" in dev
    db.set_reach(dev["id"], "online", 1.0)
    assert db.device(dev["id"])["reach"] == "online"


def test_config_register_that_skips_nvram_is_flagged(ctx):
    """Real 2911 (15.6(3)M0a) after password recovery: register 0x2142 = boots without its startup-config."""
    d = add(ctx, 1, pid="CISCO2911/K9")
    ctx.check_confreg(d["id"], "Cisco CISCO2911/K9 (revision 1.0)\nConfiguration register is 0x2142\n")
    p = alerts.open_problems(ctx.db, d["id"])
    assert [(x["key"], x["severity"]) for x in p] == [("confreg", "warning")] and "0x2102" in p[0]["message"]
    ctx.check_confreg(d["id"], "Configuration register is 0x2102\n")
    assert alerts.open_problems(ctx.db, d["id"]) == []
    from pandora import alloc
    assert alloc.model_kind("CISCO2911/K9") == "router" and alloc.default_ports("CISCO2911/K9", "router_edge", 2) \
        == ["GigabitEthernet0/1"]


def test_tftp_default_file_misses_are_quiet(tmp_path, caplog):
    """A booting classic IOS box asks for network-confg, cisconet.cfg, router-confg, ciscortr.cfg, <host>-confg
    over and over: answered (not found) without filling the log. Its own pandora-<mac>.cfg is still logged."""
    import logging
    import socket
    import struct
    import time

    import pytest

    from pandora.net import tftp
    try:
        srv = tftp.start("127.0.0.1", tmp_path, lambda name, ip: None)
    except PermissionError:
        pytest.skip("port 69 needs privileges here")
    try:
        with caplog.at_level(logging.DEBUG):
            for name in ("network-confg", "kmutnb-rtr-02-confg", "pandora-74a2e64e04ba.cfg"):
                s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
                s.settimeout(2)
                s.sendto(struct.pack("!H", 1) + name.encode() + b"\0octet\0", ("127.0.0.1", 69))
                assert struct.unpack("!H", s.recvfrom(512)[0][:2])[0] == 5      # TFTP ERROR = not found, answered
                s.close()
            time.sleep(0.2)
        shown = [r for r in caplog.records if r.levelno >= logging.INFO]
        assert [r.getMessage() for r in shown if r.name == "pandora.tftp"] == \
            ["TFTP pandora-74a2e64e04ba.cfg from 127.0.0.1 -> not found"]
        assert not [r for r in shown if r.name.startswith("tftpy") and "not found" in r.getMessage()]
    finally:
        srv.stop(now=True)


def test_cdp_from_a_factory_box_names_its_model_and_our_port(ctx):
    """Real AutoInstall 2960 (MAC only, no PID): Gi0/24 typed by hand, the box has FastEthernet0/24 -> refused,
    unreachable. Its CDP (sent at boot, with its DHCP address) tells the model and the port the laptop is on."""
    dev = ctx.db.upsert(mac="00:24:97:b1:8c:40", ip="10.99.0.101", source="dhcp", path="autoinstall")
    n = {"via": "cdp", "remote_name": "Switch", "remote_port": "FastEthernet0/24", "platform": "cisco WS-C2960-24TT-L",
         "addresses": ["10.99.0.101"]}
    ctx.learn_from_neighbor(n)
    dev = ctx.db.device(dev["id"])
    assert dev["pid"] == "WS-C2960-24TT-L" and dev["state"] == "identified"
    assert ctx.preview([dev["id"]])[0]["reserved_ports"] == ["FastEthernet0/24", "FastEthernet0/23"]
    # laptop on another port later (still factory): that one becomes the first reserved port
    ctx.learn_from_neighbor({**n, "remote_port": "Fa0/5"})
    assert ctx.preview([dev["id"]])[0]["reserved_ports"][0] == "FastEthernet0/5"
    # a provisioned box (e.g. the switch between the laptop and a new box) is never changed
    ctx.db.set_state(dev["id"], "provisioned")
    assert ctx.learn_from_neighbor({**n, "remote_port": "Fa0/9"}) is None


def test_cdp_without_address_matches_by_mac_block(ctx):
    """Unselected AutoInstall 2960: no DHCP lease from us, so its CDP has no address. Its port MAC (Fa0/24 =
    base+0x18) is next to the Vlan1 MAC it asked DHCP with (base+0x40). Two boxes that close: no guess."""
    dev = ctx.db.upsert(mac="00:24:97:b1:8c:40", source="dhcp", path="autoinstall")
    n = {"via": "cdp", "src_mac": "00:24:97:b1:8c:18", "remote_port": "FastEthernet0/24",
         "platform": "cisco WS-C2960-24TT-L", "addresses": []}
    assert ctx.learn_from_neighbor(n)["id"] == dev["id"]
    assert ctx.db.device(dev["id"])["pid"] == "WS-C2960-24TT-L"
    assert ctx.learn_from_neighbor({**n, "src_mac": "00:24:97:b2:00:00"}) is None    # far away: someone else
    ctx.db.upsert(mac="00:24:97:b1:8c:80", source="dhcp")                          # a second box that close
    assert ctx.learn_from_neighbor(n) is None


class Fake2960:
    """What a factory 2960 (FastEthernet ports) answers once stage 1 gave it an address on Vlan1."""
    ANSWERS = {
        "show version": "Cisco IOS Software, C2960 Software (C2960-LANBASEK9-M), Version 15.0(2)SE11\n"
                        "Model number                    : WS-C2960-24TT-L\nSystem serial number            : "
                        "FOC1234X5YZ\nConfiguration register is 0xF\n",
        "show ip interface brief": "Interface  IP-Address  OK? Method Status  Protocol\n"
                                   "Vlan1      10.99.0.13  YES manual up      up\n"
                                   + "".join(f"FastEthernet0/{n}  unassigned  YES unset  down  down\n"
                                             for n in range(1, 25))
                                   + "GigabitEthernet0/1  unassigned  YES unset  down  down\n",
        "show ip arp 10.99.0.1": "Internet  10.99.0.1   0   0050.56c0.0001  ARPA   Vlan1\n",
        "show mac address-table address 0050.56c0.0001": "   1    0050.56c0.0001    DYNAMIC     Fa0/7\n",
    }

    def __init__(self):
        self.config_sets = []

    def __enter__(self):
        return self

    def __exit__(self, *a):
        return False

    def enable(self):
        pass

    def send_command(self, cmd, **kw):
        return self.ANSWERS.get(cmd, "% Invalid input detected at '^' marker.")

    def send_config_set(self, lines, **kw):
        self.config_sets.append(list(lines))
        if lines and lines[0].startswith("event manager applet"):  # the box runs it: the address moves to Vlan99
            self.ANSWERS = {**self.ANSWERS, "show ip interface brief": self.ANSWERS["show ip interface brief"]
                            .replace("Vlan1      10.99.0.13", "Vlan99     10.99.0.10")}
        return ""


def test_two_stage_autoinstall_for_a_switch_nobody_named(ctx, monkeypatch):
    """Real 2960: AutoInstall, no PnP, no CDP, so no model and no port names before it is up. Stage 1 names no port;
    stage 2 asks the box, finds the PC on Fa0/7 from its MAC table and moves management there by an EEM applet."""
    from pandora import access, deliver
    d = ctx.db.upsert(mac="00:24:97:b1:8c:40", ip="10.99.0.101", source="dhcp", path="autoinstall")
    row = ctx.preview([d["id"]])[0]
    assert row["problems"] == [] and row["reserved_ports"] == []
    stage1 = row["config"]
    assert "interface Vlan1\n ip address 10.99.0.10 255.255.255.0" in stage1
    assert "Ethernet" not in stage1 and "vlan 99" not in stage1               # no port name to get wrong
    assert ctx.queue([d["id"]])[0]["queued"]
    box, merged = Fake2960(), []
    monkeypatch.setattr(ctx, "session", lambda dev: box)
    monkeypatch.setattr(ctx, "ssh_config", lambda dev, lines: (merged.append(lines), "[OK]")[1])
    monkeypatch.setattr(ctx, "probe", lambda dev: ("", {"cap_vty_last": 15, "cap_snmp_priv": True}))
    monkeypatch.setattr(access, "ssh_open", lambda ip, *a, **k: True)
    monkeypatch.setattr(deliver.time, "sleep", lambda s: None)
    ok, note = ctx.stage_two(d["id"])
    dev = ctx.db.devices(d["id"])[0]
    assert ok, note
    assert "line vty 0 15" in "\n".join(merged[-1])                       # asked the image, like any SSH push
    assert dev["pid"] == "WS-C2960-24TT-L" and dev["ip"] == "10.99.0.10" and "PC on FastEthernet0/7" in note
    assert set(dev["reserved"].split(", ")) == {"FastEthernet0/7", "FastEthernet0/23"}  # PC's port + model's last
    applet = box.config_sets[-1]
    body = "\n".join(applet)
    assert applet[0] == "event manager applet PANDORA-STAGE2"
    assert body.index('"interface Vlan1"') < body.index('"switchport access vlan 99"') < body.index('"write memory"')
    assert "secret" not in body and "snmp-server" not in body                # no secrets kept in an applet
    assert "interface FastEthernet0/7" in merged[-1] and "interface Vlan99" in merged[-1]
    assert ctx.db.vars(d["id"])["staged"] is False                          # compliance judges the final config


def test_two_stage_stops_safely_when_the_pc_port_is_unknown(ctx, monkeypatch):
    from pandora import access, deliver
    d = ctx.db.upsert(mac="00:24:97:b1:8c:40", ip="10.99.0.101", source="dhcp", path="autoinstall")
    ctx.queue([d["id"]])
    box = Fake2960()
    box.ANSWERS = {**Fake2960.ANSWERS, "show ip arp 10.99.0.1": ""}
    monkeypatch.setattr(ctx, "session", lambda dev: box)
    monkeypatch.setattr(access, "ssh_open", lambda ip, *a, **k: True)
    monkeypatch.setattr(deliver.time, "sleep", lambda s: None)
    ok, note = ctx.stage_two(d["id"])
    assert not ok and "VLAN 1" in note and box.config_sets == []             # nothing moved: still reachable


def test_two_stage_stops_when_eem_is_missing_or_the_move_did_not_happen(ctx, monkeypatch):
    from pandora import access, deliver
    d = ctx.db.upsert(mac="00:24:97:b1:8c:40", ip="10.99.0.101", source="dhcp", path="autoinstall")
    ctx.queue([d["id"]])
    merged = []
    monkeypatch.setattr(ctx, "ssh_config", lambda dev, lines: (merged.append(lines), "[OK]")[1])
    monkeypatch.setattr(access, "ssh_open", lambda ip, *a, **k: True)
    monkeypatch.setattr(deliver.time, "sleep", lambda s: None)

    class NoEem(Fake2960):
        def send_config_set(self, lines, **kw):
            self.config_sets.append(list(lines))
            return "event manager applet PANDORA-STAGE2\n                        ^\n% Invalid input detected at '^' marker."
    no_eem = NoEem()
    monkeypatch.setattr(ctx, "session", lambda dev: no_eem)
    ok, note = ctx.stage_two(d["id"])
    assert not ok and "refused the EEM applet" in note and "FastEthernet0/1-24" in note and merged == []

    class Stuck(Fake2960):
        def send_config_set(self, lines, **kw):  # accepted, but the address never moves
            self.config_sets.append(list(lines))
            return ""
    stuck = Stuck()
    monkeypatch.setattr(ctx, "session", lambda dev: stuck)
    ok, note = ctx.stage_two(d["id"])
    assert not ok and "did not happen" in note and merged == []            # no full merge over VLAN 1


def test_router_mgmt_port_follows_the_laptop_cable(ctx):
    d = ctx.db.upsert(mac="74:a2:e6:4e:04:ba", ip="10.99.0.102", pid="CISCO2911/K9", path="pnp")
    ctx.db.x("UPDATE devices SET role='router_edge' WHERE id=?", d["id"])
    ctx.learn_from_neighbor({"via": "cdp", "remote_port": "GigabitEthernet0/2", "platform": "cisco CISCO2911/K9",
                             "addresses": ["10.99.0.102"]})
    assert ctx.preview([d["id"]])[0]["reserved_ports"] == ["GigabitEthernet0/2"]


def test_real_port_names_from_the_box_refuse_a_wrong_one(ctx):
    from pandora import alloc
    brief = """Interface              IP-Address      OK? Method Status                Protocol
Vlan1                  10.99.0.101     YES DHCP   up                    up
FastEthernet0/1        unassigned      YES unset  down                  down
FastEthernet0/24       unassigned      YES unset  up                    up
GigabitEthernet0/1     unassigned      YES unset  down                  down
GigabitEthernet0/2     unassigned      YES unset  down                  down
"""
    names = alloc.parse_ifnames(brief)
    assert names == ["FastEthernet0/1", "FastEthernet0/24", "GigabitEthernet0/1", "GigabitEthernet0/2"]
    assert alloc.summarize_ports(names) == "FastEthernet0/1-24, GigabitEthernet0/1-2"
    d = add(ctx, 1, pid="WS-C2960-24TT-L")
    ctx.db.set_vars(d["id"], {"cap_ifnames": names})
    alloc.allocate(ctx.db, ctx.cfg, d["id"], ["Gi0/24"])
    problems = ctx.render(d["id"])[1]
    assert any("GigabitEthernet0/24: no such port" in p and "FastEthernet0/1-24" in p for p in problems)
    alloc.allocate(ctx.db, ctx.cfg, d["id"], ["Fa0/24"])
    assert not ctx.render(d["id"])[1]


def test_windows_connection_reset_noise_is_dropped():
    from pandora.app import _quiet_resets

    class Loop:
        seen = []

        def default_exception_handler(self, context):
            self.seen.append(context)
    loop = Loop()
    _quiet_resets(loop, {"exception": ConnectionResetError(10054), "handle": "<Handle _ProactorBasePipeTransport."
                                                                            "_call_connection_lost(None)>"})
    _quiet_resets(loop, {"exception": ValueError("real bug"), "message": "boom"})
    assert len(loop.seen) == 1 and isinstance(loop.seen[0]["exception"], ValueError)


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
