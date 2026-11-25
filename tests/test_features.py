"""Features adapted from Oxidized / Golden Config / Zabbix / NetBox: backup, compliance, alerts, API."""
import tempfile
from pathlib import Path

from conftest import add

from pandora import alerts, alloc, backup, compliance, devicetypes, platforms


def _provisioned(ctx, n=1, pid="C9300-24P"):
    d = add(ctx, n, pid=pid, ip=f"10.99.0.{50 + n}")
    ctx.db.set_state(d["id"], "provisioned")
    return ctx.db.device(d["id"])


def _running_from(intended: str) -> str:
    """What a switch shows after applying `intended`: ranges expanded, secret hashed, snmp user/crypto hidden."""
    out, members = [], None
    for line in intended.splitlines():
        if not line.strip() or line.startswith(("!", "crypto key", "snmp-server user")):
            continue
        if line.startswith("interface range "):
            members = alloc.expand_range(line[len("interface range "):])
            out.append(("RANGE", members, []))
            continue
        if line.startswith(" ") and members is not None:
            out[-1][2].append(line)
            continue
        members = None
        out.append(line.replace("secret Adm1nPass!", "secret 9 $9$hash"))
    text = []
    for item in out:
        if isinstance(item, tuple):
            for m in item[1]:
                text += [f"interface {m}"] + item[2]
        else:
            text.append(item)
    return "\n".join(text) + "\n"


def test_platform_clean_strips_volatile_lines():
    raw = ("Building configuration...\r\n\r\nCurrent configuration : 1234 bytes\r\n"
           "! Last configuration change at 10:00\r\nhostname a\r\n")
    assert platforms.clean("iosxe", raw) == "hostname a\n"
    assert platforms.get(None)["netmiko"] == "cisco_ios" and platforms.get("iosxe")["netmiko"] == "cisco_xe"


def test_backup_stores_only_changes_and_diffs(ctx):
    d = _provisioned(ctx)
    cfgs = iter(["hostname a\nusername pandora privilege 15 secret 9 $9$abc\n",
                 "hostname a\nusername pandora privilege 15 secret 9 $9$abc\n",
                 "Current configuration : 99 bytes\nhostname b\n"])
    ctx.ssh_command = lambda dev, cmd: next(cfgs)
    first, same, changed = (backup.fetch(ctx, d["id"]) for _ in range(3))
    assert first["changed"] and not same["changed"] and changed["changed"]
    hist = backup.history(ctx.db, d["id"])
    assert len(hist) == 2 and (hist[0]["added"], hist[0]["removed"]) == (1, 2)
    assert "$9$abc" not in backup.get(ctx.db, first["id"])["text"]  # stored masked
    diff = backup.diff(ctx.db, first["id"], changed["id"])
    assert "-hostname a" in diff and "+hostname b" in diff


def test_compliance_compliant_then_drift_and_safe_remediation(ctx):
    d = _provisioned(ctx)
    ctx.db.set_vars(d["id"], {"access_ports": [{"ports": "Gi1/0/1 - 2", "vlan": 10}]})
    intended, _, a = ctx.render(d["id"])
    running = _running_from(intended)
    ok = compliance.compare(intended, running, a["reserved_ports"], 99)
    assert ok["compliant"], [f for f in ok["features"] if not f["compliant"]]
    # drift: someone shut a mgmt port and removed the trap host
    drifted = running.replace(" description PANDORA-MGMT reserved\n",
                              " description PANDORA-MGMT reserved\n shutdown\n", 1)
    drifted = "\n".join(l for l in drifted.splitlines() if not l.startswith("snmp-server host"))
    bad = compliance.compare(intended, drifted, a["reserved_ports"], 99)
    assert {f["name"] for f in bad["features"] if not f["compliant"]} == {"mgmt-ports", "snmp"}
    rem = bad["remediation"]
    assert " no shutdown" in rem and any(l.startswith("snmp-server host") for l in rem)
    # a removed user is reported, but never "fixed" by pushing a user line without its secret
    no_user = "\n".join(l for l in running.splitlines() if not l.startswith("username"))
    r2 = compliance.compare(intended, no_user, a["reserved_ports"], 99)
    assert not r2["compliant"] and not any(l.startswith("username") for l in r2["remediation"])


def test_compliance_remediation_order_for_changed_vlan():
    res = compliance.compare("interface GigabitEthernet1/0/24\n switchport access vlan 99\n",
                             "interface GigabitEthernet1/0/24\n switchport access vlan 10\n", ["Gi1/0/24"], 99)
    assert res["remediation"] == ["interface GigabitEthernet1/0/24", " no switchport access vlan 10",
                                  " switchport access vlan 99"]


def test_alerts_triggers_and_recovery(ctx):
    d = _provisioned(ctx)
    alloc.allocate(ctx.db, ctx.cfg, d["id"])  # reserved Gi1/0/23-24
    alerts.on_sample(ctx, d, {"Gi1/0/5:oper": "up", "Gi1/0/24:oper": "up", "cpu5min": "10"}, None)
    assert alerts.open_problems(ctx.db) == []
    alerts.on_sample(ctx, d, {"Gi1/0/5:oper": "down", "Gi1/0/24:oper": "down", "cpu5min": "95"},
                     {"Gi1/0/5:oper": "up", "Gi1/0/24:oper": "up"})
    sev = {p["key"]: p["severity"] for p in alerts.open_problems(ctx.db)}
    assert sev == {"if:GigabitEthernet1/0/5": "warning", "if:GigabitEthernet1/0/24": "high", "cpu": "average"}
    assert alerts.worst(ctx.db)[d["id"]] == "high"
    alerts.on_sample(ctx, d, {"Gi1/0/5:oper": "up", "Gi1/0/24:oper": "up", "cpu5min": "5"}, None)
    assert alerts.open_problems(ctx.db) == []  # recovered on their own
    for _ in range(alerts.UNREACHABLE_AFTER):
        alerts.on_poll_failed(ctx, d)
    assert [p["key"] for p in alerts.open_problems(ctx.db)] == ["unreachable"]
    alerts.ack(ctx, alerts.open_problems(ctx.db)[0]["id"], "on it")
    assert alerts.open_problems(ctx.db)[0]["note"] == "on it"
    ctx.db.set_state(d["id"], "failed", "boom")
    alerts.on_device(ctx, ctx.db.device(d["id"]))
    assert any(p["key"] == "provision" and p["severity"] == "high" for p in alerts.open_problems(ctx.db))


def test_devicetype_library_fallback():
    folder = Path(tempfile.mkdtemp(prefix="pandora-dt-"))
    (folder / "x.yaml").write_text(
        "manufacturer: Cisco\nmodel: Catalyst 9500-16X\npart_number: C9500-16X\ninterfaces:\n"
        "  - name: GigabitEthernet0/0\n    type: 1000base-t\n    mgmt_only: true\n"
        + "".join(f"  - name: TenGigabitEthernet1/0/{i}\n    type: 10gbase-x-sfpp\n" for i in range(1, 17)))
    devicetypes.load.cache_clear()
    try:
        assert devicetypes.last_ports("C9500-16X", 2, str(folder)) == ["TenGigabitEthernet1/0/15",
                                                                       "TenGigabitEthernet1/0/16"]
        assert devicetypes.last_ports("NOPE", 2, str(folder)) is None
    finally:
        devicetypes.load.cache_clear()


def test_new_api_endpoints(ctx):
    from fastapi.testclient import TestClient

    from pandora.app import create_app
    c = TestClient(create_app(ctx, background=False))
    d = _provisioned(ctx)
    other = add(ctx, 2)
    assert [x["id"] for x in c.get("/api/devices", params={"state": "provisioned"}).json()] == [d["id"]]
    assert [x["id"] for x in c.get("/api/devices", params={"q": "00:00:00:00:00:02"}).json()] == [other["id"]]
    csv = c.get("/api/devices.csv").text.splitlines()
    assert csv[0].startswith("id,state,hostname") and len(csv) == 3
    alerts.raise_(ctx, d["id"], "cpu", "average", "CPU 95%")
    dash = c.get("/api/dashboard").json()
    assert dash["problems"]["average"] == 1 and dash["states"]["provisioned"] == 1
    pid = c.get("/api/problems").json()[0]["id"]
    assert c.post(f"/api/problems/{pid}/ack", json={"note": "x"}).status_code == 200
    det = c.get(f"/api/devices/{d['id']}").json()
    assert det["device"]["id"] == d["id"] and det["problems"][0]["severity"] == "average"
    assert c.get("/api/devices/999").status_code == 404
    ctx.ssh_command = lambda dev, cmd: "hostname x\n"
    assert c.post(f"/api/devices/{d['id']}/backups").json()["changed"] is True
    assert c.post(f"/api/devices/{other['id']}/backups").status_code == 400  # no IP yet
    res = c.post(f"/api/devices/{d['id']}/compliance").json()
    assert res["compliant"] is False and c.get(f"/api/devices/{d['id']}/compliance").json()["backup_id"]
    assert c.post(f"/api/devices/{d['id']}/remediate", json={}).status_code == 400  # needs confirm
    assert any(p["key"] == "drift" for p in c.get("/api/problems").json())


def test_image_caps_from_real_iol_help_shape_the_config(ctx):
    from pandora.deliver import parse_caps
    vty = "line vty 0 ?\n  <1-4>  Last Line number\n  <cr>   <cr>\n"
    l2_group = "  auth    group using the authNoPriv Security Level\n  noauth  group using the noAuthNoPriv Security Level\n"
    rtr_traps = "  bfd                          Allow SNMP BFD traps\n  cef                          Enable SNMP CEF traps\n"
    caps = parse_caps(vty, l2_group, rtr_traps)
    assert caps == {"cap_vty_last": 4, "cap_snmp_priv": False, "cap_traps_config": False}
    assert parse_caps("  <1-1869>  Last Line number", "", "") == {"cap_vty_last": 15}  # unread help keeps defaults
    d = add(ctx, 90)
    ctx.db.set_vars(d["id"], caps)
    text, problems, _ = ctx.render(d["id"])
    assert any("no SNMPv3 priv" in p for p in problems)  # never downgrade without the operator's say-so
    ctx.cfg["snmp_allow_auth_nopriv"] = True
    text, problems, _ = ctx.render(d["id"])
    assert not problems and "line vty 0 4\n" in text and "traps config" not in text
    assert "snmp-server group PANDORA v3 auth\n" in text and "priv aes" not in text
    assert "informs version 3 auth pandora-auth" in text  # its own USM user: one level per user on the receiver


def test_console_probe_never_presses_a_key_on_a_box_that_is_zero_touching(monkeypatch):
    from pandora import console

    class FakePort:  # a factory IOS-XE box mid-AutoInstall, as seen on blank IOL in containerlab
        def __init__(self, *a, **k):
            self.out, self.written = (b"No startup-config, starting autoinstall/pnp/ztp...\r\n\r\n"
                                      b"Autoinstall will terminate if any input is detected on console\r\n"), b""

        def read(self, n):
            chunk, self.out = self.out[:n], self.out[n:]
            return chunk

        def write(self, b):
            self.written += b

        def close(self):
            FakePort.last = self

    monkeypatch.setattr(console.serial, "serial_for_url", FakePort)
    assert console.probe("socket://127.0.0.1:5022") == {"console_state": "ztp"}
    assert FakePort.last.written == b""  # any input would have ended its AutoInstall
    assert console.classify("Autoinstall will terminate if any input is detected\r\nSwitch>") == "user"


def test_preflight_catches_bad_ranges_and_missing_secrets():
    from pandora import config, preflight
    cfg = {**config.DEFAULTS, "admin_password": "Adm1nPass!", "snmp_auth": "", "snmp_priv": "short"}
    assert [r[0] for r in preflight.check_secrets(cfg)] == ["ok", "fail", "fail"]
    assert all(r[0] == "ok" for r in preflight.check_ranges(cfg))  # the shipped defaults are consistent
    bad = preflight.check_ranges({**cfg, "dhcp_range": "10.99.0.90-10.99.0.120", "mgmt_range": "10.0.0.1-10.99.0.1"})
    text = " ".join(r[2] for r in bad if r[0] == "fail")
    assert "not inside" in text  # mgmt_range spans outside the NIC subnet
    lap = preflight.check_ranges({**cfg, "dhcp_range": "10.99.0.90-10.99.0.120"})
    assert any("overlap" in r[2] for r in lap)  # 90-99 is in both ranges
    assert any("contains server_ip" in r[2] for r in preflight.check_ranges({**cfg, "dhcp_range": "10.99.0.1-10.99.0.5"}))


def test_boot_config_only_for_the_box_itself_and_no_cross_site_api(ctx):
    from pandora.api import ui_ok
    d = ctx.db.upsert(mac="aa:00:00:00:00:77", pid="C9300-24P", ip="10.99.0.150", path="autoinstall")
    assert ctx.queue([d["id"]])[0]["queued"]
    d = ctx.db.device(d["id"])
    assert "username pandora" in ctx.boot_config(d, "autoinstall", "10.99.0.150")
    assert ctx.boot_config(d, "autoinstall", "10.99.0.151") is None  # a neighbour on the segment gets nothing
    assert ctx.tftp_lookup("pandora-aa0000000077.cfg", "10.99.0.151") is None
    local = {"host": "127.0.0.1"}
    assert ui_ok("127.0.0.1", local) and ui_ok("127.0.0.1", {**local, "sec-fetch-site": "same-origin"})
    assert not ui_ok("127.0.0.1", {**local, "sec-fetch-site": "cross-site"})  # <img src> from a web page


def test_device_identity_guards_and_subnet_clash(ctx):
    from types import SimpleNamespace

    from pandora.net.pnp import _own
    from pandora.preflight import clashes

    def req(ip):
        return SimpleNamespace(client=SimpleNamespace(host=ip))

    con = ctx.db.upsert(serial="FOCCONSOLE1", pid="C9300-24P", console_port="COM7", path="console")
    assert ctx.queue([con["id"]])[0]["queued"]
    con = ctx.db.device(con["id"])
    assert not _own(ctx.db, con, req("10.99.0.66"))  # selected box with no address: nobody may claim its serial
    assert ctx.boot_config({**con, "ip": "10.99.0.66"}, "ztp", "10.99.0.66") is None  # console box: no ZTP file
    pnp = ctx.db.upsert(serial="FOCPNP0001", pid="C9300-24P", ip="10.99.0.120", path="pnp")
    assert ctx.queue([pnp["id"]])[0]["queued"]
    pnp = ctx.db.device(pnp["id"])
    mgmt = ctx.db.q("SELECT mgmt_ip FROM allocations WHERE device_id=?", pnp["id"])[0]["mgmt_ip"]
    assert _own(ctx.db, pnp, req("10.99.0.120")) and not _own(ctx.db, pnp, req(mgmt))  # mgmt IP: not before config
    ctx.db.set_state(pnp["id"], "provisioning", "PnP: config-upgrade sent")
    assert _own(ctx.db, ctx.db.device(pnp["id"]), req(mgmt))  # after it: the agent reports from there
    assert clashes("10.99.0.1/24", [("Wi-Fi", "192.168.1.5/24")]) == []
    assert clashes("10.99.0.1/24", [("Wi-Fi", "10.99.0.50/16")]) == ["Wi-Fi 10.99.0.50/16"]


def test_ztp_report_cannot_move_a_serial_onto_another_row(ctx):
    from fastapi.testclient import TestClient

    from pandora.app import create_app
    victim = ctx.db.upsert(serial="FOCVICTIM01", pid="C9300-24P", ip="10.99.0.150")
    attacker = ctx.db.upsert(mac="aa:00:00:00:00:99", ip="testclient")  # a box with no serial yet
    with TestClient(create_app(ctx, background=False)) as c:
        c.post("/ztp/done", json={"serial": "FOCVICTIM01", "ok": True, "version": ""})
    assert ctx.db.device(attacker["id"])["serial"] is None  # the victim's serial was not attached to it
    assert ctx.db.device(victim["id"])["ip"] == "10.99.0.150"  # and the victim's row is untouched


def _campus(ctx):
    """d1, d2 = L3 switches; a1 under d1 with a3 behind it; a2 under d2; r1 router on d1; a4 only behind r1."""
    ids = {}
    for n, (mac, role) in enumerate([("d1", "switch_access"), ("d2", "switch_access"), ("a1", "switch_access"),
                                     ("a2", "switch_access"), ("a3", "switch_access"), ("r1", "router_edge"),
                                     ("a4", "switch_access")]):
        d = ctx.db.upsert(mac=f"aa:00:00:00:01:{n:02x}", pid="C9300-24P", ip=f"172.30.0.{n + 10}")
        ctx.db.x("UPDATE devices SET role=?, hostname=? WHERE id=?", role, mac, d["id"])
        ids[mac] = d["id"]
    ctx.preview(list(ids.values()), ports={str(i): "Ethernet0/3" if n != "d1" else "Ethernet1/3" for n, i in ids.items()})
    for i in ids.values():
        ctx.db.set_state(i, "provisioned")
    for n in ("d1", "d2"):  # the two L3 switches (as the SSH probe records it)
        ctx.db.set_vars(ids[n], {**ctx.db.vars(ids[n]), "cap_ip_routing": True})

    def e(a, pa, b, pb):
        return {"from": ids[a], "to": ids[b], "from_port": pa, "to_port": pb}
    edges = [e("d1", "Ethernet0/2", "d2", "Ethernet0/2"), e("d1", "Ethernet1/0", "a1", "Ethernet0/1"),
             e("a1", "Ethernet0/2", "a3", "Ethernet0/1"), e("d2", "Ethernet1/0", "a2", "Ethernet0/1"),
             e("r1", "Ethernet0/2", "d1", "Ethernet0/1"), e("r1", "Ethernet0/1", "a4", "Ethernet0/1")]
    # every box's Ethernet0/0 on one out-of-band switch: everyone is everyone's CDP neighbor there (as on IOL)
    names = list(ids)
    edges += [e(a, "Ethernet0/0", b, "Ethernet0/0") for k, a in enumerate(names) for b in names[k + 1:]]
    return ids, edges


def test_mgmt_design_plans_domains_trunks_and_router_subinterface(ctx):
    from pandora import mgmt
    ids, edges = _campus(ctx)
    sug = mgmt.suggest(ctx.db.devices(), [ids["d1"], ids["d2"]], edges)
    assert sug == {ids["a1"]: ids["d1"], ids["a3"]: ids["d1"], ids["r1"]: ids["d1"], ids["a2"]: ids["d2"]}
    assert ids["a4"] not in sug  # only reachable through a router: no suggestion
    doms = [{"backbone": ids["d1"], "vlan": 10, "subnet": "10.10.0.0/24"},
            {"backbone": ids["d2"], "vlan": 20, "subnet": "10.20.0.0/24"}]
    p = mgmt.plan(ctx, doms, sug, edges)
    assert p["ok"], p["problems"]
    by = {d["hostname"]: d for d in p["devices"]}
    ops_ip = {n: ctx.db.q("SELECT mgmt_ip FROM allocations WHERE device_id=?", ids[n])[0]["mgmt_ip"] for n in ids}
    d1 = "\n".join(by["d1"]["lines"])
    assert "ip routing" in d1 and "interface Vlan10\n description PANDORA-MGMT domain gateway\n ip address 10.10.0.1 255.255.255.0" in d1
    assert f"ip route 10.20.0.0 255.255.255.0 {ops_ip['d2']}" in d1  # the other domain, via d2's ops address
    assert by["d1"]["trunks"] == ["Ethernet0/1", "Ethernet0/2", "Ethernet1/0"]
    a1 = "\n".join(by["a1"]["lines"])
    assert "interface Vlan10" in a1 and "ip default-gateway 10.10.0.1" in a1 and by["a1"]["new_ip"] == "10.10.0.10"
    assert by["a1"]["trunks"] == ["Ethernet0/1", "Ethernet0/2"]  # its uplink, and the link a3 hangs off
    assert "switchport trunk allowed vlan add 10,99" in a1
    r1 = "\n".join(by["r1"]["lines"])
    assert "interface Ethernet0/2.10\n description PANDORA-MGMT via d1\n encapsulation dot1Q 10" in r1
    assert "ip route 10.99.0.0 255.255.255.0 10.10.0.1" in r1 and "ip route 0.0.0.0" not in r1  # no default route
    assert "switchport" not in r1
    assert not any("Ethernet0/0" in d["trunks"] for d in p["devices"])  # the shared out-of-band segment is no link
    assert "switchport trunk allowed vlan add 99" in "\n".join(by["d2"]["lines"])  # backbone link: ops VLAN
    assert {r["subnet"]: r["via"] for r in p["pc_routes"]} == {"10.10.0.0/24": ops_ip["d1"], "10.20.0.0/24": ops_ip["d2"]}

    bad = mgmt.plan(ctx, doms + [{"backbone": ids["r1"], "vlan": 20, "subnet": "10.99.0.0/25"}],
                    {**sug, ids["a4"]: ids["d1"]}, edges)
    text = " ".join(bad["problems"])
    assert not bad["ok"] and "edge router" in text and "VLAN 20 is not free" in text and "overlaps" in text
    assert "a4 has no CDP path" in text  # behind a router: the VLAN can't be bridged there


def test_mgmt_design_keeps_reserved_ports_off_management_paths(ctx):
    from pandora import mgmt
    ids, edges = _campus(ctx)
    edges[1] = {**edges[1], "to_port": "Ethernet0/3"}  # a1's uplink is its reserved PC port
    p = mgmt.plan(ctx, [{"backbone": ids["d1"], "vlan": 10, "subnet": "10.10.0.0/24"}], {ids["a1"]: ids["d1"]}, edges)
    assert not p["ok"] and any("reserved PC port" in x for x in p["problems"])


def test_compliance_checks_the_management_design_as_ios_prints_it():
    design = ("vlan 10\n name PANDORA-MGMT-10\ninterface Vlan10\n description PANDORA-MGMT via d1\n"
              " ip address 10.10.0.10 255.255.255.0\n no shutdown\nip default-gateway 10.10.0.1\nip routing\n"
              "interface Ethernet0/1\n switchport trunk encapsulation dot1q\n switchport mode trunk\n"
              " switchport trunk allowed vlan add 10,99")
    base = ("hostname a1\nvlan 10\n name PANDORA-MGMT-10\ninterface Vlan10\n description PANDORA-MGMT via d1\n"
            " ip address 10.10.0.10 255.255.255.0\nip default-gateway 10.10.0.1\n")
    trunk = "interface Ethernet0/1\n switchport trunk encapsulation dot1q\n switchport mode trunk\n"

    def check(running):
        r = compliance.compare("hostname a1", running, [], 99, design)
        return r, {f["name"]: f["compliant"] for f in r["features"]}

    r, f = check(base + trunk)  # all VLANs allowed: IOS prints no list; "ip routing" hidden by default
    assert r["compliant"] and f["mgmt-design"], r
    r, f = check(base + trunk + " switchport trunk allowed vlan 1-9\n switchport trunk allowed vlan add 10,99\n")
    assert f["mgmt-design"], r  # a long list split over two lines still holds
    r, f = check(base + trunk + " switchport trunk allowed vlan 1-5,10\n")  # someone pruned VLAN 99
    assert not f["mgmt-design"] and " switchport trunk allowed vlan add 10,99" in r["remediation"]
    r, f = check(base + "interface Ethernet0/1\n switchport mode access\n")  # the trunk was undone
    assert not f["mgmt-design"] and " switchport mode trunk" in r["remediation"]
    r, f = check(base.replace("ip default-gateway 10.10.0.1\n", "") + trunk)
    assert not f["mgmt-design"] and "ip default-gateway 10.10.0.1" in r["remediation"]
    assert f["hostname"]  # the rest of the device is judged as before
    r, f = check(base + trunk + "no ip routing\n")  # routing turned off on purpose: IOS prints it, so it shows
    assert not f["mgmt-design"] and "ip routing" in r["remediation"]
    r, f = check(base + trunk + " switchport trunk allowed vlan remove 99\n")  # not a form IOS prints: not trusted
    assert not f["mgmt-design"]
    r, f = check(base + trunk + " Switchport Trunk Allowed VLAN remove 99\n")  # any spelling: still not trusted
    assert not f["mgmt-design"]
    r, f = check(base + trunk + " switchport trunk allowed vlan 1-999999999\n")  # not a VLAN range: fail closed
    assert not f["mgmt-design"]


def test_backbone_must_be_an_l3_switch(ctx):
    from pandora import mgmt
    from pandora.deliver import parse_caps
    assert parse_caps("", "", "", "ip routing ?\n  <cr>  <cr>\n") == {"cap_ip_routing": True}  # IOL / Cat9k
    assert parse_caps("", "", "", "ip routing ?\n% Unrecognized command\n") == {"cap_ip_routing": False}
    assert parse_caps("", "", "", "") == {}  # unreadable help: unknown, never guessed
    assert parse_caps("", "", "", "ip routing ?\n% Ambiguous command: \"ip routing\"\n") == {}  # unknown, not yes
    assert parse_caps("", "", "", "ip routing ? see <cr> below\n  protocol  Something\n") == {}  # <cr> not on its own
    ids, edges = _campus(ctx)
    dom = [{"backbone": ids["a2"], "vlan": 10, "subnet": "10.10.0.0/24"}]
    ctx.db.set_vars(ids["a2"], {**ctx.db.vars(ids["a2"]), "cap_ip_routing": False})  # a 2960 LAN Base, say
    p = mgmt.plan(ctx, dom, {}, edges)
    assert not p["ok"] and any("layer-2-only" in x for x in p["problems"])
    ctx.db.set_vars(ids["a2"], {k: v for k, v in ctx.db.vars(ids["a2"]).items() if k != "cap_ip_routing"})
    p = mgmt.plan(ctx, dom, {}, edges)  # never probed and no answer: blocked, not assumed
    assert not p["ok"] and any("could not check" in x for x in p["problems"])


def test_retired_ops_address_is_what_compliance_expects(ctx):
    d = add(ctx, 91)
    text, problems, a = ctx.render(d["id"])
    assert not problems and f" ip address {a['mgmt_ip']} " in text
    ctx.db.set_vars(d["id"], {"ops_retired": True})
    text, _, _ = ctx.render(d["id"])
    assert f"interface Vlan{ctx.cfg['mgmt_vlan']}\n description PANDORA-MGMT\n no ip address\n" in text
    assert a["mgmt_ip"] not in text


def test_topology_keeps_cables_and_drops_a_shared_segment():
    from pandora.topology import point_to_point
    e = lambda a, ap, b, bp: {"from": a, "from_port": ap, "to": b, "to_port": bp}  # noqa: E731
    cable = e(1, "Et0/1", 2, "Et0/1")
    mesh = [e(a, "Et0/0", b, "Et0/0") for a in (1, 2, 3) for b in (1, 2, 3) if a < b]  # IOL's shared e0/0 bridge
    keep, dropped = point_to_point([cable, *mesh])
    assert keep == [cable] and dropped == 3


def test_changing_the_role_before_claiming_renames_the_box(ctx):
    d = add(ctx, 92)
    first = ctx.preview([d["id"]], role="switch_access")[0]
    again = ctx.preview([d["id"]], role="router_edge")[0]
    assert "-sw-" in first["hostname"] and "-rtr-" in again["hostname"], (first["hostname"], again["hostname"])
    assert ctx.preview([d["id"]], role="router_edge")[0]["hostname"] == again["hostname"]  # same role: same name


def test_a_name_that_may_have_reached_the_box_is_kept_on_a_role_change(ctx):
    d = add(ctx, 93)
    first = ctx.preview([d["id"]], role="switch_access")[0]
    ctx.db.save_config(d["id"], "pnp", "hostname x", "failed half way")  # something was sent
    ctx.db.set_state(d["id"], "failed", "push failed")
    again = ctx.preview([d["id"]], role="router_edge")[0]
    assert (again["hostname"], again["mgmt_ip"]) == (first["hostname"], first["mgmt_ip"])
