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
