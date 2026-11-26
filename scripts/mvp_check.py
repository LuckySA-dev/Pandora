"""End-to-end MVP check against a simulated lab (no Cisco hardware needed).

    python scripts/mvp_check.py            # run every check, print PASS/FAIL
    python scripts/mvp_check.py --serve    # then keep the lab + UI up on http://127.0.0.1:8097

Fakes: IOS / IOS-XE devices over SSH (paramiko) and over a fake COM port, an SNMPv3 agent (snmpsim).
Real: the PandoraBox app over HTTP, PnP/ZTP over HTTP, AutoInstall over TFTP, DHCP decisions, netmiko,
textfsm, pysnmp, the SNMP inform receiver, the web terminal websocket and the agent's tools.
Simulated devices use 127.0.0.x / 127.0.1.x source addresses so each one looks like its own host.
"""
import asyncio
import json
import os
import re
import shutil
import socket
import subprocess
import sys
import tempfile
import threading
import time
import traceback
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))

import httpx  # noqa: E402
import paramiko  # noqa: E402
import uvicorn  # noqa: E402

from pandora import access, config, console  # noqa: E402
from pandora.agent import loop as agent_loop  # noqa: E402
from pandora.agent import tools as agent_tools  # noqa: E402
from pandora.app import create_app  # noqa: E402
from pandora.db import DB  # noqa: E402
from pandora.deliver import Ctx  # noqa: E402
from pandora.net import dhcp, tftp  # noqa: E402

PORT = 8097  # not 8099: the containerlab small lab publishes its PandoraBox container there (WSL relay)
BASE = f"http://127.0.0.1:{PORT}"
SECRETS = {"admin_password": "Adm1nPass!", "snmp_auth": "AuthKey123", "snmp_priv": "PrivKey123"}
REGISTRY: dict[str, "FakeIOS"] = {}  # ip -> device answering SSH there
RESULTS = []


# =====================================================================================
# Fake Cisco device
# =====================================================================================
class FakeIOS:
    def __init__(self, name, pid, serial, xe=True, factory=True, user=None, password=None, cdp=None):
        self.name, self.pid, self.serial, self.xe, self.factory = name, pid, serial, xe, factory
        self.hostname = "Switch" if factory else name
        self.users = {user: password} if user else {}
        self.running = [] if factory else [f"hostname {name}", f"username {user} privilege 15 secret 9 $9$x",
                                           "interface Vlan1", " ip address 192.168.1.10 255.255.255.0",
                                           "interface GigabitEthernet1/0/47", " switchport mode trunk",
                                           "interface GigabitEthernet1/0/48", " switchport mode trunk"]
        self.has_keys = not factory
        self.cdp = cdp or []
        self.snapshots = {}
        self.crypto_prompts = 0
        self.saved = False
        self.lock = threading.RLock()

    def version(self):
        if self.xe:
            return (f"Cisco IOS XE Software, Version 17.09.04a\r\nCisco IOS Software [Cupertino], Catalyst L3 Switch "
                    f"Software (CAT9K_IOSXE), Version 17.9.4a, RELEASE SOFTWARE (fc3)\r\n{self.hostname} uptime is 1 hour"
                    f"\r\nModel Number                       : {self.pid}\r\nSystem Serial Number               : {self.serial}")
        return (f"Cisco IOS Software, C2960X Software (C2960X-UNIVERSALK9-M), Version 15.2(7)E9, RELEASE SOFTWARE (fc1)"
                f"\r\n{self.hostname} uptime is 5 minutes\r\ncisco {self.pid} (APM86XXX) processor (revision B0) with "
                f"524288K bytes of memory.\r\nProcessor board ID {self.serial}")

    def cdp_text(self):
        out = []
        for n in self.cdp:
            out.append(f"-------------------------\r\nDevice ID: {n['name']}\r\nEntry address(es): \r\n  IP address: "
                       f"{n['ip']}\r\nPlatform: cisco {n['platform']},  Capabilities: Switch IGMP \r\nInterface: "
                       f"{n['local']},  Port ID (outgoing port): {n['remote']}\r\nHoldtime : 150 sec\r\n\r\nVersion :\r\n"
                       f"Cisco IOS Software\r\n\r\nadvertisement version: 2\r\nManagement address(es): \r\n  IP address: "
                       f"{n['ip']}\r\n")
        return "\r\n".join(out)

    def apply(self, lines):
        """What PnP / ZTP / AutoInstall do on the box: config lines straight into running-config."""
        s = Session(self, console=False)
        s.mode = "config"
        for line in lines:
            if line.strip() and not line.lstrip().startswith("!"):
                s.config_line(line)
        self.saved = True


class Session:
    """One CLI session (SSH channel or console). line(text) -> what the device prints next."""

    def __init__(self, dev, console):
        self.dev, self.console = dev, console
        self.current_if = None
        self.parent = None  # index in running-config of the block being configured
        self.pending = None
        self.fresh = console
        if console and dev.factory:
            self.mode = "dialog"
        elif console and dev.users:
            self.mode = "login_user"
        elif console:
            self.mode = "user"
        else:
            self.mode = "priv"  # SSH: priv-15 user lands at #
        self.login_user = None

    def prompt(self):
        h = self.dev.hostname
        return {"user": f"{h}>", "priv": f"{h}#", "config": f"{h}(config)#", "sub": f"{h}(config-if)#"}[self.mode]

    def banner(self):
        return "" if self.console else f"\r\n{self.prompt()}"

    def line(self, text) -> str:
        with self.dev.lock:
            body, show_prompt = self._line(text.rstrip("\r\n"))
        if not show_prompt:
            return body
        return "\r\n" + (body + "\r\n" if body else "") + self.prompt()

    def _line(self, t):
        d = self.dev
        if self.mode == "dialog":
            if t.strip().lower() == "no":
                self.mode = "autoinstall"
                return "\r\nWould you like to terminate autoinstall? [yes]: ", False
            return ("\r\n         --- System Configuration Dialog ---\r\n\r\nWould you like to enter the initial "
                    "configuration dialog? [yes/no]: "), False
        if self.mode == "autoinstall":
            self.mode = "return"
            return "\r\n\r\nPress RETURN to get started!\r\n", False
        if self.mode == "return":
            self.mode = "user"
            return "", True
        if self.mode == "login_user":
            if self.fresh or not t:
                self.fresh = False
                return "\r\nUser Access Verification\r\n\r\nUsername: ", False
            self.login_user, self.mode = t.strip(), "login_pass"
            return "\r\nPassword: ", False
        if self.mode == "login_pass":
            if d.users.get(self.login_user) == t.strip():
                self.mode = "priv"
                return "", True
            self.mode = "login_user"
            return "\r\n% Login invalid\r\n\r\nUsername: ", False
        if self.pending:
            fn, self.pending = self.pending, None
            return fn(t)
        cmd = t.strip()
        if self.mode in ("config", "sub"):
            return self.config_line(t), True
        if self.mode == "user":
            if cmd == "enable":
                self.mode = "priv"
                return "", True
            if cmd.startswith("show") or cmd == "":
                return self.exec_cmd(cmd), True
            return "% Invalid input detected at '^' marker.", True
        return self.exec_cmd(cmd), True

    def exec_cmd(self, cmd):
        d = self.dev
        if cmd in ("", "enable") or cmd.startswith(("terminal ", "term ")):
            return ""
        if cmd == "show version":
            return d.version()
        if cmd == "show inventory":
            return f'NAME: "Chassis", DESCR: "Cisco switch"\r\nPID: {d.pid}  , VID: V01  , SN: {d.serial}'
        if cmd.startswith("show running-config"):
            return "Building configuration...\r\n\r\nCurrent configuration : 4096 bytes\r\n!\r\n" + "\r\n".join(d.running) + "\r\nend"
        if cmd == "show cdp neighbors detail":
            return d.cdp_text()
        if cmd == "show clock":
            return "*12:00:00.000 UTC Tue Nov 24 2026"
        if cmd.startswith("show"):
            return ""
        if cmd.startswith("ping"):
            return "!!!!!\r\nSuccess rate is 100 percent (5/5)"
        if cmd in ("configure terminal", "conf t"):
            self.mode = "config"
            return "Enter configuration commands, one per line.  End with CNTL/Z."
        if cmd in ("write memory", "write mem", "copy running-config startup-config"):
            d.saved = True
            return "Building configuration...\r\n[OK]"
        m = re.match(r"copy running-config (flash:\S+)", cmd)
        if m:
            def confirm(_):
                d.snapshots[m.group(1)] = list(d.running)
                return "\r\n4096 bytes copied in 0.120 secs", True
            self.pending = confirm
            return f"Destination filename [{m.group(1).split(':')[1]}]? "
        m = re.match(r"configure replace (flash:\S+) force", cmd)
        if m and m.group(1) in d.snapshots:
            d.running = list(d.snapshots[m.group(1)])
            return "Total number of passes: 1\r\nRollback Done"
        return "% Invalid input detected at '^' marker."

    def config_line(self, raw):
        d, t = self.dev, raw.strip()
        if t in ("end", "\x1a"):
            self.mode = "priv"
            return ""
        if t == "exit":
            self.mode = "config" if self.mode == "sub" else "priv"
            return ""
        if t.startswith("do "):
            return self.exec_cmd(t[3:])
        if t.startswith("this-is-invalid"):
            return "% Invalid input detected at '^' marker."
        if t.startswith("crypto key generate"):
            if d.has_keys:
                d.crypto_prompts += 1

                def answer(a):
                    if a.strip().lower() not in ("yes", "no"):
                        return "% Please answer 'yes' or 'no'.\r\n% Do you really want to replace them? [yes/no]: ", False
                    return "", True
                self.pending = answer
                return "% You already have RSA keys defined named pandora.\r\n% Do you really want to replace them? [yes/no]: "
            d.has_keys = True
            return "% Generating 2048 bit RSA keys, keys will be non-exportable...\r\n[OK] (elapsed time was 1 seconds)"
        if not raw.startswith(" "):
            self.current_if = None
            self.mode = "config"
        if t.startswith(("interface", "line ", "vlan ", "event manager applet")):
            self.mode = "sub"
            self.current_if = t.split(None, 1)[1] if t.startswith("interface") else None
        m = re.match(r"hostname (\S+)", t)
        if m:
            d.hostname = m.group(1)
        m = re.match(r"username (\S+) privilege 15 secret (\S+)", t)
        if m:
            d.users[m.group(1)] = m.group(2)
        m = re.match(r"ip address (\d+\.\d+\.\d+\.\d+) ", t)
        if m and self.current_if:
            REGISTRY[m.group(1)] = d
        line = raw.rstrip()
        if not raw.startswith(" "):  # top-level: like IOS, re-enter an existing block / replace a hostname
            if t.startswith("hostname "):
                d.running = [l for l in d.running if not l.startswith("hostname ")]
            if t.startswith("no ") and t[3:] in d.running:
                d.running.remove(t[3:])
                self.parent = None
                return ""
            if line in d.running:
                self.parent = d.running.index(line)
                return ""
            d.running.append(line)
            self.parent = len(d.running) - 1
            return ""
        if self.parent is None:  # sub-command without a parent we know: keep it at the end
            d.running.append(line)
            return ""
        end = self.parent + 1
        while end < len(d.running) and d.running[end].startswith(" "):
            end += 1
        block = d.running[self.parent + 1:end]
        if t.startswith("no ") and t[3:] in [b.strip() for b in block]:  # "no shutdown" removes "shutdown"
            del d.running[self.parent + 1 + [b.strip() for b in block].index(t[3:])]
            return ""
        if line not in block:
            d.running.insert(end, line)
        return ""


# =====================================================================================
# Fake transports: SSH server per IP, COM port
# =====================================================================================
HOSTKEY = paramiko.RSAKey.generate(2048)


class _Srv(paramiko.ServerInterface):
    def __init__(self, dev):
        self.dev = dev

    def check_auth_password(self, user, password):
        return paramiko.AUTH_SUCCESSFUL if self.dev.users.get(user) == password else paramiko.AUTH_FAILED

    def get_allowed_auths(self, user):
        return "password"

    def check_channel_request(self, kind, chanid):
        return paramiko.OPEN_SUCCEEDED if kind == "session" else paramiko.OPEN_FAILED_ADMINISTRATIVELY_PROHIBITED

    def check_channel_shell_request(self, channel):
        return True

    def check_channel_pty_request(self, *a):
        return True


def _serve_conn(conn, ip):
    dev = REGISTRY.get(ip)
    if dev is None:
        return conn.close()
    t = paramiko.Transport(conn)
    t.add_server_key(getattr(dev, "hostkey", None) or HOSTKEY)
    try:
        t.start_server(server=_Srv(dev))
        chan = t.accept(20)
        if chan is None:
            return
        s, buf, last = Session(dev, console=False), "", ""
        chan.send(s.banner())
        while True:
            data = chan.recv(1024)
            if not data:
                break
            for ch in data.decode("latin-1"):
                if ch == "\n" and last == "\r":
                    last = ch
                    continue
                last = ch
                if ch in "\x7f\x08":  # backspace / DEL: like IOS, erase one character and wipe it on screen
                    if buf:
                        buf = buf[:-1]
                        chan.send("\b \b")
                elif ch in "\r\n":
                    chan.send(s.line(buf))
                    buf = ""
                else:
                    buf += ch
                    chan.send(ch)
    except Exception:
        pass
    finally:
        t.close()


def start_ssh_listeners(ips):
    for ip in ips:
        srv = socket.socket()
        srv.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        srv.bind((ip, 22))
        srv.listen(8)

        def loop(srv=srv, ip=ip):
            while True:
                c, _ = srv.accept()
                if ip not in REGISTRY:  # behave like a closed port for ssh_open()
                    c.close()
                    continue
                threading.Thread(target=_serve_conn, args=(c, ip), daemon=True).start()
        threading.Thread(target=loop, daemon=True).start()


CONSOLES: dict[str, FakeIOS] = {}


class FakeSerial:
    def __init__(self, port, baud=9600, timeout=0.2):
        self.dev = CONSOLES[port]
        self.s, self.out, self.buf, self.timeout = Session(self.dev, console=True), "", "", timeout

    def write(self, b):
        for ch in b.decode("latin-1"):
            if ch in "\x7f\x08":
                if self.buf:
                    self.buf = self.buf[:-1]
                    self.out += "\b \b"
            elif ch in "\r\n":
                self.out += self.s.line(self.buf)
                self.buf = ""
            else:
                self.buf += ch
        return len(b)

    def read(self, n):
        if not self.out:
            time.sleep(self.timeout)
            return b""
        chunk, self.out = self.out[:n], self.out[n:]
        return chunk.encode("latin-1")

    def close(self):
        pass


class _Port:
    def __init__(self, device):
        self.device = device


def install_fake_consoles():
    console.serial.Serial = FakeSerial
    console.serial.serial_for_url = lambda port, *a, **k: FakeSerial(port, *a, **k)
    console.list_ports.comports = lambda: [_Port(p) for p in CONSOLES]


# =====================================================================================
# SNMP agent (snmpsim) for the existing switch
# =====================================================================================
def snmprec(dev_ip_for_cdp_neighbor):
    recs = {
        "1.3.6.1.2.1.1.1.0": "4|Cisco IOS XE Software, Version 17.12.04, Catalyst L3 Switch Software (CAT9K_IOSXE)",
        "1.3.6.1.2.1.1.2.0": "6|1.3.6.1.4.1.9.1.2494",
        "1.3.6.1.2.1.1.5.0": "4|core-sw.pandora.local",
        "1.3.6.1.2.1.47.1.1.1.1.11.1000": "4|FOC3333X0CC",
        "1.3.6.1.2.1.47.1.1.1.1.13.1000": "4|C9300-48P",
        "1.3.6.1.2.1.2.2.1.8.1": "2|1", "1.3.6.1.2.1.2.2.1.8.2": "2|2",
        "1.3.6.1.2.1.31.1.1.1.1.1": "4|Gi1/0/1", "1.3.6.1.2.1.31.1.1.1.1.2": "4|Gi1/0/2",
        "1.3.6.1.2.1.31.1.1.1.6.1": "70|123456", "1.3.6.1.2.1.31.1.1.1.6.2": "70|0",
        "1.3.6.1.2.1.31.1.1.1.10.1": "70|654321", "1.3.6.1.2.1.31.1.1.1.10.2": "70|0",
        "1.3.6.1.4.1.9.9.109.1.1.1.1.8.1": "66|7",
        "1.3.6.1.4.1.9.9.23.1.2.1.1.4.1.1": "4x|" + socket.inet_aton(dev_ip_for_cdp_neighbor).hex(),
        "1.3.6.1.4.1.9.9.23.1.2.1.1.6.1.1": "4|lab-sw-01",
        "1.3.6.1.4.1.9.9.23.1.2.1.1.7.1.1": "4|GigabitEthernet1/0/48",
        "1.3.6.1.4.1.9.9.23.1.2.1.1.8.1.1": "4|cisco C9300-24P",
    }
    key = lambda o: tuple(int(x) for x in o.split("."))
    return "\n".join(f"{o}|{recs[o]}" for o in sorted(recs, key=key)) + "\n"


def start_snmpsim(workdir: Path, ip, cdp_ip):
    data = workdir / "snmp-data"
    data.mkdir(parents=True, exist_ok=True)
    # Real Cisco agents (and pandora) use an empty SNMPv3 context; snmpsim maps that to a file named "self".
    (data / "self.snmprec").write_text(snmprec(cdp_ip))
    beside = Path(sys.executable).parent / "snmpsim-command-responder.exe"  # a venv run without activating it
    exe = shutil.which("snmpsim-command-responder") or (str(beside) if beside.exists() else None) or str(
        Path(os.environ.get("APPDATA", "")) / "Python" / f"Python{sys.version_info.major}{sys.version_info.minor}"
        / "Scripts" / "snmpsim-command-responder.exe")
    args = [exe, f"--data-dir={data}", f"--agent-udpv4-endpoint={ip}:161", f"--cache-dir={workdir / 'snmp-cache'}",
            "--v3-user=pandora", f"--v3-auth-key={SECRETS['snmp_auth']}", "--v3-auth-proto=SHA",
            f"--v3-priv-key={SECRETS['snmp_priv']}", "--v3-priv-proto=AES", f"--logging-method=file:{workdir / 'snmpsim.log'}"]
    return subprocess.Popen(args, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)


# =====================================================================================
# helpers
# =====================================================================================
def check(name):
    def deco(fn):
        t0 = time.time()
        try:
            detail = fn() or ""
            RESULTS.append((True, name, detail, time.time() - t0))
            print(f"PASS  {name}  {detail}", flush=True)
        except Exception as e:
            RESULTS.append((False, name, f"{type(e).__name__}: {e}", time.time() - t0))
            print(f"FAIL  {name}  {type(e).__name__}: {e}", flush=True)
            traceback.print_exc(limit=3)
        return fn
    return deco


def wait_for(pred, timeout=60, step=0.5, what="condition"):
    end = time.time() + timeout
    while time.time() < end:
        v = pred()
        if v:
            return v
        time.sleep(step)
    raise TimeoutError(f"timed out waiting for {what}")


def ui():
    return httpx.Client(base_url=BASE, timeout=120)


def from_ip(ip):
    """HTTP client whose packets come from `ip`, like a device on the provisioning subnet."""
    return httpx.Client(base_url=BASE, timeout=30, transport=httpx.HTTPTransport(local_address=ip))


def discover_pkt(mac, vendor=b""):
    hdr = dhcp.HDR.pack(1, 1, 6, 0, 0x1234, 0, 0, *(b"\0" * 4,) * 4, bytes.fromhex(mac.replace(":", "")) + b"\0" * 10,
                        b"\0" * 64, b"\0" * 128, dhcp.MAGIC)
    return hdr + b"\x35\x01\x01" + (bytes([60, len(vendor)]) + vendor if vendor else b"") + b"\xff"


def request_pkt(mac, ip):
    hdr = dhcp.HDR.pack(1, 1, 6, 0, 0x1234, 0, 0, *(bytes(4),) * 4, bytes.fromhex(mac.replace(':', '')) + bytes(10),
                        bytes(64), bytes(128), dhcp.MAGIC)
    return hdr + bytes([53, 1, 3, 50, 4]) + socket.inet_aton(ip) + bytes([255])


def dev_state(ctx, **key):
    d = ctx.db.find(**key)
    return d and d["state"]


# =====================================================================================
# the run
# =====================================================================================
def main():
    serve = "--serve" in sys.argv
    work = Path(tempfile.mkdtemp(prefix="pandora-mvp-"))
    cfg = config.load(work / "none.toml")
    cfg.update(SECRETS, server_ip="127.0.0.1", netmask="255.0.0.0", http_port=PORT,
               mgmt_range="127.0.0.10-127.0.0.40", dhcp_range="127.0.1.100-127.0.1.150", iface="loopback")
    ctx = Ctx(DB(str(work / "pandora.db")), cfg)
    app = create_app(ctx)
    server = uvicorn.Server(uvicorn.Config(app, host="127.0.0.1", port=PORT, log_level="warning"))
    threading.Thread(target=server.run, daemon=True).start()
    wait_for(lambda: server.started, 20, what="uvicorn")

    # ---- lab -----------------------------------------------------------------------
    start_ssh_listeners([f"127.0.0.{i}" for i in range(2, 41)])
    core = FakeIOS("core-sw", "C9300-48P", "FOC3333X0CC", factory=False, user="admin", password="cisco123",
                   cdp=[{"name": "lab-sw-01.pandora.local", "ip": "127.0.0.10", "platform": "C9300-24P",
                         "local": "GigabitEthernet1/0/1", "remote": "GigabitEthernet1/0/48"}])
    REGISTRY["127.0.0.2"] = core
    snmpsim = start_snmpsim(work, "127.0.0.2", "127.0.0.10")
    tftp.start("127.0.0.1", work / "tftp", ctx.tftp_lookup)
    dsrv = dhcp.DhcpServer("127.0.0.1", "255.0.0.0", config.ip_range(cfg["dhcp_range"]), ctx.dhcp_decide)

    pnp_box = FakeIOS("pnp", "C9300-24P", "FOC1111X0AA",
                      cdp=[{"name": "core-sw.pandora.local", "ip": "127.0.0.2", "platform": "C9300-48P",
                            "local": "GigabitEthernet1/0/48", "remote": "GigabitEthernet1/0/1"}])
    ztp_box = FakeIOS("ztp", "C9300-48P", "FOC2222X0BB")
    ai_box = FakeIOS("ai", "WS-C2960X-24TS-L", "FOC4444X0DD", xe=False)
    CONSOLES["COM98"] = FakeIOS("con-old", "C9200L-24T-4G", "JAE5555X0EE", factory=False)  # configured, no login
    CONSOLES["COM99"] = FakeIOS("con", "C9200L-24T-4G", "JAE6666X0FF")                       # factory
    install_fake_consoles()
    macs = {"pnp": "aa:00:00:00:00:01", "ztp": "aa:00:00:00:00:02", "ai": "aa:00:00:00:00:03"}
    c = ui()

    # ---- 1. discovery ---------------------------------------------------------------
    @check("discovery: DHCP sees all 3 LAN boxes, only the PnP one gets options before selection")
    def _():
        o1 = dsrv.handle(discover_pkt(macs["pnp"], b"ciscopnp"))
        o2 = dsrv.handle(discover_pkt(macs["ztp"]))
        o3 = dsrv.handle(discover_pkt(macs["ai"]))
        assert o1 and 43 in dhcp.parse(o1)["options"] and o2 is None and o3 is None
        assert all(ctx.db.find(mac=m) for m in macs.values())
        return f"leases {dsrv.leases}"

    @check("discovery: PnP agent identifies itself, gets backoff (not configured) until selected")
    def _():
        h = from_ip(dsrv.leases[macs["pnp"]])
        udi = f"PID:{pnp_box.pid},VID:V01,SN:{pnp_box.serial}"
        r = h.post("/pnp/WORK-REQUEST", content=_wr(udi)).text
        assert "device-info" in r
        h.post("/pnp/WORK-RESPONSE", content=_resp(udi, True, "<hardwareInfo><platformName>C9300-24P</platformName>"
               "</hardwareInfo><imageInfo><versionString>17.9.4a</versionString></imageInfo>"))
        assert "callbackAfter" in h.post("/pnp/WORK-REQUEST", content=_wr(udi)).text
        d = ctx.db.find(serial=pnp_box.serial)
        assert d["state"] == "identified" and d["os_type"] == "iosxe" and d["mac"] == macs["pnp"]
        return f"#{d['id']} {d['pid']} {d['version']}"

    @check("discovery: console watcher finds both COM ports and reads the configured one")
    def _():
        seen = {}
        for port in CONSOLES:
            r = console.probe(port)
            seen[port] = r["console_state"]
            facts = {k: v for k, v in r.items() if k != "console_state"}
            ctx.db.upsert(console_port=port, source="console", path="console", note=f"console: {r['console_state']}", **facts)
        assert seen == {"COM98": "user", "COM99": "dialog"}, seen
        assert ctx.db.find(console_port="COM98")["serial"] == "JAE5555X0EE"
        return str(seen)

    @check("discovery: SNMPv3 sweep finds the already-configured switch")
    def _():
        rows = wait_for(lambda: c.post("/api/snmp/sweep", json={"subnet": "127.0.0.0/30"}).json(), 20, 2, "snmpsim")
        d = rows[0]
        assert d["serial"] == "FOC3333X0CC" and d["pid"] == "C9300-48P" and d["os_type"] == "iosxe"
        assert ctx.db.device(d["id"])["path"] == "ssh"
        return f"#{d['id']} {d['hostname']} {d['version']}"

    @check("inventory: nothing was configured during discovery")
    def _():
        assert not (pnp_box.running or ztp_box.running or ai_box.running or CONSOLES["COM99"].running)
        assert all(d["state"] in ("discovered", "identified") for d in c.get("/api/devices").json())
        return f"{len(c.get('/api/devices').json())} devices in inventory"

    # ---- 2. select, preview, allocate --------------------------------------------------
    ids = {}

    @check("preview: conflict-free names/IPs/reserved ports; existing switch gets no guessed ports")
    def _():
        ids.update(pnp=ctx.db.find(serial=pnp_box.serial)["id"], ztp=ctx.db.find(mac=macs["ztp"])["id"],
                   ai=ctx.db.find(mac=macs["ai"])["id"], con=ctx.db.find(console_port="COM99")["id"],
                   old=ctx.db.find(console_port="COM98")["id"], core=ctx.db.find(serial="FOC3333X0CC")["id"])
        c.patch(f"/api/devices/{ids['ztp']}", json={"path": "ztp"})
        ctx.db.upsert(mac=macs["ztp"], pid=ztp_box.pid)        # PID learned e.g. from a label/opt 124
        ctx.db.upsert(mac=macs["ai"], pid=ai_box.pid)
        rows = c.post("/api/preview", json={"ids": list(ids.values())}).json()
        by = {r["id"]: r for r in rows}
        names = [r["hostname"] for r in rows]
        ips = [r["mgmt_ip"] for r in rows]
        assert len(set(names)) == len(names) and len(set(ips)) == len(ips), (names, ips)
        assert by[ids["pnp"]]["reserved_ports"] == ["GigabitEthernet1/0/23", "GigabitEthernet1/0/24"]
        assert by[ids["ai"]]["reserved_ports"] == ["GigabitEthernet1/0/23", "GigabitEthernet1/0/24"]
        assert by[ids["core"]]["reserved_ports"] == [] and by[ids["core"]]["problems"]
        assert not by[ids["pnp"]]["problems"]
        return ", ".join(f"{r['hostname']}={r['mgmt_ip']}" for r in rows)

    @check("wizard: role vars render; using a reserved port is flagged")
    def _():
        bad = c.post("/api/preview", json={"ids": [ids["ztp"]], "role": "switch_access",
                                           "vars": {"access_ports": [{"ports": "Gi1/0/1 - 48", "vlan": 10}]}}).json()[0]
        assert any("reserved" in p for p in bad["problems"])
        ok = c.post("/api/preview", json={"ids": [ids["ztp"]], "role": "switch_access",
                                          "vars": {"vlans": [{"id": 10, "name": "USERS"}],
                                                   "access_ports": [{"ports": "Gi1/0/1 - 20", "vlan": 10}],
                                                   "uplink": "Gi1/0/45 - 46"}}).json()[0]
        assert not ok["problems"] and "interface range Gi1/0/1 - 20" in ok["config"] and "vlan 10\n name USERS" in ok["config"]
        return "access/uplink rendered, misuse blocked"

    # ---- 3. delivery -------------------------------------------------------------------
    @check("provision: queue all; existing SSH switch asks for credentials, others continue")
    def _():
        res = c.post("/api/provision", json={"ids": [ids[k] for k in ("pnp", "ztp", "ai", "con", "old")]}).json()
        assert all(r["queued"] for r in res), res
        core_res = c.post("/api/provision", json={"ids": [ids["core"]]}).json()[0]
        assert not core_res["queued"] and core_res["problems"]  # no ports chosen yet -> refused
        c.post("/api/preview", json={"ids": [ids["core"]], "ports": {str(ids["core"]): "Gi1/0/10"}})
        c.post("/api/provision", json={"ids": [ids["core"]]})
        assert dev_state(ctx, serial="FOC3333X0CC") == "needs_credentials"
        return "core-sw -> needs_credentials"

    @check("PnP: config-upgrade -> device downloads /cfg -> write memory -> terminate -> provisioned")
    def _():
        h = from_ip(dsrv.leases[macs["pnp"]])
        udi = f"PID:{pnp_box.pid},VID:V01,SN:{pnp_box.serial}"
        for _ in range(6):
            r = h.post("/pnp/WORK-REQUEST", content=_wr(udi)).text
            if "config-upgrade" in r:
                url = re.search(r"<location>(.+?)</location>", r).group(1)
                pnp_box.apply(h.get(url).text.splitlines())
                # Vlan1 is shut by the pre-config: the PnP agent now talks from the mgmt SVI address
                h = from_ip(next(ip for ip, b in REGISTRY.items() if b is pnp_box))
            if "<terminate/>" in r:
                break
            h.post("/pnp/WORK-RESPONSE", content=_resp(udi, True))
        d = ctx.db.device(ids["pnp"])
        assert d["state"] == "provisioned", d["state"]
        assert pnp_box.hostname == d["hostname"] and "interface Vlan1" in pnp_box.running and pnp_box.has_keys
        return f"{d['hostname']} @ {d['ip']}"

    @check("ZTP: queued box now gets option 67; bootstrap.py runs (fake Guest Shell) and reports back")
    def _():
        offer = dhcp.parse(dsrv.handle(discover_pkt(macs["ztp"])))
        url = offer["options"][67].decode()
        lease = dsrv.leases[macs["ztp"]]
        script = from_ip(lease).get(url.replace(f"http://127.0.0.1:{PORT}", "")).text
        _run_ztp(script, ztp_box, lease)
        d = wait_for(lambda: ctx.db.device(ids["ztp"])["state"] == "provisioned" and ctx.db.device(ids["ztp"]),
                     10, what="ztp provisioned")
        assert ztp_box.hostname == d["hostname"] and "interface range Gi1/0/1 - 20" in ztp_box.running
        return f"{d['hostname']} @ {d['ip']}"

    @check("AutoInstall: option 150/67 -> TFTP per-MAC file -> SSH verify on the new mgmt IP")
    def _():
        import tftpy
        o = dhcp.parse(dsrv.handle(discover_pkt(macs["ai"])))
        fname = o["options"][67].decode()
        assert socket.inet_ntoa(o["options"][150]) == "127.0.0.1"
        out = work / "ai.cfg"
        tftpy.TftpClient("127.0.0.1", 69, localip=dsrv.leases[macs["ai"]]).download(fname, str(out))
        text = out.read_text()
        assert "event manager applet PANDORA-SAVE" in text
        ai_box.apply(text.splitlines())
        d = wait_for(lambda: ctx.db.device(ids["ai"])["state"] == "provisioned" and ctx.db.device(ids["ai"]),
                     40, 1, "autoinstall verify")
        return f"{fname} -> {d['hostname']} @ {d['ip']} ({d['os_type']} {d['version']})"

    @check("console: factory box (dialog) pre-configured; configured box keeps Vlan1 and keys")
    def _():
        fac, old = CONSOLES["COM99"], CONSOLES["COM98"]
        wait_for(lambda: dev_state(ctx, console_port="COM99") == "provisioned", 180, 2, "console COM99")
        wait_for(lambda: dev_state(ctx, console_port="COM98") == "provisioned", 180, 2, "console COM98")
        assert fac.saved and fac.hostname.startswith("lab-sw") and "interface Vlan1" in fac.running
        assert old.saved and "interface Vlan1" not in old.running[4:] and old.crypto_prompts == 0
        return f"{fac.hostname}, {old.hostname}"

    @check("SSH merge: credentials -> merged; chosen port only; uplinks untouched; no RSA prompt")
    def _():
        r = c.post(f"/api/devices/{ids['core']}/credentials", json={"username": "admin", "password": "cisco123"})
        assert r.status_code == 200
        d = wait_for(lambda: ctx.db.device(ids["core"])["state"] in ("provisioned", "failed") and ctx.db.device(ids["core"]),
                     90, 1, "ssh merge")
        assert d["state"] == "provisioned", d["note"]
        run = "\n".join(core.running)
        assert "interface GigabitEthernet1/0/10\n description PANDORA-MGMT reserved" in run
        assert "interface GigabitEthernet1/0/48\n description" not in run and core.crypto_prompts == 0
        assert "interface Vlan1\n no ip address" not in run
        return f"{d['hostname']} @ {d['ip']}"

    @check("inventory: every pre-configured device has a unique hostname + mgmt IP that answers SSH")
    def _():
        devs = [d for d in c.get("/api/devices").json() if d["state"] == "provisioned"]
        assert len(devs) == 6, [(d["id"], d["state"], d["note"]) for d in c.get("/api/devices").json()]
        assert len({d["hostname"] for d in devs}) == 6 and len({d["ip"] for d in devs}) == 6
        assert all(access.ssh_open(d["ip"]) for d in devs if d["path"] != "console")
        return ", ".join(sorted(f"{d['hostname']}={d['ip']}" for d in devs))

    # ---- 4. SNMP / topology / terminal / extra config ------------------------------------
    @check("SNMP: poll interface status + counters + CPU")
    def _():
        r = c.post(f"/api/snmp/poll/{ids['core']}")  # new mgmt IP: the simulator isn't there
        assert r.status_code == 502 and "SNMP poll failed" in r.json()["error"]
        ctx.db.x("UPDATE devices SET ip='127.0.0.2' WHERE id=?", ids["core"])  # snmpsim lives on the old IP
        s = c.post(f"/api/snmp/poll/{ids['core']}").json()
        assert s["Gi1/0/1:oper"] == "up" and s["Gi1/0/2:oper"] == "down" and s["cpu5min"] == "7", s
        assert c.get(f"/api/snmp/samples/{ids['core']}").json()
        return f"{len(s)} values"

    @check("SNMP: v3 inform (linkDown) reaches the receiver and the traps list")
    def _():
        asyncio.run(_send_inform())
        t = wait_for(lambda: c.get("/api/traps").json(), 10, 0.5, "trap")
        assert t[0]["oid"] == "linkDown" and t[0]["src"] == "127.0.0.1", t[0]
        return t[0]["oid"]

    @check("topology: SNMP CDP for core-sw + SSH textfsm fallback for the PnP switch, one deduped link")
    def _():
        g = c.get("/api/topology").json()
        pnp_id, core_id = ids["pnp"], ids["core"]
        links = [e for e in g["edges"] if {e["from"], e["to"]} == {pnp_id, core_id}]
        assert len(links) == 1, g["edges"]
        return f"{len(g['nodes'])} nodes / {len(g['edges'])} edges: {links[0]['label']}"

    @check("extra config: dry-run diff, guard blocks reserved port, push applies")
    def _():
        p = ids["pnp"]
        dry = c.post(f"/api/devices/{p}/config", json={"text": "interface Gi1/0/5\n switchport access vlan 20",
                                                       "dry_run": True}).json()
        assert "+interface Gi1/0/5" in dry["diff"]
        blocked = c.post(f"/api/devices/{p}/config", json={"text": "interface Gi1/0/24\n shutdown"}).json()
        assert blocked.get("blocked")
        out = c.post(f"/api/devices/{p}/config", json={"text": "interface Gi1/0/5\n switchport access vlan 20"}).json()
        assert "output" in out and " switchport access vlan 20" in pnp_box.running
        return "ok"

    @check("terminal: websocket shell to a device; foreign Origin refused")
    def _():
        return asyncio.run(_terminal(ids["pnp"]))

    # ---- 5. agent ----------------------------------------------------------------------------
    @check("agent: look -> propose -> apply (waits for Approve) -> verify -> rollback (Approve)")
    def _():
        p = ids["pnp"]
        snap = {}

        def approver():
            while not snap.get("stop"):
                for aid in list(agent_tools.APPROVALS):
                    c.post(f"/api/approve/{aid}", json={"ok": True})
                    snap.setdefault("approved", 0)
                    snap["approved"] += 1
                time.sleep(0.2)
        threading.Thread(target=approver, daemon=True).start()
        prov = _Scripted(p, ids["core"], snap)
        agent_loop.run(ctx, "put Gi1/0/6 in VLAN 30 and verify, then roll back", provider=prov)
        snap["stop"] = True
        assert snap.get("approved") == 2, snap
        assert prov.errors == [], prov.errors
        assert "interface Gi1/0/6" not in "\n".join(pnp_box.running)  # rolled back
        return f"{prov.calls} tool calls, 2 approvals, rolled back"

    # ---- 6. round-3 scenarios ----------------------------------------------------------------
    @check("AutoInstall #2: TFTP still serving after the first transfer; DHCP REQUEST -> ACK with options")
    def _():
        import tftpy
        mac, box = "aa:00:00:00:00:04", FakeIOS("ai2", "WS-C2960X-48TS-L", "FOC7777X0GG", xe=False)
        assert dsrv.handle(discover_pkt(mac)) is None  # unselected: silent
        d = ctx.db.upsert(mac=mac, pid=box.pid)
        res = c.post("/api/provision", json={"ids": [d["id"]]}).json()[0]
        assert res["queued"], res
        o = dhcp.parse(dsrv.handle(discover_pkt(mac)))
        ack = dhcp.parse(dsrv.handle(request_pkt(mac, dsrv.leases[mac])))
        assert ack["options"][53] == bytes([dhcp.ACK]) and ack["options"][67] == o["options"][67]
        out = work / "ai2.cfg"
        tftpy.TftpClient("127.0.0.1", 69, localip=dsrv.leases[mac]).download(o["options"][67].decode(), str(out))
        box.apply(out.read_text().splitlines())
        d = wait_for(lambda: ctx.db.device(d["id"])["state"] == "provisioned" and ctx.db.device(d["id"]),
                     40, 1, "second autoinstall")
        assert box.hostname == d["hostname"]
        return f"{d['hostname']} @ {d['ip']}"

    @check("console with a login: asks for credentials, then pre-configures (no factory changes)")
    def _():
        CONSOLES["COM97"] = box = FakeIOS("con-login", "C9200L-24T-4G", "JAE8888X0HH", factory=False,
                                          user="admin", password="cisco123")
        r = console.probe("COM97")
        assert r["console_state"] == "login", r
        dev = ctx.db.upsert(console_port="COM97", source="console", path="console")  # PID unknown behind login
        res = c.post("/api/provision", json={"ids": [dev["id"]]}).json()[0]
        assert res["queued"], res
        wait_for(lambda: dev_state(ctx, console_port="COM97") == "needs_credentials", 60, 1, "needs_credentials")
        assert c.post(f"/api/devices/{dev['id']}/credentials",
                      json={"username": "admin", "password": "cisco123"}).status_code == 200
        wait_for(lambda: dev_state(ctx, console_port="COM97") in ("provisioned", "failed"), 180, 2, "console login")
        d = ctx.db.device(dev["id"])
        assert d["state"] == "provisioned", d["note"]
        assert box.saved and box.crypto_prompts == 0 and box.hostname == d["hostname"]
        assert "interface Vlan1" not in box.running[4:]
        return f"{d['hostname']} ({d['pid']})"

    @check("compliance: mgmt port shut + trap host removed -> drift problem -> fix -> compliant again")
    def _():
        p = ids["pnp"]
        r = c.post(f"/api/devices/{p}/compliance").json()
        assert r["compliant"], [f for f in r["features"] if not f["compliant"]]
        drift = ["interface GigabitEthernet1/0/24", " shutdown", "no snmp-server host 127.0.0.1 informs version 3 priv pandora"]
        c.post(f"/api/devices/{p}/config", json={"override": True, "text": "\n".join(drift)})
        r = c.post(f"/api/devices/{p}/compliance").json()
        assert {f["name"] for f in r["features"] if not f["compliant"]} == {"mgmt-ports", "snmp"}, r["features"]
        assert any(x["key"] == "drift" and x["device_id"] == p for x in c.get("/api/problems").json())
        assert c.post(f"/api/devices/{p}/remediate", json={}).status_code == 400  # needs an explicit yes
        fix = c.post(f"/api/devices/{p}/remediate", json={"confirm": True}).json()
        assert fix["pushed"] and fix["result"]["compliant"], fix
        assert not any(x["key"] == "drift" and x["device_id"] == p for x in c.get("/api/problems").json())
        hist = c.get(f"/api/devices/{p}/backups").json()
        diff = c.get(f"/api/backups/{hist[-1]['id']}/diff/{hist[0]['id']}").json()["diff"]
        assert len(hist) >= 3 and "@@" in diff
        return f"{len(fix['result']['features'])} features compliant again, {len(hist)} backups"

    @check("SSH host key: pinned on first login; a changed key is refused before the password + problem; forget -> pins the new one")
    def _():
        from pandora import hostkeys
        p = ids["pnp"]
        box = REGISTRY[ctx.db.device(p)["ip"]]
        assert hostkeys.pinned(ctx.db, p) == hostkeys.text(HOSTKEY), "first login did not pin the key"
        box.hostkey, users = paramiko.RSAKey.generate(2048), box.users
        box.users = {}  # an impostor: no login would work, and none must be tried
        r = c.post(f"/api/devices/{p}/backups")
        assert r.status_code >= 400, r.text
        probs = [x for x in c.get("/api/problems").json() if x["key"] == "ssh-host-key" and x["device_id"] == p]
        assert probs and probs[0]["severity"] == "high", probs
        box.users = users
        assert c.post(f"/api/devices/{p}/forget-host-key").json()["ok"]
        assert c.post(f"/api/devices/{p}/backups").status_code == 200
        assert hostkeys.pinned(ctx.db, p) == hostkeys.text(box.hostkey)
        assert not any(x["key"] == "ssh-host-key" for x in c.get("/api/problems").json())
        return "changed key refused, problem raised, re-pinned after forget"

    @check("SSH host key: a box claiming a known serial from a new address with another key is refused; row untouched")
    def _():
        import copy

        from pandora import alerts, hostkeys
        p = ids["pnp"]
        before = ctx.db.device(p)
        box = REGISTRY[before["ip"]]
        used = {d["ip"] for d in ctx.db.devices()} | {a["mgmt_ip"] for a in ctx.db.q("SELECT mgmt_ip FROM allocations")}
        new_ip = next(f"127.0.0.{i}" for i in range(40, 1, -1) if f"127.0.0.{i}" not in REGISTRY.keys() | used)
        impostor = copy.copy(box)  # same serial and login, its own key
        impostor.hostkey = paramiko.RSAKey.generate(2048)
        REGISTRY[new_ip] = impostor
        try:
            r = c.post("/api/devices", json={"ip": new_ip, "username": ctx.cfg["admin_user"],
                                             "password": SECRETS["admin_password"]})
            assert r.status_code == 502 and "HostKeyChanged" in r.text, r.text
            after = ctx.db.device(p)
            assert (after["ip"], after["path"]) == (before["ip"], before["path"]), (before, after)
            assert not ctx.db.find(ip=new_ip), "a row was created for the impostor"
            assert hostkeys.pinned(ctx.db, p) == hostkeys.text(box.hostkey)
            assert any(x["key"] == "ssh-host-key" and x["device_id"] == p for x in c.get("/api/problems").json())
        finally:
            del REGISTRY[new_ip]
            alerts.resolve(ctx, p, "ssh-host-key")
        return f"{new_ip} claimed serial {before['serial']}: refused, device stays on {before['ip']}"

    # ---- summary --------------------------------------------------------------------------------
    ok = sum(1 for r in RESULTS if r[0])
    print(f"\n{ok}/{len(RESULTS)} checks passed  (work dir {work})", flush=True)
    for good, name, detail, _secs in RESULTS:
        if not good:
            print(f"  FAILED: {name}: {detail}")
    if serve:
        print(f"Lab + UI up on {BASE}  (Ctrl+C to stop)", flush=True)
        try:
            while True:
                time.sleep(1)
        except KeyboardInterrupt:
            pass
    snmpsim.terminate()
    return 0 if ok == len(RESULTS) else 1


# ---- pieces used above ----------------------------------------------------------------
def _wr(udi):
    return (f'<?xml version="1.0"?><pnp xmlns="urn:cisco:pnp" version="1.0" udi="{udi}">'
            f'<info xmlns="urn:cisco:pnp:work-info" correlator="c1"><deviceId><udi>{udi}</udi></deviceId></info></pnp>')


def _resp(udi, ok, extra=""):
    return (f'<pnp xmlns="urn:cisco:pnp" version="1.0" udi="{udi}"><response correlator="c1" success="{int(ok)}" '
            f'xmlns="urn:cisco:pnp:device-info">{extra}</response></pnp>')


def _run_ztp(script, box, lease):
    """Run the served bootstrap.py like the Guest Shell would: `cli` talks to the box, HTTP leaves from its lease IP."""
    import types
    import urllib.request
    cli = types.ModuleType("cli")
    s = Session(box, console=False)
    cli.execute = lambda cmd: s.exec_cmd(cmd)
    cli.executep = lambda cmd: print("   ztp>", s.exec_cmd(cmd).splitlines()[-1])
    cli.configurep = lambda lines: box.apply(lines)

    class _Resp:
        def __init__(self, r):
            self.r = r

        def getcode(self):
            return self.r.status_code

        def read(self):
            return self.r.content

    def urlopen(req, timeout=30):
        h = from_ip(lease)
        if isinstance(req, str):
            return _Resp(h.get(req))
        return _Resp(h.post(req.full_url, content=req.data, headers=dict(req.headers)))

    saved = sys.modules.get("cli"), urllib.request.urlopen
    sys.modules["cli"], urllib.request.urlopen = cli, urlopen
    try:
        exec(compile(script, "bootstrap.py", "exec"), {"__name__": "__main__"})
    finally:
        sys.modules.pop("cli", None)
        if saved[0]:
            sys.modules["cli"] = saved[0]
        urllib.request.urlopen = saved[1]


async def _send_inform():
    from pysnmp.hlapi.v3arch.asyncio import (
        ContextData,
        Integer32,
        NotificationType,
        ObjectIdentity,
        ObjectType,
        SnmpEngine,
        UdpTransportTarget,
        UsmUserData,
        send_notification,
        usmAesCfb128Protocol,
        usmHMACSHAAuthProtocol,
    )
    err, status, _, _ = await send_notification(
        SnmpEngine(), UsmUserData("pandora", SECRETS["snmp_auth"], SECRETS["snmp_priv"],
                                  authProtocol=usmHMACSHAAuthProtocol, privProtocol=usmAesCfb128Protocol),
        await UdpTransportTarget.create(("127.0.0.1", 162), timeout=3, retries=1), ContextData(), "inform",
        NotificationType(ObjectIdentity("1.3.6.1.6.3.1.1.5.3")).add_varbinds(
            ObjectType(ObjectIdentity("1.3.6.1.2.1.2.2.1.1.2"), Integer32(2))))
    if err:
        raise RuntimeError(str(err))


async def _terminal(device_id):
    import websockets
    url = f"ws://127.0.0.1:{PORT}/ws/term/{device_id}"
    try:
        async with websockets.connect(url, origin="https://evil.example") as ws:
            await asyncio.wait_for(ws.recv(), 3)
        raise AssertionError("foreign origin was accepted")
    except (websockets.ConnectionClosed, websockets.InvalidStatus, asyncio.TimeoutError):
        pass
    async with websockets.connect(url, origin=f"http://127.0.0.1:{PORT}") as ws:
        await ws.send(json.dumps({"resize": [140, 40]}))
        t0 = time.time()
        await ws.send(json.dumps({"data": "show clokc"}))  # typo, fixed with two backspaces like a person would
        await ws.send(json.dumps({"data": "\x7f\x7f"}))
        await ws.send(json.dumps({"data": "ck\r"}))
        out, end, first = "", time.time() + 10, None
        while "UTC" not in out and time.time() < end:
            msg = await asyncio.wait_for(ws.recv(), 10)
            first = first or time.time()
            out += msg.decode() if isinstance(msg, bytes) else msg
    assert "UTC" in out and "\b \b" in out, out
    echo_ms = round((first - t0) * 1000)
    assert echo_ms < 300, f"first echo took {echo_ms} ms"
    return f"backspace edits the line like IOS, first echo after {echo_ms} ms"


class _Scripted:
    """Stands in for the LLM: drives the real tools in the order a good model would."""

    def __init__(self, dev, core, snap):
        self.dev, self.core, self.snap, self.errors, self.calls, self.n = dev, core, snap, [], 0, 0
        self.snapshot_id = None

    def step(self, user_text=None, results=None):
        for _, name, out, err in results or []:
            self.calls += 1
            if err:
                self.errors.append((name, out))
            if name == "apply_config":
                self.snapshot_id = json.loads(out).get("snapshot_id")
        self.n += 1
        lines = ["interface Gi1/0/6", " switchport access vlan 30"]
        plan = {
            1: ("Looking at the inventory and the port.", [("list_devices", {}),
                                                           ("show", {"device_id": self.dev, "command": "show running-config"}),
                                                           ("snmp_get", {"device_id": self.core, "oids": ["1.3.6.1.2.1.1.5.0"]})]),
            2: ("Plan: one access port change.", [("propose_config", {"device_id": self.dev, "lines": lines})]),
            3: ("Applying.", [("apply_config", {"device_id": self.dev, "lines": lines, "reason": "VLAN 30 on Gi1/0/6"})]),
            4: ("Verifying.", [("show", {"device_id": self.dev, "command": "show running-config"})]),
            5: ("Rolling back as asked.", [("rollback", {"device_id": self.dev, "snapshot_id": self.snapshot_id or 0})]),
            6: ("Done: applied, verified, rolled back.", []),
        }[self.n]
        return plan[0], [{"id": f"t{self.n}{i}", "name": n, "args": a} for i, (n, a) in enumerate(plan[1])]


if __name__ == "__main__":
    sys.exit(main())
