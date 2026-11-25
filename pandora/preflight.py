"""`python -m pandora --preflight`: everything a real lab run needs, checked before any device is cabled.

Each check is (level, what, detail) with level ok | warn | fail. Any fail = the run would not work.
Nothing here changes the machine: it binds and releases sockets and reads system state.
"""
import ipaddress
import os
import socket
import subprocess
import sys
from pathlib import Path

from . import config

FIREWALL = ('netsh advfirewall firewall add rule name="PandoraBox" dir=in action=allow protocol=UDP '
            'localport=67,69,162\n      netsh advfirewall firewall add rule name="PandoraBox-HTTP" dir=in '
            'action=allow protocol=TCP localport={port}')


def check_ranges(cfg) -> list[tuple]:
    """DHCP leases and mgmt IPs: inside the NIC's subnet, apart from each other and from the laptop."""
    net = ipaddress.ip_network(f"{cfg['server_ip']}/{cfg['netmask']}", strict=False)
    out, sets = [], {}
    for key in ("dhcp_range", "mgmt_range"):
        try:
            ips = {ipaddress.ip_address(i) for i in config.ip_range(cfg[key])}
        except ValueError as e:
            out.append(("fail", key, f"{cfg[key]!r}: {e}"))
            continue
        sets[key] = ips
        if not all(i in net for i in ips):
            out.append(("fail", key, f"{cfg[key]} is not inside {net} (server_ip/netmask)"))
        elif ipaddress.ip_address(cfg["server_ip"]) in ips:
            out.append(("fail", key, f"{cfg[key]} contains server_ip {cfg['server_ip']}"))
        else:
            out.append(("ok", key, f"{cfg[key]} ({len(ips)} addresses)"))
    if len(sets) == 2 and sets["dhcp_range"] & sets["mgmt_range"]:
        out.append(("fail", "ranges", "dhcp_range and mgmt_range overlap: a lease could take a device's mgmt IP"))
    return out


def check_secrets(cfg) -> list[tuple]:
    out = []
    for key in ("admin_password", "snmp_auth", "snmp_priv"):
        env = f"PANDORA_{key.upper()}"
        n = len(cfg.get(key) or "")
        out.append(("ok", env, "set") if n >= 8 else ("fail", env, "missing" if not n else f"only {n} chars, need 8+"))
    return out


def _bind(kind, ip, port) -> str | None:
    s = socket.socket(socket.AF_INET, kind)
    try:
        s.bind((ip, port))
        return None
    except OSError as e:
        return str(e)
    finally:
        s.close()


def check_network(cfg) -> list[tuple]:
    from .__main__ import iface_is_safe
    out = []
    ok, why = iface_is_safe(cfg["iface"])
    out.append(("ok" if ok else "fail", "iface", f"{cfg['iface']!r}: {why}"))
    if err := _bind(socket.SOCK_DGRAM, cfg["server_ip"], 0):
        out.append(("fail", "server_ip", f"{cfg['server_ip']} is not an address of this machine ({err}): "
                                         f"give the NIC {cfg['iface']!r} this static IP"))
        return out
    out.append(("ok", "server_ip", f"{cfg['server_ip']} is on this machine"))
    for kind, port, what in ((socket.SOCK_DGRAM, 67, "DHCP"), (socket.SOCK_DGRAM, 69, "TFTP (AutoInstall)"),
                             (socket.SOCK_DGRAM, 162, "SNMP informs"),
                             (socket.SOCK_STREAM, int(cfg["http_port"]), "HTTP (UI, PnP, ZTP, configs)")):
        err = _bind(kind, cfg["server_ip"], port)
        out.append(("fail", f"port {port}", f"{what}: {err} (another DHCP/TFTP server or Internet Connection "
                                             "Sharing running?)") if err else ("ok", f"port {port}", what))
    if int(cfg["http_port"]) != 80:
        out.append(("warn", "http_port", f"{cfg['http_port']}: PnP is told the port in option 43, but some agents "
                                         "only try 80"))
    return out


def clashes(ours: str, others: list[tuple[str, str]]) -> list[str]:
    """Other NICs whose subnet overlaps the provisioning one: device traffic could leave by the wrong NIC."""
    net = ipaddress.ip_network(ours, strict=False)
    return [f"{alias} {cidr}" for alias, cidr in others if ipaddress.ip_network(cidr, strict=False).overlaps(net)]


def check_other_nics(cfg) -> list[tuple]:
    """A laptop on Wi-Fi/office LAN as well is fine, as long as that network is a different subnet."""
    if sys.platform != "win32":
        return []
    import json
    r = subprocess.run(["powershell", "-NoProfile", "-NonInteractive", "-Command",
                        "Get-NetIPAddress -AddressFamily IPv4 | Where-Object IPAddress -ne '127.0.0.1' | "
                        "Select-Object InterfaceAlias, IPAddress, PrefixLength | ConvertTo-Json"],
                       capture_output=True, text=True)
    rows = json.loads(r.stdout or "[]")
    rows = [rows] if isinstance(rows, dict) else rows
    others = [(x["InterfaceAlias"], f"{x['IPAddress']}/{x['PrefixLength']}") for x in rows
              if x["InterfaceAlias"] != cfg["iface"]]
    ours = f"{cfg['server_ip']}/{cfg['netmask']}"
    if bad := clashes(ours, others):
        return [("fail", "other NICs", f"{', '.join(bad)} overlaps the provisioning subnet {ours}: device traffic "
                                       "could go out the wrong NIC. Move server_ip/ranges to another subnet")]
    return [("ok", "other NICs", (", ".join(f"{a} {c}" for a, c in others) or "none")
             + ": separate subnets, internet stays on them")]


def foreign_dhcp(iface: str, own_ip: str, timeout=4) -> list[str] | None:
    """Send one DHCP DISCOVER out of `iface` and list the servers that answer, other than us.
    Someone answering = the switch is cabled to a real network, and our DHCP would fight its router.
    None = could not probe (no Npcap/raw access)."""
    try:
        from scapy.all import BOOTP, DHCP, IP, UDP, Ether, conf, get_if_hwaddr, srp
        from scapy.error import Scapy_Exception
    except ImportError:
        return None
    try:
        conf.checkIPaddr = False  # offers come from the server's address, not the broadcast we sent to
        mac = get_if_hwaddr(iface)
        pkt = (Ether(dst="ff:ff:ff:ff:ff:ff", src=mac) / IP(src="0.0.0.0", dst="255.255.255.255")
               / UDP(sport=68, dport=67)
               / BOOTP(chaddr=bytes.fromhex(mac.replace(":", "")), xid=0x50414E44, flags=0x8000)
               / DHCP(options=[("message-type", "discover"), "end"]))
        ans, _ = srp(pkt, iface=iface, timeout=timeout, multi=True, verbose=0)
    except (OSError, ValueError, Scapy_Exception):  # no Npcap / no raw access / unknown NIC; real bugs surface
        return None
    return sorted({r[IP].src for _, r in ans if DHCP in r and r[IP].src != own_ip})


def check_segment(cfg) -> list[tuple]:
    found = foreign_dhcp(cfg["iface"], cfg["server_ip"])
    if found is None:
        return [("warn", "DHCP on segment", "could not probe (Npcap missing or not Administrator). PandoraBox will "
                                            "refuse to start DHCP unless you confirm with --assume-isolated")]
    if found:
        return [("fail", "DHCP on segment", f"another DHCP server answers on {cfg['iface']!r} ({', '.join(found)}): "
                                            "the switch is connected to a real network. Unplug its uplink first")]
    return [("ok", "DHCP on segment", "no other DHCP server answers: PandoraBox can serve here")]


def check_windows(cfg) -> list[tuple]:
    if sys.platform != "win32":
        return []
    out = []
    npcap = Path(os.environ.get("SystemRoot", r"C:\Windows")) / "System32" / "Npcap"
    out.append(("ok", "Npcap", "installed") if npcap.exists() else
               ("warn", "Npcap", "not installed: CDP/LLDP heard on the laptop NIC won't show (https://npcap.com)"))
    r = subprocess.run(["powershell", "-NoProfile", "-NonInteractive", "-Command",
                        "@(Get-NetFirewallRule -DisplayName 'PandoraBox*' -ErrorAction SilentlyContinue "
                        "| Where-Object Enabled -eq 'True').Count"], capture_output=True, text=True)
    n = int(r.stdout.strip()) if r.stdout.strip().isdigit() else 0
    out.append(("ok", "firewall", f"{n} PandoraBox rule(s)") if n >= 2 else
               ("warn", "firewall", "no inbound rules yet; as Administrator run:\n      "
                + FIREWALL.format(port=cfg["http_port"])))
    return out


def check_rest(cfg) -> list[tuple]:
    out = []
    try:
        from cryptography.hazmat.decrepit.ciphers import algorithms  # noqa: F401  (pysnmp AES priv)
        out.append(("ok", "SNMPv3 priv", "AES available"))
    except ImportError:
        out.append(("fail", "SNMPv3 priv", "pip install 'cryptography>=47' (pysnmp needs it for AES)"))
    from serial.tools import list_ports
    ports = [p.device for p in list_ports.comports()] + list(cfg.get("console_urls") or [])
    out.append(("ok", "console", ", ".join(ports)) if ports else
               ("warn", "console", "no COM port or console_urls: console delivery unavailable (LAN paths still work)"))
    llm = cfg["llm"]
    if llm["provider"] == "claude" and not os.environ.get("ANTHROPIC_API_KEY"):
        out.append(("warn", "agent", "ANTHROPIC_API_KEY not set: the AI agent tab won't run"))
    else:
        out.append(("ok", "agent", f"{llm['provider']} / {llm['model']}"))
    if cfg.get("snmp_allow_auth_nopriv"):
        out.append(("warn", "snmp_allow_auth_nopriv", "on: boxes without AES get SNMPv3 authNoPriv (lab images)"))
    return out


def run(config_path) -> int:
    p = Path(config_path)
    cfg = config.load(p)
    rows = [("ok", "config", str(p)) if p.exists() else
            ("warn", "config", f"{p} not found: defaults in use (copy pandora.toml.example)")]
    for part in (check_secrets, check_ranges, check_network, check_other_nics, check_segment, check_windows,
                 check_rest):
        try:
            rows += part(cfg)
        except Exception as e:
            rows.append(("fail", part.__name__, f"{type(e).__name__}: {e}"))
    mark = {"ok": "OK  ", "warn": "WARN", "fail": "FAIL"}
    for level, what, detail in rows:
        print(f"{mark[level]}  {what:<24} {detail}")
    fails = sum(r[0] == "fail" for r in rows)
    print(f"\n{'Ready' if not fails else f'{fails} problem(s) to fix'} for a real lab run.")
    return 1 if fails else 0
