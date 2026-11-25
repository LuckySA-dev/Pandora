"""Turn raw facts (show version, inventory, sysDescr, PnP UDI) into inventory fields."""
import re


def parse_show_version(text: str) -> dict:
    out = {}
    m = re.search(r"Cisco IOS[ -]XE Software.*?Version\s+([^\s,]+)", text, re.I | re.S)
    if m:
        out.update(os_type="iosxe", version=m.group(1))
    elif m := re.search(r"Cisco IOS Software.*?Version\s+([^\s,]+)", text, re.I | re.S):
        # IOS-XE 16+ can also print "Cisco IOS Software [Fuji]"; these markers give it away.
        xe = re.search(r"IOS-XE|IOSXE|cat9k|packages\.conf", text, re.I)
        out.update(os_type="iosxe" if xe else "ios", version=m.group(1))
    if m := re.search(r"^(\S+) uptime is", text, re.M):
        out["hostname"] = m.group(1)
    if m := re.search(r"System Serial Number\s*:\s*(\S+)", text) or re.search(r"Processor board ID (\S+)", text):
        out["serial"] = m.group(1)
    if m := re.search(r"Model [Nn]umber\s*:\s*(\S+)", text) or re.search(r"^cisco (\S+) .*processor", text, re.M | re.I):
        out["pid"] = m.group(1)
    return out


def parse_inventory(text: str) -> dict:
    m = re.search(r"PID:\s*(\S+?)\s*,.*?SN:\s*(\S+)", text)
    return {"pid": m.group(1), "serial": m.group(2)} if m else {}


def parse_sysdescr(descr: str) -> dict:
    return {k: v for k, v in parse_show_version(descr).items() if k in ("os_type", "version")}


def parse_udi(udi: str) -> dict:
    """'PID:C9300-24P,VID:V01,SN:FOC1234X0AB' -> {'pid':..., 'serial':...}"""
    parts = dict(p.strip().split(":", 1) for p in udi.split(",") if ":" in p)
    return {"pid": parts.get("PID"), "serial": parts.get("SN")}


def guess_path(device: dict) -> str:
    """Delivery matrix: console > PnP-capable > already configured (ssh) > IOS-XE ZTP > IOS AutoInstall."""
    if device.get("console_port"):
        return "console"
    if "pnp" in (device.get("vendor_class") or "").lower():
        return "pnp"
    if device.get("source") in ("snmp", "cdp", "lldp"):
        return "ssh"
    if device.get("os_type") == "iosxe":
        return "ztp"
    return "autoinstall"
