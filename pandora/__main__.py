"""python -m pandora [--config pandora.toml] [--db pandora.db] [--no-dhcp]"""
import argparse
import logging
import re
import subprocess
import sys
from pathlib import Path

import uvicorn

from . import config, console
from .app import create_app
from .db import DB
from .deliver import Ctx
from .net import dhcp, sniff, tftp

log = logging.getLogger("pandora")


def iface_is_safe(name: str) -> tuple[bool, str]:
    """A rogue DHCP server on an office LAN is an outage: only serve on a static, gateway-less NIC."""
    if not name:
        return False, "set `iface` in pandora.toml to the NIC cabled to the Cisco gear"
    if sys.platform != "win32":
        return True, "non-Windows: not checked, make sure the NIC is isolated"
    # PowerShell objects, not netsh text: netsh labels are translated on non-English Windows.
    alias = name.replace("'", "''")
    ps = (f"$i = Get-NetIPInterface -InterfaceAlias '{alias}' -AddressFamily IPv4 -ErrorAction Stop; "
          f"$g = @(Get-NetRoute -InterfaceAlias '{alias}' -DestinationPrefix '0.0.0.0/0' -ErrorAction SilentlyContinue); "
          "'{0}|{1}' -f $i.Dhcp, $g.Count")
    r = subprocess.run(["powershell", "-NoProfile", "-NonInteractive", "-Command", ps], capture_output=True, text=True)
    m = re.fullmatch(r"(\w+)\|(\d+)", r.stdout.strip())
    if r.returncode or not m:
        return False, f"interface '{name}' not found (see Get-NetIPInterface)"
    return check_iface(m.group(1), int(m.group(2)), name)


def check_iface(dhcp: str, gateways: int, name: str) -> tuple[bool, str]:
    if dhcp.lower() != "disabled":
        return False, f"'{name}' gets its own address by DHCP: it is on a real network, not an isolated one"
    if gateways:
        return False, f"'{name}' has a default gateway: it is on a real network, not an isolated one"
    return True, "ok"


def main():
    ap = argparse.ArgumentParser(prog="pandora")
    ap.add_argument("--config", default="pandora.toml")
    ap.add_argument("--db", default="pandora.db")
    ap.add_argument("--no-dhcp", action="store_true", help="UI, console, SNMP and SSH only")
    ap.add_argument("--preflight", action="store_true", help="check this machine for a real lab run, then exit")
    args = ap.parse_args()
    if args.preflight:
        from . import preflight
        sys.exit(preflight.run(args.config))
    logging.basicConfig(level=logging.INFO, format="%(asctime)s %(name)s %(message)s")

    cfg = config.load(args.config)
    ctx = Ctx(DB(args.db), cfg)
    app = create_app(ctx)

    if args.no_dhcp:
        log.info("DHCP/TFTP disabled (--no-dhcp)")
    else:
        ok, why = iface_is_safe(cfg["iface"])
        if not ok:
            sys.exit(f"Refusing to start DHCP: {why}. Use --no-dhcp for console/SNMP/SSH only.")
        try:
            dhcp.DhcpServer(cfg["server_ip"], cfg["netmask"], config.ip_range(cfg["dhcp_range"]),
                            ctx.dhcp_decide, cfg["iface"]).start()
            tftp.start(cfg["server_ip"], Path(".pandora/tftp"), ctx.tftp_lookup)
        except OSError as e:
            sys.exit(f"Cannot bind DHCP/TFTP on {cfg['server_ip']}: {e}\n"
                     "Run as Administrator and allow it in the firewall, e.g.:\n"
                     '  netsh advfirewall firewall add rule name="PandoraBox" dir=in action=allow '
                     "protocol=UDP localport=67,69,162\n"
                     '  netsh advfirewall firewall add rule name="PandoraBox-HTTP" dir=in action=allow '
                     f"protocol=TCP localport={cfg['http_port']}")
        sniff.start(cfg["iface"], lambda n: _remember(ctx, n))

    def on_console(port, r):
        facts = {k: v for k, v in r.items() if k != "console_state"}
        dev = ctx.db.upsert(console_port=port, source="console", path="console",
                            note=f"console: {r['console_state']}", **facts)
        ctx.emit("device", dev)

    console.watch(on_console, urls=cfg.get("console_urls") or ())
    log.info("UI: http://127.0.0.1:%s", cfg["http_port"])
    uvicorn.run(app, host="0.0.0.0", port=int(cfg["http_port"]), log_level="warning")


def _remember(ctx, n):
    key = (n["remote_name"], n["remote_port"])
    if all((s["remote_name"], s["remote_port"]) != key for s in ctx.sniffed):
        ctx.sniffed.append(n)
        ctx.emit("neighbor", n)


if __name__ == "__main__":
    main()
