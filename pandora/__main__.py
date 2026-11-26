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
    ap.add_argument("--assume-isolated", action="store_true",
                    help="start DHCP even if the check for another DHCP server can't run (no Npcap)")
    ap.add_argument("--preflight", action="store_true", help="check this machine for a real lab run, then exit")
    args = ap.parse_args()
    if args.preflight:
        from . import preflight
        sys.exit(preflight.run(args.config))
    logging.basicConfig(level=logging.INFO, format="%(asctime)s %(name)s %(message)s")
    logging.getLogger("tftpy").setLevel(logging.WARNING)  # ~15 lines per request; pandora.tftp logs each one

    cfg = config.load(args.config)
    ctx = Ctx(DB(args.db), cfg)
    app = create_app(ctx)

    if args.no_dhcp:
        log.info("DHCP/TFTP disabled (--no-dhcp)")
    else:
        ok, why = iface_is_safe(cfg["iface"])
        if not ok:
            sys.exit(f"Refusing to start DHCP: {why}. Use --no-dhcp for console/SNMP/SSH only.")
        from .preflight import foreign_dhcp
        others = foreign_dhcp(cfg["iface"], cfg["server_ip"])
        if others:  # the switch has an uplink to a real network: two DHCP servers = an outage for its users
            sys.exit(f"Refusing to start DHCP: another DHCP server answers on {cfg['iface']!r} ({', '.join(others)}). "
                     "Unplug the switch's uplink to the real network, or use --no-dhcp.")
        if others is None and not args.assume_isolated:  # fail closed: unknown is not "clean"
            sys.exit(f"Refusing to start DHCP: could not check {cfg['iface']!r} for another DHCP server (install Npcap "
                     "and run as Administrator). If you are sure the switch has no uplink to a real network, start "
                     "with --assume-isolated.")
        try:
            dhcp.DhcpServer(cfg["server_ip"], cfg["netmask"], config.ip_range(cfg["dhcp_range"]),
                            ctx.dhcp_decide, cfg["iface"]).start()
            tftp.start(cfg["server_ip"], Path(".pandora/tftp"), ctx.tftp_lookup)
        except OSError as e:
            sys.exit(f"Cannot bind DHCP/TFTP on {cfg['server_ip']}: {e}\n"
                     "Is another PandoraBox still running? Find it with:\n"
                     "  Get-NetUDPEndpoint -LocalPort 67,69,162 | Select LocalAddress, LocalPort, OwningProcess\n"
                     "Otherwise run as Administrator and allow it in the firewall, e.g.:\n"
                     '  netsh advfirewall firewall add rule name="PandoraBox" dir=in action=allow '
                     "protocol=UDP localport=67,69,162\n"
                     '  netsh advfirewall firewall add rule name="PandoraBox-HTTP" dir=in action=allow '
                     f"protocol=TCP localport={cfg['http_port']}")
        sniff.start(cfg["iface"], lambda n: _remember(ctx, n))

    def on_console(port, r):
        ctx.emit("device", remember_console(ctx.db, port, r))

    console.watch(on_console, urls=cfg.get("console_urls") or ())
    log.info("UI: http://127.0.0.1:%s", cfg["http_port"])
    # bounded: an open terminal or live page must not keep a stopped PandoraBox alive (and holding its ports)
    # keep-alive 15 s: the IOS PnP agent reuses its connection exactly 5 s later, which raced uvicorn's 5 s default (RST)
    uvicorn.run(app, host="0.0.0.0", port=int(cfg["http_port"]), log_level="warning", timeout_graceful_shutdown=5,
                timeout_keep_alive=15)


def remember_console(db, port, r) -> dict:
    """A box heard on a console port. Source/delivery only for a box we didn't know: plugging a console cable into a
    switch already on PnP/SSH must not switch its delivery to console (seen: a real 2960X mid-onboarding)."""
    facts = {k: v for k, v in r.items() if k != "console_state"}
    known = db.find(serial=facts.get("serial"), console_port=port)
    first = {} if known else {"source": "console", "path": "console"}
    return db.upsert(console_port=port, note=f"console: {r['console_state']}", **first, **facts)


def _remember(ctx, n):
    key = (n["remote_name"], n["remote_port"])
    if all((s["remote_name"], s["remote_port"]) != key for s in ctx.sniffed):
        ctx.sniffed.append(n)
        ctx.emit("neighbor", n)


if __name__ == "__main__":
    main()
