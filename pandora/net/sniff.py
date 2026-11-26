"""Hear CDP / LLDP on the laptop NIC (scapy + Npcap). Optional: logs and returns if unavailable."""
import logging
import threading

log = logging.getLogger("pandora.sniff")


def start(iface: str, on_neighbor):
    try:
        from scapy.all import load_contrib, sniff
        load_contrib("cdp")
        load_contrib("lldp")
        from scapy.contrib import cdp, lldp
    except Exception as e:
        log.warning("CDP/LLDP sniffing disabled (%s). Install Npcap to enable it.", e)
        return

    def handle(pkt):
        n = None
        if pkt.haslayer(cdp.CDPv2_HDR):
            # the address ties the box to its inventory row (its DHCP lease while it is factory)
            addrs = [r.addr for layer in (cdp.CDPMsgAddr, getattr(cdp, "CDPMsgMgmtAddr", None)) if layer
                     and pkt.haslayer(layer) for r in (pkt[layer].addr or []) if getattr(r, "addr", None)]
            n = {"via": "cdp", "src_mac": (pkt.src or "").lower(),
                 "remote_name": _get(pkt, cdp.CDPMsgDeviceID, "val"),
                 "remote_port": _get(pkt, cdp.CDPMsgPortID, "iface"),
                 "platform": _get(pkt, cdp.CDPMsgPlatform, "val"),
                 "software": _get(pkt, cdp.CDPMsgSoftwareVersion, "val")[:200],
                 "addresses": [str(a) for a in addrs]}
        elif pkt.haslayer(lldp.LLDPDU):
            raw = pkt[lldp.LLDPDUManagementAddress].management_address \
                if pkt.haslayer(lldp.LLDPDUManagementAddress) else b""
            n = {"via": "lldp",
                 "remote_name": _get(pkt, lldp.LLDPDUSystemName, "system_name"),
                 "remote_port": _get(pkt, lldp.LLDPDUPortID, "id"),
                 "platform": _get(pkt, lldp.LLDPDUSystemDescription, "description")[:200],
                 "addresses": [".".join(map(str, raw))] if isinstance(raw, bytes) and len(raw) == 4 else []}
        if n and n["remote_name"]:
            n["remote_name"] = n["remote_name"].split(".")[0]
            on_neighbor(n)

    def run():
        try:
            sniff(iface=iface, store=False, prn=handle,
                  filter="ether dst 01:00:0c:cc:cc:cc or ether proto 0x88cc")
        except Exception as e:
            log.warning("CDP/LLDP sniff stopped: %s", e)

    threading.Thread(target=run, daemon=True, name="sniff").start()


def _get(pkt, layer, field):
    if not pkt.haslayer(layer):
        return ""
    v = getattr(pkt[layer], field, b"")
    return v.decode("latin-1", "replace") if isinstance(v, bytes) else str(v)
