"""Minimal DHCP server bound to ONE interface. Options are chosen per client by a `decide` callback.

decide(mac, info, ip) -> dict[int, bytes] of extra options, or None to stay silent (device is only "seen").
"""
import ipaddress
import logging
import socket
import struct
import threading

log = logging.getLogger("pandora.dhcp")

MAGIC = 0x63825363
HDR = struct.Struct("!4BIHH4s4s4s4s16s64s128sI")
DISCOVER, OFFER, REQUEST, DECLINE, ACK, NAK, RELEASE = 1, 2, 3, 4, 5, 6, 7


def parse(pkt: bytes) -> dict:
    f = HDR.unpack_from(pkt)
    if f[-1] != MAGIC:
        raise ValueError("not DHCP")
    opts, i, data = {}, HDR.size, pkt
    while i < len(data):
        code = data[i]
        if code == 255:
            break
        if code == 0:
            i += 1
            continue
        ln = data[i + 1]
        opts[code] = data[i + 2:i + 2 + ln]
        i += 2 + ln
    return {"op": f[0], "xid": f[4], "flags": f[6], "giaddr": f[10],
            "chaddr": f[11], "mac": ":".join(f"{b:02x}" for b in f[11][:6]), "options": opts}


def build(req: dict, msg_type: int, yiaddr: str, server_ip: str, options: dict[int, bytes]) -> bytes:
    # siaddr (next server) only when we hand out a TFTP file: classic IOS treats it as a config server and asks it
    # for network-confg, cisconet.cfg, router-confg, ciscortr.cfg over and over (seen on a 2960X doing PnP)
    siaddr = server_ip if {66, 150} & set(options) else "0.0.0.0"
    hdr = HDR.pack(2, 1, 6, 0, req["xid"], 0, req["flags"] | 0x8000, b"\0" * 4,
                   socket.inet_aton(yiaddr), socket.inet_aton(siaddr), req["giaddr"],
                   req["chaddr"], b"\0" * 64, b"\0" * 128, MAGIC)
    opts = {53: bytes([msg_type]), 54: socket.inet_aton(server_ip), **options}
    body = b"".join(bytes([k, len(v)]) + v for k, v in opts.items())
    return hdr + body + b"\xff"


def opt43_pnp(server_ip: str, port: int = 80) -> bytes:
    """Cisco PnP discovery string: 5A1N;B2;K4;I<server>;J<port> (K4 = http)."""
    return f"5A1N;B2;K4;I{server_ip};J{port}".encode()


def info_from(req: dict) -> dict:
    o = req["options"]
    txt = lambda c: o.get(c, b"").decode("latin-1", "replace").strip("\0")
    return {"vendor_class": txt(60), "client_id": o.get(61, b"").hex(), "hostname": txt(12),
            "requested_ip": socket.inet_ntoa(o[50]) if len(o.get(50, b"")) == 4 else None}


class DhcpServer:
    def __init__(self, server_ip, netmask, pool: list[str], decide, iface_name: str | None = None):
        self.server_ip, self.pool, self.decide, self.iface = server_ip, pool, decide, iface_name
        self.mask = socket.inet_aton(netmask)
        self.leases: dict[str, str] = {}  # ponytail: in memory, restarting forgets leases (devices just re-DHCP)
        self.offered: dict[str, dict] = {}
        self.sock = None

    def lease_for(self, mac: str) -> str:
        if mac not in self.leases:
            used = set(self.leases.values())
            free = next((ip for ip in self.pool if ip not in used), None)
            if free is None:
                raise RuntimeError("DHCP pool exhausted")
            self.leases[mac] = free
        return self.leases[mac]

    def handle(self, pkt: bytes) -> bytes | None:
        req = parse(pkt)
        if req["op"] != 1:
            return None
        mtype = req["options"].get(53, b"\0")[0]
        mac = req["mac"]
        if mtype == DISCOVER:
            ip = self.lease_for(mac)
            extra = self.decide(mac, info_from(req), ip)
            if extra is None:
                return None
            self.offered[mac] = extra
            return build(req, OFFER, ip, self.server_ip, self._opts(extra))
        if mtype == REQUEST and mac in self.offered:
            want = info_from(req)["requested_ip"]
            ip = self.lease_for(mac)
            if want and want != ip:
                return build(req, NAK, "0.0.0.0", self.server_ip, {})
            extra = self.decide(mac, info_from(req), ip) or self.offered[mac]
            return build(req, ACK, ip, self.server_ip, self._opts(extra))
        if mtype in (RELEASE, DECLINE):
            self.leases.pop(mac, None)
            self.offered.pop(mac, None)
        return None

    def _opts(self, extra):
        return {1: self.mask, 51: struct.pack("!I", 3600), **extra}

    def bind(self):
        """In the caller's thread, so a busy port stops startup. Exclusive: with SO_REUSEADDR a second PandoraBox
        (an old copy that never exited) bound port 67 too, and two DHCP servers answered on one segment (seen)."""
        s = self.sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        if hasattr(socket, "SO_EXCLUSIVEADDRUSE"):  # Windows
            s.setsockopt(socket.SOL_SOCKET, socket.SO_EXCLUSIVEADDRUSE, 1)
        s.setsockopt(socket.SOL_SOCKET, socket.SO_BROADCAST, 1)
        if hasattr(socket, "SO_BINDTODEVICE") and self.iface:  # Linux
            s.setsockopt(socket.SOL_SOCKET, socket.SO_BINDTODEVICE, self.iface.encode())
            s.bind(("", 67))
        else:  # Windows: binding to the NIC address limits us to that NIC
            s.bind((self.server_ip, 67))
        log.info("DHCP listening on %s:67", self.server_ip)

    def serve_forever(self):
        if self.sock is None:
            self.bind()
        s = self.sock
        while True:
            pkt, addr = s.recvfrom(4096)
            try:
                reply = self.handle(pkt)
            except Exception:
                log.exception("bad DHCP packet from %s", addr)
                continue
            if reply:
                # ponytail: always broadcast; relayed (giaddr) setups would unicast to the relay instead
                s.sendto(reply, ("255.255.255.255", 68))

    def start(self):
        self.bind()  # raises OSError here, not in the thread
        threading.Thread(target=self.serve_forever, daemon=True, name="dhcp").start()


def ip_opt(ip: str) -> bytes:
    return ipaddress.IPv4Address(ip).packed
