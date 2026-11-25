"""SNMP (pysnmp 7, asyncio): sweep, identify, CDP/LLDP neighbors, polling, v3 inform receiver.

Numeric OIDs only, so no MIB compilation is needed.
"""
import asyncio
import contextlib
import ipaddress
import json
import logging
import socket

from pysnmp.hlapi.v3arch.asyncio import (
    CommunityData,
    ContextData,
    ObjectIdentity,
    ObjectType,
    SnmpEngine,
    UdpTransportTarget,
    UsmUserData,
    bulk_walk_cmd,
    get_cmd,
    usmAesCfb128Protocol,
    usmHMACSHAAuthProtocol,
)

from .identify import parse_sysdescr

log = logging.getLogger("pandora.snmp")

SYS = {"sysDescr": "1.3.6.1.2.1.1.1.0", "sysObjectID": "1.3.6.1.2.1.1.2.0", "sysName": "1.3.6.1.2.1.1.5.0"}
ENT_SERIAL = "1.3.6.1.2.1.47.1.1.1.1.11"
ENT_MODEL = "1.3.6.1.2.1.47.1.1.1.1.13"
IF_NAME = "1.3.6.1.2.1.31.1.1.1.1"
IF_OPER = "1.3.6.1.2.1.2.2.1.8"
IF_HC_IN = "1.3.6.1.2.1.31.1.1.1.6"
IF_HC_OUT = "1.3.6.1.2.1.31.1.1.1.10"
CPU_5MIN = "1.3.6.1.4.1.9.9.109.1.1.1.1.8"
AVG_BUSY5 = "1.3.6.1.4.1.9.2.1.58"           # OLD-CISCO-CPU-MIB: IOL 17.18 has only this one (no cpmCPUTotalTable)
CDP_CACHE = "1.3.6.1.4.1.9.9.23.1.2.1.1"   # .4 address .6 deviceId .7 devicePort .8 platform; index ifIndex.n
LLDP_REM = "1.0.8802.1.1.2.1.4.1.1"        # .7 portId .9 sysName; index timeMark.localPort.n
LLDP_LOC_PORT = "1.0.8802.1.1.2.1.3.7.1.3"  # index localPort
TRAPS = {"1.3.6.1.6.3.1.1.5.1": "coldStart", "1.3.6.1.6.3.1.1.5.3": "linkDown",
         "1.3.6.1.6.3.1.1.5.4": "linkUp", "1.3.6.1.4.1.9.9.43.2.0.1": "configChange"}

@contextlib.contextmanager
def engine():
    """A short-lived engine per request. A shared one breaks in two ways: its UDP transport is bound to
    one event loop (the agent runs SNMP in its own loop), and on Windows one ICMP "port unreachable"
    from a dead host (WSAECONNRESET) kills the shared socket, so every later request times out."""
    e = SnmpEngine()
    try:
        yield e
    finally:
        e.close_dispatcher()


def level(cfg, dev_vars: dict) -> str | None:
    """SNMPv3 security level for a device: 'priv' unless its image has no AES (seen: IOL L2), then 'auth'
    only if the operator allowed it (cfg snmp_allow_auth_nopriv), else None = can't configure SNMP safely."""
    if dev_vars.get("cap_snmp_priv", True):
        return "priv"
    return "auth" if cfg.get("snmp_allow_auth_nopriv") else None


def user(cfg, level) -> str:
    """A USM user has one security level on PandoraBox's side: pysnmp refuses an authNoPriv inform for a user that
    has priv ("authNoPriv wanted while priv expected", seen with IOL L2 informs). authNoPriv boxes get their own."""
    return cfg["snmp_user"] + ("-auth" if level == "auth" else "")


def auth(cfg, community: str | None = None, dev: dict | None = None):
    if community:
        return CommunityData(community, mpModel=1)
    if dev and level(cfg, json.loads(dev.get("vars") or "{}")) == "auth":
        return UsmUserData(user(cfg, "auth"), cfg["snmp_auth"], authProtocol=usmHMACSHAAuthProtocol)
    return UsmUserData(cfg["snmp_user"], cfg["snmp_auth"], cfg["snmp_priv"],
                       authProtocol=usmHMACSHAAuthProtocol, privProtocol=usmAesCfb128Protocol)


def _val(v):
    """pysnmp value -> python. OctetStrings that aren't text come back as bytes."""
    if hasattr(v, "asOctets"):
        return _text_or_bytes(v.asOctets())
    return v.prettyPrint()


def _text_or_bytes(raw: bytes):
    """Text only if every byte is printable ASCII/UTF-8 or tab/CR/LF. Checking for "\\n" alone made
    10.x.x.x addresses (first byte 0x0a) look like text."""
    try:
        s = raw.decode()
    except UnicodeDecodeError:
        return raw
    return s if all(c.isprintable() or c in "\t\r\n" for c in s) else raw


@contextlib.asynccontextmanager
async def session(ip, timeout=2.0, retries=1):
    """One engine + target for every request of one device operation (a poll is 5 walks). Building an
    engine reloads pysnmp's MIB modules (~60 ms of CPU, blocking the loop): per walk, that made polling
    12 devices take as long concurrently as one by one. Reuse also keeps the SNMPv3 engine-ID discovery."""
    target = await UdpTransportTarget.create((ip, 161), timeout=timeout, retries=retries)
    with engine() as e:
        yield e, target


async def get(ip, a, *oids, timeout=1.0, s=None) -> dict:
    if s is None:
        async with session(ip, timeout, retries=0) as s:
            return await get(ip, a, *oids, s=s)
    err, status, _, vbs = await get_cmd(s[0], a, s[1], ContextData(), *[ObjectType(ObjectIdentity(o)) for o in oids])
    if err or status:
        raise RuntimeError(str(err or status.prettyPrint()))
    return {str(n): _val(v) for n, v in vbs}


async def walk(ip, a, base, timeout=2.0, s=None) -> dict:
    if s is None:
        async with session(ip, timeout) as s:
            return await walk(ip, a, base, s=s)
    out = {}
    async for err, status, _, vbs in bulk_walk_cmd(s[0], a, s[1], ContextData(), 0, 25,
                                                   ObjectType(ObjectIdentity(base)), lexicographicMode=False):
        if err or status:
            raise RuntimeError(str(err or status.prettyPrint()))
        out.update({str(n): _val(v) for n, v in vbs})
    return out


async def identify(ip, a) -> dict:
    async with session(ip, timeout=1.0, retries=0) as ss:  # sweep: dead hosts must fail fast
        s = await get(ip, a, *SYS.values(), s=ss)
        facts = {"ip": ip, "hostname": str(s[SYS["sysName"]]).split(".")[0], "source": "snmp",
                 **parse_sysdescr(str(s[SYS["sysDescr"]]))}
        serials = [v for v in (await walk(ip, a, ENT_SERIAL, s=ss)).values() if v]
        models = [v for v in (await walk(ip, a, ENT_MODEL, s=ss)).values() if v]
    if serials:
        facts["serial"] = str(serials[0])
    if models:
        facts["pid"] = str(models[0])
    return facts


async def sweep(subnet: str, a, limit=64) -> list[dict]:
    sem = asyncio.Semaphore(limit)

    async def one(ip):
        async with sem:
            try:
                return await identify(str(ip), a)
            except Exception:
                return None

    hosts = list(ipaddress.ip_network(subnet, strict=False).hosts())[:1024]
    return [r for r in await asyncio.gather(*(one(h) for h in hosts)) if r]


def _rows(walked: dict, base: str, index_len: int) -> dict:
    """{base.col.idx...: v} -> {idx_tuple: {col: v}}"""
    rows = {}
    for oid, v in walked.items():
        rest = oid[len(base) + 1:].split(".")
        col, idx = rest[0], tuple(rest[1:1 + index_len])
        rows.setdefault(idx, {})[col] = v
    return rows


def _ip(v):
    if isinstance(v, (bytes, bytearray)) and len(v) == 4:
        return socket.inet_ntoa(bytes(v))
    if isinstance(v, str) and len(v) == 4:  # an address whose 4 bytes happen to be printable, e.g. 65.66.67.68
        return socket.inet_ntoa(v.encode("latin-1"))
    if isinstance(v, str) and v.startswith("0x") and len(v) == 10:
        return socket.inet_ntoa(bytes.fromhex(v[2:]))
    return None


def parse_cdp(walked: dict, ifnames: dict) -> list[dict]:
    out = []
    for (ifindex, _), r in _rows(walked, CDP_CACHE, 2).items():
        out.append({"local_port": ifnames.get(ifindex, ifindex), "remote_name": str(r.get("6", "")).split(".")[0],
                    "remote_port": str(r.get("7", "")), "platform": str(r.get("8", "")),
                    "remote_ip": _ip(r.get("4")), "via": "cdp"})
    return out


def parse_lldp(walked: dict, locports: dict) -> list[dict]:
    out = []
    for (_, lport, _), r in _rows(walked, LLDP_REM, 3).items():
        out.append({"local_port": locports.get(lport, lport), "remote_name": str(r.get("9", "")).split(".")[0],
                    "remote_port": str(r.get("7", "")), "platform": "", "remote_ip": None, "via": "lldp"})
    return out


async def neighbors(ip, a) -> list[dict]:
    async with session(ip) as s:
        ifn = {k.rsplit(".", 1)[1]: str(v) for k, v in (await walk(ip, a, IF_NAME, s=s)).items()}
        nb = parse_cdp(await walk(ip, a, CDP_CACHE, s=s), ifn)
        try:
            loc = {k.rsplit(".", 1)[1]: str(v) for k, v in (await walk(ip, a, LLDP_LOC_PORT, s=s)).items()}
            seen = {n["remote_name"] for n in nb}
            nb += [n for n in parse_lldp(await walk(ip, a, LLDP_REM, s=s), loc) if n["remote_name"] not in seen]
        except Exception:
            pass  # LLDP not enabled: CDP is enough
    return nb


async def poll(ip, a) -> dict:
    """Interface status + traffic counters + CPU. Returns {name: value}."""
    async with session(ip) as s:
        ifn = {k.rsplit(".", 1)[1]: str(v) for k, v in (await walk(ip, a, IF_NAME, s=s)).items()}
        out = {}
        for base, label in ((IF_OPER, "oper"), (IF_HC_IN, "in"), (IF_HC_OUT, "out")):
            for k, v in (await walk(ip, a, base, s=s)).items():
                name = ifn.get(k.rsplit(".", 1)[1])
                if name and not name.startswith(("Nu", "Vo", "Lo")):
                    out[f"{name}:{label}"] = {"1": "up", "2": "down"}.get(str(v), str(v)) if label == "oper" else str(v)
        cpu = list((await walk(ip, a, CPU_5MIN, s=s)).values()) or list((await walk(ip, a, AVG_BUSY5, s=s)).values())
    if cpu:
        out["cpu5min"] = str(cpu[0])
    return out


def start_receiver(cfg, on_trap, port=162):
    """SNMPv3 *informs*: the receiver is the authoritative engine, so no per-device engine IDs are needed.
    Must be called from inside the running asyncio loop."""
    from pysnmp.carrier.asyncio.dgram import udp
    from pysnmp.entity import config
    from pysnmp.entity import engine as eng
    from pysnmp.entity.rfc3413 import ntfrcv
    from pysnmp.proto.rfc1902 import OctetString
    e = eng.SnmpEngine(OctetString(hexValue=cfg["snmp_engine_id"]))  # the ID the devices were told (base.j2)
    config.add_transport(e, udp.DOMAIN_NAME, udp.UdpTransport().open_server_mode((cfg["server_ip"], port)))
    config.add_v3_user(e, cfg["snmp_user"], config.USM_AUTH_HMAC96_SHA, cfg["snmp_auth"],
                       config.USM_PRIV_CFB128_AES, cfg["snmp_priv"])
    if cfg.get("snmp_allow_auth_nopriv"):
        config.add_v3_user(e, user(cfg, "auth"), config.USM_AUTH_HMAC96_SHA, cfg["snmp_auth"])

    def cb(snmp_engine, state_ref, ctx_engine_id, ctx_name, var_binds, cb_ctx):
        _, addr = snmp_engine.message_dispatcher.get_transport_info(state_ref)
        vbs = [(str(n), str(_val(v))) for n, v in var_binds]
        trap_oid = next((v for n, v in vbs if n == "1.3.6.1.6.3.1.1.4.1.0"), "")
        on_trap(addr[0], TRAPS.get(trap_oid, trap_oid), vbs)

    ntfrcv.NotificationReceiver(e, cb)
    e.transport_dispatcher.job_started(1)
    log.info("SNMP inform receiver on %s:%s", cfg["server_ip"], port)
    return e
