"""Settings from pandora.toml + secrets from env."""
import ipaddress
import os
import tomllib
from pathlib import Path

DEFAULTS = {
    "iface": "", "server_ip": "10.99.0.1", "netmask": "255.255.255.0",
    "dhcp_range": "10.99.0.100-10.99.0.199", "mgmt_range": "10.99.0.10-10.99.0.99",
    "mgmt_gateway": "", "mgmt_vlan": 99, "reserved_port_count": 2, "site": "lab",
    "hostname_pattern": "{site}-{role}-{nn:02d}", "domain": "pandora.local",
    "admin_user": "pandora", "snmp_user": "pandora", "http_port": 80,
    # PandoraBox's own SNMP engine ID (inform receiver). IOS sends SNMPv3 informs only to a remote engine it knows
    # (`snmp-server engineID remote` + a remote user): seen on IOL 17.18, 0 informs sent without them.
    "snmp_engine_id": "80001F8804" + b"pandora".hex(),
    "llm": {"provider": "claude", "model": "claude-opus-5-5", "ollama_url": "http://127.0.0.1:11434"},
}


def load(path: str | Path = "pandora.toml") -> dict:
    cfg = {**DEFAULTS, "llm": dict(DEFAULTS["llm"])}
    p = Path(path)
    if p.exists():
        data = tomllib.loads(p.read_text(encoding="utf-8"))
        cfg["llm"].update(data.pop("llm", {}))
        cfg.update(data)
    cfg["admin_password"] = os.environ.get("PANDORA_ADMIN_PASSWORD", "")
    cfg["snmp_auth"] = os.environ.get("PANDORA_SNMP_AUTH", "")
    cfg["snmp_priv"] = os.environ.get("PANDORA_SNMP_PRIV", "")
    return cfg


def ip_range(spec: str) -> list[str]:
    """'10.0.0.10-10.0.0.12' -> ['10.0.0.10', '10.0.0.11', '10.0.0.12']"""
    a, b = (int(ipaddress.IPv4Address(x.strip())) for x in spec.split("-"))
    return [str(ipaddress.IPv4Address(i)) for i in range(a, b + 1)]
