"""Per-OS knowledge in one place (Oxidized "models", LibreNMS OS definitions).

Everything that differs between IOS and IOS-XE lives here as data, so the rest of the code
asks `platforms.get(os_type)` instead of scattering `if os == ...` checks.
"""
import re

# Lines that change on their own (timestamps, counters): stripping them keeps backups from
# producing a "change" every time we fetch (Oxidized does the same per model).
_VOLATILE = [
    r"^Building configuration\.\.\.",
    r"^Current configuration : \d+ bytes",
    r"^! Last configuration change at .*",
    r"^! NVRAM config last updated at .*",
    r"^! No configuration change since last restart",
    r"^ntp clock-period \d+",
    r"^\s*$",
    # from Oxidized's IOS model (Apache-2.0, see NOTICE): errors from commands some boxes don't support
    r"^% Invalid input detected at '\^' marker\.$",
    r"^\s+\^$",
]

PLATFORMS = {
    "iosxe": {"name": "Cisco IOS-XE", "netmiko": "cisco_xe", "backup": "show running-config",
              "strip": _VOLATILE},
    "ios": {"name": "Cisco IOS", "netmiko": "cisco_ios", "backup": "show running-config",
            "strip": _VOLATILE + [r"^! Configuration last modified by .*"]},
}


def get(os_type: str | None) -> dict:
    """Unknown OS (not identified yet) behaves like classic IOS, the most forgiving netmiko driver."""
    return PLATFORMS.get(os_type or "", PLATFORMS["ios"])


def clean(os_type: str | None, text: str) -> str:
    """Config text as we store and compare it: volatile lines removed, line endings normalised."""
    pats = [re.compile(p) for p in get(os_type)["strip"]]
    lines = [l.rstrip() for l in text.replace("\r\n", "\n").replace("\r", "\n").split("\n")]
    return "\n".join(l for l in lines if not any(p.match(l) for p in pats)) + "\n"
