"""Does the device already have a login? -> ask the user for credentials, else continue."""
import re
import socket

# device_id -> {"username", "password", "secret"}. Session memory only: never written to db or logs.
CREDS: dict[int, dict] = {}

_LOGIN = re.compile(r"(user\s*name|login|password)\s*:\s*$", re.I)


def ssh_open(ip: str | None, port: int = 22, timeout: float = 2.0) -> bool:
    if not ip:
        return False
    try:
        with socket.create_connection((ip, port), timeout=timeout):
            return True
    except OSError:
        return False


def console_needs_login(text: str) -> bool:
    """True when the last thing the console printed is a Username:/Password: prompt."""
    lines = [l for l in text.replace("\r", "\n").split("\n") if l.strip()]
    return bool(lines) and bool(_LOGIN.search(lines[-1]))


def needs_credentials(device: dict, console_text: str | None = None) -> bool:
    if device["id"] in CREDS:
        return False
    if device.get("path") == "console":
        return console_needs_login(console_text or "")
    # Over IP: an open SSH port means the box is already configured -> ask before touching it.
    return ssh_open(device.get("ip"))
