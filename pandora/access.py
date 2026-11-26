"""Does the device already have a login? -> ask the user for credentials, else continue."""
import re
import socket

# device_id -> {"username", "password", "secret"}. Session memory only: never written to db or logs.
CREDS: dict[int, dict] = {}

_LOGIN = re.compile(r"(user\s*name|login|password)\s*:\s*$", re.I)


def ssh_open(ip: str | None, port: int = 22, timeout: float = 2.0) -> bool:
    """Does a login service answer there? An open TCP port is not enough: IOS can accept on 22 and close at once
    (keys gone, no crypto), or answer on 23 with "% Connection refused" when the vty lines allow SSH only. So port
    22 must send the SSH greeting, and 23 must not refuse."""
    if not ip:
        return False
    try:
        with socket.create_connection((ip, port), timeout=timeout) as s:
            if port not in (22, 23):
                return True
            s.settimeout(timeout)
            got = b""
            try:
                while len(got) < 64 and (chunk := s.recv(64)):
                    got += chunk
                    if port == 22 and b"SSH-" in got or port == 23 and len(got) >= 3:
                        break
            except OSError:
                pass  # nothing more within the timeout
            if port == 22:
                return b"SSH-" in got
            return bool(got) and b"refused" not in got.lower()  # IOS telnet opens with its option negotiation
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
