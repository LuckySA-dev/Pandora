"""USB/RJ45 console: find ports, read the device state, log in, identify, paste config."""
import contextlib
import logging
import re
import threading
import time

import serial
from serial.tools import list_ports

from .access import console_needs_login
from .identify import parse_inventory, parse_show_version

log = logging.getLogger("pandora.console")
LOCKS: dict[str, threading.Lock] = {}  # one user of a COM port at a time (probe / push / web terminal)

# IOS-XE with no startup-config: "Autoinstall will terminate if any input is detected on console"
ZTP_RUNNING = re.compile(r"Autoinstall will terminate|starting autoinstall/pnp/ztp|%PNP-6-PNP_", re.I)
STATES = [  # order matters: first match on the tail of the output wins
    ("dialog", re.compile(r"initial configuration dialog\?.*$|\[yes/no\]:\s*$", re.I)),
    ("autoinstall", re.compile(r"terminate autoinstall\?.*$", re.I)),
    ("return", re.compile(r"Press RETURN to get started", re.I)),
    ("rommon", re.compile(r"(rommon \d+ ?>|switch:)\s*$", re.I)),
    ("priv", re.compile(r"\n[\w.\-()]+#\s*$")),
    ("user", re.compile(r"\n[\w.\-()]+>\s*$")),
    ("ztp", ZTP_RUNNING),  # last: a real prompt in the same tail wins
]


def classify(text: str) -> str:
    tail = text[-400:]
    if console_needs_login(tail):
        return "login"
    return next((name for name, rx in STATES if rx.search(tail)), "unknown")


class Console:
    def __init__(self, port, baud=9600):
        self.port = port
        # COM3 / /dev/ttyUSB0, or a terminal server: socket://host:port, rfc2217://host:port
        self.s = serial.serial_for_url(port, baud, timeout=0.2)
        self.factory = False  # set when we see the no-startup-config setup/autoinstall dialog

    def read(self, quiet=1.0, limit=30.0) -> str:
        """Read until the line is quiet for `quiet` seconds."""
        buf, last, start = b"", time.time(), time.time()
        while time.time() - last < quiet and time.time() - start < limit:
            chunk = self.s.read(4096)
            if chunk:
                buf, last = buf + chunk, time.time()
                if b"--More--" in chunk:
                    self.s.write(b" ")
        return buf.decode("latin-1", "replace")

    def send(self, line: str, quiet=1.0) -> str:
        self.s.write(line.encode() + b"\r")
        return self.read(quiet)

    def state(self) -> tuple[str, str]:
        text = self.send("", 1.5)
        return classify(text), text

    def login(self, creds: dict | None, max_steps=25) -> bool:
        """Walk from whatever the console shows to a privileged prompt. False = needs credentials."""
        for _ in range(max_steps):
            st, text = self.state()
            if st == "priv":
                self.send("terminal length 0")
                return True
            if st == "ztp":  # we were asked to configure it here: taking over stops its AutoInstall/PnP
                self.factory = True
                self.send("", 3)
            elif st == "dialog":
                self.factory = True
                self.send("no", 3)
            elif st == "autoinstall":
                self.factory = True
                self.send("yes", 3)
            elif st == "return":
                continue
            elif st == "login":
                if not creds:
                    return False
                if re.search(r"(user\s*name|login)\s*:\s*$", text.strip(), re.I):
                    self.send(creds["username"])
                self.send(creds["password"], 2)
            elif st == "user":
                out = self.send("enable")
                if console_needs_login(out):
                    if not creds:
                        return False
                    self.send(creds.get("secret") or creds["password"], 2)
            elif st == "rommon":
                raise RuntimeError("device is in ROMMON; boot it first")
            else:
                time.sleep(2)  # still booting
        raise RuntimeError("could not reach a privileged prompt")

    def ask(self, question: str) -> str:
        """IOS `?` help for a config command, nothing configured: type it + '?', read, then backspace over the
        half line IOS types back (not Ctrl-C: some console servers turn it into a signal or a break)."""
        self.send("configure terminal")
        self.s.write(f"{question} ?".encode())
        out = self.read(1.5)
        self.s.write(b"\x08" * (len(question) + 2))
        self.read(0.5)
        self.send("end")
        return out

    def facts(self) -> dict:
        f = parse_show_version(self.send("show version", 2))
        f.update({k: v for k, v in parse_inventory(self.send("show inventory", 2)).items() if v})
        f.pop("hostname", None)
        return f

    def configure(self, text: str) -> list[str]:
        """Paste line by line (consoles drop characters if you blast them). Returns error lines."""
        errors = []
        self.send("configure terminal")
        for line in text.splitlines():
            if not line.strip() or line.lstrip().startswith("!"):
                continue
            out = self.send(line, 0.3 if not line.startswith("crypto key") else 8)
            if "% Invalid" in out or "% Incomplete" in out or "% Ambiguous" in out:
                errors.append(f"{line.strip()} -> {out.strip().splitlines()[-1] if out.strip() else '?'}")
        self.send("end")
        self.send("write memory", 5)
        return errors

    def close(self):
        self.s.close()


@contextlib.contextmanager
def session(port):
    lock = LOCKS.setdefault(port, threading.Lock())
    if not lock.acquire(timeout=30):
        raise RuntimeError(f"{port} is busy")
    con = None
    try:
        con = Console(port)
        yield con
    finally:
        if con:
            con.close()
        lock.release()


def probe(port) -> dict:
    """Look only: never answer dialogs here. Listen before pressing RETURN: on a factory box any console
    input ends its AutoInstall/PnP/ZTP, so a box that says it is zero-touching is left alone."""
    with session(port) as con:
        heard = con.read(quiet=2, limit=6)
        if ZTP_RUNNING.search(heard):
            return {"console_state": "ztp"}
        st, text = con.state()
        facts = {}
        if st in ("priv", "user"):
            con.send("terminal length 0")
            facts = con.facts()
        return {"console_state": st, **facts}


def watch(on_found, interval=5.0, urls=()):
    """Poll for new COM ports (plus terminal-server `urls`, cfg console_urls) forever; on_found(port, probe)."""
    known = set()

    def loop():
        while True:
            ports = {p.device for p in list_ports.comports()} | set(urls)
            for port in sorted(ports - known):
                try:
                    r = probe(port)
                    if r["console_state"] == "unknown":
                        continue  # silent port or device still booting: try again next round
                    on_found(port, r)
                except Exception as e:
                    log.info("probe %s: %s", port, e)  # not a usable serial port: don't retry
                known.add(port)
            known.intersection_update(ports)  # unplugged ports get probed again when they return
            time.sleep(interval)

    threading.Thread(target=loop, daemon=True, name="console-watch").start()
