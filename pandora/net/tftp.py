"""TFTP for classic IOS AutoInstall. Files are generated per device on request (FreeZTP idea)."""
import importlib
import io
import logging
import re
import threading
import time
from pathlib import Path

import tftpy
from tftpy.TftpContexts import TftpContextServer

log = logging.getLogger("pandora.tftp")
# What every classic IOS box asks for while booting without a config (broadcast, whether or not it was pointed at
# us): answered "not found" so it moves on, but not logged. On the bench they were ~100 log lines per box.
IOS_DEFAULTS = re.compile(r"^(network-confg|cisconet\.cfg|router-confg|ciscortr\.cfg|[\w.-]+-confg)$", re.I)


class _QuietMisses(logging.Filter):
    """tftpy logs a refused file as an ERROR with a session dump; a refused file is how we say "not for you"."""

    def filter(self, record):
        msg = record.getMessage()
        return "File not found" not in msg and "Currently handling these sessions" not in msg


for _name in ("tftpy.TftpServer", "tftpy.TftpStates", "tftpy.TftpContexts"):
    logging.getLogger(_name).addFilter(_QuietMisses())


class _NoLockContext(TftpContextServer):
    """Our files are generated in memory (BytesIO): there is nothing to lock, and tftpy's lock helper
    needs a real file (.name / fileno). TftpServer(flock=False) is not passed on to its per-transfer
    contexts (tftpy 0.8.x), so without this the server thread crashes after the first transfer."""

    def __init__(self, *a, **kw):
        super().__init__(*a, **kw)
        self.flock = False


# `tftpy.TftpServer` is the class; the module of the same name is where listen() looks the context up.
importlib.import_module("tftpy.TftpServer").TftpContextServer = _NoLockContext


def start(server_ip: str, root: Path, lookup):
    """lookup(filename, client_ip) -> str config or None (= file not found)."""
    root.mkdir(parents=True, exist_ok=True)

    def dyn(path, raddress=None, rport=None):
        name = Path(str(path)).name
        text = lookup(name, raddress)
        quiet = not text and IOS_DEFAULTS.match(name)
        (log.debug if quiet else log.info)("TFTP %s from %s -> %s", name, raddress, "served" if text else "not found")
        return io.BytesIO(text.encode()) if text else None

    server = tftpy.TftpServer(str(root), dyn_file_func=dyn, flock=False)
    # tftpy binds inside listen(), in its thread: a busy port 69 used to kill only that thread while PandoraBox
    # ran on without AutoInstall (seen: an old copy still held 69). Wait for the bind and re-raise here instead.
    failed = []

    def run():
        try:
            server.listen(server_ip, 69)
        except Exception as e:
            failed.append(e)

    threading.Thread(target=run, daemon=True, name="tftp").start()
    deadline = time.time() + 5
    while not failed and time.time() < deadline:
        sock = server.sock
        try:
            if sock and sock.getsockname()[1] == 69:
                return server
        except OSError:
            pass  # created, not bound yet
        time.sleep(0.05)
    raise failed[0] if failed else OSError(f"TFTP did not start on {server_ip}:69")
