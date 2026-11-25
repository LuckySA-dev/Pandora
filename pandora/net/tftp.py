"""TFTP for classic IOS AutoInstall. Files are generated per device on request (FreeZTP idea)."""
import importlib
import io
import logging
import threading
from pathlib import Path

import tftpy
from tftpy.TftpContexts import TftpContextServer

log = logging.getLogger("pandora.tftp")


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
        text = lookup(Path(str(path)).name, raddress)
        log.info("TFTP %s from %s -> %s", path, raddress, "served" if text else "not found")
        return io.BytesIO(text.encode()) if text else None

    server = tftpy.TftpServer(str(root), dyn_file_func=dyn, flock=False)
    threading.Thread(target=server.listen, args=(server_ip, 69), daemon=True, name="tftp").start()
    return server
