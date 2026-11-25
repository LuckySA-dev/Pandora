"""Web terminal: xterm.js <-> SSH shell or console port over a websocket.

Protocol (adapted from WebSSH, MIT, Copyright (c) 2017 Shengdun Hua):
  browser -> server  JSON text frames: {"data": "<keys>"} | {"resize": [cols, rows]} | {"break": true}
  server -> browser  raw device bytes in binary frames (the browser decodes UTF-8 as a stream)
Reads block with a short timeout instead of polling, so output reaches the screen as soon as the
device sends it; every key (backspace, arrows, Ctrl-C, Tab, ?) goes to the device untouched, which
is what makes it behave like a session on the box itself.
"""
import asyncio
import contextlib
import json
import socket
import threading

from fastapi import APIRouter, WebSocket, WebSocketDisconnect

from .. import console
from . import ui_ok

BUF = 32 * 1024


def router(ctx):
    r = APIRouter()

    @r.websocket("/ws/term/{device_id}")
    async def term(ws: WebSocket, device_id: int, cols: int = 120, rows: int = 32):
        if not ui_ok(ws.client.host, ws.headers):
            return await ws.close()
        await ws.accept()
        d = ctx.db.device(device_id)
        lp, q, alive = asyncio.get_running_loop(), asyncio.Queue(), threading.Event()
        alive.set()
        with contextlib.ExitStack() as stack:
            try:  # lock wait / serial open / SSH connect block: keep them off the event loop
                if not d:
                    raise LookupError("no such device")
                link = await asyncio.to_thread(_open, ctx, d, stack, _clamp(cols, 20, 400), _clamp(rows, 5, 200))
            except Exception as e:
                await ws.send_bytes(f"\r\n*** {type(e).__name__}: {e}\r\n".encode())
                return await ws.close()

            def pump():  # device -> browser
                while alive.is_set():
                    try:
                        data = link.read()
                    except Exception:
                        data = None
                    if data is None:  # session ended on the device side
                        lp.call_soon_threadsafe(q.put_nowait, None)
                        return
                    if data:
                        lp.call_soon_threadsafe(q.put_nowait, data)

            async def sender():
                while (data := await q.get()) is not None:
                    await ws.send_bytes(data)
                await ws.send_bytes(b"\r\n[session closed by the device]\r\n")
                await ws.close()

            threading.Thread(target=pump, daemon=True, name=f"term-{device_id}").start()
            task = asyncio.create_task(sender())
            try:
                while True:  # browser -> device
                    msg = json.loads(await ws.receive_text())
                    if isinstance(msg.get("data"), str):
                        link.write(msg["data"].encode("utf-8"))
                    if isinstance(msg.get("resize"), list) and len(msg["resize"]) == 2:
                        link.resize(_clamp(msg["resize"][0], 20, 400), _clamp(msg["resize"][1], 5, 200))
                    if msg.get("break"):
                        link.send_break()
            except (WebSocketDisconnect, RuntimeError, ValueError, AttributeError):
                pass
            finally:
                alive.clear()
                task.cancel()

    return r


def _clamp(v, lo, hi):
    try:
        return max(lo, min(hi, int(v)))
    except (TypeError, ValueError):
        return lo


class _Console:
    def __init__(self, con):
        self.s = con.s
        self.s.timeout = 0.05  # wake fast; read() below returns as soon as anything arrives

    def read(self):
        n = getattr(self.s, "in_waiting", 0)
        return self.s.read(n or 1)

    def write(self, b):
        self.s.write(b)

    def resize(self, cols, rows):
        pass  # a serial line has no window size

    def send_break(self):  # ROMMON / password recovery on Cisco consoles
        if hasattr(self.s, "send_break"):
            self.s.send_break(0.3)


class _Ssh:
    def __init__(self, chan):
        self.chan = chan
        chan.settimeout(0.5)

    def read(self):
        try:
            data = self.chan.recv(BUF)
        except socket.timeout:
            return b""
        return data if data else None  # b"" from recv = channel closed

    def write(self, b):
        self.chan.sendall(b)

    def resize(self, cols, rows):
        with contextlib.suppress(Exception):
            self.chan.resize_pty(width=cols, height=rows)

    def send_break(self):
        pass  # not meaningful over SSH


def _open(ctx, d, stack, cols, rows):
    """Blocking: a link to the device's console port or an SSH shell sized to the browser window."""
    if d["path"] == "console" and d["console_port"]:
        return _Console(stack.enter_context(console.session(d["console_port"])))
    import paramiko

    from ..hostkeys import Pin
    c = ctx.creds_for(d)
    client = paramiko.SSHClient()
    client.set_missing_host_key_policy(Pin(ctx, d["id"]))  # same pinned key as netmiko; refused before the password
    client.connect(d["ip"], username=c["username"], password=c["password"], timeout=10,
                   look_for_keys=False, allow_agent=False)
    stack.callback(client.close)
    return _Ssh(client.invoke_shell(term="xterm", width=cols, height=rows))
