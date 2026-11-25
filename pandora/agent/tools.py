"""Agent tools. Reads run freely; anything that changes a device or template waits for a human Approve."""
import itertools
import json
import re
import threading
import time
from pathlib import Path

from .. import alloc, snmp
from ..db import mask_secrets

READ_ONLY = re.compile(r"^(show|ping|traceroute)\b", re.I)
BAD_PIPE = re.compile(r"\|\s*(redirect|append|tee)\b", re.I)

# ---- approvals -----------------------------------------------------------------
_ids = itertools.count(1)
APPROVALS: dict[int, dict] = {}


def request_approval(ctx, summary: dict, timeout=600) -> bool:
    aid = next(_ids)
    APPROVALS[aid] = {"event": threading.Event(), "ok": False}
    ctx.emit("approval", {"id": aid, **summary})
    APPROVALS[aid]["event"].wait(timeout)
    return APPROVALS.pop(aid)["ok"]


def answer(aid: int, ok: bool):
    if aid in APPROVALS:
        APPROVALS[aid]["ok"] = ok
        APPROVALS[aid]["event"].set()


# ---- tool definitions ------------------------------------------------------------
def _s(props, req):
    return {"type": "object", "properties": props, "required": req, "additionalProperties": False}


DEV = {"type": "integer", "description": "device id from list_devices"}
LINES = {"type": "array", "items": {"type": "string"}, "description": "IOS config lines, in order"}
SPECS = [
    {"name": "list_devices", "description": "Inventory: id, hostname, ip, pid, os, state, reserved mgmt ports.",
     "input_schema": _s({}, [])},
    {"name": "show", "description": "Run a read-only command (show/ping/traceroute) over SSH.",
     "input_schema": _s({"device_id": DEV, "command": {"type": "string"}}, ["device_id", "command"])},
    {"name": "get_running_config", "description": "show running-config (secrets masked).",
     "input_schema": _s({"device_id": DEV}, ["device_id"])},
    {"name": "snmp_get", "description": "SNMPv3 GET of numeric OIDs.",
     "input_schema": _s({"device_id": DEV, "oids": {"type": "array", "items": {"type": "string"}}},
                        ["device_id", "oids"])},
    {"name": "propose_config", "description": "Dry run: shows which lines are new vs. running config and "
                                              "whether they touch protected mgmt ports/VLAN/users. Changes nothing.",
     "input_schema": _s({"device_id": DEV, "lines": LINES}, ["device_id", "lines"])},
    {"name": "apply_config", "description": "Apply config lines. Takes a flash snapshot first, then WAITS for the "
                                            "human to approve. Returns device output and the snapshot id for rollback.",
     "input_schema": _s({"device_id": DEV, "lines": LINES, "reason": {"type": "string"}},
                        ["device_id", "lines", "reason"])},
    {"name": "rollback", "description": "configure replace to a snapshot taken by apply_config (needs approval).",
     "input_schema": _s({"device_id": DEV, "snapshot_id": {"type": "integer"}}, ["device_id", "snapshot_id"])},
    {"name": "read_template", "description": "Read a Jinja config template (e.g. switch_access.j2).",
     "input_schema": _s({"name": {"type": "string"}}, ["name"])},
    {"name": "write_template", "description": "Create/overwrite a role template (needs approval). "
                                              "base.j2 (mgmt access) cannot be changed.",
     "input_schema": _s({"name": {"type": "string"}, "content": {"type": "string"}}, ["name", "content"])},
]


class Tools:
    def __init__(self, ctx):
        self.ctx = ctx

    def run(self, name, args) -> str:
        fn = getattr(self, "t_" + name, None)
        if fn is None:
            raise ValueError(f"unknown tool {name}")
        out = fn(**args)
        return out if isinstance(out, str) else json.dumps(out, default=str, indent=1)

    def _dev(self, device_id):
        d = self.ctx.db.device(int(device_id))
        if not d or not d["ip"]:
            raise ValueError(f"device {device_id} unknown or has no IP")
        return d

    def _protected(self, d):
        a = alloc.allocate(self.ctx.db, self.ctx.cfg, d["id"])
        return a["reserved_ports"]

    # ---- read --------------------------------------------------------------
    def t_list_devices(self):
        keys = ("id", "hostname", "ip", "pid", "os_type", "version", "state", "path", "role", "reserved")
        return [{k: d[k] for k in keys} for d in self.ctx.db.devices()]

    def t_show(self, device_id, command):
        # A line break would make netmiko send the rest as further commands (config mode included).
        if "\n" in command or "\r" in command or not READ_ONLY.match(command.strip()) or BAD_PIPE.search(command):
            raise ValueError("one show/ping/traceroute line, without redirect/append/tee")
        return mask_secrets(self.ctx.ssh_command(self._dev(device_id), command))[:20000]

    def t_get_running_config(self, device_id):
        return self.t_show(device_id, "show running-config")

    def t_snmp_get(self, device_id, oids):
        import asyncio
        d = self._dev(device_id)
        return asyncio.run(snmp.get(d["ip"], snmp.auth(self.ctx.cfg, dev=d), *oids, timeout=3))

    def t_propose_config(self, device_id, lines):
        d = self._dev(device_id)
        running = {l.strip() for l in self.ctx.ssh_command(d, "show running-config").splitlines()}
        return {"new_lines": [l for l in lines if l.strip() not in running],
                "already_present": [l for l in lines if l.strip() in running],
                "blocked": alloc.guard(lines, self._protected(d), self.ctx.cfg["mgmt_vlan"],
                                       [self.ctx.cfg["admin_user"]])}

    def t_read_template(self, name):
        return self._tpl(name).read_text(encoding="utf-8")

    # ---- write (approval) ----------------------------------------------------
    def t_apply_config(self, device_id, lines, reason):
        d = self._dev(device_id)
        blocked = alloc.guard(lines, self._protected(d), self.ctx.cfg["mgmt_vlan"], [self.ctx.cfg["admin_user"]])
        if blocked:
            return {"applied": False, "blocked": blocked}
        if not request_approval(self.ctx, {"device": d["hostname"] or d["ip"], "lines": lines, "reason": reason}):
            return {"applied": False, "reason": "rejected by user (or no answer in 10 min)"}
        snap = f"flash:pandora-{int(time.time())}.cfg"
        self._exec(d, f"copy running-config {snap}")
        snap_id = self.ctx.db.save_config(d["id"], "snapshot", snap, "before agent change")
        out = self.ctx.ssh_config(d, lines)
        self.ctx.db.save_config(d["id"], "agent", "\n".join(lines), reason)
        errors = [l for l in out.splitlines() if l.startswith("%")]
        return {"applied": True, "snapshot_id": snap_id, "errors": errors, "output": mask_secrets(out)[-4000:]}

    def t_rollback(self, device_id, snapshot_id):
        d = self._dev(device_id)
        rows = self.ctx.db.q("SELECT text FROM configs WHERE id=? AND device_id=? AND method='snapshot'",
                             int(snapshot_id), d["id"])
        if not rows:
            raise ValueError("no such snapshot for this device")
        if not request_approval(self.ctx, {"device": d["hostname"] or d["ip"],
                                           "lines": [f"configure replace {rows[0]['text']} force"],
                                           "reason": "rollback"}):
            return {"rolled_back": False}
        return {"rolled_back": True, "output": self._exec(d, f"configure replace {rows[0]['text']} force")}

    def t_write_template(self, name, content):
        path = self._tpl(name)
        if path.name == "base.j2":
            raise ValueError("base.j2 holds PandoraBox's own access and is not editable by the agent")
        if not request_approval(self.ctx, {"device": f"template {path.name}", "lines": content.splitlines(),
                                           "reason": "template change"}):
            return {"written": False}
        path.write_text(content, encoding="utf-8")
        return {"written": True}

    def _tpl(self, name):
        if not re.fullmatch(r"[\w-]+\.j2", name):
            raise ValueError("template name must look like role_name.j2")
        return Path(self.ctx.template_dir) / name

    def _exec(self, d, cmd):
        from ..deliver import connect
        with connect(self.ctx.netmiko_params(d)) as conn:
            conn.enable()
            out = conn.send_command_timing(cmd)
            if out.rstrip().endswith("?"):  # "Destination filename [...]?" / "Proceed?"
                out += conn.send_command_timing("\n")
            return out
