"""Config lifecycle per device: push history, extra config, backups + diff, compliance + remediation."""
import difflib

from fastapi import APIRouter
from fastapi.responses import JSONResponse

from .. import alloc, backup, compliance
from ..db import mask_secrets


def router(ctx):
    r = APIRouter(prefix="/api")

    def device_with_ip(device_id):
        d = ctx.db.device(device_id)
        if not d:
            return None, JSONResponse({"error": "no such device"}, 404)
        if not d["ip"]:
            return None, JSONResponse({"error": "device has no IP yet: pre-config it first"}, 400)
        return d, None

    @r.get("/devices/{device_id}/configs")
    def pushes(device_id: int):
        return ctx.db.q("SELECT id, method, result, ts, text FROM configs WHERE device_id=? ORDER BY id DESC",
                        device_id)

    @r.post("/devices/{device_id}/config")
    def extra_config(device_id: int, body: dict):
        """Extra config after pre-config: guard -> diff -> push over SSH (dry_run returns the diff only)."""
        d, err = device_with_ip(device_id)
        if err:
            return err
        lines = [l for l in body.get("text", "").splitlines() if l.strip()]
        a = alloc.allocate(ctx.db, ctx.cfg, device_id)
        blocked = alloc.guard(lines, a["reserved_ports"], ctx.cfg["mgmt_vlan"], [ctx.cfg["admin_user"]])
        if blocked and not body.get("override"):
            return {"blocked": blocked}
        running = ctx.ssh_command(d, "show running-config")
        diff = "\n".join(difflib.unified_diff(running.splitlines(), running.splitlines() + lines,
                                              "running", "proposed", lineterm="", n=0))
        if body.get("dry_run"):
            return {"diff": mask_secrets(diff), "blocked": blocked}
        out = ctx.ssh_config(d, lines)
        ctx.db.save_config(device_id, "extra", "\n".join(lines), "override" if blocked else "ok")
        ctx.db.audit("user", "extra_config", {"id": device_id, "override": bool(blocked)})
        return {"output": mask_secrets(out)}

    # ---- backups (Oxidized) ---------------------------------------------------------------
    @r.get("/devices/{device_id}/backups")
    def backups(device_id: int):
        return backup.history(ctx.db, device_id)

    @r.post("/devices/{device_id}/backups")
    def backup_now(device_id: int):
        d, err = device_with_ip(device_id)
        if err:
            return err
        try:
            return backup.fetch(ctx, d["id"])
        except Exception as e:
            return JSONResponse({"error": f"backup failed: {e}"}, 502)

    @r.get("/backups/{backup_id}")
    def backup_text(backup_id: int):
        b = backup.get(ctx.db, backup_id)
        return b or JSONResponse({"error": "no such backup"}, 404)

    @r.get("/backups/{old_id}/diff/{new_id}")
    def backup_diff(old_id: int, new_id: int):
        try:
            return {"diff": backup.diff(ctx.db, old_id, new_id)}
        except ValueError as e:
            return JSONResponse({"error": str(e)}, 400)

    # ---- compliance (Golden Config) ---------------------------------------------------------
    @r.get("/devices/{device_id}/compliance")
    def compliance_get(device_id: int):
        return compliance.get(ctx.db, device_id) or {}

    @r.post("/devices/{device_id}/compliance")
    def compliance_run(device_id: int):
        d, err = device_with_ip(device_id)
        if err:
            return err
        try:
            return compliance.run(ctx, d["id"])
        except Exception as e:
            return JSONResponse({"error": f"compliance check failed: {e}"}, 502)

    @r.post("/devices/{device_id}/remediate")
    def remediate(device_id: int, body: dict):
        if not body.get("confirm"):  # the UI shows the plan first; pushing needs an explicit yes
            return JSONResponse({"error": "confirm required"}, 400)
        d, err = device_with_ip(device_id)
        if err:
            return err
        try:
            return compliance.remediate(ctx, d["id"])
        except Exception as e:
            return JSONResponse({"error": f"remediation failed: {e}"}, 502)

    return r
