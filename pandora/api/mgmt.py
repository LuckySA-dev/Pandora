"""Management network design wizard (after pre-config): backbones, members, plan, apply."""
import asyncio

from fastapi import APIRouter
from fastapi.responses import JSONResponse

from .. import mgmt, topology


def router(ctx) -> APIRouter:
    r = APIRouter(prefix="/api/mgmt")

    async def edges():  # always fresh: trunks are chosen from the cabling as it is now
        return (await topology.collect(ctx))["edges"]

    def backbones(body):  # backbones + members, only real, known device ids: the probe logs in to them
        known = {d["id"] for d in ctx.db.devices()}
        ids = [d.get("backbone") for d in body.get("domains", [])] + list((body.get("members") or {}).keys())
        return sorted({int(i) for i in ids if str(i).isdigit() and int(i) in known})

    @r.get("")
    def current():
        return {**mgmt.current(ctx.db), "ops_subnet": str(mgmt.ops_net(ctx.cfg)), "ops_vlan": ctx.cfg["mgmt_vlan"],
                "iface": ctx.cfg.get("iface", ""),
                "devices": [{k: d[k] for k in ("id", "hostname", "ip", "pid", "role", "state")}
                            for d in ctx.db.devices() if d["state"] == "provisioned"]}

    @r.post("/suggest")
    async def suggest(body: dict):
        sug = mgmt.suggest(ctx.db.devices(), [int(b) for b in body.get("backbones", [])], await edges())
        return {str(k): v for k, v in sug.items()}

    @r.post("/plan")
    async def plan(body: dict):
        e = await edges()
        await asyncio.to_thread(mgmt.ensure_caps, ctx, backbones(body))
        return await asyncio.to_thread(mgmt.plan, ctx, body.get("domains", []), body.get("members", {}), e)

    @r.post("/apply")
    async def apply(body: dict):
        # the plan is made again here from the cabling and inventory: lines from the browser are never pushed
        e = await edges()
        await asyncio.to_thread(mgmt.ensure_caps, ctx, backbones(body))
        p = await asyncio.to_thread(mgmt.plan, ctx, body.get("domains", []), body.get("members", {}), e)
        if not p["ok"]:
            return JSONResponse({"error": "; ".join(p["problems"]), "plan": p}, 400)
        return {"plan": p, "results": await asyncio.to_thread(mgmt.apply, ctx, p)}

    @r.post("/retire")
    async def retire(body: dict):
        if body.get("confirm") is not True:  # removes addresses: an explicit yes, like remediate
            return JSONResponse({"error": "confirm: true required"}, 400)
        return {"results": await asyncio.to_thread(mgmt.retire, ctx)}

    return r
