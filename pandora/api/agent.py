"""AI agent: start a run, answer its approval requests."""
from fastapi import APIRouter
from fastapi.responses import JSONResponse

from ..agent import loop as agent_loop
from ..agent import tools as agent_tools


def router(ctx):
    r = APIRouter(prefix="/api")

    @r.post("/agent")
    def agent(body: dict):
        goal = (body.get("goal") or "").strip()
        if not goal:
            return JSONResponse({"error": "goal required"}, 400)
        agent_loop.start(ctx, goal)
        return {"started": True}

    @r.get("/approvals")
    def pending():
        return sorted(agent_tools.APPROVALS)

    @r.post("/approve/{aid}")
    def approve(aid: int, body: dict):
        ctx.db.audit("user", "approval", {"id": aid, "ok": bool(body.get("ok"))})
        agent_tools.answer(aid, bool(body.get("ok")))
        return {"ok": True}

    return r
