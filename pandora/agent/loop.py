"""Coding-agent style loop: goal -> model picks tools -> we run them -> results back -> repeat."""
import logging
import threading

from . import providers
from .tools import SPECS, Tools

log = logging.getLogger("pandora.agent")

SYSTEM = """You are PandoraBox's network agent. You operate real Cisco IOS / IOS-XE devices through tools.
Work like an engineer at the CLI:
1. Look first: list_devices, then show / get_running_config / snmp_get on the devices involved.
2. Plan the smallest change that does the job. Run propose_config to see new lines and any block.
3. apply_config with a one-line reason. A human approves every change; if rejected, stop and ask.
4. Verify with show commands. If verification fails, explain and offer rollback with the snapshot id.
Never touch the reserved PANDORA-MGMT ports, the mgmt VLAN SVI, the pandora user, SSH or SNMP settings:
they are how this tool reaches the devices. End with a short summary of what changed and what you verified."""


def run(ctx, goal: str, max_steps=40, provider=None):
    """Blocking. Streams every step as ctx.emit('agent', {...})."""
    tools = Tools(ctx)
    p = provider or providers.make(ctx.cfg["llm"], SYSTEM, SPECS)
    say = lambda kind, **kw: ctx.emit("agent", {"kind": kind, **kw})
    ctx.db.audit("user", "agent:goal", goal)
    try:
        text, calls = p.step(user_text=goal)
        for _ in range(max_steps):
            if text:
                say("text", text=text)
            if not calls:
                return say("done")
            results = []
            for c in calls:
                say("tool", name=c["name"], args=c["args"])
                try:
                    out, err = tools.run(c["name"], c["args"]), False
                except Exception as e:  # report to the model, it decides what next
                    out, err = f"{type(e).__name__}: {e}", True
                ctx.db.audit("agent", f"tool:{c['name']}", {"args": c["args"], "error": err, "out": out[:1000]})
                say("result", name=c["name"], output=out[:3000], error=err)
                results.append((c["id"], c["name"], out, err))
            text, calls = p.step(results=results)
        say("error", text=f"stopped after {max_steps} steps")
    except Exception as e:
        log.exception("agent failed")
        say("error", text=f"{type(e).__name__}: {e}")


def start(ctx, goal):
    threading.Thread(target=run, args=(ctx, goal), daemon=True, name="agent").start()
