"""What a device's state means right now, for the UI: the provisioning state until it is configured, then what
monitoring sees. "Ready" only for a configured box that answers and is healthy; a box that stopped answering
is Offline, not Ready (it used to stay Ready forever, with "offline" as a small note under it).
"""
RESTARTED = 15 * 60 * 100  # sysUpTime (1/100 s) under 15 min: it just came back from a restart

# order = how bad, for sorting: the worst first
ORDER = ("failed", "offline", "degraded", "restarted", "drifted", "needs_credentials", "provisioning", "queued",
         "configured", "identified", "discovered", "ready")


def of(d: dict, severity: str | None = None, compliant: bool | None = None, last: dict | None = None) -> str:
    """d: a devices row (state, reach). severity: its worst open problem. last: its last SNMP sample."""
    if d["state"] != "provisioned":
        return d["state"]  # discovered / identified / needs_credentials / queued / provisioning / failed
    if d.get("reach") == "offline":
        return "offline"
    if not d.get("reach"):
        return "configured"  # pre-configured, SNMP hasn't answered yet: not proven ready
    up = str((last or {}).get("uptime", ""))
    if up.isdigit() and int(up) < RESTARTED:
        return "restarted"
    if severity in ("average", "high", "disaster"):
        return "degraded"
    if compliant is False:
        return "drifted"
    return "ready"
