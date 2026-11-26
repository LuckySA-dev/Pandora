"""Conflict-free per-device allocation (hostname, mgmt IP, reserved mgmt ports) + change guard."""
import json
import re
import sqlite3

from .config import ip_range

ROLE_SHORT = {"switch_access": "sw", "router_edge": "rtr"}

# (PID regex, interface format). Unknown PID -> user must type the ports in the preview.
PORT_TABLE = [
    (r"^C9[23]00[LX]?-(\d+)", "GigabitEthernet1/0/{n}"),
    (r"^C9200CX-(\d+)", "GigabitEthernet1/0/{n}"),
    (r"^WS-C(?:2960XR?|2960S|3650|3850)-(\d+)", "GigabitEthernet1/0/{n}"),
    (r"^WS-C(?:2960G|3560G|3750G)-(\d+)", "GigabitEthernet0/{n}"),
    (r"^WS-C(?:2960|3560|3750)-(\d+)", "FastEthernet0/{n}"),
    (r"^IE-?\d+-(\d+)", "GigabitEthernet1/{n}"),
]
ROUTER_PORTS = [(r"^(ISR4|C8[235]|C1[01]\d\d)", "GigabitEthernet0/0/1"),
                (r"^(CISCO|C)(19|29|39)\d\d", "GigabitEthernet0/1")]


_SWITCH_PID = re.compile(r"^(WS-C|C9[23]00|C1000-|IE-?\d)")


def model_kind(pid: str | None) -> str | None:
    """'switch' / 'router' when the PID says so, else None. Picking the other role pushes lines the box refuses
    (real 2960X given the router role: `ip address` on a switch port)."""
    pid = (pid or "").upper()
    if _SWITCH_PID.match(pid):
        return "switch"
    return "router" if any(re.match(rx, pid) for rx, _ in ROUTER_PORTS) else None


def default_ports(pid: str | None, role: str, count: int) -> list[str] | None:
    pid = (pid or "").upper()
    if role == "router_edge":
        return next(([fmt] for rx, fmt in ROUTER_PORTS if re.match(rx, pid)), None)
    for rx, fmt in PORT_TABLE:
        m = re.match(rx, pid)
        if m:
            last = int(m.group(1))
            return [fmt.format(n=n) for n in range(last - count + 1, last + 1)]
    from .devicetypes import last_ports  # NetBox devicetype-library YAML, if the user added it
    return last_ports(pid, count)


class AllocError(Exception):
    pass


def allocate(db, cfg, device_id, ports: list[str] | None = None) -> dict:
    """Idempotent: a device keeps its allocation. UNIQUE constraints make duplicates impossible."""
    dev = db.device(device_id)
    existing = db.q("SELECT * FROM allocations WHERE device_id=?", device_id)
    if not existing:
        short = ROLE_SHORT.get(dev["role"], dev["role"])
        seen_names = {r["hostname"] for r in db.q("SELECT hostname FROM devices WHERE hostname IS NOT NULL")}
        # other boxes' addresses are taken; the box's own is not. A box already answering on a free mgmt address
        # keeps it: a new one meant re-addressing the very interface the SSH push runs over (real 1941: the session
        # died mid-config after `ip address`, "ReadTimeout ... no shutdown")
        seen_ips = {cfg["server_ip"], cfg.get("mgmt_gateway")} | {
            r["ip"] for r in db.q("SELECT ip FROM devices WHERE ip IS NOT NULL AND id<>?", device_id)}
        free_ips = [ip for ip in ip_range(cfg["mgmt_range"]) if ip not in seen_ips]
        if dev["ip"] in free_ips:
            free_ips.remove(dev["ip"])
            free_ips.insert(0, dev["ip"])
        nn, i = 1, 0
        while True:
            name = cfg["hostname_pattern"].format(site=cfg["site"], role=short, nn=nn)
            if name in seen_names:
                nn += 1
                continue
            if i >= len(free_ips):
                raise AllocError(f"mgmt_range {cfg['mgmt_range']} is exhausted")
            try:
                db.x("INSERT INTO allocations (device_id, hostname, mgmt_ip) VALUES (?,?,?)",
                     device_id, name, free_ips[i])
                break
            except sqlite3.IntegrityError as e:
                if "hostname" in str(e):
                    nn += 1
                elif "mgmt_ip" in str(e):
                    i += 1
                else:  # device_id: allocated in parallel by someone else, use theirs
                    break
    alloc = db.q("SELECT * FROM allocations WHERE device_id=?", device_id)[0]

    if ports is not None:
        db.x("DELETE FROM reserved_ports WHERE device_id=?", device_id)
    have = [r["port"] for r in db.q("SELECT port FROM reserved_ports WHERE device_id=?", device_id)]
    if not have:
        have = [normalize_if(p) for p in (ports or guess_ports(dev, cfg) or [])]
        for p in have:
            db.x("INSERT OR IGNORE INTO reserved_ports VALUES (?,?,?)", device_id, p,
                 "mgmt" if ports else "mgmt-default")
    return {"device_id": device_id, "hostname": alloc["hostname"], "mgmt_ip": alloc["mgmt_ip"],
            "reserved_ports": have}


def guess_ports(dev, cfg) -> list[str] | None:
    """Reserved ports when the user named none. The port the laptop is cabled to, as the box itself named it over
    CDP (vars seen_port), always comes first: that is the PC's way in after pre-config. Then the model's last ports
    (factory boxes only: on an existing switch the last ports are often uplinks)."""
    count = int(cfg["reserved_port_count"]) if dev["role"] != "router_edge" else 1
    seen = (json.loads(dev.get("vars") or "{}")).get("seen_port")
    model = None if dev["path"] == "ssh" else default_ports(dev["pid"], dev["role"], int(cfg["reserved_port_count"]))
    if not seen:
        return model
    return [seen] + [p for p in (model or []) if p != seen][:count - 1]


_PHYSICAL = re.compile(r"^(Fast|Gigabit|TenGigabit|TwoGigabit|FiveGigabit|TwentyFiveGig|FortyGigabit|HundredGig)?"
                       r"Ethernet\d", re.I)


def parse_ifnames(text: str) -> list[str]:
    """`show ip interface brief` -> this box's physical port names, as it spells them."""
    names = [normalize_if(m.group(1)) for m in re.finditer(r"^(\S+?\d+(?:/\d+)*)\s+\S+\s+(?:YES|NO)\s", text, re.M)]
    return [n for n in names if _PHYSICAL.match(n)]


def summarize_ports(names: list[str]) -> str:
    """['FastEthernet0/1', ..., 'FastEthernet0/24', 'GigabitEthernet0/1'] -> 'FastEthernet0/1-24, GigabitEthernet0/1'"""
    groups: dict[str, list[int]] = {}
    for n in names:
        if m := re.match(r"^(.*?)(\d+)$", n):
            groups.setdefault(m.group(1), []).append(int(m.group(2)))
    out = []
    for prefix, nums in groups.items():
        nums = sorted(set(nums))
        out.append(f"{prefix}{nums[0]}" + (f"-{nums[-1]}" if len(nums) > 1 else ""))
    return ", ".join(out)


def drop_default_ports(db, device_id):
    """Forget guessed mgmt ports (keep ones the user chose)."""
    db.x("DELETE FROM reserved_ports WHERE device_id=? AND purpose='mgmt-default'", device_id)


def release(db, device_id):
    db.x("DELETE FROM reserved_ports WHERE device_id=?", device_id)
    db.x("DELETE FROM allocations WHERE device_id=?", device_id)


# ---- interface names ---------------------------------------------------------
_CANON = ["GigabitEthernet", "FastEthernet", "TenGigabitEthernet", "TwoGigabitEthernet",
          "TwentyFiveGigE", "FiveGigabitEthernet", "FortyGigabitEthernet", "HundredGigE",
          "AppGigabitEthernet", "Ethernet", "Vlan", "Port-channel", "Loopback"]
_IF = re.compile(r"^([A-Za-z-]+)\s*((?:\d+/)*)(\d+(?:\.\d+)?)\s*(?:-\s*(\d+))?$")


def _canon(letters: str) -> str:
    low = letters.lower()
    return next((c for c in _CANON if c.lower().startswith(low)), letters)


def normalize_if(name: str) -> str:
    m = _IF.match(name.strip())
    return f"{_canon(m.group(1))}{m.group(2)}{m.group(3)}" if m else name.strip()


def expand_range(spec: str) -> list[str]:
    """'Gi1/0/1 - 3, Gi1/0/47-48' -> full names."""
    out = []
    for part in spec.split(","):
        m = _IF.match(part.strip())
        if not m:
            continue
        lo, hi = m.group(3), m.group(4) or m.group(3)
        if "." in lo:
            out.append(f"{_canon(m.group(1))}{m.group(2)}{lo}")
        else:
            out += [f"{_canon(m.group(1))}{m.group(2)}{n}" for n in range(int(lo), int(hi) + 1)]
    return out


# ---- guard -------------------------------------------------------------------
def guard(lines: list[str], reserved: list[str], mgmt_vlan: int, users: list[str]) -> list[str]:
    """Return why a change would cut PandoraBox off (empty list = safe).

    No sub-mode tracking: *entering* a protected interface at all is the violation,
    so unindented command lists behave the same as indented ones.
    """
    protected = {normalize_if(p) for p in reserved} | {f"Vlan{mgmt_vlan}"}
    users_l = {u.lower() for u in users if u}
    bad = []
    for raw in lines:
        line = raw.strip()
        if "\n" in line or "\r" in line:  # hidden extra commands would slip past the checks below
            bad.append(f"{line!r} contains a line break: send one command per line")
            continue
        m = re.match(r"^(?:no\s+|default\s+)?interface\s+range\s+(.+)$", line, re.I)
        if m:
            hits = protected & set(expand_range(m.group(1)))
            if hits:
                bad.append(f"'{line}' includes the reserved management ports {', '.join(sorted(hits))}")
            continue
        m = re.match(r"^(?:no\s+|default\s+)?interface\s+(.+)$", line, re.I)
        if m:
            if normalize_if(m.group(1)) in protected:
                bad.append(f"'{line}' is a reserved management port")
            continue
        m = re.match(r"^no\s+vlan\s+([\d,\- ]+)$", line, re.I)
        if m and mgmt_vlan in _vlan_list(m.group(1)):
            bad.append(f"'{line}' removes the mgmt VLAN {mgmt_vlan}")
            continue
        m = re.match(r"^no\s+username\s+(\S+)", line, re.I)
        if m and m.group(1).lower() in users_l:
            bad.append(f"'{line}' removes PandoraBox's login user")
            continue
        if re.match(r"^(no\s+snmp-server\b|no\s+ip\s+ssh\b|crypto\s+key\s+zeroize|no\s+ip\s+domain[ -]name"
                    r"|no\s+ip\s+default-gateway)", line, re.I):
            bad.append(f"'{line}' removes PandoraBox's management access")
    return bad


def _vlan_list(spec: str) -> list[int]:
    out = []
    for part in spec.replace(" ", "").split(","):
        if "-" in part:
            a, b = part.split("-")
            out += range(int(a), int(b) + 1)
        elif part.isdigit():
            out.append(int(part))
    return out
