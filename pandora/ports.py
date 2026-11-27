"""Front panel, uplinks, out-of-band: what each physical port of a box is, from its port names and model.

Real switches put their fiber / SFP uplinks apart from the copper front panel, and the UI shows them apart
(mixing 4 SFP cages into 48 copper ports reads wrong). The provisioning backbone also must never turn an
uplink into a provisioning port. One answer for both, from names only (no MIB tells fiber from copper on IOS):

- the biggest group of same-type ports on one module is the front panel (Gi1/0/1-48, Fa0/1-24, Gi0/1-52);
- another module of it is an uplink module (Gi1/1/1-4, Te1/1/1-8 on a C9300 / C2960X);
- another, faster type is an uplink (Gi0/1-2 next to Fa0/1-24 on a 2960, Te1/0/1-2 on a 2960X);
- ports past the model's count are SFP (WS-C3560G-48TS: Gi0/1-48 copper, Gi0/49-52 SFP);
- a port with fewer numbers than the front panel is the out-of-band management port (Gi0/0 on a C9300);
- groups of the same size (IOL: Et0/0-3 and Et1/0-3, one per slot) are all front panel.
"""
import re

_TYPES = {"fa": 1, "et": 1, "gi": 2, "tw": 3, "fi": 3, "te": 4, "fo": 5, "hu": 6}  # rough speed rank
_NAME = re.compile(r"^([A-Za-z-]+?)(\d+(?:/\d+)*)$")


def parse(name: str):
    """'GigabitEthernet1/0/24' or 'Gi1/0/24' -> ('gi', (1, 0, 24)); None for anything not a physical port."""
    m = _NAME.fullmatch(str(name).strip())
    if not m or m.group(1).lower().startswith("ap"):  # AppGigabitEthernet: the app-hosting port, not a jack
        return None
    kind = m.group(1)[:2].lower()
    if kind not in _TYPES:
        return None
    nums = tuple(int(x) for x in m.group(2).split("/"))
    return (kind, nums) if len(nums) >= 2 else None


# A port name as it may go into a config line (`interface <name>`): letters, then slot/port numbers, maybe a
# subinterface. Names come from devices (CDP advertisements, ifName): anything else, a line break above all, would
# add lines of its own to the config PandoraBox pushes.
SAFE_NAME = re.compile(r"[A-Za-z][A-Za-z-]{0,40}\d{1,4}(?:/\d{1,4}){0,3}(?:\.\d{1,5})?")


def safe_name(name) -> bool:
    return bool(SAFE_NAME.fullmatch(str(name or "")))


def model_count(pid: str | None) -> int | None:
    """WS-C3560G-48TS-E -> 48, C9300-24P -> 24, WS-C2960X-24PD-L -> 24 (copper ports the model is named for)."""
    m = re.search(r"-(\d{1,2})[A-Z]", str(pid or ""))
    return int(m.group(1)) if m else None


def classify(names, pid: str | None = None) -> dict[str, str]:
    """{name: 'access' | 'uplink' | 'oob'} for the physical ports among `names` (others are left out)."""
    parsed = {n: p for n in names if (p := parse(n))}
    if not parsed:
        return {}
    groups: dict[tuple, list[str]] = {}
    for n, (kind, nums) in parsed.items():
        groups.setdefault((kind, nums[:-1]), []).append(n)
    sizes = {len(v) for v in groups.values()}
    main_key = max(groups, key=lambda k: (len(groups[k]), -_TYPES[k[0]], [-x for x in k[1]]))
    main_kind, main_mod = main_key
    out = {}
    for key, members in groups.items():
        kind, mod = key
        if len(mod) < len(main_mod):
            label = "oob"
        elif key == main_key or (len(sizes) == 1 and kind == main_kind):
            label = "access"  # the front panel, or one of several equal slots (IOL)
        else:
            label = "uplink"
        for n in members:
            out[n] = label
    count = model_count(pid)
    if count:  # one numbering for copper and SFP: ports past the model's count are the SFP ones
        for n in groups[main_key]:
            if parsed[n][1][-1] > count:
                out[n] = "uplink"
    return out


def sort_key(name: str):
    """Natural order: physical ports by type then numbers (Gi1/0/2 before Gi1/0/10), everything else after."""
    p = parse(name)
    return (0, _TYPES[p[0]], p[1], name) if p else (1, 0, (), str(name))
