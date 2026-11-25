"""Optional NetBox devicetype-library support (CC0 data).

Drop YAML files from https://github.com/netbox-community/devicetype-library (e.g. the
`device-types/Cisco/` folder) into `devicetypes/` and PandoraBox learns the port names of every
model there, so unknown PIDs no longer need reserved ports typed by hand.
"""
import functools
import logging
from pathlib import Path

log = logging.getLogger("pandora.devicetypes")
DIR = Path("devicetypes")
_NOT_ACCESS = ("virtual", "lag", "bridge")  # interface types that can't be a mgmt access port


@functools.lru_cache(maxsize=1)
def load(folder: str = str(DIR)) -> dict[str, list[str]]:
    """{part_number_or_model (upper-case): [front-panel interface names in file order]}"""
    import yaml
    out = {}
    for f in sorted(Path(folder).rglob("*.y*ml")):
        try:
            d = yaml.safe_load(f.read_text(encoding="utf-8")) or {}
        except Exception as e:
            log.warning("skip %s: %s", f, e)
            continue
        ports = [i["name"] for i in d.get("interfaces") or []
                 if i.get("name") and not i.get("mgmt_only") and str(i.get("type", "")) not in _NOT_ACCESS]
        for key in (d.get("part_number"), d.get("model")):
            if key and ports:
                out[str(key).upper()] = ports
    return out


def last_ports(pid: str | None, count: int, folder: str = str(DIR)) -> list[str] | None:
    """The last `count` access ports of this model (same convention as the built-in table)."""
    if not pid:
        return None
    ports = load(folder).get(pid.upper()) or load(folder).get(pid.upper().split("/")[0])
    return ports[-count:] if ports else None
