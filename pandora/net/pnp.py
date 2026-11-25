"""Device-pull HTTP: Cisco PnP protocol, IOS-XE ZTP bootstrap, per-serial config download.

PnP flow ported from the Open_PnP_Server idea (oliverl-21), reduced to what we need:
  WORK-REQUEST #1 -> device-info          (identification, always)
  not queued      -> backoff 1 min        (device keeps polling until the user selects it)
  queued          -> config-upgrade (running) -> cli-exec "write memory" -> backoff terminate
"""
import logging
import xml.etree.ElementTree as ET

from fastapi import APIRouter, Request, Response
from jinja2 import Environment, FileSystemLoader

from ..identify import parse_show_version, parse_udi

log = logging.getLogger("pandora.pnp")

XML = "application/xml"


def _wrap(udi, body):
    return f'<?xml version="1.0" encoding="UTF-8"?>\n<pnp xmlns="urn:cisco:pnp" version="1.0" udi="{udi}">{body}</pnp>'


def req_device_info(udi, c):
    return _wrap(udi, f'<request correlator="{c}" xmlns="urn:cisco:pnp:device-info"><deviceInfo type="all"/></request>')


def req_config(udi, c, url):
    return _wrap(udi, f'<request correlator="{c}" xmlns="urn:cisco:pnp:config-upgrade"><config details="all">'
                      f'<copy><source><location>{url}</location></source><applyTo>running</applyTo></copy>'
                      f'</config><noReload/></request>')


def req_cli(udi, c, cmd):
    return _wrap(udi, f'<request correlator="{c}" xmlns="urn:cisco:pnp:cli-exec">'
                      f'<execCLI maxWait="PT120S" xsd="false"><cmd>{cmd}</cmd></execCLI></request>')


def req_backoff(udi, c, minutes=None):
    inner = "<terminate/>" if minutes is None else f"<callbackAfter><minutes>{minutes}</minutes></callbackAfter>"
    return _wrap(udi, f'<request correlator="{c}" xmlns="urn:cisco:pnp:backoff"><backoff>{inner}</backoff></request>')


def bye(udi, c):
    return _wrap(udi, f'<info xmlns="urn:cisco:pnp:work-info" correlator="{c}"><workInfo><bye/></workInfo></info>')


def parse_msg(body: bytes) -> dict:
    # Stdlib expat does not resolve external entities; size cap blunts entity-expansion tricks.
    if len(body) > 512_000:
        raise ValueError("PnP message too large")
    root = ET.fromstring(body)
    out = {"udi": root.get("udi", ""), "correlator": "", "success": None, "texts": {}}
    for e in root.iter():
        tag = e.tag.split("}")[-1]
        if e.get("correlator") and not out["correlator"]:
            out["correlator"] = e.get("correlator")
        if tag == "response":
            out["success"] = e.get("success") == "1"
        if e.text and e.text.strip():
            out["texts"][tag] = e.text.strip()
    return out


def _own(db, dev, request, strict=False) -> bool:
    """Is this caller the device itself? PnP/ZTP have no device authentication (no certificates), so the
    address is the identity: once a box is selected (queued/provisioning) only its own addresses may speak for
    its serial: the one it called from / leased, or the mgmt IP we gave it (after the config is applied the
    PnP agent reports from there). strict: also before selection (reports about a box come from that box)."""
    selected = dev is not None and dev["state"] in ("queued", "provisioning")
    if not dev or (not dev["ip"] and not selected):
        return True  # discovery: a box we have no address for yet
    mine = {dev["ip"]} - {None}
    if dev["state"] == "provisioning":  # config already sent: the box may now speak from the mgmt IP we gave it
        mine |= {r["mgmt_ip"] for r in db.q("SELECT mgmt_ip FROM allocations WHERE device_id=?", dev["id"])}
    if request.client.host in mine:
        return True
    if strict or selected:
        log.warning("device %s (serial %s) is at %s, but %s spoke for it: ignored", dev["id"], dev["serial"],
                    dev["ip"], request.client.host)
        return False
    return True


def router(ctx) -> APIRouter:
    r = APIRouter()
    steps: dict[str, str] = {}  # serial -> last request we sent
    tpl = Environment(loader=FileSystemLoader(ctx.template_dir), keep_trailing_newline=True)

    def xml(s):
        return Response(s, media_type=XML)

    @r.get("/pnp/HELLO")
    def hello():
        return Response(status_code=200)

    @r.post("/pnp/WORK-REQUEST")
    async def work_request(request: Request):
        m = parse_msg(await request.body())
        udi, c = m["udi"], m["correlator"]
        facts = parse_udi(udi)
        known = ctx.db.find(serial=facts["serial"]) if facts.get("serial") else None
        if not _own(ctx.db, known, request):  # someone else claims a selected box's serial: no config, no row change
            return xml(req_backoff(udi, c, 1))
        dev = ctx.db.upsert(**facts, ip=request.client.host, source="pnp", vendor_class="ciscopnp")
        if not dev["path"]:
            dev = ctx.db.upsert(serial=facts["serial"], path="pnp")
        ctx.emit("device", dev)
        serial, step = facts["serial"], steps.get(facts["serial"])
        if step is None:
            steps[serial] = "info"
            return xml(req_device_info(udi, c))
        # failed/done included: the user may queue the device again after fixing something
        if dev["state"] in ("queued", "provisioning") and dev["path"] == "pnp" and step in ("info", "wait", "failed", "done"):
            if ctx.boot_config(dev, "pnp") is None:
                return xml(req_backoff(udi, c, 1))
            steps[serial] = "config"
            ctx.db.set_state(dev["id"], "provisioning", "PnP: config-upgrade sent")
            url = f"http://{ctx.cfg['server_ip']}:{ctx.cfg['http_port']}/cfg/{serial}"
            return xml(req_config(udi, c, url))
        if step == "config_ok":
            steps[serial] = "save"
            return xml(req_cli(udi, c, "write memory"))
        if step == "saved":
            steps[serial] = "done"
            return xml(req_backoff(udi, c))  # terminate the PnP agent
        steps[serial] = "wait" if step in ("info", "wait") else step
        return xml(req_backoff(udi, c, 1))

    @r.post("/pnp/WORK-RESPONSE")
    async def work_response(request: Request):
        m = parse_msg(await request.body())
        facts = parse_udi(m["udi"])
        serial = facts["serial"]
        dev = ctx.db.find(serial=serial)
        if not _own(ctx.db, dev, request, strict=True):
            return xml(bye(m["udi"], m["correlator"]))
        step = steps.get(serial)
        if dev and step == "info":
            t = m["texts"]
            ver = t.get("versionString", "")
            xe = "XE" in ver.upper() or ver[:2] in ("16", "17", "26")  # IOS-XE trains
            ctx.db.upsert(serial=serial, pid=t.get("platformName") or facts["pid"], version=ver,
                          os_type=("iosxe" if xe else "ios") if ver else None)
            steps[serial] = "wait"
        elif dev and step == "config":
            if m["success"]:
                steps[serial] = "config_ok"
            else:
                steps[serial] = "failed"
                ctx.finish(dev["id"], "pnp", False, f"config-upgrade failed: {m['texts']}")
        elif dev and step == "save":
            steps[serial] = "saved"
            ctx.finish(dev["id"], "pnp", bool(m["success"]), "PnP config applied + saved")
        if dev:
            ctx.emit("device", ctx.db.device(dev["id"]))
        return xml(bye(m["udi"], m["correlator"]))

    @r.get("/cfg/{serial}")
    def cfg_file(request: Request, serial: str):
        dev = ctx.db.find(serial=serial)
        text = ctx.boot_config(dev, "pnp", request.client.host) if dev else None
        return Response(text, media_type="text/plain") if text else Response(status_code=404)

    # ---- IOS-XE ZTP --------------------------------------------------------
    @r.get("/ztp/bootstrap.py")
    def ztp_script():
        return Response(tpl.get_template("ztp.py.j2").render(**ctx.cfg), media_type="text/plain")

    @r.get("/ztp/cfg")
    def ztp_cfg(request: Request, serial: str = ""):
        dev = ctx.db.find(serial=serial, ip=request.client.host)
        if dev and serial and not dev["serial"]:
            dev = ctx.db.upsert(ip=request.client.host, serial=serial)
        text = ctx.boot_config(dev, "ztp", request.client.host) if dev else None
        if not text:
            return Response(status_code=204)
        ctx.db.set_state(dev["id"], "provisioning", "ZTP: config downloaded")
        ctx.emit("device", ctx.db.device(dev["id"]))
        return Response(text, media_type="text/plain")

    @r.post("/ztp/done")
    async def ztp_done(request: Request):
        data = await request.json()
        serial = data.get("serial") or ""
        dev = ctx.db.find(serial=serial, ip=request.client.host) if serial else None
        # the report must come from the box, and be about the box it came from: never let it name another row
        if dev and _own(ctx.db, dev, request, strict=True) and dev["serial"] in (None, serial):
            facts = parse_show_version(data.get("version", ""))  # may itself contain serial/hostname
            facts.pop("hostname", None)
            ctx.db.upsert(ip=request.client.host, **{**facts, "serial": serial})
            if dev["state"] == "provisioning":
                ctx.finish(dev["id"], "ztp", bool(data.get("ok")), data.get("error") or "ZTP applied + saved")
            ctx.emit("device", ctx.db.device(dev["id"]))
        return {"ok": True}

    return r
