"""IOS image upgrade for a box whose image has no crypto (no K9, so no SSH; real 2960 / 3560 on the bench).

Telnet in (allowed per box, deliver.allow_telnet), copy a K9 image the user put in `.pandora/tftp/images/` over
TFTP, check its MD5 on the box, boot it, reload. Then turn SSH on and Telnet off, make-before-break: keys and
`ip ssh` first with `transport input telnet ssh`, an SSH login has to work (it pins the host key), and only then
the full config (vty `transport input ssh`) goes in over SSH and Telnet is switched off in PandoraBox.
Every step checks before it acts, so a rerun after a failure carries on where it stopped.
Cisco serves images only behind a Cisco account: the user downloads the file; nothing here fetches one.
"""
import hashlib
import logging
import re
import threading
import time
from pathlib import Path

from . import access, hostkeys

log = logging.getLogger("pandora.upgrade")
FOLDER = Path(".pandora/tftp/images")  # inside the TFTP root: tftpy serves a real file there by its path
_md5: dict[tuple, str] = {}
_running: set[int] = set()


def images() -> list[dict]:
    """Image files the user put in the folder (name, size, MD5; the MD5 is computed once per file version)."""
    FOLDER.mkdir(parents=True, exist_ok=True)
    out = []
    for p in sorted(FOLDER.glob("*.bin")):
        if not re.fullmatch(r"[\w.+-]{1,120}\.bin", p.name):
            log.warning("image %r skipped: its name goes into IOS commands, only letters, digits and ._+- are taken",
                        p.name)
            continue
        st = p.stat()
        key = (p.name, st.st_size, st.st_mtime)
        if key not in _md5:
            h = hashlib.md5()
            with p.open("rb") as f:
                for chunk in iter(lambda: f.read(1 << 20), b""):
                    h.update(chunk)
            _md5[key] = h.hexdigest()
        out.append({"name": p.name, "size": st.st_size, "md5": _md5[key], "k9": "k9" in p.name.lower()})
    return out


def start(ctx, device_id, name) -> str | None:
    """Checks, then runs in the background. Returns why it can't start, or None."""
    img = next((i for i in images() if i["name"] == name), None)
    if not img:
        return f"no image {name!r} in {FOLDER.resolve()}"
    if not img["k9"]:
        return f"{name} has no K9 in its name: it has no crypto either, so SSH would still be impossible"
    if device_id in _running:
        return "an upgrade of this box is already running"
    dev = ctx.db.device(device_id)
    if not dev or not dev["ip"] or not ctx.reachable(dev):
        return "PandoraBox can't log in to this box (SSH, or Telnet if allowed): check its address and Telnet setting"
    _running.add(device_id)
    threading.Thread(target=_run, args=(ctx, device_id, img), daemon=True, name=f"upgrade-{device_id}").start()
    return None


def _step(ctx, device_id, text, ok=None):
    """Progress lives in the device note (Devices list, device page) and in the audit log."""
    ctx.db.update(device_id, note=f"K9 upgrade: {text}")
    ctx.db.set_vars(device_id, {**ctx.db.vars(device_id), "upgrade": {"step": text, "ok": ok, "ts": time.time()}})
    ctx.db.audit("system", "upgrade", {"id": device_id, "step": text, "ok": ok})
    ctx.emit("device", ctx.db.device(device_id))
    log.info("device %s: %s", device_id, text)


def _run(ctx, device_id, img):
    try:
        ok, text = run(ctx, device_id, img)
    except Exception as e:
        log.exception("upgrade of %s", device_id)
        ok, text = False, f"stopped: {type(e).__name__}: {e}"
    finally:
        _running.discard(device_id)
    _step(ctx, device_id, text, ok)


def booted_image(show_version: str) -> str:
    m = re.search(r'System image file is "([^"]+)"', show_version)
    return m.group(1) if m else ""


def flash_free(dir_out: str) -> int | None:
    m = re.search(r"\((\d+) bytes free\)", dir_out)
    return int(m.group(1)) if m else None


def run(ctx, device_id, img) -> tuple[bool, str]:
    name, server = img["name"], ctx.cfg["server_ip"]
    dev = ctx.db.device(device_id)
    with ctx.session(dev) as c:
        c.enable()
        ver = c.send_command("show version")
        if name not in booted_image(ver):
            # 1. the file on flash, checked
            have = c.send_command(f"dir flash:{name}")
            if "No such file" in have or "Error" in have:
                free = flash_free(c.send_command("dir flash:"))
                if free is not None and free < img["size"] + 1_000_000:
                    return False, (f"flash has {free:,} bytes free, {name} needs {img['size']:,}: delete the old "
                                   "image yourself first (`dir flash:`, then `delete /recursive flash:<old>`)")
                _step(ctx, device_id, f"copying {name} ({img['size'] // 1_000_000} MB) over TFTP, minutes on old boxes")
                out = c.send_command(f"copy tftp://{server}/images/{name} flash:{name}",
                                     expect_string=r"Destination filename|\?|#", read_timeout=60)
                if "Destination filename" in out or out.rstrip().endswith("?"):
                    out += c.send_command("\n", expect_string=r"#", read_timeout=3600)
                if re.search(r"%Error|Error opening|Not enough space|No such file", out):
                    return False, f"copy failed: {next(l for l in out.splitlines() if 'rror' in l or 'No ' in l)}"
            _step(ctx, device_id, "checking the MD5 on the box")
            out = c.send_command(f"verify /md5 flash:{name}", read_timeout=1800)
            got = (re.search(r"=\s*([0-9a-f]{32})", out) or [None, ""])[1]
            if got != img["md5"]:
                return False, (f"MD5 on the box {got or '(none)'} is not the file's {img['md5']}: the copy is "
                               f"broken. Delete flash:{name} and start again")
            # 2. boot it
            _step(ctx, device_id, "setting the boot image, saving, reloading")
    if name not in booted_image(ver):
        ctx.ssh_config(dev, ["no boot system", f"boot system flash:{name}"])  # saves too
        with ctx.session(dev) as c:
            c.enable()
            if name not in c.send_command("show boot"):
                return False, "the box didn't take `boot system`: nothing reloaded"
            out = c.send_command_timing("reload", read_timeout=30)
            if "Save?" in out or "[yes/no]" in out:
                out += c.send_command_timing("no", read_timeout=30)
            if "confirm" in out:
                c.write_channel("\n")
        time.sleep(30)
        _step(ctx, device_id, "waiting for the box to come back on the new image (several minutes)")
        if not _wait(lambda: ctx.reachable(ctx.db.device(device_id)), 1200):
            return False, "the box didn't come back within 20 minutes: check its console"
        with ctx.session(ctx.db.device(device_id)) as c:
            c.enable()
            ver = c.send_command("show version")
        if name not in booted_image(ver):
            return False, f"the box came back on {booted_image(ver) or 'another image'}, not {name}"

    # 3. SSH on, Telnet still allowed (make-before-break)
    dev = ctx.db.device(device_id)
    if not access.ssh_open(dev["ip"]):
        _step(ctx, device_id, "turning SSH on (keys + ip ssh), Telnet kept until SSH logs in")
        with ctx.session(dev) as c:
            c.enable()
            c.config_mode()
            c.send_command_timing(f"ip domain name {ctx.cfg['domain']}")
            out = c.send_command_timing("crypto key generate rsa general-keys modulus 2048", read_timeout=120)
            if "replace them" in out:
                c.send_command_timing("no")  # keys already there (rerun): keep them
            last = ctx.db.vars(device_id).get("cap_vty_last", 4)
            for line in ("ip ssh version 2", f"line vty 0 {last}", " transport input telnet ssh", "end"):
                c.send_command_timing(line)
            c.set_base_prompt()
            c.save_config()
        # this run made the keys: the first SSH login below pins them (a box with no crypto never had a pin)
        hostkeys.forget(ctx, device_id, "new image, new RSA key made by the upgrade", resolve=False)
        if not _wait(lambda: access.ssh_open(dev["ip"]), 120):
            return False, "SSH didn't open after the keys were made: Telnet stays on, check `show ip ssh`"
    ctx.ssh_command(dev, "show ip ssh")  # logs in over SSH (Telnet isn't used once SSH answers) and pins the key

    # 4. Telnet off on the box: probe caps again (cap_ssh is now true). A box PandoraBox pre-configured gets its full
    # config (vty `transport input ssh`, compliance stays green). One only added by IP keeps its own login method
    # (maybe a line password, not `login local`): just SSH-only vty lines, which the SSH login above proved safe.
    _step(ctx, device_id, "SSH works: switching the vty lines to SSH only, Telnet off")
    _, caps = ctx.probe(dev)
    ctx.db.set_vars(device_id, {**ctx.db.vars(device_id), **caps})
    if dev["state"] == "provisioned":
        text, problems, _ = ctx.render(device_id)
        if problems:
            return False, f"on {name} with SSH, but the config can't be rendered: {'; '.join(problems)}"
        lines = ctx.lines_with_cleanup(text, caps)
    else:
        lines = [f"line vty 0 {caps.get('cap_vty_last', 4)}", " transport input ssh"]
    out = ctx.ssh_config(dev, lines)
    if bad := [ln for ln in out.splitlines() if ln.startswith("%") and "Invalid" in ln]:
        return False, f"on {name} with SSH, but the merge was refused: {'; '.join(bad)}"
    ctx.allow_telnet(device_id, False, f"upgraded to {name}, SSH works")
    return True, f"on {name}, SSH on, Telnet off"


def _wait(pred, timeout) -> bool:
    end = time.time() + timeout
    while time.time() < end:
        if pred():
            return True
        time.sleep(10)
    return False
