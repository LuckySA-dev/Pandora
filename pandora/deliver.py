"""The workflow: inventory -> preview (allocate + render + conflicts) -> queue -> push via the right path."""
import logging
import re
import threading
import time
from pathlib import Path

from jinja2 import Environment, FileSystemLoader

from . import access, alloc, hostkeys, platforms, snmp
from .identify import guess_path, parse_show_version
from .net.dhcp import ip_opt, opt43_pnp

log = logging.getLogger("pandora.deliver")
BOOT_PATHS = ("pnp", "ztp", "autoinstall")


class Ctx:
    """Everything the routes, servers and agent share."""

    def __init__(self, db, cfg, emit=None):
        self.db, self.cfg = db, cfg
        self.emit = emit or (lambda kind, data: None)
        self.template_dir = str(Path(__file__).parent / "templates")
        self.env = Environment(loader=FileSystemLoader(self.template_dir), trim_blocks=True, lstrip_blocks=True)
        self.sniffed: list[dict] = []  # CDP/LLDP neighbors heard on the laptop NIC

    # ---- render ----------------------------------------------------------
    def render(self, device_id, factory=False, autosave=False) -> tuple[str, list[str], dict]:
        dev = self.db.device(device_id)
        problems = []
        try:
            a = alloc.allocate(self.db, self.cfg, device_id)
        except alloc.AllocError as e:
            return "", [str(e)], {}
        if not a["reserved_ports"]:
            problems.append(f"no default mgmt ports for PID '{dev['pid'] or '?'}': enter reserved ports")
        for key in ("admin_password", "snmp_auth", "snmp_priv"):
            if len(self.cfg.get(key) or "") < 8:
                problems.append(f"env PANDORA_{key.upper()} missing or < 8 chars")
        dev_vars = self.db.vars(device_id)
        level = snmp.level(self.cfg, dev_vars)
        if level is None:
            problems.append("this IOS image has no SNMPv3 priv (AES): set snmp_allow_auth_nopriv = true "
                            "to accept authNoPriv for it")
        # cap_* = what the image accepts, asked over SSH/console before a push. Boot files (PnP/AutoInstall/ZTP)
        # can't ask, and PnP rolls back the whole file on one rejected line (seen: IOL router, "traps config"):
        # so only lines every IOS takes. vty 0-4 always exists; lines left alone keep IOS's `login` (refused).
        v = {"cap_vty_last": 4, "cap_traps_config": False, **self.cfg, **dev_vars, "snmp_level": level or "priv",
             "snmp_user": snmp.user(self.cfg, level or "priv"),
             "role": dev["role"], "hostname": a["hostname"],
             "mgmt_ip": a["mgmt_ip"], "reserved_ports": a["reserved_ports"], "gateway": self.cfg["mgmt_gateway"],
             "factory": factory, "autosave": autosave}
        role_text = self.env.get_template(f"{dev['role']}.j2").render(**v)
        problems += alloc.guard(role_text.splitlines(), a["reserved_ports"], self.cfg["mgmt_vlan"],
                                [self.cfg["admin_user"]])
        base = self.env.get_template("base.j2").render(**v) if a["reserved_ports"] else ""
        return base + role_text, problems, a

    def preview(self, ids, role=None, ports: dict | None = None, role_vars: dict | None = None) -> list[dict]:
        rows = []
        for i in ids:
            dev = self.db.device(i)
            if role and role != dev["role"]:
                self.db.x("UPDATE devices SET role=? WHERE id=?", role, i)
                # The hostname carries the role ({site}-{role}-{nn}). A name reserved by an earlier Review with
                # another role was never sent to the box until it is claimed: take it back and name it again.
                if dev["state"] in ("discovered", "identified", "needs_credentials", "failed"):
                    self.db.x("DELETE FROM allocations WHERE device_id=?", i)
            if role_vars is not None:  # role vars come from the wizard; keep the probed image caps
                self.db.set_vars(i, {**{k: v for k, v in self.db.vars(i).items() if k.startswith("cap_")},
                                     **role_vars})
            if ports and ports.get(str(i)):
                alloc.allocate(self.db, self.cfg, i, [p.strip() for p in ports[str(i)].split(",") if p.strip()])
            dev = self.db.device(i)
            text, problems, a = self.render(i)
            rows.append({"id": i, "path": dev["path"] or guess_path(dev), "serial": dev["serial"], "pid": dev["pid"],
                         **a, "config": text, "problems": problems})
        return rows

    # ---- queue -----------------------------------------------------------
    def queue(self, ids) -> list[dict]:
        out = []
        for i in ids:
            dev = self.db.device(i)
            _, problems, _ = self.render(i)
            if (dev["path"] or guess_path(dev)) == "console" and not dev["pid"]:
                # A factory box at the setup dialog can't tell its PID until the push logs in;
                # _push_console reads it and renders again, so default ports are found then.
                problems = [p for p in problems if "mgmt ports" not in p]
            if problems:
                out.append({"id": i, "queued": False, "problems": problems})
                continue
            path = dev["path"] or guess_path(dev)
            dev = self.db.upsert(**{k: dev[k] for k in ("serial", "mac", "console_port", "ip") if dev[k]}, path=path)
            if path != "console" and access.needs_credentials(dev):
                self.db.x("UPDATE devices SET path='ssh' WHERE id=?", i)  # already configured: merge over SSH
                alloc.drop_default_ports(self.db, i)
                self.db.set_state(i, "needs_credentials",
                                  "SSH is open: pick reserved mgmt ports in Preview (not uplinks), then enter credentials")
            else:
                self.db.set_state(i, "queued", f"waiting for device via {path}")
                if path in ("console", "ssh"):
                    self.push_async(i)
            self.emit("device", self.db.device(i))
            out.append({"id": i, "queued": True, "state": self.db.device(i)["state"]})
        return out

    def set_credentials(self, device_id, creds: dict):
        access.CREDS[device_id] = creds
        dev = self.db.device(device_id)
        if dev["path"] != "console":
            self.db.x("UPDATE devices SET path='ssh' WHERE id=?", device_id)  # merge over SSH
            alloc.drop_default_ports(self.db, device_id)  # guessed ports may be this switch's uplinks
        self.db.set_state(device_id, "queued", "credentials received")
        self.push_async(device_id)

    def add_by_ssh(self, ip, creds) -> dict:
        """Add an already-configured device by address + login (no SNMP needed): log in, read what it is."""

        from .identify import parse_inventory
        params = {"device_type": "cisco_ios", "host": ip, "username": creds["username"], "password": creds["password"],
                  "secret": creds.get("secret") or creds["password"], "fast_cli": False, "conn_timeout": 10}
        known = self.db.find(ip=ip)
        pin = hostkeys.Pin(self, known and known["id"])
        with connect(params, pin) as conn:
            conn.enable()
            facts = parse_show_version(conn.send_command("show version"))
            facts.update({k: v for k, v in parse_inventory(conn.send_command("show inventory")).items() if v})
        hostname = facts.pop("hostname", None)
        # Known by serial at a new address: its identity is known only now. Check the pin before anything about
        # that device changes (address, path, credentials): a box claiming its serial with another key gets nothing.
        same = self.db.find(serial=facts.get("serial"), ip=ip)
        if same and pin.seen and (want := hostkeys.pinned(self.db, same["id"])) and want != pin.seen:
            raise hostkeys.HostKeyChanged(hostkeys.mismatch(self, same["id"], ip, " (added by IP)"))
        dev = self.db.upsert(ip=ip, source="ssh", path="ssh", hostname=hostname, **facts)
        if dev["path"] != "ssh":
            self.db.x("UPDATE devices SET path='ssh' WHERE id=?", dev["id"])
        access.CREDS[dev["id"]] = creds
        if pin.seen:
            hostkeys.remember(self.db, dev["id"], pin.seen)
        self.db.audit("user", "added_by_ssh", {"id": dev["id"], "ip": ip})
        dev = self.db.device(dev["id"])
        self.emit("device", dev)
        return dev

    def creds_for(self, dev) -> dict:
        return access.CREDS.get(dev["id"]) or {"username": self.cfg["admin_user"],
                                               "password": self.cfg["admin_password"],
                                               "secret": self.cfg["admin_password"]}

    # ---- device-pull paths (DHCP / PnP / ZTP / TFTP) -----------------------
    def boot_config(self, dev, method, client_ip=None) -> str | None:
        if not dev or dev["state"] not in ("queued", "provisioning") or (dev["path"] or method) != method:
            return None  # not selected, or selected for another path (a console box gets no ZTP file)
        # The file holds the admin password and SNMP keys: only the box itself may fetch it, from the address
        # PandoraBox gave it (DHCP lease) or saw it call from (PnP). A neighbour that knows the serial gets nothing.
        if client_ip and dev["ip"] != client_ip:
            log.warning("boot config for device %s asked by %s, not its address %s: refused", dev["id"], client_ip,
                        dev["ip"])
            return None
        text, problems, _ = self.render(dev["id"], factory=True, autosave=method == "autoinstall")
        if problems:
            return None
        if client_ip:  # actually handed to the box at its own address (not PnP's "would there be a file?" check)
            hostkeys.forget(self, dev["id"], f"{method}: factory config (new RSA key) sent", resolve=False)
        return text

    def dhcp_decide(self, mac, info, ip):
        facts = {"mac": mac, "ip": ip, "vendor_class": info["vendor_class"] or None}
        # Leases are in memory: after a restart this IP may still sit on another device's row.
        # Take it off that row so upsert() can't merge two different devices by IP.
        self.db.x("UPDATE devices SET ip=NULL WHERE ip=? AND (mac IS NULL OR mac<>?)", ip, mac)
        if not self.db.find(mac=mac):
            facts["source"] = "dhcp"
        dev = self.db.upsert(**facts)
        if not dev["path"]:
            dev = self.db.upsert(mac=mac, path=guess_path(dev))
        self.emit("device", dev)
        s, queued, p = self.cfg["server_ip"], dev["state"] in ("queued", "provisioning"), dev["path"]
        if queued and p == "ztp":
            return {67: f"http://{s}:{self.cfg['http_port']}/ztp/bootstrap.py".encode()}
        if queued and p == "autoinstall":
            return {150: ip_opt(s), 66: s.encode(), 67: f"pandora-{mac.replace(':', '')}.cfg".encode()}
        if (queued and p == "pnp") or "pnp" in (info["vendor_class"] or "").lower():
            return {43: opt43_pnp(s, self.cfg["http_port"])}  # PnP: identify always, configure only if queued
        return None  # seen, not touched

    def tftp_lookup(self, filename, client_ip):
        dev = None
        if filename.startswith("pandora-"):
            raw = filename[8:].split(".")[0]
            dev = self.db.find(mac=":".join(raw[i:i + 2] for i in range(0, 12, 2)))
        dev = dev or self.db.find(ip=client_ip)
        text = self.boot_config(dev, "autoinstall", client_ip)
        if text and dev["state"] == "queued":
            self.db.set_state(dev["id"], "provisioning", "AutoInstall: config downloaded")
            self.emit("device", self.db.device(dev["id"]))
            threading.Thread(target=self._verify_ssh, args=(dev["id"], "autoinstall"), daemon=True).start()
        return text

    def _verify_ssh(self, device_id, method, wait=300):
        """AutoInstall reports nothing back: success = our SSH login works on the new mgmt IP."""
        a = alloc.allocate(self.db, self.cfg, device_id)
        end = time.time() + wait
        while time.time() < end:
            if access.ssh_open(a["mgmt_ip"]):
                try:
                    out = self.ssh_command(self.db.device(device_id) | {"ip": a["mgmt_ip"]}, "show version")
                    self.db.upsert(**{k: v for k, v in parse_show_version(out).items() if k != "hostname"},
                                   mac=self.db.device(device_id)["mac"])
                    return self.finish(device_id, method, True, "SSH login on mgmt IP works")
                except Exception as e:
                    log.info("verify %s: %s", device_id, e)
            time.sleep(10)
        self.finish(device_id, method, False, f"no SSH on {a['mgmt_ip']} after {wait}s")

    def finish(self, device_id, method, ok, detail):
        text, _, a = self.render(device_id)
        self.db.save_config(device_id, method, text, detail)
        if ok:
            old_ip = self.db.device(device_id)["ip"]
            # A merged (SSH) device was reached on its existing address. Only switch to the new mgmt IP once
            # PandoraBox can actually reach it; otherwise every later backup/poll/terminal would fail.
            if method == "ssh" and old_ip and old_ip != a["mgmt_ip"] and not access.ssh_open(a["mgmt_ip"]):
                detail = f"{detail}; still using {old_ip} (new mgmt IP {a['mgmt_ip']} not reachable from here yet)"
                self.db.x("UPDATE devices SET hostname=? WHERE id=?", a["hostname"], device_id)
            else:
                self.db.x("UPDATE devices SET ip=?, hostname=? WHERE id=?", a["mgmt_ip"], a["hostname"], device_id)
        self.db.set_state(device_id, "provisioned" if ok else "failed", detail)
        self.emit("device", self.db.device(device_id))
        if ok and method in ("pnp", "ztp", "autoinstall"):
            threading.Thread(target=self.complete, args=(device_id,), daemon=True).start()

    def complete(self, device_id) -> str:
        """Boot files carry only lines every IOS takes (PnP rolls back the whole file on one rejected line). Now
        that SSH works, ask this image what it accepts and merge the full config: vty 0-15, `traps config`, ...
        Re-applying the lines the box already has changes nothing."""
        dev = self.db.device(device_id)
        try:
            _, caps = self.probe(dev)
            self.db.set_vars(device_id, {**self.db.vars(device_id), **caps})
            text, problems, _ = self.render(device_id)
            if problems:
                raise RuntimeError("; ".join(problems))
            out = self.ssh_config(dev, [l for l in text.splitlines() if l.strip() and not l.lstrip().startswith("!")])
            errors = [l for l in out.splitlines() if l.startswith("%") and "Invalid" in l]
            result = "; ".join(errors) or "capability-dependent lines added over SSH"
        except Exception as e:
            log.info("completing %s over SSH failed: %s", device_id, e)
            result = f"not completed over SSH: {type(e).__name__}: {e}"
        self.db.save_config(device_id, "ssh-complete", text if "text" in locals() else "", result)
        self.db.audit("system", "complete", {"id": device_id, "result": result})
        return result

    # ---- push paths (console / SSH) --------------------------------------------
    def push_async(self, device_id):
        threading.Thread(target=self.push, args=(device_id,), daemon=True, name=f"push-{device_id}").start()

    def push(self, device_id):
        dev = self.db.device(device_id)
        self.db.set_state(device_id, "provisioning", f"pushing via {dev['path']}")
        self.emit("device", self.db.device(device_id))
        try:
            if dev["path"] == "console":
                self._push_console(dev)
            else:
                self._push_ssh(dev)
        except NeedCredentials:
            self.db.set_state(device_id, "needs_credentials", "console asks for a login")
            self.emit("device", self.db.device(device_id))
        except Exception as e:
            log.exception("push %s failed", device_id)
            self.finish(device_id, dev["path"], False, f"{type(e).__name__}: {e}")

    def _push_console(self, dev):
        from . import console
        creds = access.CREDS.get(dev["id"])
        with console.session(dev["console_port"]) as con:
            if not con.login(creds):
                raise NeedCredentials()
            self.db.upsert(console_port=dev["console_port"], **con.facts())
            # Factory = no startup-config. The dialog/AutoInstall banner may have scrolled by long before we came.
            con.factory = con.factory or "not present" in con.send("show startup-config", 2)
            if con.factory:
                hostkeys.forget(self, dev["id"], "console: factory box, pre-config generates a new RSA key",
                                resolve=False)
            self.db.set_vars(dev["id"], {**self.db.vars(dev["id"]), **parse_caps(*map(con.ask, CAP_QUESTIONS))})
            # Factory = the console showed the setup/autoinstall dialog. A configured box that merely
            # has no login must keep its Vlan1 and keys.
            text, problems, _ = self.render(dev["id"], factory=con.factory)
            if problems:
                raise RuntimeError("; ".join(problems))
            errors = con.configure(text)
        self.finish(dev["id"], "console", not errors, "; ".join(errors) or "pasted + saved")

    def netmiko_params(self, dev, ip=None):
        c = self.creds_for(dev)
        return {"device_type": platforms.get(dev.get("os_type"))["netmiko"],
                "host": ip or dev["ip"], "username": c["username"], "password": c["password"],
                "secret": c.get("secret") or c["password"], "fast_cli": False}

    def session(self, dev):
        return connect(self.netmiko_params(dev), hostkeys.Pin(self, dev["id"]))

    def ssh_command(self, dev, cmd, use_textfsm=False):
        with self.session(dev) as conn:
            conn.enable()
            return conn.send_command(cmd, use_textfsm=use_textfsm)

    def ssh_config(self, dev, lines) -> str:
        with self.session(dev) as conn:
            conn.enable()
            # A "hostname" line changes the prompt mid-session, and netmiko would wait for the old one
            # (ReadTimeout). Leave config mode ourselves, re-learn the prompt, then save.
            out = conn.send_config_set(lines, read_timeout=180, exit_config_mode=False)
            out += conn.send_command_timing("end", strip_prompt=False, strip_command=False)
            conn.set_base_prompt()
            out += conn.save_config()
            return out

    def probe(self, dev) -> tuple[str, dict]:
        """`show version` plus what this image accepts, asked with IOS's own `?` help (nothing is configured)."""
        with self.session(dev) as conn:
            conn.enable()
            ver = conn.send_command("show version")

            def ask(q):
                conn.config_mode()
                out = conn.send_command_timing(f"{q} ?", strip_prompt=False, strip_command=False)
                # IOS types the half line back after "?": Ctrl-C drops it (Ctrl-U did not, and Enter would run it)
                conn.send_command_timing("\x03", strip_prompt=False)
                conn.exit_config_mode()
                return out
            caps = parse_caps(*map(ask, CAP_QUESTIONS))
        return ver, caps

    def _push_ssh(self, dev):
        if not access.ssh_open(dev["ip"]):
            raise RuntimeError(f"SSH not reachable on {dev['ip']}")
        out, caps = self.probe(dev)
        self.db.upsert(ip=dev["ip"], **{k: v for k, v in parse_show_version(out).items() if k != "hostname"})
        self.db.set_vars(dev["id"], {**self.db.vars(dev["id"]), **caps})
        text, problems, _ = self.render(dev["id"])
        if problems:
            raise RuntimeError("; ".join(problems))
        lines = [l for l in text.splitlines() if l.strip() and not l.lstrip().startswith("!")]
        out = self.ssh_config(self.db.device(dev["id"]), lines)
        errors = [l for l in out.splitlines() if l.startswith("%") and "Invalid" in l]
        self.finish(dev["id"], "ssh", not errors, "; ".join(errors) or "merged + saved")


def connect(params, pin=None, tries=2):
    """netmiko ConnectHandler with one retry on a connect timeout. A SYN lost while spanning tree settles (seen on
    real IOL right after the management design turned ports into trunks) must not fail a backup, push or
    compliance check. A wrong password or a changed host key is not retried. `pin` (hostkeys.Pin) checks the
    device's SSH host key before the password is sent."""
    from netmiko import ConnectHandler
    from netmiko.exceptions import NetmikoTimeoutException
    for k in range(tries):
        try:
            if pin is None:
                return ConnectHandler(**params)
            conn = ConnectHandler(**params, auto_connect=False)
            conn.key_policy = pin
            conn._open()
            return conn
        except NetmikoTimeoutException:
            if k == tries - 1:
                raise
            log.info("SSH to %s timed out, trying once more", params.get("host"))
            time.sleep(5)


class NeedCredentials(Exception):
    pass


CAP_QUESTIONS = ("line vty 0", "snmp-server group PANDORA v3", "snmp-server enable traps", "ip routing")  # + " ?"


def parse_caps(vty_help: str, group_help: str, traps_help: str, routing_help: str = "") -> dict:
    """IOS `?` help -> template caps. Seen on containerlab IOL 17.18: vty only 0-4, the L2 image offers no
    'priv' (no AES), the router image no 'traps config'. Help we can't read keeps the default."""
    caps = {}
    if m := re.search(r"<1-(\d+)>", vty_help):
        caps["cap_vty_last"] = min(int(m.group(1)), 15)  # ISR offers <1-1869>: lines are created, cap at 0-15
    if re.search(r"^\s+auth\s", group_help, re.M):
        caps["cap_snmp_priv"] = bool(re.search(r"^\s+priv\s", group_help, re.M))
    if re.search(r"^\s+\S+\s+Enable ", traps_help, re.M):
        caps["cap_traps_config"] = bool(re.search(r"^\s+config\s", traps_help, re.M))
    # an L3-capable image offers `ip routing <cr>`; an L2-only one (e.g. 2960 LAN Base) doesn't know the command.
    # Only a management backbone needs it (mgmt.plan).
    # Strict: a help line that is exactly `<cr>` (IOS prints "  <cr>  <cr>") = yes; the two "no such command"
    # answers = no; anything else (Ambiguous, Incomplete, garbled) stays unknown, which blocks a backbone.
    if re.search(r"^\s*<cr>(\s+<cr>)?\s*$", routing_help, re.M):
        caps["cap_ip_routing"] = True
    elif re.search(r"^\s*% (Invalid input detected|Unrecognized command)", routing_help, re.M):
        caps["cap_ip_routing"] = False
    return caps
