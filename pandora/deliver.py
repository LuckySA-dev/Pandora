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
        real = self.db.vars(device_id).get("cap_ifnames") or []  # what the box said it has (SSH/console probe)
        has = f" (this box has {alloc.summarize_ports(real)})" if real else ""
        if self.db.vars(device_id).get("staged"):
            pass  # two-stage AutoInstall: no port is named until stage 2 has asked the box
        elif not a["reserved_ports"]:
            problems.append(f"no default mgmt ports for PID '{dev['pid'] or '?'}': enter reserved ports{has}")
        elif real and (bad := [p for p in a["reserved_ports"] if alloc.normalize_if(p) not in real]):
            problems.append(f"{', '.join(bad)}: no such port on this box{has}")
        kind = alloc.model_kind(dev["pid"])
        if dev["role"] == "router_edge" and kind == "switch":
            # the router template puts `ip address` on a physical port: a switch port refuses it (real 2960X)
            problems.append(f"{dev['pid']} is a switch: pick the role switch_access, not router_edge")
        elif dev["role"] == "switch_access" and kind == "router":
            # the switch template needs VLANs, SVIs and switchports: a router has none of them
            problems.append(f"{dev['pid']} is a router: pick the role router_edge (Edge router), not switch_access")
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
             # vty stay on Telnet only for a box proven to have no crypto AND allowed Telnet by the user
             "no_ssh": dev_vars.get("cap_ssh") is False and dev_vars.get("telnet") is True,
             "role": dev["role"], "hostname": a["hostname"],
             "mgmt_ip": a["mgmt_ip"], "reserved_ports": a["reserved_ports"], "gateway": self.cfg["mgmt_gateway"],
             "factory": factory, "autosave": autosave}
        role_text = self.env.get_template(f"{dev['role']}.j2").render(**v)
        problems += alloc.guard(role_text.splitlines(), a["reserved_ports"], self.cfg["mgmt_vlan"],
                                [self.cfg["admin_user"]])
        base = self.env.get_template("base.j2").render(**v) if a["reserved_ports"] or v.get("staged") else ""
        return base + role_text, problems, a

    def preview(self, ids, role=None, ports: dict | None = None, role_vars: dict | None = None) -> list[dict]:
        rows = []
        for i in ids:
            self.set_role(i, role)
            if role_vars is not None:  # role vars come from the wizard; keep what the box told us (caps, CDP)
                self.db.set_vars(i, {**{k: v for k, v in self.db.vars(i).items() if k.startswith(("cap_", "seen_"))},
                                     **role_vars})
            if ports and ports.get(str(i)):
                alloc.allocate(self.db, self.cfg, i, [p.strip() for p in ports[str(i)].split(",") if p.strip()])
            self._mark_staged(i)
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
            self._mark_staged(i)
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
                self.db.set_state(i, "queued", f"waiting for device via {path}" + self._boot_hint(dev, path))
                if path in ("console", "ssh"):
                    self.push_async(i)
            self.emit("device", self.db.device(i))
            out.append({"id": i, "queued": True, "state": self.db.device(i)["state"]})
        return out

    def _mark_staged(self, device_id) -> bool:
        """AutoInstall of a switch whose model nobody told us (no PnP, no CDP): its port names are unknown, so it is
        done in two stages (stage 1 names no port, see stage_two). Typed ports are kept as a preference."""
        dev = self.db.device(device_id)
        staged = (dev["path"] or guess_path(dev)) == "autoinstall" and dev["role"] != "router_edge" and not dev["pid"]
        if bool(self.db.vars(device_id).get("staged")) != staged:
            self.db.set_vars(device_id, {**self.db.vars(device_id), "staged": staged})
        return staged

    def _boot_hint(self, dev, path) -> str:
        """PnP/ZTP/AutoInstall wait for the box to call in, which it does only when it boots with no startup-config.
        Say so, and say when PandoraBox itself already saved one on it (it will then wait forever)."""
        if path not in BOOT_PATHS:
            return ""
        saved = self.db.q("SELECT ts FROM configs WHERE device_id=? AND method IN ('console', 'ssh') "
                          "ORDER BY ts DESC LIMIT 1", dev["id"])
        if saved:
            when = time.strftime("%Y-%m-%d %H:%M", time.localtime(saved[0]["ts"]))
            return (f": config was already pushed to it over console/SSH ({when}), so it may boot configured and never "
                    f"call in. Wipe it (write erase, reload) or use Console delivery")
        return ": it calls in only after booting with no startup-config, cabled to this laptop's segment"

    def set_credentials(self, device_id, creds: dict):
        access.CREDS[device_id] = creds
        dev = self.db.device(device_id)
        if dev["path"] != "console":
            self.db.x("UPDATE devices SET path='ssh' WHERE id=?", device_id)  # merge over SSH
            alloc.drop_default_ports(self.db, device_id)  # guessed ports may be this switch's uplinks
        self.db.set_state(device_id, "queued", "credentials received")
        self.push_async(device_id)

    def add_by_ssh(self, ip, creds, telnet=False) -> dict:
        """Add an already-configured device by address + login (no SNMP needed): log in, read what it is.
        telnet: the user says this box has no SSH (IOS without crypto); the login then goes in cleartext."""

        from .identify import parse_inventory
        params = {"device_type": "cisco_ios_telnet" if telnet else "cisco_ios", "host": ip,
                  "username": creds["username"], "password": creds["password"],
                  "secret": creds.get("secret") or creds["password"], "fast_cli": False, "conn_timeout": 10}
        known = self.db.find(ip=ip)
        pin = None if telnet else hostkeys.Pin(self, known and known["id"])
        with connect(params, pin) as conn:
            conn.enable()
            ver = conn.send_command("show version")
            facts = parse_show_version(ver)
            facts.update({k: v for k, v in parse_inventory(conn.send_command("show inventory")).items() if v})
            if telnet and not no_crypto(conn):
                raise RuntimeError("its image has crypto (K9, or it knows `ip ssh`): it can run SSH, so Telnet is "
                                   "refused. Turn SSH on there and add it without the Telnet tick")
        hostname = facts.pop("hostname", None)
        # Known by serial at a new address: its identity is known only now. Check the pin before anything about
        # that device changes (address, path, credentials): a box claiming its serial with another key gets nothing.
        same = self.db.find(serial=facts.get("serial"), ip=ip)
        if same and pin and pin.seen and (want := hostkeys.pinned(self.db, same["id"])) and want != pin.seen:
            raise hostkeys.HostKeyChanged(hostkeys.mismatch(self, same["id"], ip, " (added by IP)"))
        # Telnet proves nothing about who answers: it may only add a new box or the same one at its own address
        if telnet and same and (hostkeys.pinned(self.db, same["id"]) or (same["ip"] and same["ip"] != ip)):
            raise RuntimeError(f"serial {facts.get('serial')} is already {same['hostname'] or '#' + str(same['id'])} "
                               f"at {same['ip']}: a Telnet login can't prove it is the same box. Remove that device "
                               "first if it was replaced")
        dev = self.db.upsert(ip=ip, source="ssh", path="ssh", hostname=hostname, **facts)
        if dev["path"] != "ssh":
            self.db.x("UPDATE devices SET path='ssh' WHERE id=?", dev["id"])
        access.CREDS[dev["id"]] = creds
        if pin and pin.seen:
            hostkeys.remember(self.db, dev["id"], pin.seen)
        if telnet:  # proven above: no crypto on this image
            self.db.set_vars(dev["id"], {**self.db.vars(dev["id"]), "cap_ssh": False})
            self.allow_telnet(dev["id"], True, "added by IP over Telnet; no crypto confirmed")
        self.db.audit("user", "added_by_ssh", {"id": dev["id"], "ip": ip})
        self.check_confreg(dev["id"], ver)
        dev = self.db.device(dev["id"])
        self.emit("device", dev)
        return dev

    def enable_telnet(self, device_id) -> str | None:
        """The user's opt-in, proven on the box: a Telnet login that finds an image without crypto. Returns why not."""
        dev = self.db.device(device_id)
        if hostkeys.pinned(self.db, device_id):
            return ("this box has shown an SSH key before, so PandoraBox won't fall back to Telnet for it. If SSH "
                    "stopped answering, check the box (and its key) instead")
        if self.db.vars(device_id).get("cap_ssh") is True:  # learned over SSH/console: authoritative, never undone
            return "this box's image was seen with SSH before: Telnet is refused"
        if not dev["ip"] or not access.ssh_open(dev["ip"], 23):
            return "Telnet doesn't answer on this box"
        if access.ssh_open(dev["ip"]):
            return "SSH answers on this box: no reason to send the login in clear text"
        try:
            with connect(self.netmiko_params(dev, telnet=True)) as conn:
                conn.enable()
                serial = parse_show_version(conn.send_command("show version")).get("serial")
                proven = no_crypto(conn)
        except Exception as e:
            return f"Telnet login failed: {type(e).__name__}: {e}"
        if dev["serial"] and serial != dev["serial"]:  # Telnet proves nothing: at least the box must say it is this one
            return f"the box answering on {dev['ip']} says serial {serial or '(none)'}, not {dev['serial']}: refused"
        if not proven:
            return "its image has crypto (K9, or it knows `ip ssh`): it can run SSH, so Telnet is refused"
        self.db.set_vars(device_id, {**self.db.vars(device_id), "cap_ssh": False})
        self.allow_telnet(device_id, True, "user; no crypto confirmed over Telnet")
        return None

    def allow_telnet(self, device_id, allow: bool, why: str):
        """Per-box opt-in, off by default: Telnet sends the login in cleartext, so it is for boxes on the isolated
        provisioning segment whose image can't run SSH, until they get a K9 image (upgrade.py)."""
        v = self.db.vars(device_id)
        v.pop("telnet", None)
        self.db.set_vars(device_id, {**v, "telnet": True} if allow else v)
        self.db.audit("user", "telnet:" + ("allow" if allow else "off"), {"id": device_id, "why": why})
        self.emit("device", self.db.device(device_id))

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
        pnp = "pnp" in (info["vendor_class"] or "").lower()
        known = self.db.find(mac=mac)
        # A provisioned box that asks for DHCP was wiped, when we can tell: its PnP agent only runs without a
        # startup-config, and a box PandoraBox configured from factory has Vlan1 shut. A box merged over SSH may run
        # a DHCP client of its own: its management address is left alone then (a lease used to overwrite it).
        wiped = bool(known and known["state"] == "provisioned" and (pnp or known["path"] in BOOT_PATHS))
        if known and known["state"] == "provisioned" and not wiped:
            facts.pop("ip")
        # A lease may still sit on another device's row (after a restart, or a wiped box that got a new one).
        # Take it off that row so upsert() can't merge two different devices by IP.
        self.db.x("UPDATE devices SET ip=NULL WHERE ip=? AND (mac IS NULL OR mac<>?)", ip, mac)
        if not known:
            facts["source"] = "dhcp"
        dev = self.db.upsert(**facts)
        if not dev["path"]:
            dev = self.db.upsert(mac=mac, path=guess_path(dev))
        if wiped:
            dev = self.factory_again(dev, f"asked for DHCP as a factory box{' (PnP)' if pnp else ''}",
                                     path="pnp" if pnp else None)
        self.emit("device", dev)
        s, queued, p = self.cfg["server_ip"], dev["state"] in ("queued", "provisioning"), dev["path"]
        if queued and p == "ztp":
            return {67: f"http://{s}:{self.cfg['http_port']}/ztp/bootstrap.py".encode()}
        if queued and p == "autoinstall":
            return {150: ip_opt(s), 66: s.encode(), 67: f"pandora-{mac.replace(':', '')}.cfg".encode()}
        if (queued and p == "pnp") or "pnp" in (info["vendor_class"] or "").lower():
            return {43: opt43_pnp(s, self.cfg["http_port"])}  # PnP: identify always, configure only if queued
        return None  # seen, not touched

    def factory_again(self, dev, why, path=None, release=False) -> dict:
        """The box has no startup-config any more (wiped and reloaded, or the user says so): a factory box to
        onboard again, not a provisioned one. Seen on the real 2960X: it stayed "Provisioned", its address moved to
        the bootstrap lease and SNMP raised "unreachable" every 3 polls until the database was thrown away.
        Name, mgmt IP and reserved ports are kept unless `release`, so onboarding again gives it the same ones;
        its SSH host key is forgotten (a factory pre-config generates a new one)."""
        from . import alerts, monitor
        i = dev["id"]
        path = path or (dev["path"] if dev["path"] in BOOT_PATHS + ("console",) else None) or \
            guess_path({**dev, "console_port": None})
        self.db.x("UPDATE devices SET path=?, hostname=NULL WHERE id=?", path, i)
        if release:
            alloc.release(self.db, i)
        access.CREDS.pop(i, None)
        dev = self.db.set_state(i, "identified" if dev["pid"] else "discovered",
                                f"{why}: back to factory. Select it to pre-configure it again")
        for key in ("unreachable", "cpu", "drift", "reboot", "provision", "creds"):  # about the configured box
            alerts.resolve(self, i, key)
        for prefix in ("if:", "trap:"):
            alerts.resolve(self, i, prefix, prefix=True)
        hostkeys.forget(self, i, why)
        self.db.set_reach(i, None)  # not monitored until it is provisioned again
        monitor.LAST.pop(i, None)
        self.db.x("DELETE FROM compliance WHERE device_id=?", i)
        self.db.audit("system", "factory-again", {"id": i, "why": why, "released": release})
        return dev

    def remove(self, device_id) -> None:
        """Forget a device completely (replaced, sold, a duplicate row). The audit log keeps its history."""
        from . import alerts, monitor
        if self.db.q("SELECT 1 FROM mgmt_domains WHERE backbone_id=?", device_id):
            raise ValueError("this device is a management backbone: change the management design first")
        with self.db.lock:
            for table, col in (("mgmt_members", "device_id"), ("mgmt_config", "device_id"), ("host_keys", "device_id"),
                               ("compliance", "device_id"), ("reserved_ports", "device_id"),
                               ("allocations", "device_id"), ("problems", "device_id"), ("backups", "device_id"),
                               ("configs", "device_id"), ("snmp_samples", "device_id"), ("devices", "id")):
                self.db.x(f"DELETE FROM {table} WHERE {col}=?", device_id)
        access.CREDS.pop(device_id, None)
        monitor.LAST.pop(device_id, None)
        alerts._fails.pop(device_id, None)
        self.db.audit("user", "device:remove", {"id": device_id})

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
                if self.db.vars(device_id).get("staged"):
                    try:
                        ok, note = self.stage_two(device_id)
                    except Exception as e:
                        log.exception("stage 2 of %s failed", device_id)
                        ok, note = False, f"stage 2: {type(e).__name__}: {e}"
                    return self.finish(device_id, "autoinstall-2stage", ok, note)
                try:
                    out = self.ssh_command(self.db.device(device_id) | {"ip": a["mgmt_ip"]}, "show version")
                    self.db.upsert(**{k: v for k, v in parse_show_version(out).items() if k != "hostname"},
                                   mac=self.db.device(device_id)["mac"])
                    return self.finish(device_id, method, True, "SSH login on mgmt IP works")
                except Exception as e:
                    log.info("verify %s: %s", device_id, e)
            time.sleep(10)
        why = ""
        if access.ssh_open(a["mgmt_ip"], 23):
            # the boot file has `transport input ssh`: telnet still open = the box refused the SSH lines. Real 2960
            # with a non-crypto image (no K9): config applied, address answering, SSH impossible.
            why = (": telnet answers there but SSH doesn't, so the box refused the SSH lines. Its IOS most likely has "
                   "no crypto (image name without K9, see `show version`). Allow Telnet for this box on its page, "
                   "then upgrade it to a K9 image there")
        self.finish(device_id, method, False, f"no SSH on {a['mgmt_ip']} after {wait}s{why}")

    def finish(self, device_id, method, ok, detail):
        text, _, a = self.render(device_id)
        self.db.save_config(device_id, method, text, detail)
        if ok:
            old_ip = self.db.device(device_id)["ip"]
            # A merged (SSH) device was reached on its existing address. Only switch to the new mgmt IP once
            # PandoraBox can actually reach it; otherwise every later backup/poll/terminal would fail.
            if method == "ssh" and old_ip and old_ip != a["mgmt_ip"] and not self.reachable(self.db.device(device_id),
                                                                                             a["mgmt_ip"]):
                detail = f"{detail}; still using {old_ip} (new mgmt IP {a['mgmt_ip']} not reachable from here yet)"
                self.db.x("UPDATE devices SET hostname=? WHERE id=?", a["hostname"], device_id)
            else:
                self.db.x("UPDATE devices SET ip=?, hostname=? WHERE id=?", a["mgmt_ip"], a["hostname"], device_id)
        self.db.set_state(device_id, "provisioned" if ok else "failed", detail)
        self.emit("device", self.db.device(device_id))
        if ok and method in ("pnp", "ztp", "autoinstall"):
            threading.Thread(target=self.complete, args=(device_id,), daemon=True).start()

    def learn_from_neighbor(self, n) -> dict | None:
        """CDP heard on the laptop NIC from a box being onboarded: its model and the name of the port the laptop is
        cabled to. A factory box sends CDP within seconds of booting, with its DHCP address, before any config. That
        port is exactly the one to keep as the management port, named the way *this* box names it (real 2960:
        "GigabitEthernet0/24" typed by hand, the box had FastEthernet0/24: refused, unreachable). Only boxes not yet
        configured; a box behind another switch is not heard (the switch in between is), so nothing is guessed."""
        if n.get("via") != "cdp":
            return None  # LLDP port IDs are often MACs or descriptions, not interface names
        dev = next((d for ip in n.get("addresses") or [] if (d := self.db.find(ip=ip))), None)
        dev = dev or self._by_mac_block(n.get("src_mac"))
        if not dev or dev["state"] in ("provisioning", "provisioned"):
            return None
        port = alloc.normalize_if(n.get("remote_port") or "")
        pid = re.sub(r"^cisco\s+", "", (n.get("platform") or "").strip(), flags=re.I).split(" ")[0]
        vars_ = self.db.vars(dev["id"])
        changed = False
        if pid and not dev["pid"] and re.match(r"^[A-Z0-9][\w/+-]{3,}$", pid, re.I):
            dev = self.db.update(dev["id"], pid=pid)
            if dev["state"] == "discovered":
                dev = self.db.set_state(dev["id"], "identified")
            changed = True
        if port and vars_.get("seen_port") != port:
            self.db.set_vars(dev["id"], {**vars_, "seen_port": port})
            alloc.drop_default_ports(self.db, dev["id"])  # guessed before we knew: guessed again with this port
            changed = True
        if changed:
            self.db.audit("system", "cdp:learned", {"id": dev["id"], "pid": dev["pid"], "laptop_port": port})
            self.emit("device", dev)
        return dev

    def _by_mac_block(self, src_mac) -> dict | None:
        """A box that has no address yet sends CDP without one: an unselected AutoInstall box gets no DHCP lease
        from us (real 2960). Its CDP leaves from a port MAC in the same small block as the MAC it asked DHCP with
        (ports and SVIs are numbered from one base MAC). Match only when exactly one not-yet-configured box is that
        close: two candidates = don't guess."""
        try:
            src = int((src_mac or "").replace(":", "").replace("-", ""), 16)
        except ValueError:
            return None
        near = []
        for d in self.db.q("SELECT * FROM devices WHERE mac IS NOT NULL AND state NOT IN ('provisioning', 'provisioned')"):
            diff = abs(int(d["mac"].replace(":", ""), 16) - src)
            if diff <= 0x80:
                near.append(d)
        return near[0] if len(near) == 1 else None

    def check_confreg(self, device_id, show_version: str):
        """`Configuration register is 0x2142` (bit 0x40): the box boots without reading its startup-config, so a saved
        pre-config is gone at the next reload (seen: a 2911 left that way after password recovery). Say so; changing
        it is the operator's call (it may be on purpose)."""
        from . import alerts
        m = re.search(r"Configuration register is (0x[0-9A-Fa-f]+)", show_version or "")
        if not m:
            return
        if int(m.group(1), 16) & 0x40:
            alerts.raise_(self, device_id, "confreg", "warning",
                          f"Configuration register is {m.group(1)}: it ignores the saved config at the next reload and "
                          "comes up empty. Unless you are recovering a password, push `config-register 0x2102`")
        else:
            alerts.resolve(self, device_id, "confreg")

    def find_pc_port(self, conn) -> str | None:
        """The switch port this PC is cabled to, in the box's own naming: its ARP entry for us gives our MAC, its
        MAC table gives the port it learned that MAC on."""
        s = self.cfg["server_ip"]
        arp = conn.send_command(f"show ip arp {s}")
        if not (m := re.search(r"([0-9a-f]{4}\.[0-9a-f]{4}\.[0-9a-f]{4})", arp, re.I)):
            conn.send_command(f"ping {s} repeat 2 timeout 1")  # fill the ARP table, then ask again
            m = re.search(r"([0-9a-f]{4}\.[0-9a-f]{4}\.[0-9a-f]{4})", conn.send_command(f"show ip arp {s}"), re.I)
        if not m:
            return None
        mac = m.group(1).lower()
        for cmd in (f"show mac address-table address {mac}", f"show mac-address-table address {mac}"):  # old IOS
            if port := re.search(rf"{re.escape(mac)}\s+\S+\s+(\S+)", conn.send_command(cmd), re.I):
                return alloc.normalize_if(port.group(1))
        return None

    def stage_two(self, device_id) -> tuple[bool, str]:
        """Second stage of a two-stage AutoInstall: the box answers SSH on its mgmt IP on Vlan1 (stage 1 named no
        port). Ask it its model, its real port names and which port the PC is on; reserve that port (then the model's
        defaults); move management to the mgmt VLAN. The move cuts this session the moment the PC's port changes VLAN,
        so the box runs it on its own: a short EEM applet (no secrets in it) that removes itself and saves. Then we
        reconnect on the same IP, merge the full config and save. Real case: a 2960 with FastEthernet ports, no PnP,
        no CDP during AutoInstall, so nothing told us its port names before it was up."""
        a = alloc.allocate(self.db, self.cfg, device_id)
        dev = self.db.update(device_id, ip=a["mgmt_ip"])
        vlan = int(self.cfg["mgmt_vlan"])
        with self.session(dev) as conn:
            conn.enable()
            ver = conn.send_command("show version")
            names = alloc.parse_ifnames(conn.send_command("show ip interface brief"))
            pc = self.find_pc_port(conn)
        facts = {k: v for k, v in parse_show_version(ver).items() if k != "hostname"}
        dev = self.db.update(device_id, **facts)
        self.check_confreg(device_id, ver)
        if not pc or pc not in names:
            return False, (f"stage 2: could not find the port this PC is cabled to (ARP/MAC table: {pc or 'nothing'}); "
                           f"the box answers on {a['mgmt_ip']} in VLAN 1. Pick reserved ports and Claim again")
        typed = [alloc.normalize_if(r["port"]) for r in self.db.q(
            "SELECT port FROM reserved_ports WHERE device_id=? AND purpose='mgmt'", device_id)]
        vars_ = {**self.db.vars(device_id), "cap_ifnames": names, "seen_port": pc}
        self.db.set_vars(device_id, vars_)
        if not (typed and pc in typed and all(p in names for p in typed)):
            self.db.x("DELETE FROM reserved_ports WHERE device_id=?", device_id)  # guessed again: the PC's port first
        ports = alloc.allocate(self.db, self.cfg, device_id)["reserved_ports"]
        gw = self.cfg.get("mgmt_gateway")
        move = ["interface Vlan1", "no ip address", "shutdown", f"vlan {vlan}", "name PANDORA-MGMT", "exit"]
        for p in ports:
            move += [f"interface {p}", "description PANDORA-MGMT reserved", "switchport mode access",
                     f"switchport access vlan {vlan}", "spanning-tree portfast", "no shutdown"]
        move += [f"interface Vlan{vlan}", "description PANDORA-MGMT", f"ip address {a['mgmt_ip']} {self.cfg['netmask']}",
                 "no shutdown"] + ([f"ip default-gateway {gw}"] if gw else [])
        actions = ["enable", "configure terminal", *move, "no event manager applet PANDORA-STAGE2", "end",
                   "write memory"]
        applet = ["event manager applet PANDORA-STAGE2", " event timer countdown time 10"] + [
            f' action {n:03d}.0 cli command "{c}"' for n, c in enumerate(actions, 1)]
        with self.session(dev) as conn:  # armed, not saved: it fires 10 s later on the box and saves itself
            conn.enable()
            armed = conn.send_config_set(applet, read_timeout=60)
        if re.search(r"^\s*% ?(Invalid|Incomplete|Unrecognized)", armed or "", re.M):
            return False, (f"stage 2: this IOS refused the EEM applet, nothing was moved; the box answers on "
                           f"{a['mgmt_ip']} in VLAN 1. Pick reserved ports ({alloc.summarize_ports(names)}) and Claim again")
        time.sleep(15)
        if not self._wait_ssh(a["mgmt_ip"], 120):
            return False, (f"stage 2: no SSH on {a['mgmt_ip']} after moving it to VLAN {vlan} on {', '.join(ports)}: "
                           "check the console (show vlan brief, show ip interface brief)")
        with self.session(self.db.device(device_id)) as conn:  # did the box really move it? (else don't merge)
            conn.enable()
            moved = re.search(rf"^Vlan{vlan}\s+{re.escape(a['mgmt_ip'])}\s", conn.send_command("show ip interface brief"),
                              re.M)
        if not moved:
            return False, f"stage 2: the move to VLAN {vlan} did not happen (still on VLAN 1): check the console"
        _, caps = self.probe(self.db.device(device_id))  # what this image accepts (vty 0-15, AES, traps config)
        self.db.set_vars(device_id, {**self.db.vars(device_id), **caps, "staged": False})
        text, problems, _ = self.render(device_id)  # the full config, now with the real port names
        if problems:
            return False, "stage 2: " + "; ".join(problems)
        out = self.ssh_config(self.db.device(device_id),
                              [ln for ln in text.splitlines() if ln.strip() and not ln.lstrip().startswith("!")])
        errors = [ln for ln in out.splitlines() if ln.startswith("%") and "Invalid" in ln]
        return not errors, "; ".join(errors) or (f"two-stage AutoInstall: {dev['pid'] or 'switch'}, PC on {pc}, "
                                                 f"management moved to VLAN {vlan} on {', '.join(ports)} + saved")

    def save_over_ssh(self, device_id, why) -> bool:
        """A boot path applied the config but could not save it: log in over SSH (the config just made that
        possible), merge what this image accepts and `write memory`. Provisioned only if that worked."""
        result = self.complete(device_id)
        ok = not result.startswith("not completed")
        self.finish(device_id, "pnp+ssh", ok, f"applied over PnP, saved over SSH ({why})" if ok else
                    f"applied over PnP but NOT saved: {why}; SSH: {result}")
        return ok

    def set_role(self, device_id, role) -> dict:
        """Change the role, and the role-based name with it (hostname is {site}-{role}-{nn}) while the reserved name
        and address provably never reached the box (never claimed, no config ever sent or saved). A failed or partial
        push may have left the mgmt IP on it: that address stays reserved, or a second box could get the same one.
        Every caller goes through here: the Devices list's role menu kept the old name (a 1941 became kmutnb-sw-02)."""
        dev = self.db.device(device_id)
        if role and role != dev["role"]:
            self.db.x("UPDATE devices SET role=? WHERE id=?", role, device_id)
            if dev["state"] in ("discovered", "identified", "needs_credentials") and not self.db.q(
                    "SELECT 1 FROM configs WHERE device_id=? LIMIT 1", device_id):
                alloc.release(self.db, device_id)  # name, address and the ports chosen for the old role
        return self.db.device(device_id)

    def complete(self, device_id) -> str:
        """Boot files carry only lines every IOS takes (PnP rolls back the whole file on one rejected line). Now
        that SSH works, ask this image what it accepts and merge the full config: vty 0-15, `traps config`, ...
        Re-applying the lines the box already has changes nothing."""
        dev = self.db.device(device_id)
        try:
            ver, caps = self.probe(dev)
            self.check_confreg(device_id, ver)
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
            caps = parse_caps(*map(con.ask, CAP_QUESTIONS))
            if names := alloc.parse_ifnames(con.send("show ip interface brief", 3)):
                caps["cap_ifnames"] = names
            self.db.set_vars(dev["id"], {**self.db.vars(dev["id"]), **caps})
            # Factory = the console showed the setup/autoinstall dialog. A configured box that merely
            # has no login must keep its Vlan1 and keys.
            text, problems, _ = self.render(dev["id"], factory=con.factory)
            if problems:
                raise RuntimeError("; ".join(problems))
            errors = con.configure(text)
        self.finish(dev["id"], "console", not errors, "; ".join(errors) or "pasted + saved")

    def uses_telnet(self, dev, ip=None) -> bool:
        """Telnet only where the user allowed it for this box (an IOS image without crypto has no SSH server) and
        only while SSH doesn't answer: once a K9 image runs SSH, SSH is used even before Telnet is switched off."""
        ip = ip or dev.get("ip")
        v = self.db.vars(dev["id"])
        # Never a silent downgrade: the user allowed it, the box was proven to have no crypto (enable_telnet /
        # add_by_ssh), and it never showed an SSH key. A box with a pinned key that stops answering SSH is an
        # error, not a reason to send the password in clear text.
        return bool(ip and v.get("telnet") is True and v.get("cap_ssh") is False
                    and not hostkeys.pinned(self.db, dev["id"]) and not access.ssh_open(ip)
                    and access.ssh_open(ip, 23))

    def reachable(self, dev, ip=None) -> bool:
        ip = ip or dev.get("ip")
        return access.ssh_open(ip) or self.uses_telnet(dev, ip)

    def netmiko_params(self, dev, ip=None, telnet=False):
        c = self.creds_for(dev)
        return {"device_type": "cisco_ios_telnet" if telnet else platforms.get(dev.get("os_type"))["netmiko"],
                "host": ip or dev["ip"], "username": c["username"], "password": c["password"],
                "secret": c.get("secret") or c["password"], "fast_cli": False}

    def session(self, dev):
        if self.uses_telnet(dev):  # cleartext, allowed per box: no host key to pin
            return connect(self.netmiko_params(dev, telnet=True))
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
            if names := alloc.parse_ifnames(conn.send_command("show ip interface brief")):
                caps["cap_ifnames"] = names  # its real port names: render refuses any other
        return ver, caps

    def _push_ssh(self, dev):
        if not self.reachable(dev):
            telnet = access.ssh_open(dev["ip"], 23)
            raise RuntimeError(f"SSH not reachable on {dev['ip']}" + (
                ": telnet answers, so its IOS image most likely has no crypto (no K9). Allow Telnet for this box on "
                "its page, then upgrade it to a K9 image there" if telnet else ""))
        out, caps = self.probe(dev)
        self.check_confreg(dev["id"], out)
        self.db.upsert(ip=dev["ip"], **{k: v for k, v in parse_show_version(out).items() if k != "hostname"})
        self.db.set_vars(dev["id"], {**self.db.vars(dev["id"]), **caps})
        text, problems, a = self.render(dev["id"])
        if problems:
            raise RuntimeError("; ".join(problems))
        lines = [l for l in text.splitlines() if l.strip() and not l.lstrip().startswith("!")]
        cur = self.db.device(dev["id"])
        try:
            out = self.ssh_config(cur, lines)
            note = "merged + saved"
        except Exception as e:
            # The config gives the box a new mgmt address. When that is on the interface this session runs over (a
            # router's mgmt port), the session dies right after `ip address` (real 1941: "ReadTimeout ... no
            # shutdown") and nothing after it is sent or saved. Expected: wait for SSH on the new address and run
            # the whole merge again there (same lines again = no change); that pass also saves.
            new = a["mgmt_ip"]
            if new == cur["ip"] or not self._wait_ssh(new):
                raise
            log.info("device %s: session lost while re-addressing (%s); merging again on %s", dev["id"], e, new)
            out = self.ssh_config(cur | {"ip": new}, lines)
            note = f"merged + saved (moved from {cur['ip']} to {new} during the merge)"
        errors = [l for l in out.splitlines() if l.startswith("%") and "Invalid" in l]
        self.finish(dev["id"], "ssh", not errors, "; ".join(errors) or note)

    @staticmethod
    def _wait_ssh(ip, timeout=90.0) -> bool:
        end = time.time() + timeout
        while time.time() < end:
            if access.ssh_open(ip):
                return True
            time.sleep(3)
        return False


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


def no_crypto(conn) -> bool:
    """Two signals from the box, both needed: `ip ssh ?` refused AND the running image's name has no K9 in it."""
    ver = conn.send_command("show version")
    m = re.search(r'System image file is "([^"]+)"', ver)
    image = (m.group(1) if m else "").lower()
    conn.config_mode()
    out = conn.send_command_timing("ip ssh ?", strip_prompt=False, strip_command=False)
    conn.send_command_timing(chr(3), strip_prompt=False)  # Ctrl-C drops the half-typed line
    conn.exit_config_mode()
    return bool(image) and "k9" not in image and bool(
        re.search(r"^\s*% (Invalid input detected|Unrecognized command)", out, re.M))


class NeedCredentials(Exception):
    pass


CAP_QUESTIONS = ("line vty 0", "snmp-server group PANDORA v3", "snmp-server enable traps", "ip routing",
                 "ip ssh")  # + " ?"


def parse_caps(vty_help: str, group_help: str, traps_help: str, routing_help: str = "", ssh_help: str = "") -> dict:
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
    # An image without crypto (no K9 in its name: real 2960 / 3560 on the bench) has no `ip ssh` at all, so no
    # SSH server: the template then leaves telnet on the vty lines (or the box would lock everyone out).
    if re.search(r"^\s*% (Invalid input detected|Unrecognized command)", ssh_help, re.M):
        caps["cap_ssh"] = False
    elif re.search(r"^\s+version\s", ssh_help, re.M):
        caps["cap_ssh"] = True
    return caps
