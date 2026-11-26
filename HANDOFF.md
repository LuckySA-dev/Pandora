# PandoraBox handoff

For the next agent picking this up. README.md is for users; this file is the working state: what is done, what is not, and the traps that cost time. Update it when you finish something.

Last updated: 2026-11-26 (first day on real Cisco hardware; see "Real hardware bench").

## What the project is

PandoraBox is one Windows-laptop program for pre-configuring factory **Cisco IOS / IOS-XE** gear:
- discover (DHCP, PnP, CDP/LLDP, SNMP sweep, console) → inventory → the user selects → conflict-free pre-config (unique hostname + mgmt IP, 1-2 reserved mgmt ports on the mgmt VLAN)
- delivery over PnP, ZTP, AutoInstall, console paste, or SSH merge (SSH already on → ask for credentials first)
- day-2: backup + diff, compliance + fix, SNMPv3 polling and informs, problems, CDP topology, web terminal, AI agent (tool loop with approvals; Claude or Ollama)

Stack: Python 3.12, FastAPI, SQLite, netmiko/paramiko (pinned <5, see below), pysnmp 7, tftpy, scapy, Jinja2. Web UI: plain HTML + ES modules, no build step.

## Ground rules (from the user)

- [ ] Never type passwords or sudo passwords for the user. Secrets only from env vars: `PANDORA_ADMIN_PASSWORD`, `PANDORA_SNMP_AUTH`, `PANDORA_SNMP_PRIV`, `ANTHROPIC_API_KEY`. Device credentials typed in the UI stay in memory.
- [ ] Ask before downloads/installs beyond the project's dependencies.
- [ ] GPL projects (Zabbix, LibreNMS) are design reference only, no code. Apache/MIT code we adapted is credited in `NOTICE` (Oxidized, hier_config, WebSSH, NetBox).
- [ ] Reply to the user in Thai; code, comments and docs in English.
- [x] Git repo on `main`, pushed to GitHub `origin` only when the user says so. Commit when a piece of work is verified; `.gitattributes` keeps LF so the lab scripts run in Linux containers. On this laptop the repo-local git author is `LuckySA` (set 2026-11-26 at the user's choice; no global identity).
- [ ] Fix problems permanently, as a class, not the one symptom (the user asked for this explicitly on the bench day).

## How to run it (Windows laptop)

- Once / after a pull: `powershell -ExecutionPolicy Bypass -File .\setup.ps1` (finds Python 3.11+, creates `.venv`, `pip install -e .[dev]`, creates `pandora.toml`, lists wired NICs).
- Every start, Administrator PowerShell: `powershell -ExecutionPolicy Bypass -File .\run.ps1` (always `.venv`, asks the 3 secrets hidden once per window, offers to stop an old copy that still holds 67/69/162/80). `-Preflight` checks the laptop, `-NoDhcp` runs without DHCP/TFTP.
- **Always use `.venv`.** The system Python has paramiko 5.1 and none of the pins; `run.ps1 -Preflight` (check `python` / `dependencies`) says so.
- Code changes need a PandoraBox restart. The user repeatedly answered "restarted" without having done it: check the process start time (`Get-CimInstance Win32_Process -Filter "Name='python.exe'"`) before believing a fix is live.
- The bench laptop: provisioning NIC `Ethernet` (Intel I219-LM) 10.99.0.1/24, Wi-Fi `10.110.x` for internet, Npcap installed, console cable usually on **COM7** (Tera Term often holds it; PandoraBox's watcher then logs "Access is denied", harmless).

## Real hardware bench (2026-11-26)

### Devices proven

| Box | IOS | Path | Result |
|---|---|---|---|
| WS-C2960X-24PD-L | 15.2(2)E7 | SSH merge | Provisioned in 29 s, startup-config verified on the console |
| WS-C2960X-24PD-L | 15.2(2)E7 | **PnP end to end** (wiped, reloaded) | Provisioned "PnP config applied + saved" + `ssh-complete`, packet capture |
| CISCO1941/K9 | 15.4(3)M3 | PnP (config applied) then SSH merge | Provisioned "merged + saved", SNMPv3 OK |
| CISCO2911/K9 | 15.6(3)M0a | **PnP + save over SSH** | Provisioned "applied over PnP, saved over SSH" in 3 min |
| WS-C3560G-48TS-E | 12.2 (K9) | **Two-stage AutoInstall**, nothing typed | Provisioned "PC on Gi0/48, management moved to VLAN 99 on Gi0/48, Gi0/47 + saved" |
| WS-C2960 (MAC 00:24:97:b1:8c:40) | ? | AutoInstall stage 1 OK (answers on Vlan1) | **Failed**: SSH never opens, telnet does = refused the SSH lines, very likely a non-K9 image. Waiting for its `show version` |

### Fixed, grouped by area (all with unit tests; simulated lab 25/25)

SSH and connectivity
- paramiko 5.x **removed** SHA-1 kex (group1/group14/gex-sha1) and `ssh-rsa`, the only algorithms classic IOS 15.x offers ("no acceptable kex algorithm"): pinned `paramiko>=3.5.1,<5` (4.0.0 tries modern algorithms first). `hostkeys.legacy_ssh_missing` + a test + a preflight check fail if they disappear again.
- Web terminal: a box with no IP opens its console (it used to SSH to `ip=None` = localhost, 10 s timeout); a vanished browser no longer crashes the handler.
- The allocator counted a box's own address as taken and moved it to a new one; re-addressing a router's mgmt port mid-SSH killed the session (`ReadTimeout ... no shutdown`). Now a box keeps its own free mgmt address, and an SSH merge that loses its session while re-addressing waits for SSH on the new address and merges again (idempotent).

PnP (classic IOS agents)
- Backoff without `<reason>` drew a fault on every poll (agent polled every 5 s): `<reason>` added.
- `/cfg/<serial>` downloaded fully but IOS reported `I/O error` on its keep-alive connection: `/cfg` answers `Connection: close`. uvicorn keep-alive 15 s (5 s raced IOS's reuse → RST).
- ISR G2 (1941, 2911) refuse cli-exec `write memory` once the config created a local user (`PnP Service Error 16, Insufficient PnP CLI-Exec Service Privilege`): the config is applied, so `Ctx.save_over_ssh` saves it; Provisioned only if that worked. A failed save is no longer noted "applied + saved".
- A file copied into running-config doesn't commit `vlan 99` / `name` before ports use it (VLAN came up as VLAN0099): boot files `exit` VLAN mode; compliance ignores `exit`.

AutoInstall and unknown port names
- No model from AutoInstall, so port names were typed and wrong (`Gi0/24` on a FastEthernet box). Three layers now:
  1. CDP from a not-yet-configured box (matched by its address, or by MAC block when it has none) gives its PID and **the port the laptop is on**; that port is reserved first (`learn_from_neighbor`, `alloc.guess_ports`, var `seen_port`). Routers too.
  2. SSH/console pushes read `show ip interface brief` (`cap_ifnames`); render refuses a reserved port the box doesn't have and lists the real ones.
  3. **Two-stage AutoInstall** when an AutoInstall switch's model is unknown (`_mark_staged`, `stage_two`, base.j2 `staged`): stage 1 names no port (mgmt IP on Vlan1); stage 2 over SSH reads the model, real ports, the PC's port (`show ip arp <server_ip>` → `show mac address-table address <mac>`), probes caps, arms a secret-free EEM applet that moves mgmt to VLAN 99 and saves, reconnects on the same IP, checks Vlan99 holds it, merges the full config. Stops safely (still on VLAN 1) if the PC's port is unknown or EEM is refused.
- The real factory 2960 sent **no CDP at all** during AutoInstall (packet capture), which is why layer 3 exists.
- Classic IOS broadcasts TFTP requests for `network-confg`, `cisconet.cfg`, `router-confg`, `ciscortr.cfg`, `<host>-confg` while booting: still answered "not found", logged at debug only; DHCP `siaddr` only when we hand out a TFTP file. A failed AutoInstall now says when telnet answers but SSH doesn't (non-K9 image).

State, inventory and restarts
- One `Ctx.factory_again` for every wipe signal (DHCP as PnP agent, DHCP from a box configured by a boot path, console at the setup dialog): back to Identified, same name/IP, host key forgotten, stale alarms and compliance cleared. DHCP no longer overwrites a provisioned box's mgmt IP.
- Device page **Reset** / **Remove** (`POST /api/devices/{id}/reset|remove`, `confirm: true`). No more renaming `pandora.db` to start over.
- DHCP leases are seeded from the inventory at start and renewals after a restart are answered (they were ignored until the lease ran out).
- Role changes all go through `Ctx.set_role` (the Devices list menu kept the old role's name: a 1941 became `kmutnb-sw-02`); the switch role is refused on router PIDs and vice versa (`alloc.model_kind`).
- Console: a paste with errors is not saved (a half config made a 2960X boot configured and wait in Queued forever); notes quote IOS's `%` line; a console cable no longer changes a known box's delivery.
- `Configuration register is 0x2142` (2911 after password recovery: ignores startup-config) raises a `confreg` warning whenever `show version` is read; changing it is the operator's call.

Monitoring
- **Backup loop**: classic IOS sends ciscoConfigManEvent for reads (`show running-config` = running → commandSource); every backup triggered the next (180 informs, ~370 SSH sessions in 30 min). Only writes (destination running/startup) count; one backup per device at a time, bursts folded. Note: `?` probes enter config mode, which IOS reports as a write, so e.g. the Management page's Review causes one backup + compliance per box (a short burst, bounded).
- **Reachability is a status**: 3 failed polls = Offline (last seen …), info problem by default (`offline_severity`), polled every `offline_retry` s (300), skipped by scheduled backups; any SNMP answer or inform = Online again. Reboots detected from sysUpTime going back. Columns `devices.reach` / `seen` (migrated into existing DBs). With one LAN card every uncabled box is offline: expected.
- Compliance false drift on classic IOS fixed: split vty blocks (`line vty 0 4` + `5 15`), `no ip domain-lookup`, ISR `duplex auto` / `speed auto`, SNMP group with IOS's auto `notify *tv.…` view.

Process and install
- `python -m pandora` didn't exit on Ctrl+C while a UI page was open (old copy kept 69/162, new one shared 67 via SO_REUSEADDR): `/ws` notices closed pages, `timeout_graceful_shutdown=5`, DHCP binds exclusively and early, a busy TFTP port stops startup. Before: still running after 20 s; after: 0.1 s.
- `pip install -e .` failed (setuptools saw `lab/` too): packages limited to `pandora*`. `setup.ps1` / `run.ps1`; preflight checks venv + every library against `pyproject.toml`. Windows Proactor `ConnectionResetError 10054` tracebacks are dropped.

### Open after the bench day
- [x] **Boxes without SSH (IOS image without crypto, no K9; the user's 3560 and the legacy 2960)**. The user chose both: Telnet only to reach the box, then a K9 image, SSH on, Telnet off.
  - Telnet is a per-box opt-in, off by default (`Ctx.allow_telnet`, var `telnet`; "This box has no SSH" on the device page, or the checkbox in Add by IP). `Ctx.uses_telnet` picks Telnet only while SSH doesn't answer; netmiko `cisco_ios_telnet`, web terminal via netmiko's vendored telnetlib (Python 3.13 dropped the stdlib one) with auto-login. No host key to pin over Telnet.
  - The probe asks `ip ssh ?`: refused = `cap_ssh` false -> base.j2 leaves out `ip ssh` / `crypto key` and sets vty `transport input telnet` (with `transport input ssh` the box would lock everyone out).
  - `pandora/upgrade.py` (device page, Access -> "Upgrade to a K9 image"; `POST /api/devices/{id}/upgrade` with `confirm: true`): the user puts the `.bin` in `.pandora/tftp/images/` (Cisco serves it only behind an account), PandoraBox checks flash space, copies it over TFTP, compares `verify /md5` with the file's MD5, sets `boot system`, saves, reloads, waits, then makes RSA keys with `transport input telnet ssh`, proves an SSH login (pins the key), and only then switches vty to SSH only (full config if PandoraBox pre-configured the box, otherwise just the vty lines so its own login method stays) and turns Telnet off. Each step checks first, so a rerun carries on; progress in the note and under Access.
  - `access.ssh_open` now needs the SSH greeting on 22 and a non-refusing answer on 23 (an open TCP port alone said "SSH" for boxes that close at once).
  - Proven on the simulated lab (26/26: a non-K9 fake with a real TFTP copy and reload). Not yet on the real 3560 / 2960: needs the K9 image file from the user.
- [ ] 3560G (#5) still lacks `login local` / `transport input ssh` on vty 5-15 (pushed before stage 2 probed caps; fixed for new boxes): **Check compliance → Fix** on it. The user chose to leave it for now.
- [ ] 2960X: `pnp profile pnp-zero-touch` stays after an SSH merge (the agent keeps calling, gets backoff). An unused reserved port raises a high "management port down".
- [ ] Classic IOS reports `?` probes as config writes, so probes trigger a backup each (bounded). Could skip configChange backups right after our own sessions.
- [ ] UI: the empty "Reserved mgmt ports" box shows the placeholder `Gi1/0/47, Gi1/0/48` even for a two-stage box; say "learned from the box after boot" there.
- [ ] Two-stage AutoInstall is switch-only; an AutoInstall router with no known model still needs typed ports (ISR G2 have PnP, which gives the model).

## Done (before the bench day)

Core
- [x] Inventory-first workflow; nothing is configured until selected (PnP gets `backoff`, others no boot options)
- [x] Conflict-free allocation (UNIQUE constraints), reserved mgmt ports, guard that protects mgmt port/VLAN/user/SSH/SNMP lines
- [x] Existing-SSH check → `needs_credentials` → merge over SSH
- [x] Delivery: PnP, ZTP (bootstrap.py), AutoInstall (DHCP 150/67 + per-MAC TFTP + EEM save), console paste, SSH merge
- [x] Console over COM **and** console servers (`socket://`, `rfc2217://`, cfg `console_urls`)
- [x] SNMPv3 sweep/identify/poll/inform receiver; CDP/LLDP topology (SNMP first, SSH textfsm fallback)
- [x] Backup + diff, compliance per feature + remediation (hier_config-style rules), problems/alerts
- [x] Web UI redesign (Atkinson Hyperlegible + Noto Sans Thai), Bench as a sortable/paged table, Figma-style SVG topology, xterm.js terminal (no lag, backspace, resize, break)
- [x] AI agent: tool loop, approvals for config changes, snapshot + rollback, audit

Real-device findings fixed (containerlab IOL, IOS-XE 17.18.2)
- [x] Image capabilities probed with IOS `?` help before SSH/console pushes (`deliver.probe`, `console.Console.ask`, `deliver.parse_caps` → device vars `cap_vty_last`, `cap_snmp_priv`, `cap_traps_config`)
- [x] SNMP authNoPriv fallback only with cfg `snmp_allow_auth_nopriv = true` (IOL L2 has no AES); `snmp.auth(..., dev=)` per device
- [x] Boot files (PnP/AutoInstall/ZTP) use only universally accepted lines (PnP rolls back the whole file on one bad line)
- [x] Console probe listens first and never presses a key on a box that is zero-touching (`console.ZTP_RUNNING`)
- [x] Factory detection on console = "startup-config is not present"
- [x] Compliance: IOS hides `no shutdown` / `ip ssh version 2`, widens `traps snmp ...`, VTP server keeps VLANs in vlan.dat (read from `show vlan brief`)

Verification
- [x] 2026-11-26: `python -m pytest` → **88 passed**; `python scripts/mvp_check.py` → **25/25**; `python -m ruff check pandora tests scripts lab` clean (run with `.venv\Scripts\python.exe`)
- [x] `python -m pandora --preflight` checks a laptop for a real run (python/venv, library versions, secrets, NIC, ports 67/69/162/80, ranges, Npcap, firewall, consoles, SNMP AES, SSH to classic IOS, agent)
- [x] 2026-11-25 (containerlab, not re-run on 11-26): `clab_check.py` small 9/9, `ztp_check.py` 6/6, medium 16/16, large (40 IOL) 16/16

- [x] **Management network wizard** (Management page, `pandora/mgmt.py`, `api/mgmt.py`, `web/js/views/mgmt.js`): after pre-config, choose L3 backbone(s) (one domain = VLAN + subnet each), members under them (suggested from CDP), review, apply. Proven on the medium IOL lab: d1/d2 backbones, 10 members incl. 2 routers via dot1Q subinterfaces, 20 trunk ports, all 12 reachable over SSH on their new addresses from one PC NIC (`clab_check.py lab/medium.clab.yml`, 13/13)
  - design: ops VLAN 99 stays (PC + every device already there, make-before-break); backbone = `ip routing` + SVI gateway + static routes to other domains via their ops IP; switch member = SVI + `ip default-gateway` (or static routes if it routes); router member = subinterface + routes to mgmt subnets only (no default route); trunks = shortest point-to-point CDP path, ops VLAN on backbone-to-backbone paths
  - lessons from real IOL: a port that hears several CDP neighbors is a shared segment (IOL e0/0, a real OOB mgmt switch) and must never be a trunk path; IOS answers some failures with "% Command rejected", so the push treats every `%` line except warnings as an error
  - [x] compliance checks the design: `mgmt_config` stores what apply pushed per device (incl. per-port dot1q/native extras); `compliance.run` adds it to the intended config as feature **mgmt-design**, with IOS display rules (no allowed-VLAN list = all; split `allowed vlan` + `add` lines; `ip routing` hidden when default; design VLANs read from vlan.dat). Proven: medium lab 14/14 (twice), an edited domain SVI on a1 is flagged as mgmt-design and fixed by remediation. Security review: reserved ports/ops VLAN keep their strict feature even if a design line named them; only canonical `allowed vlan` forms are trusted; `ip routing` counts as held unless the box shows `no ip routing`
  - [x] Flaky/slow SSH right after a design (once in three runs: connect timeout / ReadTimeout; drift check 35-90 s) was spanning tree, not the routed path: steady state measured 60/60 logins at 0.8 s. Ports that just became trunks sit ~30 s in listening/learning per new VLAN (classic PVST on IOL). `mgmt.apply` now waits per switch until `show spanning-tree` has no LIS/LRN port (asked over the old address), then needs 3 good connects in a row; `deliver.connect` retries a connect timeout once everywhere. Result: 3/3 fresh runs 14/14, after-design checks 5-7 s, drift check 14-22 s
  - lesson: the lab's drift test must not cut its own management path (removing the member's gateway made it depend on ARP over VLAN 99 and failed once in three runs)
  - by design (user confirmed): **a backbone is always an L3 switch**, never a router; routers only join as members (dot1Q subinterface on their uplink). The wizard offers only switches, and `mgmt.plan` refuses a router backbone. It also refuses a **layer-2-only switch**: the image's own `ip routing ?` help is part of the capability probe (`cap_ip_routing`, recorded at SSH/console pre-config; `mgmt.ensure_caps` asks PnP/AutoInstall boxes over SSH at Review), and a backbone that can't be asked is blocked, not assumed
  - [x] **retire the old VLAN 99 addresses** (wizard step 4, "Remove old addresses", `mgmt.retire`, `POST /api/mgmt/retire` with `confirm: true`): only members that already answer on their domain address; backbones keep theirs (the PC's way in); device var `ops_retired` makes the template (and so compliance) expect `no ip address` there. Proven on the medium lab: 10 members, old address gone, domain SSH works, all compliant
  - [x] real bug found by retire: IOL L2 has `ip routing` **on by default and hidden**, so the member's `ip default-gateway` was ignored and members only answered through the VLAN 99 connected route. `mgmt.ensure_caps` now asks every box in the plan `show ip route` ("Gateway of last resort" = routing on → static routes, "Default gateway is" = off → `ip default-gateway`), var `ip_routing_on`
  - [x] every design device sends informs from its domain address (`snmp-server source-interface informs Vlan<domain>` / the router subinterface)
  - by design: an L2 path through a router is refused (cable members to switches); a backbone is an L3 switch, so bridging the management VLAN through a router is out of scope

## Not done / next

- [x] **Medium lab (12 IOL nodes) scale run**: 9/9, see the section at the end
- [x] **SSH host keys, trust on first use** (`pandora/hostkeys.py`, table `host_keys`): the first key a device shows is pinned to the device (not the IP, so the management design keeps it); a different key is refused before the password is sent (`hostkeys.Pin` is paramiko's policy for netmiko via `deliver.connect(params, pin)` and for the web terminal) and opens a `ssh-host-key` problem (high) with a "Trust new key" button (`POST /api/devices/{id}/forget-host-key`). A box PandoraBox re-provisions from factory (boot file served, console factory push, `factory_again`) forgets its pin first. Proven: mvp_check (impostor key refused, problem, forget → re-pinned), real IOL, and the real bench boxes
- [x] UI works offline after a clone: fonts (OFL) and xterm.js + fit (MIT) vendored in `pandora/web/vendor/` by `scripts/vendor_web.py`; verified 0 external requests in the browser
- [x] Laptop with internet + switch on the dedicated NIC: preflight and startup probe for another DHCP server on the segment (scapy DISCOVER; verified against a Cisco `ip dhcp pool` in the ztp lab) and refuse to serve DHCP if one answers; preflight fails if another NIC overlaps the provisioning subnet
- [x] Security review round 3: `/ztp/done` writes to the checked row by id (`db.update`), and a serial already on another row is refused; `_own` never trusts a selected or reported-on row without a known address; the other-DHCP-server check fails closed (no Npcap/raw access = refuse DHCP unless `--assume-isolated`)
- [x] Security review round 2: a selected box with no known address can't be claimed by serial; the allocated mgmt IP counts as the box's address only once its config was sent (state provisioning); `/ztp/done` must name the serial of the box it comes from; a boot file is served only for the device's own delivery path
- [x] Security review 2026-11-25 fixed: boot configs (PnP `/cfg`, ZTP `/ztp/cfg`, AutoInstall TFTP) are served only to the device's own address; PnP/ZTP reports and a selected box's serial are only accepted from its own address or its allocated mgmt IP (`net/pnp.py _own`); the UI/API refuses cross-site requests marked by `Sec-Fetch-Site`
- [ ] ZTP (Guest Shell Python) on a real image: IOL has no Guest Shell; needs Cat8000v or Cat9000v. **Blocked on the user**: Cisco serves the qcow2 only from software.cisco.com behind a Cisco account login (never type it for them, never use unofficial mirrors). The user puts e.g. `c8000v-universalk9_16G_serial.17.xx.qcow2` into `~/vrnetlab/cisco/c8000v` (WSL), then `make` there builds `vrnetlab/cisco_c8000v`; KVM works in WSL
- [x] **SNMPv3 informs from real IOS**, proven on the medium lab and on the real bench boxes. IOS sends **no** v3 informs until it knows the receiver: base.j2 has `snmp-server engineID remote <server_ip> <snmp_engine_id>` + `snmp-server user ... remote <server_ip> v3 ...` (engine ID line first, it localizes the keys); the receiver uses that fixed engine ID (cfg `snmp_engine_id`). pysnmp refuses an authNoPriv inform for a user that has priv, so authNoPriv boxes use the user `<snmp_user>-auth`
- [x] After PnP / ZTP / AutoInstall succeed, `Ctx.complete` asks the image over SSH (`?` help) and merges the full config (vty 5-15, `traps config` where the image has them); saved as config method `ssh-complete`
- [x] CPU: IOL 17.18 has no CISCO-PROCESS-MIB `cpmCPUTotalTable`; `snmp.poll` falls back to OLD-CISCO-CPU-MIB `avgBusy5`. Real Catalysts have the cpm table (first choice)
- [ ] Known limits: no NX-OS/XR, no PnP image upgrade, DHCP has no relay (giaddr) support, non-K9 (no crypto) images can't be managed (SSH only)
- [ ] Not yet on real hardware: ZTP, the Management network wizard (proven on IOL only), the AI agent

## Containerlab labs (WSL Debian, user `lucky`)

Note 2026-11-26: on this bench laptop (user `Sirirod`) WSL has **no distribution installed**; the labs below ran on the previous machine. Install Debian + containerlab again before using them (ask first: it is a download/install).

- containerlab 0.79 is setuid and `lucky` is in `clab_admins`: **no sudo needed**. Images: `vrnetlab/cisco_iol:17.18.02`, `vrnetlab/cisco_iol:L2-17.18.02`, `pandorabox-dev:latest` (built from `lab/Dockerfile`; the project is bind-mounted at `/app`, so code edits need no rebuild).
- **Keep `wsl -d Debian -- sleep infinity` running** (a background task). WSL stops an idle distro ~15 s after the last Windows-side command and every container dies with it ("Exited (0)"). This was misdiagnosed once as an NVRAM problem.
- Deploy with `CLAB_LABDIR_BASE=$HOME/clab containerlab deploy -t lab/<x>.clab.yml --reconfigure` (lab dir on the Linux disk).
- `docker restart` of a clab node loses its veth links: redeploy instead.
- If the keepalive ends (it did once, exit 4, after many hours), every IOL node shows `Exited (0)` and only the linux nodes come back on their own, without links. Recover: start the keepalive again, wait ~30 s for Docker, then `containerlab deploy ... --reconfigure` each lab (the first deploy right after WSL starts can fail; run it again).

| Lab | Nodes | Check | Notes |
|---|---|---|---|
| `lab/small.clab.yml` | pandora + core (router) + acc1/acc2 (L2), mgmt 172.30.30.0/24 | `docker exec clab-pandora-small-pandora python scripts/clab_check.py` | the check brings up core e0/1-2 (IOL router re-shuts ports after boot) |
| `lab/ztp.clab.yml` | pandora (eth1 10.99.0.1) + sw + blank1/blank3 (router) + blank2 (L2), mgmt 172.30.31.0/24 | `docker exec clab-pandora-ztp-pandora python scripts/ztp_check.py` | fresh deploy before every run; blanks boot only when the check starts the console relay |
| `lab/medium.clab.yml` | pandora + r1/r2 + d1/d2 + a1-a8, mgmt 172.30.32.0/24 | `docker exec clab-pandora-medium-pandora python scripts/clab_check.py lab/medium.clab.yml` | scale run; same checks as small |
| `lab/extra.clab.yml` + `lab/extra-pandora.sh` | a factory-blank IOL router `blank` cabled to the medium lab's PandoraBox (eth2, bridged with eth1 into br0); the app restarted on the same DB with DHCP/TFTP/PnP | onboard it by hand in the UI: it arrives over DHCP + PnP | added to a running medium lab without redeploying it; proven: DHCP (ciscopnp) -> PnP HELLO + device-info -> Identified, waiting for the user |
| `lab/large.clab.yml` | pandora + r1/r2 + d1-d4 + a1-a34, mgmt 172.30.33.0/24 | `docker exec clab-pandora-large-pandora python scripts/clab_check.py lab/large.clab.yml` | 40 IOL, ~6 GB; 16/16 incl. the design with 4 backbones |

How the blank IOL boxes work (`lab/ztp/blank.sh`): plain `linux` nodes running the IOL image with no `-c` config (an empty config file counts as a broken startup-config and stops AutoInstall), fresh NVRAM, IOL e0/0 = eth1, console = `script` pty dialled into `lab/ztp/console_relay.py` (ports 70NN device side, `socket://127.0.0.1:50NN` client side, log in `/tmp/console-NN.log`). The vrnetlab entrypoint is skipped because it flushes eth0, which carries the console.

IOL facts: 4 ports per slot (e0/0 = clab mgmt in configured nodes), vty 0-4, IOL MAC = `aa:bb:cc:00:<IOL_PID hex>:00`, router image has no `traps config`, L2 image has no SNMP AES and its AutoInstall never sends DHCP, neither has Guest Shell.

## Tooling traps on this machine

- Windows PowerShell 5.1 mangles double quotes inside `python -c "..."` and `git commit -m @'...'@` arguments: put Python in a script file (scratchpad) and commit with `git commit -F <file>`.
- Seeing what a device really does: `scapy` sniff on `Ethernet` (Npcap) works from the venv; mask secrets (`pandora.db.mask_secrets`) before printing captured config and delete captures afterwards (the boot config carries the admin password and SNMP keys in clear).
- Reading the switch without disturbing it: open COM7 with pyserial, answer `no` to the setup dialog only, run `show` commands; never type during PnP/AutoInstall.
- Git Bash on Windows: pass `MSYS_NO_PATHCONV=1` before `wsl.exe ... docker cp /mnt/c/...` or the path is rewritten to `C:/Program Files/Git/...`.
- `$var` inside `wsl.exe -- bash -c '...'` from Git Bash can arrive empty: put the script in a file and pipe it (`docker exec -i <c> bash < script.sh`).
- `/tmp` inside a lab container is wiped on redeploy: `docker cp` helper scripts again.

## Where things are

`pandora/deliver.py` (workflow, probe, parse_caps, factory_again, stage_two, save_over_ssh, learn_from_neighbor), `pandora/alloc.py` (allocation, guess_ports, model_kind, parse_ifnames), `pandora/console.py`, `pandora/compliance.py`, `pandora/monitor.py` + `alerts.py` (reachability, backups on config writes), `pandora/snmp.py`, `pandora/net/` (dhcp, tftp, pnp, sniff), `pandora/templates/base.j2`, `pandora/api/*`, `pandora/web/*`, `setup.ps1`, `run.ps1`, `scripts/*_check.py`, `lab/*`, `docs/real-lab.md` (bench runbook), `docs/research.md` (what was learned from other projects).

## Medium lab (scale run)

- [x] topology written: `lab/medium.clab.yml`, 12 IOL (r1, r2 routers; d1, d2 distribution; a1-a8 access, access pairs cross-linked), 16 cabled links, mgmt 172.30.32.0/24
- [x] `scripts/clab_check.py <topology>` reads the lab file: nodes, roles (no `type: L2` = router), expected CDP links, and the first free port per node as its mgmt port (every node must keep one free port; IOL has 4 ports per slot)
- [x] deployed and run on 2026-11-25: **9/9**, about 3 GB RAM for the whole lab

Numbers from that run (all devices handled in parallel):

| Step | 12 nodes | 3 nodes (small lab) |
|---|---|---|
| add by IP + login | 2.2 s | 2.1 s |
| SSH merge pre-config (probe + push + save) | 24 s | 24 s |
| compliance of every node | 3.3 s | 3.2 s |
| SNMPv3 poll of every node | 5.9 s → **1.5 s** after the fix below | 1.3 s |
| CDP topology, every cabled link | 16/16 in 4.8 s → 2.0 s | 3/3 in 1.0 s |

- [x] SNMP polling grew with device count even when `gather`ed. Profiled: 70% of the time was `pysnmp.smi.builder.load_modules`, i.e. building a new `SnmpEngine` (MIB load, ~60 ms of CPU that blocks the loop) for **every walk**, 5 per poll. Fix: `snmp.session(ip)` = one engine + target per device operation, shared by all walks of `poll` / `neighbors` / `identify` (also keeps the SNMPv3 engine-ID discovery). One poll 0.37 s → 0.11 s, 12 devices 4.5 s → 1.1 s. `monitor.poll_forever` now polls up to 16 devices concurrently instead of one by one.
- [ ] Remaining cost is ~60 ms engine build per device (≈ 9 s of CPU per minute at 100 devices, interleaved with the UI on the same loop). If a big site needs more: share one engine per event loop and rebuild it after a transport error (the reason it is per-device today: an ICMP "port unreachable" on Windows, WSAECONNRESET, kills a shared socket)
- Note: after hostnames change, neighbors keep the old names in their CDP cache for the 180 s holdtime, so the topology briefly shows them as external nodes (seen as "17/16 links" in a rerun)
- [x] Large lab `lab/large.clab.yml` (40 IOL: 2 routers, 4 L3 backbones d1-d4, 34 access, 56 links; generated; ~6 GB RAM, destroy the other labs first). Day-2 scales well, nothing queues: add+login 7 s, SSH pre-config of all 40 in 34 s, compliance 10 s, SNMPv3 poll 8 s, CDP 56/56 in 18 s. Design: plan fine (4 domains, 36 members, 76 trunks). Apply first left 8 members unverified at the 150 s window; `mgmt.apply` now waits until **every** switch in the design has no LIS/LRN port before judging any address (window 150 s + 5 s per device), and then reached all 40 (213 s)
- [x] **Unicast flooding after the design (found on the large lab, then in 1 of 4 medium runs)**: SSH stalls (ReadTimeout), 17-47 % ping loss, backbones flooding ~700-3000 pps out of every trunk (IOL counts the drops as "collisions"), lost BPDUs, RSTP churn. Root cause: **asymmetric routing**. The PC reaches a member through its backbone in the domain VLAN, but the member replies on its still-connected ops VLAN 99 address, so no switch ever learns the member's domain-VLAN MAC and every packet to it is flooded through the domain. Fix: retire the old addresses right after the design (the wizard says why); `mgmt.retire` first checks that the member reaches its own gateway (`ping <gw>`). Result: medium 16/16 and **large (40 IOL) 16/16**; the after-design checks are back to 5 s / 15 s. Ruled out on the way: MAC table size ("Space Available: 0" is shown even with 54 entries) and switch CPU (1-4 %). A root-priority line on backbones made no difference and was removed
