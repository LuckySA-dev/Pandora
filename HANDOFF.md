# PandoraBox handoff

For the next agent picking this up. README.md is for users; this file is the working state: what is done, what is not, and the traps that cost time. Update it when you finish something.

Last updated: 2026-11-25.

## What the project is

PandoraBox is one Windows-laptop program for pre-configuring factory **Cisco IOS / IOS-XE** gear:
- discover (DHCP, PnP, CDP/LLDP, SNMP sweep, console) → inventory → the user selects → conflict-free pre-config (unique hostname + mgmt IP, 1-2 reserved mgmt ports on the mgmt VLAN)
- delivery over PnP, ZTP, AutoInstall, console paste, or SSH merge (SSH already on → ask for credentials first)
- day-2: backup + diff, compliance + fix, SNMPv3 polling and informs, problems, CDP topology, web terminal, AI agent (tool loop with approvals; Claude or Ollama)

Stack: Python 3.12, FastAPI, SQLite, netmiko/paramiko, pysnmp 7, tftpy, scapy, Jinja2. Web UI: plain HTML + ES modules, no build step.

## Ground rules (from the user)

- [ ] Never type passwords or sudo passwords for the user. Secrets only from env vars: `PANDORA_ADMIN_PASSWORD`, `PANDORA_SNMP_AUTH`, `PANDORA_SNMP_PRIV`, `ANTHROPIC_API_KEY`. Device credentials typed in the UI stay in memory.
- [ ] Ask before downloads/installs beyond the project's dependencies.
- [ ] GPL projects (Zabbix, LibreNMS) are design reference only, no code. Apache/MIT code we adapted is credited in `NOTICE` (Oxidized, hier_config, WebSSH, NetBox).
- [ ] Reply to the user in Thai; code, comments and docs in English.
- [x] Git repo on `main`, pushed to GitHub `origin` when the user says so. Commit when a piece of work is verified; `.gitattributes` keeps LF so the lab scripts run in Linux containers.

## Done

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

Verification (all green on 2026-11-25)
- [x] `python -m pytest` → 48 passed
- [x] `python -m pandora --preflight` checks a laptop for a real run (secrets, NIC, ports 67/69/162/80, ranges, Npcap, firewall, consoles, SNMP AES, agent)
- [x] `python scripts/mvp_check.py` (simulated lab, port 8097 since the small lab publishes 8099) → 24/24 (incl. SSH host-key impostor check)
- [x] `scripts/clab_check.py` on `lab/small.clab.yml` (real IOL, day-2) → 9/9
- [x] `scripts/ztp_check.py` on `lab/ztp.clab.yml` (factory-blank IOL: DHCP, PnP, AutoInstall, completion over SSH, console) → 6/6
- [x] `scripts/clab_check.py lab/medium.clab.yml` (12 real IOL, parallel) → 16/16 incl. management design + its compliance, SNMPv3 informs from all 12 nodes, retiring the old addresses
- [x] `scripts/clab_check.py lab/large.clab.yml` (40 real IOL, 4 backbones) → 16/16
- [x] `python -m ruff check pandora tests scripts lab` clean

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
- [x] **SSH host keys, trust on first use** (`pandora/hostkeys.py`, table `host_keys`): the first key a device shows is pinned to the device (not the IP, so the management design keeps it); a different key is refused before the password is sent (`hostkeys.Pin` is paramiko's policy for netmiko via `deliver.connect(params, pin)` and for the web terminal) and opens a `ssh-host-key` problem (high) with a "Trust new key" button (`POST /api/devices/{id}/forget-host-key`). A box PandoraBox re-provisions from factory (boot file served, console factory push) forgets its pin first. Proven: mvp_check (impostor key refused, problem, forget → re-pinned) and real IOL (all medium logins pinned and verified incl. after the design)
- [x] UI works offline after a clone: fonts (OFL) and xterm.js + fit (MIT) vendored in `pandora/web/vendor/` by `scripts/vendor_web.py`; verified 0 external requests in the browser
- [x] Laptop with internet + switch on the dedicated NIC: preflight and startup probe for another DHCP server on the segment (scapy DISCOVER; verified against a Cisco `ip dhcp pool` in the ztp lab) and refuse to serve DHCP if one answers; preflight fails if another NIC overlaps the provisioning subnet
- [x] Security review round 3: `/ztp/done` writes to the checked row by id (`db.update`), and a serial already on another row is refused; `_own` never trusts a selected or reported-on row without a known address; the other-DHCP-server check fails closed (no Npcap/raw access = refuse DHCP unless `--assume-isolated`)
- [x] Security review round 2: a selected box with no known address can't be claimed by serial; the allocated mgmt IP counts as the box's address only once its config was sent (state provisioning); `/ztp/done` must name the serial of the box it comes from; a boot file is served only for the device's own delivery path
- [x] Security review 2026-11-25 fixed: boot configs (PnP `/cfg`, ZTP `/ztp/cfg`, AutoInstall TFTP) are served only to the device's own address; PnP/ZTP reports and a selected box's serial are only accepted from its own address or its allocated mgmt IP (`net/pnp.py _own`); the UI/API refuses cross-site requests marked by `Sec-Fetch-Site`
- [ ] ZTP (Guest Shell Python) on a real image: IOL has no Guest Shell; needs Cat8000v or Cat9000v. **Blocked on the user**: Cisco serves the qcow2 only from software.cisco.com behind a Cisco account login (never type it for them, never use unofficial mirrors). The user puts e.g. `c8000v-universalk9_16G_serial.17.xx.qcow2` into `~/vrnetlab/cisco/c8000v` (WSL), then `make` there builds `vrnetlab/cisco_c8000v`; KVM works in WSL
- [x] **SNMPv3 informs from real IOS**, proven on the medium lab (linkDown from all 12 nodes through the management domains, each from its own address). Two real bugs fixed: IOS sends **no** v3 informs (0 Inform-request PDUs) until it knows the receiver: base.j2 now has `snmp-server engineID remote <server_ip> <snmp_engine_id>` + `snmp-server user ... remote <server_ip> v3 ...` (engine ID line first, it localizes the keys); the receiver uses that fixed engine ID (cfg `snmp_engine_id`). And pysnmp refuses an authNoPriv inform for a user that has priv, so authNoPriv boxes use the user `<snmp_user>-auth` (`snmp.user(cfg, level)`, both users on the receiver). The lab's PandoraBox server_ip is now its eth1 address (10.99.0.1) when it is cabled to a node, like a real laptop
- [x] After PnP / ZTP / AutoInstall succeed, `Ctx.complete` asks the image over SSH (`?` help) and merges the full config (vty 5-15, `traps config` where the image has them); saved as config method `ssh-complete`. ztp lab: both boxes completed and compliant (IOS leaves `ip dhcp client client-id ascii ...` on the boot port: ignored by compliance)
- [x] CPU: IOL 17.18 has no CISCO-PROCESS-MIB `cpmCPUTotalTable`; `snmp.poll` falls back to OLD-CISCO-CPU-MIB `avgBusy5` (1.3.6.1.4.1.9.2.1.58.0), which IOL answers. Real Catalysts have the cpm table (first choice)
- [ ] Known limits: no NX-OS/XR, no PnP image upgrade, DHCP has no relay (giaddr) support
- [ ] **Real hardware run**: follow [docs/real-lab.md](docs/real-lab.md) (laptop prep, `python -m pandora --preflight` until Ready, factory reset, discovery, each path, day-2, report table). Ready to start; on this laptop preflight currently fails only on things the user sets up: the 3 secrets, the dedicated NIC "Ethernet 2" with 10.99.0.1, and the firewall rules

## Containerlab labs (WSL Debian, user `lucky`)

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
| `lab/large.clab.yml` | pandora + r1/r2 + d1-d4 + a1-a34, mgmt 172.30.33.0/24 | `docker exec clab-pandora-large-pandora python scripts/clab_check.py lab/large.clab.yml` | 40 IOL, ~6 GB; 16/16 incl. the design with 4 backbones |

Running now (2026-11-25): only the large lab is up (~6 GB; small, medium and ztp were destroyed; redeploy as needed). Destroy with `CLAB_LABDIR_BASE=$HOME/clab containerlab destroy -t lab/<x>.clab.yml --cleanup`.

How the blank IOL boxes work (`lab/ztp/blank.sh`): plain `linux` nodes running the IOL image with no `-c` config (an empty config file counts as a broken startup-config and stops AutoInstall), fresh NVRAM, IOL e0/0 = eth1, console = `script` pty dialled into `lab/ztp/console_relay.py` (ports 70NN device side, `socket://127.0.0.1:50NN` client side, log in `/tmp/console-NN.log`). The vrnetlab entrypoint is skipped because it flushes eth0, which carries the console.

IOL facts: 4 ports per slot (e0/0 = clab mgmt in configured nodes), vty 0-4, IOL MAC = `aa:bb:cc:00:<IOL_PID hex>:00`, router image has no `traps config`, L2 image has no SNMP AES and its AutoInstall never sends DHCP, neither has Guest Shell.

## Tooling traps on this machine

- Shell is Git Bash on Windows: pass `MSYS_NO_PATHCONV=1` before `wsl.exe ... docker cp /mnt/c/...` or the path is rewritten to `C:/Program Files/Git/...`.
- `$var` inside `wsl.exe -- bash -c '...'` from Git Bash can arrive empty: put the script in a file and pipe it (`docker exec -i <c> bash < script.sh`).
- `/tmp` inside a lab container is wiped on redeploy: `docker cp` helper scripts again.
- A GateGuard hook asks for "facts" (importers, affected API, data, the user's instruction) before the first edit of each file and before the first shell command: state them and retry.

## Where things are

`pandora/deliver.py` (workflow, probe, parse_caps), `pandora/console.py`, `pandora/compliance.py`, `pandora/snmp.py`, `pandora/templates/base.j2`, `pandora/api/*`, `pandora/web/*`, `scripts/*_check.py`, `lab/*`, `docs/research.md` (what was learned from other projects), plan: `C:\Users\User\.claude\plans\project-pandorabox-preconfig-soft-twilight-of-00f8793b-927c-426b-92d9-5f1a3e1173b8.md`.

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
