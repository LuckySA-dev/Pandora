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
- [x] Git repo on `main` (no remote). Commit when a piece of work is verified; `.gitattributes` keeps LF so the lab scripts run in Linux containers.

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
- [x] `python -m pytest` → 40 passed
- [x] `python -m pandora --preflight` checks a laptop for a real run (secrets, NIC, ports 67/69/162/80, ranges, Npcap, firewall, consoles, SNMP AES, agent)
- [x] `python scripts/mvp_check.py` (simulated lab) → 23/23
- [x] `scripts/clab_check.py` on `lab/small.clab.yml` (real IOL, day-2) → 9/9
- [x] `scripts/ztp_check.py` on `lab/ztp.clab.yml` (factory-blank IOL: DHCP, PnP, AutoInstall, console) → 5/5
- [x] `scripts/clab_check.py lab/medium.clab.yml` (12 real IOL, parallel) → 14/14 incl. management design + its compliance
- [x] `python -m ruff check pandora tests scripts lab` clean

- [x] **Management network wizard** (Management page, `pandora/mgmt.py`, `api/mgmt.py`, `web/js/views/mgmt.js`): after pre-config, choose L3 backbone(s) (one domain = VLAN + subnet each), members under them (suggested from CDP), review, apply. Proven on the medium IOL lab: d1/d2 backbones, 10 members incl. 2 routers via dot1Q subinterfaces, 20 trunk ports, all 12 reachable over SSH on their new addresses from one PC NIC (`clab_check.py lab/medium.clab.yml`, 13/13)
  - design: ops VLAN 99 stays (PC + every device already there, make-before-break); backbone = `ip routing` + SVI gateway + static routes to other domains via their ops IP; switch member = SVI + `ip default-gateway` (or static routes if it routes); router member = subinterface + routes to mgmt subnets only (no default route); trunks = shortest point-to-point CDP path, ops VLAN on backbone-to-backbone paths
  - lessons from real IOL: a port that hears several CDP neighbors is a shared segment (IOL e0/0, a real OOB mgmt switch) and must never be a trunk path; IOS answers some failures with "% Command rejected", so the push treats every `%` line except warnings as an error
  - [x] compliance checks the design: `mgmt_config` stores what apply pushed per device (incl. per-port dot1q/native extras); `compliance.run` adds it to the intended config as feature **mgmt-design**, with IOS display rules (no allowed-VLAN list = all; split `allowed vlan` + `add` lines; `ip routing` hidden when default; design VLANs read from vlan.dat). Proven: medium lab 14/14 (twice), an edited domain SVI on a1 is flagged as mgmt-design and fixed by remediation. Security review: reserved ports/ops VLAN keep their strict feature even if a design line named them; only canonical `allowed vlan` forms are trusted; `ip routing` counts as held unless the box shows `no ip routing`
  - [ ] SSH through the domain address is slow to connect in the lab (the drift check took 35-90 s vs 15 s on the clab address): look at it on real gear before blaming the code
  - lesson: the lab's drift test must not cut its own management path (removing the member's gateway made it depend on ARP over VLAN 99 and failed once in three runs)
  - by design (user confirmed): **a backbone is always an L3 switch**, never a router; routers only join as members (dot1Q subinterface on their uplink). The wizard offers only switches, and `mgmt.plan` refuses a router backbone
  - [ ] not yet: removing the old VLAN 99 addresses is left to the operator; an L2 path through a router is refused (cable members to switches); an L2-only switch picked as backbone is only caught when `ip routing` fails at apply

## Not done / next

- [x] **Medium lab (12 IOL nodes) scale run**: 9/9, see the section at the end
- [ ] **SSH host keys are not verified** (paramiko `AutoAddPolicy` in the web terminal, netmiko defaults elsewhere): fine on an isolated provisioning segment, must be trust-on-first-use before production use. Record each device's key after pre-config (pre-config generates the RSA key on factory boxes), store it with the device, reject a changed key with a clear problem; apply to netmiko and the terminal alike
- [x] UI works offline after a clone: fonts (OFL) and xterm.js + fit (MIT) vendored in `pandora/web/vendor/` by `scripts/vendor_web.py`; verified 0 external requests in the browser
- [x] Laptop with internet + switch on the dedicated NIC: preflight and startup probe for another DHCP server on the segment (scapy DISCOVER; verified against a Cisco `ip dhcp pool` in the ztp lab) and refuse to serve DHCP if one answers; preflight fails if another NIC overlaps the provisioning subnet
- [x] Security review round 3: `/ztp/done` writes to the checked row by id (`db.update`), and a serial already on another row is refused; `_own` never trusts a selected or reported-on row without a known address; the other-DHCP-server check fails closed (no Npcap/raw access = refuse DHCP unless `--assume-isolated`)
- [x] Security review round 2: a selected box with no known address can't be claimed by serial; the allocated mgmt IP counts as the box's address only once its config was sent (state provisioning); `/ztp/done` must name the serial of the box it comes from; a boot file is served only for the device's own delivery path
- [x] Security review 2026-11-25 fixed: boot configs (PnP `/cfg`, ZTP `/ztp/cfg`, AutoInstall TFTP) are served only to the device's own address; PnP/ZTP reports and a selected box's serial are only accepted from its own address or its allocated mgmt IP (`net/pnp.py _own`); the UI/API refuses cross-site requests marked by `Sec-Fetch-Site`
- [ ] ZTP (Guest Shell Python) on a real image: IOL has no Guest Shell; needs Cat8000v or Cat9000v (vrnetlab, KVM is available in WSL). Ask the user before downloading images.
- [ ] SNMP informs from real devices: the lab reaches devices through containerlab's `clab-mgmt` VRF, so informs need `snmp-server host ... vrf clab-mgmt` (lab only) or a data-plane path to PandoraBox
- [ ] Optional: after PnP/AutoInstall succeed, auto-run an SSH probe + merge to add capability-dependent lines (`traps config`, vty 5-15)
- [ ] CPU OID returns nothing on IOL (`cpu ?%`); check on a real Catalyst
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

Running now (2026-11-25): small and medium labs are up; the ztp lab was destroyed (it needs a fresh deploy per run anyway). Destroy with `CLAB_LABDIR_BASE=$HOME/clab containerlab destroy -t lab/<x>.clab.yml --cleanup`.

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
- [ ] Next scale step: a large lab (~40 IOL) to see where SSH pushes and the SQLite writes start to queue
