# PandoraBox

Zero-touch pre-config for Cisco IOS / IOS-XE, run from one Windows laptop.

**Discover** (DHCP, PnP, console, SNMP, CDP/LLDP) → **Inventory** → you **select** → **preview** (conflict-free hostname, mgmt IP, reserved mgmt ports) → **pre-config** via PnP, ZTP, AutoInstall, console, or SSH → topology, extra config, web terminal, SNMP monitoring, and an approval-gated AI agent.

## Setup (Windows)

1. Use a **dedicated NIC** cabled to the Cisco gear: a static IP (e.g. `10.99.0.1/24`) and **no gateway**. PandoraBox refuses to run DHCP on a NIC that looks like a real network.
2. Install the dependencies: `pip install -e .[dev]`. Install [Npcap](https://npcap.com) for CDP/LLDP sniffing (optional).
3. `copy pandora.toml.example pandora.toml` and edit `iface` / `server_ip`.
4. Set the secrets (never stored in files):
   ```powershell
   $env:PANDORA_ADMIN_PASSWORD = "..."   # local user pushed to devices
   $env:PANDORA_SNMP_AUTH = "..."        # SNMPv3 auth, >= 8 chars
   $env:PANDORA_SNMP_PRIV = "..."        # SNMPv3 priv, >= 8 chars
   $env:ANTHROPIC_API_KEY = "..."        # only for the agent with provider = "claude"
   ```
5. Check the laptop before cabling anything. It verifies secrets, the NIC, the ports, the IP ranges, Npcap, the firewall and consoles, and says what to fix:
   ```powershell
   python -m pandora --preflight
   ```
6. Run it from an **Administrator** PowerShell. If binding fails, it prints the `netsh` firewall rules to add.
   ```powershell
   python -m pandora
   ```
   Open http://127.0.0.1 (the UI answers only to this laptop). `--no-dhcp` runs only the console, SNMP, and SSH features.

For a first run on real switches, follow [docs/real-lab.md](docs/real-lab.md) step by step.

**Cabling:** plug the laptop into one of the **reserved mgmt ports** (by default the last two ports of each switch). After pre-config those ports move to the mgmt VLAN (99) in the same subnet, so the laptop keeps reaching the device.

## How each device gets its config

| Device | Path | Trigger |
|---|---|---|
| IOS-XE with PnP agent | PnP | DHCP opt 43. Identified right away; gets config only after you select it |
| IOS-XE 16.5+ | ZTP | DHCP opt 67 → `/ztp/bootstrap.py` (Guest Shell) |
| Classic IOS | AutoInstall | DHCP opt 150/67 → per-MAC file over TFTP; an EEM applet saves it |
| Anything on console | Console | setup dialog skipped, paste, `write memory`. COM port or a console server port (`socket://host:port`, `rfc2217://…`, listed in `console_urls`) |
| Already configured | SSH | port 22 open → asks you for credentials, then merges |

Factory devices that aren't selected get no boot options (PnP ones get only `backoff`), so nothing is configured until you click **Pre-config selected**.

## After pre-config: the management network

The **Management** page is a wizard for the network you manage the devices through, once they are pre-configured:

1. **Backbones:** pick one or more L3 switches. Each owns a management domain: its own VLAN and subnet, and its VLAN interface is the gateway.
2. **Members:** every other device goes under a backbone. PandoraBox suggests the nearest one from the CDP cabling.
3. **Review:** the exact lines per device, the ports that become trunks (shortest point-to-point path to the backbone, never a reserved PC port or a shared segment), and the routes to add on the PC.
4. **Apply:** backbones first, then everyone else. Every device gets its own SSH address in its domain (switches: an SVI and default gateway; routers: a dot1Q subinterface on the uplink plus routes, never a default route). PandoraBox switches to the new address only once SSH answers there.

The PC keeps its one LAN card on the pre-config management VLAN (99) and reaches each domain through that domain's backbone. Nothing existing is removed, so the old addresses keep working while you check.

## Safety rails

- Hostname and mgmt IP are allocated under UNIQUE constraints, so two devices can never get the same one.
- The reserved mgmt ports, mgmt VLAN/SVI, `pandora` user, SSH, and SNMP lines are protected. The wizard, extra config, and agent can't touch them (the UI has an explicit override).
- Agent: read-only commands run freely. Every config change shows the lines and waits for **Approve**, takes a flash snapshot first (`rollback` = `configure replace`), and is written to the audit table.
- Stored configs have secrets masked. Credentials you type live only in memory.

## After pre-config: day-2 features

Ideas adapted from Oxidized, Nautobot Golden Config, Zabbix, LibreNMS, NetBox and Catalyst Center (design only, no code copied). See [docs/research.md](docs/research.md).

- **Config backup:** running-config fetched every 6 h and right after a `configChange` trap, stored only when it changed, with a diff between any two versions.
- **Compliance:** the latest backup compared with what PandoraBox intends, per feature (hostname, management VLAN, management ports, login/SSH, SNMP, role). A drifted device gets a problem, and a **fix** plan you review before it is pushed.
- **Problems:** severity, acknowledge with a note, close on their own when the cause is gone (port down, management port down, CPU ≥ 80%, no SNMP answer, failed pre-config, drift, reboot).
- **UI:** Bench (every device as its faceplate, with link LEDs and yellow tape on the management ports), Devices with search, state filters, CSV export and a 4-step onboarding, a device page (overview, config, push, terminal, history), Topology coloured by problems, Problems, Agent. Light and dark themes, works on a phone.
- **More device models:** drop YAML files from the CC0 [NetBox devicetype-library](https://github.com/netbox-community/devicetype-library) into `devicetypes/` and their port names are used for reserved ports.

## Code layout

```
pandora/
  app.py            composition: security middleware, background jobs, live events
  api/              HTTP routes, one module per domain (inventory, configs, monitoring, agent, terminal)
  deliver.py        onboarding workflow: preview -> queue -> push (PnP / ZTP / AutoInstall / console / SSH)
  alloc.py          conflict-free hostname, mgmt IP, reserved ports + change guard
  platforms.py      per-OS knowledge (netmiko driver, backup command, volatile lines)
  backup.py  compliance.py  alerts.py  monitor.py   day-2 features and background jobs
  net/              DHCP, TFTP, PnP/ZTP HTTP, CDP/LLDP sniffing
  agent/            LLM providers, tools, loop
  web/              index.html, css/, js/ (ES modules, no build step; views/ = one file per page)
tests/              unit tests (pytest)
scripts/mvp_check.py  end-to-end check against a simulated lab (fake IOS over SSH/console, snmpsim)
```

## Tests

```powershell
python -m pytest
```

```powershell
python scripts/mvp_check.py
```

### Real Cisco IOL in containerlab (WSL Debian)

Keep `wsl -d Debian -- sleep infinity` open (WSL stops an idle distro and every container with it), then:

| Lab | Deploy | Check | Covers |
|---|---|---|---|
| [lab/small.clab.yml](lab/small.clab.yml) | `CLAB_LABDIR_BASE=$HOME/clab containerlab deploy -t lab/small.clab.yml --reconfigure` | `docker exec clab-pandora-small-pandora python scripts/clab_check.py` | day-2: add by IP, SSH merge, backup, compliance + fix, SNMPv3, CDP topology, web terminal |
| [lab/medium.clab.yml](lab/medium.clab.yml) | same, `lab/medium.clab.yml` | `docker exec clab-pandora-medium-pandora python scripts/clab_check.py lab/medium.clab.yml` | the same day-2 checks on 12 nodes / 16 links, all devices in parallel |
| [lab/ztp.clab.yml](lab/ztp.clab.yml) | same, `lab/ztp.clab.yml` (fresh deploy before every run) | `docker exec clab-pandora-ztp-pandora python scripts/ztp_check.py` | factory-blank boxes: DHCP discovery, PnP, AutoInstall, console over `socket://` |

What real IOS-XE 17.18 (IOL) taught us, now handled in the code:
- Images differ: vty 0-4 only, no AES on the L2 image, no `traps config` on the router image. Before an SSH or console push PandoraBox asks the box with `?` help and renders to match. SNMP falls back to authNoPriv only if `snmp_allow_auth_nopriv = true`.
- PnP rolls back the whole file on one rejected line, so boot files (PnP/AutoInstall/ZTP) use only lines every IOS accepts.
- Any console input ends a factory box's AutoInstall/PnP: the console watcher listens first and leaves a zero-touching box alone.
- IOS hides defaults (`no shutdown`, `ip ssh version 2`), widens trap lists and keeps VLANs in vlan.dat under VTP server: compliance accounts for all of these.
- Not testable on IOL: ZTP (no Guest Shell; needs Cat8000v/Cat9000v), DHCP from the L2 image (its AutoInstall loop never sends DHCP), SNMP informs (the lab reaches devices through containerlab's mgmt VRF).

`python -m ruff check pandora tests scripts` runs the lint rules in `pyproject.toml`. `mvp_check.py` needs `pip install snmpsim pysmi`; add `--serve` to keep the simulated lab and the UI up on http://127.0.0.1:8099.

Known limits: IOS/IOS-XE only (no NX-OS POAP / XR). PnP doesn't do image upgrades. DHCP doesn't support relays (giaddr). The UI needs no internet: fonts and xterm.js are vendored in `pandora/web/vendor/` (`scripts/vendor_web.py` refreshes them).
