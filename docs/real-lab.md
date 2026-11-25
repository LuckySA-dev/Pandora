# First run on real Cisco gear

A step-by-step runbook for the first test of PandoraBox on real switches and routers, cabled to the Windows laptop. Each step says what to do, what you should see, and what to note down. It follows what we already proved on Cisco IOL in containerlab (see the README), so a difference from what is written here is a finding worth recording.

## What to bring

- The Windows laptop with PandoraBox installed (`pip install -e .[dev]`) and a **second NIC** (USB Ethernet is fine) used only for the Cisco gear.
- An unmanaged switch or the access switch under test, to connect the laptop NIC to several devices at once.
- A USB console cable (or a console server port).
- Ideally one box of each kind: an IOS-XE switch with PnP (Catalyst 9200/9300), a classic IOS switch (2960/3750), an IOS-XE router (ISR 4000 / Catalyst 8000), and one box that already has a config with SSH.
- Nothing from the office network on this segment: PandoraBox runs a DHCP server on it.

## Laptop on the internet as well

That is fine and expected: keep Wi-Fi (or the office LAN) for the internet and use a **second NIC** for the Cisco gear. What matters:

- **The dedicated NIC:** static IP, no gateway, nothing else on it. PandoraBox refuses to serve DHCP on a NIC that gets its address by DHCP or has a gateway, so plugging the switch into the NIC that has the internet is refused, not an outage.
- **The switch under test must not be uplinked to a real network.** If it is, that network's DHCP server and PandoraBox's would both answer. PandoraBox sends one DHCP DISCOVER before it starts serving and refuses to run DHCP if anyone else answers (preflight shows the same check). The check needs Npcap and an Administrator window; if it can't run, PandoraBox refuses too, unless you start it with `--assume-isolated` after making sure yourself that the switch has no uplink.
- **Different subnets:** if the Wi-Fi network is also 10.99.0.x, device traffic can leave by the wrong NIC. Preflight fails on an overlap; change `server_ip` and the ranges.
- **The UI needs no internet:** fonts and the terminal library ship with the project.

## 1. Prepare the laptop (once)

Give the dedicated NIC a static address and no gateway. Use the adapter name from `Get-NetAdapter`; in an Administrator PowerShell:

```powershell
New-NetIPAddress -InterfaceAlias "Ethernet 2" -IPAddress 10.99.0.1 -PrefixLength 24
```

Allow DHCP, TFTP, SNMP informs and HTTP in (Administrator PowerShell):

```powershell
netsh advfirewall firewall add rule name="PandoraBox" dir=in action=allow protocol=UDP localport=67,69,162
```

```powershell
netsh advfirewall firewall add rule name="PandoraBox-HTTP" dir=in action=allow protocol=TCP localport=80
```

Copy the example config and set `iface` to the adapter name:

```powershell
copy pandora.toml.example pandora.toml
```

Set the secrets in the PowerShell window that will run PandoraBox. They are never written to a file; pick your own values, at least 8 characters each:

```powershell
$env:PANDORA_ADMIN_PASSWORD = Read-Host "admin password for devices"
```

```powershell
$env:PANDORA_SNMP_AUTH = Read-Host "SNMPv3 auth key"
```

```powershell
$env:PANDORA_SNMP_PRIV = Read-Host "SNMPv3 priv key"
```

Then check everything until it says **Ready**:

```powershell
python -m pandora --preflight
```

- [ ] preflight says Ready (warnings for Npcap, the agent key or consoles are fine to start with)

## 2. Start PandoraBox

In the same Administrator PowerShell:

```powershell
python -m pandora
```

Open http://127.0.0.1 on the laptop.

- [ ] the UI opens, Bench and Devices are empty
- [ ] the log says `DHCP listening on 10.99.0.1:67`

## 3. Make the boxes factory-fresh

On each test box (not the one that should keep its config), from its console: `write erase`, then `reload`, answer **no** to saving. On a switch also delete `flash:vlan.dat` for a clean VLAN table.

Important, seen in the lab: **once the box reloads, do not press any key on its console.** IOS-XE prints "Autoinstall will terminate if any input is detected on console": one keypress ends PnP/AutoInstall. PandoraBox's own console watcher only listens while a box is zero-touching.

## 4. Discovery: nothing is configured until you select

Cable the boxes to the laptop NIC (through the switch) and let them boot.

- [ ] each box appears on Devices within a minute or two, source `dhcp`, with its MAC
- [ ] IOS-XE boxes show vendor class `ciscopnp` and delivery **PnP**; a PnP box then shows its serial and PID (device-info) while staying **identified**
- [ ] classic IOS boxes show delivery **AutoInstall**
- [ ] no box gets a hostname or mgmt IP yet: check one console, it is still at the factory prompt
- [ ] a box that already has SSH shows **needs credentials** when selected

Record for each box: model, IOS version, MAC, what PandoraBox showed, how long until it appeared.

## 5. Pre-config each path

Select one box at a time on Devices, pick its role and reserved mgmt port(s), check the preview (unique hostname and mgmt IP, no red problems), then **Pre-config selected**. The laptop must stay cabled to a port that ends up in the mgmt VLAN (the reserved ports), or reach the box through the access switch.

| Path | How to test | Expect |
|---|---|---|
| PnP (IOS-XE) | select the PnP box | config-upgrade, then **provisioned** and "PnP config applied + saved"; SSH works on the new mgmt IP |
| AutoInstall (classic IOS) | select the 2960/3750 | it fetches `pandora-<mac>.cfg` over TFTP, an EEM applet saves it, PandoraBox verifies SSH on the new IP |
| ZTP (IOS-XE 16.5+) | set Delivery to **ZTP** before selecting, then reload the box so its next DHCP gets option 67 | Guest Shell runs `bootstrap.py`, the box reports back, **provisioned** |
| Console | factory box on the USB console, Delivery **Console** | setup dialog skipped, config pasted, `write memory`, SSH on the new IP |
| SSH merge | the box that already has a config | asks for credentials, merges only PandoraBox's sections, existing config kept |

- [ ] every path ends **provisioned**; on **failed**, copy the note (it holds what the box said)
- [ ] on each box, `show running-config` has the reserved port(s) in VLAN 99 (switches), the `pandora` user, SSH, and the SNMPv3 group
- [ ] two boxes never got the same hostname or mgmt IP

ZTP is the one path not yet proven on a real image (IOL has no Guest Shell), so it is the most likely to need a fix.

## 6. Day-2 on the provisioned boxes

- [ ] Device page → Config: a backup exists; **Check compliance** says compliant
- [ ] shut a reserved mgmt port by hand, check compliance again: drift shown, the fix plan has `no shutdown`, **Fix** makes it compliant
- [ ] SNMP: interface states and counters appear within a minute (Bench LEDs, device Interfaces tab)
- [ ] pull a cable: a linkDown inform arrives and a problem opens; plug it back: the problem closes
- [ ] Topology shows the CDP links between the boxes, on the right ports
- [ ] Terminal: prompt appears, typing has no lag, backspace and Ctrl+C work, `show run` scrolls
- [ ] Agent (if an API key is set): "add VLAN 20 on <port> of <switch>": it looks, proposes, waits for Approve, applies, verifies

## 7. Management network (after pre-config)

Plug the PC (one LAN card is enough) into a reserved port of the switch you'll use as backbone, still on VLAN 99.

- [ ] Management page: tick the backbone L3 switch(es), keep or change their VLAN/subnet
- [ ] Members: the suggestion matches the cabling (each device under the backbone it hangs off)
- [ ] Review: no problems; read the trunk ports, they must be inter-switch links only
- [ ] run the "On this PC" `New-NetRoute` lines in an Administrator PowerShell
- [ ] Apply: every device shows its new SSH address in green
- [ ] SSH (Terminal tab) to a device behind each backbone works; the data VLANs on the trunked links still pass traffic

## 8. Report back

Fill one row per box and add it to HANDOFF.md:

| Box (model, IOS version) | Path | Result | Time to provisioned | Notes (errors, prompts, anything unexpected) |
|---|---|---|---|---|
| | | | | |

## If something goes wrong

- **No DHCP from a box:** it still has a startup-config (`show startup-config`), someone pressed a key on its console, or the box is not on the laptop's segment. Preflight checks the laptop side.
- **PnP fails with "Invalid input":** PnP applies the whole file or nothing. The note shows the rejected line; that line must become capability-dependent like `traps config` (see `deliver.parse_caps`).
- **Provisioned but no SSH on the new IP:** the laptop is not on the mgmt VLAN. Cable it to a reserved port, or check the access switch port VLAN.
- **SNMP problems on a switch without AES:** the preview says so. Only set `snmp_allow_auth_nopriv = true` if you accept authNoPriv for it.
- **Port 67 or 80 busy:** preflight names it. Usually Internet Connection Sharing (67) or IIS/another web server (80).
