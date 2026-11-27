#!/bin/bash
# Inside the backbone lab's PandoraBox: the blank boxes' console relay (IOL boots only once it answers), then
# PandoraBox itself with DHCP / TFTP / PnP on eth1 (the single LAN card, cabled to bb). Its database is /tmp/bb.db:
# kept when this script runs again (a restart), new on every lab deploy.
#   docker exec -i clab-pandora-bb-pandora bash < lab/backbone-pandora.sh
cd /app
if ! ss -ltn | grep -q ':7061 '; then
  nohup python -c 'import asyncio, importlib.util as u
s = u.spec_from_file_location("relay", "lab/ztp/console_relay.py"); m = u.module_from_spec(s); s.loader.exec_module(m)
asyncio.run(m.main([61, 62]))' > /tmp/relay.log 2>&1 &
fi
old=$(for p in /proc/[0-9]*; do c=$(tr '\0' ' ' < "$p/cmdline" 2>/dev/null); case "$c" in *"-m pandora"*) echo "${p#/proc/}";; esac; done)
[ -n "$old" ] && kill $old 2>/dev/null && sleep 3 && kill -9 $old 2>/dev/null
cat > /tmp/bb.toml <<'T'
iface = "eth1"
server_ip = "10.99.0.1"
http_port = 8099
site = "lab"
mgmt_range = "10.99.0.10-10.99.0.99"
dhcp_range = "10.99.0.100-10.99.0.150"
mgmt_gateway = ""
ui_allow = ["172.16.0.0/12"]
snmp_allow_auth_nopriv = true
T
# the lab's test secrets (never real ones)
PANDORA_ADMIN_PASSWORD='Adm1nPass!' PANDORA_SNMP_AUTH=AuthKey123 PANDORA_SNMP_PRIV=PrivKey123 \
  nohup python -m pandora --db /tmp/bb.db --config /tmp/bb.toml --assume-isolated > /tmp/ui.log 2>&1 &
sleep 8
grep -E "DHCP|UI:|Refusing|Error" /tmp/ui.log | tail -4
