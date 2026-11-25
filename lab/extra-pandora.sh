#!/bin/bash
# Run inside the medium lab's PandoraBox after `containerlab deploy -t lab/extra.clab.yml`:
#   docker exec -i clab-pandora-medium-pandora bash < lab/extra-pandora.sh
# 1. eth1 (cable to d1) + eth2 (cable to the blank box) become one segment, br0, which carries 10.99.0.1
#    and the routes the management design gave the PC.
# 2. the console relay for the blank box (IOL boots only once it answers).
# 3. PandoraBox restarted on the same database, now WITH DHCP / TFTP / PnP on br0.
set -e
if ! ip link show br0 >/dev/null 2>&1; then
  routes=$(ip route show | grep ' dev eth1' | grep -v 'proto kernel' || true)
  ip link add br0 type bridge
  ip link set br0 up
  ip addr del 10.99.0.1/24 dev eth1
  ip link set eth1 master br0
  ip link set eth2 master br0
  ip link set eth2 up
  ip addr add 10.99.0.1/24 dev br0
  echo "$routes" | while read -r r; do [ -n "$r" ] && ip route replace ${r/dev eth1/dev br0}; done
fi
ip -br addr show br0

cd /app
if ! ss -ltn | grep -q ':7041 '; then
  nohup python -c 'import asyncio, importlib.util as u
s = u.spec_from_file_location("relay", "lab/ztp/console_relay.py"); m = u.module_from_spec(s); s.loader.exec_module(m)
asyncio.run(m.main([41]))' > /tmp/relay.log 2>&1 &
fi

old=$(for p in /proc/[0-9]*; do c=$(tr '\0' ' ' < "$p/cmdline" 2>/dev/null); case "$c" in *"-m pandora"*|*clab_check*) echo "${p#/proc/}";; esac; done)
[ -n "$old" ] && kill $old 2>/dev/null
for i in 1 2 3 4 5; do ss -lun | grep -q '10.99.0.1:69 ' || break; sleep 1; done
[ -n "$old" ] && kill -9 $old 2>/dev/null  # one copy only: two would both answer DHCP on br0
sleep 1
db=$(ls -d /tmp/pandora-clab-*/pandora.db | head -1)
cat > /tmp/lab.toml <<'T'
iface = "br0"
server_ip = "10.99.0.1"
http_port = 8099
site = "clab"
mgmt_range = "10.99.0.10-10.99.0.99"
dhcp_range = "10.99.0.100-10.99.0.150"
mgmt_gateway = ""
ui_allow = ["172.16.0.0/12"]
snmp_allow_auth_nopriv = true
T
# the lab's test secrets (the same ones clab_check.py configured on the medium devices)
PANDORA_ADMIN_PASSWORD='Adm1nPass!' PANDORA_SNMP_AUTH=AuthKey123 PANDORA_SNMP_PRIV=PrivKey123 \
  nohup python -m pandora --db "$db" --config /tmp/lab.toml --assume-isolated > /tmp/ui.log 2>&1 &
sleep 8
grep -E "DHCP|TFTP|PnP|Refusing|UI:|Error" /tmp/ui.log | tail -5
