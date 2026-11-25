#!/bin/bash
# Factory-blank IOL: no containerlab boot config, fresh NVRAM on every start, IOL port e0/0 = eth1.
# Its console (IOL's stdin/stdout) dials the lab terminal server in the PandoraBox container (console_relay.py).
cd /iol
rm -f nvram_* config.txt  # no startup config at all (an empty -c file counts as a broken one)
printf '%s:0/0 513:0/0\n' "$IOL_PID" > NETMAP
printf '[default]\nbase_port = 49000\nnetmap = /iol/NETMAP\n[513:0/0]\neth_dev = eth1\n' > iouyap.ini
RELAY=/dev/tcp/${CONSOLE_RELAY:-172.30.31.2}/$((7000 + IOL_PID))
until (exec 3<>"$RELAY") 2>/dev/null; do sleep 2; done
exec 3<>"$RELAY"
# Not /entrypoint.sh: it flushes eth0, which here carries this console connection (IOL uses eth1).
/usr/bin/iouyap 513 -q &
# IOL needs a tty for its console: `script` gives it a pty and copies it to and from the socket
exec script -qfec "/iol/iol.bin $IOL_PID -e 1 -s 0 -n 1024" /dev/null <&3 >&3 2>&3
