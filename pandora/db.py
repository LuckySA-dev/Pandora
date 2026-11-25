"""SQLite inventory. One connection + one lock: fine for a single-laptop tool."""
import json
import re
import sqlite3
import threading
import time

SCHEMA = """
CREATE TABLE IF NOT EXISTS devices (
  id INTEGER PRIMARY KEY,
  serial TEXT UNIQUE, mac TEXT UNIQUE, console_port TEXT UNIQUE, ip TEXT,
  pid TEXT, os_type TEXT, version TEXT, hostname TEXT,
  source TEXT, vendor_class TEXT, path TEXT, role TEXT DEFAULT 'switch_access',
  state TEXT DEFAULT 'discovered', vars TEXT DEFAULT '{}', note TEXT,
  created REAL, updated REAL
);
CREATE TABLE IF NOT EXISTS allocations (
  device_id INTEGER PRIMARY KEY REFERENCES devices(id),
  hostname TEXT NOT NULL UNIQUE, mgmt_ip TEXT NOT NULL UNIQUE
);
CREATE TABLE IF NOT EXISTS reserved_ports (
  device_id INTEGER REFERENCES devices(id), port TEXT, purpose TEXT,
  PRIMARY KEY (device_id, port)
);
CREATE TABLE IF NOT EXISTS configs (
  id INTEGER PRIMARY KEY, device_id INTEGER, method TEXT, text TEXT, result TEXT, ts REAL
);
CREATE TABLE IF NOT EXISTS snmp_samples (device_id INTEGER, ts REAL, name TEXT, value TEXT);
CREATE TABLE IF NOT EXISTS traps (ts REAL, src TEXT, oid TEXT, varbinds TEXT);
CREATE TABLE IF NOT EXISTS audit (ts REAL, actor TEXT, action TEXT, detail TEXT);
CREATE TABLE IF NOT EXISTS backups (
  id INTEGER PRIMARY KEY, device_id INTEGER, ts REAL, checked REAL, sha TEXT, text TEXT
);
CREATE TABLE IF NOT EXISTS problems (
  id INTEGER PRIMARY KEY, device_id INTEGER, key TEXT, severity TEXT, message TEXT,
  opened REAL, closed REAL, acked REAL, note TEXT
);
CREATE INDEX IF NOT EXISTS problems_open ON problems (device_id, key, closed);
CREATE TABLE IF NOT EXISTS compliance (device_id INTEGER PRIMARY KEY, ts REAL, result TEXT);
-- management design (mgmt.py): one domain per L3 backbone, one SSH address per member; UNIQUE = no clashes
CREATE TABLE IF NOT EXISTS mgmt_domains (
  backbone_id INTEGER PRIMARY KEY REFERENCES devices(id), vlan INTEGER NOT NULL UNIQUE,
  subnet TEXT NOT NULL UNIQUE, gateway TEXT NOT NULL
);
CREATE TABLE IF NOT EXISTS mgmt_members (
  device_id INTEGER PRIMARY KEY REFERENCES devices(id), backbone_id INTEGER NOT NULL, ip TEXT NOT NULL UNIQUE
);
CREATE TABLE IF NOT EXISTS mgmt_config (device_id INTEGER PRIMARY KEY REFERENCES devices(id), lines TEXT NOT NULL);
-- hostkeys.py: SSH host key pinned on first use, per device (not per address)
CREATE TABLE IF NOT EXISTS host_keys (device_id INTEGER PRIMARY KEY REFERENCES devices(id), key TEXT NOT NULL, ts REAL);
CREATE INDEX IF NOT EXISTS samples_dev ON snmp_samples (device_id, ts);
"""

STATES = ("discovered", "identified", "needs_credentials", "queued", "provisioning", "provisioned", "failed")
FIELDS = ("serial", "mac", "console_port", "ip", "pid", "os_type", "version", "hostname",
          "source", "vendor_class", "path", "role", "note")

# Secret masking adapted from Oxidized lib/oxidized/model/ios.rb (Apache-2.0, see NOTICE), plus rules for
# what PandoraBox itself renders (type-less secrets, SNMPv3 user keys). Applied before anything is stored.
_HIDE = "<secret hidden>"
_SECRET_RULES = [
    (r"^(snmp-server community).*", r"\1 <configuration removed>"),
    # v1/v2c host lines carry the community; an SNMPv3 line carries only the user name, so leave it intact
    (r"^(?!.*version 3)(snmp-server host \S+(?: vrf \S+)?(?: informs?)?(?: version (?:1|2c))?) +\S+( .*)?$", r"\1 " + _HIDE + r"\2"),
    (r"^(username .+ (?:password|secret) \d) .+", r"\1 " + _HIDE),
    (r"^(enable (?:password|secret)(?: level \d+)? \d) .+", r"\1 " + _HIDE),
    (r"^( +(?:password|secret)) (?:\d )?\S+", r"\1 " + _HIDE),
    (r"^(.*wpa-psk ascii \d) (\S+)", r"\1 " + _HIDE),
    (r"^(.*key 7) (\d.+)", r"\1 " + _HIDE),
    (r"^(tacacs-server (?:.+ )?key) .+", r"\1 " + _HIDE),
    (r"^(crypto isakmp key) (\S+) (.*)", r"\1 " + _HIDE + r" \3"),
    (r"^( +ip ospf message-digest-key \d+ md5) .+", r"\1 " + _HIDE),
    (r"^( +ip ospf authentication-key) .+", r"\1 " + _HIDE),
    (r"^( +neighbor \S+ password) .+", r"\1 " + _HIDE),
    (r"^( +vrrp \d+ authentication text) .+", r"\1 " + _HIDE),
    (r"^( +standby \d+ authentication md5 key-string) .+?((?: timeout \d+)?)$", r"\1 " + _HIDE + r"\2"),
    (r"^( +standby \d+ authentication) (?!md5).{1,8}$", r"\1 " + _HIDE),
    (r"^( +key-string) .+", r"\1 " + _HIDE),
    (r"^((?:tacacs|radius) server [^\n]+\n(?: +[^\n]+\n)* +key) [^\n]+$", r"\1 " + _HIDE),
    (r"^( +ppp (?:chap|pap) password \d) .+", r"\1 " + _HIDE),
    (r"^( +pre-shared-key).*", r"\1 <configuration removed>"),
    (r"^(.*server-key(?: \d)?) (?!<)\S+", r"\1 " + _HIDE),
    (r"^( +domain-password) \S+ ?(.*)", r"\1 " + _HIDE + r" \2"),
    # PandoraBox's own rendered config: secrets without a type digit, SNMPv3 auth/priv keys
    (r"^(username \S+ (?:privilege \d+ )?(?:secret|password)) (?!\d )(?!<)\S+", r"\1 " + _HIDE),
    (r"^(enable (?:secret|password)) (?!\d )(?!<)\S+", r"\1 " + _HIDE),
    (r"(\bauth (?:sha|md5)) (?!<)\S+", r"\1 " + _HIDE),
    (r"(\bpriv (?:aes(?: \d+)?|des)) (?!<)\S+", r"\1 " + _HIDE),
]
_SECRETS = [(re.compile(rx, re.M), rep) for rx, rep in _SECRET_RULES]


def mask_secrets(text: str) -> str:
    """Configs are kept for diff/history; never keep the cleartext secrets in them."""
    for rx, rep in _SECRETS:
        text = rx.sub(rep, text)
    return text


class DB:
    def __init__(self, path=":memory:"):
        self.conn = sqlite3.connect(path, check_same_thread=False, isolation_level=None)
        self.conn.row_factory = sqlite3.Row
        self.lock = threading.RLock()
        self.conn.executescript(SCHEMA)

    def q(self, sql, *args):
        with self.lock:
            return [dict(r) for r in self.conn.execute(sql, args).fetchall()]

    def x(self, sql, *args):
        with self.lock:
            return self.conn.execute(sql, args)

    # ---- devices -------------------------------------------------------
    def device(self, device_id):
        rows = self.q("SELECT * FROM devices WHERE id=?", device_id)
        return rows[0] if rows else None

    def devices(self):
        return self.q("""SELECT d.*, a.hostname AS alloc_hostname, a.mgmt_ip,
                         (SELECT group_concat(port, ', ') FROM reserved_ports r WHERE r.device_id=d.id) AS reserved
                         FROM devices d LEFT JOIN allocations a ON a.device_id=d.id ORDER BY d.id""")

    def find(self, **keys):
        for k in ("serial", "mac", "console_port", "ip"):
            if keys.get(k):
                rows = self.q(f"SELECT * FROM devices WHERE {k}=?", keys[k])
                if rows:
                    return rows[0]
        return None

    def upsert(self, **facts) -> dict:
        """Merge facts into the matching device (by serial > mac > console port > ip) or create it."""
        facts = {k: v for k, v in facts.items() if k in FIELDS and v not in (None, "")}
        with self.lock:
            row = self.find(**facts)
            now = time.time()
            if row is None:
                cols = ", ".join(facts) + ", created, updated"
                marks = ", ".join("?" * len(facts)) + ", ?, ?"
                cur = self.x(f"INSERT INTO devices ({cols}) VALUES ({marks})", *facts.values(), now, now)
                row = self.device(cur.lastrowid)
                self.audit("system", "discovered", row)
            elif facts:
                sets = ", ".join(f"{k}=?" for k in facts)
                self.x(f"UPDATE devices SET {sets}, updated=? WHERE id=?", *facts.values(), now, row["id"])
                row = self.device(row["id"])
            if row["state"] == "discovered" and (row["pid"] or row["os_type"]):
                row = self.set_state(row["id"], "identified")
            return row

    def update(self, device_id, **facts) -> dict:
        """Write facts to this exact row (no matching): for reports already checked against that row."""
        facts = {k: v for k, v in facts.items() if k in FIELDS and v not in (None, "")}
        if facts:
            sets = ", ".join(f"{k}=?" for k in facts)
            self.x(f"UPDATE devices SET {sets}, updated=? WHERE id=?", *facts.values(), time.time(), device_id)
        return self.device(device_id)

    def set_state(self, device_id, state, note=None):
        assert state in STATES, state
        self.x("UPDATE devices SET state=?, note=coalesce(?, note), updated=? WHERE id=?",
               state, note, time.time(), device_id)
        self.audit("system", f"state:{state}", {"id": device_id, "note": note})
        return self.device(device_id)

    def vars(self, device_id) -> dict:
        return json.loads(self.device(device_id)["vars"] or "{}")

    def set_vars(self, device_id, vars_: dict):
        self.x("UPDATE devices SET vars=? WHERE id=?", json.dumps(vars_), device_id)

    # ---- history -------------------------------------------------------
    def save_config(self, device_id, method, text, result):
        cur = self.x("INSERT INTO configs (device_id, method, text, result, ts) VALUES (?,?,?,?,?)",
                     device_id, method, mask_secrets(text), result, time.time())
        return cur.lastrowid

    def audit(self, actor, action, detail):
        self.x("INSERT INTO audit VALUES (?,?,?,?)", time.time(), actor, action,
               json.dumps(detail, default=str)[:4000])
