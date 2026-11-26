// The switch faceplate: the copper front panel in banks of 12 (Cisco numbering: first of each pair on top), the
// uplink / SFP ports in their own block on the right as on the real box, link LEDs from SNMP, yellow tape on the
// ports PandoraBox reserved for management, a dimmed jack for a port someone shut. Which port is which comes from
// the server (ports.py: the same answer the provisioning backbone uses), so a 3560G-48TS shows 48 + 4 SFP.
import { html, deviceName, STATE_LABEL } from "./ui.js";

const portNumber = (name) => {
  // front-panel ports only: Gi1/0/24, GigabitEthernet0/24, Fa0/12 (not uplink modules like Te1/1/1)
  const m = String(name).match(/(?:^|[A-Za-z])(\d+)\/0\/(\d+)$/) || String(name).match(/^[A-Za-z-]+0\/(\d+)$/);
  return m ? Number(m[m.length - 1]) : null;
};
export function portCount(device, interfaces = []) {
  const fromPid = Number((String(device.pid || "").match(/-(\d{1,2})[A-Z]/) || [])[1]);
  const fromIf = Math.max(0, ...interfaces.map((i) => portNumber(i.name) || 0));
  const n = Math.max(fromPid || 0, fromIf);
  return n >= 4 ? Math.min(n, 52) : 24;
}

// One spelling for a port whatever reported it: SNMP ifName says "Et0/3", the reserved list "Ethernet0/3",
// IOS "GigabitEthernet1/0/24" or "Gi1/0/24" -> "et0/3", "gi1/0/24" (like alloc.normalize_if on the server).
const canon = (name) => String(name).trim().replace(/^([A-Za-z]{2})[A-Za-z-]*/, "$1").toLowerCase();
const nums = (name) => (String(name).match(/\d+/g) || []).map(Number);

// Labels: the last number when the group is one module (1..48), else slot/port (IOL 0/0 .. 1/3)
function labelled(list) {
  const prefix = (n) => n.replace(/\d+$/, "");
  const one = list.every((i) => prefix(i.name) === prefix(list[0].name));
  return list.map((i) => ({ ...i, label: one ? String(nums(i.name).at(-1)) : nums(i.name).join("/") }));
}

function portsOf(device, interfaces) {
  const kinds = interfaces.filter((i) => ["access", "uplink", "oob"].includes(i.kind));
  if (kinds.length) {
    return {
      front: labelled(kinds.filter((i) => i.kind === "access")),
      uplinks: labelled(kinds.filter((i) => i.kind !== "access")),
    };
  }
  // before the first SNMP poll: 1..N guessed from the model
  const n = portCount(device, interfaces);
  return { front: Array.from({ length: n }, (_, i) => ({ name: null, num: i + 1, label: String(i + 1) })), uplinks: [] };
}

function cell(p, k, resByName, resByNum, sfp) {
  const res = p.name ? resByName.has(canon(p.name)) : resByNum.has(p.num);
  const up = p.oper === "up", shut = p.admin === "down";
  const top = k % 2 === 0;
  const state = shut ? "shut down" : p.oper || "";
  const led = html`<span class="led ${up ? "green" : ""}"></span>`;
  const jack = html`<span class="jack"></span>`;
  return html`<span class="port ${sfp ? "sfp" : ""} ${res ? "reserved" : ""} ${shut ? "shut" : ""}"
      title="${p.name || `Port ${p.label}`}${state ? `: ${state}` : ""}${p.alias ? ` (${p.alias})` : ""}${res ? ", PandoraBox management port" : ""}">
    ${top ? html`${led}${jack}` : html`${jack}${led}`}
    ${res ? html`<span class="tag ${top ? "" : "below"}">MGMT</span>` : ""}
    <span class="num">${p.label}</span></span>`;
}

export function faceplate(device, { interfaces = [], compact = false, severity = null } = {}) {
  const { front, uplinks } = portsOf(device, interfaces);
  const resNames = String(device.reserved || "").split(",").map((p) => p.trim()).filter(Boolean);
  const resByName = new Set(resNames.map(canon));
  const resByNum = new Set(resNames.map(portNumber).filter(Boolean));
  const banks = [];
  for (let start = 0; start < front.length; start += 12) {
    banks.push(html`<span class="bank">${front.slice(start, start + 12).map((p, k) => cell(p, k, resByName, resByNum, false))}</span>`);
  }
  const sysLed = { provisioned: "green", failed: "red", provisioning: "amber blink", queued: "amber" }[device.state] || "";
  return html`<div class="faceplate ${compact ? "compact" : ""}" role="img"
      aria-label="${deviceName(device)}: ${front.length} ports${uplinks.length ? ` and ${uplinks.length} uplinks` : ""}, state ${STATE_LABEL[device.status || device.state] || device.state}">
    ${compact ? "" : html`<div class="silk"><b>${deviceName(device)}</b>${device.pid || "unknown model"}</div>`}
    <div>
      ${compact ? "" : html`<div class="status"><span class="state"><span class="led ${sysLed}"></span>SYST</span>
        <span>${device.os_type === "iosxe" ? "IOS-XE" : device.os_type === "ios" ? "IOS" : ""} ${device.version || ""}</span></div>`}
      <div class="ports">${banks}
        ${uplinks.length ? html`<span class="uplinks" aria-label="Uplink ports"><span class="bank">${uplinks.map((p, k) => cell(p, k, resByName, resByNum, true))}</span>
          <span class="uplink-label">Uplinks</span></span>` : ""}</div>
    </div>
    ${severity ? html`<span class="sev-flag sev-pill sev-${severity}">${severity}</span>` : ""}
  </div>`;
}
