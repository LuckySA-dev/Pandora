// The switch faceplate: front-panel ports with link LEDs (from SNMP) and yellow tape on the
// ports PandoraBox reserved for management. Cisco numbering: odd ports on top, even below.
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
// Physical Ethernet ports only: no subinterfaces (Et0/2.10), SVIs, loopbacks, tunnels, app-hosting ports.
const PHYSICAL = /^(?:et|fa|gi|te|tw|fi|fo|hu)\d+(?:\/\d+)+$/;
const nums = (name) => (String(name).match(/\d+/g) || []).map(Number);
const byNumbers = (a, b) => { const x = nums(a), y = nums(b); for (let i = 0; i < Math.max(x.length, y.length); i++) if ((x[i] ?? -1) !== (y[i] ?? -1)) return (x[i] ?? -1) - (y[i] ?? -1); return 0; };

// What to draw: the device's own ports once SNMP has listed them (any naming: Gi1/0/24, Ethernet0/0 on IOL,
// several slots); before the first poll, numbered 1..N guessed from the model (C9300-24P -> 24).
function portsOf(device, interfaces) {
  const real = interfaces.filter((i) => PHYSICAL.test(canon(i.name))).map((i) => i.name).sort(byNumbers);
  if (real.length) {
    const prefix = (n) => n.replace(/\d+$/, "");
    const one = real.every((n) => prefix(n) === prefix(real[0])); // one module: label by the last number
    return real.map((name) => ({ name, label: one ? String(nums(name).at(-1)) : nums(name).join("/") }));
  }
  const n = portCount(device, interfaces);
  return Array.from({ length: n }, (_, i) => ({ name: null, num: i + 1, label: String(i + 1) }));
}

export function faceplate(device, { interfaces = [], compact = false, severity = null } = {}) {
  const ports = portsOf(device, interfaces);
  const n = ports.length;
  const operByName = new Map(interfaces.map((i) => [canon(i.name), i.oper]));
  const operByNum = new Map(interfaces.map((i) => [portNumber(i.name), i.oper]));
  const resNames = String(device.reserved || "").split(",").map((p) => p.trim()).filter(Boolean);
  const resByName = new Set(resNames.map(canon));
  const resByNum = new Set(resNames.map(portNumber).filter(Boolean));
  const banks = [];
  // Cisco front panels: the first port of each pair on top, the second below, 12 to a bank
  for (let start = 0; start < n; start += 12) {
    const cells = ports.slice(start, start + 12).map((p, k) => {
      const o = p.name ? operByName.get(canon(p.name)) : operByNum.get(p.num);
      const res = p.name ? resByName.has(canon(p.name)) : resByNum.has(p.num);
      const topRow = k % 2 === 0;
      return html`<span class="port ${res ? "reserved" : ""}" title="${p.name || `Port ${p.label}`}${o ? `: ${o}` : ""}${res ? " (PandoraBox mgmt)" : ""}">
        ${topRow ? html`<span class="led ${o === "up" ? "green" : ""}"></span><span class="jack"></span>` : html`<span class="jack"></span><span class="led ${o === "up" ? "green" : ""}"></span>`}
        ${res && topRow ? html`<span class="tag">MGMT</span>` : ""}
        <span class="num">${p.label}</span></span>`;
    });
    banks.push(html`<span class="bank">${cells}</span>`);
  }
  const sysLed = { provisioned: "green", failed: "red", provisioning: "amber blink", queued: "amber" }[device.state] || "";
  return html`<div class="faceplate ${compact ? "compact" : ""}" role="img"
      aria-label="${deviceName(device)}: ${n} ports, state ${STATE_LABEL[device.state] || device.state}">
    ${compact ? "" : html`<div class="silk"><b>${deviceName(device)}</b>${device.pid || "unknown model"}</div>`}
    <div>
      ${compact ? "" : html`<div class="status"><span class="state"><span class="led ${sysLed}"></span>SYST</span>
        <span>${device.os_type === "iosxe" ? "IOS-XE" : device.os_type === "ios" ? "IOS" : ""} ${device.version || ""}</span></div>`}
      <div class="ports">${banks}</div>
    </div>
    ${severity ? html`<span class="sev-flag sev-pill sev-${severity}">${severity}</span>` : ""}
  </div>`;
}
