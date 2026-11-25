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

export function faceplate(device, { interfaces = [], compact = false, severity = null } = {}) {
  const n = portCount(device, interfaces);
  const oper = new Map(interfaces.map((i) => [portNumber(i.name), i.oper]));
  const reserved = new Set(String(device.reserved || "").split(",").map((p) => portNumber(p.trim())).filter(Boolean));
  const banks = [];
  for (let start = 1; start <= n; start += 12) {
    const ports = [];
    for (let p = start; p < Math.min(start + 12, n + 1); p += 2) {
      for (const num of [p, p + 1]) {
        if (num > n) continue;
        const o = oper.get(num);
        const led = o === "up" ? "green" : o === "down" ? "" : "";
        const res = reserved.has(num);
        ports.push(html`<span class="port ${res ? "reserved" : ""}" title="Port ${num}${o ? `: ${o}` : ""}${res ? " (PandoraBox mgmt)" : ""}">
          ${num % 2 ? html`<span class="led ${led}"></span><span class="jack"></span>` : html`<span class="jack"></span><span class="led ${led}"></span>`}
          ${res && num % 2 ? html`<span class="tag">MGMT</span>` : ""}
          <span class="num">${num}</span></span>`);
      }
    }
    banks.push(html`<span class="bank">${ports}</span>`);
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
