// Dashboard: the bench as a sortable, searchable, paged table (built for hundreds of devices),
// then onboarding pipeline, problems, health and recent activity.
import { api } from "../api.js";
import { createGrid } from "../grid.js";
import { on } from "../live.js";
import { ago, deviceName, html, PATH_LABEL, reachTag, render, SEVERITIES, stateBadge, STATE_LABEL } from "../ui.js";

const PIPELINE = ["discovered", "identified", "queued", "provisioning", "provisioned"];

const COLUMNS = [
  { key: "name", label: "Device", sort: "name", render: (d) => html`<a href="#/devices/${d.id}">${deviceName(d)}</a><div class="sub">${d.pid || "model unknown"}</div>` },
  { key: "state", label: "State", sort: "status", render: (d) => html`${stateBadge(d.status || d.state)}${d.status === "offline" ? reachTag(d) : ""}` },
  { key: "severity", label: "Problems", sort: "severity", render: (d) => (d.severity ? html`<span class="sev-pill sev-${d.severity}">${d.severity}</span>` : html`<span class="muted">none</span>`) },
  // the address PandoraBox reaches it on now (after a management design that is the domain address, not the
  // pre-config one, which may have been retired)
  { key: "ip", label: "Management IP", sort: "ip", render: (d) => d.ip || d.mgmt_ip || html`<span class="muted">none yet</span>` },
  { key: "ports", label: "Links up", sort: "ports", render: (d) => (d.ports_total
    ? html`<span class="ports-up">${d.ports_up}/${d.ports_total}</span><span class="ports-bar" aria-hidden="true"><span style="width:${Math.round((100 * d.ports_up) / d.ports_total)}%"></span></span>`
    : html`<span class="muted">not polled</span>`) },
  { key: "compliant", label: "Config", render: (d) => (d.compliant == null ? html`<span class="muted">not checked</span>`
    : d.compliant ? html`<span class="state"><span class="led green"></span>Compliant</span>` : html`<span class="state"><span class="led amber"></span>Drifted</span>`) },
  { key: "path", label: "Delivery", sort: "path", render: (d) => PATH_LABEL[d.path] || "" },
  { key: "updated", label: "Last change", sort: "updated", render: (d) => html`<span class="sub">${ago(d.updated)}</span>` },
];

export async function mount(root) {
  render(root, html`
  <div class="page-head">
    <div><h1>Bench</h1><p class="lede" id="bench-lede">&nbsp;</p></div>
    <div class="actions"><a class="btn primary" href="#/devices">Onboard devices</a></div>
  </div>
  <div class="bench-layout">
    <div class="grid">
      <section class="panel" id="bench" aria-label="Devices on the bench"></section>
      <section class="panel" id="activity"></section>
    </div>
    <aside class="grid" id="summary" aria-label="Problems, onboarding and health"></aside>
  </div>`);

  const grid = createGrid(root.querySelector("#bench"), COLUMNS, {
    url: "/api/devices", storageKey: "pandora.bench", sort: "severity", order: "asc",
    placeholder: "Search name, serial, model, IP, MAC", rowHref: (d) => `#/devices/${d.id}`,
    empty: "No devices yet. Discovery watches DHCP, PnP, console ports and SNMP.",
  });
  const summary = async () => {
    const dash = await api.get("/api/dashboard");
    const open = SEVERITIES.reduce((n, s) => n + dash.problems[s], 0);
    const lede = root.querySelector("#bench-lede");
    if (lede) lede.textContent = dash.total
      ? `${dash.states.provisioned || 0} of ${dash.total} devices pre-configured. ${open ? `${open} open problem${open > 1 ? "s" : ""}.` : "No open problems."}`
      : "Nothing found yet. Plug a switch into the provisioning port or a console cable.";
    const box = root.querySelector("#summary");
    if (box) render(box, view(dash, open));
    const act = root.querySelector("#activity");
    if (act) render(act, activity(dash));
  };
  await Promise.all([grid.load(), summary()]);

  // Live updates touch one row in O(1) (grid.patch); only changes that can reorder the table or move the
  // totals (problems, compliance, a device that is not on this page) reload it, debounced.
  let t, s;
  const later = () => { clearTimeout(t); t = setTimeout(() => { grid.reload(); summary(); }, 500); };
  const totals = () => { s ||= setTimeout(() => { s = 0; summary(); }, 5000); }; // at most every 5 s
  const offs = [
    on("snmp", ({ id, ts, sample }) => {
      let up = 0, total = 0;
      for (const k in sample) if (k.endsWith(":oper")) { total += 1; up += sample[k] === "up"; }
      grid.patch(id, { ports_up: up, ports_total: total, polled: ts });
      totals();
    }),
    // a state or reachability change moves the live status, which the server works out (status.py): reload, debounced
    on("device", later),
    on("problem", later),
    on("compliance", later),
  ];
  return () => { offs.forEach((f) => f()); clearTimeout(t); clearTimeout(s); };
}

function activity(dash) {
  return html`<h2>Recent activity</h2>
    <table class="table" style="margin-top:6px"><tbody>
      ${dash.events.map((e) => html`<tr><td class="sub" style="width:120px">${ago(e.ts)}</td><td>${describe(e)}</td></tr>`)}
    </tbody></table>`;
}

function view(dash, open) {
  return html`
    <section class="panel">
      <div class="panel-head"><h2>Problems</h2><a class="more" href="#/problems">All problems</a></div>
      ${open ? html`<div class="sevbar" role="img" aria-label="Open problems by severity">
        ${[...SEVERITIES].reverse().filter((s) => dash.problems[s]).map((s) =>
          html`<span class="sev-${s}" style="flex:${dash.problems[s]};background:var(--sev)" title="${dash.problems[s]} ${s}"></span>`)}</div>` : ""}
      ${dash.open_problems.length ? dash.open_problems.map((p) => html`<div class="problem ${p.acked ? "acked" : ""}">
          <span class="sev sev-${p.severity}"></span>
          <div><div class="msg">${p.message}</div>
            <div class="meta"><a href="#/devices/${p.device_id}">${p.hostname || `#${p.device_id}`}</a>, ${ago(p.opened)}${p.acked ? ", acknowledged" : ""}</div></div>
          <span class="sev-pill sev-${p.severity}">${p.severity}</span></div>`)
        : html`<p class="muted">All clear. Problems appear here when a port goes down, CPU runs hot, a device stops answering or its config drifts.</p>`}
    </section>
      <section class="panel">
        <h2>Onboarding</h2>
        <div class="pipeline" style="margin-top:10px">
          ${PIPELINE.map((s) => html`<div class="stage ${s === "provisioned" ? "done" : ""}"><b>${dash.states[s] || 0}</b><span>${STATE_LABEL[s]}</span></div>`)}
        </div>
        ${dash.states.needs_credentials || dash.states.failed ? html`<p style="margin-top:10px">
          ${dash.states.needs_credentials ? html`<a href="#/devices?state=needs_credentials">${dash.states.needs_credentials} waiting for a login</a> ` : ""}
          ${dash.states.failed ? html`<a href="#/devices?state=failed">${dash.states.failed} failed</a>` : ""}</p>` : ""}
      </section>
      <section class="panel">
        <h2>Health</h2>
        <dl class="facts" style="margin-top:8px">
          ${dash.statuses ? html`<dt>Status</dt><dd>${["ready", "offline", "degraded", "restarted", "drifted", "configured"].filter((s) => dash.statuses[s]).map((s, i) =>
            html`${i ? ", " : ""}${dash.statuses[s]} ${STATE_LABEL[s].toLowerCase()}`) || "none configured yet"}</dd>` : ""}
          <dt>Answering SNMP</dt><dd>${dash.availability.up} of ${dash.availability.total}${dash.availability.down ? `, ${dash.availability.down} offline` : ""}</dd>
          <dt>Config compliant</dt><dd>${dash.compliance.compliant}${dash.compliance.drift ? html`, <a href="#/problems">${dash.compliance.drift} drifted</a>` : ""}${dash.compliance.unchecked ? `, ${dash.compliance.unchecked} not checked yet` : ""}</dd>
          ${dash.top_cpu.length ? html`<dt>Busiest CPU</dt><dd>${dash.top_cpu.map((c, i) => html`${i ? ", " : ""}<a href="#/devices/${c.id}">${c.hostname}</a> ${c.cpu}%`)}</dd>` : ""}
        </dl>
      </section>`;
}

function describe(e) {
  let d = {};
  try { d = JSON.parse(e.detail); } catch { /* plain text */ }
  const id = d && (d.device ?? d.id);
  const who = id != null ? html`<a href="#/devices/${id}">device #${id}</a>` : "";
  const map = {
    discovered: html`Found ${deviceName(d || {})}`,
    "config:changed": html`Config changed on ${who}`,
    "config:first": html`First backup of ${who}`,
    remediation: html`Pushed a compliance fix to ${who}`,
    "reach:offline": html`${who} went offline <span class="sub">(${d?.note || ""})</span>`,
    "reach:online": html`${who} is back online <span class="sub">(${d?.note || ""})</span>`,
    extra_config: html`Pushed extra config to ${who}`,
  };
  if (map[e.action]) return map[e.action];
  if (e.action.startsWith("state:")) return html`${who || "A device"} is now ${STATE_LABEL[e.action.slice(6)] || e.action.slice(6)}${d?.note ? html` <span class="sub">(${d.note})</span>` : ""}`;
  if (e.action.startsWith("problem:")) return html`${e.action.slice(8)} problem on ${who}: ${d?.message || ""}`;
  return html`${e.actor}: ${e.action} ${who}`;
}
