// Devices: filterable inventory + onboarding in four steps (choose, role, review, claim).
import { api } from "../api.js";
import { createGrid } from "../grid.js";
import { on } from "../live.js";
import {
  attempt, deviceName, dialog, html, PATH_LABEL, reachTag, render, ROLE_LABEL, sevPill, stateBadge, STATE_LABEL, STATES, toast,
} from "../ui.js";

const STEPS = ["Choose devices", "Role and template", "Review", "Claim"];

export async function mount(root, params) {
  const st = { state: params.state || "", selected: new Set(), known: new Map(), facets: {}, ob: null, page: [] };
  let grid = null;
  render(root, html`<div class="page-head" id="dev-head"></div><div id="ob"></div><section class="panel" id="inv"></section>`);
  const head = () => render(root.querySelector("#dev-head"), html`
    <div><h1>Devices</h1><p class="lede">Everything PandoraBox has found. Nothing is configured until you claim it.</p></div>
    <div class="actions">
      <button class="btn" data-act="add">Add by IP</button>
      <button class="btn" data-act="sweep">Find with SNMP</button>
      <a class="btn" href="/api/devices.csv${grid?.state.q ? `?q=${encodeURIComponent(grid.state.q)}` : ""}" download>Export CSV</a>
      <button class="btn primary" data-act="onboard" ${st.selected.size ? "" : "disabled"}>Onboard ${st.selected.size || ""} selected</button>
    </div>`);
  const draw = () => { head(); render(root.querySelector("#ob"), st.ob ? onboarding(st) : html``); grid?.redraw(); };

  const columns = [
    { label: () => html`<input type="checkbox" data-selall aria-label="Select all on this page" ${st.page.length && st.page.every((d) => st.selected.has(d.id)) ? "checked" : ""}>`,
      width: "36px", render: (d) => html`<input type="checkbox" data-sel="${d.id}" aria-label="Select ${deviceName(d)}" ${st.selected.has(d.id) ? "checked" : ""}>` },
    { label: "Device", sort: "name", render: (d) => html`<a href="#/devices/${d.id}">${deviceName(d)}</a><div class="sub">${d.pid || "model unknown"}${d.serial ? `, ${d.serial}` : ""}</div>` },
    { label: "State", sort: "state", render: (d) => html`${stateBadge(d.state)}${reachTag(d)}${d.note ? html`<div class="sub clip" title="${d.note}">${d.note}</div>` : ""}` },
    { label: "Found via", render: (d) => html`${d.source || ""}<div class="sub">${d.console_port || d.mac || ""}</div>` },
    { label: "Delivery", sort: "path", render: (d) => html`<select data-path="${d.id}" aria-label="Delivery path">${Object.entries(PATH_LABEL).map(([k, v]) => html`<option value="${k}" ${d.path === k ? "selected" : ""}>${v}</option>`)}</select>` },
    { label: "Role", sort: "role", render: (d) => html`<select data-role="${d.id}" aria-label="Role">${Object.entries(ROLE_LABEL).map(([k, v]) => html`<option value="${k}" ${d.role === k ? "selected" : ""}>${v}</option>`)}</select>` },
    { label: "Address", sort: "ip", render: (d) => html`${d.ip || ""}${d.mgmt_ip && d.mgmt_ip !== d.ip ? html`<div class="sub">mgmt ${d.mgmt_ip}</div>` : ""}` },
    { label: "Mgmt ports", render: (d) => (d.reserved || "").split(",").filter(Boolean).map((p) => html`<span class="tape">${p.trim().replace(/^[A-Za-z]+Ethernet/, "")}</span>`) },
    { label: "", sort: "severity", render: (d) => (d.state === "needs_credentials" ? html`<button class="btn small primary" data-act="login" data-id="${d.id}">Enter login</button>` : sevPill(d.severity)) },
  ];
  grid = createGrid(root.querySelector("#inv"), columns, {
    url: "/api/devices", storageKey: "pandora.devices", sort: "name", q: params.q || "",
    placeholder: "Search name, serial, model, IP, MAC", params: () => ({ state: st.state }),
    empty: "No devices found yet. Connect a factory switch, plug in a console cable, or search a subnet with SNMP.",
    toolbar: () => html`<div class="chips" role="group" aria-label="Filter by state">${STATES.filter((s) => st.facets[s]).map((s) =>
      html`<button class="chip" data-act="chip" data-state="${s}" aria-pressed="${st.state === s}">${STATE_LABEL[s]}<span class="n">${st.facets[s]}</span></button>`)}</div>`,
    onData: (d) => { st.facets = d.states || {}; st.page = d.items; d.items.forEach((x) => st.known.set(x.id, x)); head(); },
  });

  root.oninput = (e) => { const t = e.target; if (st.ob && t.dataset.ob) st.ob.form[t.dataset.ob] = t.type === "checkbox" ? t.checked : t.value; };
  root.onchange = async (e) => {
    const t = e.target;
    if (t.dataset.sel) { t.checked ? st.selected.add(+t.dataset.sel) : st.selected.delete(+t.dataset.sel); head(); grid.redraw(); }
    if (t.dataset.selall !== undefined) { st.page.forEach((d) => (t.checked ? st.selected.add(d.id) : st.selected.delete(d.id))); head(); grid.redraw(); }
    if (t.dataset.path) await attempt(() => api.patch(`/api/devices/${t.dataset.path}`, { path: t.value }), "Delivery path saved");
    if (t.dataset.role) await attempt(() => api.patch(`/api/devices/${t.dataset.role}`, { role: t.value }), "Role saved");
    if (st.ob && t.dataset.ob === "role") draw();
  };
  root.onclick = async (e) => {
    const b = e.target.closest("[data-act]");
    if (!b) return;
    const act = b.dataset.act;
    if (act === "chip") { st.state = st.state === b.dataset.state ? "" : b.dataset.state; grid.state.page = 1; grid.load(); }
    if (act === "sweep") await sweep(() => grid.reload());
    if (act === "add") await addByIp(() => grid.reload());
    if (act === "login") await login(+b.dataset.id);
    if (act === "onboard") { st.ob = { step: 0, ids: [...st.selected], form: { role: "switch_access", vlans: "10 USERS\n20 VOICE", access: "", uplink: "" }, rows: null, result: null }; draw(); }
    if (act === "ob-cancel") { st.ob = null; draw(); }
    if (act === "ob-drop") { st.ob.ids = st.ob.ids.filter((i) => i !== +b.dataset.id); draw(); }
    if (act === "ob-back") { st.ob.step -= 1; draw(); }
    if (act === "ob-next") await next(st, draw);
    if (act === "ob-recheck") await recheck(st, draw);
  };
  head();
  await grid.load();
  const offs = [on("device", () => { clearTimeout(st.lt); st.lt = setTimeout(() => grid.reload(), 400); })];
  return () => { offs.forEach((f) => f()); clearTimeout(st.lt); };
}

// ---- onboarding -------------------------------------------------------------------------------
function onboarding(st) {
  const ob = st.ob;
  const byId = st.known;
  const f = ob.form;
  const body = [
    () => html`<p>These devices will get a hostname, a management IP and reserved management ports, then their configuration.</p>
      <ul>${ob.ids.map((id) => html`<li>${deviceName(byId.get(id) || { id })} <span class="muted">${PATH_LABEL[byId.get(id)?.path] || ""}</span>
        <button class="btn small" data-act="ob-drop" data-id="${id}" aria-label="Remove">Remove</button></li>`)}</ul>`,
    () => html`<label class="field" for="ob-role">Role for all chosen devices</label>
      <select id="ob-role" data-ob="role">${Object.entries(ROLE_LABEL).map(([k, v]) => html`<option value="${k}" ${f.role === k ? "selected" : ""}>${v}</option>`)}</select>
      ${f.role === "switch_access" ? html`
        <label class="field" for="ob-vlans">VLANs, one per line: id and name</label>
        <textarea id="ob-vlans" class="cli" rows="3" data-ob="vlans">${f.vlans}</textarea>
        <label class="field" for="ob-access">Access ports, one per line: range then VLAN (for example Gi1/0/1 - 20 10)</label>
        <textarea id="ob-access" class="cli" rows="3" data-ob="access">${f.access}</textarea>
        <label class="field" for="ob-uplink">Uplink trunk range</label>
        <input id="ob-uplink" data-ob="uplink" value="${f.uplink}" placeholder="Gi1/0/45 - 46">`
      : html`
        <label class="field" for="ob-wanp">WAN port and address (leave the address empty for DHCP)</label>
        <div style="display:flex;gap:8px"><input id="ob-wanp" data-ob="wan_port" value="${f.wan_port || ""}" placeholder="GigabitEthernet0/0/0">
          <input data-ob="wan_ip" value="${f.wan_ip || ""}" placeholder="203.0.113.2 255.255.255.252" aria-label="WAN address"></div>
        <label class="field" for="ob-lanp">LAN port and address</label>
        <div style="display:flex;gap:8px"><input id="ob-lanp" data-ob="lan_port" value="${f.lan_port || ""}" placeholder="GigabitEthernet0/0/2">
          <input data-ob="lan_ip" value="${f.lan_ip || ""}" placeholder="192.168.10.1 255.255.255.0" aria-label="LAN address"></div>`}`,
    () => review(ob),
    () => html`${(ob.result || []).map((r) => html`<p>${deviceName(byId.get(r.id) || { id: r.id })}:
        ${r.queued ? html`${stateBadge(r.state)}` : html`<span class="muted">not claimed: ${(r.problems || []).join("; ")}</span>`}</p>`)}
      <p class="muted">Factory devices pick up their configuration the next time they ask (PnP, ZTP, AutoInstall). Watch progress on the Bench.</p>`,
  ][ob.step]();
  const blocked = ob.step === 2 && (!ob.rows || ob.rows.some((r) => r.problems.length));
  return html`<section class="panel onboard" aria-label="Onboarding">
    <div class="panel-head"><h2>Onboard ${ob.ids.length} device${ob.ids.length === 1 ? "" : "s"}</h2>
      <button class="btn small more" data-act="ob-cancel">${ob.step === 3 ? "Close" : "Cancel"}</button></div>
    <ol class="stepper" style="padding:0">${STEPS.map((s, i) => html`<li class="${i < ob.step ? "done" : ""}" ${i === ob.step ? html`aria-current="step"` : ""}>${s}</li>`)}</ol>
    ${body}
    ${ob.step < 3 ? html`<div style="display:flex;gap:8px;margin-top:16px">
      ${ob.step ? html`<button class="btn" data-act="ob-back">Back</button>` : ""}
      <button class="btn primary" data-act="ob-next" ${blocked || !ob.ids.length ? "disabled" : ""}>${["Choose role", "Review", "Claim and configure"][ob.step]}</button>
      ${ob.step === 2 ? html`<button class="btn" data-act="ob-recheck">Save ports and check again</button>` : ""}
    </div>` : ""}
  </section>`;
}

function review(ob) {
  if (!ob.rows) return html`<p class="muted">Checking for conflicts…</p>`;
  const bad = ob.rows.filter((r) => r.problems.length).length;
  return html`<p>${bad ? `${bad} device${bad > 1 ? "s need" : " needs"} attention before claiming.` : "No conflicts: every device gets its own name, address and management ports."}</p>
    <div class="scroll-x"><table class="table"><thead><tr><th>Device</th><th>Hostname</th><th>Mgmt IP</th><th>Reserved mgmt ports</th><th>Delivery</th><th>Check</th></tr></thead>
    <tbody>${ob.rows.map((r) => html`<tr>
      <td>${r.serial || r.pid || `#${r.id}`}</td><td>${r.hostname}</td><td>${r.mgmt_ip}</td>
      <td><input data-ports="${r.id}" value="${(r.reserved_ports || []).join(", ")}" placeholder="Gi1/0/47, Gi1/0/48" aria-label="Reserved ports" style="min-width:220px"></td>
      <td>${PATH_LABEL[r.path] || r.path}</td>
      <td>${r.problems.length ? html`<span style="color:var(--led-red)">${r.problems.join("; ")}</span>` : html`<span class="state"><span class="led green"></span>OK</span>`}</td></tr>
      <tr><td></td><td colspan="5"><details><summary class="muted">Configuration that will be sent</summary><pre class="config">${r.config}</pre></details></td></tr>`)}
    </tbody></table></div>`;
}

const vars = (f) => (f.role === "switch_access" ? {
  vlans: f.vlans.split("\n").map((l) => l.trim()).filter(Boolean).map((l) => { const [id, ...n] = l.split(/\s+/); return { id, name: n.join("_") || `VLAN${id}` }; }),
  access_ports: f.access.split("\n").map((l) => l.trim().match(/^(.*\S)\s+(\d+)$/)).filter(Boolean).map((m) => ({ ports: m[1], vlan: m[2] })),
  uplink: f.uplink.trim(),
} : { wan_port: f.wan_port || "", wan_ip: f.wan_ip || "", lan_port: f.lan_port || "", lan_ip: f.lan_ip || "" });

async function next(st, draw) {
  const ob = st.ob;
  if (ob.step === 0) { ob.step = 1; return draw(); }
  if (ob.step === 1) {
    ob.step = 2; ob.rows = null; draw();
    ob.rows = await attempt(() => api.post("/api/preview", { ids: ob.ids, role: ob.form.role, vars: vars(ob.form) }));
    if (!ob.rows) ob.step = 1;
    return draw();
  }
  if (ob.step === 2) {
    ob.result = await attempt(() => api.post("/api/provision", { ids: ob.ids }));
    if (ob.result) { ob.step = 3; st.selected.clear(); toast(`Claimed ${ob.result.filter((r) => r.queued).length} device(s)`, "ok"); }
    return draw();
  }
}

async function recheck(st, draw) {
  const ports = {};
  document.querySelectorAll("[data-ports]").forEach((i) => (ports[i.dataset.ports] = i.value));
  st.ob.rows = await attempt(() => api.post("/api/preview", { ids: st.ob.ids, ports })) || st.ob.rows;
  draw();
}

async function sweep(reload) {
  const r = await dialog({
    title: "Find devices with SNMP",
    body: html`<p>Searches a subnet for devices that already run a configuration. Uses the SNMPv3 user from settings unless you give a v2c community.</p>
      <label class="field" for="sw-net">Subnet</label><input id="sw-net" name="subnet" placeholder="10.99.0.0/24" required>
      <label class="field" for="sw-comm">v2c community (optional)</label><input id="sw-comm" name="community" type="password" autocomplete="off">`,
    actions: [{ label: "Cancel", value: false }, { label: "Search subnet", value: true, kind: "primary" }],
  });
  if (!r.value || !r.form.subnet) return;
  toast(`Searching ${r.form.subnet}…`);
  const found = await attempt(() => api.post("/api/snmp/sweep", { subnet: r.form.subnet, community: r.form.community }));
  if (found) { toast(`Found ${found.length} device(s)`, "ok"); reload(); }
}

async function addByIp(reload) {
  const r = await dialog({
    title: "Add a device by IP",
    body: html`<p>For a switch or router that already runs a configuration but has no SNMP yet. PandoraBox logs in over SSH,
      reads the model and software, and keeps the login in memory only.</p>
      <label class="field" for="ad-ip">IP address</label><input id="ad-ip" name="ip" placeholder="10.1.1.20" required>
      <label class="field" for="ad-u">Username</label><input id="ad-u" name="username" autocomplete="off" required>
      <label class="field" for="ad-p">Password</label><input id="ad-p" name="password" type="password" autocomplete="off" required>
      <label class="field" for="ad-s">Enable secret (if different)</label><input id="ad-s" name="secret" type="password" autocomplete="off">
      <label class="check" style="margin-top:12px"><input type="checkbox" name="telnet">This box has no SSH: log in over Telnet</label>
      <p class="muted" style="margin-top:4px">Only for an IOS image without crypto (no K9 in its name), on the isolated provisioning network: Telnet sends the login in clear text. Its page then offers an upgrade to a K9 image, which turns SSH on and Telnet off.</p>`,
    actions: [{ label: "Cancel", value: false }, { label: "Log in and add", value: true, kind: "primary" }],
  });
  if (!r.value) return;
  toast(`Logging in to ${r.form.ip}…`);
  const dev = await attempt(() => api.post("/api/devices", { ...r.form, telnet: r.form.telnet === "on", secret: r.form.secret || r.form.password }));
  if (dev) { toast(`Added ${dev.hostname || dev.ip}`, "ok"); reload(); }
}

export async function login(id) {
  const r = await dialog({
    title: "This device already has a login",
    body: html`<p>PandoraBox will log in with these, read the running configuration and add its settings without replacing yours. They are kept in memory only.</p>
      <label class="field" for="cr-u">Username</label><input id="cr-u" name="username" autocomplete="off" required>
      <label class="field" for="cr-p">Password</label><input id="cr-p" name="password" type="password" autocomplete="off" required>
      <label class="field" for="cr-s">Enable secret (if different)</label><input id="cr-s" name="secret" type="password" autocomplete="off">`,
    actions: [{ label: "Cancel", value: false }, { label: "Log in and configure", value: true, kind: "primary" }],
  });
  if (!r.value) return;
  if (!r.form.username || !r.form.password) return toast("Username and password are both needed.", "error");
  await attempt(() => api.post(`/api/devices/${id}/credentials`, { ...r.form, secret: r.form.secret || r.form.password }), "Logging in…");
}
