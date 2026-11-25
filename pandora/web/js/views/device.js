// One device: faceplate, overview, config (compliance + backups + diff), push, terminal, history.
import { api } from "../api.js";
import { faceplate } from "../faceplate.js";
import { on } from "../live.js";
import {
  ago, attempt, confirmDialog, deviceName, dialog, html, PATH_LABEL, render, ROLE_LABEL, stateBadge, toast, when,
} from "../ui.js";

const TABS = [["overview", "Overview"], ["config", "Config"], ["push", "Push config"], ["terminal", "Terminal"], ["history", "History"]];
const bytes = (v) => {
  const n = Number(v);
  if (!Number.isFinite(n)) return "";
  const u = ["B", "KB", "MB", "GB", "TB"];
  let i = 0, x = n;
  while (x >= 1024 && i < u.length - 1) { x /= 1024; i++; }
  return `${x.toFixed(x < 10 && i ? 1 : 0)} ${u[i]}`;
};

export async function mount(root, params) {
  const id = Number(params.id);
  const tab = TABS.some(([k]) => k === params.tab) ? params.tab : "overview";
  const st = { id, tab, det: null, backups: [], picked: [], text: "", comp: null, pushes: [], events: [], out: "", term: null };

  const draw = () => render(root, view(st));
  const loadDet = async () => { st.det = await api.get(`/api/devices/${id}`); };
  const loadTab = async () => {
    if (tab === "config") {
      [st.backups, st.comp] = await Promise.all([api.get(`/api/devices/${id}/backups`), api.get(`/api/devices/${id}/compliance`)]);
      await showPicked(st);
    }
    if (tab === "push" || tab === "history") st.pushes = await api.get(`/api/devices/${id}/configs`);
    if (tab === "history") st.events = await api.get("/api/events", { device_id: id, limit: 500 });
  };
  try { await loadDet(); } catch (e) { render(root, html`<div class="panel empty">${e.message}. <a href="#/devices">Back to devices</a></div>`); return; }
  await loadTab();
  draw();
  if (tab === "terminal") openTerminal(st);

  root.onclick = async (e) => {
    const b = e.target.closest("[data-act]");
    if (!b) return;
    const act = b.dataset.act;
    if (act === "poll") { await attempt(() => api.post(`/api/snmp/poll/${id}`), "Polled"); await loadDet(); draw(); }
    if (act === "backup") { const r = await attempt(() => api.post(`/api/devices/${id}/backups`)); if (r) toast(r.changed ? "New backup saved" : "No change since the last backup", "ok"); }
    if (act === "check") { await attempt(() => api.post(`/api/devices/${id}/compliance`), "Compliance checked"); }
    if (act === "fix") await fix(st);
    if (act === "ack") await ack(+b.dataset.id);
    if (act === "login") { const { login } = await import("./devices.js"); await login(id); }
    if (act === "dry" || act === "send") await push(st, act === "dry", draw);
    if (act === "connect") openTerminal(st);
    if (act === "break") { st.term?.send({ break: true }); st.term?.xterm.focus(); }
    if (act === "ctrlc") { st.term?.send({ data: "\x03" }); st.term?.xterm.focus(); }
    if (act === "full") {
      const p = document.getElementById("term-panel");
      if (document.fullscreenElement) document.exitFullscreen(); else p?.requestFullscreen?.();
      setTimeout(() => st.term?.xterm.focus(), 200);
    }
    if (["backup", "check", "fix", "ack"].includes(act)) { await loadDet(); await loadTab(); draw(); }
  };
  root.onchange = async (e) => {
    if (e.target.dataset.pick) {
      const v = Number(e.target.dataset.pick);
      st.picked = e.target.checked ? [...st.picked, v].slice(-2) : st.picked.filter((x) => x !== v);
      await showPicked(st);
      draw();
    }
  };
  let t;
  // Live refresh redraws the page, which would wipe an open terminal: leave the Terminal tab alone.
  const later = () => {
    if (tab === "terminal") return;
    clearTimeout(t);
    t = setTimeout(async () => { await loadDet(); if (tab === "config") await loadTab(); draw(); }, 300);
  };
  const mine = (d) => d && (d.id === id || d.device_id === id);
  const offs = [on("device", (d) => mine(d) && later()), on("snmp", (d) => mine(d) && later()),
    on("problem", (d) => mine(d) && later()), on("backup", (d) => mine(d) && later()), on("compliance", (d) => mine(d) && later())];
  return () => { offs.forEach((f) => f()); clearTimeout(t); closeTerminal(st); };
}

async function showPicked(st) {
  const [a, b] = [...st.picked].sort((x, y) => x - y);
  if (a && b) st.text = { diff: (await api.get(`/api/backups/${a}/diff/${b}`)).diff };
  else if (a || st.backups[0]) st.text = { config: (await api.get(`/api/backups/${a || st.backups[0].id}`)).text };
  else st.text = null;
}

function view(st) {
  const { device: d, interfaces, problems } = st.det;
  return html`
  <p style="margin:0 0 6px"><a href="#/devices">Devices</a></p>
  <div class="page-head">
    <div><h1>${deviceName(d)}</h1>
      <p class="lede">${stateBadge(d.state)} ${d.pid || "Model unknown"}${d.serial ? `, serial ${d.serial}` : ""}${d.version ? `, ${d.os_type === "iosxe" ? "IOS-XE" : "IOS"} ${d.version}` : ""}</p></div>
    <div class="actions">
      ${d.state === "needs_credentials" ? html`<button class="btn primary" data-act="login">Enter login</button>` : ""}
      <button class="btn" data-act="poll" ${d.ip ? "" : "disabled"}>Poll now</button>
      <button class="btn" data-act="backup" ${d.ip ? "" : "disabled"}>Back up now</button>
      <button class="btn" data-act="check" ${d.ip ? "" : "disabled"}>Check compliance</button>
    </div>
  </div>
  ${faceplate(d, { interfaces, severity: problems[0]?.severity })}
  <nav class="tabs" role="tablist">${TABS.map(([k, label]) => html`<a role="tab" href="#/devices/${d.id}/${k}" aria-selected="${st.tab === k}">${label}${k === "config" && st.det.compliance && !st.det.compliance.compliant ? " (drift)" : ""}</a>`)}</nav>
  ${{ overview, config, push: pushTab, terminal, history }[st.tab](st)}`;
}

function overview(st) {
  const { device: d, interfaces, problems } = st.det;
  return html`<div class="grid cols-dash">
    <div class="grid">
      <section class="panel"><h2>Open problems</h2>
        ${problems.length ? problems.map((p) => html`<div class="problem ${p.acked ? "acked" : ""}"><span class="sev sev-${p.severity}"></span>
            <div><div class="msg">${p.message}</div><div class="meta">${ago(p.opened)}${p.acked ? `, acknowledged${p.note ? `: ${p.note}` : ""}` : ""}</div></div>
            ${p.acked ? html`<span class="sev-pill sev-${p.severity}">${p.severity}</span>` : html`<button class="btn small" data-act="ack" data-id="${p.id}">Acknowledge</button>`}</div>`)
          : html`<p class="muted">No open problems on this device.</p>`}
      </section>
      <section class="panel"><div class="panel-head"><h2>Interfaces</h2><span class="more muted">${st.det.polled ? `polled ${ago(st.det.polled)}` : "not polled yet"}</span></div>
        ${interfaces.length ? html`<div class="scroll-x"><table class="table"><thead><tr><th>Port</th><th>Link</th><th>In</th><th>Out</th></tr></thead><tbody>
          ${interfaces.map((i) => html`<tr><td>${i.name}</td><td><span class="state"><span class="led ${i.oper === "up" ? "green" : i.oper === "down" ? "red" : ""}"></span>${i.oper || ""}</span></td>
            <td>${bytes(i.in)}</td><td>${bytes(i.out)}</td></tr>`)}</tbody></table></div>`
          : html`<p class="muted">Interface status appears after the first SNMP poll of a pre-configured device.</p>`}
      </section>
    </div>
    <section class="panel"><h2>Details</h2>
      <dl class="facts" style="margin-top:8px">
        <dt>Hostname</dt><dd>${d.hostname || d.alloc_hostname || ""}</dd>
        <dt>Management IP</dt><dd>${d.mgmt_ip || d.ip || ""}</dd>
        <dt>Mgmt ports</dt><dd>${(d.reserved || "").split(",").filter(Boolean).map((p) => html`<span class="tape">${p.trim()}</span>`) || ""}</dd>
        <dt>Role</dt><dd>${ROLE_LABEL[d.role] || d.role || ""}</dd>
        <dt>Delivery</dt><dd>${PATH_LABEL[d.path] || d.path || ""}</dd>
        <dt>Found via</dt><dd>${d.source || ""} ${d.console_port || d.mac || ""}</dd>
        <dt>CPU (5 min)</dt><dd>${st.det.cpu != null ? `${st.det.cpu}%` : "unknown"}</dd>
        <dt>Backups</dt><dd>${st.det.backups}${st.det.last_backup ? `, last ${ago(st.det.last_backup)}` : ""}</dd>
        <dt>Compliance</dt><dd>${st.det.compliance ? (st.det.compliance.compliant ? "Compliant" : "Drifted") : "Not checked"}</dd>
        <dt>Note</dt><dd>${d.note || ""}</dd>
      </dl>
    </section>
  </div>`;
}

function config(st) {
  const c = st.comp && st.comp.features ? st.comp : null;
  return html`
  <section class="panel" style="margin-bottom:16px">
    <div class="panel-head"><h2>Compliance</h2>
      <span class="more">${c ? html`checked ${ago(c.ts)}` : ""} <button class="btn small" data-act="check">Check now</button></span></div>
    ${!c ? html`<p class="muted">Not checked yet. A check backs up the running configuration and compares it with what PandoraBox intends for this device.</p>`
      : html`<p>${c.compliant ? "The running configuration matches what PandoraBox intends." : "The running configuration has drifted from what PandoraBox intends."}</p>
        ${c.features.map((f) => html`<div class="feature"><span class="led ${f.compliant ? "green" : "amber"}" style="margin-top:6px"></span>
          <div><b>${featureName(f.name)}</b> <span class="muted">${f.compliant ? "matches" : `${f.missing.length} missing, ${f.extra.length} unexpected`}</span>
          ${f.missing.length || f.extra.length ? html`<ul>${f.missing.map((l) => html`<li>missing: ${l}</li>`)}${f.extra.map((l) => html`<li>unexpected: ${l}</li>`)}</ul>` : ""}</div></div>`)}
        ${!c.compliant && c.remediation.length ? html`<button class="btn primary" style="margin-top:12px" data-act="fix">Review fix</button>` : ""}`}
  </section>
  <section class="panel">
    <div class="panel-head"><h2>Backups</h2><span class="more"><button class="btn small" data-act="backup">Back up now</button></span></div>
    ${st.backups.length ? html`<div class="split">
      <div><p class="muted" style="font-size:13px">Tick two versions to compare them.</p>
        <div class="list-select">${st.backups.map((b) => html`<label><input type="checkbox" data-pick="${b.id}" ${st.picked.includes(b.id) ? "checked" : ""}>
          <span>${when(b.ts)}<span class="sub muted" style="display:block;font-size:12px">checked ${ago(b.checked)}</span></span>
          <span class="delta"><span class="plus">+${b.added}</span> <span class="minus">-${b.removed}</span></span></label>`)}</div></div>
      <div>${st.text?.diff != null ? diffView(st.text.diff) : html`<pre class="config">${st.text?.config || ""}</pre>`}</div>
    </div>` : html`<p class="muted">No backups yet. PandoraBox backs up pre-configured devices every 6 hours and right after a config-change trap.</p>`}
  </section>`;
}

const featureName = (n) => ({ hostname: "Hostname", "mgmt-vlan": "Management VLAN", "mgmt-ports": "Management ports",
  access: "Login and SSH", snmp: "SNMP", role: "Role configuration" }[n] || n);

const diffView = (text) => html`<pre class="diff">${text ? text.split("\n").map((l) =>
  html`<span class="${l.startsWith("@@") ? "hunk" : l.startsWith("+") && !l.startsWith("+++") ? "add" : l.startsWith("-") && !l.startsWith("---") ? "del" : ""}">${l}\n</span>`) : "These two versions are identical."}</pre>`;

function pushTab(st) {
  return html`<div class="grid cols-dash">
    <section class="panel"><h2>Push config</h2>
      <p class="muted">Sent over SSH and saved. Lines that touch the reserved management ports, the management VLAN or PandoraBox's login are blocked unless you allow it.</p>
      <label class="field" for="push-text">Configuration lines</label>
      <textarea id="push-text" class="cli" rows="10" placeholder="interface Gi1/0/5&#10; switchport access vlan 20"></textarea>
      <div style="display:flex;gap:8px;align-items:center;margin-top:10px;flex-wrap:wrap">
        <button class="btn" data-act="dry">Show what changes</button><button class="btn primary" data-act="send">Push</button>
        <label class="check"><input type="checkbox" id="push-override"> Allow changes to management access</label></div>
      ${st.out ? html`<pre class="config" style="margin-top:12px">${st.out}</pre>` : ""}
    </section>
    <section class="panel"><h2>Sent before</h2>${pushList(st.pushes)}</section></div>`;
}
const pushList = (rows) => (rows.length ? rows.map((c) => html`<details style="padding:6px 0;border-bottom:1px solid var(--line)">
  <summary>${when(c.ts)}, ${c.method} <span class="muted">${c.result || ""}</span></summary><pre class="config">${c.text}</pre></details>`)
  : html`<p class="muted">Nothing sent to this device yet.</p>`);

function terminal(st) {
  const con = st.det.device.path === "console";
  return html`<section class="panel term-panel" id="term-panel"><div class="panel-head"><h2>Terminal</h2>
    <span class="muted">${con ? `Console ${st.det.device.console_port}` : `SSH to ${st.det.device.ip || "?"}`}</span>
    <span class="more term-tools">
      ${con ? html`<button class="btn small" data-act="break" title="Send a serial break (ROMMON, password recovery)">Send break</button>` : ""}
      <button class="btn small" data-act="ctrlc" title="Interrupt the running command">Ctrl+C</button>
      <button class="btn small" data-act="full">Full screen</button>
      <button class="btn small" data-act="connect">Reconnect</button></span></div>
    <div class="term" id="term"></div>
    <p class="muted term-hint">Keys go straight to the device: Tab completes, ? shows help, arrows recall history. Copy with Ctrl+Shift+C, paste with Ctrl+Shift+V.</p>
  </section>`;
}

function history(st) {
  return html`<div class="grid cols-dash">
    <section class="panel"><h2>Events</h2>${st.events.length ? html`<table class="table"><tbody>${st.events.map((e) =>
      html`<tr><td class="sub" style="width:170px">${when(e.ts)}</td><td>${e.actor}</td><td>${e.action}</td></tr>`)}</tbody></table>`
      : html`<p class="muted">No events yet.</p>`}</section>
    <section class="panel"><h2>Configuration sent</h2>${pushList(st.pushes)}</section></div>`;
}

// ---- actions ------------------------------------------------------------------------------------
async function fix(st) {
  const c = st.comp;
  const ok = await confirmDialog("Push this fix?", html`<p>These lines bring the device back to what PandoraBox intends. They may change the management ports and VLAN.</p>
    <pre class="config">${c.remediation.join("\n")}</pre>`, "Push fix");
  if (!ok) return;
  const r = await attempt(() => api.post(`/api/devices/${st.id}/remediate`, { confirm: true }));
  if (r) toast(r.result?.compliant ? "Fixed: the device is compliant again" : "Fix pushed, but some differences remain", r.result?.compliant ? "ok" : "error");
}

async function ack(problemId) {
  const r = await dialog({ title: "Acknowledge problem", body: html`<label class="field" for="ack-note">Note for the team (optional)</label><input id="ack-note" name="note" style="width:100%">`,
    actions: [{ label: "Cancel", value: false }, { label: "Acknowledge", value: true, kind: "primary" }] });
  if (r.value) await attempt(() => api.post(`/api/problems/${problemId}/ack`, { note: r.form.note || "" }), "Acknowledged");
}

async function push(st, dry, draw) {
  const text = document.getElementById("push-text").value;
  const override = document.getElementById("push-override").checked;
  if (!text.trim()) return toast("Type the configuration lines to send first.", "error");
  const r = await attempt(() => api.post(`/api/devices/${st.id}/config`, { text, dry_run: dry, override }));
  if (!r) return;
  if (r.blocked?.length && !r.diff && !r.output) st.out = `Blocked:\n${r.blocked.join("\n")}`;
  else st.out = r.diff ?? r.output ?? "";
  if (!dry && r.output != null) { toast("Pushed and saved", "ok"); st.pushes = await api.get(`/api/devices/${st.id}/configs`); }
  draw();
  document.getElementById("push-text").value = text;
}

export function closeTerminal(st) {
  if (!st.term) return;
  st.term.ro.disconnect();
  st.term.ws.close();
  st.term.xterm.dispose();
  st.term = null;
}

function openTerminal(st) {
  const el = document.getElementById("term");
  if (!el || !window.Terminal) return;
  closeTerminal(st);
  el.textContent = "";
  const xterm = new window.Terminal({
    fontSize: 14, lineHeight: 1.15, cursorBlink: true, scrollback: 10000,
    fontFamily: "'Atkinson Hyperlegible Mono', Consolas, ui-monospace, monospace",
    theme: { background: "#0f1418", foreground: "#d8e0e6", cursor: "#6fb2d9", selectionBackground: "#3a86b480" },
  });
  const fit = window.FitAddon ? new window.FitAddon.FitAddon() : null;
  if (fit) xterm.loadAddon(fit);
  xterm.open(el);
  fit?.fit();
  const ws = new WebSocket(`${location.protocol === "https:" ? "wss" : "ws"}://${location.host}/ws/term/${st.id}?cols=${xterm.cols}&rows=${xterm.rows}`);
  ws.binaryType = "arraybuffer";
  const send = (msg) => ws.readyState === 1 && ws.send(JSON.stringify(msg));
  ws.onmessage = (e) => xterm.write(typeof e.data === "string" ? e.data : new Uint8Array(e.data)); // xterm decodes UTF-8 itself
  ws.onclose = () => xterm.write("\r\n\x1b[2m[disconnected: press Reconnect]\x1b[0m\r\n");
  xterm.onData((d) => send({ data: d }));                       // every key, untouched: backspace, arrows, Tab, ?
  xterm.onResize(({ cols, rows }) => send({ resize: [cols, rows] }));
  xterm.attachCustomKeyEventHandler((e) => {                     // Ctrl+C stays an interrupt; Ctrl+Shift+C/V copy/paste
    if (e.type !== "keydown" || !e.ctrlKey || !e.shiftKey) return true;
    if (e.code === "KeyC") { navigator.clipboard?.writeText(xterm.getSelection()); return false; }
    if (e.code === "KeyV") { navigator.clipboard?.readText().then((t) => send({ data: t })); return false; }
    return true;
  });
  const ro = new ResizeObserver(() => { try { fit?.fit(); } catch { /* hidden */ } });
  ro.observe(el);
  xterm.focus();
  st.term = { ws, xterm, ro, send };
}
