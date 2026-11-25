// Problems (Zabbix): what needs attention, worst first. Acknowledge with a note; closes by itself on recovery.
import { api } from "../api.js";
import { on } from "../live.js";
import { ago, attempt, dialog, html, render, SEVERITIES } from "../ui.js";

export async function mount(root) {
  const st = { sev: "", closed: false, rows: [] };
  const load = async () => {
    st.rows = await api.get("/api/problems", { include_closed: st.closed || "" });
    draw();
  };
  const draw = () => {
    const rows = st.rows.filter((p) => !st.sev || p.severity === st.sev);
    const counts = Object.fromEntries(SEVERITIES.map((s) => [s, st.rows.filter((p) => p.severity === s && !p.closed).length]));
    render(root, html`
    <div class="page-head"><div><h1>Problems</h1>
      <p class="lede">Raised by SNMP polls, traps, compliance checks and pre-config results. They close by themselves when the cause is gone.</p></div></div>
    <div style="display:flex;gap:12px;align-items:center;flex-wrap:wrap;margin-bottom:12px">
      <div class="chips" role="group" aria-label="Filter by severity">${[...SEVERITIES].reverse().map((s) => html`<button class="chip" data-sev="${s}" aria-pressed="${st.sev === s}">${s}<span class="n">${counts[s]}</span></button>`)}</div>
      <label class="check"><input type="checkbox" id="show-closed" ${st.closed ? "checked" : ""}> Show resolved</label>
    </div>
    <section class="panel">${rows.length ? rows.map((p) => html`<div class="problem ${p.acked || p.closed ? "acked" : ""}">
        <span class="sev sev-${p.severity}"></span>
        <div><div class="msg">${p.message}</div>
          <div class="meta"><a href="#/devices/${p.device_id}">${p.hostname || `device #${p.device_id}`}</a>${p.ip ? ` (${p.ip})` : ""}, opened ${ago(p.opened)}
            ${p.closed ? `, resolved ${ago(p.closed)}` : ""}${p.acked ? `, acknowledged${p.note ? `: ${p.note}` : ""}` : ""}</div></div>
        <div style="display:flex;gap:8px;align-items:center"><span class="sev-pill sev-${p.severity}">${p.severity}</span>
          ${!p.acked && !p.closed ? html`<button class="btn small" data-ack="${p.id}">Acknowledge</button>` : ""}</div></div>`)
      : html`<div class="empty">${st.sev ? `No ${st.sev} problems.` : "No problems. Everything that PandoraBox watches is healthy."}</div>`}</section>`);
  };
  root.onclick = async (e) => {
    const sev = e.target.closest("[data-sev]")?.dataset.sev;
    if (sev) { st.sev = st.sev === sev ? "" : sev; draw(); }
    const id = e.target.closest("[data-ack]")?.dataset.ack;
    if (id) {
      const r = await dialog({ title: "Acknowledge problem",
        body: html`<label class="field" for="ack-note">Note for the team (optional)</label><input id="ack-note" name="note" style="width:100%">`,
        actions: [{ label: "Cancel", value: false }, { label: "Acknowledge", value: true, kind: "primary" }] });
      if (r.value) { await attempt(() => api.post(`/api/problems/${id}/ack`, { note: r.form.note || "" }), "Acknowledged"); load(); }
    }
  };
  root.onchange = (e) => { if (e.target.id === "show-closed") { st.closed = e.target.checked; load(); } };
  await load();
  const off = on("problem", () => load());
  return off;
}
