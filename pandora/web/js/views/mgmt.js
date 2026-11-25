// Management network wizard (after pre-config): pick the L3 backbone(s), put every other device under one,
// review the exact lines and trunks, apply. One domain (VLAN + subnet) per backbone.
import { api } from "../api.js";
import { attempt, html, render, ROLE_LABEL } from "../ui.js";

const STEPS = ["Backbones", "Members", "Review", "Apply"];

export async function mount(root) {
  const cur = await api.get("/api/mgmt");
  const st = {
    step: 0, devices: cur.devices, plan: null, results: null, busy: false,
    domains: cur.domains.map((d) => ({ backbone: d.backbone_id, vlan: d.vlan, subnet: d.subnet })),
    members: { ...cur.members },
  };
  const byId = new Map(st.devices.map((d) => [d.id, d]));
  const label = (id) => byId.get(+id)?.hostname || `#${id}`;
  const isBackbone = (id) => st.domains.some((d) => d.backbone === +id);
  const domainBody = () => st.domains.map((d) => ({ backbone: d.backbone, vlan: +d.vlan, subnet: d.subnet }));

  const steps = [
    () => html`<p>Pick the L3 switch(es) that will route management. Each gets its own management VLAN and subnet;
        its VLAN interface becomes the gateway for the devices under it. The PC stays on VLAN ${cur.ops_vlan}
        (${cur.ops_subnet}), where every device already has an address.</p>
      <div class="scroll-x"><table class="table"><thead><tr><th>Backbone</th><th>Device</th><th>Model</th><th>Management VLAN</th><th>Subnet</th></tr></thead>
      <tbody>${st.devices.filter((d) => d.role !== "router_edge").map((d) => {
        const dom = st.domains.find((x) => x.backbone === d.id);
        return html`<tr><td><input type="checkbox" data-bb="${d.id}" ${dom ? "checked" : ""} aria-label="Use ${d.hostname} as a backbone"></td>
          <td>${d.hostname}</td><td>${d.pid || ""}</td>
          <td>${dom ? html`<input data-vlan="${d.id}" value="${dom.vlan}" inputmode="numeric" style="width:6em" aria-label="VLAN">` : ""}</td>
          <td>${dom ? html`<input data-subnet="${d.id}" value="${dom.subnet}" style="width:12em" aria-label="Subnet">` : ""}</td></tr>`;
      })}</tbody></table></div>
      ${st.devices.some((d) => d.role === "router_edge") ? html`<p class="muted">Edge routers can't be backbones; they join a backbone through a subinterface on their uplink.</p>` : ""}`,
    () => html`<p>Each device gets an SSH address in its backbone's VLAN. Suggested from the cabling (CDP): the nearest backbone through switches.</p>
      <button class="btn small" data-act="suggest">Suggest from cabling again</button>
      <div class="scroll-x" style="margin-top:12px"><table class="table"><thead><tr><th>Device</th><th>Role</th><th>Under backbone</th></tr></thead>
      <tbody>${st.devices.filter((d) => !isBackbone(d.id)).map((d) => html`<tr><td>${d.hostname}</td><td>${ROLE_LABEL[d.role] || d.role}</td>
        <td><select data-member="${d.id}" aria-label="Backbone for ${d.hostname}"><option value="">Not in the design</option>
          ${st.domains.map((x) => html`<option value="${x.backbone}" ${+st.members[d.id] === x.backbone ? "selected" : ""}>${label(x.backbone)} (VLAN ${x.vlan})</option>`)}</select></td></tr>`)}
      </tbody></table></div>`,
    () => review(),
    () => results(),
  ];

  function review() {
    const p = st.plan;
    if (!p) return html`<p class="muted">Reading the cabling and working out the changes…</p>`;
    return html`${p.problems.length ? html`<div class="panel" style="border-color:var(--led-red)"><p><strong>Fix these first:</strong></p>
        <ul>${p.problems.map((x) => html`<li>${x}</li>`)}</ul></div>`
      : html`<p>No conflicts. Backbones are configured first, then every other device; nothing existing is removed.</p>`}
      <div class="scroll-x"><table class="table"><thead><tr><th>Device</th><th>Part</th><th>New SSH address</th><th>Ports made trunks</th></tr></thead>
      <tbody>${p.devices.map((d) => html`<tr><td>${d.hostname}</td><td>${d.role === "backbone" ? "Backbone (gateway)" : d.role === "member" ? `Under ${label(d.backbone)}` : "Carries the VLAN"}</td>
        <td>${d.new_ip || ""}</td><td>${d.trunks.join(", ")}</td></tr>
        <tr><td></td><td colspan="3"><details><summary class="muted">Configuration that will be sent</summary><pre class="config">${d.lines.join("\n")}</pre></details></td></tr>`)}
      </tbody></table></div>
      ${p.pc_routes.length ? html`<h3>On this PC</h3><p>Reach each management subnet through its backbone (Administrator PowerShell, once):</p>
        <pre class="config">${p.pc_routes.map((r) => `New-NetRoute -DestinationPrefix ${r.subnet} -InterfaceAlias "${cur.iface || "Ethernet 2"}" -NextHop ${r.via}`).join("\n")}</pre>` : ""}`;
  }

  function results() {
    if (!st.results) return html`<p class="muted">Configuring backbones, then the other devices, then checking SSH on every new address…</p>`;
    const ok = st.results.filter((r) => r.pushed && (r.reachable || !r.new_ip)).length;
    return html`<p>${ok} of ${st.results.length} devices done.</p>
      <div class="scroll-x"><table class="table"><thead><tr><th>Device</th><th>Configured</th><th>SSH on new address</th><th>Error</th></tr></thead>
      <tbody>${st.results.map((r) => html`<tr><td>${r.hostname}</td>
        <td>${r.pushed ? html`<span class="state"><span class="led green"></span>Yes</span>` : html`<span class="state"><span class="led red"></span>No</span>`}</td>
        <td>${!r.new_ip ? "" : r.reachable ? html`<span class="state"><span class="led green"></span>${r.new_ip}</span>` : html`<span class="state"><span class="led amber"></span>${r.new_ip} not answering yet</span>`}</td>
        <td>${r.error || ""}</td></tr>`)}</tbody></table></div>
      <p class="muted">A device that doesn't answer on its new address keeps its old one in PandoraBox. Check the PC routes, then run the wizard again.</p>
      <h3>Old addresses</h3>
      <p>Every member still has its pre-config address in VLAN ${cur.ops_vlan}. Remove it from the members that answer on their new address; backbones keep theirs, it is the PC's way in. Do it now: until then a member answers over the old VLAN, so switches never learn its new address and flood every packet to it through the domain.</p>
      <button class="btn" data-act="retire" ${st.busy ? "disabled" : ""}>Remove old addresses</button>
      ${st.retired ? html`<ul>${st.retired.map((r) => html`<li>${r.hostname}: ${r.retired ? "removed" : r.error}</li>`)}</ul>` : ""}`;
  }

  const draw = () => {
    const blocked = (st.step === 0 && !st.domains.length) || (st.step === 2 && (!st.plan || !st.plan.ok)) || st.busy;
    render(root, html`<div class="page-head"><div><h1>Management network</h1>
      <p class="lede">After pre-config: one or more L3 backbones, every device reachable over SSH through its backbone's management VLAN.</p></div></div>
      <section class="panel onboard" aria-label="Management network wizard">
      <ol class="stepper" style="padding:0">${STEPS.map((s, i) => html`<li class="${i < st.step ? "done" : ""}" ${i === st.step ? html`aria-current="step"` : ""}>${s}</li>`)}</ol>
      ${steps[st.step]()}
      ${st.step < 3 ? html`<div style="display:flex;gap:8px;margin-top:16px">
        ${st.step ? html`<button class="btn" data-act="back">Back</button>` : ""}
        <button class="btn primary" data-act="next" ${blocked ? "disabled" : ""}>${["Choose members", "Review", "Apply to devices"][st.step]}</button>
        ${st.step === 2 ? html`<button class="btn" data-act="replan">Check again</button>` : ""}</div>`
      : html`<div style="margin-top:16px"><button class="btn" data-act="restart">Start over</button></div>`}
      </section>`);
  };

  const replan = async () => {
    st.plan = null; draw();
    st.plan = await attempt(() => api.post("/api/mgmt/plan", { domains: domainBody(), members: st.members }));
    draw();
  };
  const suggest = async () => {
    const s = await attempt(() => api.post("/api/mgmt/suggest", { backbones: st.domains.map((d) => d.backbone) }));
    if (s) { st.members = { ...st.members, ...s }; draw(); }
  };

  root.onchange = (e) => {
    const t = e.target;
    if (t.dataset.bb) {
      const id = +t.dataset.bb;
      if (t.checked) {
        const n = st.domains.length + 1;
        st.domains.push({ backbone: id, vlan: 10 * n, subnet: `10.${10 * n}.0.0/24` });
      } else {
        st.domains = st.domains.filter((d) => d.backbone !== id);
      }
      draw();
    }
    const dom = st.domains.find((d) => d.backbone === +(t.dataset.vlan || t.dataset.subnet));
    if (dom && t.dataset.vlan) dom.vlan = t.value.trim();
    if (dom && t.dataset.subnet) dom.subnet = t.value.trim();
    if (t.dataset.member) st.members[t.dataset.member] = t.value ? +t.value : "";
  };
  root.onclick = async (e) => {
    const act = e.target.closest("[data-act]")?.dataset.act;
    if (!act) return;
    if (act === "back") { st.step -= 1; draw(); }
    if (act === "retire" && confirm("Remove the old management-VLAN address from every member that answers on its new address?")) {
      st.busy = true; draw();
      const r = await attempt(() => api.post("/api/mgmt/retire", { confirm: true }), "Old addresses removed");
      st.busy = false; st.retired = r ? r.results : []; draw();
    }
    if (act === "restart") { st.step = 0; st.plan = st.results = null; draw(); }
    if (act === "suggest") await suggest();
    if (act === "replan") await replan();
    if (act === "next") {
      if (st.step === 0) {
        st.step = 1;
        if (!Object.keys(st.members).length) await suggest(); else draw();
      } else if (st.step === 1) { st.step = 2; await replan(); }
      else if (st.step === 2) {
        st.step = 3; st.busy = true; st.results = null; draw();
        const r = await attempt(() => api.post("/api/mgmt/apply", { domains: domainBody(), members: st.members }), "Management network applied");
        st.busy = false; st.results = r ? r.results : []; draw();
      }
    }
  };
  draw();
}
