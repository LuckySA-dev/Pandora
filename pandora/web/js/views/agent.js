// AI agent: give a goal, watch each step, approve every change before it reaches a device.
import { api } from "../api.js";
import { on } from "../live.js";
import { attempt, html, render, toast } from "../ui.js";

const EXAMPLES = [
  "Which devices have a port down, and why?",
  "Put Gi1/0/5 on lab-sw-01 into VLAN 20 and verify",
  "Check that every switch can reach 10.99.0.1",
];
const transcript = []; // kept while the page is open, so switching views keeps the conversation
let redraw = null;
let listening = false;

function listen() { // once per page load: steps and approvals keep arriving while you look at other views
  if (listening) return;
  listening = true;
  on("agent", (a) => { transcript.push(a); redraw?.(); });
  on("approval", (a) => { transcript.push({ ...a, kind: "approval" }); redraw?.(); });
}

export async function mount(root) {
  listen();
  const draw = () => {
    render(root, html`
    <div class="page-head"><div><h1>Agent</h1>
      <p class="lede">Works like an engineer at the CLI: looks first, proposes the smallest change, waits for your approval, then verifies.</p></div></div>
    <section class="panel" style="margin-bottom:16px">
      <label class="field" for="goal" style="margin-top:0">What should the agent do?</label>
      <textarea id="goal" rows="2" placeholder="Describe the outcome, for example: put Gi1/0/5 on lab-sw-01 into VLAN 20"></textarea>
      <div style="display:flex;gap:8px;margin-top:10px;align-items:center;flex-wrap:wrap">
        <button class="btn primary" data-act="run">Run</button>
        <span class="muted" style="font-size:13px">Read-only commands run on their own. Every change waits for Approve.</span></div>
      <div class="suggestions">${EXAMPLES.map((x) => html`<button class="chip" data-example="${x}">${x}</button>`)}</div>
    </section>
    <section class="transcript" aria-live="polite">${transcript.map(turn)}</section>`);
  };
  const add = (t) => { transcript.push(t); draw(); window.scrollTo(0, document.body.scrollHeight); };
  if (transcript.some((t) => t.kind === "approval" && !t.answer)) toast("The agent is waiting for your approval below.");
  root.onclick = async (e) => {
    const ex = e.target.closest("[data-example]")?.dataset.example;
    if (ex) { document.getElementById("goal").value = ex; document.getElementById("goal").focus(); }
    const act = e.target.closest("[data-act]")?.dataset.act;
    if (act === "run") {
      const goal = document.getElementById("goal").value.trim();
      if (!goal) return document.getElementById("goal").focus();
      add({ kind: "you", text: goal });
      await attempt(() => api.post("/api/agent", { goal }));
    }
    const ap = e.target.closest("[data-approve]");
    if (ap) {
      const ok = ap.dataset.ok === "1";
      await attempt(() => api.post(`/api/approve/${ap.dataset.approve}`, { ok }));
      const t = transcript.find((x) => x.kind === "approval" && String(x.id) === ap.dataset.approve);
      if (t) t.answer = ok ? "Approved" : "Rejected";
      draw();
    }
  };
  redraw = () => { draw(); window.scrollTo(0, document.body.scrollHeight); };
  draw();
  return () => { redraw = null; };
}

function turn(t) {
  if (t.kind === "you") return html`<div class="turn you">${t.text}</div>`;
  if (t.kind === "text") return html`<div class="turn text">${t.text}</div>`;
  if (t.kind === "tool") return html`<div class="turn tool">Running ${t.name} ${JSON.stringify(t.args)}</div>`;
  if (t.kind === "result") return html`<div class="turn tool ${t.error ? "err" : ""}"><details><summary>${t.name} ${t.error ? "failed" : "result"}</summary><pre>${t.output}</pre></details></div>`;
  if (t.kind === "error") return html`<div class="turn err">${t.text}</div>`;
  if (t.kind === "done") return html`<div class="turn muted">Finished.</div>`;
  if (t.kind === "approval") return html`<div class="turn approval"><h3>Approve change on ${t.device}?</h3>
    <p class="muted">${t.reason}</p><pre class="config">${(t.lines || []).join("\n")}</pre>
    ${t.answer ? html`<p><b>${t.answer}</b></p>` : html`<div style="display:flex;gap:8px;margin-top:10px">
      <button class="btn primary" data-approve="${t.id}" data-ok="1">Approve and apply</button>
      <button class="btn" data-approve="${t.id}" data-ok="0">Reject</button></div>`}</div>`;
  return "";
}
