// Small UI toolkit: auto-escaping templates, time, toasts, dialogs, shared vocab.
// Everything that came from a device or the network goes through html`` (escaped by default).

class Safe { constructor(s) { this.s = s; } toString() { return this.s; } }
export const raw = (s) => new Safe(String(s));
const ESC = { "&": "&amp;", "<": "&lt;", ">": "&gt;", '"': "&quot;", "'": "&#39;" };
export const esc = (v) => String(v ?? "").replace(/[&<>"']/g, (c) => ESC[c]);
const part = (v) => (v instanceof Safe ? v.s : Array.isArray(v) ? v.map(part).join("") : v === false || v == null ? "" : esc(v));
export function html(strings, ...vals) {
  return new Safe(strings.reduce((out, s, i) => out + s + (i < vals.length ? part(vals[i]) : ""), ""));
}
export const render = (el, safe) => { el.innerHTML = safe instanceof Safe ? safe.s : esc(safe); return el; };
export const $ = (s, root = document) => root.querySelector(s);
export const $$ = (s, root = document) => [...root.querySelectorAll(s)];

export function ago(ts) {
  if (!ts) return "never";
  const s = Math.max(0, Date.now() / 1000 - ts);
  if (s < 60) return "just now";
  if (s < 3600) return `${Math.floor(s / 60)} min ago`;
  if (s < 86400) return `${Math.floor(s / 3600)} h ago`;
  return new Date(ts * 1000).toLocaleDateString();
}
export const when = (ts) => (ts ? new Date(ts * 1000).toLocaleString() : "");

export const SEVERITIES = ["info", "warning", "average", "high", "disaster"];
export const STATES = ["discovered", "identified", "needs_credentials", "queued", "provisioning", "provisioned", "failed"];
export const STATE_LABEL = {
  discovered: "Discovered", identified: "Identified", needs_credentials: "Needs login", queued: "Queued",
  provisioning: "Configuring", provisioned: "Ready", failed: "Failed",
};
export const PATH_LABEL = { pnp: "PnP", ztp: "ZTP", autoinstall: "AutoInstall", console: "Console", ssh: "SSH" };
export const ROLE_LABEL = { switch_access: "Access switch", router_edge: "Edge router" };

export function stateBadge(state) {
  const led = { provisioned: "green", failed: "red", needs_credentials: "amber", queued: "amber", provisioning: "amber blink" }[state] || "";
  return html`<span class="state"><span class="led ${led}"></span>${STATE_LABEL[state] || state}</span>`;
}
export const sevPill = (sev) => (sev ? html`<span class="sev-pill sev-${sev}">${sev}</span>` : "");
export const deviceName = (d) => d.hostname || d.alloc_hostname || d.serial || d.ip || d.console_port || `#${d.id}`;

// ---- toasts ----------------------------------------------------------------------------------
export function toast(msg, kind = "") {
  let box = $(".toasts");
  if (!box) { box = document.createElement("div"); box.className = "toasts"; box.setAttribute("role", "status"); document.body.append(box); }
  const t = document.createElement("div");
  t.className = `toast ${kind}`;
  t.textContent = msg;
  box.append(t);
  setTimeout(() => t.remove(), kind === "error" ? 8000 : 4000);
}

// ---- dialog: resolves with the clicked action's value (or null) and the form's values -----------
export function dialog({ title, body, actions = [{ label: "Close", value: null }] }) {
  return new Promise((resolve) => {
    const d = document.createElement("dialog");
    render(d, html`<form method="dialog"><h2>${title}</h2><div class="dlg-body">${body}</div>
      <div class="actions">${actions.map((a, i) => html`<button class="btn ${a.kind || ""}" value="${i}">${a.label}</button>`)}</div></form>`);
    document.body.append(d);
    d.addEventListener("close", () => {
      const a = actions[Number(d.returnValue)];
      const form = Object.fromEntries(new FormData(d.querySelector("form")));
      d.remove();
      resolve({ value: a ? a.value : null, form });
    });
    d.showModal();
    d.querySelector("input,textarea,select")?.focus();
  });
}
export const confirmDialog = (title, body, label = "Confirm", kind = "primary") =>
  dialog({ title, body, actions: [{ label: "Cancel", value: false }, { label, value: true, kind }] }).then((r) => r.value === true);

// Run an async action, toast the error instead of failing silently.
export async function attempt(fn, okMsg) {
  try { const r = await fn(); if (okMsg) toast(okMsg, "ok"); return r; }
  catch (e) { toast(e.message, "error"); return null; }
}
