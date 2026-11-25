// Shell: hash router, nav state, live status, problem/approval badges, keyboard shortcuts, theme.
import { api } from "./api.js";
import { connect, on, onStatus } from "./live.js";
import { $, html, render, toast } from "./ui.js";

const ROUTES = [
  [/^\/?$/, "dashboard", () => import("./views/dashboard.js")],
  [/^\/devices\/(?<id>\d+)(?:\/(?<tab>\w+))?$/, "devices", () => import("./views/device.js")],
  [/^\/devices$/, "devices", () => import("./views/devices.js")],
  [/^\/topology$/, "topology", () => import("./views/topology.js")],
  [/^\/management$/, "management", () => import("./views/mgmt.js")],
  [/^\/problems$/, "problems", () => import("./views/problems.js")],
  [/^\/agent$/, "agent", () => import("./views/agent.js")],
];
const view = $("#view");
let dispose = null;
let seq = 0;

async function route() {
  const [path, query = ""] = location.hash.slice(1).split("?");
  const hit = ROUTES.map(([rx, nav, load]) => [path.match(rx), nav, load]).find(([m]) => m);
  if (dispose) { try { dispose(); } catch { /* view already gone */ } dispose = null; }
  document.querySelectorAll("[data-nav]").forEach((a) => a.removeAttribute("aria-current"));
  if (!hit) return render(view, html`<div class="panel empty">This page does not exist. <a href="#/">Go to the bench</a></div>`);
  const [m, nav, load] = hit;
  document.querySelector(`[data-nav="${nav}"]`)?.setAttribute("aria-current", "page");
  const params = { ...Object.fromEntries(new URLSearchParams(query)), ...(m.groups || {}) };
  const mine = ++seq;
  try {
    const mod = await load();
    const d = await mod.mount(view, params);
    if (mine === seq) dispose = d || null; else d?.();
  } catch (e) {
    console.error(e);
    render(view, html`<div class="panel empty">Could not load this page: ${e.message}</div>`);
  }
}

// ---- badges ------------------------------------------------------------------------------------
const pending = new Set();
async function refreshProblems() {
  try {
    const rows = await api.get("/api/problems");
    const b = $("#badge-problems");
    b.hidden = !rows.length;
    b.textContent = rows.length > 99 ? "99+" : rows.length;
  } catch { /* offline: the live dot already says so */ }
}
function refreshAgent() {
  const b = $("#badge-agent");
  b.hidden = !pending.size;
  b.textContent = pending.size;
}

// ---- boot ------------------------------------------------------------------------------------------
onStatus((s) => render($("#live"), html`<span class="led ${s === "live" ? "green" : s === "offline" ? "red" : "amber blink"}"></span>${s === "live" ? "Live" : s === "offline" ? "Reconnecting" : "Connecting"}`));
on("problem", (p) => {
  refreshProblems();
  if (p.state === "open" && ["high", "disaster"].includes(p.severity)) toast(`${p.severity}: ${p.message}`, "error");
});
on("approval", (a) => {
  pending.add(a.id); refreshAgent();
  if (!location.hash.startsWith("#/agent")) toast(`The agent wants to change ${a.device}. Open Agent to approve.`);
});
document.addEventListener("click", (e) => { const id = e.target.closest("[data-approve]")?.dataset.approve; if (id) { pending.delete(Number(id)); refreshAgent(); } });

$("#search").addEventListener("submit", (e) => {
  e.preventDefault();
  const q = $("#search-q").value.trim();
  location.hash = `#/devices${q ? `?q=${encodeURIComponent(q)}` : ""}`;
});
document.addEventListener("keydown", (e) => {
  const typing = /INPUT|TEXTAREA|SELECT/.test(document.activeElement?.tagName) || document.activeElement?.closest?.(".term");
  if (e.key === "/" && !typing) { e.preventDefault(); $("#search-q").focus(); }
  if (e.key === "Escape" && document.activeElement === $("#search-q")) $("#search-q").blur();
});
$("#theme-toggle").addEventListener("click", (e) => {
  e.preventDefault();
  const dark = document.documentElement.dataset.theme
    ? document.documentElement.dataset.theme === "dark"
    : matchMedia("(prefers-color-scheme: dark)").matches;
  document.documentElement.dataset.theme = dark ? "light" : "dark";
  try { localStorage.setItem("pandora.theme", document.documentElement.dataset.theme); } catch { /* private mode */ }
  route(); // charts and the topology read colours when drawn
});

window.addEventListener("hashchange", route);
connect();
refreshProblems();
route();
