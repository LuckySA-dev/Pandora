// Topology as a Figma-style canvas: dot grid, device cards that stay exactly where you put them
// (no physics), pan/zoom like a design tool, marquee select, align, snap, properties panel.
//   V select, H or hold Space: hand, Ctrl/Cmd+scroll or +/-: zoom, scroll: pan, Shift+1: fit, Shift+0: 100%,
//   arrows: nudge (Shift = 10 px), Ctrl+A: select all, Esc: clear, double-click a card: open the device.
import { api } from "../api.js";
import { on } from "../live.js";
import { $, attempt, html, render, toast } from "../ui.js";

const KEY = "pandora.topology.layout.v3"; // v3: tiered layout (edge routers, L3 backbones, then their switches)
const GRID = 20, W = 200, H = 68, MIN_K = 0.2, MAX_K = 3;
const css = (v) => getComputedStyle(document.documentElement).getPropertyValue(v).trim();
const short = (p) => String(p || "").replace(/^([A-Za-z]{2})[A-Za-z-]*?(\d)/, "$1$2");
const load = () => { try { return JSON.parse(localStorage.getItem(KEY) || "{}"); } catch { return {}; } };
const save = (o) => { try { localStorage.setItem(KEY, JSON.stringify(o)); } catch { /* private mode */ } };

export async function mount(root) {
  const s = { nodes: new Map(), edges: [], view: { x: 60, y: 60, k: 1 }, sel: new Set(), tool: "select", snap: true,
    space: false, drag: null, collected: 0, raf: 0 };
  Object.assign(s, load().ui || {});

  render(root, html`
  <div class="page-head"><div><h1>Topology</h1>
    <p class="lede" id="topo-lede">Links learned from CDP and LLDP. Cards stay where you put them.</p></div></div>
  <div class="canvas-wrap" id="canvas-wrap">
    <svg id="cv" class="canvas tool-select" role="application" aria-label="Topology canvas" tabindex="0"></svg>
    <div class="canvas-toolbar" role="toolbar" aria-label="Canvas tools">
      <button data-tool="select" title="Select (V)" aria-label="Select tool">${icon("select")}</button>
      <button data-tool="hand" title="Hand (H, or hold Space)" aria-label="Hand tool">${icon("hand")}</button>
      <span class="sep"></span>
      <button data-cmd="zoom-out" title="Zoom out (-)" aria-label="Zoom out">${icon("minus")}</button>
      <button data-cmd="zoom-100" class="zoom" title="Zoom to 100% (Shift+0)" id="zoom-label">100%</button>
      <button data-cmd="zoom-in" title="Zoom in (+)" aria-label="Zoom in">${icon("plus")}</button>
      <button data-cmd="fit" title="Zoom to fit (Shift+1)" aria-label="Zoom to fit">${icon("fit")}</button>
      <span class="sep"></span>
      <button data-cmd="layout" title="Auto layout: arrange by links" aria-label="Auto layout">${icon("layout")}</button>
      <button data-cmd="snap" title="Snap to grid" aria-label="Snap to grid" id="snap-btn">${icon("grid")}</button>
      <button data-cmd="refresh" title="Collect links again from the devices" aria-label="Refresh links" id="refresh-btn">${icon("refresh")}</button>
    </div>
    <aside class="canvas-panel" id="props" aria-live="polite"></aside>
  </div>`);
  const svg = $("#cv", root);

  // ---- data ------------------------------------------------------------------------------------------
  async function fetchGraph(fresh) {
    const btn = $("#refresh-btn", root);
    btn?.classList.add("busy");
    const wait = $("#topo-lede", root);  // the first collection asks every device (SNMP, then SSH): say so
    if (wait && (fresh || !s.nodes.size)) wait.textContent = "Collecting links from the devices (CDP and LLDP)… this can take a minute.";
    const g = await attempt(() => api.get("/api/topology", { fresh: fresh || "" }));
    btn?.classList.remove("busy");
    if (!g) return;
    const saved = load().pos || {};
    const old = s.nodes;
    s.nodes = new Map(g.nodes.map((n) => {
      const id = String(n.id);
      const p = old.get(id) || saved[id];
      return [id, { ...n, id, x: p?.x, y: p?.y }];
    }));
    s.edges = g.edges.map((e) => ({ ...e, from: String(e.from), to: String(e.to) }));
    s.collected = g.collected;
    const missing = [...s.nodes.values()].filter((n) => n.x == null);
    if (missing.length) {
      const auto = autoLayout(s);
      missing.forEach((n) => Object.assign(n, auto.get(n.id)));
      if (missing.length === s.nodes.size) fit();
    }
    const lede = $("#topo-lede", root);
    if (lede && g.collected) lede.textContent = `${s.nodes.size} devices, ${s.edges.length} cabled links from CDP and LLDP, collected ${new Date(g.collected * 1000).toLocaleTimeString()}.`
      + (g.shared ? ` ${g.shared} neighbours heard over a shared segment (an out-of-band switch or hub) are left out: they are not cables.` : "")
      + " Select a card to see its port numbers.";
    draw();
  }

  // ---- drawing -----------------------------------------------------------------------------------------
  function draw() {
    cancelAnimationFrame(s.raf);
    s.raf = requestAnimationFrame(paint);
  }
  function paint() {
    const { x, y, k } = s.view;
    const nodes = [...s.nodes.values()];
    render(svg, html`
      <defs><pattern id="dots" width="${GRID}" height="${GRID}" patternUnits="userSpaceOnUse" patternTransform="translate(${x} ${y}) scale(${k})">
        <circle cx="1" cy="1" r="${Math.max(0.6, 1 / k)}" class="dot"></circle></pattern></defs>
      <rect class="bg" width="100%" height="100%" fill="url(#dots)"></rect>
      <g transform="translate(${x} ${y}) scale(${k})">
        ${s.edges.map((e) => edge(s, e, s.sel.has(e.from) || s.sel.has(e.to)))}
        ${nodes.map((n) => card(n, s.sel.has(n.id), k))}
      </g>
      ${s.drag?.marquee ? html`<rect class="marquee" x="${Math.min(s.drag.mx0, s.drag.mx1)}" y="${Math.min(s.drag.my0, s.drag.my1)}"
        width="${Math.abs(s.drag.mx1 - s.drag.mx0)}" height="${Math.abs(s.drag.my1 - s.drag.my0)}"></rect>` : ""}`);
    $("#zoom-label", root).textContent = `${Math.round(k * 100)}%`;
    root.querySelectorAll("[data-tool]").forEach((b) => b.setAttribute("aria-pressed", String(b.dataset.tool === activeTool())));
    $("#snap-btn", root).setAttribute("aria-pressed", String(s.snap));
    svg.setAttribute("class", `canvas tool-${activeTool()}${s.drag?.pan ? " panning" : ""}`);
    props();
  }
  const activeTool = () => (s.space ? "hand" : s.tool);

  function props() {
    const panel = $("#props", root);
    const sel = [...s.sel].map((id) => s.nodes.get(id)).filter(Boolean);
    if (sel.length === 1) {
      const n = sel[0];
      const dev = /^\d+$/.test(n.id);
      render(panel, html`<h3>${n.label}</h3>
        <p class="muted">${n.title || (dev ? "" : "Neighbour seen over CDP/LLDP, not in the inventory")}</p>
        ${n.severity ? html`<p><span class="sev-pill sev-${n.severity}">${n.severity} problem</span></p>` : dev ? html`<p class="muted">No open problems</p>` : ""}
        <div class="xy"><label>X <input type="number" step="${GRID}" data-xy="x" value="${Math.round(n.x)}"></label>
          <label>Y <input type="number" step="${GRID}" data-xy="y" value="${Math.round(n.y)}"></label></div>
        ${dev ? html`<a class="btn primary" href="#/devices/${n.id}">Open device</a>` : ""}
        <p class="muted hint">${linksOf(n.id).length} link${linksOf(n.id).length === 1 ? "" : "s"}</p>`);
    } else if (sel.length > 1) {
      render(panel, html`<h3>${sel.length} selected</h3>
        <div class="align" role="group" aria-label="Align">
          <button class="btn small" data-align="left">Align left</button><button class="btn small" data-align="top">Align top</button>
          <button class="btn small" data-align="hspace">Space evenly across</button><button class="btn small" data-align="vspace">Space evenly down</button></div>
        <p class="muted hint">Drag any selected card to move them together.</p>`);
    } else {
      render(panel, html`<h3>Canvas</h3>
        <div class="legend">
          <span><i class="sw" style="background:var(--led-green)"></i>Ready, no problems</span>
          <span><i class="sw" style="background:var(--led-amber)"></i>Warning or in progress</span>
          <span><i class="sw" style="background:var(--led-red)"></i>High or disaster problem</span>
          <span><i class="sw" style="background:var(--led-off)"></i>Not in the inventory</span>
          <span><svg width="26" height="8" aria-hidden="true"><line x1="0" y1="4" x2="26" y2="4" stroke="${css("--led-red")}" stroke-width="2" stroke-dasharray="5 3"></line></svg>Link with a port down</span></div>
        <p class="muted hint">Click a card to see it here. Drag on empty space to select several. Ctrl+scroll zooms, scroll pans, Space+drag moves the canvas.</p>`);
    }
  }
  const linksOf = (id) => s.edges.filter((e) => e.from === id || e.to === id);

  // ---- geometry helpers -----------------------------------------------------------------------------
  const rect = () => svg.getBoundingClientRect();
  const toWorld = (cx, cy) => { const r = rect(); return { x: (cx - r.left - s.view.x) / s.view.k, y: (cy - r.top - s.view.y) / s.view.k }; };
  const snapV = (v) => (s.snap ? Math.round(v / GRID) * GRID : v);
  function zoomAt(k, cx, cy) {
    const r = rect();
    const px = cx ?? r.left + r.width / 2, py = cy ?? r.top + r.height / 2;
    const w = toWorld(px, py);
    s.view.k = Math.min(MAX_K, Math.max(MIN_K, k));
    s.view.x = px - r.left - w.x * s.view.k;
    s.view.y = py - r.top - w.y * s.view.k;
    persist(); draw();
  }
  function fit() {
    const ns = [...s.nodes.values()];
    if (!ns.length) return;
    const r = rect(), pad = 60;
    const x0 = Math.min(...ns.map((n) => n.x)), y0 = Math.min(...ns.map((n) => n.y) ) - 20;
    const x1 = Math.max(...ns.map((n) => n.x + W)), y1 = Math.max(...ns.map((n) => n.y + H));
    const k = Math.min(MAX_K, Math.max(MIN_K, Math.min((r.width - pad * 2 - 260) / (x1 - x0 || 1), (r.height - pad * 2) / (y1 - y0 || 1))));
    s.view = { k, x: pad - x0 * k, y: pad - y0 * k };
    persist(); draw();
  }
  function persist() {
    const pos = {};
    s.nodes.forEach((n, id) => { pos[id] = { x: n.x, y: n.y }; });
    save({ pos: { ...(load().pos || {}), ...pos }, ui: { view: s.view, snap: s.snap } });
  }

  // ---- pointer -------------------------------------------------------------------------------------------
  svg.addEventListener("pointerdown", (e) => {
    svg.focus();
    const g = e.target.closest(".node");
    if (e.button === 1 || activeTool() === "hand") {
      s.drag = { pan: true, px: e.clientX, py: e.clientY, vx: s.view.x, vy: s.view.y };
    } else if (g) {
      const id = g.dataset.id;
      if (e.shiftKey) { s.sel.has(id) ? s.sel.delete(id) : s.sel.add(id); } else if (!s.sel.has(id)) { s.sel = new Set([id]); }
      const w = toWorld(e.clientX, e.clientY);
      s.drag = { move: true, wx: w.x, wy: w.y, start: new Map([...s.sel].map((i) => [i, { x: s.nodes.get(i).x, y: s.nodes.get(i).y }])), moved: false };
    } else {
      if (!e.shiftKey) s.sel.clear();
      const r = rect();
      s.drag = { marquee: true, mx0: e.clientX - r.left, my0: e.clientY - r.top, mx1: e.clientX - r.left, my1: e.clientY - r.top, base: new Set(s.sel) };
    }
    svg.setPointerCapture(e.pointerId);
    draw();
  });
  svg.addEventListener("pointermove", (e) => {
    const d = s.drag;
    if (!d) return;
    if (d.pan) { s.view.x = d.vx + e.clientX - d.px; s.view.y = d.vy + e.clientY - d.py; }
    if (d.move) {
      const w = toWorld(e.clientX, e.clientY);
      const anchor = d.start.values().next().value;
      const dx = snapV(anchor.x + w.x - d.wx) - anchor.x, dy = snapV(anchor.y + w.y - d.wy) - anchor.y;
      d.start.forEach((p, id) => { const n = s.nodes.get(id); n.x = p.x + dx; n.y = p.y + dy; });
      d.moved = d.moved || dx !== 0 || dy !== 0;
    }
    if (d.marquee) {
      const r = rect();
      d.mx1 = e.clientX - r.left; d.my1 = e.clientY - r.top;
      const a = toWorld(Math.min(d.mx0, d.mx1) + r.left, Math.min(d.my0, d.my1) + r.top);
      const b = toWorld(Math.max(d.mx0, d.mx1) + r.left, Math.max(d.my0, d.my1) + r.top);
      s.sel = new Set(d.base);
      s.nodes.forEach((n, id) => { if (n.x < b.x && n.x + W > a.x && n.y < b.y && n.y + H > a.y) s.sel.add(id); });
    }
    draw();
  });
  const end = () => { if (s.drag?.moved || s.drag?.pan) persist(); s.drag = null; draw(); };
  svg.addEventListener("pointerup", end);
  svg.addEventListener("pointercancel", end);
  svg.addEventListener("dblclick", (e) => {
    const id = e.target.closest(".node")?.dataset.id;
    if (id && /^\d+$/.test(id)) location.hash = `#/devices/${id}`;
  });
  svg.addEventListener("wheel", (e) => {
    e.preventDefault();
    if (e.ctrlKey || e.metaKey) zoomAt(s.view.k * Math.exp(-e.deltaY * 0.0025), e.clientX, e.clientY);
    else { s.view.x -= e.shiftKey ? e.deltaY : e.deltaX; s.view.y -= e.shiftKey ? 0 : e.deltaY; persist(); draw(); }
  }, { passive: false });

  // ---- keyboard ------------------------------------------------------------------------------------------
  const typing = () => /INPUT|TEXTAREA|SELECT/.test(document.activeElement?.tagName);
  const onKey = (e) => {
    if (typing()) return;
    if (e.code === "Space" && !s.space && e.type === "keydown") { s.space = true; draw(); e.preventDefault(); return; }
    if (e.type !== "keydown") return;
    const k = e.key;
    if (k === "v" || k === "V") s.tool = "select";
    else if (k === "h" || k === "H") s.tool = "hand";
    else if (k === "+" || k === "=") zoomAt(s.view.k * 1.25);
    else if (k === "-" || k === "_") zoomAt(s.view.k / 1.25);
    else if (e.shiftKey && e.code === "Digit1") fit();
    else if (e.shiftKey && e.code === "Digit0") zoomAt(1);
    else if (k === "Escape") s.sel.clear();
    else if ((e.ctrlKey || e.metaKey) && (k === "a" || k === "A")) { e.preventDefault(); s.sel = new Set(s.nodes.keys()); }
    else if (k.startsWith("Arrow") && s.sel.size) {
      e.preventDefault();
      const step = e.shiftKey ? 10 : 1;
      const [dx, dy] = { ArrowLeft: [-step, 0], ArrowRight: [step, 0], ArrowUp: [0, -step], ArrowDown: [0, step] }[k];
      s.sel.forEach((id) => { const n = s.nodes.get(id); n.x += dx; n.y += dy; });
      persist();
    } else return;
    draw();
  };
  const onKeyUp = (e) => { if (e.code === "Space") { s.space = false; draw(); } };
  document.addEventListener("keydown", onKey);
  document.addEventListener("keyup", onKeyUp);

  // ---- toolbar + panel ------------------------------------------------------------------------------------
  root.addEventListener("click", async (e) => {
    const t = e.target.closest("[data-tool]")?.dataset.tool;
    if (t) { s.tool = t; draw(); }
    const c = e.target.closest("[data-cmd]")?.dataset.cmd;
    if (c === "zoom-in") zoomAt(s.view.k * 1.25);
    if (c === "zoom-out") zoomAt(s.view.k / 1.25);
    if (c === "zoom-100") zoomAt(1);
    if (c === "fit") fit();
    if (c === "snap") { s.snap = !s.snap; persist(); draw(); }
    if (c === "refresh") await fetchGraph(true);
    if (c === "layout") {
      const auto = autoLayout(s);
      s.nodes.forEach((n, id) => Object.assign(n, auto.get(id)));
      persist(); fit(); toast("Arranged by links. Drag cards to fine-tune.");
    }
    const a = e.target.closest("[data-align]")?.dataset.align;
    if (a) { align(s, a); persist(); draw(); }
  });
  root.addEventListener("change", (e) => {
    const k = e.target.dataset.xy;
    if (!k || s.sel.size !== 1) return;
    const n = s.nodes.get([...s.sel][0]);
    n[k] = Number(e.target.value) || 0;
    persist(); draw();
  });

  await fetchGraph(false);
  if (!load().ui?.view) fit();
  const off = on("problem", () => fetchGraph(false)); // recolour, never move
  return () => { off(); document.removeEventListener("keydown", onKey); document.removeEventListener("keyup", onKeyUp); cancelAnimationFrame(s.raf); };
}

// ---- pieces ---------------------------------------------------------------------------------------------
function colorOf(n) {
  if (n.group === "me") return "var(--cable)";
  if (n.group === "external") return "var(--led-off)";
  if (["high", "disaster"].includes(n.severity) || n.group === "failed") return "var(--led-red)";
  if (n.severity || n.group !== "provisioned") return "var(--led-amber)";
  return "var(--led-green)";
}

function card(n, selected, k) {
  const c = colorOf(n);
  const sub = n.group === "me" ? "This laptop" : n.group === "external" ? "Not in inventory" : n.title || "";
  return html`<g class="node ${selected ? "selected" : ""} ${n.group === "external" ? "external" : ""}" data-id="${n.id}" transform="translate(${n.x} ${n.y})">
    <text class="frame-label" x="0" y="-8" style="font-size:${11 / Math.max(k, 0.6)}px">${n.group === "me" ? "PandoraBox" : n.group === "external" ? "Neighbour" : "Device"}</text>
    <rect class="card" width="${W}" height="${H}" rx="8"></rect>
    <rect x="0" y="0" width="5" height="${H}" rx="2" fill="${c}"></rect>
    <circle cx="${W - 16}" cy="18" r="5" fill="${c}"></circle>
    <text class="n-title" x="16" y="28">${String(n.label).slice(0, 22)}</text>
    <text class="n-sub" x="16" y="49">${String(sub).trim().slice(0, 30)}</text>
    ${selected ? html`<rect class="sel-outline" x="-3" y="-3" width="${W + 6}" height="${H + 6}" rx="10"></rect>
      ${[[-3, -3], [W - 3, -3], [-3, H - 3], [W - 3, H - 3]].map(([hx, hy]) => html`<rect class="handle" x="${hx - 1}" y="${hy - 1}" width="8" height="8"></rect>`)}` : ""}
  </g>`;
}

// Cards in different rows: an uplink, drawn top to bottom. Same row: a peer link (access pair, router pair),
// drawn lighter so the tree reads first. Port numbers only for the selected card's links.
function edge(s, e, labelled) {
  let a = s.nodes.get(e.from), b = s.nodes.get(e.to);
  if (!a || !b || a.x == null || b.x == null) return "";
  let pa = e.from_port, pb = e.to_port;
  const vertical = Math.abs(a.y - b.y) > H;
  let d, mx, my;
  if (vertical) {
    if (a.y > b.y) { [a, b] = [b, a]; [pa, pb] = [pb, pa]; }
    const x1 = a.x + W / 2, y1 = a.y + H, x2 = b.x + W / 2, y2 = b.y;
    const dy = (y2 - y1) / 2;
    d = `M${x1} ${y1} C${x1} ${y1 + dy} ${x2} ${y2 - dy} ${x2} ${y2}`;
    mx = (x1 + x2) / 2; my = (y1 + y2) / 2;
  } else {
    const right = b.x >= a.x;
    const x1 = right ? a.x + W : a.x, x2 = right ? b.x : b.x + W, y = a.y + H, y2 = b.y + H;
    const dip = 28 + Math.min(60, Math.abs(x2 - x1) / 6); // a shallow arc under the row, clear of the cards
    d = `M${x1 - (right ? 20 : -20)} ${y} C${x1} ${y + dip} ${x2} ${y2 + dip} ${x2 + (right ? 20 : -20)} ${y2}`;
    mx = (x1 + x2) / 2; my = (y + y2) / 2 + dip * 0.75;
  }
  const label = `${short(pa)}  ${short(pb)}`;
  return html`<g class="edge ${e.down ? "down" : ""} ${vertical ? "" : "peer"}"><path d="${d}"></path>
    ${labelled ? html`<g transform="translate(${mx} ${my})"><rect class="pill" x="${-label.length * 3.4 - 8}" y="-10" width="${label.length * 6.8 + 16}" height="20" rx="10"></rect>
    <text class="pill-text" text-anchor="middle" y="4">${label}</text></g>` : ""}</g>`;
}

// Tiers, top to bottom, like a campus drawing: edge routers (and PandoraBox), the L3 backbones, then every
// switch by its hop count from the nearest backbone. Without a management design the best-connected switches
// stand in for backbones. Each row is ordered by where its uplinks sit above (barycentre), which keeps a
// switch under its backbone and the lines from crossing. O(nodes + links) plus a sort per row.
function autoLayout(s) {
  const ids = [...s.nodes.keys()];
  const adj = new Map(ids.map((i) => [i, new Set()]));
  s.edges.forEach((e) => { adj.get(e.from)?.add(e.to); adj.get(e.to)?.add(e.from); });
  const node = (id) => s.nodes.get(id);
  const top = (id) => id === "PandoraBox" || node(id).role === "router_edge";
  let roots = ids.filter((id) => node(id).backbone);
  if (!roots.length) {
    const sw = ids.filter((id) => !top(id) && /^\d+$/.test(id));
    const most = Math.max(0, ...sw.map((id) => adj.get(id).size));
    roots = sw.filter((id) => most && adj.get(id).size === most);
  }
  const tier = new Map(roots.map((id) => [id, 1]));
  const queue = [...roots];
  for (let i = 0; i < queue.length; i++) { // BFS, never through a router (routers sit on top)
    const u = queue[i];
    adj.get(u).forEach((v) => { if (!tier.has(v) && !top(v)) { tier.set(v, tier.get(u) + 1); queue.push(v); } });
  }
  ids.forEach((id) => { if (top(id)) tier.set(id, 0); });
  const last = Math.max(1, ...tier.values()) + 1;
  ids.forEach((id) => { if (!tier.has(id)) tier.set(id, last); }); // islands and neighbours with no path

  const rows = [];
  tier.forEach((t, id) => (rows[t] ||= []).push(id));
  const pos = new Map();
  const place = (row, y) => row.forEach((id, i) => pos.set(id, { x: i * (W + 40), y }));
  const bary = (id, ref) => {
    const xs = [...adj.get(id)].filter((m) => pos.has(m) && ref(m)).map((m) => pos.get(m).x);
    return xs.length ? xs.reduce((a, b) => a + b, 0) / xs.length : Infinity;
  };
  let y = 0;
  const order = [1, 0, ...rows.keys()].filter((t, i, a) => rows[t] && a.indexOf(t) === i);
  // place the backbones first, then routers above them, then each lower row under its uplinks
  for (const t of order) {
    const row = rows[t];
    if (t === 1) row.sort();
    else row.sort((a, b) => bary(a, (m) => tier.get(m) < t || t === 0) - bary(b, (m) => tier.get(m) < t || t === 0) || a.localeCompare(b));
    place(row, 0);
  }
  rows.forEach((row) => { if (!row) return; row.forEach((id) => { pos.get(id).y = y; }); y += H + 140; });
  // centre every row on the widest one
  const width = Math.max(...rows.filter(Boolean).map((r) => r.length)) * (W + 40);
  rows.forEach((row) => { if (!row) return; const off = (width - row.length * (W + 40)) / 2; row.forEach((id) => { pos.get(id).x += off; }); });
  pos.forEach((p) => { p.x = Math.round(p.x / GRID) * GRID; p.y = Math.round(p.y / GRID) * GRID; });
  return pos;
}

function align(s, how) {
  const ns = [...s.sel].map((id) => s.nodes.get(id));
  if (how === "left") { const x = Math.min(...ns.map((n) => n.x)); ns.forEach((n) => { n.x = x; }); }
  if (how === "top") { const y = Math.min(...ns.map((n) => n.y)); ns.forEach((n) => { n.y = y; }); }
  if (how === "hspace" || how === "vspace") {
    const k = how === "hspace" ? "x" : "y";
    ns.sort((a, b) => a[k] - b[k]);
    const first = ns[0][k], last = ns[ns.length - 1][k];
    ns.forEach((n, i) => { n[k] = Math.round(first + ((last - first) * i) / Math.max(1, ns.length - 1)); });
  }
}

function icon(name) {
  const p = {
    select: "M5 3l11 6-5 1.5L9 16z", hand: "M7 10V5.5a1.2 1.2 0 0 1 2.4 0V9m0-4.5V4a1.2 1.2 0 0 1 2.4 0v5m0-4a1.2 1.2 0 0 1 2.4 0v5m0-3a1.2 1.2 0 0 1 2.4 0V12a5 5 0 0 1-5 5h-1a5 5 0 0 1-4-2l-2.6-3.6a1.2 1.2 0 0 1 2-1.4L7 11",
    minus: "M5 10h10", plus: "M10 5v10M5 10h10", fit: "M4 8V4h4M12 4h4v4M16 12v4h-4M8 16H4v-4",
    layout: "M3 4h5v4H3zM12 4h5v4h-5zM7.5 12h5v4h-5zM5.5 8v2h9V8M10 10v2", grid: "M4 4v12M10 4v12M16 4v12M4 4h12M4 10h12M4 16h12",
    refresh: "M16 10a6 6 0 1 1-2-4.5M16 3v4h-4",
  }[name];
  return html`<svg viewBox="0 0 20 20" width="18" height="18" fill="none" stroke="currentColor" stroke-width="1.6" stroke-linecap="round" stroke-linejoin="round" aria-hidden="true"><path d="${p}"></path></svg>`;
}
