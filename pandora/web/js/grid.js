// Paged, sortable, searchable table backed by the server (sorting and paging happen in the API, so it
// stays fast with thousands of devices). Page list and per-page choices follow NetBox's paginator
// (EnhancedPaginator / smart_pages, Apache-2.0): first, last, two either side of the current page, gaps as "…".
import { api } from "./api.js";
import { html, render } from "./ui.js";

const lbl = (c) => (typeof c.label === "function" ? c.label() : c.label);

export function smartPages(page, pages) {
  if (pages <= 5) return Array.from({ length: pages }, (_, i) => i + 1);
  const wanted = [1, page - 2, page - 1, page, page + 1, page + 2, pages].filter((p) => p >= 1 && p <= pages);
  const list = [...new Set(wanted)].sort((a, b) => a - b);
  const out = [];
  list.forEach((p, i) => { if (i && p - list[i - 1] !== 1) out.push(false); out.push(p); });
  return out;
}

const store = {
  get: (k, d) => { try { return JSON.parse(localStorage.getItem(k)) ?? d; } catch { return d; } },
  set: (k, v) => { try { localStorage.setItem(k, JSON.stringify(v)); } catch { /* private mode */ } },
};

/**
 * columns: [{ key, label, sort?: apiSortKey, render: (row) => html }]
 * opts: url, storageKey, sort, order, params(): extra query, rowHref(row), toolbar(): html, empty: text,
 *       onData(data): called after each load (facets, selection), q: initial search
 */
export function createGrid(el, columns, opts) {
  const saved = store.get(`${opts.storageKey}.grid`, {});
  const st = { q: opts.q || "", sort: saved.sort || opts.sort || "", order: saved.order || opts.order || "asc",
    page: 1, per_page: saved.per_page || 20, data: null, loading: false };
  let seq = 0, timer, rows = new Map(); // id -> row on this page: a live update finds its row in O(1)

  async function load() {
    const mine = ++seq;
    st.loading = true;
    const data = await api.get(opts.url, { ...(opts.params?.() || {}), q: st.q, sort: st.sort, order: st.order,
      page: st.page, per_page: st.per_page });
    if (mine !== seq) return; // a newer search already answered
    st.data = data; st.page = data.page; st.loading = false;
    rows = new Map(data.items.map((r) => [r.id, r]));
    opts.onData?.(data);
    draw();
  }

  function draw() {
    const focus = document.activeElement;
    const keep = focus?.dataset?.g === "q" ? [focus.selectionStart, focus.selectionEnd] : null;
    const d = st.data;
    const from = d && d.total ? (d.page - 1) * d.per_page + 1 : 0;
    const to = d ? Math.min(d.total, d.page * d.per_page) : 0;
    render(el, html`
      <div class="grid-tools">
        <input type="search" data-g="q" value="${st.q}" placeholder="${opts.placeholder || "Search"}" aria-label="${opts.placeholder || "Search"}">
        ${opts.toolbar?.() || ""}
      </div>
      <div class="scroll-x"><table class="table grid-table">
        <thead><tr>${columns.map((c) => {
          const active = c.sort && st.sort === c.sort;
          return html`<th ${active ? html`aria-sort="${st.order === "asc" ? "ascending" : "descending"}"` : ""} style="${c.width ? `width:${c.width}` : ""}">
            ${c.sort ? html`<button class="sort" data-g="sort" data-key="${c.sort}">${lbl(c)}<span class="arrow" aria-hidden="true">${active ? (st.order === "asc" ? "▲" : "▼") : ""}</span></button>` : lbl(c)}</th>`;
        })}</tr></thead>
        <tbody>${d?.items.length ? d.items.map((row) => html`<tr class="${opts.rowHref ? "clickable" : ""}" ${opts.rowHref ? html`data-href="${opts.rowHref(row)}"` : ""}>
            ${columns.map((c) => html`<td>${c.render(row)}</td>`)}</tr>`)
          : html`<tr><td colspan="${columns.length}"><div class="empty">${d ? (st.q ? `Nothing matches "${st.q}".` : opts.empty || "Nothing here yet.") : "Loading…"}</div></td></tr>`}
        </tbody></table></div>
      ${d ? html`<div class="pager">
        <span class="muted">${d.total ? `Showing ${from}–${to} of ${d.total}` : "Showing 0 of 0"}</span>
        ${d.pages > 1 ? html`<nav aria-label="Pages">
          <button data-g="page" data-page="${d.page - 1}" ${d.page <= 1 ? "disabled" : ""} aria-label="Previous page">‹</button>
          ${smartPages(d.page, d.pages).map((p) => (p === false ? html`<span class="gap" aria-hidden="true">…</span>`
            : html`<button data-g="page" data-page="${p}" ${p === d.page ? html`aria-current="page"` : ""} aria-label="Page ${p}">${p}</button>`))}
          <button data-g="page" data-page="${d.page + 1}" ${d.page >= d.pages ? "disabled" : ""} aria-label="Next page">›</button></nav>` : html`<span></span>`}
        <label class="muted">Per page <select data-g="pp">${d.page_lengths.map((n) => html`<option ${n === d.per_page ? "selected" : ""}>${n}</option>`)}</select></label>
      </div>` : ""}`);
    if (keep) { const i = el.querySelector('[data-g="q"]'); i.focus(); i.setSelectionRange(...keep); }
  }

  const persist = () => store.set(`${opts.storageKey}.grid`, { sort: st.sort, order: st.order, per_page: st.per_page });
  el.addEventListener("input", (e) => {
    if (e.target.dataset.g !== "q") return;
    st.q = e.target.value; st.page = 1;
    clearTimeout(timer); timer = setTimeout(load, 250);
  });
  el.addEventListener("change", (e) => {
    if (e.target.dataset.g === "pp") { st.per_page = Number(e.target.value); st.page = 1; persist(); load(); }
  });
  el.addEventListener("click", (e) => {
    const b = e.target.closest("[data-g]");
    if (b?.dataset.g === "sort") {
      const k = b.dataset.key;
      st.order = st.sort === k && st.order === "asc" ? "desc" : "asc";
      st.sort = k; st.page = 1; persist(); load();
      return;
    }
    if (b?.dataset.g === "page") { st.page = Number(b.dataset.page); load(); el.scrollIntoView({ block: "nearest" }); return; }
    const row = e.target.closest("tr[data-href]");
    if (row && !e.target.closest("input,select,button,a,label")) location.hash = row.dataset.href;
  });

  /** Merge fields into the row with this id if it is on the page; false = not shown here (caller may reload). */
  function patch(id, fields) {
    const row = rows.get(id);
    if (!row) return false;
    Object.assign(row, fields);
    frame ||= requestAnimationFrame(() => { frame = 0; draw(); }); // a burst of updates paints once
    return true;
  }
  let frame = 0;

  return { load, reload: () => load(), state: st, redraw: draw, patch };
}
