// JSON API client. Errors carry the server's message so the UI can say what went wrong.
async function call(method, url, body) {
  const r = await fetch(url, {
    method,
    headers: body ? { "Content-Type": "application/json" } : {},
    body: body ? JSON.stringify(body) : undefined,
  });
  const data = await r.json().catch(() => ({}));
  if (!r.ok) throw new Error(data.error || data.detail || `${r.status} ${r.statusText}`);
  return data;
}
const qs = (params) => {
  const p = new URLSearchParams(Object.entries(params || {}).filter(([, v]) => v !== "" && v != null));
  return p.toString() ? `?${p}` : "";
};

export const api = {
  get: (url, params) => call("GET", url + qs(params)),
  post: (url, body = {}) => call("POST", url, body),
  patch: (url, body) => call("PATCH", url, body),
  qs,
};
