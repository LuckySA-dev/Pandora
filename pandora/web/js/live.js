// Live events from the server (/ws). Views subscribe with on(type, fn) and get an unsubscribe back.
const handlers = new Map();
let status = "connecting";
const statusListeners = new Set();

export function on(type, fn) {
  if (!handlers.has(type)) handlers.set(type, new Set());
  handlers.get(type).add(fn);
  return () => handlers.get(type).delete(fn);
}
export function onStatus(fn) { statusListeners.add(fn); fn(status); return () => statusListeners.delete(fn); }
function setStatus(s) { status = s; statusListeners.forEach((fn) => fn(s)); }

export function connect() {
  const ws = new WebSocket(`${location.protocol === "https:" ? "wss" : "ws"}://${location.host}/ws`);
  ws.onopen = () => setStatus("live");
  ws.onclose = () => { setStatus("offline"); setTimeout(connect, 2000); };
  ws.onmessage = (e) => {
    const { type, data } = JSON.parse(e.data);
    handlers.get(type)?.forEach((fn) => fn(data));
    handlers.get("*")?.forEach((fn) => fn(type, data));
  };
}
