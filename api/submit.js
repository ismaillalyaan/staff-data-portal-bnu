// Receives one survey response and appends it to the Google Sheet.
const crypto = require("crypto");
const L = require("./_lib.js");

const MAX_BODY = 100 * 1024;
const RATE_MAX = Number(process.env.RATE_MAX) || 60; // campus networks share one public IP, so keep this generous
const RATE_WINDOW = 10 * 60 * 1000;
const hits = new Map();

function clean(v) {
  if (Array.isArray(v)) return v.slice(0, 50).map(x => clean(x)).filter(x => x !== "").join(" | ");
  if (typeof v === "number" && Number.isFinite(v)) return String(v);
  let s = L.cleanText(v, 3000);
  if (/^[=+\-@\t\r]/.test(s)) s = "'" + s;
  return s;
}
function limited(ip) {
  const now = Date.now();
  const list = (hits.get(ip) || []).filter(t => now - t < RATE_WINDOW);
  if (list.length >= RATE_MAX) { hits.set(ip, list); return true; }
  list.push(now); hits.set(ip, list);
  if (hits.size > 5000) for (const [k, v] of hits) if (!v.some(t => now - t < RATE_WINDOW)) hits.delete(k);
  return false;
}

module.exports = async (req, res) => {
  if (req.method !== "POST") { res.setHeader("Allow", "POST"); return L.send(res, 405, { ok: false }); }

  const allowed = (process.env.ALLOWED_ORIGINS || "").split(",").map(s => s.trim()).filter(Boolean);
  if (allowed.length && !allowed.includes(req.headers.origin || "")) return L.send(res, 403, { ok: false });

  if (!/^application\/json/i.test(req.headers["content-type"] || "")) return L.send(res, 415, { ok: false });
  if (Number(req.headers["content-length"] || 0) > MAX_BODY) return L.send(res, 413, { ok: false });
  if (limited(L.clientIp(req))) return L.send(res, 429, { ok: false }, { "Retry-After": "600" });

  let body = req.body;
  if (typeof body === "string") { try { body = JSON.parse(body); } catch (e) { return L.send(res, 400, { ok: false }); } }
  if (!body || typeof body !== "object" || !body.a || typeof body.a !== "object" || Array.isArray(body.a)) return L.send(res, 400, { ok: false });
  if (JSON.stringify(body).length > MAX_BODY) return L.send(res, 413, { ok: false });

  try {
    const st = L.publicStatus(await L.readSettings(false));
    if (!st.open) return L.send(res, 403, { ok: false, closed: true, message: st.message });
  } catch (e) { /* if settings cannot be read, keep accepting */ }

  let known = 0;
  const row = [new Date().toLocaleString("sv-SE", { timeZone: "Africa/Cairo" }), crypto.randomUUID()];
  for (const q of L.QUESTIONS) {
    const raw = Object.prototype.hasOwnProperty.call(body.a, q.key) ? body.a[q.key] : "";
    const v = clean(raw);
    if (v) known++;
    row.push(v);
  }
  if (!known) return L.send(res, 400, { ok: false });

  try {
    await L.appendRow(row);
    return L.send(res, 200, { ok: true });
  } catch (e) {
    console.error("submit failed:", e && e.message);
    return L.send(res, 502, { ok: false });
  }
};
