// Admin API: login/logout, open-close settings, and the collected data (password protected).
const L = require("./_lib.js");
const S = require("./_sb.js");

const MAX_BODY = 10 * 1024;
const FAIL_MAX = 5, FAIL_WINDOW = 15 * 60 * 1000, SESSION_SEC = 2 * 60 * 60;
const fails = new Map();

function failed(ip) { const now = Date.now(); const l = (fails.get(ip) || []).filter(t => now - t < FAIL_WINDOW); l.push(now); fails.set(ip, l); }
function blocked(ip) { const now = Date.now(); const l = (fails.get(ip) || []).filter(t => now - t < FAIL_WINDOW); fails.set(ip, l); return l.length >= FAIL_MAX; }
const wait = ms => new Promise(r => setTimeout(r, ms));

function view(s) {
  return { state: s.state, closeAtLocal: L.isoToCairo(s.closeAt), message: s.message, open: L.isOpen(s) };
}

module.exports = async (req, res) => {
  if (!L.secretOk()) return L.send(res, 503, { ok: false, error: "not_configured" });

  if (req.method === "GET") {
    if (!L.authed(req)) return L.send(res, 401, { ok: false });
    try {
      const [settings, records] = await Promise.all([L.readSettings(true), L.readRecords()]);
      return L.send(res, 200, { ok: true, settings: view(settings), records });
    } catch (e) {
      console.error("admin read failed:", e && e.message);
      return L.send(res, 502, { ok: false });
    }
  }

  if (req.method !== "POST") { res.setHeader("Allow", "GET, POST"); return L.send(res, 405, { ok: false }); }
  if (!L.sameOrigin(req)) return L.send(res, 403, { ok: false });
  if (!/^application\/json/i.test(req.headers["content-type"] || "")) return L.send(res, 415, { ok: false });
  if (Number(req.headers["content-length"] || 0) > MAX_BODY) return L.send(res, 413, { ok: false });
  let b = req.body;
  if (typeof b === "string") { try { b = JSON.parse(b); } catch (e) { return L.send(res, 400, { ok: false }); } }
  if (!b || typeof b !== "object") return L.send(res, 400, { ok: false });

  if (b.action === "login") {
    const ip = L.clientIp(req);
    if (blocked(ip)) return L.send(res, 429, { ok: false }, { "Retry-After": "900" });
    if (typeof b.password === "string" && b.password.length <= 200 && L.safeEq(b.password, process.env.ADMIN_PASSWORD)) {
      return L.send(res, 200, { ok: true }, { "Set-Cookie": L.makeCookie(SESSION_SEC) });
    }
    failed(ip); await wait(600);
    return L.send(res, 401, { ok: false });
  }
  if (b.action === "logout") return L.send(res, 200, { ok: true }, { "Set-Cookie": L.clearCookie() });

  if (!L.authed(req)) return L.send(res, 401, { ok: false });

  if (b.action === "settings") {
    const state = b.state === "closed" ? "closed" : b.state === "open" ? "open" : null;
    if (!state) return L.send(res, 400, { ok: false });
    let closeAt = "";
    if (b.closeAtLocal) {
      closeAt = L.cairoToISO(String(b.closeAtLocal));
      if (!closeAt) return L.send(res, 400, { ok: false, error: "bad_date" });
    }
    const message = L.cleanText(b.message, 500) || L.DEFAULT_MESSAGE;
    try {
      const s = { state, closeAt, message };
      await L.writeSettings(s);
      return L.send(res, 200, { ok: true, settings: view(s) });
    } catch (e) {
      console.error("admin save failed:", e && e.message);
      return L.send(res, 502, { ok: false });
    }
  }

  // Reset a user's password. Only reachable with the admin session; users have no reset option of their own.
  if (b.action === "resetpw") {
    if (!S.configured()) return L.send(res, 503, { ok: false, error: "not_configured" });
    const email = S.normEmail(b.email);
    if (!S.validEmail(email)) return L.send(res, 400, { ok: false, error: "bad_email" });
    if (!S.validPassword(b.password)) return L.send(res, 400, { ok: false, error: "bad_password" });
    try {
      const p = await S.db("profiles?email=eq." + encodeURIComponent(email) + "&select=id&limit=1");
      if (!p.ok) return L.send(res, 502, { ok: false });
      if (!p.j || !p.j[0]) return L.send(res, 404, { ok: false, error: "not_found" });
      const u = await S.admin("/users/" + encodeURIComponent(p.j[0].id), { method: "PUT", body: { password: b.password } });
      if (!u.ok) return L.send(res, 502, { ok: false });
      return L.send(res, 200, { ok: true });
    } catch (e) {
      console.error("admin resetpw failed:", e && e.message);
      return L.send(res, 502, { ok: false });
    }
  }
  return L.send(res, 400, { ok: false });
};
