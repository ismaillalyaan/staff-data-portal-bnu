// Admin API. No shared password: admins are normal accounts listed in public.admins.
//   login / logout          - email + password of an admin account
//   settings                - open / close the form
//   decide                  - approve or reject a user's edit request (one approval = one edit)
//   addadmin / removeadmin  - owner only
//   resetpw                 - reset a user's password
const L = require("./_lib.js");
const S = require("./_sb.js");

const MAX_BODY = 10 * 1024;
const FAIL_MAX = 5, FAIL_WINDOW = 15 * 60 * 1000, SESSION_SEC = 2 * 60 * 60;
const fails = new Map(); // key (ip or email) -> [timestamps]
const enc = encodeURIComponent;

function failed(k) { const now = Date.now(); const l = (fails.get(k) || []).filter(t => now - t < FAIL_WINDOW); l.push(now); fails.set(k, l); }
function blocked(k) { const now = Date.now(); const l = (fails.get(k) || []).filter(t => now - t < FAIL_WINDOW); fails.set(k, l); return l.length >= FAIL_MAX; }
const wait = ms => new Promise(r => setTimeout(r, ms));
const UUID = /^[0-9a-f-]{36}$/i;

function view(s) {
  return { state: s.state, closeAtLocal: L.isoToCairo(s.closeAt), message: s.message, open: L.isOpen(s) };
}

// Edit requests with the requester's name and email (newest first).
async function listRequests() {
  const r = await S.db("edit_requests?select=id,user_id,reason,status,admin_note,created_at,decided_at,used_at&order=created_at.desc&limit=200");
  if (!r.ok) throw new Error("requests read failed");
  const people = await peopleById(r.j.map(x => x.user_id));
  return r.j.map(x => ({
    id: x.id, status: x.status, reason: x.reason, note: x.admin_note || "",
    name: (people[x.user_id] || {}).full_name || "—", email: (people[x.user_id] || {}).email || "",
    createdAt: x.created_at, decidedAt: x.decided_at, usedAt: x.used_at
  }));
}
async function peopleById(ids) {
  const uniq = [...new Set(ids.filter(i => UUID.test(String(i))))];
  const out = {};
  if (!uniq.length) return out;
  const r = await S.db("profiles?id=in.(" + uniq.join(",") + ")&select=id,full_name,email");
  if (!r.ok) throw new Error("profiles read failed");
  for (const p of r.j) out[p.id] = p;
  return out;
}
async function listAdmins() {
  const r = await S.db("admins?select=user_id,role,created_at&order=created_at.asc");
  if (!r.ok) throw new Error("admins read failed");
  const people = await peopleById(r.j.map(x => x.user_id));
  return r.j.map(x => ({ id: x.user_id, role: x.role, createdAt: x.created_at, name: (people[x.user_id] || {}).full_name || "—", email: (people[x.user_id] || {}).email || "" }));
}

module.exports = async (req, res) => {
  if (!L.secretOk() || !S.configured()) return L.send(res, 503, { ok: false, error: "not_configured" });

  try {
    if (req.method === "GET") {
      const me = await L.adminOf(req);
      if (!me) return L.send(res, 401, { ok: false });
      const [settings, records, requests, admins, mine] = await Promise.all([L.readSettings(true), L.readRecords(), listRequests(), listAdmins(), peopleById([me.uid])]);
      const p = mine[me.uid] || {};
      return L.send(res, 200, { ok: true, me: { id: me.uid, role: me.role, name: p.full_name || "", email: p.email || "" }, settings: view(settings), records, requests, admins });
    }

    if (req.method !== "POST") { res.setHeader("Allow", "GET, POST"); return L.send(res, 405, { ok: false }); }
    if (!L.sameOrigin(req)) return L.send(res, 403, { ok: false });
    if (!/^application\/json/i.test(req.headers["content-type"] || "")) return L.send(res, 415, { ok: false });
    if (Number(req.headers["content-length"] || 0) > MAX_BODY) return L.send(res, 413, { ok: false });
    let b = req.body;
    if (typeof b === "string") { try { b = JSON.parse(b); } catch (e) { return L.send(res, 400, { ok: false }); } }
    if (!b || typeof b !== "object" || Array.isArray(b)) return L.send(res, 400, { ok: false });

    /* ---- login: an admin account's own email + password ---- */
    if (b.action === "login") {
      const ip = L.clientIp(req), email = S.normEmail(b.email);
      if (blocked("ip:" + ip) || blocked("em:" + email)) return L.send(res, 429, { ok: false }, { "Retry-After": "900" });
      const password = typeof b.password === "string" ? b.password.slice(0, 200) : "";
      if (S.validEmail(email) && password) {
        const r = await S.auth("/token?grant_type=password", { email, password });
        const uid = r.ok && r.j && r.j.user && r.j.user.id;
        if (uid && await L.isAdminUser(uid)) return L.send(res, 200, { ok: true }, { "Set-Cookie": L.makeCookie(uid, SESSION_SEC) });
      }
      // same answer for "unknown email", "wrong password" and "not an admin"
      failed("ip:" + ip); if (email) failed("em:" + email); await wait(600);
      return L.send(res, 401, { ok: false });
    }
    if (b.action === "logout") return L.send(res, 200, { ok: true }, { "Set-Cookie": L.clearCookie() });

    const me = await L.adminOf(req);
    if (!me) return L.send(res, 401, { ok: false });
    const owner = me.role === "owner";

    if (b.action === "settings") {
      const state = b.state === "closed" ? "closed" : b.state === "open" ? "open" : null;
      if (!state) return L.send(res, 400, { ok: false });
      let closeAt = "";
      if (b.closeAtLocal) {
        closeAt = L.cairoToISO(String(b.closeAtLocal));
        if (!closeAt) return L.send(res, 400, { ok: false, error: "bad_date" });
      }
      const message = L.cleanText(b.message, 500) || L.DEFAULT_MESSAGE;
      const s = { state, closeAt, message };
      await L.writeSettings(s);
      return L.send(res, 200, { ok: true, settings: view(s) });
    }

    /* ---- edit requests: approve = the user may edit exactly once; reject / revoke = no edit ---- */
    if (b.action === "decide") {
      const id = String(b.id || "");
      if (!UUID.test(id)) return L.send(res, 400, { ok: false });
      const approve = b.decision === "approve";
      if (!approve && b.decision !== "reject") return L.send(res, 400, { ok: false });
      const note = L.cleanText(b.note, 300);
      // approve only works on a pending request; reject also revokes an approval that was not used yet
      const from = approve ? "eq.pending" : "in.(pending,approved)";
      const u = await S.db("edit_requests?id=eq." + enc(id) + "&status=" + from + "&select=id", {
        method: "PATCH", headers: { Prefer: "return=representation" },
        body: { status: approve ? "approved" : "rejected", admin_note: note, decided_at: new Date().toISOString(), decided_by: me.uid }
      });
      if (!u.ok) return L.send(res, 502, { ok: false });
      if (!Array.isArray(u.j) || !u.j.length) return L.send(res, 409, { ok: false, error: "not_pending" });
      return L.send(res, 200, { ok: true, requests: await listRequests() });
    }

    /* ---- admin management (owner only) ---- */
    if (b.action === "addadmin") {
      if (!owner) return L.send(res, 403, { ok: false });
      const email = S.normEmail(b.email);
      if (!S.validEmail(email)) return L.send(res, 400, { ok: false, error: "bad_email" });
      const p = await S.db("profiles?email=eq." + enc(email) + "&select=id&limit=1");
      if (!p.ok) return L.send(res, 502, { ok: false });
      if (!p.j[0]) return L.send(res, 404, { ok: false, error: "not_found" }); // the person must register first
      const ins = await S.db("admins?on_conflict=user_id", {
        method: "POST", headers: { Prefer: "resolution=ignore-duplicates,return=minimal" },
        body: { user_id: p.j[0].id, role: "admin" }
      });
      if (!ins.ok) return L.send(res, 502, { ok: false });
      return L.send(res, 200, { ok: true, admins: await listAdmins() });
    }
    if (b.action === "removeadmin") {
      if (!owner) return L.send(res, 403, { ok: false });
      const id = String(b.id || "");
      if (!UUID.test(id)) return L.send(res, 400, { ok: false });
      if (id === me.uid) return L.send(res, 400, { ok: false, error: "self" });
      const d = await S.db("admins?user_id=eq." + enc(id) + "&role=eq.admin", { method: "DELETE", headers: { Prefer: "return=minimal" } }); // never the owner
      if (!d.ok) return L.send(res, 502, { ok: false });
      return L.send(res, 200, { ok: true, admins: await listAdmins() });
    }

    /* ---- reset a user's password (users have no reset option of their own) ---- */
    if (b.action === "resetpw") {
      const email = S.normEmail(b.email);
      if (!S.validEmail(email)) return L.send(res, 400, { ok: false, error: "bad_email" });
      if (!S.validPassword(b.password)) return L.send(res, 400, { ok: false, error: "bad_password" });
      const p = await S.db("profiles?email=eq." + enc(email) + "&select=id&limit=1");
      if (!p.ok) return L.send(res, 502, { ok: false });
      if (!p.j || !p.j[0]) return L.send(res, 404, { ok: false, error: "not_found" });
      const target = p.j[0].id;
      // An admin account's password can only be changed by that admin (account page) or, for plain admins, by the owner.
      const t = await S.db("admins?user_id=eq." + enc(target) + "&select=role&limit=1");
      if (!t.ok) return L.send(res, 502, { ok: false });
      if (t.j[0] && target !== me.uid && !(owner && t.j[0].role !== "owner")) return L.send(res, 403, { ok: false, error: "protected" });
      const u = await S.admin("/users/" + enc(target), { method: "PUT", body: { password: b.password } });
      if (!u.ok) return L.send(res, 502, { ok: false });
      return L.send(res, 200, { ok: true });
    }
    return L.send(res, 400, { ok: false });
  } catch (e) {
    console.error("admin failed:", e && e.message);
    return L.send(res, 502, { ok: false });
  }
};
