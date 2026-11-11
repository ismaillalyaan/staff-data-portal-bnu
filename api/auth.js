// Accounts: sign up (no email verification), sign in, session, profile.
// Supabase Auth keeps the passwords, Supabase Postgres keeps profiles/responses.
// Password resets are done by the admin only (api/admin.js, action "resetpw").
// Once a response is submitted it is locked: the user sends an edit request (action "request_edit"),
// an admin approves it in api/admin.js, and api/submit.js lets exactly one edit through per approval.
const L = require("./_lib.js");
const S = require("./_sb.js");

const SESSION_SEC = 7 * 24 * 3600;
const ADMIN_SESSION_SEC = 2 * 60 * 60; // same lifetime as api/admin.js; re-issued whenever an admin's user session is used
const buckets = new Map();
function limited(key, max, windowMs) {
  const now = Date.now();
  const list = (buckets.get(key) || []).filter(t => now - t < windowMs);
  if (list.length >= max) { buckets.set(key, list); return true; }
  list.push(now); buckets.set(key, list);
  if (buckets.size > 8000) for (const [k, v] of buckets) if (!v.some(t => now - t < 3600000)) buckets.delete(k);
  return false;
}
const fails = new Map(); // email -> {n, until}
const enc = encodeURIComponent;

async function profileById(id) {
  const r = await S.db("profiles?id=eq." + enc(id) + "&select=id,email,full_name,nid_last4&limit=1");
  return r.ok && Array.isArray(r.j) && r.j[0] ? r.j[0] : null;
}
async function profileByEmail(email) {
  const r = await S.db("profiles?email=eq." + enc(email) + "&select=id&limit=1");
  return r.ok && Array.isArray(r.j) && r.j[0] ? r.j[0] : null;
}
// true / false, or null when the auth user no longer exists
async function isConfirmed(id) {
  const r = await S.admin("/users/" + enc(id));
  if (r.status === 404) return null;
  return !!(r.ok && r.j && r.j.email_confirmed_at);
}
async function dropUser(id) {
  await S.admin("/users/" + enc(id), { method: "DELETE" });
  await S.db("profiles?id=eq." + enc(id), { method: "DELETE" });
}
const pub = p => ({ name: p.full_name, first: S.firstName(p.full_name), email: p.email, nidLast4: p.nid_last4 });
const startSession = async (res, uid, body) => {
  const cookies = [L.makeUserCookie(uid, SESSION_SEC)];
  if (await L.isAdminUser(uid)) cookies.push(L.makeCookie(uid, ADMIN_SESSION_SEC)); // admins are signed in to the panel too
  return L.send(res, 200, body, { "Set-Cookie": cookies });
};

async function me(req, res) {
  let status = { open: true, message: "" };
  try { status = L.publicStatus(await L.readSettings(false)); } catch (e) { /* keep default */ }
  const uid = L.userId(req);
  if (!uid) return L.send(res, 200, { user: null, status });
  const p = await profileById(uid);
  if (!p) return L.send(res, 200, { user: null, status }, { "Set-Cookie": L.clearUserCookie() });
  const r = await S.db("responses?user_id=eq." + enc(uid) + "&select=answers,history,created_at,updated_at&limit=1");
  const row = r.ok && Array.isArray(r.j) && r.j[0];
  const response = row ? { a: row.answers || {}, ts: row.updated_at, created: row.created_at, history: Array.isArray(row.history) ? row.history : [] } : null;
  const er = await S.db("edit_requests?user_id=eq." + enc(uid) + "&select=id,reason,status,admin_note,created_at,decided_at&order=created_at.desc&limit=5");
  const reqs = er.ok && Array.isArray(er.j) ? er.j : [];
  const open = reqs.find(x => x.status === "pending" || x.status === "approved") || null;
  const last = reqs.find(x => x.status !== "pending" && x.status !== "approved") || null;
  const edit = {
    state: open ? open.status : "none",
    request: open ? { reason: open.reason, createdAt: open.created_at, decidedAt: open.decided_at, note: open.admin_note || "" } : null,
    last: last ? { status: last.status, note: last.admin_note || "", decidedAt: last.decided_at } : null
  };
  const admin = !!(await L.isAdminUser(uid));
  // An admin who is already signed in does not sign in again for the admin panel:
  // the admin cookie is issued from the user session (api/admin.js still re-checks public.admins on every request).
  const extra = admin && L.adminCookieUid(req) !== uid ? { "Set-Cookie": [L.makeCookie(uid, ADMIN_SESSION_SEC)] } : undefined;
  return L.send(res, 200, { user: pub(p), response, status, edit, admin }, extra);
}

// User asks for permission to edit a response they already submitted.
async function requestEdit(req, res, b, uid) {
  if (!(await profileById(uid))) return L.send(res, 401, { ok: false });
  const reason = L.cleanText(b.reason, 500);
  if (reason.length < 5) return L.send(res, 400, { ok: false, reason: "reason" });
  if (limited("er:" + uid, 10, 24 * 3600000)) return L.send(res, 429, { ok: false, reason: "rate" });
  try { if (!L.publicStatus(await L.readSettings(false)).open) return L.send(res, 403, { ok: false, reason: "closed" }); } catch (e) { /* keep going */ }
  const r = await S.db("responses?user_id=eq." + enc(uid) + "&select=id&limit=1");
  if (!r.ok) return L.send(res, 502, { ok: false, reason: "db" });
  if (!r.j[0]) return L.send(res, 400, { ok: false, reason: "no_response" }); // nothing to edit yet: just fill the form
  const open = await S.db("edit_requests?user_id=eq." + enc(uid) + "&status=in.(pending,approved)&select=id&limit=1");
  if (!open.ok) return L.send(res, 502, { ok: false, reason: "db" });
  if (open.j[0]) return L.send(res, 409, { ok: false, reason: "already_open" });
  const ins = await S.db("edit_requests", { method: "POST", headers: { Prefer: "return=minimal" }, body: { user_id: uid, reason } });
  if (!ins.ok) return L.send(res, ins.status === 409 ? 409 : 502, { ok: false, reason: ins.status === 409 ? "already_open" : "db" }); // 409 = the unique index caught a double click
  await L.logEvent(req, { uid, action: "edit_request", detail: { reason: reason.slice(0, 200) } });
  return L.send(res, 200, { ok: true });
}
async function cancelEdit(req, res, uid) {
  const d = await S.db("edit_requests?user_id=eq." + enc(uid) + "&status=eq.pending", { method: "DELETE", headers: { Prefer: "return=minimal" } });
  if (!d.ok) return L.send(res, 502, { ok: false, reason: "db" });
  await L.logEvent(req, { uid, action: "edit_cancel" });
  return L.send(res, 200, { ok: true });
}

async function signup(req, res, b, ip) {
  if (b.hp) return L.send(res, 200, { ok: true }); // honeypot: pretend
  const name = S.cleanName(b.name), email = S.normEmail(b.email), nid = S.EN(b.nid).replace(/\s/g, ""), password = b.password;
  if (!S.validName(name)) return L.send(res, 400, { ok: false, reason: "name" });
  if (!S.validEmail(email)) return L.send(res, 400, { ok: false, reason: "email" });
  if (!S.validNid(nid)) return L.send(res, 400, { ok: false, reason: "nid" });
  if (!S.validPassword(password)) return L.send(res, 400, { ok: false, reason: "password" });
  if (limited("su:" + ip, 100, 3600000) || limited("su:" + email, 5, 3600000)) return L.send(res, 429, { ok: false, reason: "rate" });

  const hash = S.nidHash(nid);
  const same = await S.db("profiles?email=eq." + enc(email) + "&select=id&limit=1");
  if (!same.ok) return L.send(res, 502, { ok: false, reason: "db" });
  if (same.j[0]) {
    if (await isConfirmed(same.j[0].id)) return L.send(res, 409, { ok: false, reason: "email_exists" });
    await dropUser(same.j[0].id); // never confirmed: start over
  }
  const own = await S.db("profiles?nid_hash=eq." + hash + "&select=id&limit=1");
  if (!own.ok) return L.send(res, 502, { ok: false, reason: "db" });
  if (own.j[0]) {
    if (await isConfirmed(own.j[0].id)) return L.send(res, 409, { ok: false, reason: "nid_exists" });
    await dropUser(own.j[0].id);
  }
  // Email verification is switched off: accounts are created already confirmed.
  const a = await S.admin("/users", { method: "POST", body: { email, password, email_confirm: true, user_metadata: { full_name: name } } });
  if (!a.ok) {
    const code = S.errCode(a);
    if (/weak_password|password/i.test(code)) return L.send(res, 400, { ok: false, reason: "password" });
    if (/exists|registered/i.test(code)) return L.send(res, 409, { ok: false, reason: "email_exists" });
    return L.send(res, 502, { ok: false, reason: "auth" });
  }
  const id = a.j && a.j.id;
  if (!id) return L.send(res, 502, { ok: false, reason: "auth" });
  const ins = await S.db("profiles", { method: "POST", headers: { Prefer: "return=minimal" }, body: { id, email, full_name: name, nid_hash: hash, nid_enc: S.nidEnc(nid), nid_last4: nid.slice(-4) } });
  if (!ins.ok) {
    await S.admin("/users/" + enc(id), { method: "DELETE" });
    return L.send(res, ins.status === 409 ? 409 : 502, { ok: false, reason: ins.status === 409 ? "nid_exists" : "db" });
  }
  await L.logEvent(req, { uid: id, email, action: "signup" });
  return startSession(res, id, { ok: true }); // no email code: sign the new user straight in
}

async function signin(req, res, b, ip) {
  const email = S.normEmail(b.email), password = typeof b.password === "string" ? b.password.slice(0, 200) : "";
  if (!S.validEmail(email) || !password) return L.send(res, 400, { ok: false, reason: "credentials" });
  const f = fails.get(email) || { n: 0, until: 0 };
  if (f.until > Date.now()) return L.send(res, 429, { ok: false, reason: "locked", minutes: Math.ceil((f.until - Date.now()) / 60000) });
  if (limited("li:" + ip, 400, 600000)) return L.send(res, 429, { ok: false, reason: "rate" });
  const r = await S.auth("/token?grant_type=password", { email, password });
  if (r.ok && r.j && r.j.user && r.j.user.id) {
    fails.delete(email);
    if (!(await profileById(r.j.user.id))) return L.send(res, 401, { ok: false, reason: "credentials" });
    await L.logEvent(req, { uid: r.j.user.id, email, action: "login" });
    return startSession(res, r.j.user.id, { ok: true });
  }
  if (/email_not_confirmed|not confirmed/i.test(S.errCode(r) + JSON.stringify(r.j || ""))) {
    // Left over from when verification was on: sign-up drops unconfirmed accounts, so ask them to register again.
    return L.send(res, 403, { ok: false, reason: "unconfirmed" });
  }
  await L.logEvent(req, { email, action: "login_failed" });
  f.n++; if (f.n >= 5) { f.until = Date.now() + 15 * 60000; f.n = 0; }
  fails.set(email, f);
  return L.send(res, 401, { ok: false, reason: "credentials" });
}

async function updateProfile(req, res, b, uid) {
  const p = await profileById(uid);
  if (!p) return L.send(res, 401, { ok: false });
  if (limited("pf:" + uid, 20, 3600000)) return L.send(res, 429, { ok: false, reason: "rate" });
  if (b.name !== undefined) {
    const name = S.cleanName(b.name);
    if (!S.validName(name)) return L.send(res, 400, { ok: false, reason: "name" });
    const u = await S.db("profiles?id=eq." + enc(uid), { method: "PATCH", headers: { Prefer: "return=minimal" }, body: { full_name: name } });
    if (!u.ok) return L.send(res, 502, { ok: false, reason: "db" });
    p.full_name = name;
  }
  if (b.newPassword) {
    if (!S.validPassword(b.newPassword)) return L.send(res, 400, { ok: false, reason: "password" });
    const c = await S.auth("/token?grant_type=password", { email: p.email, password: String(b.currentPassword || "").slice(0, 200) });
    if (!c.ok) return L.send(res, 401, { ok: false, reason: "current" });
    const u = await S.admin("/users/" + enc(uid), { method: "PUT", body: { password: b.newPassword } });
    if (!u.ok) return L.send(res, 502, { ok: false, reason: "auth" });
  }
  await L.logEvent(req, { uid, email: p.email, action: "profile_update", detail: { name: b.name !== undefined, password: !!b.newPassword } });
  return L.send(res, 200, { ok: true, user: pub(p) });
}

module.exports = async (req, res) => {
  if (!S.configured() || !L.userSecretOk()) return L.send(res, 503, { ok: false, reason: "config" });
  try {
    if (req.method === "GET") return await me(req, res);
    if (req.method !== "POST") { res.setHeader("Allow", "GET, POST"); return L.send(res, 405, { ok: false }); }
    if (!L.sameOrigin(req)) return L.send(res, 403, { ok: false, reason: "origin" });
    if (!/^application\/json/i.test(req.headers["content-type"] || "")) return L.send(res, 415, { ok: false, reason: "type" });
    let b = req.body;
    if (typeof b === "string") { try { b = JSON.parse(b); } catch (e) { b = null; } }
    if (!b || typeof b !== "object" || Array.isArray(b) || JSON.stringify(b).length > 10000) return L.send(res, 400, { ok: false });
    const ip = L.clientIp(req);
    switch (b.action) {
      case "signup": return await signup(req, res, b, ip);
      case "login": return await signin(req, res, b, ip);
      case "logout": {
        const uid = L.userId(req);
        if (uid) await L.logEvent(req, { uid, action: "logout" });
        return L.send(res, 200, { ok: true }, { "Set-Cookie": [L.clearUserCookie(), L.clearCookie()] });
      }
      case "form_ack": { // the user closed the "you can submit only once" notice
        const uid = L.userId(req);
        if (!uid) return L.send(res, 401, { ok: false });
        await L.logEvent(req, { uid, action: "form_ack", detail: { mode: b.mode === "edit" ? "edit" : "first" } });
        return L.send(res, 200, { ok: true });
      }
      case "profile": {
        const uid = L.userId(req);
        if (!uid) return L.send(res, 401, { ok: false });
        return await updateProfile(req, res, b, uid);
      }
      case "request_edit": {
        const uid = L.userId(req);
        if (!uid) return L.send(res, 401, { ok: false });
        return await requestEdit(req, res, b, uid);
      }
      case "cancel_edit": {
        const uid = L.userId(req);
        if (!uid) return L.send(res, 401, { ok: false });
        return await cancelEdit(req, res, uid);
      }
      default: return L.send(res, 400, { ok: false });
    }
  } catch (e) {
    console.error("auth failed:", e && e.message);
    return L.send(res, 502, { ok: false, reason: "server" });
  }
};
