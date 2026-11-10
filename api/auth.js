// Accounts: sign up (email code), sign in, session, profile.
// Supabase Auth keeps the passwords, Supabase Postgres keeps profiles/responses, codes are mailed through Gmail SMTP.
const L = require("./_lib.js");
const S = require("./_sb.js");
const C = require("./_codes.js");

const SESSION_SEC = 7 * 24 * 3600;
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
const startSession = (res, uid, body) => L.send(res, 200, body, { "Set-Cookie": L.makeUserCookie(uid, SESSION_SEC) });

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
  return L.send(res, 200, { user: pub(p), response, status });
}

async function signup(req, res, b, ip) {
  if (b.hp) return L.send(res, 200, { ok: true, verify: true }); // honeypot: pretend
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
  const a = await S.admin("/users", { method: "POST", body: { email, password, email_confirm: false, user_metadata: { full_name: name } } });
  if (!a.ok) {
    const code = S.errCode(a);
    if (/weak_password|password/i.test(code)) return L.send(res, 400, { ok: false, reason: "password" });
    if (/exists|registered/i.test(code)) return L.send(res, 409, { ok: false, reason: "email_exists" });
    return L.send(res, 502, { ok: false, reason: "auth" });
  }
  const id = a.j && a.j.id;
  if (!id) return L.send(res, 502, { ok: false, reason: "auth" });
  const ins = await S.db("profiles", { method: "POST", headers: { Prefer: "return=minimal" }, body: { id, email, full_name: name, nid_hash: hash, nid_last4: nid.slice(-4) } });
  if (!ins.ok) {
    await S.admin("/users/" + enc(id), { method: "DELETE" });
    return L.send(res, ins.status === 409 ? 409 : 502, { ok: false, reason: ins.status === 409 ? "nid_exists" : "db" });
  }
  if ((await C.sendCode(email, "signup")) === "mail") { await dropUser(id); return L.send(res, 502, { ok: false, reason: "mail" }); }
  return L.send(res, 200, { ok: true, verify: true, email });
}

async function verify(req, res, b, ip) {
  const email = S.normEmail(b.email), code = S.EN(b.code).replace(/\s/g, "");
  if (!S.validEmail(email) || !S.validCode(code)) return L.send(res, 400, { ok: false, reason: "code" });
  if (limited("vf:" + email, 10, 900000) || limited("vf:" + ip, 200, 900000)) return L.send(res, 429, { ok: false, reason: "rate" });
  const p = await profileByEmail(email);
  if (!p || !(await C.checkCode(email, "signup", code))) return L.send(res, 400, { ok: false, reason: "code" });
  const u = await S.admin("/users/" + enc(p.id), { method: "PUT", body: { email_confirm: true } });
  if (!u.ok) return L.send(res, 502, { ok: false, reason: "auth" });
  return startSession(res, p.id, { ok: true });
}

async function resend(req, res, b, ip) {
  const email = S.normEmail(b.email);
  if (!S.validEmail(email)) return L.send(res, 400, { ok: false, reason: "email" });
  if (limited("rs:" + email, 6, 3600000) || limited("rs:" + ip, 200, 3600000)) return L.send(res, 429, { ok: false, reason: "rate" });
  const p = await profileByEmail(email);
  if (p && (await isConfirmed(p.id)) === false) {
    const sent = await C.sendCode(email, "signup");
    if (sent === "wait") return L.send(res, 429, { ok: false, reason: "wait" });
    if (sent === "mail") return L.send(res, 502, { ok: false, reason: "mail" });
  }
  return L.send(res, 200, { ok: true }); // same answer whether or not the account exists
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
    return startSession(res, r.j.user.id, { ok: true });
  }
  if (/email_not_confirmed|not confirmed/i.test(S.errCode(r) + JSON.stringify(r.j || ""))) {
    await C.sendCode(email, "signup"); // answers "wait" when one was just sent
    return L.send(res, 403, { ok: false, reason: "unconfirmed", email });
  }
  f.n++; if (f.n >= 5) { f.until = Date.now() + 15 * 60000; f.n = 0; }
  fails.set(email, f);
  return L.send(res, 401, { ok: false, reason: "credentials" });
}

async function forgot(req, res, b, ip) {
  const email = S.normEmail(b.email);
  if (!S.validEmail(email)) return L.send(res, 400, { ok: false, reason: "email" });
  if (limited("fg:" + email, 4, 3600000) || limited("fg:" + ip, 100, 3600000)) return L.send(res, 429, { ok: false, reason: "rate" });
  const p = await profileByEmail(email);
  if (p && (await isConfirmed(p.id))) {
    const sent = await C.sendCode(email, "reset");
    if (sent === "wait") return L.send(res, 429, { ok: false, reason: "wait" });
    if (sent === "mail") return L.send(res, 502, { ok: false, reason: "mail" });
  }
  return L.send(res, 200, { ok: true });
}
async function reset(req, res, b, ip) {
  const email = S.normEmail(b.email), code = S.EN(b.code).replace(/\s/g, "");
  if (!S.validEmail(email) || !S.validCode(code)) return L.send(res, 400, { ok: false, reason: "code" });
  if (!S.validPassword(b.password)) return L.send(res, 400, { ok: false, reason: "password" });
  if (limited("vf:" + email, 10, 900000) || limited("vf:" + ip, 200, 900000)) return L.send(res, 429, { ok: false, reason: "rate" });
  const p = await profileByEmail(email);
  if (!p || !(await C.checkCode(email, "reset", code))) return L.send(res, 400, { ok: false, reason: "code" });
  const u = await S.admin("/users/" + enc(p.id), { method: "PUT", body: { password: b.password } });
  if (!u.ok) return L.send(res, 400, { ok: false, reason: "password" });
  return startSession(res, p.id, { ok: true });
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
  return L.send(res, 200, { ok: true, user: pub(p) });
}

module.exports = async (req, res) => {
  if (!S.configured() || !L.userSecretOk() || !C.mailReady()) return L.send(res, 503, { ok: false, reason: "config" });
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
      case "verify": return await verify(req, res, b, ip);
      case "resend": return await resend(req, res, b, ip);
      case "login": return await signin(req, res, b, ip);
      case "forgot": return await forgot(req, res, b, ip);
      case "reset": return await reset(req, res, b, ip);
      case "logout": return L.send(res, 200, { ok: true }, { "Set-Cookie": L.clearUserCookie() });
      case "profile": {
        const uid = L.userId(req);
        if (!uid) return L.send(res, 401, { ok: false });
        return await updateProfile(req, res, b, uid);
      }
      default: return L.send(res, 400, { ok: false });
    }
  } catch (e) {
    console.error("auth failed:", e && e.message);
    return L.send(res, 502, { ok: false, reason: "server" });
  }
};
