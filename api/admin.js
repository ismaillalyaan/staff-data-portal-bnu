// Admin API. No shared password: admins are normal accounts listed in public.admins.
// Every admin has a role (owner / admin), a list of permissions and an optional college scope:
//   permissions: data (dashboard + export), requests (edit requests), settings (open/close the form), passwords (reset user passwords)
//   colleges:    null = all colleges, otherwise only people/responses of the listed colleges
// The owner always has every permission and sees every college.
//   login / logout          - email + password of an admin account
//   settings                - open / close the form                     (settings)
//   decide                  - approve or reject an edit request         (requests, in college scope)
//   resetpw                 - reset a user's password                   (passwords, in college scope)
//   addadmin / updateadmin / removeadmin - owner only
const L = require("./_lib.js");
const S = require("./_sb.js");

const MAX_BODY = 10 * 1024;
const FAIL_MAX = 5, FAIL_WINDOW = 15 * 60 * 1000, SESSION_SEC = 2 * 60 * 60;
const fails = new Map(); // key (ip or email) -> [timestamps]
const enc = encodeURIComponent;

// Must match the college list in index.html.
const COLLEGES = [
  "كلية الطب البشري", "كلية طب الأسنان", "كلية العلاج الطبيعي", "كلية الطب البيطري", "كلية الهندسة",
  "كلية علوم الحاسب", "كلية الاقتصاد وإدارة الأعمال", "كلية الفنون البصرية والتصميم", "كلية علوم الطاقة",
  "كلية تكنولوجيا العلوم الصحية التطبيقية"
];

function failed(k) { const now = Date.now(); const l = (fails.get(k) || []).filter(t => now - t < FAIL_WINDOW); l.push(now); fails.set(k, l); }
function blocked(k) { const now = Date.now(); const l = (fails.get(k) || []).filter(t => now - t < FAIL_WINDOW); fails.set(k, l); return l.length >= FAIL_MAX; }
const wait = ms => new Promise(r => setTimeout(r, ms));
const UUID = /^[0-9a-f-]{36}$/i;

function view(s) {
  return { state: s.state, closeAtLocal: L.isoToCairo(s.closeAt), message: s.message, open: L.isOpen(s) };
}

// What the browser needs to know about the signed-in admin.
function meView(me, p) {
  return { id: me.uid, role: me.role, name: (p && p.full_name) || "", email: (p && p.email) || "", permissions: me.permissions, colleges: me.colleges };
}

// Validate the permission list and college scope sent when adding or editing an admin.
// Returns { permissions, colleges } or null when the input is malformed.
function readGrant(b) {
  if (!Array.isArray(b.permissions) || b.permissions.length > 20) return null;
  const permissions = [...new Set(b.permissions.map(String))];
  if (!permissions.every(p => L.PERMS.includes(p))) return null;
  let colleges = null; // all colleges
  if (b.allColleges === false) {
    if (!Array.isArray(b.colleges) || !b.colleges.length || b.colleges.length > COLLEGES.length) return null;
    colleges = [...new Set(b.colleges.map(String))];
    if (!colleges.every(c => COLLEGES.includes(c))) return null;
  }
  return { permissions, colleges };
}

// user id -> college (from the user's submitted response); users without a response are missing.
async function collegesByUser(ids) {
  const uniq = [...new Set(ids.filter(i => UUID.test(String(i))))];
  const out = {};
  if (!uniq.length) return out;
  const r = await S.db("responses?user_id=in.(" + uniq.join(",") + ")&select=user_id,answers");
  if (!r.ok) throw new Error("responses read failed");
  for (const x of r.j) out[x.user_id] = L.collegeOf(x.answers);
  return out;
}

// Edit requests with the requester's name and email (newest first), limited to the admin's colleges.
async function listRequests(me) {
  const r = await S.db("edit_requests?select=id,user_id,reason,status,admin_note,created_at,decided_at,used_at&order=created_at.desc&limit=200");
  if (!r.ok) throw new Error("requests read failed");
  const ids = r.j.map(x => x.user_id);
  const [people, cols] = await Promise.all([peopleById(ids), collegesByUser(ids)]);
  return r.j.filter(x => L.inScope(me, cols[x.user_id] || "")).map(x => ({
    id: x.id, status: x.status, reason: x.reason, note: x.admin_note || "",
    name: (people[x.user_id] || {}).full_name || "—", email: (people[x.user_id] || {}).email || "",
    college: cols[x.user_id] || "",
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
  const r = await S.db("admins?select=user_id,role,permissions,colleges,created_at&order=created_at.asc");
  if (!r.ok) throw new Error("admins read failed");
  const people = await peopleById(r.j.map(x => x.user_id));
  return r.j.map(x => ({
    id: x.user_id, role: x.role, createdAt: x.created_at,
    permissions: x.role === "owner" ? L.PERMS.slice() : (x.permissions || []),
    colleges: x.role === "owner" || !Array.isArray(x.colleges) ? null : x.colleges,
    name: (people[x.user_id] || {}).full_name || "—", email: (people[x.user_id] || {}).email || ""
  }));
}
// Responses limited to the admin's colleges.
async function scopedRecords(me) {
  const all = await L.readRecords();
  return me.colleges ? all.filter(x => me.colleges.includes(L.collegeOf(x.a))) : all;
}

module.exports = async (req, res) => {
  if (!L.secretOk() || !S.configured()) return L.send(res, 503, { ok: false, error: "not_configured" });

  try {
    if (req.method === "GET") {
      const me = await L.adminOf(req);
      if (!me) return L.send(res, 401, { ok: false });
      const owner = me.role === "owner";
      const [settings, records, requests, admins, mine] = await Promise.all([
        L.can(me, "settings") ? L.readSettings(true) : null,
        L.can(me, "data") ? scopedRecords(me) : [],
        L.can(me, "requests") ? listRequests(me) : [],
        owner ? listAdmins() : [],
        peopleById([me.uid])
      ]);
      return L.send(res, 200, {
        ok: true, me: meView(me, mine[me.uid]), colleges: COLLEGES,
        settings: settings ? view(settings) : null, records, requests, admins
      });
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
        if (uid && await L.isAdminUser(uid)) {
          await L.logEvent(req, { uid, email, action: "admin_login" });
          return L.send(res, 200, { ok: true }, { "Set-Cookie": L.makeCookie(uid, SESSION_SEC) });
        }
      }
      // same answer for "unknown email", "wrong password" and "not an admin"
      failed("ip:" + ip); if (email) failed("em:" + email);
      await L.logEvent(req, { email, action: "admin_login_failed" });
      await wait(600);
      return L.send(res, 401, { ok: false });
    }
    if (b.action === "logout") {
      const uid = L.adminCookieUid(req);
      if (uid) await L.logEvent(req, { uid, action: "admin_logout" });
      return L.send(res, 200, { ok: true }, { "Set-Cookie": L.clearCookie() });
    }

    const me = await L.adminOf(req);
    if (!me) return L.send(res, 401, { ok: false });
    const owner = me.role === "owner";

    if (b.action === "settings") {
      if (!L.can(me, "settings")) return L.send(res, 403, { ok: false, error: "forbidden" });
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
      await L.logEvent(req, { uid: me.uid, action: "settings_update", detail: { state, closeAt: closeAt || "", message: message.slice(0, 120) } });
      return L.send(res, 200, { ok: true, settings: view(s) });
    }

    /* ---- edit requests: approve = the user may edit exactly once; reject / revoke = no edit ---- */
    if (b.action === "decide") {
      if (!L.can(me, "requests")) return L.send(res, 403, { ok: false, error: "forbidden" });
      const id = String(b.id || "");
      if (!UUID.test(id)) return L.send(res, 400, { ok: false });
      const approve = b.decision === "approve";
      if (!approve && b.decision !== "reject") return L.send(res, 400, { ok: false });
      const note = L.cleanText(b.note, 300);
      // a college-limited admin may only decide requests of people in their colleges
      if (me.colleges) {
        const q = await S.db("edit_requests?id=eq." + enc(id) + "&select=user_id&limit=1");
        if (!q.ok) return L.send(res, 502, { ok: false });
        if (!q.j[0]) return L.send(res, 409, { ok: false, error: "not_pending" });
        const cols = await collegesByUser([q.j[0].user_id]);
        if (!L.inScope(me, cols[q.j[0].user_id] || "")) return L.send(res, 403, { ok: false, error: "forbidden" });
      }
      // approve only works on a pending request; reject also revokes an approval that was not used yet
      const from = approve ? "eq.pending" : "in.(pending,approved)";
      const u = await S.db("edit_requests?id=eq." + enc(id) + "&status=" + from + "&select=id,user_id", {
        method: "PATCH", headers: { Prefer: "return=representation" },
        body: { status: approve ? "approved" : "rejected", admin_note: note, decided_at: new Date().toISOString(), decided_by: me.uid }
      });
      if (!u.ok) return L.send(res, 502, { ok: false });
      if (!Array.isArray(u.j) || !u.j.length) return L.send(res, 409, { ok: false, error: "not_pending" });
      await L.logEvent(req, { uid: me.uid, action: "edit_decide", target: u.j[0].user_id, detail: { decision: approve ? "approve" : "reject", note } });
      return L.send(res, 200, { ok: true, requests: await listRequests(me) });
    }

    /* ---- admin management (owner only) ---- */
    if (b.action === "addadmin") {
      if (!owner) return L.send(res, 403, { ok: false });
      const email = S.normEmail(b.email);
      if (!S.validEmail(email)) return L.send(res, 400, { ok: false, error: "bad_email" });
      const grant = readGrant(b);
      if (!grant) return L.send(res, 400, { ok: false, error: "bad_grant" });
      const p = await S.db("profiles?email=eq." + enc(email) + "&select=id&limit=1");
      if (!p.ok) return L.send(res, 502, { ok: false });
      if (!p.j[0]) return L.send(res, 404, { ok: false, error: "not_found" }); // the person must register first
      const ex = await S.db("admins?user_id=eq." + enc(p.j[0].id) + "&select=user_id&limit=1");
      if (!ex.ok) return L.send(res, 502, { ok: false });
      if (ex.j[0]) return L.send(res, 409, { ok: false, error: "already_admin" });
      const ins = await S.db("admins", {
        method: "POST", headers: { Prefer: "return=minimal" },
        body: { user_id: p.j[0].id, role: "admin", permissions: grant.permissions, colleges: grant.colleges }
      });
      if (!ins.ok) return L.send(res, 502, { ok: false });
      await L.logEvent(req, { uid: me.uid, action: "admin_add", target: p.j[0].id, targetEmail: email, detail: { permissions: grant.permissions, colleges: grant.colleges } });
      return L.send(res, 200, { ok: true, admins: await listAdmins() });
    }
    if (b.action === "updateadmin") {
      if (!owner) return L.send(res, 403, { ok: false });
      const id = String(b.id || "");
      if (!UUID.test(id)) return L.send(res, 400, { ok: false });
      const grant = readGrant(b);
      if (!grant) return L.send(res, 400, { ok: false, error: "bad_grant" });
      // never the owner (role=eq.admin), so the owner can't lock themselves out
      const u = await S.db("admins?user_id=eq." + enc(id) + "&role=eq.admin&select=user_id", {
        method: "PATCH", headers: { Prefer: "return=representation" },
        body: { permissions: grant.permissions, colleges: grant.colleges }
      });
      if (!u.ok) return L.send(res, 502, { ok: false });
      if (!Array.isArray(u.j) || !u.j.length) return L.send(res, 404, { ok: false, error: "not_found" });
      await L.logEvent(req, { uid: me.uid, action: "admin_update", target: id, detail: { permissions: grant.permissions, colleges: grant.colleges } });
      return L.send(res, 200, { ok: true, admins: await listAdmins() });
    }
    if (b.action === "removeadmin") {
      if (!owner) return L.send(res, 403, { ok: false });
      const id = String(b.id || "");
      if (!UUID.test(id)) return L.send(res, 400, { ok: false });
      if (id === me.uid) return L.send(res, 400, { ok: false, error: "self" });
      const d = await S.db("admins?user_id=eq." + enc(id) + "&role=eq.admin", { method: "DELETE", headers: { Prefer: "return=minimal" } }); // never the owner
      if (!d.ok) return L.send(res, 502, { ok: false });
      await L.logEvent(req, { uid: me.uid, action: "admin_remove", target: id });
      return L.send(res, 200, { ok: true, admins: await listAdmins() });
    }

    /* ---- reset a user's password (users have no reset option of their own) ---- */
    if (b.action === "resetpw") {
      if (!L.can(me, "passwords")) return L.send(res, 403, { ok: false, error: "forbidden" });
      const email = S.normEmail(b.email);
      if (!S.validEmail(email)) return L.send(res, 400, { ok: false, error: "bad_email" });
      if (!S.validPassword(b.password)) return L.send(res, 400, { ok: false, error: "bad_password" });
      const p = await S.db("profiles?email=eq." + enc(email) + "&select=id&limit=1");
      if (!p.ok) return L.send(res, 502, { ok: false });
      if (!p.j || !p.j[0]) return L.send(res, 404, { ok: false, error: "not_found" });
      const target = p.j[0].id;
      // a college-limited admin may only reset people whose response belongs to their colleges
      if (me.colleges) {
        const cols = await collegesByUser([target]);
        if (!L.inScope(me, cols[target] || "")) return L.send(res, 404, { ok: false, error: "not_found" });
      }
      // An admin account's password can only be changed by that admin (account page) or, for plain admins, by the owner.
      const t = await S.db("admins?user_id=eq." + enc(target) + "&select=role&limit=1");
      if (!t.ok) return L.send(res, 502, { ok: false });
      if (t.j[0] && target !== me.uid && !(owner && t.j[0].role !== "owner")) return L.send(res, 403, { ok: false, error: "protected" });
      const u = await S.admin("/users/" + enc(target), { method: "PUT", body: { password: b.password } });
      if (!u.ok) return L.send(res, 502, { ok: false });
      await L.logEvent(req, { uid: me.uid, action: "password_reset", target, targetEmail: email });
      return L.send(res, 200, { ok: true });
    }

    /* ---- activity log (owner only): newest first, optional category and e-mail search, paged by id ---- */
    if (b.action === "logs") {
      if (!owner) return L.send(res, 403, { ok: false, error: "forbidden" });
      const cats = {
        accounts: ["signup", "login", "login_failed", "logout", "profile_update"],
        form: ["form_ack", "form_submit", "form_edit"],
        requests: ["edit_request", "edit_cancel", "edit_decide"],
        admin: ["admin_login", "admin_login_failed", "admin_logout", "settings_update", "admin_add", "admin_update", "admin_remove", "password_reset"]
      };
      const PAGE = 100;
      let path = "activity_logs?select=id,created_at,actor_id,actor_email,action,target_id,target_email,detail,ip&order=id.desc&limit=" + (PAGE + 1);
      if (cats[b.category]) path += "&action=in.(" + cats[b.category].join(",") + ")";
      const q = String(b.q || "").replace(/[^\p{L}\p{N}@._+-]/gu, "").slice(0, 60);
      if (q) path += "&or=(actor_email.ilike.*" + enc(q) + "*,target_email.ilike.*" + enc(q) + "*)";
      if (/^\d{1,15}$/.test(String(b.before || ""))) path += "&id=lt." + b.before;
      const r = await S.db(path);
      if (!r.ok) return L.send(res, 200, { ok: false, error: "no_table" }); // usually: supabase.sql was not run again
      const more = r.j.length > PAGE, rows = r.j.slice(0, PAGE);
      const people = await peopleById(rows.flatMap(x => [x.actor_id, x.target_id]).filter(Boolean));
      const nm = (id, email) => ({ name: (people[id] || {}).full_name || "", email: (people[id] || {}).email || email || "" });
      return L.send(res, 200, {
        ok: true, more,
        logs: rows.map(x => ({ id: x.id, at: x.created_at, action: x.action, actor: nm(x.actor_id, x.actor_email), target: x.target_id || x.target_email ? nm(x.target_id, x.target_email) : null, detail: x.detail || {}, ip: x.ip || "" }))
      });
    }
    return L.send(res, 400, { ok: false });
  } catch (e) {
    console.error("admin failed:", e && e.message);
    return L.send(res, 502, { ok: false });
  }
};
