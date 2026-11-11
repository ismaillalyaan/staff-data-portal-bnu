// Shared helpers for the serverless functions (files starting with "_" are not routes).
const crypto = require("crypto");
const QUESTIONS = require("./questions.json");

// Column titles for exports (CSV etc.).
const HEADERS = ["وقت الاستلام", "المعرف", ...QUESTIONS.map(q => (q.n ? q.n + ". " : "") + q.label)];
const DEFAULT_MESSAGE = "تم إغلاق الاستمارة. شكرًا لمشاركتكم.";

// Loaded lazily so a require cycle with _sb.js can never happen.
const sb = () => require("./_sb.js");

/* ---------- small utils ---------- */
const b64url = b => Buffer.from(b).toString("base64").replace(/=/g, "").replace(/\+/g, "-").replace(/\//g, "_");
const sha = s => crypto.createHash("sha256").update(String(s)).digest();
const safeEq = (a, b) => crypto.timingSafeEqual(sha(a), sha(b));
const clientIp = req => String(req.headers["x-forwarded-for"] || "").split(",")[0].trim() || "unknown";

function send(res, code, body, extra) {
  res.statusCode = code;
  res.setHeader("Content-Type", "application/json; charset=utf-8");
  res.setHeader("Cache-Control", "no-store");
  res.setHeader("X-Content-Type-Options", "nosniff");
  if (extra) for (const k of Object.keys(extra)) res.setHeader(k, extra[k]);
  res.end(JSON.stringify(body));
}

function cleanText(v, max) {
  if (typeof v !== "string") return "";
  return v.replace(/[\u0000-\u0008\u000B\u000C\u000E-\u001F\u007F\u202A-\u202E\u2066-\u2069]/g, "").trim().slice(0, max);
}

/* ---------- Responses (Supabase: public.responses) ---------- */
// Same shape the dashboard always received: [{ id, ts, a }], oldest first, newest 5000 at most.
async function readRecords() {
  const PAGE = 1000, MAX = 5000;
  const rows = [];
  for (let off = 0; off < MAX; off += PAGE) {
    const r = await sb().db("responses?select=id,answers,updated_at&order=updated_at.desc&limit=" + PAGE + "&offset=" + off);
    if (!r.ok) throw new Error("db read failed");
    rows.push(...r.j);
    if (r.j.length < PAGE) break;
  }
  return rows.reverse().map(x => ({
    id: x.id || "",
    ts: isoToCairo(x.updated_at),
    a: x.answers && typeof x.answers === "object" ? x.answers : {}
  }));
}

/* ---------- Cairo time ---------- */
function tzOffsetMin(utcMs) {
  const f = new Intl.DateTimeFormat("en-US", { timeZone: "Africa/Cairo", hourCycle: "h23", year: "numeric", month: "2-digit", day: "2-digit", hour: "2-digit", minute: "2-digit", second: "2-digit" });
  const p = Object.fromEntries(f.formatToParts(new Date(utcMs)).map(x => [x.type, x.value]));
  return (Date.UTC(+p.year, +p.month - 1, +p.day, +p.hour, +p.minute, +p.second) - utcMs) / 60000;
}
function cairoToISO(local) {
  const m = /^(\d{4})-(\d{2})-(\d{2})T(\d{2}):(\d{2})$/.exec(local || "");
  if (!m) return null;
  const guess = Date.UTC(+m[1], +m[2] - 1, +m[3], +m[4], +m[5]);
  let ms = guess - tzOffsetMin(guess) * 60000;
  ms = guess - tzOffsetMin(ms) * 60000;
  return new Date(ms).toISOString();
}
function isoToCairo(iso) {
  const ms = Date.parse(iso || "");
  if (isNaN(ms)) return "";
  return new Date(ms + tzOffsetMin(ms) * 60000).toISOString().slice(0, 16);
}

/* ---------- Form settings (Supabase: public.settings, a single row with id = 1) ---------- */
let settingsCache = { v: null, t: 0 };

async function readSettings(fresh) {
  if (!fresh && settingsCache.v && Date.now() - settingsCache.t < 4000) return settingsCache.v;
  const s = { state: "open", closeAt: "", message: DEFAULT_MESSAGE };
  const r = await sb().db("settings?id=eq.1&select=state,close_at,message&limit=1");
  if (!r.ok) throw new Error("settings read failed");
  const row = r.j && r.j[0];
  if (row) {
    if (row.state === "open" || row.state === "closed") s.state = row.state;
    s.closeAt = row.close_at || "";
    if (row.message) s.message = row.message;
  }
  settingsCache = { v: s, t: Date.now() };
  return s;
}
async function writeSettings(s) {
  const r = await sb().db("settings", {
    method: "POST",
    headers: { Prefer: "resolution=merge-duplicates,return=minimal" },
    body: { id: 1, state: s.state, close_at: s.closeAt || "", message: s.message || "", updated_at: new Date().toISOString() }
  });
  if (!r.ok) throw new Error("settings write failed");
  settingsCache = { v: s, t: Date.now() };
}
function isOpen(s) {
  if (s.state === "closed") return false;
  if (s.closeAt) { const t = Date.parse(s.closeAt); if (!isNaN(t) && Date.now() >= t) return false; }
  return true;
}
function publicStatus(s) {
  return { open: isOpen(s), message: s.message || DEFAULT_MESSAGE, closeAt: s.closeAt || null };
}

/* ---------- Signed cookies (HMAC with SESSION_SECRET) ---------- */
// There is no shared admin password anymore. An admin is a normal account that has a row in public.admins.
// The "adm" cookie only proves "this browser logged in as admin X recently"; every admin request
// re-checks public.admins, so removing someone from that table cuts their access immediately.
const COOKIE = "adm";
const UCOOKIE = "usr";
const secretOk = () => (process.env.SESSION_SECRET || "").length >= 32;
const userSecretOk = secretOk;
const sign = p => b64url(crypto.createHmac("sha256", process.env.SESSION_SECRET).update(p).digest());
const unb64 = s => Buffer.from(s.replace(/-/g, "+").replace(/_/g, "/"), "base64").toString();

function makeSigned(name, purpose, uid, maxAgeSec) {
  const p = b64url(JSON.stringify({ uid, p: purpose, exp: Date.now() + maxAgeSec * 1000 }));
  return name + "=" + p + "." + sign(p) + "; HttpOnly; Secure; SameSite=Strict; Path=/api; Max-Age=" + maxAgeSec;
}
const clearSigned = name => name + "=; HttpOnly; Secure; SameSite=Strict; Path=/api; Max-Age=0";
// returns the uid inside a valid, unexpired cookie of the given purpose, else null
function readSigned(req, name, purpose) {
  if (!secretOk()) return null;
  const m = new RegExp("(?:^|;\\s*)" + name + "=([^;]+)").exec(req.headers.cookie || "");
  if (!m) return null;
  const [p, sig] = m[1].split(".");
  if (!p || !sig) return null;
  const good = sign(p);
  if (sig.length !== good.length || !crypto.timingSafeEqual(Buffer.from(sig), Buffer.from(good))) return null;
  try {
    const o = JSON.parse(unb64(p));
    if (!(o.exp > Date.now()) || !/^[0-9a-f-]{36}$/i.test(String(o.uid))) return null;
    // user cookies issued before purposes existed carry no "p"; admin cookies must always carry "adm"
    if (purpose === "usr" ? (o.p && o.p !== "usr") : o.p !== purpose) return null;
    return o.uid;
  } catch (e) { return null; }
}

const makeCookie = (uid, maxAgeSec) => makeSigned(COOKIE, "adm", uid, maxAgeSec);
const clearCookie = () => clearSigned(COOKIE);
const makeUserCookie = (uid, maxAgeSec) => makeSigned(UCOOKIE, "usr", uid, maxAgeSec);
const clearUserCookie = () => clearSigned(UCOOKIE);
const userId = req => readSigned(req, UCOOKIE, "usr");
const adminCookieUid = req => readSigned(req, COOKIE, "adm");

// Admin check: valid admin cookie AND the account is still listed in public.admins.
// Returns { uid, role } or null.
// Permissions an admin can be given. The owner always has all of them and sees every college.
const PERMS = ["data", "requests", "settings", "passwords"];
// Returns { uid, role, permissions, colleges } or null. colleges === null means "all colleges".
async function adminOf(req) {
  const uid = readSigned(req, COOKIE, "adm");
  if (!uid) return null;
  const r = await sb().db("admins?user_id=eq." + encodeURIComponent(uid) + "&select=role,permissions,colleges&limit=1");
  if (!r.ok) throw new Error("admin lookup failed");
  const row = Array.isArray(r.j) && r.j[0];
  if (!row) return null;
  const owner = row.role === "owner";
  return {
    uid, role: row.role,
    permissions: owner ? PERMS.slice() : (Array.isArray(row.permissions) ? row.permissions.filter(p => PERMS.includes(p)) : []),
    colleges: owner || !Array.isArray(row.colleges) ? null : row.colleges
  };
}
const can = (me, perm) => !!me && me.permissions.includes(perm);
// college of a response (question 7); "" when unknown
const collegeOf = answers => (answers && typeof answers === "object" && typeof answers["7"] === "string") ? answers["7"] : "";
const inScope = (me, college) => !me.colleges || me.colleges.includes(college);
// Is this account an admin? (used to show the admin link to the user)
async function isAdminUser(uid) {
  const r = await sb().db("admins?user_id=eq." + encodeURIComponent(uid) + "&select=role&limit=1");
  return r.ok && Array.isArray(r.j) && !!r.j[0] ? r.j[0].role : null;
}
function sameOrigin(req) {
  const o = req.headers.origin;
  if (!o) return false;
  try { return new URL(o).host === req.headers.host; } catch (e) { return false; }
}

module.exports = {
  QUESTIONS, HEADERS, DEFAULT_MESSAGE, send, cleanText, clientIp, safeEq,
  readRecords, readSettings, writeSettings, isOpen, publicStatus,
  cairoToISO, isoToCairo, makeCookie, clearCookie, adminOf, isAdminUser, sameOrigin, secretOk,
  PERMS, can, collegeOf, inScope,
  makeUserCookie, clearUserCookie, userId, userSecretOk, adminCookieUid
};
