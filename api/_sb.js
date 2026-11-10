// Supabase helpers: Auth (GoTrue) + Postgres (PostgREST). Only the server talks to Supabase.
const crypto = require("crypto");

const URL_ = () => String(process.env.SUPABASE_URL || "").replace(/\/+$/, "");
const ANON = () => process.env.SUPABASE_ANON_KEY || "";
const SERVICE = () => process.env.SUPABASE_SERVICE_ROLE_KEY || "";
const configured = () => !!(URL_() && ANON() && SERVICE());

async function call(url, key, opts) {
  const o = Object.assign({}, opts);
  const base = { apikey: key, "Content-Type": "application/json" };
  // New sb_publishable_ / sb_secret_ keys are not JWTs: Supabase wants them in the apikey header only.
  // Legacy anon / service_role keys are JWTs and are still sent as a bearer token too.
  if (!/^sb_/.test(key)) base.Authorization = "Bearer " + key;
  o.headers = Object.assign(base, o.headers || {});
  if (o.body && typeof o.body !== "string") o.body = JSON.stringify(o.body);
  const r = await fetch(url, o);
  let j = null; const t = await r.text();
  try { j = t ? JSON.parse(t) : null; } catch (e) { j = null; }
  return { ok: r.ok, status: r.status, j };
}
// Auth endpoints called with the public (anon) key
const auth = (path, body, extra) => call(URL_() + "/auth/v1" + path, ANON(), Object.assign({ method: "POST", body }, extra));
// Admin endpoints and database access use the service role key (server only)
const admin = (path, opts) => call(URL_() + "/auth/v1/admin" + path, SERVICE(), opts);
const db = (path, opts) => call(URL_() + "/rest/v1/" + path, SERVICE(), opts);

const errCode = r => String((r.j && (r.j.error_code || r.j.code || r.j.msg || r.j.error)) || r.status);

/* ---------- validation ---------- */
const EN = s => String(s == null ? "" : s).replace(/[٠-٩]/g, c => c.charCodeAt(0) - 0x660).replace(/[۰-۹]/g, c => c.charCodeAt(0) - 0x6F0);
const normEmail = s => String(s || "").trim().toLowerCase();
const validEmail = s => s.length <= 120 && /^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(s);
const cleanName = s => String(s || "").replace(/[\u0000-\u001F\u007F‪-‮⁦-⁩<>]/g, "").replace(/\s+/g, " ").trim().slice(0, 100);
function validName(s) { return s.length >= 6 && s.split(" ").filter(x => x.length > 1).length >= 2; }
// Egyptian national ID: 14 digits, century digit 2 or 3, valid month and day.
function validNid(n) {
  if (!/^[23]\d{13}$/.test(n)) return false;
  const m = +n.slice(3, 5), d = +n.slice(5, 7);
  return m >= 1 && m <= 12 && d >= 1 && d <= 31;
}
function validPassword(p) { return typeof p === "string" && p.length >= 8 && p.length <= 72 && /[A-Za-z؀-ۿ]/.test(p) && /\d/.test(p); }
const validCode = c => /^\d{6,10}$/.test(c);
const nidHash = n => crypto.createHmac("sha256", process.env.SESSION_SECRET || "").update("nid:" + n).digest("hex");
const firstName = n => String(n || "").split(" ")[0] || "";

// National ID, stored encrypted (AES-256-GCM) in profiles.nid_enc so authorised staff can recover it.
// Key: NID_ENC_KEY if set (any long random string), otherwise derived from SESSION_SECRET.
// Keep the key stable: rotating it makes existing nid_enc values unreadable.
const nidKey = () => crypto.createHash("sha256").update("nid-enc:" + (process.env.NID_ENC_KEY || process.env.SESSION_SECRET || "")).digest();
const b64u = b => Buffer.from(b).toString("base64").replace(/=/g, "").replace(/\+/g, "-").replace(/\//g, "_");
const unb64u = s => Buffer.from(String(s).replace(/-/g, "+").replace(/_/g, "/"), "base64");
function nidEnc(n) {
  const iv = crypto.randomBytes(12);
  const c = crypto.createCipheriv("aes-256-gcm", nidKey(), iv);
  const ct = Buffer.concat([c.update(String(n), "utf8"), c.final()]);
  return "v1." + b64u(iv) + "." + b64u(c.getAuthTag()) + "." + b64u(ct);
}
// returns the plain national ID, or null if the value is missing or cannot be decrypted
function nidDec(v) {
  try {
    const [ver, iv, tag, ct] = String(v || "").split(".");
    if (ver !== "v1" || !iv || !tag || !ct) return null;
    const d = crypto.createDecipheriv("aes-256-gcm", nidKey(), unb64u(iv));
    d.setAuthTag(unb64u(tag));
    return Buffer.concat([d.update(unb64u(ct)), d.final()]).toString("utf8");
  } catch (e) { return null; }
}

module.exports = { configured, auth, admin, db, errCode, EN, normEmail, validEmail, cleanName, validName, validNid, validPassword, validCode, nidHash, nidEnc, nidDec, firstName };
