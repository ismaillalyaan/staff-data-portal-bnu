// Shared helpers for the serverless functions (files starting with "_" are not routes).
const crypto = require("crypto");
const QUESTIONS = require("./questions.json");

const HEADERS = ["وقت الاستلام", "المعرف", ...QUESTIONS.map(q => (q.n ? q.n + ". " : "") + q.label)];
const MULTI = new Set(QUESTIONS.filter(q => q.type === "checks" || q.type === "multiselect").map(q => String(q.key)));
const DEFAULT_MESSAGE = "تم إغلاق الاستمارة. شكرًا لمشاركتكم.";
const SETTINGS_TAB = "_settings";

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
  return v.replace(/[\u0000-\u0008\u000B\u000C\u000E-\u001F\u007F‪-‮⁦-⁩]/g, "").trim().slice(0, max);
}

/* ---------- Google auth ---------- */
let tokenCache = { value: "", exp: 0 };
function makeJwt(email, privateKey, now) {
  const head = b64url(JSON.stringify({ alg: "RS256", typ: "JWT" }));
  const claim = b64url(JSON.stringify({
    iss: email, scope: "https://www.googleapis.com/auth/spreadsheets",
    aud: "https://oauth2.googleapis.com/token", iat: now, exp: now + 3600
  }));
  const sig = crypto.createSign("RSA-SHA256").update(head + "." + claim).sign(privateKey);
  return head + "." + claim + "." + b64url(sig);
}
async function accessToken() {
  const nowMs = Date.now();
  if (tokenCache.value && tokenCache.exp - 60000 > nowMs) return tokenCache.value;
  const email = process.env.GOOGLE_SERVICE_ACCOUNT_EMAIL;
  let key = process.env.GOOGLE_PRIVATE_KEY || "";
  if (process.env.GOOGLE_PRIVATE_KEY_BASE64) key = Buffer.from(process.env.GOOGLE_PRIVATE_KEY_BASE64, "base64").toString("utf8");
  key = key.trim().replace(/^["']|["']$/g, "").replace(/\\n/g, "\n").trim();
  if (!email || !key) throw new Error("missing credentials");
  const jwt = makeJwt(email, key, Math.floor(nowMs / 1000));
  const r = await fetch("https://oauth2.googleapis.com/token", {
    method: "POST",
    headers: { "Content-Type": "application/x-www-form-urlencoded" },
    body: "grant_type=" + encodeURIComponent("urn:ietf:params:oauth:grant-type:jwt-bearer") + "&assertion=" + encodeURIComponent(jwt)
  });
  if (!r.ok) throw new Error("token " + r.status);
  const j = await r.json();
  tokenCache = { value: j.access_token, exp: nowMs + (j.expires_in || 3600) * 1000 };
  return tokenCache.value;
}

/* ---------- Sheets ---------- */
async function sheets(suffix, opts) {
  const token = await accessToken();
  const r = await fetch("https://sheets.googleapis.com/v4/spreadsheets/" + encodeURIComponent(process.env.SHEET_ID) + suffix,
    Object.assign({ headers: { Authorization: "Bearer " + token, "Content-Type": "application/json" } }, opts));
  if (!r.ok) { const e = new Error("sheets " + r.status); e.status = r.status; throw e; }
  return r.json();
}
const values = range => "/values/" + encodeURIComponent(range);

let headerOk = false;
async function appendRow(row) {
  const q = "?valueInputOption=RAW&insertDataOption=INSERT_ROWS";
  if (!headerOk) {
    const first = await sheets(values("A1:A1"));
    if (!first.values || !first.values.length) {
      await sheets(values("A1:A1") + ":append" + q, { method: "POST", body: JSON.stringify({ values: [HEADERS] }) });
    }
    headerOk = true;
  }
  await sheets(values("A1:A1") + ":append" + q, { method: "POST", body: JSON.stringify({ values: [row] }) });
}

async function readRecords() {
  const j = await sheets(values("A:CZ"));
  const rows = j.values || [];
  const out = [];
  for (const row of rows) {
    if (!row || !row.length || row[0] === HEADERS[0]) continue;
    const a = {};
    QUESTIONS.forEach((q, i) => {
      const v = row[2 + i];
      if (v === undefined || v === "") return;
      a[q.key] = MULTI.has(String(q.key)) ? String(v).split(" | ") : v;
    });
    out.push({ id: row[1] || "", ts: String(row[0] || "").replace(" ", "T"), a });
  }
  return out.slice(-5000);
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

/* ---------- Form settings (stored in a hidden tab of the same sheet) ---------- */
let settingsCache = { v: null, t: 0 };
const range = () => "'" + SETTINGS_TAB + "'!A1:B3";

async function readSettings(fresh) {
  if (!fresh && settingsCache.v && Date.now() - settingsCache.t < 15000) return settingsCache.v;
  let s = { state: "open", closeAt: "", message: DEFAULT_MESSAGE };
  try {
    const j = await sheets(values(range()));
    (j.values || []).forEach(r => {
      if (r[0] === "state" && (r[1] === "open" || r[1] === "closed")) s.state = r[1];
      if (r[0] === "closeAt") s.closeAt = r[1] || "";
      if (r[0] === "message" && r[1]) s.message = r[1];
    });
  } catch (e) {
    if (e.status !== 400 && e.status !== 404) throw e; // tab not created yet: defaults
  }
  settingsCache = { v: s, t: Date.now() };
  return s;
}
async function writeSettings(s) {
  const body = JSON.stringify({ values: [["state", s.state], ["closeAt", s.closeAt || ""], ["message", s.message || ""]] });
  const put = () => sheets(values(range()) + "?valueInputOption=RAW", { method: "PUT", body });
  try { await put(); }
  catch (e) {
    if (e.status !== 400) throw e;
    await sheets(":batchUpdate", { method: "POST", body: JSON.stringify({ requests: [{ addSheet: { properties: { title: SETTINGS_TAB, hidden: true } } }] }) });
    await put();
  }
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

/* ---------- Admin session (signed cookie) ---------- */
const COOKIE = "adm";
const secretOk = () => (process.env.SESSION_SECRET || "").length >= 32 && !!process.env.ADMIN_PASSWORD;
const sign = p => b64url(crypto.createHmac("sha256", process.env.SESSION_SECRET).update(p).digest());
function makeCookie(maxAgeSec) {
  const p = b64url(JSON.stringify({ exp: Date.now() + maxAgeSec * 1000 }));
  return COOKIE + "=" + p + "." + sign(p) + "; HttpOnly; Secure; SameSite=Strict; Path=/api; Max-Age=" + maxAgeSec;
}
const clearCookie = () => COOKIE + "=; HttpOnly; Secure; SameSite=Strict; Path=/api; Max-Age=0";
function authed(req) {
  if (!secretOk()) return false;
  const m = new RegExp("(?:^|;\\s*)" + COOKIE + "=([^;]+)").exec(req.headers.cookie || "");
  if (!m) return false;
  const [p, sig] = m[1].split(".");
  if (!p || !sig) return false;
  const good = sign(p);
  if (sig.length !== good.length || !crypto.timingSafeEqual(Buffer.from(sig), Buffer.from(good))) return false;
  try { return JSON.parse(Buffer.from(p.replace(/-/g, "+").replace(/_/g, "/"), "base64").toString()).exp > Date.now(); } catch (e) { return false; }
}
function sameOrigin(req) {
  const o = req.headers.origin;
  if (!o) return false;
  try { return new URL(o).host === req.headers.host; } catch (e) { return false; }
}

module.exports = {
  QUESTIONS, HEADERS, DEFAULT_MESSAGE, send, cleanText, clientIp, safeEq, makeJwt,
  appendRow, readRecords, readSettings, writeSettings, isOpen, publicStatus,
  cairoToISO, isoToCairo, makeCookie, clearCookie, authed, sameOrigin, secretOk
};
