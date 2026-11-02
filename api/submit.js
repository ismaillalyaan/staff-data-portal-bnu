// Vercel serverless function: receives one survey response and appends it to a Google Sheet.
// Secrets come from environment variables only (never from the repository):
//   GOOGLE_SERVICE_ACCOUNT_EMAIL, GOOGLE_PRIVATE_KEY, SHEET_ID, ALLOWED_ORIGINS (optional, comma separated)
const crypto = require("crypto");
const QUESTIONS = require("./questions.json");

const KEYS = new Set(QUESTIONS.map(q => String(q.key)));
const HEADERS = ["وقت الاستلام", "المعرف", ...QUESTIONS.map(q => (q.n ? q.n + ". " : "") + q.label)];

const MAX_BODY = 100 * 1024;
const MAX_STR = 3000;
const RATE_MAX = 5;
const RATE_WINDOW = 10 * 60 * 1000;
const hits = new Map();
let tokenCache = { value: "", exp: 0 };

const b64url = b => Buffer.from(b).toString("base64").replace(/=/g, "").replace(/\+/g, "-").replace(/\//g, "_");

function makeJwt(email, privateKey, now) {
  const head = b64url(JSON.stringify({ alg: "RS256", typ: "JWT" }));
  const claim = b64url(JSON.stringify({
    iss: email,
    scope: "https://www.googleapis.com/auth/spreadsheets",
    aud: "https://oauth2.googleapis.com/token",
    iat: now,
    exp: now + 3600
  }));
  const sig = crypto.createSign("RSA-SHA256").update(head + "." + claim).sign(privateKey);
  return head + "." + claim + "." + b64url(sig);
}

async function accessToken() {
  const nowMs = Date.now();
  if (tokenCache.value && tokenCache.exp - 60000 > nowMs) return tokenCache.value;
  const email = process.env.GOOGLE_SERVICE_ACCOUNT_EMAIL;
  const key = (process.env.GOOGLE_PRIVATE_KEY || "").replace(/\\n/g, "\n");
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

function clean(v) {
  if (Array.isArray(v)) return v.slice(0, 50).map(x => clean(x)).filter(x => x !== "").join(" | ");
  if (typeof v === "number" && Number.isFinite(v)) return String(v);
  if (typeof v !== "string") return "";
  let s = v.replace(/[\u0000-\u0008\u000B\u000C\u000E-\u001F\u007F‪-‮⁦-⁩]/g, "").trim().slice(0, MAX_STR);
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

async function sheets(path, token, opts) {
  const id = process.env.SHEET_ID;
  const r = await fetch("https://sheets.googleapis.com/v4/spreadsheets/" + encodeURIComponent(id) + "/values/" + path,
    Object.assign({ headers: { Authorization: "Bearer " + token, "Content-Type": "application/json" } }, opts));
  if (!r.ok) throw new Error("sheets " + r.status);
  return r.json();
}

async function appendRow(values, token) {
  const q = "?valueInputOption=RAW&insertDataOption=INSERT_ROWS";
  const first = await sheets("A1:A1", token);
  if (!first.values || !first.values.length) {
    await sheets("A1:append" + q, token, { method: "POST", body: JSON.stringify({ values: [HEADERS] }) });
  }
  await sheets("A1:append" + q, token, { method: "POST", body: JSON.stringify({ values: [values] }) });
}

function send(res, code, body) {
  res.statusCode = code;
  res.setHeader("Content-Type", "application/json; charset=utf-8");
  res.setHeader("Cache-Control", "no-store");
  res.setHeader("X-Content-Type-Options", "nosniff");
  res.end(JSON.stringify(body));
}

module.exports = async (req, res) => {
  if (req.method !== "POST") { res.setHeader("Allow", "POST"); return send(res, 405, { ok: false }); }

  const allowed = (process.env.ALLOWED_ORIGINS || "").split(",").map(s => s.trim()).filter(Boolean);
  if (allowed.length && !allowed.includes(req.headers.origin || "")) return send(res, 403, { ok: false });

  if (!/^application\/json/i.test(req.headers["content-type"] || "")) return send(res, 415, { ok: false });
  if (Number(req.headers["content-length"] || 0) > MAX_BODY) return send(res, 413, { ok: false });

  const ip = String(req.headers["x-forwarded-for"] || "").split(",")[0].trim() || "unknown";
  if (limited(ip)) { res.setHeader("Retry-After", "600"); return send(res, 429, { ok: false }); }

  let body = req.body;
  if (typeof body === "string") { try { body = JSON.parse(body); } catch (e) { return send(res, 400, { ok: false }); } }
  if (!body || typeof body !== "object" || !body.a || typeof body.a !== "object" || Array.isArray(body.a)) return send(res, 400, { ok: false });
  if (JSON.stringify(body).length > MAX_BODY) return send(res, 413, { ok: false });

  let known = 0;
  const row = [new Date().toLocaleString("sv-SE", { timeZone: "Africa/Cairo" }), crypto.randomUUID()];
  for (const q of QUESTIONS) {
    const raw = Object.prototype.hasOwnProperty.call(body.a, q.key) ? body.a[q.key] : "";
    const v = clean(raw);
    if (v) known++;
    row.push(v);
  }
  if (!known) return send(res, 400, { ok: false });

  try {
    await appendRow(row, await accessToken());
    return send(res, 200, { ok: true });
  } catch (e) {
    console.error("submit failed:", e && e.message);
    return send(res, 502, { ok: false });
  }
};

module.exports._test = { makeJwt, clean, HEADERS, KEYS };
