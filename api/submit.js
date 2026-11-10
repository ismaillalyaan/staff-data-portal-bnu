// Saves (or updates) the signed-in user's response in Supabase.
const crypto = require("crypto");
const L = require("./_lib.js");
const S = require("./_sb.js");

const MAX_BODY = 100 * 1024;
const hits = new Map();
function limited(key) {
  const now = Date.now();
  const list = (hits.get(key) || []).filter(t => now - t < 600000);
  if (list.length >= 12) { hits.set(key, list); return true; }
  list.push(now); hits.set(key, list);
  if (hits.size > 5000) for (const [k, v] of hits) if (!v.some(t => now - t < 600000)) hits.delete(k);
  return false;
}

const stripCtl = s => s.replace(/[\u0000-\u0008\u000B\u000C\u000E-\u001F\u007F\u202A-\u202E\u2066-\u2069]/g, "").trim().slice(0, 3000);
// stored value: text, or a list of texts
function keep(v) {
  if (Array.isArray(v)) { const a = v.slice(0, 50).map(x => (typeof x === "string" ? stripCtl(x) : "")).filter(Boolean); return a.length ? a : ""; }
  if (typeof v === "number" && Number.isFinite(v)) return String(v);
  return typeof v === "string" ? stripCtl(v) : "";
}

// Writes a response row with answers_detail (number + question + answer). If the column has not been
// created yet (supabase.sql not re-run), the save still goes through without it.
async function save(url, method, base, detail) {
  const send = body => S.db(url, { method, headers: { Prefer: "return=minimal" }, body });
  let r = await send(Object.assign({}, base, { answers_detail: detail }));
  if (!r.ok && /answers_detail/.test(JSON.stringify(r.j || ""))) {
    console.error("responses.answers_detail column is missing: run the new line in supabase.sql");
    r = await send(base);
  }
  return r;
}

module.exports = async (req, res) => {
  if (req.method !== "POST") { res.setHeader("Allow", "POST"); return L.send(res, 405, { ok: false }); }
  if (!S.configured() || !L.userSecretOk()) return L.send(res, 503, { ok: false, reason: "config" });

  const norm = s => String(s).trim().toLowerCase().replace(/\/+$/, "").replace(/^https?:\/\//, "");
  const allowed = (process.env.ALLOWED_ORIGINS || "").split(",").map(norm).filter(Boolean);
  if (allowed.length && !allowed.includes(norm(req.headers.origin || ""))) return L.send(res, 403, { ok: false, reason: "origin" });
  if (!L.sameOrigin(req)) return L.send(res, 403, { ok: false, reason: "origin" });
  if (!/^application\/json/i.test(req.headers["content-type"] || "")) return L.send(res, 415, { ok: false, reason: "type" });
  if (Number(req.headers["content-length"] || 0) > MAX_BODY) return L.send(res, 413, { ok: false, reason: "size" });

  const uid = L.userId(req);
  if (!uid) return L.send(res, 401, { ok: false, reason: "auth" });
  if (limited(uid)) return L.send(res, 429, { ok: false, reason: "rate" }, { "Retry-After": "600" });

  let body = req.body;
  if (typeof body === "string") { try { body = JSON.parse(body); } catch (e) { return L.send(res, 400, { ok: false }); } }
  if (!body || typeof body !== "object" || !body.a || typeof body.a !== "object" || Array.isArray(body.a)) return L.send(res, 400, { ok: false });
  if (JSON.stringify(body).length > MAX_BODY) return L.send(res, 413, { ok: false });

  try {
    const st = L.publicStatus(await L.readSettings(false));
    if (!st.open) return L.send(res, 403, { ok: false, closed: true, message: st.message });
  } catch (e) { /* if settings cannot be read, keep accepting */ }

  const stored = {}; let known = 0;
  for (const q of L.QUESTIONS) {
    if (!Object.prototype.hasOwnProperty.call(body.a, q.key)) continue;
    const v = keep(body.a[q.key]);
    if (v) { stored[q.key] = v; known++; }
  }
  if (!known) return L.send(res, 400, { ok: false });
  // Question number, question text and answer, in question order. Text comes from the server's own list.
  const detail = L.QUESTIONS.filter(q => stored[q.key] !== undefined)
    .map(q => ({ key: q.key, n: q.n || null, question: q.label, answer: stored[q.key] }));

  try {
    const prof = await S.db("profiles?id=eq." + encodeURIComponent(uid) + "&select=id&limit=1");
    if (!prof.ok || !prof.j[0]) return L.send(res, 401, { ok: false, reason: "auth" });

    const old = await S.db("responses?user_id=eq." + encodeURIComponent(uid) + "&select=id,answers,history,updated_at&limit=1");
    if (!old.ok) return L.send(res, 502, { ok: false, reason: "db" });
    const prev = old.j[0] || null;
    const rid = prev ? prev.id : crypto.randomUUID();
    const now = new Date().toISOString();

    if (prev) {
      let history = Array.isArray(prev.history) ? prev.history : [];
      if (JSON.stringify(prev.answers) !== JSON.stringify(stored)) history = [{ ts: prev.updated_at, a: prev.answers }, ...history].slice(0, 10);
      const u = await save("responses?id=eq." + rid, "PATCH", { answers: stored, history, updated_at: now }, detail);
      if (!u.ok) return L.send(res, 502, { ok: false, reason: "db" });
    } else {
      const u = await save("responses", "POST", { id: rid, user_id: uid, answers: stored, history: [], created_at: now, updated_at: now }, detail);
      if (!u.ok) return L.send(res, 502, { ok: false, reason: "db" });
    }

    return L.send(res, 200, { ok: true, updated: !!prev, ts: now });
  } catch (e) {
    console.error("submit failed:", e && e.message);
    return L.send(res, 502, { ok: false, reason: "server" });
  }
};
