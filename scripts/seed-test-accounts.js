// Creates confirmed test accounts (no email code needed) so the portal can be tested end to end.
//   node scripts/seed-test-accounts.js [count]     create (default 5)
//   node scripts/seed-test-accounts.js --clean     delete test accounts only
// Needs the same env vars as Vercel: SUPABASE_URL, SUPABASE_SERVICE_ROLE_KEY, SESSION_SECRET (and NID_ENC_KEY if you set one).
// Every test email ends with @test.bnu.invalid, and --clean touches nothing else.
const crypto = require("crypto");
const S = require("../api/_sb.js");

const DOMAIN = "@test.bnu.invalid";
const PASSWORD = process.env.TEST_PASSWORD || "Test12345";
const enc = encodeURIComponent;

for (const k of ["SUPABASE_URL", "SUPABASE_SERVICE_ROLE_KEY", "SESSION_SECRET"]) {
  if (!process.env[k]) { console.error("Missing env var: " + k); process.exit(1); }
}
if (process.env.SESSION_SECRET.length < 32) { console.error("SESSION_SECRET must be 32+ characters (use the same value as in Vercel)."); process.exit(1); }
if (!S.validPassword(PASSWORD)) { console.error("TEST_PASSWORD must be 8+ characters with a letter and a digit."); process.exit(1); }

const NAMES = ["أحمد محمد علي حسن", "سارة محمود إبراهيم السيد", "محمد عبد الله كامل يوسف", "نور الهدى خالد مصطفى", "عمر طارق فتحي سليمان",
  "مريم أشرف حسني عادل", "يوسف هاني رمضان فؤاد", "هدى سمير عثمان جابر", "كريم وائل صلاح الدين", "ليلى ياسر عطية منصور"];
// Fake but valid-format national IDs: 2 + birth date 900101 + governorate 01 + serial
const nidFor = i => "29001010100" + String(i).padStart(3, "0");
const emailFor = i => "test" + i + DOMAIN;

async function clean() {
  const r = await S.db("profiles?email=like." + enc("*" + DOMAIN) + "&select=id,email");
  if (!r.ok) throw new Error("could not list test profiles (" + r.status + ")");
  for (const p of r.j) {
    const d = await S.admin("/users/" + enc(p.id), { method: "DELETE" }); // cascades to profiles and responses
    console.log((d.ok || d.status === 404 ? "deleted " : "FAILED  ") + p.email);
    await S.db("profiles?id=eq." + enc(p.id), { method: "DELETE" });
  }
  await S.db("email_codes?email=like." + enc("*" + DOMAIN), { method: "DELETE" });
  console.log("done: " + r.j.length + " test account(s) removed.");
}

async function seed(count) {
  for (let i = 1; i <= count; i++) {
    const email = emailFor(i), name = NAMES[(i - 1) % NAMES.length], nid = nidFor(i);
    if (!S.validNid(nid) || !S.validName(name)) throw new Error("generated invalid test data for #" + i);
    const ex = await S.db("profiles?email=eq." + enc(email) + "&select=id&limit=1");
    if (!ex.ok) throw new Error("db error (" + ex.status + "): is supabase.sql applied?");
    if (ex.j[0]) { console.log("exists  " + email); continue; }
    const u = await S.admin("/users", { method: "POST", body: { email, password: PASSWORD, email_confirm: true, user_metadata: { full_name: name } } });
    if (!u.ok || !u.j || !u.j.id) { console.error("FAILED  " + email + " (" + S.errCode(u) + ")"); continue; }
    const p = await S.db("profiles", { method: "POST", headers: { Prefer: "return=minimal" }, body: { id: u.j.id, email, full_name: name, nid_hash: S.nidHash(nid), nid_enc: S.nidEnc(nid), nid_last4: nid.slice(-4) } });
    if (!p.ok) { await S.admin("/users/" + enc(u.j.id), { method: "DELETE" }); console.error("FAILED  " + email + " profile (" + p.status + ")"); continue; }
    if (i === 1) { // one account already has a submitted response, the rest are empty
      const now = new Date().toISOString();
      const a = { 1: name, 7: "كلية علوم الحاسب", 21: "معيد", 23: "تعيين", 27: "12", 35: "لا", 48: "لا", 68: "نعم" };
      const rr = await S.db("responses", { method: "POST", headers: { Prefer: "return=minimal" }, body: { id: crypto.randomUUID(), user_id: u.j.id, answers: a, history: [], created_at: now, updated_at: now } });
      if (!rr.ok) console.error("  (sample response failed: " + rr.status + ")");
    }
    console.log("created " + email + "  national ID " + nid + (i === 1 ? "  (has a sample response)" : ""));
  }
  console.log("\nLog in with any of these emails and password: " + PASSWORD);
}

(async () => {
  const arg = process.argv[2];
  if (arg === "--clean") return clean();
  const n = arg ? parseInt(arg, 10) : 5;
  if (!(n >= 1 && n <= 50)) { console.error("count must be 1-50"); process.exit(1); }
  return seed(n);
})().catch(e => { console.error("error:", e.message); process.exit(1); });
