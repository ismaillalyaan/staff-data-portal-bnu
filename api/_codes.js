// Email verification codes: generated and mailed by this server (Gmail SMTP), stored hashed in Supabase.
const crypto = require("crypto");
const S = require("./_sb.js");

const TTL_MIN = 10, MAX_TRIES = 5, COOLDOWN_MS = 60000;
const enc = encodeURIComponent;
const hashOf = (email, purpose, code) => crypto.createHmac("sha256", process.env.SESSION_SECRET || "").update("code:" + purpose + ":" + email + ":" + code).digest("hex");

let transport = null;
function mailer() {
  if (transport) return transport;
  const nodemailer = require("nodemailer");
  transport = nodemailer.createTransport({
    host: "smtp.gmail.com", port: 465, secure: true,
    auth: { user: process.env.GMAIL_USER, pass: String(process.env.GMAIL_APP_PASSWORD || "").replace(/\s+/g, "") }
  });
  return transport;
}
const mailReady = () => !!(process.env.GMAIL_USER && process.env.GMAIL_APP_PASSWORD);

const TEXT = {
  signup: { subject: "رمز تأكيد البريد الإلكتروني", lead: "استخدم الرمز التالي لتأكيد بريدك الإلكتروني وإكمال إنشاء حسابك" },
  reset: { subject: "رمز استعادة كلمة المرور", lead: "استخدم الرمز التالي لتعيين كلمة مرور جديدة لحسابك" }
};
function html(purpose, code) {
  const t = TEXT[purpose];
  return `<div dir="rtl" style="font-family:Tahoma,Arial,sans-serif;max-width:480px;margin:auto;padding:24px;border:1px solid #e2e8ea;border-radius:10px">
<h2 style="margin:0 0 12px;color:#0a5f7a">منصة بيانات الهيئة المعاونة ـ جامعة بنها الأهلية</h2>
<p style="margin:0 0 16px;color:#233">${t.lead}:</p>
<p style="font-size:34px;letter-spacing:8px;text-align:center;margin:18px 0;font-weight:700;color:#073345" dir="ltr">${code}</p>
<p style="color:#667;font-size:13px">الرمز صالح لمدة ${TTL_MIN} دقائق. إذا لم تطلب هذا الرمز فتجاهل الرسالة، ولا تشاركه مع أحد.</p></div>`;
}

// Returns "ok", "wait" (sent less than a minute ago) or "mail" (sending failed).
async function sendCode(email, purpose) {
  const old = await S.db("email_codes?email=eq." + enc(email) + "&purpose=eq." + purpose + "&select=sent_at&limit=1");
  if (old.ok && old.j[0] && Date.now() - Date.parse(old.j[0].sent_at) < COOLDOWN_MS) return "wait";
  const code = String(crypto.randomInt(0, 1000000)).padStart(6, "0");
  const now = new Date();
  const w = await S.db("email_codes?on_conflict=email,purpose", {
    method: "POST", headers: { Prefer: "resolution=merge-duplicates,return=minimal" },
    body: { email, purpose, code_hash: hashOf(email, purpose, code), expires_at: new Date(now.getTime() + TTL_MIN * 60000).toISOString(), attempts: 0, sent_at: now.toISOString() }
  });
  if (!w.ok) return "mail";
  try {
    await mailer().sendMail({
      from: '"منصة بيانات الهيئة المعاونة" <' + process.env.GMAIL_USER + ">",
      to: email, subject: TEXT[purpose].subject + " - " + code,
      text: TEXT[purpose].lead + ": " + code + "\nالرمز صالح لمدة " + TTL_MIN + " دقائق.",
      html: html(purpose, code)
    });
  } catch (e) {
    console.error("mail failed:", e && e.message);
    await S.db("email_codes?email=eq." + enc(email) + "&purpose=eq." + purpose, { method: "DELETE" });
    return "mail";
  }
  return "ok";
}

// True when the code is right (and consumes it).
async function checkCode(email, purpose, code) {
  const r = await S.db("email_codes?email=eq." + enc(email) + "&purpose=eq." + purpose + "&select=code_hash,expires_at,attempts&limit=1");
  const row = r.ok && r.j[0];
  const del = () => S.db("email_codes?email=eq." + enc(email) + "&purpose=eq." + purpose, { method: "DELETE" });
  if (!row) return false;
  if (Date.parse(row.expires_at) < Date.now() || row.attempts >= MAX_TRIES) { await del(); return false; }
  const a = Buffer.from(row.code_hash), b = Buffer.from(hashOf(email, purpose, code));
  if (a.length === b.length && crypto.timingSafeEqual(a, b)) { await del(); return true; }
  await S.db("email_codes?email=eq." + enc(email) + "&purpose=eq." + purpose, { method: "PATCH", headers: { Prefer: "return=minimal" }, body: { attempts: row.attempts + 1 } });
  return false;
}

module.exports = { sendCode, checkCode, mailReady };
