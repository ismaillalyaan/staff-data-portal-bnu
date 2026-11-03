// Public: tells the page whether the form is open.
const L = require("./_lib.js");
module.exports = async (req, res) => {
  if (req.method !== "GET") { res.setHeader("Allow", "GET"); return L.send(res, 405, { ok: false }); }
  try {
    return L.send(res, 200, Object.assign({ ok: true }, L.publicStatus(await L.readSettings(false))));
  } catch (e) {
    console.error("status failed:", e && e.message);
    return L.send(res, 200, { ok: true, open: true, message: L.DEFAULT_MESSAGE, closeAt: null });
  }
};
