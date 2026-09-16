// Vercel serverless function: admin-only delete of a user (auth account + cascades states/profiles).
// Requires env vars: SUPABASE_URL, SUPABASE_SERVICE_ROLE_KEY (server-side secret, never in the client).
module.exports = async (req, res) => {
  if (req.method !== "POST") return res.status(405).json({ error: "method not allowed" });
  const URL = process.env.SUPABASE_URL;
  const SRK = process.env.SUPABASE_SERVICE_ROLE_KEY;
  const ADMIN = "admin@email.com";
  if (!URL || !SRK) return res.status(500).json({ error: "server not configured (env vars missing)" });
  const token = (req.headers.authorization || "").replace(/^Bearer\s+/i, "");
  let body = req.body;
  if (typeof body === "string") { try { body = JSON.parse(body); } catch (e) { body = {}; } }
  const userId = body && body.userId;
  if (!token || !userId) return res.status(400).json({ error: "missing token or userId" });
  try {
    // 1) verify the caller is the admin
    const ur = await fetch(URL + "/auth/v1/user", { headers: { apikey: SRK, Authorization: "Bearer " + token } });
    if (!ur.ok) return res.status(401).json({ error: "unauthorized" });
    const user = await ur.json();
    if ((user.email || "").toLowerCase() !== ADMIN) return res.status(403).json({ error: "not admin" });
    if (userId === user.id) return res.status(400).json({ error: "cannot delete self" });
    // 2) delete the target user (states/profiles rows cascade)
    const dr = await fetch(URL + "/auth/v1/admin/users/" + userId, { method: "DELETE", headers: { apikey: SRK, Authorization: "Bearer " + SRK } });
    if (!dr.ok) { const t = await dr.text(); return res.status(500).json({ error: "delete failed: " + t.slice(0, 200) }); }
    return res.status(200).json({ ok: true });
  } catch (e) {
    return res.status(500).json({ error: String(e && e.message || e) });
  }
};
