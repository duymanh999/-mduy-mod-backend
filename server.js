import express from "express";
import crypto from "node:crypto";
import archiver from "archiver";
import archiverZipEncrypted from "archiver-zip-encrypted";
import pg from "pg";
import { readFileSync } from "node:fs";

const { Pool } = pg;
const app = express();
app.set("trust proxy", true);
app.use(express.json({ limit: "30mb" }));
archiver.registerFormat("zip-encrypted", archiverZipEncrypted);

const PORT = process.env.PORT || 10000;
const LINK4M_API_TOKEN = process.env.LINK4M_API_TOKEN || "";
const FRONTEND_URL = (process.env.FRONTEND_URL || "https://duymanh999.github.io").replace(/\/+$/, "");
const PUBLIC_BASE_URL = (process.env.PUBLIC_BASE_URL || "https://mduy-mod-backend.onrender.com").replace(/\/+$/, "");
const ADMIN_PASSWORD = process.env.ADMIN_PASSWORD || "";
const DATABASE_URL = process.env.DATABASE_URL || "";
if (!DATABASE_URL) console.error("DATABASE_URL chưa được cấu hình");
if (!ADMIN_PASSWORD) console.error("ADMIN_PASSWORD chưa được cấu hình — trang quản trị sẽ bị khóa");

const pool = DATABASE_URL ? new Pool({ connectionString: DATABASE_URL, ssl: { rejectUnauthorized: false }, max: 5 }) : null;
const jobs = new Map();
const usage = new Map();

function ipOf(req) { return String(req.ip || req.headers["x-forwarded-for"] || "unknown").split(",")[0].trim(); }
function dayKey() { return new Date().toISOString().slice(0, 10); }
function randomId() { return crypto.randomBytes(18).toString("base64url"); }
function hashKey(key) { return crypto.createHash("sha256").update(String(key).trim().toUpperCase()).digest("hex"); }
function safeName(name) { return String(name).replace(/[^a-zA-Z0-9._ -]/g, "_").slice(0, 120) || "MDUY-MOD.zip"; }
function newKey() { return "MDUY-" + crypto.randomBytes(4).toString("hex").toUpperCase() + "-" + crypto.randomBytes(4).toString("hex").toUpperCase() + "-" + crypto.randomBytes(2).toString("hex").toUpperCase(); }

async function initDb() {
  if (!pool) return;
  await pool.query(`CREATE TABLE IF NOT EXISTS access_keys (
    id BIGSERIAL PRIMARY KEY,
    key_hash CHAR(64) UNIQUE NOT NULL,
    package_uses INTEGER NOT NULL CHECK (package_uses IN (50,100,200)),
    uses_remaining INTEGER NOT NULL CHECK (uses_remaining >= 0),
    price_vnd INTEGER NOT NULL,
    revoked BOOLEAN NOT NULL DEFAULT FALSE,
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
  )`);
  await pool.query(`CREATE INDEX IF NOT EXISTS access_keys_created_at_idx ON access_keys(created_at DESC)`);
  console.log("PostgreSQL key table ready");
}
function requireDb(req, res, next) { if (!pool) return res.status(503).json({ error: "Database chưa được cấu hình." }); next(); }
function adminOnly(req, res, next) {
  if (!ADMIN_PASSWORD) return res.status(503).json({ error: "Chưa cấu hình ADMIN_PASSWORD trong Render." });
  const supplied = String(req.get("x-admin-password") || "");
  const a = Buffer.from(supplied), b = Buffer.from(ADMIN_PASSWORD);
  if (a.length !== b.length || !crypto.timingSafeEqual(a, b)) return res.status(401).json({ error: "Mật khẩu quản trị không đúng." });
  next();
}

function allowCors(req, res, next) {
  const origin = req.headers.origin;
  if (!FRONTEND_URL || origin === FRONTEND_URL) { if (origin) res.setHeader("Access-Control-Allow-Origin", origin); }
  res.setHeader("Vary", "Origin");
  res.setHeader("Access-Control-Allow-Headers", "Content-Type, X-Admin-Password");
  res.setHeader("Access-Control-Allow-Methods", "GET,POST,OPTIONS");
  if (req.method === "OPTIONS") return res.sendStatus(204);
  next();
}
app.use(allowCors);
app.get("/health", (req, res) => res.json({ ok: true, databaseConfigured: !!pool }));
app.get("/admin", (req, res) => {
  try { res.type("html").send(readFileSync(new URL("./admin.html", import.meta.url), "utf8")); }
  catch { res.status(404).send("Thiếu file admin.html trong repository."); }
});

// Public endpoint: checks a key without consuming a use.
app.post("/api/keys/validate", requireDb, async (req, res) => {
  try {
    const key = String(req.body?.key || "").trim();
    if (!key) return res.status(400).json({ error: "Vui lòng nhập key." });
    const result = await pool.query("SELECT uses_remaining, revoked FROM access_keys WHERE key_hash=$1", [hashKey(key)]);
    if (!result.rowCount || result.rows[0].revoked || result.rows[0].uses_remaining <= 0) return res.status(403).json({ valid: false, error: "Key không hợp lệ, đã bị thu hồi hoặc hết lượt." });
    return res.json({ valid: true, usesRemaining: result.rows[0].uses_remaining });
  } catch (e) { console.error("validate key:", e); res.status(500).json({ error: "Không thể kiểm tra key lúc này." }); }
});

// Admin: create a key, return the plaintext only once.
app.post("/api/admin/keys", requireDb, adminOnly, async (req, res) => {
  try {
    const packageUses = Number(req.body?.packageUses);
    const packages = { 50: 50000, 100: 100000, 200: 150000 };
    if (!(packageUses in packages)) return res.status(400).json({ error: "Chọn gói 50, 100 hoặc 200 lượt." });
    let key, result;
    for (let i=0; i<5; i++) {
      key = newKey();
      try { result = await pool.query("INSERT INTO access_keys(key_hash, package_uses, uses_remaining, price_vnd) VALUES($1,$2,$2,$3) RETURNING id, package_uses, uses_remaining, price_vnd, revoked, created_at", [hashKey(key), packageUses, packages[packageUses]]); break; }
      catch (e) { if (e.code !== "23505" || i === 4) throw e; }
    }
    res.status(201).json({ key, record: result.rows[0] });
  } catch (e) { console.error("create key:", e); res.status(500).json({ error: "Không tạo được key." }); }
});
app.get("/api/admin/keys", requireDb, adminOnly, async (req, res) => {
  try {
    const result = await pool.query("SELECT id, package_uses, uses_remaining, price_vnd, revoked, created_at, updated_at FROM access_keys ORDER BY created_at DESC LIMIT 500");
    res.json({ keys: result.rows });
  } catch (e) { console.error("list keys:", e); res.status(500).json({ error: "Không tải được danh sách key." }); }
});
app.post("/api/admin/keys/:id/revoke", requireDb, adminOnly, async (req, res) => {
  try {
    const result = await pool.query("UPDATE access_keys SET revoked=TRUE, updated_at=NOW() WHERE id=$1 RETURNING id", [req.params.id]);
    if (!result.rowCount) return res.status(404).json({ error: "Không tìm thấy key." });
    res.json({ ok: true });
  } catch (e) { console.error("revoke key:", e); res.status(500).json({ error: "Không thu hồi được key." }); }
});

app.post("/api/mod/create", async (req, res) => {
  let reservedKeyHash = null;
  let createdJobId = null;
  try {
    const { zipBase64, filename, key: userKey } = req.body || {};
    if (typeof zipBase64 !== "string" || zipBase64.length < 20) {
      return res.status(400).json({ error: "Thiếu ZIP." });
    }
    const raw = Buffer.from(zipBase64, "base64");
    if (!raw.length) return res.status(400).json({ error: "ZIP không hợp lệ." });

    const id = randomId();
    const ip = ipOf(req);
    const safeFilename = safeName(filename || "MDUY-MOD.zip");

    // Paid-key path: consume one use and download directly, without Link4m or the free daily IP cap.
    if (typeof userKey === "string" && userKey.trim()) {
      if (!pool) return res.status(503).json({ error: "Hệ thống key chưa kết nối cơ sở dữ liệu." });
      const reserve = await pool.query(`UPDATE access_keys SET uses_remaining=uses_remaining-1, updated_at=NOW()
        WHERE key_hash=$1 AND revoked=FALSE AND uses_remaining>0
        RETURNING key_hash, uses_remaining`, [hashKey(userKey)]);
      if (!reserve.rowCount) return res.status(403).json({ error: "Key không hợp lệ, đã bị thu hồi hoặc hết lượt." });
      reservedKeyHash = reserve.rows[0].key_hash;
      jobs.set(id, { id, zip: raw, filename: safeFilename, createdAt: Date.now(), ip });
      createdJobId = id;
      const remaining = reserve.rows[0].uses_remaining;
      reservedKeyHash = null; // Consume only after ZIP job is stored successfully.
      return res.json({ id, directDownload: true, usesRemaining: remaining,
        downloadUrl: `${PUBLIC_BASE_URL}/api/mod/download/${encodeURIComponent(id)}`,
        message: "MOD đã sẵn sàng để tải trực tiếp." });
    }

    // Legacy/free path: keep the original Link4m flow and 3-creation-per-IP-per-day limit.
    if (!LINK4M_API_TOKEN) return res.status(500).json({ error: "LINK4M_API_TOKEN chưa được cấu hình" });
    if (!PUBLIC_BASE_URL) return res.status(500).json({ error: "PUBLIC_BASE_URL chưa được cấu hình" });
    const dailyKey = `${ip}:${dayKey()}`;
    const used = usage.get(dailyKey)?.count || 0;
    if (used >= 3) return res.status(429).json({ error: "IP này đã dùng hết 3 lượt hôm nay." });

    jobs.set(id, { id, zip: raw, filename: safeFilename, createdAt: Date.now(), ip });
    createdJobId = id;
    const claimUrl = `${PUBLIC_BASE_URL}/claim/${encodeURIComponent(id)}`;
    let shortUrl;
    try { shortUrl = await shortenWithLink4m(claimUrl); }
    catch (e) { jobs.delete(id); createdJobId = null; throw e; }
    usage.set(dailyKey, { day: dayKey(), count: used + 1 });
    return res.json({ id, shortUrl,
      downloadUrl: `${PUBLIC_BASE_URL}/api/mod/download/${encodeURIComponent(id)}`,
      message: "Đi qua Link4m để tới trang tải ZIP." });
  } catch (e) {
    if (reservedKeyHash) {
      try { await pool.query("UPDATE access_keys SET uses_remaining=uses_remaining+1, updated_at=NOW() WHERE key_hash=$1 AND revoked=FALSE", [reservedKeyHash]); }
      catch (refundError) { console.error("Không hoàn lại được lượt key:", refundError); }
    }
    if (createdJobId) jobs.delete(createdJobId);
    console.error("MOD create error:", e);
    return res.status(500).json({ error: e.message || "Server error" });
  }
});

app.get("/claim/:id", (req, res) => {
  const job = jobs.get(req.params.id);
  if (!job) return res.status(404).send("Link đã hết hạn hoặc không tồn tại.");
  res.type("html").send(`<!doctype html><html lang="vi"><head><meta name="viewport" content="width=device-width,initial-scale=1"><title>MDUY MOD FF — Tải ZIP</title><style>*{box-sizing:border-box}body{margin:0;min-height:100vh;display:grid;place-items:center;padding:24px;font-family:system-ui,-apple-system,sans-serif;background:#09090b;color:#fff}.card{width:min(460px,100%);padding:26px;border:1px solid #5967a5;border-radius:22px;background:linear-gradient(145deg,#111833,#28122f);box-shadow:0 25px 90px #000b;text-align:center}.kicker{color:#62eaff;font-size:10px;font-weight:900;letter-spacing:2px}h1{margin:8px 0 10px;font-size:25px}p{color:#bfc8e8;line-height:1.6}button{width:100%;padding:14px;border:0;border-radius:12px;font-size:16px;font-weight:900;cursor:pointer;background:linear-gradient(100deg,#65ffd0,#45e7ff 34%,#8d7aff 68%,#ff5fcf);color:#07101d}.small{font-size:11px;color:#929dc5;margin-top:12px}</style></head><body><div class="card"><div class="kicker">MDUY MOD FF</div><h1>Link đã hoàn tất</h1><p>ZIP đã sẵn sàng. Bấm nút bên dưới để tải file.</p><button onclick="location.href='/api/mod/download/${encodeURIComponent(req.params.id)}'">TẢI ZIP</button><div class="small">Không cần mật khẩu.</div></div></body></html>`);
});
app.get("/api/mod/download/:id", (req, res) => {
  const job = jobs.get(req.params.id);
  if (!job) return res.status(404).send("Not found");
  res.setHeader("Content-Type", "application/zip");
  res.setHeader("Content-Disposition", `attachment; filename="${job.filename}"`);
  res.send(job.zip);
});
async function shortenWithLink4m(targetUrl) {
  const url = new URL("https://link4m.co/api-shorten/v2");
  url.searchParams.set("api", LINK4M_API_TOKEN);
  url.searchParams.set("url", targetUrl);
  const response = await fetch(url, { method: "GET", headers: { "Accept": "application/json" } });
  const body = await response.text();
  let data;
  try { data = JSON.parse(body); } catch { console.error("Link4m raw response:", body.slice(0, 1000)); throw new Error("Link4m trả về dữ liệu không hợp lệ."); }
  if (!response.ok || data.status !== "success" || !data.shortenedUrl) throw new Error(data.message || "Link4m không tạo được link.");
  return data.shortenedUrl;
}

app.listen(PORT, async () => {
  console.log(`MDUY backend listening on ${PORT}`);
  try { await initDb(); } catch (e) { console.error("PostgreSQL initialization failed:", e); }
});
