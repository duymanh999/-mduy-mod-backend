import express from "express";
import crypto from "node:crypto";
import archiver from "archiver";
import archiverZipEncrypted from "archiver-zip-encrypted";

const app = express();
app.set("trust proxy", true);
app.use(express.json({ limit: "30mb" }));

// Register the encrypted ZIP format explicitly.
// This fixes: "create(zip-encrypted): format not registered"
archiver.registerFormat("zip-encrypted", archiverZipEncrypted);

const PORT = process.env.PORT || 10000;
const LINK4M_API_TOKEN = process.env.LINK4M_API_TOKEN || "";
const FRONTEND_URL = (process.env.FRONTEND_URL || "").replace(/\/+$/, "");
const PUBLIC_BASE_URL = (process.env.PUBLIC_BASE_URL || "").replace(/\/+$/, "");

const jobs = new Map();
const usage = new Map();

function ipOf(req) {
  return String(
    req.ip || req.headers["x-forwarded-for"] || "unknown"
  ).split(",")[0].trim();
}

function dayKey() {
  return new Date().toISOString().slice(0, 10);
}

function randomPassword() {
  return crypto.randomBytes(9).toString("base64url");
}

function randomId() {
  return crypto.randomBytes(18).toString("base64url");
}

function cleanup() {
  const now = Date.now();

  for (const [id, job] of jobs) {
    if (now - job.createdAt > 24 * 60 * 60 * 1000) {
      jobs.delete(id);
    }
  }

  for (const [key, value] of usage) {
    if (value.day !== dayKey()) {
      usage.delete(key);
    }
  }
}

setInterval(cleanup, 10 * 60 * 1000).unref();

function allowCors(req, res, next) {
  const origin = req.headers.origin;

  if (!FRONTEND_URL || origin === FRONTEND_URL) {
    if (origin) {
      res.setHeader("Access-Control-Allow-Origin", origin);
    }
  }

  res.setHeader("Vary", "Origin");
  res.setHeader("Access-Control-Allow-Headers", "Content-Type");
  res.setHeader("Access-Control-Allow-Methods", "GET,POST,OPTIONS");

  if (req.method === "OPTIONS") {
    return res.sendStatus(204);
  }

  next();
}

app.use(allowCors);

app.get("/health", (req, res) => {
  res.json({ ok: true });
});

app.post("/api/mod/create", async (req, res) => {
  try {
    if (!LINK4M_API_TOKEN) {
      return res.status(500).json({
        error: "LINK4M_API_TOKEN chưa được cấu hình"
      });
    }

    if (!PUBLIC_BASE_URL) {
      return res.status(500).json({
        error: "PUBLIC_BASE_URL chưa được cấu hình"
      });
    }

    const ip = ipOf(req);
    const key = `${ip}:${dayKey()}`;
    const used = usage.get(key)?.count || 0;

    if (used >= 3) {
      return res.status(429).json({
        error: "IP này đã dùng hết 3 lượt hôm nay."
      });
    }

    const { zipBase64, filename } = req.body || {};

    if (typeof zipBase64 !== "string" || zipBase64.length < 20) {
      return res.status(400).json({ error: "Thiếu ZIP." });
    }

    const id = randomId();
    const password = randomPassword();
    const raw = Buffer.from(zipBase64, "base64");

    // Encrypt the user's original ZIP with a unique random password.
    const encrypted = await encryptZip(raw, password);

    const job = {
      id,
      password,
      encrypted,
      filename: safeName(filename || "MDUY-MOD.zip"),
      createdAt: Date.now(),
      claimed: false,
      ip
    };

    jobs.set(id, job);

    const claimUrl =
      `${PUBLIC_BASE_URL}/claim/${encodeURIComponent(id)}`;

    const shortUrl = await shortenWithLink4m(claimUrl);

    // Count the creation only after Link4m successfully returns a short URL.
    usage.set(key, {
      day: dayKey(),
      count: used + 1
    });

    res.json({
      id,
      shortUrl,
      downloadUrl:
        `${PUBLIC_BASE_URL}/api/mod/download/${encodeURIComponent(id)}`,
      message: "Đi qua Link4m để nhận mật khẩu."
    });
  } catch (e) {
    console.error(e);
    res.status(500).json({
      error: e.message || "Server error"
    });
  }
});

app.get("/claim/:id", (req, res) => {
  const job = jobs.get(req.params.id);

  if (!job) {
    return res.status(404).send("Link đã hết hạn hoặc không tồn tại.");
  }

  if (job.claimed) {
    return res.status(410).send("Link này đã được sử dụng.");
  }

  res.type("html").send(`<!doctype html>
<html lang="vi">
<head>
<meta name="viewport" content="width=device-width,initial-scale=1">
<title>MDUY MOD FF</title>
<style>
body{
  font-family:system-ui,-apple-system,sans-serif;
  background:#09090b;
  color:#fff;
  padding:40px 20px;
  text-align:center;
}
button{
  padding:14px 22px;
  border:0;
  border-radius:12px;
  font-weight:700;
  font-size:16px;
}
pre{
  white-space:pre-wrap;
  word-break:break-word;
  margin-top:20px;
}
</style>
</head>
<body>
<h2>MDUY MOD FF</h2>
<p>Nhấn nút để nhận mật khẩu ZIP.</p>
<button onclick="claim()">LẤY MẬT KHẨU</button>
<pre id="o"></pre>
<script>
async function claim(){
  const r = await fetch(
    '/api/mod/claim/${encodeURIComponent(req.params.id)}',
    { method:'POST' }
  );
  const d = await r.json();
  document.getElementById('o').textContent =
    d.password
      ? 'Mật khẩu: ' + d.password
      : (d.error || 'Lỗi');
}
</script>
</body>
</html>`);
});

app.post("/api/mod/claim/:id", (req, res) => {
  const job = jobs.get(req.params.id);

  if (!job) {
    return res.status(404).json({ error: "Link hết hạn." });
  }

  if (job.claimed) {
    return res.status(410).json({
      error: "Mật khẩu đã được nhận."
    });
  }

  job.claimed = true;

  res.json({
    password: job.password,
    filename: job.filename
  });
});

app.get("/api/mod/download/:id", (req, res) => {
  const job = jobs.get(req.params.id);

  if (!job) {
    return res.status(404).send("Not found");
  }

  res.setHeader("Content-Type", "application/zip");
  res.setHeader(
    "Content-Disposition",
    `attachment; filename="${job.filename}"`
  );

  res.send(job.encrypted);
});

function safeName(name) {
  return String(name)
    .replace(/[^a-zA-Z0-9._ -]/g, "_")
    .slice(0, 120) || "MDUY-MOD.zip";
}

async function encryptZip(zipBuffer, password) {
  return await new Promise((resolve, reject) => {
    const chunks = [];

    const archive = archiver.create("zip-encrypted", {
      zlib: { level: 0 },
      encryptionMethod: "aes256",
      password
    });

    archive.on("data", chunk => chunks.push(chunk));
    archive.on("error", reject);
    archive.on("end", () => {
      resolve(Buffer.concat(chunks));
    });

    archive.append(zipBuffer, {
      name: "MDUY-MOD-PACKAGE.zip",
      store: true
    });

    archive.finalize();
  });
}

async function shortenWithLink4m(targetUrl) {
  // Link4m API documentation:
  // GET https://link4m.co/api-shorten/v2?api=TOKEN&url=DESTINATION
  const url = new URL("https://link4m.co/api-shorten/v2");
  url.searchParams.set("api", LINK4M_API_TOKEN);
  url.searchParams.set("url", targetUrl);

  const response = await fetch(url, {
    method: "GET",
    headers: {
      "Accept": "application/json"
    }
  });

  const body = await response.text();

  let data;
  try {
    data = JSON.parse(body);
  } catch {
    console.error("Link4m raw response:", body.slice(0, 1000));
    throw new Error("Link4m trả về dữ liệu không hợp lệ.");
  }

  if (!response.ok || data.status !== "success" || !data.shortenedUrl) {
    throw new Error(
      data.message || "Link4m không tạo được link."
    );
  }

  return data.shortenedUrl;
}

app.listen(PORT, () => {
  console.log(`MDUY backend listening on ${PORT}`);
});
