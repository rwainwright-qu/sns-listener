import express from "express";
import morgan from "morgan";
import getRawBody from "raw-body";
import crypto from "crypto";
import fetch from "node-fetch";
import { URL } from "url";

const app = express();
const PORT = process.env.PORT || 8080;

// =================== simple 24h in-memory log ===================
const TTL_MS = 24 * 60 * 60 * 1000;
const MAX_EVENTS = 5000;
const events = []; // { ts, id, headers, body, raw, note? }

function prune() {
  const cutoff = Date.now() - TTL_MS;
  while (events.length && events[0].ts < cutoff) events.shift();
}
setInterval(prune, 60 * 1000);

function pushEvent(entry) {
  events.push(entry);
  if (events.length > MAX_EVENTS) events.shift();
}

// =================== helpers ===================
function nowEntry(note, req, extra = {}) {
  return {
    ts: Date.now(),
    id: crypto.randomUUID(),
    headers: req.headers,
    body: req.body,
    raw: req.raw,
    note,
    ...extra
  };
}

// Capture raw body so we can verify signatures
app.use(morgan("tiny"));
app.use(async (req, res, next) => {
  if (req.method === "POST" || req.method === "PUT") {
    try {
      req.raw = (await getRawBody(req)).toString("utf8");
      const ct = (req.headers["content-type"] || "").toLowerCase();
      if (ct.includes("application/json")) {
        try { req.body = JSON.parse(req.raw || "{}"); } catch { req.body = {}; }
      } else {
        req.body = req.raw;
      }
    } catch (e) {
      return res.status(400).send("Unable to read body");
    }
  }
  next();
});

// =================== AWS SNS signature verification ===================
// This matches AWS’ published algorithm:
// 1) Build string-to-sign based on Message/Subject/Timestamp/TopicArn/Type
// 2) Download SigningCertURL (must be from *.amazonaws.com/* or *.amazonaws.com.cn/*)
// 3) Verify Base64 Signature with SHA1withRSA against X.509 cert public key

function isTrustedCertUrl(urlString) {
  try {
    const u = new URL(urlString);
    const host = u.hostname.toLowerCase();
    const isHttps = u.protocol === "https:";
    const domainOk =
      host.endsWith(".amazonaws.com") ||
      host.endsWith(".amazonaws.com.cn");
    // Basic allowlist; you can tighten further if desired
    return isHttps && domainOk;
  } catch {
    return false;
  }
}

function buildStringToSign(messageType, msg) {
  // Per AWS docs, the order/fields differ by type.
  const lines = [];
  function add(key) {
    if (msg[key] !== undefined) {
      lines.push(key);
      lines.push(String(msg[key]));
    }
  }

  if (messageType === "Notification") {
    add("Message");
    if (msg.Subject) add("Subject");
    add("MessageId");
    add("Timestamp");
    add("TopicArn");
    add("Type");
  } else if (
    messageType === "SubscriptionConfirmation" ||
    messageType === "UnsubscribeConfirmation"
  ) {
    add("Message");
    add("MessageId");
    add("SubscribeURL");
    add("Timestamp");
    add("Token");
    add("TopicArn");
    add("Type");
  } else {
    // Unknown type; fall back to empty string (will fail verification)
    return "";
  }

  return lines.join("\n") + "\n";
}

async function verifySnsSignature(req) {
  const messageType = req.headers["x-amz-sns-message-type"];
  if (!messageType) return false;
  const msg = req.body || {};
  const certUrl = msg.SigningCertURL;
  const signatureB64 = msg.Signature;

  if (!certUrl || !signatureB64) return false;
  if (!isTrustedCertUrl(certUrl)) return false;

  const stringToSign = buildStringToSign(messageType, msg);
  if (!stringToSign) return false;

  // Fetch and cache certs very naively (process lifetime cache)
  const cache = verifySnsSignature._cache || (verifySnsSignature._cache = new Map());
  let pem = cache.get(certUrl);
  if (!pem) {
    const r = await fetch(certUrl, { timeout: 10_000 });
    if (!r.ok) return false;
    pem = await r.text();
    cache.set(certUrl, pem);
  }

  const verifier = crypto.createVerify("RSA-SHA1");
  verifier.update(stringToSign, "utf8");
  verifier.end();

  try {
    const ok = verifier.verify(pem, Buffer.from(signatureB64, "base64"));
    return ok;
  } catch {
    return false;
  }
}

// =================== Webhook endpoint ===================
app.post("/webhook", async (req, res) => {
  const messageType = req.headers["x-amz-sns-message-type"];

  // Verify SNS signature first; if it fails, return 401 (prevents bogus confirmations).
  const verified = await verifySnsSignature(req);
  if (!verified) {
    pushEvent(nowEntry("SNS signature verification FAILED", req));
    return res.status(401).send("Invalid SNS signature");
  }

  // Handle SubscriptionConfirmation / UnsubscribeConfirmation
  if (
    messageType === "SubscriptionConfirmation" ||
    messageType === "UnsubscribeConfirmation"
  ) {
    const url = req.body?.SubscribeURL;
    if (url) {
      try {
        const r = await fetch(url, { timeout: 10_000 });
        pushEvent(
          nowEntry("Confirmed AWS SNS subscription link", req, {
            confirmStatus: r.status
          })
        );
      } catch (e) {
        pushEvent(
          nowEntry("Failed to confirm AWS SNS subscription link", req, {
            error: String(e)
          })
        );
      }
    } else {
      pushEvent(nowEntry("SNS confirmation message without SubscribeURL", req));
    }
    return res.status(200).send("OK");
  }

  // Normal Notification
  pushEvent(nowEntry("SNS Notification", req));
  return res.status(200).send("OK");
});

// =================== Health & UI ===================
app.get("/health", (_req, res) => {
  res.status(200).json({ ok: true, now: new Date().toISOString(), events: events.length });
});

app.get("/", (_req, res) => {
  prune();
  const rows = events
    .slice()
    .reverse()
    .map((e) => {
      const when = new Date(e.ts).toLocaleString();
      const bodyPretty = (() => {
        try { return JSON.stringify(e.body, null, 2); } catch { return String(e.body); }
      })();
      return `
        <details>
          <summary><b>${when}</b> — ${e.note || "Event"} — id: ${e.id}</summary>
          <pre><b>Headers</b>\n${JSON.stringify(e.headers, null, 2)}</pre>
          <pre><b>Body</b>\n${bodyPretty}</pre>
        </details>
        <hr/>
      `;
    })
    .join("\n");

  res.setHeader("Content-Type", "text/html; charset=utf-8");
  res.end(`<!doctype html>
<html>
<head>
<meta charset="utf-8" />
<meta name="viewport" content="width=device-width,initial-scale=1" />
<title>SNS Listener</title>
<style>
  body { font-family: ui-sans-serif, -apple-system, Segoe UI, Roboto, Arial, sans-serif; max-width: 960px; margin: 2rem auto; padding: 0 1rem; }
  summary { cursor: pointer; }
  pre { background: #f6f8fa; padding: 12px; overflow-x: auto; border-radius: 6px; }
  hr { border: none; border-top: 1px solid #eee; margin: 1rem 0; }
  .top { display: flex; gap: 12px; align-items: center; }
  .btn { padding: 8px 12px; border: 1px solid #ddd; border-radius: 6px; background: #fff; cursor: pointer; text-decoration: none; color: #000; }
</style>
<script> setInterval(() => location.reload(), 5000); </script>
</head>
<body>
  <div class="top">
    <h1>AWS SNS Event Listener</h1>
    <a class="btn" href="/health">Health</a>
    <a class="btn" href="#" onclick="location.reload()">Refresh</a>
  </div>
  <p>Shows the last 24 hours of webhook calls to <code>POST /webhook</code>. Entries auto-purge and are never persisted.</p>
  ${rows || "<p><i>No events yet…</i></p>"}
</body>
</html>`);
});

// =================== start ===================
app.listen(PORT, () => {
  console.log(`SNS listener running on http://0.0.0.0:${PORT}`);
});
