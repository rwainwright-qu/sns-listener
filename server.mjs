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
const events = []; // { ts, id, headers, body, raw, note?, verified? }

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

function parseInnerMessage(body) {
  const candidate = body && body.Message ? body.Message : body;

  if (typeof candidate === "string") {
    try {
      return JSON.parse(candidate);
    } catch {
      return body;
    }
  }

  return candidate;
}

function getEventLabel(req) {
  const payload = parseInnerMessage(req.body);
  const entityType =
    (payload && (payload.entityType || payload.EntityType)) || "UnknownEntity";
  const eventType =
    (payload && (payload.eventType || payload.EventType)) || "UnknownEvent";
  return "[" + entityType + "] - [" + eventType + "]";
}

function serializeEvent(e) {
  return {
    id: e.id,
    when: new Date(e.ts).toLocaleString(),
    ts: e.ts,
    note: e.note || "Event",
    headers: e.headers,
    body: e.body,
    raw: e.raw,
    verified: e.verified
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
        try {
          req.body = JSON.parse(req.raw || "{}");
        } catch {
          req.body = {};
        }
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

function isTrustedCertUrl(urlString) {
  try {
    const u = new URL(urlString);
    const host = u.hostname.toLowerCase();
    const isHttps = u.protocol === "https:";
    const domainOk =
      host.endsWith(".amazonaws.com") ||
      host.endsWith(".amazonaws.com.cn");

    return isHttps && domainOk;
  } catch {
    return false;
  }
}

function buildStringToSign(messageType, msg) {
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

  const cache =
    verifySnsSignature._cache || (verifySnsSignature._cache = new Map());

  let pem = cache.get(certUrl);

  if (!pem) {
    const r = await fetch(certUrl, { timeout: 10000 });
    if (!r.ok) return false;
    pem = await r.text();
    cache.set(certUrl, pem);
  }

  const verifier = crypto.createVerify("RSA-SHA1");
  verifier.update(stringToSign, "utf8");
  verifier.end();

  try {
    return verifier.verify(pem, Buffer.from(signatureB64, "base64"));
  } catch {
    return false;
  }
}

// =================== Webhook endpoint ===================
app.post("/webhook", async (req, res) => {
  const messageType = req.headers["x-amz-sns-message-type"];
  const verified = await verifySnsSignature(req);

  if (
    messageType === "SubscriptionConfirmation" ||
    messageType === "UnsubscribeConfirmation"
  ) {
    const url = req.body && req.body.SubscribeURL;

    if (url) {
      try {
        const r = await fetch(url, { timeout: 10000 });
        pushEvent(
          nowEntry("Confirmed AWS SNS subscription link", req, {
            confirmStatus: r.status,
            verified
          })
        );
      } catch (e) {
        pushEvent(
          nowEntry("Failed to confirm AWS SNS subscription link", req, {
            error: String(e),
            verified
          })
        );
      }
    } else {
      pushEvent(
        nowEntry("SNS confirmation message without SubscribeURL", req, {
          verified
        })
      );
    }

    return res.status(200).send("OK");
  }

  const eventLabel = getEventLabel(req);

  pushEvent(
    nowEntry(eventLabel, req, {
      verified
    })
  );

  return res.status(200).send("OK");
});

// =================== Health & UI ===================
app.get("/health", (_req, res) => {
  res.status(200).json({
    ok: true,
    now: new Date().toISOString(),
    events: events.length
  });
});

app.get("/events", (_req, res) => {
  prune();
  res.status(200).json(events.slice().reverse().map(serializeEvent));
});

app.get("/", (_req, res) => {
  prune();

  const uiEvents = events.slice().reverse().map(serializeEvent);
  const eventsJson = JSON.stringify(uiEvents).replace(/</g, "\\u003c");

  res.setHeader("Content-Type", "text/html; charset=utf-8");
  res.end(`<!doctype html>
<html>
<head>
<meta charset="utf-8" />
<meta name="viewport" content="width=device-width,initial-scale=1" />
<title>SNS Listener</title>
<style>
  body {
    font-family: ui-sans-serif, -apple-system, Segoe UI, Roboto, Arial, sans-serif;
    max-width: 960px;
    margin: 2rem auto;
    padding: 0 1rem;
  }

  .top {
    display: flex;
    gap: 12px;
    align-items: center;
    flex-wrap: wrap;
  }

  .btn {
    padding: 8px 12px;
    border: 1px solid #ddd;
    border-radius: 6px;
    background: #fff;
    cursor: pointer;
    text-decoration: none;
    color: #000;
  }

  .meta {
    color: #666;
    font-size: 14px;
  }

  .event-list {
    margin-top: 1rem;
    display: grid;
    gap: 10px;
  }

  .event-row {
    border: 1px solid #e5e7eb;
    border-radius: 8px;
    padding: 12px;
    background: #fff;
    cursor: pointer;
  }

  .event-row:hover {
    background: #f9fafb;
  }

  .event-title {
    font-weight: 600;
  }

  .event-time {
    color: #666;
    font-size: 13px;
    margin-top: 4px;
  }

  .modal-backdrop {
    position: fixed;
    inset: 0;
    background: rgba(0,0,0,0.45);
    display: none;
    align-items: center;
    justify-content: center;
    padding: 24px;
  }

  .modal-backdrop.open {
    display: flex;
  }

  .modal {
    width: min(900px, 100%);
    max-height: 90vh;
    overflow: auto;
    background: #fff;
    border-radius: 12px;
    padding: 16px;
    box-shadow: 0 20px 60px rgba(0,0,0,0.25);
  }

  .modal-header {
    display: flex;
    justify-content: space-between;
    align-items: center;
    gap: 12px;
  }

  .close-btn {
    border: 1px solid #ddd;
    background: #fff;
    border-radius: 6px;
    padding: 8px 12px;
    cursor: pointer;
  }

  pre {
    background: #f6f8fa;
    padding: 12px;
    overflow-x: auto;
    border-radius: 6px;
    white-space: pre-wrap;
    word-break: break-word;
  }
</style>
</head>
<body>
  <div class="top">
    <h1>AWS SNS Event Listener</h1>
    <a class="btn" href="/health">Health</a>
    <button class="btn" id="refreshBtn" type="button">Refresh</button>
    <span class="meta">Auto-refreshes every 5 seconds without resetting the modal</span>
  </div>

  <p>Shows the last 24 hours of webhook calls to <code>POST /webhook</code>. Entries auto-purge and are never persisted.</p>

  <div id="eventList" class="event-list"></div>

  <div id="modalBackdrop" class="modal-backdrop">
    <div class="modal">
      <div class="modal-header">
        <div>
          <div id="modalTitle" class="event-title"></div>
          <div id="modalTime" class="event-time"></div>
        </div>
        <button class="close-btn" id="closeBtn" type="button">Close</button>
      </div>

      <div id="modalMeta"></div>

      <h3>Headers</h3>
      <pre id="modalHeaders"></pre>

      <h3>Body</h3>
      <pre id="modalBody"></pre>
    </div>
  </div>

<script>
  let events = ${eventsJson};
  let selectedEventId = null;

  function pretty(value) {
    try {
      return JSON.stringify(value, null, 2);
    } catch {
      return String(value);
    }
  }

  function escapeHtmlClient(str) {
    return String(str)
      .replaceAll("&", "&amp;")
      .replaceAll("<", "&lt;")
      .replaceAll(">", "&gt;")
      .replaceAll('"', "&quot;")
      .replaceAll("'", "&#39;");
  }

  function renderList() {
    const container = document.getElementById("eventList");

    if (!events.length) {
      container.innerHTML = "<p><i>No events yet...</i></p>";
      return;
    }

    container.innerHTML = events.map(function (e) {
      return '<div class="event-row" data-id="' + escapeHtmlClient(e.id) + '">' +
        '<div class="event-title">' + escapeHtmlClient(e.note) + "</div>" +
        '<div class="event-time">' + escapeHtmlClient(e.when) + ' - id: ' + escapeHtmlClient(e.id) + "</div>" +
      "</div>";
    }).join("");

    Array.from(container.querySelectorAll(".event-row")).forEach(function (row) {
      row.addEventListener("click", function () {
        openModal(row.dataset.id);
      });
    });
  }

  function openModal(id) {
    selectedEventId = id;
    const e = events.find(function (x) {
      return x.id === id;
    });

    if (!e) return;

    document.getElementById("modalTitle").textContent = e.note;
    document.getElementById("modalTime").textContent = e.when + " - id: " + e.id;
    document.getElementById("modalMeta").innerHTML =
      "<p><b>Signature verified:</b> " +
      (e.verified === true ? "yes" : e.verified === false ? "no" : "unknown") +
      "</p>";
    document.getElementById("modalHeaders").textContent = pretty(e.headers);
    document.getElementById("modalBody").textContent = pretty(e.body);
    document.getElementById("modalBackdrop").classList.add("open");
  }

  function closeModal() {
    selectedEventId = null;
    document.getElementById("modalBackdrop").classList.remove("open");
  }

  async function refreshEvents() {
    try {
      const res = await fetch("/events", { cache: "no-store" });
      if (!res.ok) return;

      events = await res.json();
      renderList();

      if (selectedEventId) {
        const stillExists = events.some(function (e) {
          return e.id === selectedEventId;
        });

        if (stillExists) {
          openModal(selectedEventId);
        } else {
          closeModal();
        }
      }
    } catch (err) {
      // Keep current UI state on refresh failures
    }
  }

  document.getElementById("refreshBtn").addEventListener("click", refreshEvents);
  document.getElementById("closeBtn").addEventListener("click", closeModal);
  document.getElementById("modalBackdrop").addEventListener("click", function (event) {
    if (event.target.id === "modalBackdrop") {
      closeModal();
    }
  });

  renderList();
  setInterval(refreshEvents, 5000);
</script>
</body>
</html>`);
});

// =================== start ===================
app.listen(PORT, () => {
  console.log("SNS listener running on http://0.0.0.0:" + PORT);
});
