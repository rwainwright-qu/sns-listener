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

function getEventPayload(reqOrEventBody) {
  if (reqOrEventBody && reqOrEventBody.body !== undefined) {
    return parseInnerMessage(reqOrEventBody.body);
  }
  return parseInnerMessage(reqOrEventBody);
}

function getEventLabel(req) {
  const payload = getEventPayload(req);
  const companyId =
    (payload && (payload.companyId || payload.CompanyId || payload.companyID)) || "UnknownCompany";
  const entityType =
    (payload && (payload.entityType || payload.EntityType)) || "UnknownEntity";
  const eventType =
    (payload && (payload.eventType || payload.EventType)) || "UnknownEvent";

  return companyId + " - " + entityType + " - " + eventType;
}

function hasSnsUserAgent(headers) {
  const userAgent = headers && (headers["user-agent"] || headers["User-Agent"]);
  return userAgent === "Amazon Simple Notification Service Agent";
}

function serializeEvent(e) {
  const payload = getEventPayload(e);
  const companyId =
    (payload && (payload.companyId || payload.CompanyId || payload.companyID)) || "";
  const entityType =
    (payload && (payload.entityType || payload.EntityType)) || "";
  const eventType =
    (payload && (payload.eventType || payload.EventType)) || "";

  return {
    id: e.id,
    when: new Date(e.ts).toLocaleString(),
    ts: e.ts,
    note: e.note || "Event",
    headers: e.headers,
    body: e.body,
    raw: e.raw,
    verified: e.verified,
    companyId,
    entityType,
    eventType,
    hasSnsDot: hasSnsUserAgent(e.headers)
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
  * {
    box-sizing: border-box;
  }

  body {
    font-family: ui-sans-serif, -apple-system, Segoe UI, Roboto, Arial, sans-serif;
    margin: 0;
    background: #f8fafc;
    color: #111827;
  }

  .page {
    padding: 20px;
    max-width: 1440px;
    margin: 0 auto;
  }

  .top {
    display: flex;
    gap: 12px;
    align-items: center;
    flex-wrap: wrap;
    margin-bottom: 12px;
  }

  .top h1 {
    margin: 0;
    margin-right: 8px;
    font-size: 28px;
  }

  .btn {
    padding: 8px 12px;
    border: 1px solid #d1d5db;
    border-radius: 8px;
    background: #fff;
    cursor: pointer;
    text-decoration: none;
    color: #111827;
  }

  .meta {
    color: #6b7280;
    font-size: 14px;
  }

  .intro {
    margin: 0 0 16px 0;
    color: #4b5563;
  }

  .layout {
    display: grid;
    grid-template-columns: 440px 1fr;
    gap: 16px;
    min-height: calc(100vh - 140px);
  }

  .panel {
    background: #fff;
    border: 1px solid #e5e7eb;
    border-radius: 12px;
    overflow: hidden;
  }

  .panel-header {
    padding: 14px 16px;
    border-bottom: 1px solid #e5e7eb;
    font-weight: 600;
    background: #fcfcfd;
  }

  .tabs {
    display: flex;
    gap: 8px;
    padding: 12px 16px;
    border-bottom: 1px solid #e5e7eb;
    background: #fcfcfd;
  }

  .tab-btn {
    appearance: none;
    border: 1px solid #d1d5db;
    background: #ffffff;
    color: #374151;
    border-radius: 999px;
    padding: 8px 14px;
    font-size: 14px;
    font-weight: 600;
    cursor: pointer;
  }

  .tab-btn:hover {
    background: #f9fafb;
  }

  .tab-btn.active {
    background: #111827;
    color: #ffffff;
    border-color: #111827;
  }

  .tab-count {
    opacity: 0.8;
    margin-left: 6px;
  }

  .filters {
    padding: 12px 16px;
    border-bottom: 1px solid #e5e7eb;
    background: #ffffff;
  }

  .filter-label {
    display: block;
    font-size: 12px;
    color: #6b7280;
    margin-bottom: 6px;
    text-transform: uppercase;
    letter-spacing: 0.04em;
  }

  .filter-select {
    width: 100%;
    padding: 10px 12px;
    border: 1px solid #d1d5db;
    border-radius: 8px;
    background: #fff;
    color: #111827;
    font-size: 14px;
  }

  .event-list {
    display: grid;
    gap: 0;
    max-height: calc(100vh - 280px);
    overflow-y: auto;
  }

  .event-row {
    border-bottom: 1px solid #f1f5f9;
    padding: 14px 16px;
    background: #fff;
    cursor: pointer;
    display: flex;
    align-items: flex-start;
    justify-content: space-between;
    gap: 12px;
  }

  .event-row:hover {
    background: #f8fafc;
  }

  .event-row.selected {
    background: #eff6ff;
  }

  .event-row-main {
    min-width: 0;
    flex: 1;
  }

  .event-title {
    font-weight: 600;
    line-height: 1.35;
    word-break: break-word;
  }

  .event-time {
    color: #6b7280;
    font-size: 13px;
    margin-top: 6px;
  }

  .event-dot {
    width: 10px;
    height: 10px;
    min-width: 10px;
    border-radius: 999px;
    background: #facc15;
    margin-top: 6px;
    box-shadow: 0 0 0 2px rgba(250, 204, 21, 0.2);
  }

  .event-list-empty {
    padding: 24px;
    color: #6b7280;
  }

  .detail-wrap {
    display: flex;
    flex-direction: column;
    min-height: calc(100vh - 220px);
  }

  .detail-empty {
    padding: 24px;
    color: #6b7280;
  }

  .detail-content {
    padding: 16px;
    overflow: auto;
  }

  .detail-title {
    font-size: 22px;
    font-weight: 700;
    margin: 0 0 8px 0;
  }

  .detail-subtitle {
    font-size: 14px;
    color: #6b7280;
    margin-bottom: 16px;
  }

  .detail-grid {
    display: grid;
    grid-template-columns: repeat(2, minmax(180px, 1fr));
    gap: 12px;
    margin-bottom: 20px;
  }

  .stat {
    border: 1px solid #e5e7eb;
    border-radius: 10px;
    padding: 12px;
    background: #fafafa;
  }

  .stat-label {
    font-size: 12px;
    color: #6b7280;
    margin-bottom: 4px;
    text-transform: uppercase;
    letter-spacing: 0.04em;
  }

  .stat-value {
    font-size: 14px;
    font-weight: 600;
    word-break: break-word;
  }

  h3 {
    margin: 20px 0 8px 0;
    font-size: 15px;
  }

  pre {
    margin: 0;
    background: #f6f8fa;
    padding: 12px;
    overflow-x: auto;
    border-radius: 8px;
    white-space: pre-wrap;
    word-break: break-word;
    border: 1px solid #e5e7eb;
  }

  @media (max-width: 980px) {
    .layout {
      grid-template-columns: 1fr;
    }

    .event-list,
    .detail-wrap {
      max-height: none;
      min-height: 0;
    }
  }
</style>
</head>
<body>
  <div class="page">
    <div class="top">
      <h1>AWS SNS Event Listener</h1>
      <a class="btn" href="/health">Health</a>
      <button class="btn" id="refreshBtn" type="button">Refresh</button>
      <span class="meta">Auto-refreshes every 5 seconds without resetting your view</span>
    </div>

    <p class="intro">Shows the last 24 hours of webhook calls to <code>POST /webhook</code>. Entries auto-purge and are never persisted.</p>

    <div class="layout">
      <div class="panel">
        <div class="panel-header">Events</div>
        <div id="eventTabs" class="tabs"></div>
        <div class="filters">
          <label class="filter-label" for="companyFilter">Company</label>
          <select id="companyFilter" class="filter-select">
            <option value="__all__">All Companies</option>
          </select>
        </div>
        <div id="eventList" class="event-list"></div>
      </div>

      <div class="panel">
        <div class="panel-header">Selected Event</div>
        <div id="detailWrap" class="detail-wrap"></div>
      </div>
    </div>
  </div>

<script>
  let events = ${eventsJson};
  let selectedEventId = null;
  let activeTab = "sns";
  let activeCompanyFilter = "__all__";

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

  function getTabFilteredEvents() {
    return events.filter(function (e) {
      if (activeTab === "sns") return !!e.hasSnsDot;
      return !e.hasSnsDot;
    });
  }

  function getCompanyOptions() {
    const filteredByTab = getTabFilteredEvents();
    const unique = Array.from(
      new Set(
        filteredByTab
          .map(function (e) {
            return (e.companyId || "").trim();
          })
          .filter(function (value) {
            return value;
          })
      )
    );

    unique.sort(function (a, b) {
      return a.localeCompare(b);
    });

    return unique;
  }

  function getFilteredEvents() {
    const filteredByTab = getTabFilteredEvents();

    if (activeCompanyFilter === "__all__") {
      return filteredByTab;
    }

    return filteredByTab.filter(function (e) {
      return (e.companyId || "") === activeCompanyFilter;
    });
  }

  function ensureValidSelection() {
    const filteredEvents = getFilteredEvents();
    const selectedStillExists = filteredEvents.some(function (e) {
      return e.id === selectedEventId;
    });

    if (!selectedStillExists) {
      selectedEventId = filteredEvents.length ? filteredEvents[0].id : null;
    }
  }

  function ensureValidCompanyFilter() {
    const options = getCompanyOptions();
    const exists =
      activeCompanyFilter === "__all__" ||
      options.some(function (value) {
        return value === activeCompanyFilter;
      });

    if (!exists) {
      activeCompanyFilter = "__all__";
    }
  }

  function renderTabs() {
    const container = document.getElementById("eventTabs");
    const snsCount = events.filter(function (e) { return !!e.hasSnsDot; }).length;
    const otherCount = events.filter(function (e) { return !e.hasSnsDot; }).length;

    container.innerHTML =
      '<button class="tab-btn' + (activeTab === "sns" ? ' active' : '') + '" data-tab="sns" type="button">' +
        'Data Stream Events <span class="tab-count">(' + snsCount + ')</span>' +
      '</button>' +
      '<button class="tab-btn' + (activeTab === "other" ? ' active' : '') + '" data-tab="other" type="button">' +
        'Other Events <span class="tab-count">(' + otherCount + ')</span>' +
      '</button>';

    Array.from(container.querySelectorAll(".tab-btn")).forEach(function (btn) {
      btn.addEventListener("click", function () {
        activeTab = btn.dataset.tab;
        ensureValidCompanyFilter();
        ensureValidSelection();
        renderTabs();
        renderCompanyFilter();
        renderList();
        renderDetail();
      });
    });
  }

  function renderCompanyFilter() {
    const select = document.getElementById("companyFilter");
    const options = getCompanyOptions();

    select.innerHTML =
      '<option value="__all__">All Companies</option>' +
      options.map(function (companyId) {
        const selected = companyId === activeCompanyFilter ? ' selected' : '';
        return '<option value="' + escapeHtmlClient(companyId) + '"' + selected + '>' +
          escapeHtmlClient(companyId) +
        '</option>';
      }).join("");

    if (
      activeCompanyFilter !== "__all__" &&
      !options.some(function (value) { return value === activeCompanyFilter; })
    ) {
      activeCompanyFilter = "__all__";
      select.value = "__all__";
    } else {
      select.value = activeCompanyFilter;
    }
  }

  function renderList() {
    const container = document.getElementById("eventList");
    const filteredEvents = getFilteredEvents();

    if (!filteredEvents.length) {
      container.innerHTML = '<div class="event-list-empty">No events in this view yet.</div>';
      return;
    }

    container.innerHTML = filteredEvents.map(function (e) {
      const isSelected = e.id === selectedEventId;

      return (
        '<div class="event-row' + (isSelected ? ' selected' : '') + '" data-id="' + escapeHtmlClient(e.id) + '">' +
          '<div class="event-row-main">' +
            '<div class="event-title">' + escapeHtmlClient(e.note) + '</div>' +
            '<div class="event-time">' + escapeHtmlClient(e.when) + ' - id: ' + escapeHtmlClient(e.id) + '</div>' +
          '</div>' +
          (e.hasSnsDot ? '<div class="event-dot" title="Amazon SNS"></div>' : '') +
        '</div>'
      );
    }).join("");

    Array.from(container.querySelectorAll(".event-row")).forEach(function (row) {
      row.addEventListener("click", function () {
        selectEvent(row.dataset.id);
      });
    });
  }

  function renderDetail() {
    const container = document.getElementById("detailWrap");
    const filteredEvents = getFilteredEvents();

    if (!filteredEvents.length) {
      container.innerHTML = '<div class="detail-empty">No events in this view yet.</div>';
      return;
    }

    let selectedEvent = null;

    if (selectedEventId) {
      selectedEvent = filteredEvents.find(function (e) {
        return e.id === selectedEventId;
      });
    }

    if (!selectedEvent) {
      selectedEvent = filteredEvents[0];
      selectedEventId = selectedEvent.id;
    }

    container.innerHTML =
      '<div class="detail-content">' +
        '<div class="detail-title">' + escapeHtmlClient(selectedEvent.note) + '</div>' +
        '<div class="detail-subtitle">' + escapeHtmlClient(selectedEvent.when) + ' - id: ' + escapeHtmlClient(selectedEvent.id) + '</div>' +

        '<div class="detail-grid">' +
          '<div class="stat">' +
            '<div class="stat-label">Company ID</div>' +
            '<div class="stat-value">' + escapeHtmlClient(selectedEvent.companyId || "-") + '</div>' +
          '</div>' +
          '<div class="stat">' +
            '<div class="stat-label">Entity Type</div>' +
            '<div class="stat-value">' + escapeHtmlClient(selectedEvent.entityType || "-") + '</div>' +
          '</div>' +
          '<div class="stat">' +
            '<div class="stat-label">Event Type</div>' +
            '<div class="stat-value">' + escapeHtmlClient(selectedEvent.eventType || "-") + '</div>' +
          '</div>' +
          '<div class="stat">' +
            '<div class="stat-label">Signature Verified</div>' +
            '<div class="stat-value">' +
              (selectedEvent.verified === true ? "yes" : selectedEvent.verified === false ? "no" : "unknown") +
            '</div>' +
          '</div>' +
          '<div class="stat">' +
            '<div class="stat-label">User Agent</div>' +
            '<div class="stat-value">' + escapeHtmlClient((selectedEvent.headers && selectedEvent.headers["user-agent"]) || "-") + '</div>' +
          '</div>' +
          '<div class="stat">' +
            '<div class="stat-label">Source</div>' +
            '<div class="stat-value">' + (selectedEvent.hasSnsDot ? "Amazon SNS" : "Other") + '</div>' +
          '</div>' +
        '</div>' +

        '<h3>Headers</h3>' +
        '<pre>' + escapeHtmlClient(pretty(selectedEvent.headers)) + '</pre>' +

        '<h3>Body</h3>' +
        '<pre>' + escapeHtmlClient(pretty(selectedEvent.body)) + '</pre>' +
      '</div>';
  }

  function selectEvent(id) {
    selectedEventId = id;
    renderList();
    renderDetail();
  }

  async function refreshEvents() {
    try {
      const res = await fetch("/events", { cache: "no-store" });
      if (!res.ok) return;

      events = await res.json();
      ensureValidCompanyFilter();
      ensureValidSelection();
      renderTabs();
      renderCompanyFilter();
      renderList();
      renderDetail();
    } catch (err) {
      // Keep current UI state on refresh failures
    }
  }

  document.getElementById("refreshBtn").addEventListener("click", refreshEvents);
  document.getElementById("companyFilter").addEventListener("change", function (event) {
    activeCompanyFilter = event.target.value;
    ensureValidSelection();
    renderList();
    renderDetail();
  });

  ensureValidCompanyFilter();
  ensureValidSelection();
  renderTabs();
  renderCompanyFilter();
  renderList();
  renderDetail();
  setInterval(refreshEvents, 5000);
</script>
</body>
</html>`);
});

// =================== start ===================
app.listen(PORT, () => {
  console.log("SNS listener running on http://0.0.0.0:" + PORT);
});
