#!/usr/bin/env node
/**
 * Aodı-AetherOS — telemetry relay (Node, zero npm dependencies).
 * POST /emit {tag, level, message} → real Telegram notifications
 * GET /last · GET /health
 * Env: TELEGRAM_TOKEN, TELEGRAM_CHAT, PORT (default 7462)
 */
const http = require("http");
const https = require("https");
const PORT = process.env.PORT || 7462;
const TOKEN = process.env.TELEGRAM_TOKEN || "";
const CHAT = process.env.TELEGRAM_CHAT || "";
const buf = [];

function sendTelegram(text) {
  if (!TOKEN || !CHAT) return Promise.resolve({ skipped: true });
  return new Promise((resolve) => {
    const q = `/bot${TOKEN}/sendMessage?chat_id=${encodeURIComponent(CHAT)}&text=${encodeURIComponent(text)}`;
    const r = https.request({ hostname: "api.telegram.org", path: q, method: "POST" },
      (res) => { res.resume(); resolve({ status: res.statusCode }); });
    r.on("error", (e) => resolve({ error: String(e) }));
    r.end();
  });
}

http.createServer((req, res) => {
  const p = req.url.split("?")[0];
  if (p === "/emit" && req.method === "POST") {
    let b = "";
    req.on("data", (c) => (b += c));
    req.on("end", async () => {
      try {
        const ev = JSON.parse(b || "{}");
        const e = { ts: new Date().toISOString(),
          tag: ev.tag || "", level: ev.level || "info",
          message: (ev.message || "").slice(0, 280) };
        buf.unshift(e);
        if (buf.length > 40) buf.pop();
        const tg = await sendTelegram(`[${e.level.toUpperCase()}] AetherOS#${e.tag}\n${e.message}`);
        res.writeHead(200, { "Content-Type": "application/json" });
        res.end(JSON.stringify({ ok: true,
          telegram: tg.skipped ? "skipped" : (tg.status ?? "sent") }));
      } catch (e) {
        res.writeHead(400, { "Content-Type": "application/json" });
        res.end(JSON.stringify({ ok: false, error: String(e) }));
      }
    });
  } else if (p === "/last") {
    res.writeHead(200, { "Content-Type": "application/json" });
    res.end(JSON.stringify({ events: buf }));
  } else if (p === "/health") {
    res.writeHead(200, { "Content-Type": "application/json" });
    res.end(JSON.stringify({ service: "aetheros.relay", version: "1.0.0",
      telegram_configured: !!(TOKEN && CHAT), buffered: buf.length }));
  } else {
    res.writeHead(404, { "Content-Type": "application/json" });
    res.end(JSON.stringify({ error: "no route" }));
  }
}).listen(PORT, () => console.log(`aetheros.relay listening :${PORT}  telegram=${TOKEN ? "on" : "off"}`));
