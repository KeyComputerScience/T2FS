#!/usr/bin/env python3
"""White-background Times New Roman UI for the reproducible T2FS-TLS demo."""

from __future__ import annotations

import argparse
import json
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from urllib.parse import parse_qs, urlparse

from t2fs_tls_reproducible_demo import perform_handshake


PAGE = """<!doctype html>
<html lang="en">
<head>
  <meta charset="utf-8">
  <meta name="viewport" content="width=device-width, initial-scale=1">
  <title>T2FS-TLS Reproducible Methodology</title>
  <style>
    :root {
      color-scheme: light;
      background: #ffffff;
      color: #000000;
      font-family: "Times New Roman", Times, serif;
    }
    body {
      margin: 0;
      background: #ffffff;
      color: #000000;
      font-family: "Times New Roman", Times, serif;
    }
    main {
      max-width: 1200px;
      margin: 0 auto;
      padding: 28px 22px 44px;
    }
    h1 {
      margin: 0 0 8px;
      font-size: 30px;
      line-height: 1.15;
    }
    p {
      margin: 8px 0 14px;
      font-size: 17px;
      line-height: 1.45;
    }
    .controls {
      display: flex;
      gap: 12px;
      flex-wrap: wrap;
      align-items: center;
      padding: 14px 0 20px;
      border-bottom: 1px solid #000000;
    }
    label {
      font-size: 16px;
    }
    select,
    input {
      padding: 6px 8px;
      border: 1px solid #000000;
      border-radius: 0;
      background: #ffffff;
      color: #000000;
      font-family: "Times New Roman", Times, serif;
      font-size: 16px;
    }
    input[type="number"] {
      width: 70px;
    }
    button {
      padding: 7px 14px;
      border: 1px solid #000000;
      border-radius: 0;
      background: #000000;
      color: #ffffff;
      font-family: "Times New Roman", Times, serif;
      font-size: 16px;
      cursor: pointer;
    }
    button:disabled {
      opacity: 0.55;
      cursor: wait;
    }
    .grid {
      display: grid;
      grid-template-columns: repeat(4, minmax(0, 1fr));
      gap: 12px;
      margin-top: 20px;
    }
    .card {
      border: 1px solid #000000;
      padding: 12px;
      min-height: 76px;
    }
    .label {
      font-size: 13px;
      text-transform: uppercase;
      letter-spacing: 0.03em;
      margin-bottom: 7px;
    }
    .value {
      font-size: 17px;
      overflow-wrap: anywhere;
    }
    table {
      width: 100%;
      border-collapse: collapse;
      margin-top: 20px;
      font-size: 15px;
    }
    th,
    td {
      border: 1px solid #000000;
      padding: 7px 9px;
      text-align: left;
      vertical-align: top;
    }
    th {
      background: #f2f2f2;
    }
    pre {
      margin-top: 20px;
      padding: 12px;
      border: 1px solid #000000;
      background: #ffffff;
      color: #000000;
      overflow: auto;
      font-size: 13px;
      line-height: 1.35;
    }
    .note {
      border: 1px solid #000000;
      padding: 10px 12px;
      margin-top: 18px;
      font-size: 16px;
    }
    @media (max-width: 900px) {
      .grid { grid-template-columns: repeat(2, minmax(0, 1fr)); }
    }
    @media (max-width: 560px) {
      .grid { grid-template-columns: 1fr; }
    }
  </style>
</head>
<body>
<main>
  <h1>T2FS-TLS Reproducible Methodology</h1>
  <p>
    This interface runs the reproducible methodology path:
    KEM-free MLWE reconciliation, HelpRec/Rec, transcript-bound HKDF,
    T2FS epoch scheduling, Finished verification, and deterministic IoT byte evidence.
  </p>

  <div class="controls">
    <label for="profile">Profile</label>
    <select id="profile">
      <option value="512">T2FS-MLWE-512-IoT</option>
      <option value="768">T2FS-MLWE-768-IoT</option>
    </select>
    <label for="rotations">Epochs</label>
    <input id="rotations" type="number" min="0" max="8" value="2">
    <label><input id="fail" type="checkbox"> induce failure</label>
    <button id="run">Run</button>
    <span id="status">Ready.</span>
  </div>

  <section id="cards" class="grid"></section>
  <section id="tables"></section>
  <pre id="json"></pre>
</main>

<script>
const cards = document.getElementById("cards");
const tables = document.getElementById("tables");
const jsonBox = document.getElementById("json");
const statusEl = document.getElementById("status");
const button = document.getElementById("run");

function esc(x) {
  return String(x).replace(/[&<>"']/g, ch => ({
    "&": "&amp;",
    "<": "&lt;",
    ">": "&gt;",
    '"': "&quot;",
    "'": "&#39;"
  }[ch]));
}

function card(label, value) {
  return `<div class="card"><div class="label">${esc(label)}</div><div class="value">${esc(value)}</div></div>`;
}

function render(data) {
  const p = data.profile;
  const h = data.help_rec;
  const f = data.finished;
  const b = data.t2fs_benefit;
  cards.innerHTML = [
    card("Profile", p.name),
    card("KEM-free innovation", "MLWE reconciliation, no encaps/decaps"),
    card("Added extension bytes", p.added_handshake_bytes),
    card("Hint bytes", h.hint_bytes),
    card("Raw bit mismatches", h.mismatched_raw_bits),
    card("Finished accepted", f.accepted),
    card("One-try failure", "2^-" + Number(p.failure_bounds.one_try_bits).toFixed(1)),
    card("Two-try failure", "2^-" + Number(p.failure_bounds.two_try_bits).toFixed(1)),
    card("T2FS state gain", b.state_reduction_percent + "%"),
    card("Transcript hash", data.transcript_hash),
    card("Z server", h.z_server),
    card("Z client", h.z_client)
  ].join("");

  const trRows = data.tls_transcript_fields.map(row =>
    `<tr><td>${esc(row.message)}</td><td>${esc(row.bytes)}</td><td>${esc(row.fingerprint)}</td></tr>`
  ).join("");
  const updRows = b.key_updates.map(row =>
    `<tr><td>${esc(row.epoch)}</td><td>${esc(row.client_app_secret)}</td><td>${esc(row.server_app_secret)}</td><td>${esc(row.fresh_rehandshake_extension_bytes_avoided)} B</td><td>${esc(row.net_rehandshake_bytes_saved)} B</td></tr>`
  ).join("");
  const proofRows = Object.entries(data.game_proof_terms).map(([k, v]) =>
    `<tr><td>${esc(k)}</td><td>${esc(v)}</td></tr>`
  ).join("");

  tables.innerHTML = `
    <table>
      <thead><tr><th>TLS transcript field</th><th>Bytes</th><th>Fingerprint</th></tr></thead>
      <tbody>${trRows}</tbody>
    </table>
    <table>
      <thead><tr><th>Epoch</th><th>Client app secret</th><th>Server app secret</th><th>Extension bytes avoided</th><th>Net bytes saved</th></tr></thead>
      <tbody>${updRows}</tbody>
    </table>
    <table>
      <thead><tr><th>Game proof term</th><th>Bound</th></tr></thead>
      <tbody>${proofRows}</tbody>
    </table>
    <div class="note">Deterministic IoT evidence is separated from target-dependent MCU measurements to avoid fabricated latency or energy claims.</div>
  `;
  jsonBox.textContent = JSON.stringify(data, null, 2);
}

async function run() {
  button.disabled = true;
  statusEl.textContent = "Running...";
  const profile = document.getElementById("profile").value;
  const rotations = document.getElementById("rotations").value || "2";
  const fail = document.getElementById("fail").checked ? "1" : "0";
  try {
    const response = await fetch(`/api/run?profile=${encodeURIComponent(profile)}&rotations=${encodeURIComponent(rotations)}&fail=${fail}`);
    if (!response.ok) throw new Error(`HTTP ${response.status}`);
    const data = await response.json();
    render(data);
    statusEl.textContent = "Completed.";
  } catch (error) {
    statusEl.textContent = `Error: ${error.message}`;
  } finally {
    button.disabled = false;
  }
}

button.addEventListener("click", run);
run();
</script>
</body>
</html>
"""


class Handler(BaseHTTPRequestHandler):
    def _send(self, status: int, content_type: str, body: bytes) -> None:
        self.send_response(status)
        self.send_header("Content-Type", content_type)
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def do_GET(self) -> None:
        parsed = urlparse(self.path)
        if parsed.path == "/":
            self._send(200, "text/html; charset=utf-8", PAGE.encode("utf-8"))
            return
        if parsed.path == "/api/run":
            query = parse_qs(parsed.query)
            profile = query.get("profile", ["512"])[0]
            try:
                rotations = int(query.get("rotations", ["2"])[0])
            except ValueError:
                rotations = 2
            rotations = max(0, min(rotations, 8))
            fail = query.get("fail", ["0"])[0] == "1"
            try:
                result = perform_handshake(profile, rotations, induce_failure=fail)
            except ValueError as exc:
                self._send(400, "application/json; charset=utf-8", json.dumps({"error": str(exc)}).encode("utf-8"))
                return
            self._send(200, "application/json; charset=utf-8", json.dumps(result, indent=2).encode("utf-8"))
            return
        self._send(404, "text/plain; charset=utf-8", b"Not found")

    def log_message(self, fmt: str, *args: object) -> None:
        return


def main() -> None:
    parser = argparse.ArgumentParser(description="Serve the reproducible T2FS-TLS methodology UI.")
    parser.add_argument("--host", default="127.0.0.1")
    parser.add_argument("--port", type=int, default=8767)
    args = parser.parse_args()
    server = ThreadingHTTPServer((args.host, args.port), Handler)
    print(f"Serving T2FS-TLS reproducible methodology at http://{args.host}:{args.port}")
    server.serve_forever()


if __name__ == "__main__":
    main()
