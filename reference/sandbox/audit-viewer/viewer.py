"""Simple audit trail viewer — serves an HTML page showing DSSP audit events."""

import json
import os
from http.server import HTTPServer, BaseHTTPRequestHandler
import urllib.request

GATEWAY_URL = os.environ.get("GATEWAY_URL", "http://localhost:8080")
PORT = int(os.environ.get("AUDIT_VIEWER_PORT", "8082"))

HTML_TEMPLATE = """<!DOCTYPE html>
<html>
<head>
    <title>DSSP Audit Trail Viewer</title>
    <style>
        body {{ font-family: monospace; background: #1a1a2e; color: #e0e0e0; padding: 20px; }}
        h1 {{ color: #00d4ff; }}
        .event {{ background: #16213e; border-left: 3px solid #0f3460; padding: 10px; margin: 8px 0; border-radius: 4px; }}
        .event-type {{ color: #00d4ff; font-weight: bold; }}
        .success {{ border-left-color: #00c853; }}
        .failure {{ border-left-color: #ff1744; }}
        .seq {{ color: #888; }}
        .timestamp {{ color: #666; font-size: 0.9em; }}
        .hash {{ color: #ffd600; font-size: 0.8em; word-break: break-all; }}
        .chain {{ margin: 20px 0; padding: 10px; background: #0f3460; border-radius: 4px; }}
        .refresh {{ background: #00d4ff; color: #1a1a2e; border: none; padding: 8px 16px; cursor: pointer; border-radius: 4px; font-family: monospace; }}
        .refresh:hover {{ background: #00b8d4; }}
    </style>
</head>
<body>
    <h1>DSSP Audit Trail Viewer</h1>
    <button class="refresh" onclick="location.reload()">Refresh</button>
    <div class="chain">
        <strong>Merkle Chain Status:</strong> {chain_status}
    </div>
    <div id="events">{events_html}</div>
    <script>setTimeout(() => location.reload(), 5000);</script>
</body>
</html>"""

EVENT_TEMPLATE = """<div class="event {status_class}">
    <span class="seq">#{seq}</span>
    <span class="event-type">{event_type}</span>
    <span class="timestamp">{timestamp}</span>
    <br>
    <span>Actor: {actor} | Outcome: {outcome}</span>
    <br>
    <span class="hash">Hash: {event_hash}</span>
    {chain_link}
</div>"""


class Handler(BaseHTTPRequestHandler):
    def do_GET(self):
        if self.path == "/health":
            self.send_response(200)
            self.send_header("Content-Type", "text/plain")
            self.end_headers()
            self.wfile.write(b"ok")
            return

        try:
            req = urllib.request.Request(f"{GATEWAY_URL}/v0.1/audit/events")
            with urllib.request.urlopen(req, timeout=5) as resp:
                data = json.loads(resp.read())
        except Exception as e:
            data = {"events": [], "error": str(e)}

        events = data.get("events", data) if isinstance(data, dict) else data
        if not isinstance(events, list):
            events = []

        events_html = ""
        chain_valid = True
        prev_hash = None

        for ev in events:
            status = ev.get("outcome", {}).get("status", "unknown")
            status_class = "success" if status == "success" else "failure" if status in ("failure", "denied") else ""

            actor_info = ev.get("actor", {})
            actor_str = f"{actor_info.get('type', '?')}"
            if "org_id" in actor_info:
                actor_str += f" ({actor_info['org_id']})"

            eh = ev.get("event_hash", {})
            hash_str = f"{eh.get('algorithm', '?')}:{eh.get('value', '?')[:16]}..." if isinstance(eh, dict) else str(eh)[:20]

            peh = ev.get("previous_event_hash")
            chain_link = ""
            if peh:
                peh_val = peh.get("value", "") if isinstance(peh, dict) else ""
                if prev_hash and peh_val != prev_hash:
                    chain_valid = False
                    chain_link = '<br><span style="color:#ff1744">CHAIN BREAK DETECTED</span>'
                else:
                    chain_link = '<br><span style="color:#00c853">Chain link valid</span>'

            if isinstance(eh, dict):
                prev_hash = eh.get("value", "")

            events_html += EVENT_TEMPLATE.format(
                seq=ev.get("sequence_number", "?"),
                event_type=ev.get("event_type", "?"),
                timestamp=ev.get("timestamp", "?"),
                actor=actor_str,
                outcome=status,
                event_hash=hash_str,
                status_class=status_class,
                chain_link=chain_link,
            )

        chain_status = '<span style="color:#00c853">VALID</span>' if chain_valid else '<span style="color:#ff1744">BROKEN</span>'
        if not events:
            chain_status = '<span style="color:#888">No events yet</span>'

        html = HTML_TEMPLATE.format(events_html=events_html or "<p>No audit events yet.</p>", chain_status=chain_status)

        self.send_response(200)
        self.send_header("Content-Type", "text/html")
        self.end_headers()
        self.wfile.write(html.encode())

    def log_message(self, format, *args):
        pass  # Suppress default logging


if __name__ == "__main__":
    server = HTTPServer(("0.0.0.0", PORT), Handler)
    print(f"Audit viewer running on http://0.0.0.0:{PORT}")
    server.serve_forever()
