"""Minimal built-in dashboard for browsing SQLite scan results."""

from __future__ import annotations

import argparse
import html
import json
import os
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from typing import Optional
from urllib.parse import parse_qs, urlparse

from .scanner import load_results_sqlite, summarize_results_sqlite


def _render_dashboard_html(database_path: str) -> str:
    """Render a small dashboard page backed by the SQLite result store."""
    stats = summarize_results_sqlite(database_path)
    rows = load_results_sqlite(database_path, limit=100)
    protocol_markup = "".join(
        f"<li><strong>{html.escape(item['protocol'])}</strong>: {item['count']}</li>"
        for item in stats["protocols"]
    )
    table_rows = "".join(
        """
        <tr>
          <td>{ip}</td>
          <td>{port}</td>
          <td>{protocol}</td>
          <td>{level}</td>
          <td>{identity}</td>
          <td>{latency}</td>
        </tr>
        """.format(
            ip=html.escape(str(row["ip"])),
            port=row["port"],
            protocol=html.escape(str(row["protocol"])),
            level=html.escape(str(row["validation_level"])),
            identity=html.escape(str(row["device_info"] or "—")),
            latency=html.escape(
                "—" if row["total_latency_ms"] is None else f'{row["total_latency_ms"]:.3f} ms'
            ),
        )
        for row in rows
    )
    return f"""<!doctype html>
<html lang="en">
<head>
  <meta charset="utf-8">
  <meta name="viewport" content="width=device-width, initial-scale=1">
  <title>ICS Finder Dashboard</title>
  <style>
    body {{ background:#0b1220; color:#e5eef9; font-family:Arial,sans-serif; margin:0; }}
    .wrap {{ max-width:1200px; margin:0 auto; padding:24px; }}
    .cards {{ display:grid; gap:16px; grid-template-columns:repeat(auto-fit, minmax(180px, 1fr)); }}
    .card {{ background:#162033; border:1px solid #24324b; border-radius:12px; padding:16px; }}
    h1,h2 {{ margin:0 0 12px; }}
    table {{ width:100%; border-collapse:collapse; margin-top:18px; }}
    th, td {{ border-bottom:1px solid #24324b; text-align:left; padding:10px; font-size:14px; }}
    code {{ color:#7dd3fc; }}
    a {{ color:#7dd3fc; }}
  </style>
</head>
<body>
  <div class="wrap">
    <h1>ICS Finder Dashboard</h1>
    <p>SQLite source: <code>{html.escape(os.path.abspath(database_path))}</code></p>
    <div class="cards">
      <div class="card"><h2>Total results</h2><div>{stats["total_results"]}</div></div>
      <div class="card"><h2>Open services</h2><div>{stats["open_results"]}</div></div>
      <div class="card"><h2>Protocol verified</h2><div>{stats["verified_results"]}</div></div>
      <div class="card">
        <h2>Protocols</h2>
        <ul>{protocol_markup or "<li>No data</li>"}</ul>
      </div>
    </div>

    <h2 style="margin-top:28px;">Latest findings</h2>
    <p>JSON endpoints: <a href="/api/stats">/api/stats</a> and <a href="/api/results">/api/results</a></p>
    <table>
      <thead>
        <tr>
          <th>IP</th>
          <th>Port</th>
          <th>Protocol</th>
          <th>Validation</th>
          <th>Identity</th>
          <th>Total latency</th>
        </tr>
      </thead>
      <tbody>{table_rows or "<tr><td colspan='6'>No results yet.</td></tr>"}</tbody>
    </table>
  </div>
</body>
</html>"""


def build_dashboard_server(
    database_path: str,
    host: str = "127.0.0.1",
    port: int = 8000,
) -> ThreadingHTTPServer:
    """Create a dashboard HTTP server bound to *database_path*."""

    class DashboardHandler(BaseHTTPRequestHandler):
        def do_GET(self) -> None:  # noqa: N802
            parsed = urlparse(self.path)
            if parsed.path == "/api/results":
                params = parse_qs(parsed.query)
                limit = int(params.get("limit", ["200"])[0])
                protocol: Optional[str] = params.get("protocol", [None])[0]
                body = json.dumps(
                    load_results_sqlite(database_path, limit=limit, protocol=protocol),
                    indent=2,
                ).encode("utf-8")
                self.send_response(200)
                self.send_header("Content-Type", "application/json; charset=utf-8")
                self.send_header("Content-Length", str(len(body)))
                self.end_headers()
                self.wfile.write(body)
                return

            if parsed.path == "/api/stats":
                body = json.dumps(
                    summarize_results_sqlite(database_path), indent=2
                ).encode("utf-8")
                self.send_response(200)
                self.send_header("Content-Type", "application/json; charset=utf-8")
                self.send_header("Content-Length", str(len(body)))
                self.end_headers()
                self.wfile.write(body)
                return

            if parsed.path == "/":
                body = _render_dashboard_html(database_path).encode("utf-8")
                self.send_response(200)
                self.send_header("Content-Type", "text/html; charset=utf-8")
                self.send_header("Content-Length", str(len(body)))
                self.end_headers()
                self.wfile.write(body)
                return

            self.send_error(404, "Not Found")

        def log_message(self, format: str, *args: object) -> None:
            return

    return ThreadingHTTPServer((host, port), DashboardHandler)


def serve_dashboard(database_path: str, host: str = "127.0.0.1", port: int = 8000) -> None:
    """Serve the dashboard until interrupted."""
    server = build_dashboard_server(database_path, host=host, port=port)
    try:
        server.serve_forever()
    finally:
        server.server_close()


def main(argv: list[str] | None = None) -> None:
    """CLI entry point for serving the dashboard standalone."""
    parser = argparse.ArgumentParser(description="Serve the ICS Finder dashboard.")
    parser.add_argument("database", help="SQLite database produced by ics_finder.")
    parser.add_argument("--host", default="127.0.0.1")
    parser.add_argument("--port", type=int, default=8000)
    args = parser.parse_args(argv)
    serve_dashboard(args.database, host=args.host, port=args.port)


if __name__ == "__main__":
    main()
