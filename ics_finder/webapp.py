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


_MODBUS_EXCEPTION_LABELS = {
    1: "Illegal Function",
    2: "Illegal Data Address",
    3: "Illegal Data Value",
    4: "Server Device Failure",
    5: "Acknowledge",
    6: "Server Device Busy",
    8: "Memory Parity Error",
    10: "Gateway Path Unavailable",
    11: "Gateway Target Failed",
}


def _parse_limit(parsed_query: dict[str, list[str]], default: int = 200, maximum: int = 1000) -> int:
    """Parse and validate a positive integer limit from query parameters."""
    raw_limit = parsed_query.get("limit", [str(default)])[0]
    try:
        limit = int(raw_limit)
    except ValueError as exc:
        raise ValueError("limit must be a valid integer") from exc
    if limit < 1:
        raise ValueError("limit must be a positive integer")
    return min(limit, maximum)


def _parse_device_info(device_info: Optional[str]) -> dict[str, str]:
    """Convert semicolon-separated device info into dashboard-friendly fields."""
    parsed = {
        "vendor": "Unknown",
        "product": "Unknown",
        "model": "Unknown",
        "revision": "Unknown",
    }
    if not device_info:
        return parsed

    for item in device_info.split(";"):
        key, separator, value = item.partition("=")
        if not separator:
            continue
        key = key.strip()
        value = value.strip() or "Unknown"
        if key == "0":
            parsed["vendor"] = value
        elif key == "1":
            parsed["product"] = value
        elif key == "2":
            parsed["revision"] = value
        elif key == "3":
            parsed["model"] = value
    if parsed["model"] == "Unknown" and parsed["product"] != "Unknown":
        parsed["model"] = parsed["product"]
    return parsed


def _build_dashboard_payload(database_path: str, limit: int = 200) -> dict[str, object]:
    """Build a dashboard-oriented JSON payload from the SQLite result store."""
    rows = load_results_sqlite(database_path, limit=limit)
    stats = summarize_results_sqlite(database_path)
    devices = []

    for row in rows:
        device_fields = _parse_device_info(row.get("device_info"))
        devices.append(
            {
                "id": str(row["id"]),
                "ip": row["ip"],
                "port": row["port"],
                "protocol": row["protocol"],
                "verification_level": row["verification_level"],
                "vendor": device_fields["vendor"],
                "product": device_fields["product"],
                "model": device_fields["model"],
                "revision": device_fields["revision"],
                "country": "Unknown",
                "lat": None,
                "lng": None,
                "tcpLatency": row["tcp_latency_ms"] or 0,
                "totalLatency": row["total_latency_ms"] or 0,
                "modbus_exception": _MODBUS_EXCEPTION_LABELS.get(row["modbus_exception_code"]),
                "registers": [],
                "coils": [],
                "unitId": 0,
                "timestamp": int(float(row["timestamp"]) * 1000),
            }
        )

    return {
        "devices": devices,
        "stats": {
            "scannedAddresses": stats["total_results"],
            "pps": 0,
            "progress": 100.0,
            "total": stats["total_results"],
            "unreachable": stats["unreachable_results"],
            "tcpOnly": stats["tcp_only_results"],
            "verified": stats["verified_results"],
            "identified": stats["identified_results"],
        },
        "summary": stats,
    }


def _protocol_badge_class(protocol: str) -> str:
    return {
        "Modbus/TCP": "badge badge-modbus",
        "S7comm": "badge badge-s7",
        "EtherNet/IP": "badge badge-enip",
        "BACnet": "badge badge-bacnet",
        "DNP3": "badge badge-dnp3",
    }.get(protocol, "badge")


def _render_dashboard_html(database_path: str) -> str:
    """Render a small dashboard page backed by the SQLite result store."""
    payload = _build_dashboard_payload(database_path, limit=100)
    stats = payload["stats"]
    summary = payload["summary"]
    rows = payload["devices"]
    protocol_markup = "".join(
        (
            "<li class='protocol-item'>"
            f"<span>{html.escape(item['protocol'])}</span>"
            f"<strong>{item['count']}</strong>"
            "</li>"
        )
        for item in summary["protocols"]
    )
    table_rows = "".join(
        """
        <tr>
          <td>{level_badge}</td>
          <td>{ip}</td>
          <td>{port}</td>
          <td><span class="{protocol_class}">{protocol}</span></td>
          <td>{vendor}</td>
          <td>{level}</td>
          <td>{latency}</td>
        </tr>
        """.format(
            ip=html.escape(str(row["ip"])),
            port=row["port"],
            protocol=html.escape(str(row["protocol"])),
            protocol_class=html.escape(_protocol_badge_class(str(row["protocol"]))),
            vendor=html.escape(str(row["vendor"] or "Unknown")),
            level_badge=html.escape(f"L{int(row['verification_level'])}"),
            level=html.escape(str(row["verification_level"])),
            latency=html.escape(
                "—" if row["totalLatency"] is None else f'{float(row["totalLatency"]):.3f} ms'
            ),
        )
        for row in rows
    )
    return f"""<!doctype html>
<html lang="en">
<head>
  <meta charset="utf-8">
  <meta name="viewport" content="width=device-width, initial-scale=1">
  <title>SCADA Scanner Dashboard</title>
  <style>
    :root {{ color-scheme: dark; }}
    * {{ box-sizing:border-box; }}
    body {{ background:#0a0a0a; color:#f3f4f6; font-family:Inter,Arial,sans-serif; margin:0; }}
    code, .mono {{ font-family:"JetBrains Mono","SFMono-Regular",Consolas,monospace; }}
    a {{ color:#22d3ee; }}
    .header {{ position:sticky; top:0; z-index:10; display:flex; justify-content:space-between; align-items:center; gap:16px; padding:18px 24px; border-bottom:1px solid rgba(255,255,255,0.08); background:#0a0a0a; }}
    .brand {{ display:flex; align-items:center; gap:12px; font-family:"JetBrains Mono","SFMono-Regular",Consolas,monospace; }}
    .brand-dot {{ width:10px; height:10px; border-radius:999px; background:#06b6d4; box-shadow:0 0 12px rgba(6,182,212,0.9); }}
    .brand-title {{ font-size:22px; font-weight:700; letter-spacing:0.08em; }}
    .brand-title span {{ color:#06b6d4; }}
    .tabs {{ display:flex; gap:6px; padding:4px; border:1px solid rgba(255,255,255,0.08); background:rgba(255,255,255,0.04); border-radius:12px; }}
    .tab-button {{ border:0; background:transparent; color:#9ca3af; padding:10px 14px; border-radius:10px; cursor:pointer; font:600 12px/1.2 "JetBrains Mono","SFMono-Regular",Consolas,monospace; letter-spacing:0.06em; }}
    .tab-button.active {{ background:rgba(255,255,255,0.09); color:#22d3ee; }}
    .wrap {{ max-width:1440px; margin:0 auto; padding:24px; }}
    .panel {{ background:#111111; border:1px solid rgba(255,255,255,0.08); border-radius:18px; }}
    .section {{ display:none; }}
    .section.active {{ display:block; }}
    .progress-panel {{ padding:20px; margin-bottom:20px; }}
    .section-title {{ display:flex; align-items:center; justify-content:space-between; gap:12px; margin-bottom:14px; }}
    .section-title h2, .section-title h3 {{ margin:0; font:600 13px/1.4 "JetBrains Mono","SFMono-Regular",Consolas,monospace; letter-spacing:0.08em; text-transform:uppercase; color:#9ca3af; }}
    .progress-bar {{ height:10px; border-radius:999px; background:rgba(255,255,255,0.05); overflow:hidden; }}
    .progress-bar > span {{ display:block; height:100%; width:{float(stats["progress"]):.2f}%; background:linear-gradient(90deg, rgba(6,182,212,0.65), rgba(34,211,238,0.95)); box-shadow:0 0 16px rgba(34,211,238,0.45); }}
    .progress-meta {{ display:grid; grid-template-columns:repeat(auto-fit, minmax(180px, 1fr)); gap:12px; margin-top:14px; }}
    .meta-label {{ color:#6b7280; font-size:11px; text-transform:uppercase; letter-spacing:0.08em; }}
    .meta-value {{ color:#e5e7eb; font-size:24px; margin-top:4px; }}
    .cards {{ display:grid; gap:16px; grid-template-columns:repeat(auto-fit, minmax(190px, 1fr)); margin-bottom:20px; }}
    .card {{ padding:18px; position:relative; overflow:hidden; }}
    .card small {{ display:block; margin-bottom:10px; color:#6b7280; font:600 11px/1.4 "JetBrains Mono","SFMono-Regular",Consolas,monospace; text-transform:uppercase; letter-spacing:0.08em; }}
    .card strong {{ font-size:34px; font-weight:600; }}
    .card-subtle {{ color:#9ca3af; font-size:13px; margin-top:8px; }}
    .layout {{ display:grid; gap:20px; grid-template-columns:minmax(0, 2fr) minmax(280px, 1fr); }}
    .table-wrap {{ overflow:auto; }}
    table {{ width:100%; border-collapse:collapse; }}
    th, td {{ border-bottom:1px solid rgba(255,255,255,0.06); text-align:left; padding:14px 16px; font-size:14px; vertical-align:top; }}
    th {{ color:#9ca3af; font:600 11px/1.4 "JetBrains Mono","SFMono-Regular",Consolas,monospace; text-transform:uppercase; letter-spacing:0.08em; background:rgba(255,255,255,0.03); }}
    td {{ color:#e5e7eb; }}
    .level-pill {{ display:inline-flex; min-width:34px; justify-content:center; padding:4px 8px; border-radius:999px; border:1px solid rgba(34,211,238,0.22); background:rgba(34,211,238,0.12); color:#67e8f9; font:600 11px/1 "JetBrains Mono","SFMono-Regular",Consolas,monospace; }}
    .badge {{ display:inline-flex; padding:4px 8px; border-radius:999px; border:1px solid rgba(255,255,255,0.12); background:rgba(255,255,255,0.04); }}
    .badge-modbus {{ color:#22d3ee; border-color:rgba(34,211,238,0.25); background:rgba(34,211,238,0.12); }}
    .badge-s7 {{ color:#c084fc; border-color:rgba(192,132,252,0.25); background:rgba(192,132,252,0.12); }}
    .badge-enip {{ color:#f472b6; border-color:rgba(244,114,182,0.25); background:rgba(244,114,182,0.12); }}
    .badge-bacnet {{ color:#4ade80; border-color:rgba(74,222,128,0.25); background:rgba(74,222,128,0.12); }}
    .badge-dnp3 {{ color:#fb923c; border-color:rgba(251,146,60,0.25); background:rgba(251,146,60,0.12); }}
    .protocol-list, .api-list {{ list-style:none; margin:0; padding:0; }}
    .protocol-item, .api-item {{ display:flex; align-items:center; justify-content:space-between; gap:16px; padding:12px 0; border-bottom:1px solid rgba(255,255,255,0.06); }}
    .protocol-item:last-child, .api-item:last-child {{ border-bottom:0; }}
    .api-item code {{ display:block; margin-bottom:4px; }}
    .muted {{ color:#9ca3af; }}
    @media (max-width: 900px) {{
      .header {{ flex-direction:column; align-items:flex-start; }}
      .layout {{ grid-template-columns:1fr; }}
      .wrap {{ padding:16px; }}
      .tabs {{ width:100%; overflow:auto; }}
    }}
  </style>
</head>
<body>
  <header class="header">
    <div class="brand">
      <span class="brand-dot"></span>
      <div class="brand-title">SCADA_SCANNER<span>_</span></div>
    </div>
    <nav class="tabs" aria-label="Dashboard sections">
      <button class="tab-button active" data-tab="overview" aria-label="Overview section">GENEL BAKIŞ</button>
      <button class="tab-button" data-tab="devices" aria-label="Devices section">CİHAZLAR</button>
      <button class="tab-button" data-tab="api" aria-label="API section">API</button>
    </nav>
  </header>
  <div class="wrap">
    <section id="overview" class="section active">
      <div class="panel progress-panel">
        <div class="section-title">
          <h2>Tarama İlerlemesi</h2>
          <div class="mono" style="color:#22d3ee;">{float(stats["progress"]):.2f}%</div>
        </div>
        <div class="progress-bar"><span></span></div>
        <div class="progress-meta">
          <div><div class="meta-label mono">Taranan Adres</div><div class="meta-value mono">{int(stats["scannedAddresses"])}</div></div>
          <div><div class="meta-label mono">Açık Servis</div><div class="meta-value mono">{int(summary["open_results"])}</div></div>
          <div><div class="meta-label mono">PPS</div><div class="meta-value mono">{int(stats["pps"])}</div></div>
        </div>
      </div>
      <div class="cards">
        <div class="panel card"><small>Toplam Bulunan</small><strong class="mono">{int(stats["total"])}</strong><div class="card-subtle">SQLite sonuç deposundaki tüm kayıtlar</div></div>
        <div class="panel card"><small>Erişilemez</small><strong class="mono">{int(stats["unreachable"])}</strong><div class="card-subtle">Bağlantı kurulamadı</div></div>
        <div class="panel card"><small>TCP Only</small><strong class="mono">{int(stats["tcpOnly"])}</strong><div class="card-subtle">Taşıma katmanı açık</div></div>
        <div class="panel card"><small>Protokol Onaylı</small><strong class="mono">{int(stats["verified"])}</strong><div class="card-subtle">Protokol cevabı doğrulandı</div></div>
        <div class="panel card"><small>Cihaz Tanımlı</small><strong class="mono">{int(stats["identified"])}</strong><div class="card-subtle">Kimlik bilgisi döndüren uçlar</div></div>
      </div>
      <div class="layout">
        <div class="panel table-wrap">
          <div class="section-title" style="padding:18px 18px 0;">
            <h3>Son Bulgular</h3>
            <div class="muted mono">SQLite source: {html.escape(os.path.abspath(database_path))}</div>
          </div>
          <table>
            <thead>
              <tr>
                <th>Lvl</th>
                <th>IP Adresi</th>
                <th>Port</th>
                <th>Protokol</th>
                <th>Vendor</th>
                <th>Seviye</th>
                <th>Gecikme</th>
              </tr>
            </thead>
            <tbody>{table_rows or "<tr><td colspan='7'>No results yet.</td></tr>"}</tbody>
          </table>
        </div>
        <div class="panel" style="padding:18px;">
          <div class="section-title"><h3>Protokol Dağılımı</h3></div>
          <ul class="protocol-list">{protocol_markup or "<li class='protocol-item'><span>No data</span><strong>0</strong></li>"}</ul>
        </div>
      </div>
    </section>
    <section id="devices" class="section">
      <div class="panel table-wrap">
        <div class="section-title" style="padding:18px 18px 0;">
          <h3>Cihazlar</h3>
          <div class="muted mono">En yeni 100 sonuç</div>
        </div>
        <table>
          <thead>
            <tr>
              <th>Lvl</th>
              <th>IP Adresi</th>
              <th>Port</th>
              <th>Protokol</th>
              <th>Vendor</th>
              <th>Ürün</th>
              <th>Revision</th>
              <th>Total Latency</th>
            </tr>
          </thead>
          <tbody>
            {"".join(
                """
                <tr>
                  <td><span class="level-pill">{level}</span></td>
                  <td>{ip}</td>
                  <td>{port}</td>
                  <td><span class="{protocol_class}">{protocol}</span></td>
                  <td>{vendor}</td>
                  <td>{product}</td>
                  <td>{revision}</td>
                  <td>{latency}</td>
                </tr>
                """.format(
                    level=html.escape(f"L{int(row['verification_level'])}"),
                    ip=html.escape(str(row["ip"])),
                    port=row["port"],
                    protocol_class=html.escape(_protocol_badge_class(str(row["protocol"]))),
                    protocol=html.escape(str(row["protocol"])),
                    vendor=html.escape(str(row["vendor"])),
                    product=html.escape(str(row["product"])),
                    revision=html.escape(str(row["revision"])),
                    latency=html.escape(
                        "—" if row["totalLatency"] is None else f'{float(row["totalLatency"]):.3f} ms'
                    ),
                )
                for row in rows
            ) or "<tr><td colspan='8'>No results yet.</td></tr>"}
          </tbody>
        </table>
      </div>
    </section>
    <section id="api" class="section">
      <div class="layout">
        <div class="panel" style="padding:20px;">
          <div class="section-title"><h3>JSON Uç Noktaları</h3></div>
          <ul class="api-list">
            <li class="api-item"><div><code>/api/stats</code><div class="muted">Toplam kayıt, açık servis, doğrulanan sonuç ve protokol dağılımı.</div></div></li>
            <li class="api-item"><div><code>/api/results?limit=200&amp;protocol=Modbus/TCP</code><div class="muted">Ham sonuç satırları; limit üst sınırı 1000.</div></div></li>
            <li class="api-item"><div><code>/api/dashboard?limit=200</code><div class="muted">Dashboard uyumlu cihaz ve özet verileri.</div></div></li>
          </ul>
        </div>
        <div class="panel" style="padding:20px;">
          <div class="section-title"><h3>Dashboard Uyumluluğu</h3></div>
          <p class="muted">Bu görünüm, <code>ics_finder_dashboard</code> reposundaki siyah/cyan SCADA panel stilini taklit eder ve aynı anda saklanan SQLite sonuçlarını doğrudan JSON olarak sunar.</p>
          <p class="muted">Gerçek zamanlı olmayan alanlar için güvenli varsayılanlar kullanılır: <code>pps=0</code>, <code>progress=100</code>, <code>country=Unknown</code>.</p>
        </div>
      </div>
    </section>
  </div>
  <script>
    const buttons = document.querySelectorAll('[data-tab]');
    const sections = document.querySelectorAll('.section');
    buttons.forEach((button) => {{
      button.addEventListener('click', () => {{
        const tab = button.getAttribute('data-tab');
        buttons.forEach((entry) => entry.classList.toggle('active', entry === button));
        sections.forEach((section) => section.classList.toggle('active', section.id === tab));
      }});
    }});
  </script>
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
            try:
                if parsed.path == "/api/results":
                    params = parse_qs(parsed.query)
                    limit = _parse_limit(params)
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

                if parsed.path == "/api/dashboard":
                    params = parse_qs(parsed.query)
                    limit = _parse_limit(params)
                    body = json.dumps(
                        _build_dashboard_payload(database_path, limit=limit),
                        indent=2,
                    ).encode("utf-8")
                    self.send_response(200)
                    self.send_header("Content-Type", "application/json; charset=utf-8")
                    self.send_header("Content-Length", str(len(body)))
                    self.end_headers()
                    self.wfile.write(body)
                    return
            except ValueError as exc:
                body = json.dumps({"error": str(exc)}).encode("utf-8")
                self.send_response(400)
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
