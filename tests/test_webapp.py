"""Tests for the built-in dashboard web application."""

from __future__ import annotations

import json
import os
import tempfile
import threading
import urllib.request

from ics_finder.scanner import ScanResult, write_results_sqlite
from ics_finder.webapp import build_dashboard_server


def test_dashboard_endpoints():
    with tempfile.NamedTemporaryFile(suffix=".db", delete=False) as fh:
        path = fh.name

    server = None
    thread = None
    try:
        write_results_sqlite(
            [
                ScanResult(
                    ip="127.0.0.1",
                    port=502,
                    open=True,
                    modbus_verified=True,
                    protocol="Modbus/TCP",
                    protocol_verified=True,
                    verification_level=3,
                    banner=None,
                    device_info="0=TestVendor",
                )
            ],
            path,
        )
        server = build_dashboard_server(path, host="127.0.0.1", port=0)
        host, port = server.server_address
        thread = threading.Thread(target=server.serve_forever, daemon=True)
        thread.start()

        stats = json.load(urllib.request.urlopen(f"http://{host}:{port}/api/stats"))
        assert stats["total_results"] == 1

        results = json.load(urllib.request.urlopen(f"http://{host}:{port}/api/results"))
        assert results[0]["protocol"] == "Modbus/TCP"

        html = urllib.request.urlopen(f"http://{host}:{port}/").read().decode("utf-8")
        assert "ICS Finder Dashboard" in html
        assert "127.0.0.1" in html
    finally:
        if server is not None:
            server.shutdown()
            server.server_close()
        if thread is not None:
            thread.join(timeout=2)
        os.unlink(path)
