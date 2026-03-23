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

        dashboard = json.load(
            urllib.request.urlopen(f"http://{host}:{port}/api/dashboard?limit=1")
        )
        assert dashboard["stats"]["identified"] == 1
        assert dashboard["devices"][0]["vendor"] == "TestVendor"
        assert dashboard["devices"][0]["product"] == "Unknown"

        html = urllib.request.urlopen(f"http://{host}:{port}/").read().decode("utf-8")
        assert "SCADA_SCANNER" in html
        assert "127.0.0.1" in html
        assert "GENEL BAKIŞ" in html
    finally:
        if server is not None:
            server.shutdown()
            server.server_close()
        if thread is not None:
            thread.join(timeout=2)
        os.unlink(path)


def test_dashboard_rejects_invalid_limit():
    with tempfile.NamedTemporaryFile(suffix=".db", delete=False) as fh:
        path = fh.name

    server = None
    thread = None
    try:
        write_results_sqlite([], path)
        server = build_dashboard_server(path, host="127.0.0.1", port=0)
        host, port = server.server_address
        thread = threading.Thread(target=server.serve_forever, daemon=True)
        thread.start()

        try:
            urllib.request.urlopen(f"http://{host}:{port}/api/results?limit=0")
        except urllib.error.HTTPError as exc:
            assert exc.code == 400
            payload = json.load(exc)
            assert "positive integer" in payload["error"]
        else:
            raise AssertionError("expected HTTP 400 for invalid limit")
    finally:
        if server is not None:
            server.shutdown()
            server.server_close()
        if thread is not None:
            thread.join(timeout=2)
        os.unlink(path)
