"""Tests for ics_finder.scanner."""

import asyncio
import ipaddress
import json
import os
import socket
import struct
import tempfile
import threading
import time

import pytest

from ics_finder.ip_utils import parse_network
from ics_finder.scanner import (
    ScanResult,
    scan_networks,
    write_results_csv,
    write_results_json,
    MODBUS_PORT,
    _MODBUS_READ_COILS,
    _build_modbus_request,
)


# ─────────────────────────────────────────────────────────────
# Minimal TCP echo / Modbus stub servers for integration tests
# ─────────────────────────────────────────────────────────────


def _start_echo_server() -> tuple[socket.socket, int]:
    """Start a TCP server that accepts one connection and immediately closes it."""
    srv = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    srv.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    srv.bind(("127.0.0.1", 0))
    srv.listen(5)
    port = srv.getsockname()[1]

    def _accept_loop():
        srv.settimeout(5)
        try:
            while True:
                try:
                    conn, _ = srv.accept()
                    conn.close()
                except socket.timeout:
                    break
        except OSError:
            pass

    t = threading.Thread(target=_accept_loop, daemon=True)
    t.start()
    return srv, port


def _build_modbus_response(transaction_id: int = 0x0001) -> bytes:
    """Build a minimal valid Modbus TCP Read Coils response."""
    import struct
    # MBAP: transaction_id, protocol_id=0, length=4
    # PDU: unit_id=1, fc=1, byte_count=1, data=0
    return struct.pack(">HHHBBBB", transaction_id, 0x0000, 4, 0x01, 0x01, 0x01, 0x00)


def _start_modbus_stub_server() -> tuple[socket.socket, int]:
    """Start a TCP server that responds with a valid Modbus response."""
    srv = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    srv.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    srv.bind(("127.0.0.1", 0))
    srv.listen(5)
    port = srv.getsockname()[1]

    response = _build_modbus_response()

    def _handle():
        srv.settimeout(5)
        try:
            while True:
                try:
                    conn, _ = srv.accept()
                    conn.recv(12)   # consume the request
                    conn.sendall(response)
                    conn.close()
                except socket.timeout:
                    break
        except OSError:
            pass

    t = threading.Thread(target=_handle, daemon=True)
    t.start()
    return srv, port


def _start_banner_server(banner: bytes = b"HELLO_BANNER") -> tuple[socket.socket, int]:
    """Start a TCP server that sends a banner immediately on connection."""
    srv = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    srv.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    srv.bind(("127.0.0.1", 0))
    srv.listen(5)
    port = srv.getsockname()[1]

    def _handle():
        srv.settimeout(5)
        try:
            while True:
                try:
                    conn, _ = srv.accept()
                    conn.sendall(banner)
                    conn.close()
                except socket.timeout:
                    break
        except OSError:
            pass

    t = threading.Thread(target=_handle, daemon=True)
    t.start()
    return srv, port


# ─────────────────────────────────────────────────────────────
# Unit tests for ScanResult
# ─────────────────────────────────────────────────────────────


class TestScanResult:
    def test_as_dict_keys(self):
        r = ScanResult(
            ip="10.0.0.1",
            port=502,
            open=True,
            modbus_verified=False,
            banner=None,
        )
        d = r.as_dict()
        assert set(d.keys()) == {"ip", "port", "open", "modbus_verified", "banner", "timestamp", "error"}

    def test_defaults(self):
        r = ScanResult(ip="1.2.3.4", port=502, open=False, modbus_verified=False, banner=None)
        assert r.error is None
        assert r.timestamp > 0


# ─────────────────────────────────────────────────────────────
# Integration tests using local stub servers
# ─────────────────────────────────────────────────────────────


class TestScanNetworks:
    def test_open_port_detected(self):
        """A listening port on localhost should be found as open."""
        srv, port = _start_echo_server()
        try:
            results = scan_networks(
                [parse_network("127.0.0.1/32")],
                port=port,
                concurrency=1,
                timeout=2.0,
                verify_modbus=False,
                hits_only=True,
            )
        finally:
            srv.close()

        assert len(results) == 1
        assert results[0].open is True
        assert results[0].ip == "127.0.0.1"

    def test_closed_port_not_in_hits(self):
        """A port with nothing listening should not appear in hits_only results."""
        # Use a port that's very unlikely to be open (high ephemeral range).
        results = scan_networks(
            [parse_network("127.0.0.1/32")],
            port=19876,
            concurrency=1,
            timeout=0.5,
            verify_modbus=False,
            hits_only=True,
        )
        open_results = [r for r in results if r.open]
        assert open_results == []

    def test_modbus_verification_pass(self):
        """A stub Modbus server should be verified successfully."""
        srv, port = _start_modbus_stub_server()
        try:
            results = scan_networks(
                [parse_network("127.0.0.1/32")],
                port=port,
                concurrency=1,
                timeout=2.0,
                verify_modbus=True,
                hits_only=True,
            )
        finally:
            srv.close()

        assert len(results) == 1
        assert results[0].open is True
        assert results[0].modbus_verified is True

    def test_all_results_includes_closed(self):
        """With hits_only=False, closed ports should also be included."""
        results = scan_networks(
            [parse_network("127.0.0.1/32")],
            port=19876,
            concurrency=1,
            timeout=0.5,
            verify_modbus=False,
            hits_only=False,
        )
        assert len(results) == 1
        assert results[0].open is False


# ─────────────────────────────────────────────────────────────
# Result serialisation tests
# ─────────────────────────────────────────────────────────────


class TestWriteResults:
    def _make_results(self):
        return [
            ScanResult(ip="10.0.0.1", port=502, open=True, modbus_verified=True, banner="deadbeef"),
            ScanResult(ip="10.0.0.2", port=502, open=False, modbus_verified=False, banner=None, error="timeout"),
        ]

    def test_write_csv(self):
        results = self._make_results()
        with tempfile.NamedTemporaryFile(suffix=".csv", delete=False) as fh:
            path = fh.name
        try:
            written = write_results_csv(results, path)
            assert written == 2
            with open(path) as f:
                content = f.read()
            assert "10.0.0.1" in content
            assert "10.0.0.2" in content
            assert "modbus_verified" in content  # header row
        finally:
            os.unlink(path)

    def test_write_json(self):
        results = self._make_results()
        with tempfile.NamedTemporaryFile(suffix=".json", delete=False) as fh:
            path = fh.name
        try:
            written = write_results_json(results, path)
            assert written == 2
            with open(path) as f:
                data = json.load(f)
            assert len(data) == 2
            ips = {r["ip"] for r in data}
            assert ips == {"10.0.0.1", "10.0.0.2"}
        finally:
            os.unlink(path)


# ─────────────────────────────────────────────────────────────
# Tests for new features: banner grabbing, WAF bypass, jitter
# ─────────────────────────────────────────────────────────────


class TestBuildModbusRequest:
    def test_valid_modbus_frame(self):
        """Generated request must be a well-formed Modbus Read Coils frame."""
        req = _build_modbus_request()
        assert len(req) == 12
        tx_id, proto_id, length, unit, fc, start, qty = struct.unpack(">HHHBBHH", req)
        assert proto_id == 0x0000
        assert length == 0x0006
        assert unit == 0x01
        assert fc == 0x01

    def test_randomised_transaction_id(self):
        """Multiple calls should produce different transaction IDs."""
        tx_ids = set()
        for _ in range(50):
            req = _build_modbus_request()
            tx_id = struct.unpack(">H", req[:2])[0]
            tx_ids.add(tx_id)
        # With 50 attempts and a 16-bit range, duplicates are extremely unlikely.
        assert len(tx_ids) > 1


class TestBannerGrab:
    def test_banner_grab_captures_data(self):
        """With banner_grab=True the scanner should capture unsolicited data."""
        banner_bytes = b"HELLO_BANNER"
        srv, port = _start_banner_server(banner_bytes)
        try:
            results = scan_networks(
                [parse_network("127.0.0.1/32")],
                port=port,
                concurrency=1,
                timeout=2.0,
                verify_modbus=False,
                hits_only=True,
                banner_grab=True,
            )
        finally:
            srv.close()

        assert len(results) == 1
        assert results[0].open is True
        assert results[0].banner == banner_bytes.hex()

    def test_no_banner_grab_returns_none(self):
        """Without banner_grab the banner field should remain None."""
        srv, port = _start_banner_server(b"DATA")
        try:
            results = scan_networks(
                [parse_network("127.0.0.1/32")],
                port=port,
                concurrency=1,
                timeout=2.0,
                verify_modbus=False,
                hits_only=True,
                banner_grab=False,
            )
        finally:
            srv.close()

        assert len(results) == 1
        assert results[0].banner is None


class TestRandomizeHosts:
    def test_randomize_does_not_lose_hosts(self):
        """Randomise must still scan all hosts in the target range."""
        srv, port = _start_echo_server()
        try:
            results = scan_networks(
                [parse_network("127.0.0.1/32")],
                port=port,
                concurrency=1,
                timeout=2.0,
                verify_modbus=False,
                hits_only=True,
                randomize_hosts=True,
            )
        finally:
            srv.close()

        assert len(results) == 1
        assert results[0].open is True


class TestJitter:
    def test_jitter_does_not_break_scan(self):
        """A small jitter value should not prevent the scan from completing."""
        srv, port = _start_echo_server()
        try:
            results = scan_networks(
                [parse_network("127.0.0.1/32")],
                port=port,
                concurrency=1,
                timeout=2.0,
                verify_modbus=False,
                hits_only=True,
                jitter=0.01,
            )
        finally:
            srv.close()

        assert len(results) == 1
        assert results[0].open is True
