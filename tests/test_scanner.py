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
    BACNET_PORT,
    DNP3_PORT,
    ETHERNET_IP_PORT,
    PROTOCOL_BACNET,
    PROTOCOL_DNP3,
    PROTOCOL_ETHERNET_IP,
    PROTOCOL_MODBUS,
    PROTOCOL_S7COMM,
    S7COMM_PORT,
    ScanResult,
    _build_bacnet_who_is_request,
    _build_dnp3_link_status_request,
    _build_enip_list_identity_request,
    scan_networks,
    summarize_results_sqlite,
    load_results_sqlite,
    write_results_csv,
    write_results_json,
    write_results_sqlite,
    MODBUS_PORT,
    _MODBUS_READ_COILS,
    _build_modbus_request,
    _build_read_holding_registers_request,
    _build_device_id_request,
    _build_s7_cotp_connect_request,
    _parse_bacnet_response,
    _parse_dnp3_response,
    _parse_enip_identity_response,
    _parse_modbus_response,
    _parse_device_id_response,
    _parse_s7_cotp_response,
    _parse_masscan_list_output,
    _MODBUS_EXCEPTION_MASK,
    VALIDATION_NO_ACCESS,
    VALIDATION_TCP_ONLY,
    VALIDATION_MODBUS_EXCEPTION,
    VALIDATION_MODBUS_CONFIRMED,
    VALIDATION_MODBUS_DEVICE_ID,
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
    """Start a TCP server that responds with a valid Modbus response.

    The server handles multiple sequential requests on the same connection
    so that the multi-level verification logic can send FC 01, FC 03, and
    FC 43 probes in sequence.
    """
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
                    conn.settimeout(2)
                    try:
                        while True:
                            data = conn.recv(12)
                            if not data:
                                break
                            response = _build_modbus_response()
                            conn.sendall(response)
                    except socket.timeout:
                        pass
                    finally:
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


def _start_s7_stub_server() -> tuple[socket.socket, int]:
    srv = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    srv.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    srv.bind(("127.0.0.1", 0))
    srv.listen(5)
    port = srv.getsockname()[1]

    response = bytes.fromhex("0300001611d0000100c0010ac1020100c2020102")

    def _handle():
        srv.settimeout(5)
        try:
            while True:
                try:
                    conn, _ = srv.accept()
                    conn.recv(256)
                    conn.sendall(response)
                    conn.close()
                except socket.timeout:
                    break
        except OSError:
            pass

    threading.Thread(target=_handle, daemon=True).start()
    return srv, port


def _build_enip_identity_response(product_name: str = "Test PLC") -> bytes:
    item = (
        struct.pack("<H", 1)
        + (b"\x00" * 16)
        + struct.pack("<H", 1337)
        + struct.pack("<H", 12)
        + struct.pack("<H", 34)
        + bytes([1, 2])
        + struct.pack("<H", 0)
        + struct.pack("<I", 123456)
        + bytes([len(product_name)])
        + product_name.encode("ascii")
        + b"\x01"
    )
    payload = (
        struct.pack("<I", 0)
        + struct.pack("<H", 0)
        + struct.pack("<H", 1)
        + struct.pack("<HH", 0x000C, len(item))
        + item
    )
    header = struct.pack("<HHIIQI", 0x0063, len(payload), 0, 0, 0, 0)
    return header + payload


def _start_enip_stub_server() -> tuple[socket.socket, int]:
    srv = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    srv.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    srv.bind(("127.0.0.1", 0))
    srv.listen(5)
    port = srv.getsockname()[1]
    response = _build_enip_identity_response()

    def _handle():
        srv.settimeout(5)
        try:
            while True:
                try:
                    conn, _ = srv.accept()
                    conn.recv(256)
                    conn.sendall(response)
                    conn.close()
                except socket.timeout:
                    break
        except OSError:
            pass

    threading.Thread(target=_handle, daemon=True).start()
    return srv, port


def _start_dnp3_stub_server() -> tuple[socket.socket, int]:
    srv = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    srv.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    srv.bind(("127.0.0.1", 0))
    srv.listen(5)
    port = srv.getsockname()[1]
    response = bytes.fromhex("0564050b010000000000")

    def _handle():
        srv.settimeout(5)
        try:
            while True:
                try:
                    conn, _ = srv.accept()
                    conn.recv(256)
                    conn.sendall(response)
                    conn.close()
                except socket.timeout:
                    break
        except OSError:
            pass

    threading.Thread(target=_handle, daemon=True).start()
    return srv, port


def _start_bacnet_udp_server() -> tuple[socket.socket, int]:
    srv = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    srv.bind(("127.0.0.1", 0))
    port = srv.getsockname()[1]
    response = bytes.fromhex("810a000801201000")

    def _handle():
        srv.settimeout(5)
        try:
            data, addr = srv.recvfrom(512)
            if data:
                srv.sendto(response, addr)
        except (socket.timeout, OSError):
            pass

    threading.Thread(target=_handle, daemon=True).start()
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
        assert set(d.keys()) == {
            "ip", "port", "open", "modbus_verified", "banner",
            "protocol", "protocol_verified", "verification_level", "transport",
            "tcp_latency_ms", "total_latency_ms", "raw_response", "timestamp",
            "error", "validation_level", "modbus_exception_code", "device_info",
        }

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

    def test_s7_protocol_verification(self):
        srv, port = _start_s7_stub_server()
        try:
            results = scan_networks(
                [parse_network("127.0.0.1/32")],
                port=port,
                concurrency=1,
                timeout=2.0,
                verify_modbus=True,
                hits_only=True,
                protocol=PROTOCOL_S7COMM,
            )
        finally:
            srv.close()

        assert len(results) == 1
        assert results[0].protocol == "S7comm"
        assert results[0].protocol_verified is True
        assert results[0].verification_level == 2

    def test_enip_protocol_verification_with_identity(self):
        srv, port = _start_enip_stub_server()
        try:
            results = scan_networks(
                [parse_network("127.0.0.1/32")],
                port=port,
                concurrency=1,
                timeout=2.0,
                verify_modbus=True,
                hits_only=True,
                protocol=PROTOCOL_ETHERNET_IP,
            )
        finally:
            srv.close()

        assert len(results) == 1
        assert results[0].protocol == "EtherNet/IP"
        assert results[0].protocol_verified is True
        assert "product_name=Test PLC" in results[0].device_info
        assert results[0].verification_level == 3

    def test_dnp3_protocol_verification(self):
        srv, port = _start_dnp3_stub_server()
        try:
            results = scan_networks(
                [parse_network("127.0.0.1/32")],
                port=port,
                concurrency=1,
                timeout=2.0,
                verify_modbus=True,
                hits_only=True,
                protocol=PROTOCOL_DNP3,
            )
        finally:
            srv.close()

        assert len(results) == 1
        assert results[0].protocol == "DNP3"
        assert results[0].protocol_verified is True
        assert results[0].verification_level == 2

    def test_bacnet_udp_verification(self):
        srv, port = _start_bacnet_udp_server()
        try:
            results = scan_networks(
                [parse_network("127.0.0.1/32")],
                port=port,
                concurrency=1,
                timeout=2.0,
                verify_modbus=True,
                hits_only=True,
                protocol=PROTOCOL_BACNET,
            )
        finally:
            srv.close()

        assert len(results) == 1
        assert results[0].protocol == "BACnet/IP"
        assert results[0].protocol_verified is True
        assert results[0].transport == "udp"


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

    def test_write_sqlite(self):
        results = self._make_results()
        with tempfile.NamedTemporaryFile(suffix=".db", delete=False) as fh:
            path = fh.name
        try:
            written = write_results_sqlite(results, path)
            assert written == 2
            loaded = load_results_sqlite(path, limit=10)
            assert len(loaded) == 2
            stats = summarize_results_sqlite(path)
            assert stats["total_results"] == 2
            assert stats["open_results"] == 1
            assert stats["unreachable_results"] == 2
            assert stats["tcp_only_results"] == 0
            assert stats["identified_results"] == 0
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


class TestAdditionalProtocolParsers:
    def test_s7_builder_and_parser(self):
        req = _build_s7_cotp_connect_request()
        assert req.startswith(b"\x03\x00")
        assert _parse_s7_cotp_response(bytes.fromhex("0300001611d0000100c0010ac1020100c2020102"))

    def test_enip_builder_and_parser(self):
        req = _build_enip_list_identity_request()
        assert len(req) == 24
        is_valid, identity = _parse_enip_identity_response(_build_enip_identity_response())
        assert is_valid is True
        assert "product_name=Test PLC" in identity

    def test_dnp3_builder_and_parser(self):
        req = _build_dnp3_link_status_request()
        assert req.startswith(b"\x05\x64")
        assert _parse_dnp3_response(bytes.fromhex("0564050b010000000000")) is True

    def test_bacnet_builder_and_parser(self):
        req = _build_bacnet_who_is_request()
        assert req.startswith(b"\x81\x0a")
        assert _parse_bacnet_response(bytes.fromhex("810a000801201000")) is True


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


# ─────────────────────────────────────────────────────────────
# Modbus exception response stub server
# ─────────────────────────────────────────────────────────────


def _build_modbus_exception_response(
    fc: int = 0x01, exception_code: int = 0x02
) -> bytes:
    """Build a Modbus TCP exception response.

    An exception response has the original function code OR'd with 0x80,
    followed by the exception code.
    """
    return struct.pack(
        ">HHHBBB",
        0x0001,       # Transaction ID
        0x0000,       # Protocol ID (Modbus)
        0x0003,       # Length (unit + fc + exc_code = 3)
        0x01,         # Unit ID
        fc | 0x80,    # Function code with exception flag
        exception_code,
    )


def _start_modbus_exception_server(
    exception_code: int = 0x02,
) -> tuple[socket.socket, int]:
    """Start a TCP server that always returns a Modbus exception response."""
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
                    conn.settimeout(2)
                    try:
                        while True:
                            data = conn.recv(12)
                            if not data:
                                break
                            # Parse the incoming FC and echo back an exception
                            # for that FC.
                            incoming_fc = data[7] if len(data) > 7 else 0x01
                            resp = _build_modbus_exception_response(
                                incoming_fc, exception_code
                            )
                            conn.sendall(resp)
                    except socket.timeout:
                        pass
                    finally:
                        conn.close()
                except socket.timeout:
                    break
        except OSError:
            pass

    t = threading.Thread(target=_handle, daemon=True)
    t.start()
    return srv, port


# ─────────────────────────────────────────────────────────────
# Tests for _parse_modbus_response
# ─────────────────────────────────────────────────────────────


class TestParseModbusResponse:
    def test_valid_normal_response(self):
        """A normal Read Coils response should parse correctly."""
        raw = _build_modbus_response()
        is_modbus, is_exc, exc_code, fc = _parse_modbus_response(raw)
        assert is_modbus is True
        assert is_exc is False
        assert exc_code is None
        assert fc == 0x01

    def test_exception_response(self):
        """An exception response should set is_exception and exception_code."""
        raw = _build_modbus_exception_response(0x01, 0x02)
        is_modbus, is_exc, exc_code, fc = _parse_modbus_response(raw)
        assert is_modbus is True
        assert is_exc is True
        assert exc_code == 0x02
        assert fc == 0x01  # original FC (high bit stripped)

    def test_non_modbus_protocol_id(self):
        """A frame with non-zero protocol ID should not be Modbus."""
        raw = struct.pack(">HHHBBBB", 0x0001, 0x0001, 4, 0x01, 0x01, 0x01, 0x00)
        is_modbus, is_exc, exc_code, fc = _parse_modbus_response(raw)
        assert is_modbus is False

    def test_too_short(self):
        """A frame shorter than 8 bytes should not parse."""
        raw = b"\x00\x01\x00\x00\x00"
        is_modbus, is_exc, exc_code, fc = _parse_modbus_response(raw)
        assert is_modbus is False

    def test_illegal_function_exception(self):
        """Illegal Function (0x01) exception should be detected."""
        raw = _build_modbus_exception_response(0x03, 0x01)
        is_modbus, is_exc, exc_code, fc = _parse_modbus_response(raw)
        assert is_modbus is True
        assert is_exc is True
        assert exc_code == 0x01
        assert fc == 0x03


# ─────────────────────────────────────────────────────────────
# Tests for enhanced Modbus request builders
# ─────────────────────────────────────────────────────────────


class TestReadHoldingRegistersRequest:
    def test_valid_frame(self):
        """FC 03 request should be a well-formed 12-byte Modbus frame."""
        req = _build_read_holding_registers_request()
        assert len(req) == 12
        tx_id, proto_id, length, unit, fc, start, qty = struct.unpack(
            ">HHHBBHH", req
        )
        assert proto_id == 0x0000
        assert length == 0x0006
        assert fc == 0x03

    def test_custom_unit_id(self):
        """FC 03 request should honour a custom unit ID."""
        req = _build_read_holding_registers_request(unit_id=0x05)
        unit = req[6]
        assert unit == 0x05


class TestDeviceIdRequest:
    def test_valid_frame(self):
        """FC 43 / MEI 14 request should be 11 bytes."""
        req = _build_device_id_request()
        assert len(req) == 11
        # FC should be 0x2B (43)
        assert req[7] == 0x2B
        # MEI Type should be 0x0E (14)
        assert req[8] == 0x0E


# ─────────────────────────────────────────────────────────────
# Tests for _parse_device_id_response
# ─────────────────────────────────────────────────────────────


class TestParseDeviceIdResponse:
    def _build_device_id_response(self) -> bytes:
        """Build a minimal Read Device Identification response."""
        vendor = b"TestVendor"
        product = b"TestProduct"
        # Objects: 0=VendorName, 1=ProductCode
        objects = (
            bytes([0x00, len(vendor)]) + vendor
            + bytes([0x01, len(product)]) + product
        )
        # PDU: unit(1) + FC(1) + MEI(1) + ReadDevId(1) + ConformityLevel(1)
        #      + MoreFollows(1) + NextObjId(1) + NumObjects(1) + objects
        pdu = struct.pack("BBBBBBBB", 0x01, 0x2B, 0x0E, 0x01, 0x01, 0x00, 0x00, 0x02) + objects
        length = len(pdu)
        mbap = struct.pack(">HHH", 0x0001, 0x0000, length)
        return mbap + pdu

    def test_parses_vendor_and_product(self):
        raw = self._build_device_id_response()
        info = _parse_device_id_response(raw)
        assert info is not None
        assert "0=TestVendor" in info
        assert "1=TestProduct" in info

    def test_returns_none_for_non_device_id(self):
        """A normal Modbus response should not parse as device ID."""
        raw = _build_modbus_response()
        info = _parse_device_id_response(raw)
        assert info is None

    def test_returns_none_for_short_data(self):
        info = _parse_device_id_response(b"\x00" * 5)
        assert info is None


# ─────────────────────────────────────────────────────────────
# Tests for Modbus exception integration
# ─────────────────────────────────────────────────────────────


class TestModbusExceptionDetection:
    def test_exception_response_marks_verified(self):
        """A Modbus exception response should still mark the device verified."""
        srv, port = _start_modbus_exception_server(exception_code=0x01)
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
        assert results[0].validation_level == VALIDATION_MODBUS_EXCEPTION
        assert results[0].modbus_exception_code == 0x01

    def test_illegal_data_address_exception(self):
        """Illegal Data Address (0x02) should be detected."""
        srv, port = _start_modbus_exception_server(exception_code=0x02)
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
        assert results[0].modbus_verified is True
        assert results[0].modbus_exception_code == 0x02


# ─────────────────────────────────────────────────────────────
# Tests for validation levels
# ─────────────────────────────────────────────────────────────


class TestValidationLevel:
    def test_closed_port_has_no_access(self):
        """A closed port should have validation_level='no_access'."""
        results = scan_networks(
            [parse_network("127.0.0.1/32")],
            port=19876,
            concurrency=1,
            timeout=0.5,
            verify_modbus=True,
            hits_only=False,
        )
        assert len(results) == 1
        assert results[0].validation_level == VALIDATION_NO_ACCESS

    def test_open_port_without_verify_has_tcp_only(self):
        """An open port without Modbus verification should be 'tcp_only'."""
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
        assert results[0].validation_level == VALIDATION_TCP_ONLY

    def test_modbus_confirmed_level(self):
        """A valid Modbus response should give 'modbus_confirmed'."""
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
        assert results[0].validation_level in (
            VALIDATION_MODBUS_CONFIRMED,
            VALIDATION_MODBUS_DEVICE_ID,
        )


# ─────────────────────────────────────────────────────────────
# Tests for masscan output parsing
# ─────────────────────────────────────────────────────────────


class TestParseMasscanOutput:
    def test_parse_list_format(self):
        """Correctly parse masscan -oL output."""
        content = (
            "# masscan\n"
            "open tcp 502 192.168.1.1 1711115200\n"
            "open tcp 502 10.0.0.5 1711115201\n"
            "# end\n"
        )
        with tempfile.NamedTemporaryFile(
            mode="w", suffix=".list", delete=False
        ) as fh:
            fh.write(content)
            path = fh.name
        try:
            ips = _parse_masscan_list_output(path)
            assert ips == ["192.168.1.1", "10.0.0.5"]
        finally:
            os.unlink(path)

    def test_empty_output(self):
        """An empty file should return no IPs."""
        with tempfile.NamedTemporaryFile(
            mode="w", suffix=".list", delete=False
        ) as fh:
            fh.write("# masscan\n# end\n")
            path = fh.name
        try:
            ips = _parse_masscan_list_output(path)
            assert ips == []
        finally:
            os.unlink(path)

    def test_ignores_non_open_lines(self):
        """Lines not starting with 'open' should be ignored."""
        content = (
            "# comment\n"
            "closed tcp 502 10.0.0.1 1711115200\n"
            "open tcp 502 10.0.0.2 1711115201\n"
        )
        with tempfile.NamedTemporaryFile(
            mode="w", suffix=".list", delete=False
        ) as fh:
            fh.write(content)
            path = fh.name
        try:
            ips = _parse_masscan_list_output(path)
            assert ips == ["10.0.0.2"]
        finally:
            os.unlink(path)
