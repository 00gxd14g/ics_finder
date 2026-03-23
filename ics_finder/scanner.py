"""
scanner.py — Async Modbus TCP port scanner with multi-level validation.

This module provides:
* :func:`scan_networks` — high-level entry point that scans a list of IP
  networks for Modbus TCP (port 502) listeners and optionally verifies the
  Modbus application-layer protocol before recording a hit.
* :func:`scan_networks_fast` — two-phase scan using *masscan* for fast TCP
  discovery followed by async Modbus protocol verification.
* :class:`ScanResult` — data class for individual scan results.
* :func:`write_results_csv` / :func:`write_results_json` — helpers to persist
  results to disk.

Modbus TCP protocol overview
-----------------------------
A Modbus TCP request is composed of a 7-byte MBAP header followed by a PDU:

    Bytes 0-1   Transaction Identifier  (echoed by server)
    Bytes 2-3   Protocol Identifier     (must be 0x0000 for Modbus)
    Bytes 4-5   Length                  (number of following bytes)
    Byte  6     Unit Identifier
    Byte  7     Function Code
    Bytes 8+    Function-specific data

Validation levels
-----------------
The scanner classifies each result into one of the following levels:

* ``no_access``         — TCP connection failed entirely.
* ``tcp_only``          — TCP port is open but no Modbus verification was
                          performed or the service did not speak Modbus.
* ``modbus_exception``  — The device returned a Modbus exception response
                          (e.g. Illegal Function / Illegal Data Address),
                          which proves a real Modbus endpoint is listening.
* ``modbus_confirmed``  — The device returned a normal Modbus data response.
* ``modbus_device_id``  — The device additionally answered a Read Device
                          Identification request (FC 43 / MEI 14).
"""

from __future__ import annotations

import asyncio
import csv
import dataclasses
import ipaddress
import json
import logging
import os
import random
import shutil
import socket
import sqlite3
import struct
import subprocess
import tempfile
import time
from typing import Dict, Iterable, List, Optional, Sequence, Tuple, Union

from .ip_utils import AnyAddress, AnyNetwork, chunked_hosts, count_hosts

logger = logging.getLogger(__name__)

# ─────────────────────────────────────────────────────────────
# Constants
# ─────────────────────────────────────────────────────────────

MODBUS_PORT: int = 502
S7COMM_PORT: int = 102
ETHERNET_IP_PORT: int = 44818
BACNET_PORT: int = 47808
DNP3_PORT: int = 20000

PROTOCOL_MODBUS = "modbus"
PROTOCOL_S7COMM = "s7comm"
PROTOCOL_ETHERNET_IP = "ethernet_ip"
PROTOCOL_BACNET = "bacnet"
PROTOCOL_DNP3 = "dnp3"

PROTOCOL_LABELS: Dict[str, str] = {
    PROTOCOL_MODBUS: "Modbus/TCP",
    PROTOCOL_S7COMM: "S7comm",
    PROTOCOL_ETHERNET_IP: "EtherNet/IP",
    PROTOCOL_BACNET: "BACnet/IP",
    PROTOCOL_DNP3: "DNP3",
}

PROTOCOL_DEFAULT_PORTS: Dict[str, int] = {
    PROTOCOL_MODBUS: MODBUS_PORT,
    PROTOCOL_S7COMM: S7COMM_PORT,
    PROTOCOL_ETHERNET_IP: ETHERNET_IP_PORT,
    PROTOCOL_BACNET: BACNET_PORT,
    PROTOCOL_DNP3: DNP3_PORT,
}

# Modbus "Read Coils" (FC 01) request:
#   Transaction ID  : 0x0001
#   Protocol ID     : 0x0000
#   Length          : 0x0006
#   Unit ID         : 0x01
#   Function Code   : 0x01 (Read Coils)
#   Start Address   : 0x0000
#   Quantity        : 0x0001
_MODBUS_READ_COILS: bytes = struct.pack(
    ">HHHBBHH", 0x0001, 0x0000, 0x0006, 0x01, 0x01, 0x0000, 0x0001
)

# Minimum bytes we need to validate a Modbus TCP header.
_MBAP_HEADER_LEN: int = 6

# Banner-grab timeout (seconds) — how long to wait for unsolicited data.
_BANNER_READ_TIMEOUT: float = 2.0

# Maximum time (seconds) to wait for a masscan subprocess to finish.
_MASSCAN_TIMEOUT: int = 7200

# Modbus exception responses carry FC | 0x80 as the function code.
_MODBUS_EXCEPTION_MASK: int = 0x80

# Well-known Modbus exception codes (from the Modbus Application Protocol
# Specification V1.1b3).
_MODBUS_EXCEPTION_NAMES: Dict[int, str] = {
    0x01: "Illegal Function",
    0x02: "Illegal Data Address",
    0x03: "Illegal Data Value",
    0x04: "Server Device Failure",
    0x05: "Acknowledge",
    0x06: "Server Device Busy",
}

# Validation level constants — see module docstring for semantics.
VALIDATION_NO_ACCESS: str = "no_access"
VALIDATION_TCP_ONLY: str = "tcp_only"
VALIDATION_MODBUS_EXCEPTION: str = "modbus_exception"
VALIDATION_MODBUS_CONFIRMED: str = "modbus_confirmed"
VALIDATION_MODBUS_DEVICE_ID: str = "modbus_device_id"
VALIDATION_PROTOCOL_CONFIRMED: str = "protocol_confirmed"
VALIDATION_IDENTITY_CONFIRMED: str = "identity_confirmed"


def normalize_protocol(protocol: Optional[str]) -> str:
    """Return a canonical protocol key."""
    aliases = {
        None: PROTOCOL_MODBUS,
        "": PROTOCOL_MODBUS,
        "modbus": PROTOCOL_MODBUS,
        "modbus/tcp": PROTOCOL_MODBUS,
        "s7": PROTOCOL_S7COMM,
        "s7comm": PROTOCOL_S7COMM,
        "ethernet-ip": PROTOCOL_ETHERNET_IP,
        "ethernet_ip": PROTOCOL_ETHERNET_IP,
        "enip": PROTOCOL_ETHERNET_IP,
        "bacnet": PROTOCOL_BACNET,
        "bacnet/ip": PROTOCOL_BACNET,
        "dnp3": PROTOCOL_DNP3,
    }
    key = (protocol or "").strip().lower()
    return aliases.get(key, key)


def protocol_label(protocol: Optional[str]) -> str:
    """Return the human-readable label for *protocol*."""
    key = normalize_protocol(protocol)
    return PROTOCOL_LABELS.get(key, key or PROTOCOL_LABELS[PROTOCOL_MODBUS])


def default_port_for_protocol(protocol: Optional[str]) -> int:
    """Return the default well-known port for *protocol*."""
    key = normalize_protocol(protocol)
    return PROTOCOL_DEFAULT_PORTS.get(key, MODBUS_PORT)


def infer_protocol_from_port(port: int) -> str:
    """Infer the protocol key from a well-known ICS port."""
    for protocol, default_port in PROTOCOL_DEFAULT_PORTS.items():
        if default_port == port:
            return protocol
    return PROTOCOL_MODBUS


# ─────────────────────────────────────────────────────────────
# Modbus request builders
# ─────────────────────────────────────────────────────────────


def _build_modbus_request(unit_id: int = 0x01) -> bytes:
    """Build a Modbus Read Coils (FC 01) request with a randomised TX ID.

    Randomising the transaction ID on each probe avoids deterministic
    signatures that stateful firewalls or WAFs could use to fingerprint
    the scanner.
    """
    tx_id = random.randint(0x0001, 0xFFFE)
    return struct.pack(
        ">HHHBBHH", tx_id, 0x0000, 0x0006, unit_id, 0x01, 0x0000, 0x0001
    )


def _build_read_holding_registers_request(unit_id: int = 0x01) -> bytes:
    """Build a Modbus Read Holding Registers (FC 03) request."""
    tx_id = random.randint(0x0001, 0xFFFE)
    return struct.pack(
        ">HHHBBHH", tx_id, 0x0000, 0x0006, unit_id, 0x03, 0x0000, 0x0001
    )


def _build_device_id_request(unit_id: int = 0x01) -> bytes:
    """Build a Modbus Read Device Identification request (FC 43 / MEI 14).

    This requests the *basic* device identification objects (vendor name,
    product code, major-minor revision) starting at object 0x00.
    """
    tx_id = random.randint(0x0001, 0xFFFE)
    # FC 0x2B (43), MEI Type 0x0E (14), Read Dev ID Code 0x01 (basic),
    # Object ID 0x00 (start from VendorName).
    return struct.pack(
        ">HHHBBBBB", tx_id, 0x0000, 0x0005, unit_id, 0x2B, 0x0E, 0x01, 0x00
    )


def _build_s7_cotp_connect_request() -> bytes:
    """Build a basic TPKT/COTP connection request used by S7comm."""
    return bytes.fromhex(
        "0300001611e00000000100c1020100c2020102c0010a"
    )


def _build_enip_list_identity_request() -> bytes:
    """Build an EtherNet/IP ListIdentity encapsulation request."""
    return struct.pack("<HHIIQI", 0x0063, 0, 0, 0, 0, 0)


def _dnp3_crc(data: bytes) -> int:
    """Compute the CRC used by DNP3 link-layer frames."""
    crc = 0x0000
    for byte in data:
        crc ^= byte
        for _ in range(8):
            if crc & 0x0001:
                crc = (crc >> 1) ^ 0xA6BC
            else:
                crc >>= 1
    return (~crc) & 0xFFFF


def _build_dnp3_link_status_request(destination: int = 1, source: int = 1024) -> bytes:
    """Build a DNP3 link-status request frame."""
    header = b"\x05\x64\x05\xc9" + struct.pack("<HH", destination, source)
    return header + struct.pack("<H", _dnp3_crc(header))


def _build_bacnet_who_is_request() -> bytes:
    """Build a minimal BACnet/IP Who-Is request."""
    return bytes.fromhex("810a000801201008")


# ─────────────────────────────────────────────────────────────
# Modbus response parsing
# ─────────────────────────────────────────────────────────────


def _parse_modbus_response(
    raw: bytes,
) -> Tuple[bool, bool, Optional[int], Optional[int]]:
    """Parse a Modbus TCP response frame.

    Returns
    -------
    (is_modbus, is_exception, exception_code, function_code)
        * *is_modbus*      — ``True`` when Protocol ID == 0x0000.
        * *is_exception*   — ``True`` when the function code has its high bit
                             set, indicating an exception response.
        * *exception_code* — The Modbus exception code (1–6) when
                             *is_exception* is ``True``, else ``None``.
        * *function_code*  — The original function code (high bit stripped
                             for exceptions), or ``None`` if parsing failed.
    """
    # We need at least MBAP header (6 bytes) + unit ID (1) + FC (1) = 8 bytes.
    if len(raw) < _MBAP_HEADER_LEN + 2:
        return False, False, None, None

    protocol_id = struct.unpack(">H", raw[2:4])[0]
    if protocol_id != 0x0000:
        return False, False, None, None

    fc = raw[7]
    if fc & _MODBUS_EXCEPTION_MASK:
        exc_code = raw[8] if len(raw) > 8 else None
        return True, True, exc_code, fc & 0x7F

    return True, False, None, fc


def _parse_device_id_response(raw: bytes) -> Optional[str]:
    """Extract human-readable device identification from an MEI 14 response.

    Returns a semicolon-separated string of ``object_id=value`` pairs, or
    ``None`` when the response cannot be parsed.
    """
    # Minimum: MBAP (7) + FC (1) + MEI type (1) + read dev id (1)
    #          + conformity (1) + more follows (1) + next obj (1) + num obj (1)
    #        = 14 bytes before the first object descriptor.
    if len(raw) < 14:
        return None
    if raw[7] != 0x2B or raw[8] != 0x0E:
        return None

    num_objects = raw[13]
    pos = 14
    parts: List[str] = []
    for _ in range(num_objects):
        if pos + 2 > len(raw):
            break
        obj_id = raw[pos]
        obj_len = raw[pos + 1]
        pos += 2
        if pos + obj_len > len(raw):
            break
        value = raw[pos : pos + obj_len].decode("ascii", errors="replace")
        parts.append(f"{obj_id}={value}")
        pos += obj_len

    return "; ".join(parts) if parts else None


def _parse_s7_cotp_response(raw: bytes) -> bool:
    """Return ``True`` when *raw* looks like an S7 COTP connection confirm."""
    return len(raw) >= 7 and raw[0] == 0x03 and raw[1] == 0x00 and raw[5] == 0xD0


def _parse_enip_identity_response(raw: bytes) -> Tuple[bool, Optional[str]]:
    """Parse an EtherNet/IP ListIdentity response."""
    if len(raw) < 24:
        return False, None

    command, _length = struct.unpack_from("<HH", raw, 0)
    status = struct.unpack_from("<I", raw, 8)[0]
    if command != 0x0063 or status != 0:
        return False, None

    payload = raw[24:]
    if len(payload) < 8:
        return True, None

    item_count = struct.unpack_from("<H", payload, 6)[0]
    pos = 8
    for _ in range(item_count):
        if pos + 4 > len(payload):
            break
        item_type, item_length = struct.unpack_from("<HH", payload, pos)
        pos += 4
        if pos + item_length > len(payload):
            break
        if item_type == 0x000C and item_length >= 33:
            item = payload[pos : pos + item_length]
            vendor_id = struct.unpack_from("<H", item, 18)[0]
            revision = f"{item[24]}.{item[25]}"
            product_name_len = item[32]
            product_name = ""
            if 33 + product_name_len <= len(item):
                product_name = item[33 : 33 + product_name_len].decode(
                    "ascii", errors="replace"
                )
            return True, (
                f"vendor_id={vendor_id}; product_name={product_name or 'unknown'}; "
                f"revision={revision}"
            )
        pos += item_length

    return True, None


def _parse_dnp3_response(raw: bytes) -> bool:
    """Return ``True`` when *raw* looks like a DNP3 link-layer frame."""
    return len(raw) >= 10 and raw[:2] == b"\x05\x64"


def _parse_bacnet_response(raw: bytes) -> bool:
    """Return ``True`` when *raw* looks like a BACnet/IP I-Am response."""
    return len(raw) >= 8 and raw[0] == 0x81 and raw[6] == 0x10 and raw[7] == 0x00


# ─────────────────────────────────────────────────────────────
# Data classes
# ─────────────────────────────────────────────────────────────


@dataclasses.dataclass
class ScanResult:
    """Result of a single IP probe.

    Attributes
    ----------
    validation_level:
        One of the ``VALIDATION_*`` constants indicating the deepest
        verification level reached during probing.
    modbus_exception_code:
        If the device returned a Modbus exception response, the numeric
        exception code (e.g. 1 = Illegal Function, 2 = Illegal Data
        Address).  ``None`` otherwise.
    device_info:
        Human-readable device identification string when the target
        supports Read Device Identification (FC 43 / MEI 14).
    """

    ip: str
    port: int
    open: bool
    modbus_verified: bool
    banner: Optional[str]
    protocol: str = PROTOCOL_LABELS[PROTOCOL_MODBUS]
    protocol_verified: bool = False
    verification_level: int = 0
    transport: str = "tcp"
    tcp_latency_ms: Optional[float] = None
    total_latency_ms: Optional[float] = None
    raw_response: Optional[str] = None
    timestamp: float = dataclasses.field(default_factory=time.time)
    error: Optional[str] = None
    validation_level: str = VALIDATION_NO_ACCESS
    modbus_exception_code: Optional[int] = None
    device_info: Optional[str] = None

    def as_dict(self) -> Dict:
        return dataclasses.asdict(self)


# ─────────────────────────────────────────────────────────────
# Core async scanning logic
# ─────────────────────────────────────────────────────────────


async def _probe(
    ip: str,
    port: int,
    timeout: float,
    verify_modbus: bool,
    banner_grab: bool = False,
    protocol: str = PROTOCOL_MODBUS,
) -> ScanResult:
    """
    Attempt a TCP connection to *ip*:*port*.

    If *verify_modbus* is ``True`` the probe performs multi-level Modbus
    validation:

    1. Send a Read Coils request (FC 01) with a randomised transaction ID.
    2. If the response is a valid Modbus data frame → ``modbus_confirmed``.
    3. If the response is a Modbus *exception* → ``modbus_exception``
       (this still proves a real Modbus endpoint is listening).
    4. If FC 01 yields no usable answer, retry with Read Holding Registers
       (FC 03) — some devices only support certain function codes.
    5. Optionally attempt Read Device Identification (FC 43 / MEI 14).

    If *banner_grab* is ``True`` and *verify_modbus* is ``False``, the scanner
    waits briefly for any unsolicited data from the server (service banner).
    """
    protocol_key = normalize_protocol(protocol)
    protocol_name = protocol_label(protocol_key)
    started_at = time.monotonic()

    if protocol_key == PROTOCOL_BACNET:
        return await _probe_bacnet(ip, port, timeout, verify_modbus, protocol_name)

    connect_started_at = time.monotonic()
    try:
        reader, writer = await asyncio.wait_for(
            asyncio.open_connection(ip, port),
            timeout=timeout,
        )
    except (asyncio.TimeoutError, ConnectionRefusedError, OSError) as exc:
        return ScanResult(
            ip=ip,
            port=port,
            open=False,
            modbus_verified=False,
            banner=None,
            protocol=protocol_name,
            protocol_verified=False,
            verification_level=0,
            tcp_latency_ms=round((time.monotonic() - connect_started_at) * 1000, 3),
            total_latency_ms=round((time.monotonic() - started_at) * 1000, 3),
            error=str(exc),
            validation_level=VALIDATION_NO_ACCESS,
        )

    protocol_verified = False
    modbus_verified = False
    banner: Optional[str] = None
    raw_response: Optional[str] = None
    validation_level = VALIDATION_TCP_ONLY
    verification_level = 1
    exception_code: Optional[int] = None
    device_info: Optional[str] = None
    connect_latency_ms = round((time.monotonic() - connect_started_at) * 1000, 3)

    try:
        if verify_modbus:
            if protocol_key == PROTOCOL_MODBUS:
                # ── Phase 1: try Read Coils (FC 01) ──────────────────
                is_modbus, is_exc, exc_c, _fc = await _send_and_parse(
                    reader, writer, _build_modbus_request(), timeout
                )
                if is_modbus and not is_exc:
                    protocol_verified = True
                    modbus_verified = True
                    validation_level = VALIDATION_MODBUS_CONFIRMED
                    verification_level = 2
                elif is_modbus and is_exc:
                    protocol_verified = True
                    modbus_verified = True
                    validation_level = VALIDATION_MODBUS_EXCEPTION
                    verification_level = 2
                    exception_code = exc_c

                # ── Phase 2: try Read Holding Registers (FC 03) ──────
                if not is_modbus:
                    is_modbus, is_exc, exc_c, _fc = await _send_and_parse(
                        reader, writer,
                        _build_read_holding_registers_request(),
                        timeout,
                    )
                    if is_modbus and not is_exc:
                        protocol_verified = True
                        modbus_verified = True
                        validation_level = VALIDATION_MODBUS_CONFIRMED
                        verification_level = 2
                    elif is_modbus and is_exc:
                        protocol_verified = True
                        modbus_verified = True
                        validation_level = VALIDATION_MODBUS_EXCEPTION
                        verification_level = 2
                        exception_code = exc_c

                # ── Phase 3: try Read Device Identification (FC 43) ──
                if protocol_verified:
                    try:
                        dev_req = _build_device_id_request()
                        writer.write(dev_req)
                        await asyncio.wait_for(writer.drain(), timeout=timeout)
                        dev_raw: bytes = await asyncio.wait_for(
                            reader.read(256), timeout=timeout,
                        )
                        if dev_raw:
                            raw_response = dev_raw.hex()
                        info = _parse_device_id_response(dev_raw)
                        if info:
                            device_info = info
                            validation_level = VALIDATION_MODBUS_DEVICE_ID
                            verification_level = 3
                    except (asyncio.TimeoutError, OSError):
                        pass
            else:
                protocol_verified, device_info, raw_response = await _verify_tcp_protocol(
                    reader=reader,
                    writer=writer,
                    protocol=protocol_key,
                    timeout=timeout,
                )
                if protocol_verified:
                    validation_level = (
                        VALIDATION_IDENTITY_CONFIRMED
                        if device_info
                        else VALIDATION_PROTOCOL_CONFIRMED
                    )
                    verification_level = 3 if device_info else 2

        elif banner_grab:
            try:
                raw = await asyncio.wait_for(
                    reader.read(256),
                    timeout=min(timeout, _BANNER_READ_TIMEOUT),
                )
                if raw:
                    banner = raw.hex()
                    raw_response = banner
            except asyncio.TimeoutError:
                pass
    except (asyncio.TimeoutError, OSError):
        pass
    finally:
        try:
            writer.close()
            await asyncio.wait_for(writer.wait_closed(), timeout=2.0)
        except (OSError, asyncio.TimeoutError):
            pass

    return ScanResult(
        ip=ip,
        port=port,
        open=True,
        modbus_verified=modbus_verified,
        banner=banner,
        protocol=protocol_name,
        protocol_verified=protocol_verified or modbus_verified,
        verification_level=verification_level,
        tcp_latency_ms=connect_latency_ms,
        total_latency_ms=round((time.monotonic() - started_at) * 1000, 3),
        raw_response=raw_response,
        validation_level=validation_level,
        modbus_exception_code=exception_code,
        device_info=device_info,
    )


async def _send_and_parse(
    reader: asyncio.StreamReader,
    writer: asyncio.StreamWriter,
    request: bytes,
    timeout: float,
) -> Tuple[bool, bool, Optional[int], Optional[int]]:
    """Send a Modbus request and parse the response.

    Returns the same tuple as :func:`_parse_modbus_response`.
    """
    try:
        writer.write(request)
        await asyncio.wait_for(writer.drain(), timeout=timeout)
        raw: bytes = await asyncio.wait_for(
            reader.read(256), timeout=timeout,
        )
        return _parse_modbus_response(raw)
    except (asyncio.TimeoutError, OSError):
        return False, False, None, None


async def _verify_tcp_protocol(
    reader: asyncio.StreamReader,
    writer: asyncio.StreamWriter,
    protocol: str,
    timeout: float,
) -> Tuple[bool, Optional[str], Optional[str]]:
    """Send a protocol-specific TCP verification probe."""
    requests = {
        PROTOCOL_S7COMM: _build_s7_cotp_connect_request,
        PROTOCOL_ETHERNET_IP: _build_enip_list_identity_request,
        PROTOCOL_DNP3: _build_dnp3_link_status_request,
    }
    builders = {
        PROTOCOL_S7COMM: lambda raw: (_parse_s7_cotp_response(raw), None),
        PROTOCOL_ETHERNET_IP: _parse_enip_identity_response,
        PROTOCOL_DNP3: lambda raw: (_parse_dnp3_response(raw), None),
    }

    request_builder = requests.get(protocol)
    response_parser = builders.get(protocol)
    if request_builder is None or response_parser is None:
        return False, None, None

    try:
        writer.write(request_builder())
        await asyncio.wait_for(writer.drain(), timeout=timeout)
        raw: bytes = await asyncio.wait_for(reader.read(512), timeout=timeout)
    except (asyncio.TimeoutError, OSError):
        return False, None, None

    if not raw:
        return False, None, None

    is_valid, identity = response_parser(raw)
    return is_valid, identity, raw.hex()


async def _probe_bacnet(
    ip: str,
    port: int,
    timeout: float,
    verify_protocol: bool,
    protocol_name: str,
) -> ScanResult:
    """Probe BACnet/IP over UDP with a Who-Is request."""
    started_at = time.monotonic()
    loop = asyncio.get_running_loop()
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    sock.setblocking(False)

    try:
        await loop.sock_connect(sock, (ip, port))
        verification_level = 1
        validation_level = VALIDATION_TCP_ONLY
        raw_response = None
        if verify_protocol:
            await loop.sock_sendall(sock, _build_bacnet_who_is_request())
            raw = await asyncio.wait_for(loop.sock_recv(sock, 512), timeout=timeout)
            raw_response = raw.hex() if raw else None
            if raw and _parse_bacnet_response(raw):
                validation_level = VALIDATION_PROTOCOL_CONFIRMED
                verification_level = 2
                return ScanResult(
                    ip=ip,
                    port=port,
                    open=True,
                    modbus_verified=False,
                    banner=None,
                    protocol=protocol_name,
                    protocol_verified=True,
                    verification_level=verification_level,
                    transport="udp",
                    total_latency_ms=round((time.monotonic() - started_at) * 1000, 3),
                    raw_response=raw_response,
                    validation_level=validation_level,
                )
        return ScanResult(
            ip=ip,
            port=port,
            open=not verify_protocol,
            modbus_verified=False,
            banner=None,
            protocol=protocol_name,
            protocol_verified=False,
            verification_level=verification_level,
            transport="udp",
            total_latency_ms=round((time.monotonic() - started_at) * 1000, 3),
            raw_response=raw_response,
            validation_level=validation_level,
        )
    except (asyncio.TimeoutError, OSError) as exc:
        return ScanResult(
            ip=ip,
            port=port,
            open=False,
            modbus_verified=False,
            banner=None,
            protocol=protocol_name,
            protocol_verified=False,
            verification_level=0,
            transport="udp",
            total_latency_ms=round((time.monotonic() - started_at) * 1000, 3),
            error=str(exc),
            validation_level=VALIDATION_NO_ACCESS,
        )
    finally:
        sock.close()


async def _worker(
    queue: asyncio.Queue,
    results: list,
    port: int,
    timeout: float,
    verify_modbus: bool,
    hits_only: bool,
    banner_grab: bool = False,
    jitter: float = 0.0,
    protocol: str = PROTOCOL_MODBUS,
) -> None:
    """Consume IP addresses from *queue* and append results to *results*.

    If *jitter* > 0, a random delay in ``[0, jitter]`` seconds is inserted
    before each probe to make scan traffic less predictable (WAF evasion).
    """
    while True:
        ip = await queue.get()
        try:
            if jitter > 0:
                await asyncio.sleep(random.uniform(0, jitter))
            result = await _probe(
                ip, port, timeout, verify_modbus, banner_grab, protocol=protocol
            )
            if not hits_only or result.open:
                results.append(result)
            if result.open:
                level = result.validation_level
                verified_str = f" [{level}]" if result.protocol_verified else ""
                logger.info("HIT  %s:%d (%s)%s", ip, port, result.protocol, verified_str)
        finally:
            queue.task_done()


async def _scan_async(
    addresses: Iterable[str],
    port: int,
    concurrency: int,
    timeout: float,
    verify_modbus: bool,
    hits_only: bool,
    progress_every: int,
    banner_grab: bool = False,
    jitter: float = 0.0,
    randomize_hosts: bool = False,
    protocol: str = PROTOCOL_MODBUS,
) -> List[ScanResult]:
    """Run the async scan and return all :class:`ScanResult` objects."""
    queue: asyncio.Queue = asyncio.Queue(maxsize=concurrency * 4)
    results: List[ScanResult] = []

    workers = [
        asyncio.create_task(
            _worker(queue, results, port, timeout, verify_modbus, hits_only,
                    banner_grab, jitter, protocol)
        )
        for _ in range(concurrency)
    ]

    addr_list: Iterable[str] = addresses
    if randomize_hosts:
        addr_list_materialized = list(addresses)
        random.shuffle(addr_list_materialized)
        addr_list = addr_list_materialized

    count = 0
    for addr in addr_list:
        await queue.put(addr)
        count += 1
        if progress_every and count % progress_every == 0:
            logger.info("Queued %d addresses …", count)

    await queue.join()

    for w in workers:
        w.cancel()
    await asyncio.gather(*workers, return_exceptions=True)

    return results


# ─────────────────────────────────────────────────────────────
# Public API
# ─────────────────────────────────────────────────────────────


def scan_networks(
    networks: Iterable[AnyNetwork],
    port: int = MODBUS_PORT,
    concurrency: int = 500,
    timeout: float = 30.0,
    verify_modbus: bool = True,
    hits_only: bool = True,
    progress_every: int = 10_000,
    banner_grab: bool = False,
    randomize_hosts: bool = False,
    jitter: float = 0.0,
    protocol: str = PROTOCOL_MODBUS,
) -> List[ScanResult]:
    """
    Scan every host address in *networks* for a listening Modbus TCP service.

    Parameters
    ----------
    networks:
        Iterable of :class:`~ipaddress.IPv4Network` /
        :class:`~ipaddress.IPv6Network` objects to scan.
    port:
        TCP port to probe (default: 502).
    concurrency:
        Maximum number of simultaneous TCP probes.
    timeout:
        Per-probe TCP connection timeout in seconds (default: 30).
    verify_modbus:
        If ``True``, send a Modbus Read Coils request and verify the response
        before marking an address as a confirmed Modbus device.
    hits_only:
        If ``True`` (default), only addresses with an *open* port are stored
        in the result list (saves memory for large scans).
    progress_every:
        Log a progress message every *N* addresses queued (0 to disable).
    banner_grab:
        If ``True``, attempt to read any unsolicited data (service banner) from
        open ports even when *verify_modbus* is ``False``.
    randomize_hosts:
        If ``True``, shuffle the host addresses before scanning so that probes
        do not follow a predictable sequential pattern (WAF evasion).
    jitter:
        Maximum random delay in seconds inserted before each probe.  A value
        of ``0`` (default) disables jitter.

    Returns
    -------
    list of ScanResult
    """
    nets_list = list(networks)
    total = count_hosts(nets_list)
    logger.info(
        "Starting scan: %d networks, ~%d hosts, port %d, concurrency %d",
        len(nets_list),
        total,
        port,
        concurrency,
    )

    def _address_iter():
        for net in nets_list:
            if net.prefixlen >= (31 if net.version == 4 else 127):
                for addr in net:
                    yield str(addr)
            else:
                for addr in net.hosts():
                    yield str(addr)

    return asyncio.run(
        _scan_async(
            _address_iter(),
            port=port,
            concurrency=concurrency,
            timeout=timeout,
            verify_modbus=verify_modbus,
            hits_only=hits_only,
            progress_every=progress_every,
            banner_grab=banner_grab,
            jitter=jitter,
            randomize_hosts=randomize_hosts,
            protocol=protocol,
        )
    )


# ─────────────────────────────────────────────────────────────
# Masscan integration (fast TCP discovery)
# ─────────────────────────────────────────────────────────────


def _parse_masscan_list_output(path: str) -> List[str]:
    """Parse a masscan ``-oL`` (list) output file and return discovered IPs.

    Each relevant line in the file has the format::

        open tcp 502 1.2.3.4 1234567890

    Lines starting with ``#`` or not starting with ``open`` are ignored.
    """
    ips: List[str] = []
    with open(path, encoding="utf-8", errors="replace") as fh:
        for line in fh:
            line = line.strip()
            if not line or line.startswith("#"):
                continue
            parts = line.split()
            if len(parts) >= 4 and parts[0] == "open":
                ips.append(parts[3])
    return ips


def masscan_discover(
    targets: Iterable[AnyNetwork],
    port: int = MODBUS_PORT,
    rate: int = 10_000,
) -> List[str]:
    """Run *masscan* to discover hosts with an open TCP port.

    Parameters
    ----------
    targets:
        Networks to scan.
    port:
        TCP port to probe.
    rate:
        Maximum packet-sending rate (packets / second).

    Returns
    -------
    list of str
        IP addresses with the port open.

    Raises
    ------
    FileNotFoundError
        If the ``masscan`` binary is not found on ``$PATH``.
    RuntimeError
        If the masscan process exits with a non-zero code.
    """
    if shutil.which("masscan") is None:
        raise FileNotFoundError(
            "masscan is not installed or not on $PATH.  "
            "Install it (e.g. 'apt install masscan') or use the default "
            "async scanner instead (omit --masscan)."
        )

    target_fd, target_path = tempfile.mkstemp(suffix=".txt", prefix="ics_targets_")
    output_fd, output_path = tempfile.mkstemp(suffix=".list", prefix="ics_masscan_")
    try:
        with os.fdopen(target_fd, "w") as tf:
            for net in targets:
                tf.write(str(net) + "\n")
        os.close(output_fd)

        cmd = [
            "masscan",
            "-iL", target_path,
            "-p", str(port),
            "--rate", str(rate),
            "-oL", output_path,
        ]
        logger.info("Running masscan: %s", " ".join(cmd))
        proc = subprocess.run(
            cmd, capture_output=True, text=True, timeout=_MASSCAN_TIMEOUT,
        )
        if proc.returncode != 0:
            raise RuntimeError(
                f"masscan exited with code {proc.returncode}: {proc.stderr}"
            )

        discovered = _parse_masscan_list_output(output_path)
        logger.info("masscan discovered %d open host(s).", len(discovered))
        return discovered
    finally:
        for p in (target_path, output_path):
            try:
                os.unlink(p)
            except OSError:
                pass


def scan_networks_fast(
    networks: Iterable[AnyNetwork],
    port: int = MODBUS_PORT,
    masscan_rate: int = 10_000,
    concurrency: int = 500,
    timeout: float = 5.0,
    hits_only: bool = True,
    progress_every: int = 10_000,
    banner_grab: bool = False,
    randomize_hosts: bool = False,
    jitter: float = 0.0,
    protocol: str = PROTOCOL_MODBUS,
) -> List[ScanResult]:
    """Two-phase scan: fast masscan discovery + async Modbus verification.

    Phase 1 uses *masscan* (SYN scan) to rapidly find hosts with an open TCP
    port.  Phase 2 performs full Modbus protocol verification on every
    discovered host using the async scanner.

    This approach is dramatically faster than probing every address with a
    full TCP handshake when scanning large networks.

    Parameters
    ----------
    networks:
        Networks to scan.
    port:
        TCP port (default: 502).
    masscan_rate:
        masscan packet rate (default: 10 000 pps).
    concurrency:
        Async verification concurrency for phase 2.
    timeout:
        Per-probe timeout for phase 2 Modbus verification.
    hits_only:
        If ``True``, only store open results.
    progress_every:
        Log interval.
    banner_grab:
        Capture banners for non-Modbus ports.
    randomize_hosts:
        Shuffle verification order.
    jitter:
        Maximum random delay before each verification probe.

    Returns
    -------
    list of ScanResult
    """
    nets_list = list(networks)
    total = count_hosts(nets_list)
    logger.info(
        "Fast scan: %d networks, ~%d hosts, port %d, masscan rate %d",
        len(nets_list), total, port, masscan_rate,
    )

    # Phase 1: masscan TCP discovery
    open_ips = masscan_discover(nets_list, port=port, rate=masscan_rate)

    if not open_ips:
        logger.info("No open hosts discovered by masscan.")
        return []

    logger.info(
        "Phase 2: verifying %d host(s) with Modbus protocol probes …",
        len(open_ips),
    )

    # Phase 2: async Modbus verification on discovered hosts only
    return asyncio.run(
        _scan_async(
            open_ips,
            port=port,
            concurrency=concurrency,
            timeout=timeout,
            verify_modbus=True,
            hits_only=hits_only,
            progress_every=progress_every,
            banner_grab=banner_grab,
            jitter=jitter,
            randomize_hosts=randomize_hosts,
            protocol=protocol,
        )
    )


# ─────────────────────────────────────────────────────────────
# Result persistence helpers
# ─────────────────────────────────────────────────────────────

_CSV_FIELDNAMES = [
    "ip", "port", "protocol", "transport", "open", "protocol_verified",
    "verification_level", "modbus_verified", "validation_level",
    "modbus_exception_code", "device_info", "banner", "tcp_latency_ms",
    "total_latency_ms", "raw_response", "timestamp", "error",
]


def write_results_csv(results: Iterable[ScanResult], path: str) -> int:
    """
    Write *results* to a CSV file at *path*.

    Returns the number of rows written.
    """
    rows = 0
    with open(path, "w", newline="", encoding="utf-8") as fh:
        writer = csv.DictWriter(fh, fieldnames=_CSV_FIELDNAMES)
        writer.writeheader()
        for result in results:
            writer.writerow(result.as_dict())
            rows += 1
    return rows


def write_results_json(results: Iterable[ScanResult], path: str) -> int:
    """
    Write *results* to a JSON file at *path*.

    Returns the number of records written.
    """
    records = [r.as_dict() for r in results]
    with open(path, "w", encoding="utf-8") as fh:
        json.dump(records, fh, indent=2)
    return len(records)


def write_results_sqlite(results: Iterable[ScanResult], path: str) -> int:
    """Append *results* to an SQLite database at *path*."""
    records = [r.as_dict() for r in results]
    conn = sqlite3.connect(path)
    try:
        conn.execute(
            """
            CREATE TABLE IF NOT EXISTS scan_results (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                ip TEXT NOT NULL,
                port INTEGER NOT NULL,
                protocol TEXT NOT NULL,
                transport TEXT NOT NULL,
                open INTEGER NOT NULL,
                protocol_verified INTEGER NOT NULL,
                verification_level INTEGER NOT NULL,
                modbus_verified INTEGER NOT NULL,
                validation_level TEXT NOT NULL,
                modbus_exception_code INTEGER,
                device_info TEXT,
                banner TEXT,
                tcp_latency_ms REAL,
                total_latency_ms REAL,
                raw_response TEXT,
                timestamp REAL NOT NULL,
                error TEXT
            )
            """
        )
        conn.executemany(
            """
            INSERT INTO scan_results (
                ip, port, protocol, transport, open, protocol_verified,
                verification_level, modbus_verified, validation_level,
                modbus_exception_code, device_info, banner, tcp_latency_ms,
                total_latency_ms, raw_response, timestamp, error
            ) VALUES (
                :ip, :port, :protocol, :transport, :open, :protocol_verified,
                :verification_level, :modbus_verified, :validation_level,
                :modbus_exception_code, :device_info, :banner, :tcp_latency_ms,
                :total_latency_ms, :raw_response, :timestamp, :error
            )
            """,
            records,
        )
        conn.commit()
    finally:
        conn.close()
    return len(records)


def load_results_sqlite(
    path: str,
    limit: int = 200,
    protocol: Optional[str] = None,
) -> List[Dict[str, object]]:
    """Load the newest rows from an SQLite results database."""
    conn = sqlite3.connect(path)
    conn.row_factory = sqlite3.Row
    try:
        query = "SELECT * FROM scan_results"
        params: List[object] = []
        if protocol:
            query += " WHERE protocol = ?"
            params.append(protocol_label(protocol))
        query += " ORDER BY timestamp DESC LIMIT ?"
        params.append(limit)
        rows = conn.execute(query, params).fetchall()
        return [dict(row) for row in rows]
    finally:
        conn.close()


def summarize_results_sqlite(path: str) -> Dict[str, object]:
    """Return aggregate counts from an SQLite results database."""
    conn = sqlite3.connect(path)
    try:
        total_rows = conn.execute("SELECT COUNT(*) FROM scan_results").fetchone()[0]
        open_rows = conn.execute(
            "SELECT COUNT(*) FROM scan_results WHERE open = 1"
        ).fetchone()[0]
        verified_rows = conn.execute(
            "SELECT COUNT(*) FROM scan_results WHERE protocol_verified = 1"
        ).fetchone()[0]
        protocol_rows = conn.execute(
            """
            SELECT protocol, COUNT(*) AS count
            FROM scan_results
            GROUP BY protocol
            ORDER BY count DESC, protocol ASC
            """
        ).fetchall()
        return {
            "total_results": total_rows,
            "open_results": open_rows,
            "verified_results": verified_rows,
            "protocols": [
                {"protocol": protocol, "count": count}
                for protocol, count in protocol_rows
            ],
        }
    finally:
        conn.close()
