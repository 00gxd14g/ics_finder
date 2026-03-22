"""
scanner.py — Async Modbus TCP port scanner.

This module provides:
* :func:`scan_networks` — high-level entry point that scans a list of IP
  networks for Modbus TCP (port 502) listeners and optionally verifies the
  Modbus application-layer protocol before recording a hit.
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

We send a "Read Coils" request (FC 01) for coil 0, quantity 1.  A valid Modbus
response must carry Protocol Identifier == 0x0000; anything else (including a
connection that closes immediately or returns garbage) is treated as a non-hit.
"""

from __future__ import annotations

import asyncio
import csv
import dataclasses
import ipaddress
import json
import logging
import struct
import time
from typing import Dict, Iterable, List, Optional, Union

from .ip_utils import AnyAddress, AnyNetwork, chunked_hosts, count_hosts

logger = logging.getLogger(__name__)

# ─────────────────────────────────────────────────────────────
# Constants
# ─────────────────────────────────────────────────────────────

MODBUS_PORT: int = 502

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


# ─────────────────────────────────────────────────────────────
# Data classes
# ─────────────────────────────────────────────────────────────


@dataclasses.dataclass
class ScanResult:
    """Result of a single IP probe."""

    ip: str
    port: int
    open: bool
    modbus_verified: bool
    banner: Optional[str]
    timestamp: float = dataclasses.field(default_factory=time.time)
    error: Optional[str] = None

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
) -> ScanResult:
    """
    Attempt a TCP connection to *ip*:*port*.

    If *verify_modbus* is ``True`` we additionally send a Modbus Read Coils
    request and check that the response carries a valid Modbus protocol
    identifier (0x0000).
    """
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
            error=str(exc),
        )

    modbus_verified = False
    banner: Optional[str] = None

    try:
        if verify_modbus:
            writer.write(_MODBUS_READ_COILS)
            await asyncio.wait_for(writer.drain(), timeout=timeout)

            raw: bytes = await asyncio.wait_for(
                reader.read(256),
                timeout=timeout,
            )
            if len(raw) >= _MBAP_HEADER_LEN:
                # Protocol Identifier is bytes 2-3; must be 0x0000 for Modbus.
                protocol_id = struct.unpack(">H", raw[2:4])[0]
                modbus_verified = protocol_id == 0x0000
            if raw:
                banner = raw.hex()
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
    )


async def _worker(
    queue: asyncio.Queue,
    results: list,
    port: int,
    timeout: float,
    verify_modbus: bool,
    hits_only: bool,
) -> None:
    """Consume IP addresses from *queue* and append results to *results*."""
    while True:
        ip = await queue.get()
        try:
            result = await _probe(ip, port, timeout, verify_modbus)
            if not hits_only or result.open:
                results.append(result)
            if result.open:
                verified_str = " (Modbus verified)" if result.modbus_verified else ""
                logger.info("HIT  %s:%d%s", ip, port, verified_str)
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
) -> List[ScanResult]:
    """Run the async scan and return all :class:`ScanResult` objects."""
    queue: asyncio.Queue = asyncio.Queue(maxsize=concurrency * 4)
    results: List[ScanResult] = []

    workers = [
        asyncio.create_task(
            _worker(queue, results, port, timeout, verify_modbus, hits_only)
        )
        for _ in range(concurrency)
    ]

    count = 0
    for addr in addresses:
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
    timeout: float = 3.0,
    verify_modbus: bool = True,
    hits_only: bool = True,
    progress_every: int = 10_000,
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
        Per-probe TCP connection timeout in seconds.
    verify_modbus:
        If ``True``, send a Modbus Read Coils request and verify the response
        before marking an address as a confirmed Modbus device.
    hits_only:
        If ``True`` (default), only addresses with an *open* port are stored
        in the result list (saves memory for large scans).
    progress_every:
        Log a progress message every *N* addresses queued (0 to disable).

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
        )
    )


# ─────────────────────────────────────────────────────────────
# Result persistence helpers
# ─────────────────────────────────────────────────────────────

_CSV_FIELDNAMES = ["ip", "port", "open", "modbus_verified", "banner", "timestamp", "error"]


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
