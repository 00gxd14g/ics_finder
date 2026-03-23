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
import random
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

# Banner-grab timeout (seconds) — how long to wait for unsolicited data.
_BANNER_READ_TIMEOUT: float = 2.0


def _build_modbus_request() -> bytes:
    """Build a Modbus Read Coils request with a randomised transaction ID.

    Randomising the transaction ID on each probe avoids deterministic
    signatures that stateful firewalls or WAFs could use to fingerprint
    the scanner.
    """
    tx_id = random.randint(0x0001, 0xFFFE)
    return struct.pack(
        ">HHHBBHH", tx_id, 0x0000, 0x0006, 0x01, 0x01, 0x0000, 0x0001
    )


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
    banner_grab: bool = False,
) -> ScanResult:
    """
    Attempt a TCP connection to *ip*:*port*.

    If *verify_modbus* is ``True`` we additionally send a Modbus Read Coils
    request (with a randomised transaction ID for WAF evasion) and check that
    the response carries a valid Modbus protocol identifier (0x0000).

    If *banner_grab* is ``True`` and *verify_modbus* is ``False``, the scanner
    waits briefly for any unsolicited data from the server (service banner).
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
            writer.write(_build_modbus_request())
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
        elif banner_grab:
            # Wait briefly for any unsolicited data the service may send.
            try:
                raw = await asyncio.wait_for(
                    reader.read(256),
                    timeout=min(timeout, _BANNER_READ_TIMEOUT),
                )
                if raw:
                    banner = raw.hex()
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
    )


async def _worker(
    queue: asyncio.Queue,
    results: list,
    port: int,
    timeout: float,
    verify_modbus: bool,
    hits_only: bool,
    banner_grab: bool = False,
    jitter: float = 0.0,
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
            result = await _probe(ip, port, timeout, verify_modbus, banner_grab)
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
    banner_grab: bool = False,
    jitter: float = 0.0,
    randomize_hosts: bool = False,
) -> List[ScanResult]:
    """Run the async scan and return all :class:`ScanResult` objects."""
    queue: asyncio.Queue = asyncio.Queue(maxsize=concurrency * 4)
    results: List[ScanResult] = []

    workers = [
        asyncio.create_task(
            _worker(queue, results, port, timeout, verify_modbus, hits_only,
                    banner_grab, jitter)
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
