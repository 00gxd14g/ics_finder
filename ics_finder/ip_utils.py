"""
ip_utils.py — IP range arithmetic for the ICS finder.

Provides helpers to:
* subtract a collection of "excluded" networks from a set of "target" networks,
* iterate over all host addresses in a list of networks,
* chunk large address spaces into smaller batches suitable for async scanning.
"""

from __future__ import annotations

import ipaddress
import itertools
from typing import Generator, Iterable, List, Union

# Type alias for convenience.
AnyNetwork = Union[ipaddress.IPv4Network, ipaddress.IPv6Network]
AnyAddress = Union[ipaddress.IPv4Address, ipaddress.IPv6Address]

# ─────────────────────────────────────────────────────────────
# Public helpers
# ─────────────────────────────────────────────────────────────


def parse_network(value: str) -> AnyNetwork:
    """
    Parse *value* as an IP network (CIDR notation or bare address).

    A bare address is treated as a host-route (``/32`` for IPv4, ``/128`` for
    IPv6).

    Raises
    ------
    ValueError
        If *value* cannot be parsed as an IP network.
    """
    return ipaddress.ip_network(value.strip(), strict=False)


def subtract_networks(
    targets: Iterable[AnyNetwork],
    exclusions: Iterable[AnyNetwork],
) -> List[AnyNetwork]:
    """
    Return the set of networks that are in *targets* but **not** in *exclusions*.

    The algorithm works by iteratively splitting each target prefix whenever an
    exclusion overlaps with it, keeping only the non-overlapping sub-prefixes.

    Parameters
    ----------
    targets:
        Networks to scan.
    exclusions:
        Networks to remove from *targets*.

    Returns
    -------
    list
        Sorted, collapsed list of remaining :class:`~ipaddress.IPv4Network` /
        :class:`~ipaddress.IPv6Network` objects.
    """
    # Work with independent mutable lists separated by IP version.
    remaining_v4: list[ipaddress.IPv4Network] = []
    remaining_v6: list[ipaddress.IPv6Network] = []

    for net in targets:
        if net.version == 4:
            remaining_v4.append(net)  # type: ignore[arg-type]
        else:
            remaining_v6.append(net)  # type: ignore[arg-type]

    for excl in exclusions:
        if excl.version == 4:
            remaining_v4 = _subtract_one(remaining_v4, excl)  # type: ignore[assignment]
        else:
            remaining_v6 = _subtract_one(remaining_v6, excl)  # type: ignore[assignment]

    result: list[AnyNetwork] = list(
        ipaddress.collapse_addresses(remaining_v4)
    ) + list(ipaddress.collapse_addresses(remaining_v6))
    return result


def iter_hosts(
    networks: Iterable[AnyNetwork],
) -> Generator[AnyAddress, None, None]:
    """
    Yield every *host* address in each network.

    For ``/32`` (IPv4) and ``/128`` (IPv6) the single address is yielded.
    For ``/31`` and ``/127`` both addresses are yielded (point-to-point links).
    For larger prefixes the network and broadcast addresses are skipped.
    """
    for net in networks:
        if net.prefixlen >= (31 if net.version == 4 else 127):
            # Include both endpoints for /31, /32, /127, /128.
            for addr in net:
                yield addr
        else:
            yield from net.hosts()


def chunked_hosts(
    networks: Iterable[AnyNetwork],
    chunk_size: int = 256,
) -> Generator[List[AnyAddress], None, None]:
    """
    Yield lists of at most *chunk_size* host addresses from *networks*.

    Useful for batching scan work without materialising the entire address
    space in memory.
    """
    it = iter_hosts(networks)
    while True:
        chunk = list(itertools.islice(it, chunk_size))
        if not chunk:
            break
        yield chunk


def count_hosts(networks: Iterable[AnyNetwork]) -> int:
    """Return the total number of host addresses across all *networks*."""
    total = 0
    for net in networks:
        if net.prefixlen >= (31 if net.version == 4 else 127):
            total += net.num_addresses
        else:
            total += max(net.num_addresses - 2, 0)
    return total


# ─────────────────────────────────────────────────────────────
# Internal helpers
# ─────────────────────────────────────────────────────────────


def _subtract_one(
    remaining: list[AnyNetwork],
    excl: AnyNetwork,
) -> list[AnyNetwork]:
    """
    Remove *excl* from every network in *remaining*, returning the new list.
    """
    new_remaining: list[AnyNetwork] = []
    for net in remaining:
        if not net.overlaps(excl):  # type: ignore[arg-type]
            new_remaining.append(net)
            continue
        # excl overlaps net — keep the non-overlapping sub-prefixes.
        new_remaining.extend(_exclude_from(net, excl))
    return new_remaining


def _exclude_from(
    net: AnyNetwork,
    excl: AnyNetwork,
) -> list[AnyNetwork]:
    """
    Return the list of sub-prefixes of *net* that do not overlap with *excl*.

    Uses the standard "address-exclude" algorithm from
    :meth:`ipaddress.IPv4Network.address_exclude`.
    """
    if excl.supernet_of(net):  # type: ignore[arg-type]
        # excl covers net entirely — nothing remains.
        return []
    try:
        return list(net.address_exclude(excl))  # type: ignore[arg-type]
    except TypeError:
        # address_exclude raises TypeError for cross-version comparisons;
        # in that case the networks cannot overlap so we keep the original.
        return [net]
