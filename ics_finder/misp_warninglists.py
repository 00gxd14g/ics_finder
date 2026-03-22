"""
misp_warninglists.py — Fetch and parse MISP warning lists to build an IP exclusion set.

Warning lists are fetched from the official MISP GitHub repository:
  https://github.com/MISP/misp-warninglists

Each list folder contains a ``list.json`` file.  We extract entries that look
like IPv4/IPv6 addresses or CIDR blocks and return them as a collection of
:class:`ipaddress.IPv4Network` / :class:`ipaddress.IPv6Network` objects.
"""

from __future__ import annotations

import ipaddress
import json
import logging
import re
import time
from typing import Generator, Iterable, List, Optional
from urllib.request import Request, urlopen
from urllib.error import URLError

from . import __version__

logger = logging.getLogger(__name__)

# GitHub raw-content base URL for the MISP warning-lists repository.
_MISP_LISTS_API = (
    "https://api.github.com/repos/MISP/misp-warninglists/contents/lists"
)
_MISP_RAW_BASE = (
    "https://raw.githubusercontent.com/MISP/misp-warninglists/main/lists"
)

# Regex that loosely matches an IPv4/IPv6 address or CIDR prefix.
_IP_RE = re.compile(
    r"^(?:"
    # IPv4 or IPv4 CIDR
    r"(?:\d{1,3}\.){3}\d{1,3}(?:/\d{1,2})?"
    r"|"
    # IPv6 or IPv6 CIDR
    r"[0-9a-fA-F:]+(?:/\d{1,3})?"
    r")$"
)

# List types that are known to contain IP/CIDR data.
_IP_LIST_TYPES = frozenset(
    {
        "cidr",
        "ip-dst",
        "ip-src",
        "ip-dst|port",
        "ip-src|port",
        "ip",
    }
)

# Delay between consecutive GitHub API requests (seconds) to stay within rate
# limits for unauthenticated access (60 req/h ≈ 1 req/60 s).
_API_REQUEST_DELAY = 1.2


def _http_get(url: str, token: Optional[str] = None, timeout: int = 30) -> bytes:
    """Perform a simple HTTP GET and return the raw response body."""
    headers = {"User-Agent": f"ics_finder/{__version__} (+github.com/00gxd14g/ics_finder)"}
    if token:
        headers["Authorization"] = f"token {token}"
    req = Request(url, headers=headers)
    try:
        with urlopen(req, timeout=timeout) as resp:
            return resp.read()
    except URLError as exc:
        raise RuntimeError(f"HTTP request failed for {url!r}: {exc}") from exc


def _parse_network(entry: str) -> Optional[ipaddress.IPv4Network | ipaddress.IPv6Network]:
    """
    Try to parse *entry* as an IP address or CIDR prefix.

    Returns ``None`` if *entry* cannot be parsed.
    """
    entry = entry.strip()
    # Strip port annotations like "192.168.1.1|80"
    entry = entry.split("|")[0]
    if not _IP_RE.match(entry):
        return None
    try:
        return ipaddress.ip_network(entry, strict=False)
    except ValueError:
        return None


def _extract_networks_from_list(
    list_data: dict,
) -> Generator[ipaddress.IPv4Network | ipaddress.IPv6Network, None, None]:
    """Yield all IP networks found in a single warning-list JSON object."""
    list_type = list_data.get("type", "").lower()
    matching_types = _IP_LIST_TYPES
    if list_type not in matching_types and list_type != "":
        # Fast path: skip lists whose declared type is clearly not IP-related
        # (e.g. "hostname", "regex", "string").
        non_ip_types = {
            "hostname", "domain", "regex", "string", "substring",
            "md5", "sha1", "sha256", "url", "filename",
        }
        if list_type in non_ip_types:
            return

    for entry in list_data.get("list", []):
        if isinstance(entry, str):
            net = _parse_network(entry)
            if net is not None:
                yield net


def fetch_warninglists(
    github_token: Optional[str] = None,
    timeout: int = 30,
) -> List[ipaddress.IPv4Network | ipaddress.IPv6Network]:
    """
    Download all MISP warning lists from GitHub and return every IP network
    that appears in them.

    Parameters
    ----------
    github_token:
        Optional GitHub personal-access token.  Without a token the GitHub API
        allows only 60 requests per hour; a token raises the limit to 5 000.
    timeout:
        Per-request HTTP timeout in seconds.

    Returns
    -------
    list
        Deduplicated, collapsed list of :class:`ipaddress.IPv4Network` and
        :class:`ipaddress.IPv6Network` objects.
    """
    logger.info("Fetching MISP warning-list directory from GitHub …")
    directory_json = _http_get(_MISP_LISTS_API, token=github_token, timeout=timeout)
    directory: list = json.loads(directory_json)

    networks: list[ipaddress.IPv4Network | ipaddress.IPv6Network] = []

    folders = [item for item in directory if item.get("type") == "dir"]
    logger.info("Found %d warning-list folders.", len(folders))

    for idx, folder in enumerate(folders):
        folder_name = folder["name"]
        raw_url = f"{_MISP_RAW_BASE}/{folder_name}/list.json"
        logger.debug("[%d/%d] Fetching %s", idx + 1, len(folders), raw_url)

        try:
            raw = _http_get(raw_url, token=github_token, timeout=timeout)
            list_data = json.loads(raw)
        except (RuntimeError, json.JSONDecodeError) as exc:
            logger.warning("Skipping %s: %s", folder_name, exc)
            continue

        before = len(networks)
        for net in _extract_networks_from_list(list_data):
            networks.append(net)
        added = len(networks) - before
        if added:
            logger.debug("  → %d networks from %s", added, folder_name)

        # Be polite to the GitHub API.
        time.sleep(_API_REQUEST_DELAY)

    # Collapse overlapping / adjacent prefixes so later set operations are
    # faster.
    ipv4 = [n for n in networks if n.version == 4]
    ipv6 = [n for n in networks if n.version == 6]
    collapsed: list[ipaddress.IPv4Network | ipaddress.IPv6Network] = list(
        ipaddress.collapse_addresses(ipv4)
    ) + list(ipaddress.collapse_addresses(ipv6))

    logger.info(
        "MISP exclusion list: %d networks (%d raw, after collapsing).",
        len(collapsed),
        len(networks),
    )
    return collapsed


def load_warninglists_from_file(
    path: str,
) -> List[ipaddress.IPv4Network | ipaddress.IPv6Network]:
    """
    Load warning-list networks from a plain-text file.

    Each line should be an IP address or CIDR prefix; blank lines and lines
    starting with ``#`` are ignored.

    Parameters
    ----------
    path:
        Path to the exclusion-list file.
    """
    networks: list[ipaddress.IPv4Network | ipaddress.IPv6Network] = []
    with open(path, encoding="utf-8") as fh:
        for line in fh:
            line = line.strip()
            if not line or line.startswith("#"):
                continue
            net = _parse_network(line)
            if net is not None:
                networks.append(net)
            else:
                logger.debug("Ignored non-IP line: %r", line)

    ipv4 = [n for n in networks if n.version == 4]
    ipv6 = [n for n in networks if n.version == 6]
    return list(ipaddress.collapse_addresses(ipv4)) + list(
        ipaddress.collapse_addresses(ipv6)
    )


def networks_from_iterable(
    iterable: Iterable[str],
) -> List[ipaddress.IPv4Network | ipaddress.IPv6Network]:
    """
    Parse an iterable of strings into a deduplicated, collapsed list of networks.

    Useful for building exclusion lists from command-line arguments.
    """
    networks: list[ipaddress.IPv4Network | ipaddress.IPv6Network] = []
    for entry in iterable:
        net = _parse_network(entry)
        if net is not None:
            networks.append(net)
    ipv4 = [n for n in networks if n.version == 4]
    ipv6 = [n for n in networks if n.version == 6]
    return list(ipaddress.collapse_addresses(ipv4)) + list(
        ipaddress.collapse_addresses(ipv6)
    )
