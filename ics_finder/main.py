"""
main.py — CLI entry point for ics_finder.

Usage examples
--------------
Scan a single subnet, excluding MISP warning lists:

    ics_finder --target 10.0.0.0/8 --use-misp --output results.csv

Scan multiple targets and verify Modbus protocol:

    ics_finder --target 192.168.1.0/24 --target 172.16.0.0/12 \\
               --verify-modbus --output hits.json --format json

Exclude custom IP ranges in addition to MISP lists:

    ics_finder --target 0.0.0.0/0 \\
               --use-misp \\
               --exclude 10.0.0.0/8 \\
               --exclude 172.16.0.0/12 \\
               --exclude 192.168.0.0/16 \\
               --output modbus_hits.csv

Use a pre-downloaded exclusion file:

    ics_finder --target 0.0.0.0/0 \\
               --exclude-file my_exclusions.txt \\
               --output results.csv

Scan all public IPv4 space (takes a very long time!):

    ics_finder --target 0.0.0.0/0 \\
               --use-misp \\
               --exclude 0.0.0.0/8 --exclude 10.0.0.0/8 \\
               --exclude 127.0.0.0/8 --exclude 172.16.0.0/12 \\
               --exclude 192.168.0.0/16 --exclude 224.0.0.0/3 \\
               --concurrency 1000 --timeout 3 \\
               --output modbus_world.csv
"""

from __future__ import annotations

import argparse
import logging
import sys
from typing import List

from .ip_utils import parse_network, subtract_networks, count_hosts, AnyNetwork
from .misp_warninglists import (
    fetch_warninglists,
    load_warninglists_from_file,
    networks_from_iterable,
)
from .scanner import scan_networks, write_results_csv, write_results_json, MODBUS_PORT

# ─────────────────────────────────────────────────────────────
# Logging setup
# ─────────────────────────────────────────────────────────────

_LOG_FORMAT = "%(asctime)s [%(levelname)s] %(name)s: %(message)s"


def _setup_logging(verbose: bool) -> None:
    level = logging.DEBUG if verbose else logging.INFO
    logging.basicConfig(format=_LOG_FORMAT, level=level, stream=sys.stderr)


# ─────────────────────────────────────────────────────────────
# Argument parser
# ─────────────────────────────────────────────────────────────


def _build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="ics_finder",
        description=(
            "Scan IP ranges for Modbus/SCADA/PLC devices (TCP port 502) "
            "while excluding networks listed in MISP warning lists."
        ),
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog=__doc__,
    )

    # Target networks
    target_group = parser.add_argument_group("Target networks")
    target_group.add_argument(
        "--target",
        metavar="CIDR",
        action="append",
        dest="targets",
        default=[],
        help="Network to scan (CIDR notation). May be repeated.",
    )
    target_group.add_argument(
        "--target-file",
        metavar="FILE",
        help="File containing one CIDR / IP per line to scan.",
    )

    # Exclusions
    excl_group = parser.add_argument_group("Exclusions")
    excl_group.add_argument(
        "--use-misp",
        action="store_true",
        default=False,
        help="Download and apply all MISP warning lists as exclusions.",
    )
    excl_group.add_argument(
        "--misp-token",
        metavar="TOKEN",
        default=None,
        help=(
            "GitHub personal-access token for fetching MISP warning lists "
            "(increases the API rate-limit from 60 to 5 000 req/h)."
        ),
    )
    excl_group.add_argument(
        "--exclude",
        metavar="CIDR",
        action="append",
        dest="exclusions",
        default=[],
        help="Additional network to exclude (CIDR notation). May be repeated.",
    )
    excl_group.add_argument(
        "--exclude-file",
        metavar="FILE",
        help="File containing one CIDR / IP per line to exclude.",
    )

    # Scanner settings
    scan_group = parser.add_argument_group("Scanner settings")
    scan_group.add_argument(
        "--port",
        type=int,
        default=MODBUS_PORT,
        metavar="PORT",
        help=f"TCP port to probe (default: {MODBUS_PORT}).",
    )
    scan_group.add_argument(
        "--concurrency",
        type=int,
        default=500,
        metavar="N",
        help="Number of simultaneous probes (default: 500).",
    )
    scan_group.add_argument(
        "--timeout",
        type=float,
        default=3.0,
        metavar="SECONDS",
        help="TCP connection timeout per probe in seconds (default: 3.0).",
    )
    scan_group.add_argument(
        "--verify-modbus",
        action="store_true",
        default=False,
        help=(
            "After a successful TCP connection, send a Modbus Read Coils "
            "request and verify the response before recording a hit."
        ),
    )
    scan_group.add_argument(
        "--all-results",
        action="store_true",
        default=False,
        help="Record all probed addresses, not just open-port hits.",
    )

    # Output
    out_group = parser.add_argument_group("Output")
    out_group.add_argument(
        "--output",
        metavar="FILE",
        default="results.csv",
        help="Output file path (default: results.csv).",
    )
    out_group.add_argument(
        "--format",
        choices=["csv", "json"],
        default="csv",
        help="Output format (default: csv).",
    )

    # Misc
    parser.add_argument(
        "--verbose", "-v", action="store_true", default=False,
        help="Enable debug logging.",
    )

    return parser


# ─────────────────────────────────────────────────────────────
# Main logic
# ─────────────────────────────────────────────────────────────


def _load_targets(args: argparse.Namespace) -> List[AnyNetwork]:
    """Parse and return the list of target networks from CLI arguments."""
    targets: list[AnyNetwork] = []

    for cidr in args.targets:
        try:
            targets.append(parse_network(cidr))
        except ValueError as exc:
            logging.getLogger(__name__).error("Invalid --target %r: %s", cidr, exc)
            sys.exit(1)

    if args.target_file:
        try:
            from .misp_warninglists import load_warninglists_from_file
            targets.extend(load_warninglists_from_file(args.target_file))
        except OSError as exc:
            logging.getLogger(__name__).error(
                "Cannot read --target-file %r: %s", args.target_file, exc
            )
            sys.exit(1)

    if not targets:
        logging.getLogger(__name__).error(
            "No targets specified.  Use --target or --target-file."
        )
        sys.exit(1)

    return targets


def _load_exclusions(args: argparse.Namespace) -> List[AnyNetwork]:
    """Aggregate all exclusion networks from CLI arguments and MISP lists."""
    log = logging.getLogger(__name__)
    exclusions: list[AnyNetwork] = []

    # Inline --exclude arguments
    inline = networks_from_iterable(args.exclusions)
    if inline:
        log.info("Loaded %d inline exclusion(s).", len(inline))
        exclusions.extend(inline)

    # --exclude-file
    if args.exclude_file:
        try:
            file_excls = load_warninglists_from_file(args.exclude_file)
            log.info(
                "Loaded %d exclusion(s) from %r.", len(file_excls), args.exclude_file
            )
            exclusions.extend(file_excls)
        except OSError as exc:
            log.error("Cannot read --exclude-file %r: %s", args.exclude_file, exc)
            sys.exit(1)

    # MISP warning lists
    if args.use_misp:
        try:
            misp_nets = fetch_warninglists(github_token=args.misp_token)
            log.info("MISP warning lists: %d networks loaded.", len(misp_nets))
            exclusions.extend(misp_nets)
        except RuntimeError as exc:
            log.error("Failed to fetch MISP warning lists: %s", exc)
            sys.exit(1)

    return exclusions


def main(argv: list[str] | None = None) -> None:
    parser = _build_parser()
    args = parser.parse_args(argv)
    _setup_logging(args.verbose)
    log = logging.getLogger(__name__)

    # 1. Resolve targets
    targets = _load_targets(args)
    log.info("Target networks: %d", len(targets))

    # 2. Resolve exclusions
    exclusions = _load_exclusions(args)

    # 3. Subtract exclusions from targets
    if exclusions:
        log.info("Subtracting %d exclusion network(s) from targets …", len(exclusions))
        scan_targets = subtract_networks(targets, exclusions)
        log.info("Remaining scan targets: %d network(s)", len(scan_targets))
    else:
        scan_targets = list(targets)

    if not scan_targets:
        log.warning("All target addresses have been excluded.  Nothing to scan.")
        sys.exit(0)

    remaining_hosts = count_hosts(scan_targets)
    log.info("Total host addresses to probe: %d", remaining_hosts)

    # 4. Run scanner
    results = scan_networks(
        scan_targets,
        port=args.port,
        concurrency=args.concurrency,
        timeout=args.timeout,
        verify_modbus=args.verify_modbus,
        hits_only=not args.all_results,
        progress_every=10_000,
    )

    hits = [r for r in results if r.open]
    log.info("Scan complete.  Open ports found: %d", len(hits))
    if args.verify_modbus:
        verified = [r for r in hits if r.modbus_verified]
        log.info("Modbus-verified devices: %d", len(verified))

    # 5. Write results
    if args.format == "json":
        written = write_results_json(results, args.output)
    else:
        written = write_results_csv(results, args.output)

    log.info("Results written to %r (%d record(s)).", args.output, written)


if __name__ == "__main__":
    main()
