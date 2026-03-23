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
from .scanner import (
    scan_networks,
    scan_networks_fast,
    write_results_csv,
    write_results_json,
    write_results_sqlite,
    default_port_for_protocol,
    infer_protocol_from_port,
    normalize_protocol,
    protocol_label,
    MODBUS_PORT,
    PROTOCOL_BACNET,
    PROTOCOL_DNP3,
    PROTOCOL_ETHERNET_IP,
    PROTOCOL_MODBUS,
    PROTOCOL_S7COMM,
)

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
        default=None,
        metavar="PORT",
        help="Port to probe. Defaults to the selected protocol's well-known port.",
    )
    scan_group.add_argument(
        "--protocol",
        choices=[
            PROTOCOL_MODBUS,
            PROTOCOL_S7COMM,
            PROTOCOL_ETHERNET_IP,
            PROTOCOL_BACNET,
            PROTOCOL_DNP3,
            "auto",
        ],
        default="auto",
        help=(
            "ICS protocol to verify. Use 'auto' to infer it from --port; "
            "defaults to Modbus when the port is unknown."
        ),
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
        default=30.0,
        metavar="SECONDS",
        help="TCP connection timeout per probe in seconds (default: 30.0).",
    )
    scan_group.add_argument(
        "--verify-protocol",
        "--verify-modbus",
        action="store_true",
        dest="verify_protocol",
        default=False,
        help=(
            "After transport-level reachability, send a protocol-specific "
            "verification request before recording a confirmed ICS service."
        ),
    )
    scan_group.add_argument(
        "--all-results",
        action="store_true",
        default=False,
        help="Record all probed addresses, not just open-port hits.",
    )
    scan_group.add_argument(
        "--banner-grab",
        action="store_true",
        default=False,
        help=(
            "Read unsolicited service banner data from open ports, "
            "even when --verify-modbus is not set."
        ),
    )
    scan_group.add_argument(
        "--randomize-hosts",
        action="store_true",
        default=False,
        help=(
            "Shuffle the host scan order to avoid sequential patterns "
            "that stateful firewalls or WAFs could detect."
        ),
    )
    scan_group.add_argument(
        "--jitter",
        type=float,
        default=0.0,
        metavar="SECONDS",
        help=(
            "Maximum random delay (in seconds) inserted before each "
            "probe to make scan traffic less predictable (default: 0)."
        ),
    )
    scan_group.add_argument(
        "--masscan",
        action="store_true",
        default=False,
        help=(
            "Use masscan for fast initial TCP port discovery (SYN scan), "
            "then verify discovered hosts with Modbus protocol probes.  "
            "Requires masscan to be installed and typically needs root."
        ),
    )
    scan_group.add_argument(
        "--masscan-rate",
        type=int,
        default=10_000,
        metavar="PPS",
        help=(
            "masscan packet-sending rate in packets per second "
            "(default: 10000).  Only used when --masscan is set."
        ),
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
    out_group.add_argument(
        "--sqlite-output",
        metavar="FILE",
        default=None,
        help="Optional SQLite database file that receives appended scan results.",
    )

    web_group = parser.add_argument_group("Web dashboard")
    web_group.add_argument(
        "--serve",
        action="store_true",
        default=False,
        help="Start the built-in dashboard after writing results.",
    )
    web_group.add_argument(
        "--serve-host",
        default="127.0.0.1",
        metavar="HOST",
        help="Dashboard bind host (default: 127.0.0.1).",
    )
    web_group.add_argument(
        "--serve-port",
        type=int,
        default=8000,
        metavar="PORT",
        help="Dashboard bind port (default: 8000).",
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

    protocol = (
        infer_protocol_from_port(args.port)
        if args.protocol == "auto" and args.port is not None
        else normalize_protocol(args.protocol)
    )
    port = args.port if args.port is not None else default_port_for_protocol(protocol)
    log.info("Protocol: %s", protocol_label(protocol))
    log.info("Probe port: %d", port)

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
    if args.masscan:
        log.info("Using masscan for fast TCP discovery (rate=%d) …", args.masscan_rate)
        try:
            results = scan_networks_fast(
                scan_targets,
                port=port,
                masscan_rate=args.masscan_rate,
                concurrency=args.concurrency,
                timeout=args.timeout,
                hits_only=not args.all_results,
                progress_every=10_000,
                banner_grab=args.banner_grab,
                randomize_hosts=args.randomize_hosts,
                jitter=args.jitter,
                protocol=protocol,
            )
        except FileNotFoundError as exc:
            log.error("%s", exc)
            sys.exit(1)
        except RuntimeError as exc:
            log.error("masscan failed: %s", exc)
            sys.exit(1)
    else:
        results = scan_networks(
            scan_targets,
            port=port,
            concurrency=args.concurrency,
            timeout=args.timeout,
            verify_modbus=args.verify_protocol,
            hits_only=not args.all_results,
            progress_every=10_000,
            banner_grab=args.banner_grab,
            randomize_hosts=args.randomize_hosts,
            jitter=args.jitter,
            protocol=protocol,
        )

    hits = [r for r in results if r.open]
    log.info("Scan complete.  Open ports found: %d", len(hits))
    if args.verify_protocol or args.masscan:
        verified = [r for r in hits if r.protocol_verified]
        log.info("%s verified devices: %d", protocol_label(protocol), len(verified))
        exceptions = [r for r in hits if r.modbus_exception_code is not None]
        if exceptions:
            log.info(
                "Devices responding with Modbus exceptions: %d", len(exceptions)
            )
        dev_id = [r for r in hits if r.device_info]
        if dev_id:
            log.info("Devices with device identification: %d", len(dev_id))

    # 5. Write results
    if args.format == "json":
        written = write_results_json(results, args.output)
    else:
        written = write_results_csv(results, args.output)

    log.info("Results written to %r (%d record(s)).", args.output, written)

    if args.sqlite_output:
        sqlite_written = write_results_sqlite(results, args.sqlite_output)
        log.info(
            "Results appended to SQLite database %r (%d record(s)).",
            args.sqlite_output,
            sqlite_written,
        )

    if args.serve:
        if not args.sqlite_output:
            log.error("--serve requires --sqlite-output so the dashboard has a data source.")
            sys.exit(1)
        from .webapp import serve_dashboard

        log.info(
            "Starting dashboard on http://%s:%d",
            args.serve_host,
            args.serve_port,
        )
        serve_dashboard(args.sqlite_output, host=args.serve_host, port=args.serve_port)


if __name__ == "__main__":
    main()
