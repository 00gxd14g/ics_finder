# ics_finder

Fast, async Modbus/SCADA/PLC device discovery scanner that leverages **MISP
warning lists** to automatically exclude known safe/false-positive IP ranges
before scanning.

---

## Overview

`ics_finder` was developed as a graduation thesis project.  Its goal is to
discover internet-exposed Industrial Control System (ICS) devices that respond
on the **Modbus TCP port (502)**, while avoiding IP ranges that are expected to
produce false positives according to the
[MISP/misp-warninglists](https://github.com/MISP/misp-warninglists) project.

### Workflow

```
1. Load MISP warning lists  ──►  build an IP exclusion set
2. Define target IP ranges  ──►  subtract exclusions
3. Async TCP scan            ──►  probe port 502 on remaining IPs
4. (Optional) Modbus verify  ──►  send Read Coils, check Modbus protocol ID
5. Save results              ──►  CSV or JSON output
```

---

## Features

| Feature | Detail |
|---|---|
| **MISP integration** | Automatically downloads all MISP warning lists and uses them as exclusions |
| **IP arithmetic** | Precise CIDR subtraction — no host is probed twice, none is missed |
| **Async scanner** | `asyncio`-based; configurable concurrency (default 500 parallel probes) |
| **Modbus verification** | Optionally sends a Modbus Read Coils (FC 01) request and validates the protocol identifier in the response |
| **Banner grabbing** | Reads unsolicited service data from open ports (`--banner-grab`) |
| **WAF bypass** | Randomised Modbus transaction IDs, host-order shuffling (`--randomize-hosts`), and inter-probe jitter (`--jitter`) |
| **Flexible output** | CSV (default) or JSON |
| **Custom exclusions** | `--exclude CIDR`, `--exclude-file FILE`, or both, in addition to MISP lists |
| **Custom targets** | `--target CIDR` (repeatable) or `--target-file FILE` |

---

## Installation

```bash
# Clone the repository
git clone https://github.com/00gxd14g/ics_finder.git
cd ics_finder

# Install (creates the `ics_finder` console script)
pip install -e .

# Or just install the dependencies and run as a module
pip install -r requirements.txt
```

**Python ≥ 3.9** is required.  No external C libraries are needed.

---

## Quick Start

### Scan a local subnet (no MISP download)

```bash
ics_finder --target 192.168.1.0/24 --output hits.csv
```

### Scan with Modbus protocol verification

```bash
ics_finder --target 192.168.1.0/24 \
           --verify-modbus \
           --output hits.json --format json
```

### Scan and exclude MISP warning lists

```bash
ics_finder --target 10.0.0.0/8 \
           --use-misp \
           --output modbus_hits.csv
```

> **Note:** Fetching all MISP warning lists makes ~100–150 unauthenticated
> GitHub API requests (≈ 2–3 minutes with the default rate-limit delay).
> Pass `--misp-token <token>` with a GitHub PAT to raise the rate limit.

### Scan all public IPv4 space

```bash
ics_finder \
  --target 0.0.0.0/0 \
  --use-misp \
  --exclude 0.0.0.0/8     \  # "this" network
  --exclude 10.0.0.0/8    \  # RFC 1918 private
  --exclude 127.0.0.0/8   \  # loopback
  --exclude 172.16.0.0/12 \  # RFC 1918 private
  --exclude 192.168.0.0/16\  # RFC 1918 private
  --exclude 224.0.0.0/3   \  # multicast + reserved
  --concurrency 1000 \
  --timeout 3 \
  --verify-modbus \
  --output modbus_world.csv
```

---

## CLI Reference

```
usage: ics_finder [-h] [--target CIDR] [--target-file FILE]
                  [--use-misp] [--misp-token TOKEN]
                  [--exclude CIDR] [--exclude-file FILE]
                  [--port PORT] [--concurrency N] [--timeout SECONDS]
                  [--verify-modbus] [--all-results]
                  [--banner-grab] [--randomize-hosts] [--jitter SECONDS]
                  [--output FILE] [--format {csv,json}] [--verbose]
```

| Option | Default | Description |
|---|---|---|
| `--target CIDR` | — | Network to scan; may be repeated |
| `--target-file FILE` | — | File with one CIDR/IP per line |
| `--use-misp` | off | Download & apply all MISP warning lists |
| `--misp-token TOKEN` | — | GitHub PAT for higher MISP API rate limit |
| `--exclude CIDR` | — | Exclude a network; may be repeated |
| `--exclude-file FILE` | — | File with one exclusion CIDR/IP per line |
| `--port PORT` | `502` | TCP port to probe |
| `--concurrency N` | `500` | Parallel probes |
| `--timeout SECONDS` | `30.0` | Per-probe TCP timeout |
| `--verify-modbus` | off | Send Modbus FC 01 and verify protocol ID |
| `--all-results` | off | Record closed ports too (default: hits only) |
| `--banner-grab` | off | Read unsolicited service banner from open ports |
| `--randomize-hosts` | off | Shuffle host scan order (WAF evasion) |
| `--jitter SECONDS` | `0` | Max random delay before each probe (WAF evasion) |
| `--output FILE` | `results.csv` | Output file path |
| `--format {csv,json}` | `csv` | Output format |
| `--verbose / -v` | off | Debug logging |

---

## Output Format

### CSV (default)

```
ip,port,open,modbus_verified,banner,timestamp,error
1.2.3.4,502,True,True,deadbeef00010000...,1711115200.0,
```

### JSON

```json
[
  {
    "ip": "1.2.3.4",
    "port": 502,
    "open": true,
    "modbus_verified": true,
    "banner": "deadbeef00010000...",
    "timestamp": 1711115200.0,
    "error": null
  }
]
```

---

## Project Layout

```
ics_finder/
├── ics_finder/
│   ├── __init__.py
│   ├── misp_warninglists.py   # Download & parse MISP warning lists
│   ├── ip_utils.py            # CIDR arithmetic (subtract, iterate, count)
│   ├── scanner.py             # Async Modbus TCP scanner + result I/O
│   └── main.py                # CLI entry point
├── tests/
│   ├── test_ip_utils.py
│   ├── test_misp_warninglists.py
│   └── test_scanner.py
├── requirements.txt
└── setup.py
```

---

## Running Tests

```bash
pip install -r requirements.txt
pytest tests/ -v
```

---

## Modbus TCP Protocol Notes

Modbus TCP wraps the standard Modbus PDU in a 6-byte **MBAP header**:

```
Byte 0-1  Transaction Identifier  (echoed by server)
Byte 2-3  Protocol Identifier     0x0000 = Modbus
Byte 4-5  Length
Byte 6    Unit Identifier
Byte 7+   Function Code + Data
```

`ics_finder` sends a **Read Coils (FC 01)** request for coil 0, quantity 1.
A valid Modbus device must reply with Protocol Identifier `0x0000`.  Any other
value (or no response) means the port is open but not running Modbus.

---

## MISP Warning Lists

The [MISP/misp-warninglists](https://github.com/MISP/misp-warninglists)
repository contains curated lists of IP ranges, domains, and other indicators
that are known to generate false positives in threat-intelligence feeds (e.g.
CDN ranges, cloud provider CIDRs, Tor exit nodes, etc.).

`ics_finder` downloads every list whose type is IP-related (`cidr`, `ip-dst`,
`ip-src`, …) and uses the extracted CIDR blocks as the exclusion set, so that
your scan avoids probing addresses that are very unlikely to belong to isolated
ICS installations.

---

## WAF Bypass Techniques

`ics_finder` includes several lightweight techniques to reduce the chance that
scans are blocked by stateful firewalls or Web Application Firewalls (WAFs):

| Technique | CLI flag | Description |
|---|---|---|
| **Randomised transaction IDs** | always on | Each Modbus request uses a random transaction ID to avoid deterministic signatures |
| **Host-order shuffling** | `--randomize-hosts` | Hosts are scanned in random order so that probes do not follow a sequential pattern |
| **Inter-probe jitter** | `--jitter SECONDS` | A random delay (0 to *N* seconds) is inserted before each probe to vary traffic timing |

### Example: scan with all WAF-bypass features enabled

```bash
ics_finder --target 10.0.0.0/16 \
           --use-misp \
           --verify-modbus \
           --banner-grab \
           --randomize-hosts \
           --jitter 0.5 \
           --timeout 30 \
           --output results.csv
```

---

## Legal & Ethical Notice

Scanning IP addresses without explicit permission may be **illegal** in your
jurisdiction.  This tool is provided for academic research, authorized
penetration testing, and thesis work only.  The authors accept no liability
for misuse.