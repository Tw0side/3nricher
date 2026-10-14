# 3nricher

[![tests](https://github.com/Tw0side/3nricher/actions/workflows/test.yml/badge.svg)](https://github.com/Tw0side/3nricher/actions/workflows/test.yml)
[![python](https://img.shields.io/badge/python-3.10%2B-blue)](https://www.python.org/)
[![license](https://img.shields.io/badge/license-MIT-green)](LICENSE)
[![last commit](https://img.shields.io/github/last-commit/Tw0side/3nricher)](https://github.com/Tw0side/3nricher/commits/main)

**Multi-source IOC enrichment pipeline for threat intelligence workflows.**

3nricher accepts Indicators of Compromise (IPs, domains, file hashes), enriches them against five threat intelligence sources in parallel, applies weighted risk scoring with a per-source rationale, and writes structured JSON and CSV reports. It is built for SOC triage, threat hunting, and detection engineering.

The tool automates the repetitive enrichment step of IOC triage, reducing per-IOC analysis time from minutes to seconds.

## Contents

- [Overview](#overview)
- [Features](#features)
- [Installation](#installation)
- [Configuration](#configuration)
- [Usage](#usage)
- [Data Sources](#data-sources)
- [Risk Scoring](#risk-scoring)
- [Enrichment History](#enrichment-history)
- [Docker](#docker)
- [Architecture](#architecture)
- [Testing](#testing)
- [Performance](#performance)
- [Known Limitations](#known-limitations)
- [Roadmap](#roadmap)
- [Version History](#version-history)
- [Contributing](#contributing)
- [License](#license)
- [Acknowledgments](#acknowledgments)

## Overview

Analysts typically spend 5 to 15 minutes per IOC checking VirusTotal, AbuseIPDB, MalwareBazaar, OTX, and similar services by hand. A phishing report with 20 IOCs can take an hour.

3nricher replaces that workflow:

1. Ingests IOCs from a file or the command line.
2. Enriches each IOC against five sources in parallel.
3. Scores risk using weighted, source-aware logic.
4. Explains every score with a per-source rationale.
5. Exports JSON and CSV for ticketing, TIP ingestion, or further analysis.

## Features

- **Five-source enrichment:** VirusTotal, AbuseIPDB, MalwareBazaar, URLhaus, AlienVault OTX.
- **Parallel processing:** `ThreadPoolExecutor` with a configurable worker count.
- **HTTP caching:** SQLite-backed cache with a 24-hour TTL (about 17x faster on repeat runs).
- **Persistent history:** every enrichment is stored in SQLite with IOC deduplication.
- **Score rationale:** each score includes an explanation of how it was reached.
- **Recency weighting:** older signals carry less weight (five-tier multiplier).
- **Source-aware floors:** confirmed malware is always rated High or above; allowlisted infrastructure is forced to Low.
- **Rate limiting:** thread-safe token bucket that respects per-API quotas.
- **Retry with backoff:** exponential backoff for HTTP 429, 5xx, and timeouts.
- **CLI query mode:** single-IOC lookup with formatted output and scriptable exit codes.
- **Test suite:** 97 automated tests with mocked HTTP; CI on Python 3.11 and 3.12.
- **Docker support:** multi-stage build, non-root user, Makefile wrappers.

## Installation

Requires Python 3.10 or later.

```bash
# Install from GitHub
pip install git+https://github.com/Tw0side/3nricher.git
```

Or install from a local clone:

```bash
git clone https://github.com/Tw0side/3nricher.git
cd 3nricher
python -m venv venv && source venv/bin/activate
pip install -e .
```

## Configuration

3nricher requires your own API keys. Provider terms of service prohibit key sharing, and free-tier limits apply per key, so keys are not bundled with the tool.

| Source | Sign up | Free tier | Required |
|--------|---------|-----------|----------|
| VirusTotal | https://www.virustotal.com/gui/my-apikey | 4 req/min, 500/day | Yes |
| AbuseIPDB | https://www.abuseipdb.com/account/api | 1,000/day | No |
| abuse.ch (MalwareBazaar, URLhaus) | https://auth.abuse.ch/ | Reasonable use | No |
| AlienVault OTX | https://otx.alienvault.com/ | 10,000/day | No |

Copy the template and add your keys:

```bash
cp .env.example .env
```

Contents of `.env`:

```ini
VT_API_KEY=your_virustotal_key_here
ABUSE_API_KEY=your_abuseipdb_key_here
ABUSE_CH_API_KEY=your_abuse_ch_key_here
OTX_API_KEY=your_otx_key_here
LOG_LEVEL=INFO
```

Create the `.env` file in the directory you run 3nricher from. Sources without a key are skipped.

## Usage

### Query a single IOC

```bash
3nricher query 8.8.8.8
3nricher query google.com
3nricher query 84c82835a5d21bbcf75a61706d8ab549
```

Example output:

```text
Enriching 8.8.8.8 ...

IOC:   8.8.8.8
Type:  ip
Risk:  Low (0)

Sources:
  virustotal     ok            0 malicious / 53 harmless
  abuseipdb      ok            0% abuse, US, Google LLC
  malwarebazaar  not_applicable (MalwareBazaar only supports file hashes)
  urlhaus        not_found
  otx            ok            0 pulses

Rationale:
  VirusTotal: 0 malicious + 0 suspicious -> +0
  AbuseIPDB: 0% abuse confidence -> +0
  MalwareBazaar: not applicable
  URLhaus: not found
  OTX: 0 community pulses -> +0
  Total: 0 (Low)

History: 2 prior enrichment(s)
  [2026-10-14 11:38:09] Low (0) - run d277562a
  [2026-10-14 11:36:12] Low (0) - run a0f1b176
```

### Enrich a file of IOCs

```bash
3nricher enrich -f iocs.txt -o report
```

This writes `report.json` and `report.csv`.

### Options

| Flag | Default | Description |
|------|---------|-------------|
| `-f, --file` | none | File of IOCs, one per line (`#` for comments) |
| `-o, --output` | `report` | Output basename; writes `<name>.json` and `<name>.csv` |
| `--workers` | `10` | Number of parallel worker threads |
| `--no-parallel` | off | Force sequential mode (for debugging) |
| `--no-persist` | off | Do not write to the history database |
| `--log-level` | `INFO` | Override the configured log level |

### Exit codes (query mode)

The `query` subcommand returns an exit code based on risk level, for use in shell scripts and automation.

| Risk | Exit code |
|------|-----------|
| Low, Medium | 0 |
| High, Critical | 1 |
| Error | 2 |

```bash
if ! 3nricher query "$IOC" > /dev/null 2>&1; then
    echo "High-risk IOC detected: $IOC"
fi
```

Note: exit code 2 (error) also evaluates as failure in the example above. Check `$?` explicitly if you need to tell errors apart from High/Critical results.

## Data Sources

| Source | IOC types | Auth | Purpose |
|--------|-----------|------|---------|
| VirusTotal | IP, domain, hash | `x-apikey` header | AV verdicts across roughly 70 engines |
| AbuseIPDB | IP | `Key` header | Abuse confidence, ISP, geolocation |
| MalwareBazaar | Hash | `Auth-Key` header | Malware family, tags, first seen |
| URLhaus | Domain, IP | `Auth-Key` header | Malicious URL hosting |
| AlienVault OTX | IP, domain, hash | `X-OTX-API-KEY` header | Community threat pulses |

### Applicability matrix

Each source declares which IOC types it supports. Unsupported combinations return a `not_applicable` status instead of sending an invalid query.

| IOC type | VirusTotal | AbuseIPDB | MalwareBazaar | URLhaus | OTX |
|----------|:----------:|:---------:|:-------------:|:-------:|:---:|
| IP | Yes | Yes | No | Yes | Yes |
| Domain | Yes | No | No | Yes | Yes |
| Hash | Yes | No | Yes | No | Yes |

## Risk Scoring

The score ranges from 0 to 100 and combines signals from all sources.

| Source | Max points | Formula |
|--------|-----------:|---------|
| VirusTotal | 50 | `min(malicious * 5 + suspicious * 2, 50)` |
| MalwareBazaar | 40 | Flat 40 for a confirmed sample |
| AbuseIPDB | 25 | `min(abuse_score * 0.25, 25) * recency` |
| URLhaus | 25 | `min(url_count * 5, 25) * recency` |
| OTX | 20 | `min(pulse_count * 2, 20)` |

**Thresholds**

| Score | Label |
|-------|-------|
| 0-19 | Low |
| 20-44 | Medium |
| 45-69 | High |
| 70-100 | Critical |

### Score floors

- A MalwareBazaar hit floors the label at High.
- An AbuseIPDB abuse score of 100 floors the label at High.

### Allowlist

Well-known clean infrastructure is forced to Low regardless of other signals.

- **IPs:** Google DNS (8.8.8.8, 8.8.4.4), Cloudflare (1.1.1.1, 1.0.0.1), Quad9 (9.9.9.9), OpenDNS.
- **Domains:** google.com, microsoft.com, cloudflare.com, amazon.com, apple.com, github.com, and their subdomains.

### Recency weighting

Time-sensitive signals (AbuseIPDB, URLhaus) are scaled by age.

| Age | Multiplier |
|-----|-----------:|
| Under 7 days | 1.0 |
| Under 30 days | 0.9 |
| Under 90 days | 0.75 |
| Under 1 year | 0.5 |
| Older | 0.3 |

## Enrichment History

Every run is stored in a local SQLite database (default: `data/3nricher.db`). This supports:

- **Verdict tracking:** detect changes such as "VirusTotal verdict moved from clean to malicious since last week".
- **IOC lifespan:** see how often an indicator has been flagged over time.
- **Audit trail:** full history for every IOC.
- **Dashboards:** the data model is the base for the planned visualization work.

Query the database directly:

```bash
sqlite3 data/3nricher.db "
  SELECT i.value, i.type, e.risk_label, e.risk_score, e.enriched_at
  FROM enrichments e
  JOIN iocs i ON i.id = e.ioc_id
  ORDER BY e.enriched_at DESC
  LIMIT 10
"
```

Or from Python:

```python
from storage.history import get_ioc_history, get_recent_runs, get_stats

history = get_ioc_history("185.220.101.1")   # all enrichments for one IOC, newest first
runs = get_recent_runs(limit=10)             # most recent batch runs
stats = get_stats()                          # summary counts
```

Use `--no-persist` to skip writing history.

## Docker

The Makefile is the simplest way to run 3nricher in a container. Each user builds the image locally. The container's non-root user is created with the builder's UID and GID, which avoids bind-mount permission errors.

```bash
make build                         # build the image
make query IOC=8.8.8.8             # query a single IOC
make enrich                        # enrich IOCs from iocs.txt
make enrich FILE=threats.txt       # enrich from a specific file
make test                          # run the test suite
```

### Why build locally

The Dockerfile accepts `UID` and `GID` build arguments:

```dockerfile
ARG UID=1000
ARG GID=1000
RUN groupadd -g "${GID}" appuser && useradd -m -u "${UID}" -g "${GID}" appuser
```

Building with `--build-arg UID=$(id -u)` gives `appuser` your UID, so bind-mounted directories stay writable. Do not use pre-built registry images, because they embed the publisher's UID.

### Manual commands

```bash
# Build with matching UID/GID
docker build \
  --build-arg UID=$(id -u) \
  --build-arg GID=$(id -g) \
  -t 3nricher:latest .

# Query one IOC
docker run --rm --env-file .env 3nricher:latest query 8.8.8.8

# Enrich a file (persistent cache and history)
mkdir -p out
docker run --rm \
  --env-file .env \
  -v 3nricher-cache:/app/cache \
  -v 3nricher-data:/app/data \
  -v $(pwd)/iocs.txt:/data/iocs.txt:ro \
  -v $(pwd)/out:/data/out \
  3nricher:latest enrich -f /data/iocs.txt -o /data/out/report
```

### Persistence

| Item | Location | Notes |
|------|----------|-------|
| Code | Baked into image | Application logic |
| Secrets (`.env`) | Injected at runtime | Never stored in the image |
| Input (`iocs.txt`) | Bind mount, read-only | Host file |
| Output (`out/`) | Bind mount, read-write | Reports visible on host |
| Cache | Named volume `3nricher-cache` | Persists across runs |
| History DB | Named volume `3nricher-data` | Persists across runs |

Remove volumes with `make clean-volumes`.

## Architecture

```text
3nricher.py            CLI orchestrator (subcommands: enrich, query)
enrichment.py          Parallel and sequential enrichment dispatcher
config.py              Central config; CWD-independent .env loading
logging_setup.py       Structured logging configuration
scoring.py             Multi-source weighted risk scoring
rationale.py           Per-IOC score explanation builder
recency.py             Age-based weighting multipliers
report.py              JSON and CSV report writers
cli.py                 Console script entry point
cli_query.py           Single-IOC query mode

sources/
  base.py              HTTP wrapper with retry and exponential backoff
  limiter.py           Thread-safe token bucket rate limiter
  virustotal.py        VirusTotal v3 API
  abuseipdb.py         AbuseIPDB v2 API
  malwarebazaar.py     MalwareBazaar API
  urlhaus.py           URLhaus API
  otx.py               AlienVault OTX API

storage/
  cache.py             SQLite-backed HTTP cache (manual hit/miss tracking)
  db.py                SQLite schema and transaction manager
  history.py           record_run, get_ioc_history, get_recent_runs, get_stats

tests/                 97 tests (pytest, responses for HTTP mocking)
```

## Testing

```bash
python -m pytest -v
```

The suite has 97 tests covering:

- Token bucket behavior (burst, throttle, timeout, invalid arguments)
- IOC type detection
- Risk scoring (floors, allowlist, caps, recency)
- Rationale formatting for all status types
- Source modules with mocked HTTP (no live API calls)
- Parallel and sequential orchestration, including order preservation
- HTTP cache (session, stats, enable/disable, path handling)
- Persistence (schema, `record_run`, deduplication, history queries, stats)
- CLI query mode (exit codes, source formatting, JSON decoding)

CI runs on every push against Python 3.11 and 3.12.

## Performance

| IOCs | Sequential | Parallel (10 workers) | Cold to warm cache |
|-----:|-----------:|----------------------:|-------------------:|
| 4 | ~22 s | ~14 s | 14.7 s to 2.6 s |
| 100 | ~25 min | ~3 min | not measured |

Throughput is bounded by the slowest API rate limit. On the VirusTotal free tier (4 requests/min), large batches are limited by that quota. Caching reduces repeat runs by about 17x.

## Known Limitations

- **Domain detection** is regex-based and not validated against the TLD list.
- **URLhaus** support is host-level only; URL-level lookups are not implemented.
- **No ATT&CK mapping.** MalwareBazaar and OTX tags are not yet mapped to MITRE techniques (planned for Iteration 6).
- **Timestamp precision** in SQLite is one second, so ordering within the same second is undefined. Adding `%f` to the schema would fix this.
- **Cache scope** is per process. Parallel instances do not share a cache; a Redis backend would be needed.

## Roadmap

| Iteration | Scope | Status |
|-----------|-------|--------|
| 1 | VirusTotal-only MVP | Done |
| 2 | Multi-source enrichment, CSV, structured logging | Done |
| 2.1 | Scoring floors, allowlist, config extraction | Done |
| 3 | Rate limiting, retry, OTX, tests, CI | Done |
| 4 | Parallel enrichment, score rationale, recency weighting | Done |
| 5 | Caching, persistence, Docker, CLI query mode, packaging | Done |
| 6 | MITRE ATT&CK mapping, three additional sources | Planned |
| 7 | PCAP input mode (Scapy) | Planned |
| 8 | Local web dashboard (FastAPI, Chart.js) | Planned |
| 9 | Live log sensor integration | Planned |

## Version History

| Tag | Iteration |
|-----|-----------|
| v0.1.0 | VirusTotal-only MVP |
| v0.2.0 | Multi-source enrichment |
| v0.2.1 | Scoring floors and allowlist |
| v0.3.0 | Rate limiting, retry, OTX, tests, CI |
| v0.4.0 | Parallel enrichment, rationale, recency |
| v0.5.0 | Caching, persistence, Docker, query mode |

To inspect an earlier release:

```bash
git checkout v0.4.0
```

## Contributing

To add a new source:

1. Create `sources/yoursource.py`.
2. Implement `query(ioc: str, ioc_type: str) -> dict`.
3. Return `{"status": "ok", ...}` or `{"status": "not_applicable", ...}`.
4. Use `safe_request()` from `sources/base.py` for HTTP calls.
5. Register the source in `enrichment.py::enrich_one()`.
6. Add tests in `tests/test_sources.py`.
7. Add the scoring weight in `scoring.py` and the explanation in `rationale.py`.

No changes to the orchestrator are required.

## License

Released under the [MIT License](LICENSE).

## Acknowledgments

- [VirusTotal](https://www.virustotal.com/): malware intelligence API
- [AbuseIPDB](https://www.abuseipdb.com/): IP reputation API
- [abuse.ch](https://abuse.ch/): MalwareBazaar and URLhaus
- [AlienVault OTX](https://otx.alienvault.com/): community threat intelligence
- [python-dotenv](https://github.com/theskumar/python-dotenv): configuration management
- [requests-cache](https://github.com/requests-cache/requests-cache): HTTP caching
- [tqdm](https://github.com/tqdm/tqdm): progress bars
