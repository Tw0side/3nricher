# 3nricher

[![tests](https://github.com/Tw0side/3nricher/actions/workflows/test.yml/badge.svg)](https://github.com/Tw0side/3nricher/actions/workflows/test.yml)
[![python](https://img.shields.io/badge/python-3.10%2B-blue)](https://www.python.org/)
[![license](https://img.shields.io/badge/license-MIT-green)](LICENSE)
[![last commit](https://img.shields.io/github/last-commit/Tw0side/3nricher)](https://github.com/Tw0side/3nricher/commits/main)

**Multi-source IOC enrichment pipeline with MITRE ATT&CK mapping.**

3nricher takes Indicators of Compromise (IPs, domains, file hashes), enriches them
against nine threat intelligence sources in parallel, applies weighted risk scoring
with a per-source rationale, and maps detected malware families to MITRE ATT&CK
techniques. It writes structured JSON and CSV reports for SOC triage, threat
hunting, and detection engineering.

It automates the repetitive IOC lookup step in SOC workflows and cuts analyst time
per IOC from minutes to seconds.

## Table of Contents

- [Features](#features)
- [Quick Start](#quick-start)
- [Configuration](#configuration)
- [Usage](#usage)
- [Sources](#sources)
- [IP Freshness and Geolocation](#ip-freshness-and-geolocation)
- [MITRE ATT&CK Mapping](#mitre-attck-mapping)
- [Risk Scoring](#risk-scoring)
- [Output Formats](#output-formats)
- [Enrichment History](#enrichment-history)
- [Docker](#docker)
- [Architecture](#architecture)
- [Testing](#testing)
- [Known Limitations](#known-limitations)
- [Roadmap](#roadmap)
- [Version History](#version-history)
- [Contributing](#contributing)
- [License](#license)
- [Acknowledgments](#acknowledgments)

## Features

- **Parallel enrichment** across 9 threat intelligence sources
- **Weighted risk scoring** with a per-source, human-readable rationale
- **Unknown verdict** that separates "no data" from "clean"
- **Confidence indicator** showing how many applicable sources returned data
- **MITRE ATT&CK mapping** from malware family to technique, with provenance
- **Allowlist and score floors** to cut false positives and false negatives
- **Recency weighting** for time-sensitive signals
- **IP geolocation and freshness scoring** via IPinfo (ASN, org, city, coordinates, bulletproof-hosting detection)
- **JSON and CSV export** for ticketing, TIP ingestion, or analysis
- **Local SQLite history** and response caching
- **Script-friendly exit codes** for pipelines and automation

## Quick Start

```bash
# Install from GitHub
pip install git+[https://github.com/Tw0side/3nricher.git](https://github.com/Tw0side/3nricher.git)

# Or clone and install locally
git clone [https://github.com/Tw0side/3nricher.git](https://github.com/Tw0side/3nricher.git)
cd 3nricher
python -m venv venv && source venv/bin/activate
pip install -e .

# Add your API keys
cp .env.example .env
# edit .env

# Run
3nricher query 8.8.8.8
```

## Configuration

3nricher needs **your own** API keys. Threat intelligence provider terms prohibit
key sharing, and free-tier limits apply per key, so keys are not bundled.

| Source | Sign up | Free tier | Required |
|--------|---------|-----------|----------|
| VirusTotal | https://www.virustotal.com/gui/my-apikey | 4 req/min, 500/day | Yes |
| AbuseIPDB | https://www.abuseipdb.com/account/api | 1,000/day | No |
| abuse.ch (MalwareBazaar, URLhaus, ThreatFox, Feodo) | https://auth.abuse.ch/ | Reasonable use | No |
| AlienVault OTX | https://otx.alienvault.com/ | 10,000/day | No |
| GreyNoise | https://viz.greynoise.io/account/ | 50/week | No |
| IPinfo | https://ipinfo.io/account/token | Unlimited Lite, 50,000/month Core | No |

Create a `.env` file in the directory you run 3nricher from:

```ini
VT_API_KEY=your_virustotal_key_here
ABUSE_API_KEY=your_abuseipdb_key_here
ABUSE_CH_API_KEY=your_abuse_ch_key_here
OTX_API_KEY=your_otx_key_here
GREYNOISE_API_KEY=your_greynoise_key_here
IPINFO_API_KEY=your_ipinfo_token_here
LOG_LEVEL=INFO
```

Sources without a key are skipped. Only VirusTotal is required.

## Usage

### Query a single IOC

```bash
3nricher query 8.8.8.8
3nricher query google.com
3nricher query 84c82835a5d21bbcf75a61706d8ab549
```

Example output:

```text
IOC:         84c82835a5d21bbcf75a61706d8ab549
Type:        md5
Risk:        Critical (100)
Confidence:  Medium
ATT&CK:      T1210, T1218.011, T1486, T1529

MITRE ATT&CK:
  T1210        Exploitation of Remote Services [lateral-movement]
               Source: malwarebazaar:WannaCry
  T1218.011    System Binary Proxy Execution: Rundll32 [defense-evasion]
               Source: malwarebazaar:WannaCry
  T1486        Data Encrypted for Impact [impact]
               Source: malwarebazaar:WannaCry
  T1529        System Shutdown/Reboot [impact]
               Source: malwarebazaar:WannaCry

Sources:
  virustotal     ok            66 malicious / 0 harmless
  abuseipdb      not_applicable (AbuseIPDB only supports IPs)
  malwarebazaar  ok            signature: WannaCry
  urlhaus        not_applicable (URLhaus supports domains and IPs only)
  otx            ok            50 pulses
  greynoise      not_applicable (GreyNoise only supports IPs)
  threatfox      not_found
  feodo          not_applicable (Feodo Tracker only supports IPs)
  ipinfo         not_applicable (IPinfo only supports IPs)

Rationale:
  VirusTotal: 66/71 malicious (92%) -> +47
  AbuseIPDB: not applicable
  MalwareBazaar: confirmed malware (WannaCry) -> +40
  URLhaus: not applicable
  OTX: 50 community pulses -> +20 (capped)
  GreyNoise: not applicable
  ThreatFox: not found
  Feodo: not applicable
  Total: 100 (Critical)
```

### Enrich a file of IOCs

```bash
3nricher enrich -f iocs.txt -o report
```

Writes `report.json` and `report.csv`.

### Options

| Flag | Default | Description |
|------|---------|-------------|
| `-f, --file` | | File of IOCs, one per line (`#` for comments) |
| `-o, --output` | `report` | Output basename, writes `<name>.json` and `<name>.csv` |
| `--workers` | `10` | Parallel worker threads |
| `--no-parallel` | | Force sequential mode (debugging) |
| `--no-persist` | | Skip writing to the history database |
| `--log-level` | `INFO` | Override the log level |

### Exit codes (query mode)

| Risk | Exit code |
|------|-----------|
| Low, Medium | 0 |
| High, Critical | 1 |
| Unknown, Error | 2 |

Shell example:

```bash
if ! 3nricher query "$IOC" > /dev/null 2>&1; then
    echo "High-risk IOC detected: $IOC"
fi
```

## Sources

| Source | IOC types | Auth | Purpose |
|--------|-----------|------|---------|
| [VirusTotal](https://www.virustotal.com/) | IP, domain, hash | `x-apikey` header | AV verdicts across ~70 engines |
| [AbuseIPDB](https://www.abuseipdb.com/) | IP | `Key` header | Abuse confidence, ISP, geolocation |
| [MalwareBazaar](https://bazaar.abuse.ch/) | Hash | `Auth-Key` header | Malware family, tags, first seen |
| [URLhaus](https://urlhaus.abuse.ch/) | Domain, IP | `Auth-Key` header | Malicious URL hosting |
| [AlienVault OTX](https://otx.alienvault.com/) | IP, domain, hash | `X-OTX-API-KEY` header | Community threat pulses |
| [GreyNoise](https://www.greynoise.io/) | IP | `key` header | Mass scanner vs. targeted activity |
| [ThreatFox](https://threatfox.abuse.ch/) | IP, domain, hash | `Auth-Key` header | Malware C2 tracking |
| [Feodo Tracker](https://feodotracker.abuse.ch/) | IP | `Auth-Key` header | Botnet C2 blocklist |
| [IPinfo](https://ipinfo.io/) | IP | `token` param | ASN, organization, geolocation, freshness |

### Applicability matrix

Each source declares which IOC types it supports. Unsupported pairs return
`not_applicable` and are excluded from scoring and confidence.

| IOC type | VT | AbuseIPDB | MB | URLhaus | OTX | GreyNoise | ThreatFox | Feodo | IPinfo |
|----------|:--:|:---------:|:--:|:-------:|:---:|:---------:|:---------:|:-----:|:------:|
| IP | Yes | Yes | No | Yes | Yes | Yes | Yes | Yes | Yes |
| Domain | Yes | No | No | Yes | Yes | No | Yes | No | No |
| Hash | Yes | No | Yes | No | Yes | No | Yes | No | No |

## IP Freshness and Geolocation

IPs get a freshness score based on ASN reputation via IPinfo:

- **Bulletproof-hosting ASNs** (M247, Selectel, FlokiNET, and similar) score **0**
  and are flagged `bulletproof_asn`.
- All other IPs score **50**.
- The CLI freshness line shows ASN, organization, city/region/country, and
  lat/long coordinates.

Example:

```text
Freshness:   ok            AS55933 Cloudie Limited · Tung Chung, Islands, HK · 22.29,113.94 (+50)
```

Geolocation reflects the IP's registered network location, not necessarily the
user's physical location.

## MITRE ATT&CK Mapping

3nricher maps malware family names and threat intelligence tags to ATT&CK
techniques, turning a raw IOC into detection-ready intelligence.

### How it works

1. **Extract candidates** from MalwareBazaar signatures, ThreatFox, and OTX tags.
2. **Look up mappings** in a curated YAML mapping table.
3. **Deduplicate** into a unique technique set with provenance.
4. **Report** via an `attack` field in JSON, `attack_ids` in CSV, and an ATT&CK
   section in `query` output.

### Mapping table

```text
attck_mappings/
├── README.md           Schema documentation
├── official/           Maintained by the project
│   ├── wannacry.yaml
│   ├── lockbit.yaml
│   ├── emotet.yaml
│   ├── qakbot.yaml
│   └── cobalt_strike.yaml
└── community/          Community contributions
    └── _template.yaml
```

Each file maps one malware family to techniques:

```yaml
malware: wannacry
aliases:
  - wannacrypt
  - wcry
category: ransomware
references:
  - [https://attack.mitre.org/software/S0366/](https://attack.mitre.org/software/S0366/)
techniques:
  - id: T1486
    name: Data Encrypted for Impact
    tactic: impact
  - id: T1529
    name: System Shutdown/Reboot
    tactic: impact
```

To add a mapping, see [`attck_mappings/README.md`](attck_mappings/README.md) and
place your YAML file in `attck_mappings/community/`.

## Risk Scoring

Each IOC gets a weighted score from 0 to 100.

| Source | Max points | Formula |
|--------|:----------:|---------|
| VirusTotal | 50 | Hybrid: ratio (0-30) + count (0-20) |
| MalwareBazaar | 40 | Flat 40 if confirmed sample (floors at High) |
| ThreatFox | 30 | Flat 30 if C2 tracked (floors at High) |
| AbuseIPDB | 25 | `min(abuse_score * 0.25, 25) * recency` |
| URLhaus | 25 | `min(url_count * 5, 25) * recency` |
| Feodo | 25 | Flat 25 if in blocklist (floors at High) |
| OTX | 20 | `min(pulse_count * 2, 20)` |
| GreyNoise | 15 | Flat 15 if classification is `malicious` |

### Thresholds

| Score | Label | Suggested action |
|-------|-------|------------------|
| 70-100 | Critical | Block and investigate |
| 45-69 | High | Investigate |
| 20-44 | Medium | Monitor |
| 0-19 | Low | Log |

### Unknown verdict

When no source returns meaningful data, the verdict is **Unknown**, not Low.

- **Low**: sources say the IOC looks clean.
- **Unknown**: there is no data to judge.

A source counts as meaningful when:

| Source | Meaningful when |
|--------|-----------------|
| VirusTotal | At least one engine produced a verdict (malicious, suspicious, or harmless) |
| OTX | `pulse_count > 0` |
| All others | `status == "ok"` |

| IOC | Verdict | Reason |
|-----|---------|--------|
| `8.8.8.8` | Low | VirusTotal analyzed it, 53 engines say harmless |
| `kjfuwyce.kr` | Unknown | VirusTotal indexed it but has no verdicts |
| `103.97.131.179` | High | ThreatFox flagged it as PureRAT C2 |

> **Unknown does not mean safe.** It means the tool has no data. Investigate
> manually or behaviorally.

### VirusTotal hybrid scoring

VirusTotal combines two components:

- **Ratio (0-30 pts):** proportional to malicious engines over total engines.
- **Count (0-20 pts):** rewards the absolute number of malicious detections.

This avoids both false-positive escalation (1/92 no longer scores like 50/92) and
false-negative dismissal (13/92 on a truly malicious domain no longer scores like
1/92).

| Detections | Score |
|-----------|:-----:|
| 1/92 | +2 |
| 10/92 | +13 |
| 13/92 | +17 |
| 30/92 | +29 |
| 50/92 | +36 |
| 62/92 | +40 |

### Confidence indicator

Confidence reports how many applicable sources returned meaningful data.

| Confidence | Rule |
|-----------|------|
| High | 80% or more of applicable sources returned data |
| Medium | 50% or more |
| Low | Under 50%, but at least one |
| None | No applicable source returned data |

Read it with the verdict: *Critical (Low confidence)* means investigate before
escalating. *Critical (High confidence)* means act.

### Score floors

These signals set a minimum label of **High**:

- MalwareBazaar hit
- AbuseIPDB `abuse_score` of 100
- ThreatFox C2 hit
- Feodo C2 hit

### Allowlist

Well-known clean infrastructure is forced to **Low** regardless of other signals.

- **IPs:** Google DNS (8.8.8.8, 8.8.4.4), Cloudflare (1.1.1.1, 1.0.0.1), Quad9
  (9.9.9.9), OpenDNS
- **Domains:** google.com, microsoft.com, cloudflare.com, amazon.com, apple.com,
  github.com (including subdomains)

### Recency weighting

Time-sensitive signals (AbuseIPDB, URLhaus) are scaled by age.

| Age | Multiplier |
|-----|:----------:|
| Under 7 days | 1.0 |
| Under 30 days | 0.9 |
| Under 90 days | 0.75 |
| Under 1 year | 0.5 |
| Older | 0.3 |

## Output Formats

### JSON (excerpt)

```json
{
  "ioc": "84c82835a5d21bbcf75a61706d8ab549",
  "type": "md5",
  "risk": "Critical",
  "risk_score": 100,
  "confidence": "Medium",
  "attack": [
    {"id": "T1486", "name": "Data Encrypted for Impact", "tactic": "impact",
     "source": "malwarebazaar:WannaCry"},
    {"id": "T1529", "name": "System Shutdown/Reboot", "tactic": "impact",
     "source": "malwarebazaar:WannaCry"}
  ],
  "sources": { "...": "..." }
}
```

### CSV (core columns)

```text
ioc,type,risk,risk_score,confidence,attack_ids,rationale,...
84c82835a5d21bbcf75a61706d8ab549,md5,Critical,100,Medium,T1210;T1218.011;T1486;T1529,...
```

## Enrichment History

Every run is saved to a local SQLite database (default: `data/3nricher.db`).

```python
from storage.history import get_ioc_history, get_recent_runs, get_stats

history = get_ioc_history("185.220.101.1")   # all enrichments for one IOC
runs = get_recent_runs(limit=10)             # most recent runs
stats = get_stats()                          # summary counts
```

Use `--no-persist` to skip saving.

## Docker

Use the included Makefile. **Build the image locally.** The container user is
created with your UID and GID, which avoids bind-mount permission problems.

```bash
make build                         # build the image
make query IOC=8.8.8.8             # query a single IOC
make enrich                        # enrich IOCs from iocs.txt
make enrich FILE=threats.txt       # enrich from a specific file
make test                          # run the test suite
```

See the `Makefile` for all commands.

## Architecture

```text
3nricher.py            CLI orchestrator (enrich and query subcommands)
enrichment.py          Parallel and sequential dispatcher
cli.py                 Console script entry point
cli_query.py           Single-IOC formatted output
attck.py               ATT&CK technique mapper
attck_loader.py        YAML mapping loader
scoring.py             Weighted risk scoring
rationale.py           Score explanation
recency.py             Age-based multipliers
freshness.py           Domain age and IP ASN freshness scoring
report.py              JSON and CSV writers
config.py              Centralized configuration
logging_setup.py       Structured logging

sources/               9 source modules, base.py, limiter.py
storage/               SQLite cache and enrichment history
attck_mappings/        YAML mappings (official and community)
tests/                 207 tests
```

## Testing

```bash
python -m pytest -v
```

207 tests cover IOC detection, scoring, rationale, recency, all 9 sources, ATT&CK
mapping, caching, persistence, and query mode. All HTTP responses are mocked. CI
runs on Python 3.11 and 3.12.

## Known Limitations

- **Reputation blind spot.** Fresh IOCs (new domains, cloud IPs, new hashes) may
  return Unknown because no source has data yet. Iteration 7b added WHOIS domain
  age and IPinfo ASN classification and geolocation to address this for domains
  and IPs.
- **Regex-based domain detection.** Domains are not TLD-validated.
- **URLhaus is host-level only.** URL-level lookups are not supported.
- **SQLite timestamps have 1-second precision.** Order between same-second
  enrichments is undefined.
- **Per-process cache.** Multiple instances do not share a cache.
- **Curated ATT&CK mappings.** 5 malware families are mapped. PRs welcome.
- **No recency weighting for VirusTotal or MalwareBazaar.** A known sample stays
  known.
- **IP geolocation is network-level.** Coordinates reflect the IP's registered
  network location, not a precise device location.

## Roadmap

- [x] **Iteration 1:** VirusTotal-only MVP
- [x] **Iteration 2:** Multi-source, CSV export, structured logging
- [x] **Iteration 2.1:** Scoring floors, allowlist
- [x] **Iteration 3:** Rate limiting, retry, OTX, tests, CI
- [x] **Iteration 4:** Parallel enrichment, score rationale, recency
- [x] **Iteration 5:** Caching, persistence, Docker, query mode, packaging
- [x] **Iteration 6:** MITRE ATT&CK mapping, GreyNoise, ThreatFox, Feodo
- [x] **Iteration 7a:** Unknown verdict, hybrid VT scoring, confidence indicator
- [x] **Iteration 7b:** Freshness detection (WHOIS domain age, IPinfo ASN classification and geolocation)
- [ ] **Iteration 7c:** PCAP input mode (Scapy)
- [ ] **Iteration 8:** Local web dashboard (FastAPI, Chart.js)
- [ ] **Iteration 9:** Live log sensor integration
- [ ] **Iteration 10:** Community scaffolding, PyPI publishing

## Version History

| Tag | Iteration |
|-----|-----------|
| `v0.1.0` | Iteration 1: VirusTotal-only MVP |
| `v0.2.0` | Iteration 2: Multi-source |
| `v0.2.1` | Scoring floors and allowlist |
| `v0.3.0` | Rate limiting, retry, OTX, tests, CI |
| `v0.4.0` | Parallel enrichment, rationale, recency |
| `v0.5.0` | Caching, persistence, Docker, query mode |
| `v0.6.0` | MITRE ATT&CK mapping and 3 new sources |
| `v0.7.1` | Iteration 7a.1: hybrid VT scoring, Unknown verdict, confidence |
| `v0.7.2` | Iteration 7b.2: IPinfo source, IP geolocation, bulletproof ASN freshness scoring |

## Contributing

Contributions are welcome.

### Add a source

1. Create `sources/yoursource.py`.
2. Implement `query(ioc: str, ioc_type: str) -> dict`.
3. Register it in `enrichment.py::enrich_one()`.
4. Add tests in `tests/test_sources.py`.

### Add an ATT&CK mapping

See [`attck_mappings/README.md`](attck_mappings/README.md). Put community
mappings in `attck_mappings/community/`.

## License

Released under the [MIT License](LICENSE).

## Acknowledgments

- [VirusTotal](https://www.virustotal.com/): malware intelligence
- [AbuseIPDB](https://www.abuseipdb.com/): IP reputation
- [abuse.ch](https://abuse.ch/): MalwareBazaar, URLhaus, ThreatFox, Feodo Tracker
- [AlienVault OTX](https://otx.alienvault.com/): community threat intelligence
- [GreyNoise](https://www.greynoise.io/): scanner classification
- [IPinfo](https://ipinfo.io/): IP geolocation and ASN data
- [MITRE ATT&CK](https://attack.mitre.org/): technique framework
- [python-dotenv](https://github.com/theskumar/python-dotenv)
- [requests-cache](https://github.com/requests-cache/requests-cache)
- [tqdm](https://github.com/tqdm/tqdm)
