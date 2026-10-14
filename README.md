markdown
# 3nricher

[![tests](https://github.com/Tw0side/3nricher/actions/workflows/test.yml/badge.svg)](https://github.com/Tw0side/3nricher/actions/workflows/test.yml)
[![python](https://img.shields.io/badge/python-3.10%2B-blue)](https://www.python.org/)
[![license](https://img.shields.io/badge/license-MIT-green)](LICENSE)
[![last commit](https://img.shields.io/github/last-commit/Tw0side/3nricher)](https://github.com/Tw0side/3nricher/commits/main)

**Multi-source IOC enrichment pipeline for threat intelligence workflows.**

3nricher takes Indicators of Compromise (IPs, domains, and file hashes), enriches
them against five threat intelligence sources in parallel, applies weighted risk
scoring with per-source rationale, and produces structured JSON and CSV reports
for SOC triage, threat hunting, and detection engineering.

Designed to automate the repetitive IOC enrichment step in SOC workflows, reducing
analyst time per IOC from minutes to seconds.

---

## ⚡ Quick Start

```bash
# Install from GitHub
pip install git+https://github.com/Tw0side/3nricher.git

# Or clone and install locally
git clone https://github.com/Tw0side/3nricher.git
cd 3nricher
python -m venv venv && source venv/bin/activate
pip install -e .

# Configure API keys (see below)
cp .env.example .env
# edit .env with your keys

# Run
3nricher query 8.8.8.8
🔑 API Keys — You Need Your Own
3nricher requires your own free API keys. Every threat intel API's Terms of
Service prohibits sharing keys, and free-tier limits are per-key — so bundling
keys with the tool would violate ToS and hit rate limits instantly.

All four services are free to sign up for:

Source	Sign up	Free tier	Required?
VirusTotal	https://www.virustotal.com/gui/my-apikey	4 req/min, 500/day	✅ Required
AbuseIPDB	https://www.abuseipdb.com/account/api	1,000/day	Optional
abuse.ch (MB + URLhaus)	https://auth.abuse.ch/	Reasonable use	Optional
AlienVault OTX	https://otx.alienvault.com/	10,000/day	Optional
Create a .env file in the directory you run 3nricher from:

ini
VT_API_KEY=your_virustotal_key_here
ABUSE_API_KEY=your_abuseipdb_key_here
ABUSE_CH_API_KEY=your_abuse_ch_key_here
OTX_API_KEY=your_otx_key_here
LOG_LEVEL=INFO
🎯 Why It Exists
SOC analysts spend 5–15 minutes per IOC manually checking VirusTotal, AbuseIPDB,
MalwareBazaar, OTX, and other sources in browser tabs. For a phishing report with
20 IOCs, that's an hour of copy-paste.

3nricher automates that workflow:

Ingests IOCs from a file or command line

Enriches each IOC against 5 sources in parallel

Scores risk with weighted, source-aware logic

Explains every score with a per-source rationale

Exports structured JSON + CSV for ticketing, TIP ingestion, or further analysis

Result: minutes → seconds per IOC.

🎮 Usage
Query a single IOC
bash
3nricher query 8.8.8.8
3nricher query google.com
3nricher query 84c82835a5d21bbcf75a61706d8ab549
Output:

text
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
  VirusTotal: 0 malicious + 0 suspicious → +0
  AbuseIPDB: 0% abuse confidence → +0
  MalwareBazaar: not applicable
  URLhaus: not found
  OTX: 0 community pulses → +0
  Total: 0 (Low)

History: 2 prior enrichment(s)
  [2026-10-14 11:38:09] Low (0) — run d277562a
  [2026-10-14 11:36:12] Low (0) — run a0f1b176
Enrich a file of IOCs
bash
3nricher enrich -f iocs.txt -o report
Produces report.json and report.csv.

Arguments
Flag	Default	Description
-f, --file	—	File of IOCs, one per line (# for comments)
-o, --output	report	Output basename → <name>.json + <name>.csv
--workers	10	Parallel worker threads
--no-parallel	—	Force sequential mode (debugging)
--no-persist	—	Skip writing to the history database
--log-level	INFO	Override log level
Exit codes (query mode)
The query subcommand returns exit codes based on risk level — useful for
shell scripting and automation:

Risk	Exit Code
Low / Medium	0
High / Critical	1
Error	2
Example:

bash
if ! 3nricher query "$IOC" > /dev/null 2>&1; then
    echo "High-risk IOC detected: $IOC"
fi
🔍 Sources
Source	IOC Types	Auth	Purpose
VirusTotal	IP, domain, hash	x-apikey header	AV verdicts across ~70 engines
AbuseIPDB	IP	Key header	Abuse confidence, ISP, geo
MalwareBazaar	Hash	Auth-Key header	Malware family, tags, first seen
URLhaus	Domain, IP	Auth-Key header	Malicious URL hosting
AlienVault OTX	IP, domain, hash	X-OTX-API-KEY header	Community threat pulses
Applicability Matrix
Each source self-declares which IOC types it supports. Non-applicable sources
return a not_applicable status instead of firing an invalid query.

IOC Type	VT	AbuseIPDB	MalwareBazaar	URLhaus	OTX
IP	✅	✅	⏭️	✅	✅
Domain	✅	⏭️	⏭️	✅	✅
Hash	✅	⏭️	✅	⏭️	✅
✨ Key Features
Five-source enrichment — VT, AbuseIPDB, MalwareBazaar, URLhaus, OTX

Parallel processing — ThreadPoolExecutor with configurable worker count

HTTP caching — SQLite-backed cache, 24h TTL, 17× speedup on repeat runs

Persistent history — every enrichment stored in SQLite with IOC deduplication

Score rationale — every IOC explains why it scored what it did

Recency weighting — stale signals carry less weight (5-tier multiplier)

Source-aware floors — confirmed malware always floors at High; allowlist forces Low

Token-bucket rate limiter — thread-safe, respects per-API quotas

Retry with exponential backoff — recovers from 429s, 5xx, and timeouts

CLI query mode — single-IOC lookup with formatted output

97 automated tests — mocked HTTP, CI on Python 3.11 and 3.12

Docker-ready — multi-stage build, non-root user, Makefile wrappers

📊 Performance
IOCs	Sequential	Parallel (10 workers)	Cold → Warm
4	~22s	~14s	14.7s → 2.6s
100	~25 min	~3 min	—
Parallelism is bounded by the slowest API rate limit (VirusTotal free tier:
4 req/min). Caching reduces repeat runs by ~17×.

🧮 Risk Scoring
Weighted score (0–100) combining all source signals:

Source	Max Points	Formula
VirusTotal	50	min(malicious × 5 + suspicious × 2, 50)
MalwareBazaar	40	Flat 40 if confirmed sample
AbuseIPDB	25	min(abuse_score × 0.25, 25) × recency
URLhaus	25	min(url_count × 5, 25) × recency
OTX	20	min(pulse_count × 2, 20)
Thresholds: 0–19 Low · 20–44 Medium · 45–69 High · 70–100 Critical

Score Floors
MalwareBazaar hit → label floored at High (confirmed malware never Medium)

AbuseIPDB abuse_score 100 → floored at High

Allowlist
Well-known clean infrastructure is forced to Low regardless of other signals:

IPs: Google DNS (8.8.8.8, 8.8.4.4), Cloudflare (1.1.1.1, 1.0.0.1),
Quad9 (9.9.9.9), OpenDNS

Domains: google.com, microsoft.com, cloudflare.com, amazon.com, apple.com,
github.com (and subdomains)

Recency Weighting
Age-based multipliers applied to time-sensitive signals (AbuseIPDB, URLhaus):

Age	Multiplier
< 7 days	1.0
< 30 days	0.9
< 90 days	0.75
< 1 year	0.5
Older	0.3
📚 Enrichment History
Every enrichment run is persisted to a local SQLite database
(default: data/3nricher.db). This enables:

Verdict tracking — "VT verdict changed from clean to malicious since last week"

IOC lifespan — "this IP has been flagged 20 times this month"

Audit trail — full history for every IOC

Dashboard-ready — foundation for future visualization

Query the DB directly
bash
sqlite3 data/3nricher.db "
  SELECT i.value, i.type, e.risk_label, e.risk_score, e.enriched_at
  FROM enrichments e
  JOIN iocs i ON i.id = e.ioc_id
  ORDER BY e.enriched_at DESC
  LIMIT 10
"
Or via Python
python
from storage.history import get_ioc_history, get_recent_runs, get_stats

# All enrichments for a specific IOC, newest first
history = get_ioc_history("185.220.101.1")

# Most recent batch runs
runs = get_recent_runs(limit=10)

# Summary counts
stats = get_stats()
Skip persistence with --no-persist.

🐳 Docker
The easiest way to run 3nricher is via the included Makefile. Each user must
build the image locally — the container's non-root user is built to match the
building user's UID/GID, preventing bind-mount permission issues.

Quick start
bash
make build                         # build the image
make query IOC=8.8.8.8             # query a single IOC
make enrich                        # enrich IOCs from iocs.txt
make enrich FILE=threats.txt       # enrich from a specific file
make test                          # run the local test suite
Why build locally?
The Dockerfile accepts UID and GID build args:

dockerfile
ARG UID=1000
ARG GID=1000
RUN groupadd -g "${GID}" appuser && useradd -m -u "${UID}" -g "${GID}" appuser
When you build with --build-arg UID=$(id -u), the container's appuser gets
your exact UID. Bind-mounted directories are then writable without permission
errors. Do not use pre-built images from registries — they bake in the
publisher's UID.

Manual Docker commands
If you don't have make:

bash
# Build with UID/GID matching
docker build \
  --build-arg UID=$(id -u) \
  --build-arg GID=$(id -g) \
  -t 3nricher:latest .

# Query one IOC
docker run --rm --env-file .env 3nricher:latest query 8.8.8.8

# Enrich a file (with persistent cache and history)
mkdir -p out
docker run --rm \
  --env-file .env \
  -v 3nricher-cache:/app/cache \
  -v 3nricher-data:/app/data \
  -v $(pwd)/iocs.txt:/data/iocs.txt:ro \
  -v $(pwd)/out:/data/out \
  3nricher:latest enrich -f /data/iocs.txt -o /data/out/report
What's persisted
Item	Location	Notes
Code	Baked into image	Application logic
Secrets (.env)	Injected at runtime	Never in the image
Input (iocs.txt)	Bind-mounted read-only	Host file
Output (out/)	Bind-mounted read-write	Reports visible on host
Cache	Named volume 3nricher-cache	Persists across runs
History DB	Named volume 3nricher-data	Persists across runs
Clean up volumes: make clean-volumes

🏗️ Architecture
text
3nricher.py            → CLI orchestrator (subcommands: enrich, query)
enrichment.py          → Parallel/sequential enrichment dispatcher
config.py              → Centralized config + CWD-independent .env loading
logging_setup.py       → Structured logging configuration
scoring.py             → Multi-source weighted risk scoring
rationale.py           → Per-IOC score explanation builder
recency.py             → Age-based weighting multipliers
report.py              → JSON + CSV report writers
cli.py                 → Console script entry point
cli_query.py           → Single-IOC query mode

sources/
├── base.py            → HTTP wrapper with retry + exponential backoff
├── limiter.py         → Thread-safe token bucket rate limiter
├── virustotal.py      → VT v3 API
├── abuseipdb.py       → AbuseIPDB v2 API
├── malwarebazaar.py   → MalwareBazaar API
├── urlhaus.py         → URLhaus API
└── otx.py             → AlienVault OTX API

storage/
├── cache.py           → SQLite-backed HTTP cache (manual hit/miss tracking)
├── db.py              → SQLite schema + transaction manager
└── history.py         → record_run, get_ioc_history, get_recent_runs, get_stats

tests/                 → 97 tests (pytest + responses for HTTP mocking)
🧪 Testing
bash
python -m pytest -v
97 tests covering:

Token bucket behavior (burst, throttle, timeout, invalid args)

IOC type detection

Risk scoring (floors, allowlist, caps, recency)

Rationale formatting (all status types)

Source modules with mocked HTTP (no live API calls)

Parallel/sequential orchestration and order preservation

HTTP cache (session, stats, enable/disable, path handling)

Persistence (schema, record_run, dedup, history queries, stats)

CLI query mode (exit codes, source formatting, JSON decoding)

CI runs on every push against Python 3.11 and 3.12.

⚠️ Known Limitations
Domain detection is regex-based — not TLD-validated

URLhaus URL-level support — currently host-level only

No ATT&CK mapping yet — MalwareBazaar/OTX tags aren't mapped to MITRE
techniques (planned for Iteration 6)

SQLite timestamps have 1-second precision — ordering between enrichments
in the same second is undefined (would need %f in the schema)

Cache is per-process — running multiple instances in parallel doesn't
share cache (would need Redis backend)

🗺️ Roadmap
☑ Iteration 1 — VirusTotal-only MVP
☑ Iteration 2 — Multi-source enrichment + CSV + structured logging
☑ Iteration 2.1 — Scoring floors, allowlist, config extraction
☑ Iteration 3 — Rate limiting, retry, OTX, tests, CI
☑ Iteration 4 — Parallel enrichment, score rationale, recency weighting
☑ Iteration 5 — Caching, persistence, Docker, CLI query mode, packaging
□ Iteration 6 — MITRE ATT&CK mapping, 3 additional sources
□ Iteration 7 — PCAP input mode (Scapy)
□ Iteration 8 — Local web dashboard (FastAPI + Chart.js)
□ Iteration 9 — Live log sensor integration
📜 Version History
Tag	Iteration
v0.1.0	Iteration 1 — VT-only MVP
v0.2.0	Iteration 2 — Multi-source enrichment
v0.2.1	Scoring floors + allowlist
v0.3.0	Rate limiting + retry + OTX + tests + CI
v0.4.0	Parallel + rationale + recency
v0.5.0	Caching + persistence + Docker + query mode
bash
git checkout v0.4.0    # see Iteration 4
🤝 Contributing
Adding a new source
Create sources/yoursource.py

Implement query(ioc: str, ioc_type: str) -> dict

Return {"status": "ok", ...} or {"status": "not_applicable", ...}

Use safe_request() from sources/base.py

Register in enrichment.py::enrich_one()

Add tests in tests/test_sources.py

Add scoring weight in scoring.py + rationale.py

That's the whole integration — no changes to the orchestrator.

📄 License
MIT

🙏 Acknowledgments
VirusTotal — malware intelligence API

AbuseIPDB — IP reputation API

abuse.ch — MalwareBazaar and URLhaus

AlienVault OTX — community threat intelligence

python-dotenv — config management

requests-cache — HTTP caching

tqdm — progress bars

text

---

## 🎯 What Changed vs. Iteration 4

| Section | Change |
|---------|--------|
| **Quick Start** | Now includes `pip install git+https://...` |
| **API Keys** | New section explaining why users bring their own keys |
| **Usage** | Now documents `query` subcommand with sample output |
| **Exit codes** | Documented for shell scripting |
| **Key Features** | Added caching, persistence, CLI query mode, Docker |
| **Performance** | Added cold → warm cache numbers |
| **Enrichment History** | New section on SQLite persistence |
| **Docker** | Complete section with Makefile + manual commands |
| **Architecture** | Updated tree with storage/, cli.py, cli_query.py |
| **Testing** | 59 → 97 tests |
| **Known Limitations** | Updated to reflect Iteration 5's remaining gaps |
| **Roadmap** | Iteration 5 marked complete |
| **Version History** | Added v0.5.0 |
| **Contributing** | Added storage to "how to add a source" |
| **Acknowledgments** | Added requests-cache |

---

## 🎬 Apply It

```bash
cd ~/Desktop/CTI/3nricher
nano README.md
# Select all (Ctrl+A in nano to select all might not work — use Ctrl+K repeatedly), paste the full content
# Ctrl+O, Enter to save
# Ctrl+X to exit

# Verify
wc -l README.md
head -10 README.md
Expected: ~500 lines, badges at the top.
