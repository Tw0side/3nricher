# 3nricher

**Multi-source IOC enrichment pipeline for threat intelligence workflows.**

3nricher ingests Indicators of Compromise (IPs, domains, and file hashes), enriches 
them against four threat intelligence sources, applies weighted risk scoring, and 
produces structured JSON and CSV reports for SOC triage, threat hunting, and 
detection engineering.

Built as a portfolio project demonstrating CTI automation, multi-source API 
integration, and production-grade error handling.

---

## Status

**Iteration 2** — Multi-source enrichment with structured logging, per-source 
error isolation, and self-declaring source applicability.

See the [Roadmap](#roadmap) for what's next.

---

## Sources

| Source | IOC Types | Auth | Purpose |
|--------|-----------|------|---------|
| [VirusTotal](https://www.virustotal.com/) | IP, domain, hash | `x-apikey` header | AV verdicts across ~70 engines |
| [AbuseIPDB](https://www.abuseipdb.com/) | IP | `Key` header | Abuse confidence, ISP, geo |
| [MalwareBazaar](https://bazaar.abuse.ch/) | Hash | `Auth-Key` header | Malware family, tags, first seen |
| [URLhaus](https://urlhaus.abuse.ch/) | Domain | `Auth-Key` header | Malicious URL hosting |

Each source self-declares its applicability. Non-applicable sources return a 
`not_applicable` status instead of firing an invalid query.

---

## Key Features

- **Multi-source enrichment** — four sources, three auth patterns, one unified schema
- **Self-declaring applicability** — each source decides what IOC types it supports
- **Per-source error isolation** — one API failure never kills a run
- **Weighted risk scoring** — 0–100 score with Low / Medium / High / Critical labels
- **Structured logging** — timestamped, level-tagged, SIEM-friendly
- **Nested JSON + wide CSV** — machine-readable and analyst-friendly output
- **Production-grade config** — centralized, `.env`-driven, CWD-independent
- **Graceful degradation** — missing API keys produce warnings, not crashes

---

## Architecture
