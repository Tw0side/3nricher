# 3nricher

IOC enrichment pipeline. Takes IOCs (IPs, domains, file hashes) from a file, 
enriches them via VirusTotal, and outputs a structured JSON report with risk labels.

## Status
**Iteration 1 (MVP)** — VirusTotal-only enrichment.

## Features
- Auto-detects IOC type (IP, domain, MD5, SHA1, SHA256)
- Queries VirusTotal API v3
- Risk labels: Low / Medium / High / Critical
- JSON report with metadata

## Install
\`\`\`bash
git clone <your-repo>
cd 3nricher
python -m venv venv
source venv/bin/activate    # or venv\Scripts\activate on Windows
pip install -r requirements.txt
cp .env.example .env         # then add your VT_API_KEY
\`\`\`

## Usage
\`\`\`bash
python 3nricher.py -f iocs.txt -o report.json
\`\`\`

## Roadmap
- [x] Iteration 1: VirusTotal only
- [ ] Iteration 2: AbuseIPDB + AlienVault OTX, CSV output, rate limiting
- [ ] Iteration 3: PCAP mode
- [ ] Iteration 4: MISP export / Sigma rule generation

## Limitations
- VT free tier: 4 requests/min, 500/day
- No caching yet (same IOC hits API every time)
- No concurrency

## License
MIT
