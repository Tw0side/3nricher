# 3nricher

[![tests](https://github.com/Tw0side/3nricher/actions/workflows/test.yml/badge.svg)](https://github.com/Tw0side/3nricher/actions/workflows/test.yml)
[![python](https://img.shields.io/badge/python-3.10%2B-blue)](https://www.python.org/)
[![license](https://img.shields.io/badge/license-MIT-green)](LICENSE)
[![last commit](https://img.shields.io/github/last-commit/Tw0side/3nricher)](https://github.com/Tw0side/3nricher/commits/main)

**Multi-source IOC enrichment pipeline for threat intelligence workflows.**

3nricher ingests Indicators of Compromise (IPs, domains, and file hashes), enriches 
them against five threat intelligence sources, applies weighted risk scoring with 
per-source rationale, and produces structured JSON and CSV reports for SOC triage, 
threat hunting, and detection engineering.

Designed to automate the repetitive IOC enrichment step in SOC workflows, reducing 
analyst time per IOC from minutes to seconds.

---

## ⚡ Quick Start

```bash
git clone https://github.com/Tw0side/3nricher.git
cd 3nricher
python -m venv venv && source venv/bin/activate
pip install -r requirements.txt
cp .env.example .env    # add your API keys
python 3nricher.py -f iocs.txt -o report
