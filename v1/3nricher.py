#!/usr/bin/env python3
"""
3nricher — IOC Enrichment Pipeline
Iteration 1: VirusTotal-only enrichment with JSON output.
"""

import os
import re
import sys
import json
import argparse
from datetime import datetime

import requests
from dotenv import load_dotenv

# ---------------------------------------------------------------
# Setup
# ---------------------------------------------------------------
load_dotenv()
VT_KEY = os.getenv("VT_API_KEY")

VT_ENDPOINTS = {
    "ip": "ip_addresses",
    "domain": "domains",
    "md5": "files",
    "sha1": "files",
    "sha256": "files",
}


# ---------------------------------------------------------------
# IOC handling
# ---------------------------------------------------------------
def detect_ioc_type(ioc: str) -> str:
    """Auto-detect IOC type from its format."""
    ioc = ioc.strip()
    if re.match(r"^\d{1,3}(\.\d{1,3}){3}$", ioc):
        return "ip"
    if re.match(r"^[a-fA-F0-9]{32}$", ioc):
        return "md5"
    if re.match(r"^[a-fA-F0-9]{40}$", ioc):
        return "sha1"
    if re.match(r"^[a-fA-F0-9]{64}$", ioc):
        return "sha256"
    if re.match(r"^([a-zA-Z0-9-]+\.)+[a-zA-Z]{2,}$", ioc):
        return "domain"
    return "unknown"


def load_iocs(path: str) -> list[str]:
    """Load IOCs from a text file, ignoring blanks and comments."""
    with open(path) as f:
        return [
            line.strip()
            for line in f
            if line.strip() and not line.startswith("#")
        ]


# ---------------------------------------------------------------
# VirusTotal
# ---------------------------------------------------------------
def query_virustotal(ioc: str, ioc_type: str) -> dict:
    """Query VirusTotal for a single IOC."""
    endpoint = VT_ENDPOINTS.get(ioc_type)
    if not endpoint:
        return {"error": "unsupported type"}

    url = f"https://www.virustotal.com/api/v3/{endpoint}/{ioc}"
    headers = {"x-apikey": VT_KEY}

    try:
        r = requests.get(url, headers=headers, timeout=10)
    except requests.RequestException as e:
        return {"error": f"request failed: {e}"}

    if r.status_code == 200:
        stats = r.json()["data"]["attributes"]["last_analysis_stats"]
        return {
            "malicious": stats.get("malicious", 0),
            "suspicious": stats.get("suspicious", 0),
            "harmless": stats.get("harmless", 0),
            "undetected": stats.get("undetected", 0),
        }
    if r.status_code == 404:
        return {"error": "not found in VT"}
    if r.status_code == 401:
        return {"error": "invalid API key"}
    if r.status_code == 429:
        return {"error": "rate limited"}
    return {"error": f"http {r.status_code}"}


# ---------------------------------------------------------------
# Risk scoring
# ---------------------------------------------------------------
def calculate_risk(vt: dict) -> str:
    """Simple risk label based on VT malicious count."""
    if "error" in vt:
        return "Unknown"
    malicious = vt.get("malicious", 0)
    suspicious = vt.get("suspicious", 0)
    score = malicious * 5 + suspicious * 2
    if score >= 40:
        return "Critical"
    if score >= 15:
        return "High"
    if score >= 5:
        return "Medium"
    return "Low"


# ---------------------------------------------------------------
# Enrichment orchestration
# ---------------------------------------------------------------
def enrich_ioc(ioc: str) -> dict:
    """Enrich a single IOC. Returns a normalized dict."""
    ioc_type = detect_ioc_type(ioc)
    vt = query_virustotal(ioc, ioc_type)
    return {
        "ioc": ioc,
        "type": ioc_type,
        "vt_malicious": vt.get("malicious", 0),
        "vt_suspicious": vt.get("suspicious", 0),
        "vt_harmless": vt.get("harmless", 0),
        "risk": calculate_risk(vt),
        "error": vt.get("error", ""),
    }


def run_enrichment(iocs: list[str]) -> list[dict]:
    """Enrich a list of IOCs, printing progress."""
    results = []
    total = len(iocs)
    for i, ioc in enumerate(iocs, 1):
        print(f"[{i}/{total}] Enriching {ioc} ...", end=" ", flush=True)
        result = enrich_ioc(ioc)
        results.append(result)
        print(result["risk"])
    return results


# ---------------------------------------------------------------
# Output
# ---------------------------------------------------------------
def save_report(results: list[dict], path: str) -> None:
    """Write results to a JSON file."""
    payload = {
        "tool": "3nricher",
        "version": "0.1.0",
        "generated_at": datetime.utcnow().isoformat() + "Z",
        "total_iocs": len(results),
        "results": results,
    }
    with open(path, "w") as f:
        json.dump(payload, f, indent=2)


# ---------------------------------------------------------------
# CLI
# ---------------------------------------------------------------
def main():
    if not VT_KEY:
        print("[!] VT_API_KEY not set. Check your .env file.")
        sys.exit(1)

    parser = argparse.ArgumentParser(
        prog="3nricher",
        description="IOC enrichment pipeline (Iteration 1: VirusTotal only)",
    )
    parser.add_argument("-f", "--file", required=True, help="File of IOCs, one per line")
    parser.add_argument("-o", "--output", default="report.json", help="Output JSON path")
    args = parser.parse_args()

    print(f"[*] Loading IOCs from {args.file}")
    iocs = load_iocs(args.file)

    if not iocs:
        print("[!] No IOCs found in file.")
        sys.exit(1)

    print(f"[*] Found {len(iocs)} IOC(s). Starting enrichment...\n")
    results = run_enrichment(iocs)

    save_report(results, args.output)
    print(f"\n[+] Report saved to {args.output}")


if __name__ == "__main__":
    main()
