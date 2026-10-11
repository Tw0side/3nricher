#!/usr/bin/env python3
"""
3nricher — IOC Enrichment Pipeline

Iteration 2: Multi-source enrichment across VirusTotal, AbuseIPDB,
MalwareBazaar, and URLhaus. Produces nested JSON and wide CSV reports
with weighted risk scoring.

Usage:
    python 3nricher.py -f iocs.txt -o report
"""
import argparse
import re
import sys
import time

from config import Config
from logging_setup import setup_logging

# Set up logging before importing sources so their loggers are configured
log = setup_logging()

from sources import virustotal, abuseipdb, malwarebazaar, urlhaus, otx
from scoring import calculate_risk
from report import write_json, write_csv


# ---------------------------------------------------------------
# IOC type detection
# ---------------------------------------------------------------
def detect_ioc_type(ioc: str) -> str:
    """
    Auto-detect IOC type from its format.

    Returns one of: ip, md5, sha1, sha256, domain, unknown
    """
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
    """
    Load IOCs from a text file.

    - One IOC per line
    - Blank lines ignored
    - Lines starting with '#' are comments
    """
    try:
        with open(path, encoding="utf-8") as f:
            return [
                line.strip()
                for line in f
                if line.strip() and not line.startswith("#")
            ]
    except OSError as e:
        log.error("Failed to read IOC file %s: %s", path, e)
        raise


# ---------------------------------------------------------------
# Enrichment
# ---------------------------------------------------------------
def enrich_ioc(ioc: str) -> dict:
    """
    Enrich a single IOC across all sources.

    Each source self-declares applicability; the orchestrator does
    not need per-source logic.
    """
    ioc_type = detect_ioc_type(ioc)

    sources_result = {
        "virustotal": virustotal.query(ioc, ioc_type),
        "abuseipdb": abuseipdb.query(ioc, ioc_type),
        "malwarebazaar": malwarebazaar.query(ioc, ioc_type),
        "urlhaus": urlhaus.query(ioc, ioc_type),
        "otx": otx.query(ioc, ioc_type),
    }

    score, risk = calculate_risk(sources_result, ioc=ioc, ioc_type=ioc_type)

    return {
        "ioc": ioc,
        "type": ioc_type,
        "risk": risk,
        "risk_score": score,
        "sources": sources_result,
    }


def run_enrichment(iocs: list[str]) -> list[dict]:
    """
    Enrich a list of IOCs sequentially, printing progress to stdout.

    Sleeps between VT calls to respect the free-tier rate limit
    (4 requests/minute → 16 second gap).
    """
    results = []
    total = len(iocs)

    for i, ioc in enumerate(iocs, 1):
        if i > 1:
            log.debug("Sleeping %ds to respect VT rate limit", Config.VT_SLEEP_SECONDS)
            time.sleep(Config.VT_SLEEP_SECONDS)

        print(f"[{i}/{total}] Enriching {ioc} ...", end=" ", flush=True)
        result = enrich_ioc(ioc)
        results.append(result)
        print(f"{result['risk']} ({result['risk_score']})")

    return results


# ---------------------------------------------------------------
# CLI
# ---------------------------------------------------------------
def main():
    # Fail fast if VT key is missing (required)
    if not Config.VT_API_KEY:
        log.error("VT_API_KEY is required. Cannot proceed.")
        sys.exit(1)

    # Warn about optional missing keys
    for warning in Config.validate():
        log.warning(warning)

    parser = argparse.ArgumentParser(
        prog="3nricher",
        description="IOC enrichment pipeline (Iteration 2: multi-source)",
    )
    parser.add_argument(
        "-f", "--file",
        required=True,
        help="File of IOCs, one per line (# for comments)",
    )
    parser.add_argument(
        "-o", "--output",
        default="report",
        help="Output basename, no extension (default: report)",
    )
    parser.add_argument(
        "--log-level",
        default=None,
        help="Override log level: DEBUG, INFO, WARNING, ERROR",
    )
    args = parser.parse_args()

    # If user passed --log-level, reconfigure logging
    if args.log_level:
        setup_logging(args.log_level)

    log.info("Loading IOCs from %s", args.file)
    try:
        iocs = load_iocs(args.file)
    except OSError:
        sys.exit(1)

    if not iocs:
        log.error("No IOCs found in %s", args.file)
        sys.exit(1)

    log.info("Found %d IOC(s). Starting enrichment...", len(iocs))

    results = run_enrichment(iocs)

    json_path = f"{args.output}.json"
    csv_path = f"{args.output}.csv"

    try:
        write_json(results, json_path)
        write_csv(results, csv_path)
    except OSError:
        sys.exit(1)

    print(f"\n[+] JSON report saved to {json_path}")
    print(f"[+] CSV report saved to {csv_path}")


if __name__ == "__main__":
    main()
