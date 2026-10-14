#!/usr/bin/env python3
"""
3nricher — IOC Enrichment Pipeline

Iteration 5: Parallel multi-source enrichment with HTTP caching and
enrichment history persistence.

Usage:
    python 3nricher.py -f iocs.txt -o report
    python 3nricher.py -f iocs.txt --workers 20
    python 3nricher.py -f iocs.txt --no-parallel
    python 3nricher.py -f iocs.txt --no-persist
"""
import argparse
import re
import sys

from config import Config
from logging_setup import setup_logging

# Set up logging before importing enrichment so its loggers are configured
log = setup_logging()

from enrichment import enrich_all
from report import write_json, write_csv
from storage.history import record_run


# ---------------------------------------------------------------
# IOC type detection (used by enrichment.py via lazy import)
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
# CLI
# ---------------------------------------------------------------
def main():
    if not Config.VT_API_KEY:
        log.error("VT_API_KEY is required. Cannot proceed.")
        sys.exit(1)

    for warning in Config.validate():
        log.warning(warning)

    parser = argparse.ArgumentParser(
        prog="3nricher",
        description="IOC enrichment pipeline (Iteration 5: parallel + rationale + cache + persistence)",
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
    parser.add_argument(
        "--no-parallel",
        action="store_true",
        help="Disable parallel enrichment (sequential mode)",
    )
    parser.add_argument(
        "--workers",
        type=int,
        default=10,
        help="Number of parallel worker threads (default: 10)",
    )
    parser.add_argument(
        "--no-persist",
        action="store_true",
        help="Skip writing to the history database",
    )
    args = parser.parse_args()

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

    parallel = not args.no_parallel
    results = enrich_all(iocs, parallel=parallel, workers=args.workers)

    json_path = f"{args.output}.json"
    csv_path = f"{args.output}.csv"

    try:
        write_json(results, json_path)
        write_csv(results, csv_path)
    except OSError:
        sys.exit(1)

    # Persist to history DB (non-fatal if it fails)
    if not args.no_persist:
        try:
            run_id = record_run(results)
            log.info("Persisted to history DB (run_id=%s)", run_id)
        except Exception as e:
            log.warning("Failed to persist to history DB: %s", e)
    else:
        log.debug("Skipping history DB persistence (--no-persist)")

    print(f"\n[+] JSON report saved to {json_path}")
    print(f"[+] CSV report saved to {csv_path}")


if __name__ == "__main__":
    main()
