"""
Report writers for 3nricher.

Handles JSON and CSV output for enrichment results.

JSON: nested per-source structure with metadata (tool, version, timestamp).
CSV:  wide format, one row per IOC, columns flattened from all sources.
"""
import csv
import json
import logging
from datetime import datetime, timezone

log = logging.getLogger("3nricher.report")


def _build_payload(results: list[dict]) -> dict:
    """Build the JSON payload wrapper with metadata."""
    return {
        "tool": "3nricher",
        "version": "0.4.0",
        "generated_at": datetime.now(timezone.utc).isoformat().replace("+00:00", "Z"),
        "total_iocs": len(results),
        "sources_queried": [
            "virustotal", "abuseipdb", "malwarebazaar", "urlhaus", "otx",
        ],
        "results": results,
    }


def write_json(results: list[dict], path: str) -> None:
    """
    Write results as pretty-printed JSON.

    Args:
        results: List of enriched IOC dicts.
        path:    Output file path.
    """
    payload = _build_payload(results)
    try:
        with open(path, "w", encoding="utf-8") as f:
            json.dump(payload, f, indent=2, ensure_ascii=False)
        log.info("Wrote JSON report: %s", path)
    except OSError as e:
        log.error("Failed to write JSON report %s: %s", path, e)
        raise


def write_csv(results: list[dict], path: str) -> None:
    """
    Write results as a wide CSV — one row per IOC.

    Columns are flattened from the nested source structure. Non-applicable
    sources leave their columns empty. Any source errors are collected into
    a single "errors" column.
    """
    fieldnames = [
        "ioc", "type", "risk", "risk_score","rationale",
        "vt_status", "vt_malicious", "vt_suspicious", "vt_harmless",
        "abuse_status", "abuse_score", "abuse_country", "abuse_isp", "abuse_reports",
        "mb_status", "mb_signature", "mb_file_type", "mb_first_seen",
        "uh_status", "uh_url_count", "uh_threat","otx_status", "otx_pulses",
        "errors",
    ]

    try:
        with open(path, "w", newline="", encoding="utf-8") as f:
            writer = csv.DictWriter(f, fieldnames=fieldnames)
            writer.writeheader()

            for r in results:
                sources = r.get("sources", {})
                vt = sources.get("virustotal", {})
                abuse = sources.get("abuseipdb", {})
                mb = sources.get("malwarebazaar", {})
                uh = sources.get("urlhaus", {})
                otx = sources.get("otx", {})

                errors = [
                    f"{name}: {s.get('reason', 'unknown')}"
                    for name, s in sources.items()
                    if s.get("status") == "error"
                ]

                writer.writerow({
                    "ioc": r.get("ioc", ""),
                    "type": r.get("type", ""),
                    "risk": r.get("risk", ""),
                    "risk_score": r.get("risk_score", ""),
                    "rationale": " | ".join(r.get("rationale", [])),
                    "vt_status": vt.get("status", ""),
                    "vt_malicious": vt.get("malicious", ""),
                    "vt_suspicious": vt.get("suspicious", ""),
                    "vt_harmless": vt.get("harmless", ""),
                    "abuse_status": abuse.get("status", ""),
                    "abuse_score": abuse.get("abuse_score", ""),
                    "abuse_country": abuse.get("country", ""),
                    "abuse_isp": abuse.get("isp", ""),
                    "abuse_reports": abuse.get("total_reports", ""),
                    "mb_status": mb.get("status", ""),
                    "mb_signature": mb.get("signature", ""),
                    "mb_file_type": mb.get("file_type", ""),
                    "mb_first_seen": mb.get("first_seen", ""),
                    "uh_status": uh.get("status", ""),
                    "uh_url_count": uh.get("url_count", ""),
                    "uh_threat": uh.get("threat", ""),
                    "otx_status": otx.get("status", ""),
                    "otx_pulses": otx.get("pulse_count", ""),
                    "errors": "; ".join(errors),
                })

        log.info("Wrote CSV report: %s", path)
    except OSError as e:
        log.error("Failed to write CSV report %s: %s", path, e)
        raise
