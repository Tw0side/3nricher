"""
Report writers for 3nricher.

Handles JSON and CSV output for enrichment results.

JSON: nested per-source structure with metadata (tool, version, timestamp).
CSV:  wide format, one row per IOC, columns flattened from all 8 sources.
"""
import csv
import json
import logging
from datetime import datetime, timezone

log = logging.getLogger("3nricher.report")


# Ordered list of sources for CSV column generation
_SOURCE_ORDER = [
    "virustotal",
    "abuseipdb",
    "malwarebazaar",
    "urlhaus",
    "otx",
    "greynoise",
    "threatfox",
    "feodo",
]


def _build_payload(results: list[dict]) -> dict:
    """Build the JSON payload wrapper with metadata."""
    from storage.cache import cache_stats
    from attck_loader import stats as attck_stats

    return {
        "tool": "3nricher",
        "version": "0.7.0",
        "generated_at": datetime.now(timezone.utc).isoformat().replace("+00:00", "Z"),
        "total_iocs": len(results),
        "sources_queried": _SOURCE_ORDER,
        "cache_stats": cache_stats(),
        "attck_stats": attck_stats(),
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
        # Core
        "ioc", "type", "risk", "risk_score", "confidence",
        "attack_ids", "rationale",
        # VirusTotal
        "vt_status", "vt_malicious", "vt_suspicious", "vt_harmless",
        # AbuseIPDB
        "abuse_status", "abuse_score", "abuse_country", "abuse_isp", "abuse_reports",
        # MalwareBazaar
        "mb_status", "mb_signature", "mb_file_type", "mb_first_seen",
        # URLhaus
        "uh_status", "uh_url_count", "uh_threat",
        # OTX
        "otx_status", "otx_pulses",
        # GreyNoise (Iteration 6)
        "gn_status", "gn_classification", "gn_name",
        # ThreatFox (Iteration 6)
        "tf_status", "tf_malware", "tf_threat_type", "tf_confidence",
        # Feodo (Iteration 6)
        "feodo_status", "feodo_malware", "feodo_detail",
        # Errors
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
                gn = sources.get("greynoise", {})
                tf = sources.get("threatfox", {})
                fe = sources.get("feodo", {})

                errors = [
                    f"{name}: {s.get('reason', 'unknown')}"
                    for name, s in sources.items()
                    if s.get("status") == "error"
                ]

                writer.writerow({
                    # Core
                    "ioc": r.get("ioc", ""),
                    "type": r.get("type", ""),
                    "risk": r.get("risk", ""),
                    "risk_score": r.get("risk_score", ""),
                    "confidence": r.get("confidence", ""),
                    "attack_ids": ";".join(t.get("id", "") for t in r.get("attack", [])),
                    "rationale": " | ".join(r.get("rationale", [])),

                    # VirusTotal
                    "vt_status": vt.get("status", ""),
                    "vt_malicious": vt.get("malicious", ""),
                    "vt_suspicious": vt.get("suspicious", ""),
                    "vt_harmless": vt.get("harmless", ""),

                    # AbuseIPDB
                    "abuse_status": abuse.get("status", ""),
                    "abuse_score": abuse.get("abuse_score", ""),
                    "abuse_country": abuse.get("country", ""),
                    "abuse_isp": abuse.get("isp", ""),
                    "abuse_reports": abuse.get("total_reports", ""),

                    # MalwareBazaar
                    "mb_status": mb.get("status", ""),
                    "mb_signature": mb.get("signature", ""),
                    "mb_file_type": mb.get("file_type", ""),
                    "mb_first_seen": mb.get("first_seen", ""),

                    # URLhaus
                    "uh_status": uh.get("status", ""),
                    "uh_url_count": uh.get("url_count", ""),
                    "uh_threat": uh.get("threat", ""),

                    # OTX
                    "otx_status": otx.get("status", ""),
                    "otx_pulses": otx.get("pulse_count", ""),

                    # GreyNoise
                    "gn_status": gn.get("status", ""),
                    "gn_classification": gn.get("classification", ""),
                    "gn_name": gn.get("name", ""),

                    # ThreatFox
                    "tf_status": tf.get("status", ""),
                    "tf_malware": tf.get("malware", ""),
                    "tf_threat_type": tf.get("threat_type", ""),
                    "tf_confidence": tf.get("confidence_level", ""),

                    # Feodo
                    "feodo_status": fe.get("status", ""),
                    "feodo_malware": fe.get("malware", ""),
                    "feodo_detail": fe.get("status_detail", ""),

                    # Errors
                    "errors": "; ".join(errors),
                })

        log.info("Wrote CSV report: %s", path)
    except OSError as e:
        log.error("Failed to write CSV report %s: %s", path, e)
        raise
