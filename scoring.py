"""
Multi-source risk scoring for 3nricher.

Combines signals from VirusTotal, AbuseIPDB, MalwareBazaar, and URLhaus
into a single 0–100 score and a categorical label.

Weighting rationale:
- VirusTotal dominates (50 pts) — aggregates ~70 AV engines, strongest signal
- MalwareBazaar (40 pts flat) — a confirmed malware sample is very high confidence
- AbuseIPDB (25 pts) — strong but subject to false positives from researchers
- URLhaus (25 pts) — indicates active malicious hosting

Final score is capped at 100.
"""
import logging

log = logging.getLogger("3nricher.scoring")


def calculate_risk(sources: dict) -> tuple[int, str]:
    """
    Compute a numeric risk score (0–100) and a categorical label.

    Args:
        sources: Dict of {source_name: {"status": ..., ...}}

    Returns:
        (score, label) — label is one of: Low, Medium, High, Critical
    """
    score = 0

    # ---- VirusTotal: up to 50 pts ----
    vt = sources.get("virustotal", {})
    if vt.get("status") == "ok":
        malicious = vt.get("malicious", 0)
        suspicious = vt.get("suspicious", 0)
        score += min(malicious * 5 + suspicious * 2, 50)

    # ---- AbuseIPDB: up to 25 pts ----
    abuse = sources.get("abuseipdb", {})
    if abuse.get("status") == "ok":
        abuse_score = abuse.get("abuse_score", 0)
        score += min(int(abuse_score * 0.25), 25)

    # ---- MalwareBazaar: 40 pts flat if found ----
    mb = sources.get("malwarebazaar", {})
    if mb.get("status") == "ok":
        score += 40

    # ---- URLhaus: up to 25 pts ----
    uh = sources.get("urlhaus", {})
    if uh.get("status") == "ok":
        url_count = uh.get("url_count", 0)
        score += min(url_count * 5, 25)

    # Cap at 100
    score = min(score, 100)

    # Categorize
    if score >= 70:
        label = "Critical"
    elif score >= 45:
        label = "High"
    elif score >= 20:
        label = "Medium"
    else:
        label = "Low"

    return score, label
