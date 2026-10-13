"""
Score rationale builder for 3nricher.

Given the source results for an IOC, produce a human-readable list of
score contributions. This is what turns a raw number into an analyst-
friendly explanation.

Example output:
    [
        "VirusTotal: 13 malicious engines → +50 (capped at 50)",
        "AbuseIPDB: 100% abuse confidence → +25",
        "OTX: 50 community pulses → +20 (capped at 20)",
        "MalwareBazaar: not applicable",
        "URLhaus: not applicable",
        "Total: 95 (Critical)",
    ]

Design:
- The rationale MUST match the scoring logic exactly. If calculate_risk
  awards 25 points for AbuseIPDB, the rationale says "+25". To keep this
  guarantee, both modules share the same weights from Config.
- Not-applicable sources are included for completeness (analysts want to
  see that a source was consulted, not silently skipped).
- Error sources are called out explicitly.
"""
import logging

from config import Config

log = logging.getLogger("3nricher.rationale")


def build_rationale(sources: dict, score: int, label: str) -> list[str]:
    """
    Build a list of human-readable rationale lines for an IOC's score.

    Args:
        sources: Dict of {source_name: {"status": ..., ...}}
        score:   Final numeric score from calculate_risk().
        label:   Final label from calculate_risk().

    Returns:
        List of strings, one per source + a final total line.
    """
    lines: list[str] = []

    # ---- VirusTotal ----
    vt = sources.get("virustotal", {})
    lines.append(_rationale_vt(vt))

    # ---- AbuseIPDB ----
    abuse = sources.get("abuseipdb", {})
    lines.append(_rationale_abuse(abuse))

    # ---- MalwareBazaar ----
    mb = sources.get("malwarebazaar", {})
    lines.append(_rationale_mb(mb))

    # ---- URLhaus ----
    uh = sources.get("urlhaus", {})
    lines.append(_rationale_urlhaus(uh))

    # ---- OTX ----
    otx = sources.get("otx", {})
    lines.append(_rationale_otx(otx))

    # Final total
    lines.append(f"Total: {score} ({label})")

    return lines


# ---------------------------------------------------------------
# Per-source rationale builders
# ---------------------------------------------------------------
def _rationale_vt(vt: dict) -> str:
    status = vt.get("status")
    if status == "not_applicable":
        return "VirusTotal: not applicable"
    if status == "not_found":
        return "VirusTotal: not found"
    if status == "error":
        return f"VirusTotal: error ({vt.get('reason', 'unknown')})"
    if status == "ok":
        malicious = vt.get("malicious", 0)
        suspicious = vt.get("suspicious", 0)
        raw = malicious * Config.SCORE_VT_PER_MALICIOUS + suspicious * Config.SCORE_VT_PER_SUSPICIOUS
        contrib = min(raw, Config.SCORE_VT_MAX)
        capped = " (capped)" if raw > Config.SCORE_VT_MAX else ""
        return (
            f"VirusTotal: {malicious} malicious + {suspicious} suspicious "
            f"→ +{contrib}{capped}"
        )
    return "VirusTotal: unknown status"


def _rationale_abuse(abuse: dict) -> str:
    status = abuse.get("status")
    if status == "not_applicable":
        return "AbuseIPDB: not applicable"
    if status == "not_found":
        return "AbuseIPDB: not found"
    if status == "error":
        return f"AbuseIPDB: error ({abuse.get('reason', 'unknown')})"
    if status == "ok":
        abuse_score = abuse.get("abuse_score", 0)
        raw = int(abuse_score * Config.SCORE_ABUSE_MULTIPLIER)
        contrib = min(raw, Config.SCORE_ABUSE_MAX)
        capped = " (capped)" if raw > Config.SCORE_ABUSE_MAX else ""
        return f"AbuseIPDB: {abuse_score}% abuse confidence → +{contrib}{capped}"
    return "AbuseIPDB: unknown status"


def _rationale_mb(mb: dict) -> str:
    status = mb.get("status")
    if status == "not_applicable":
        return "MalwareBazaar: not applicable"
    if status == "not_found":
        return "MalwareBazaar: not found"
    if status == "error":
        return f"MalwareBazaar: error ({mb.get('reason', 'unknown')})"
    if status == "ok":
        sig = mb.get("signature", "unknown")
        return f"MalwareBazaar: confirmed malware ({sig}) → +{Config.SCORE_MB_HIT}"
    return "MalwareBazaar: unknown status"


def _rationale_urlhaus(uh: dict) -> str:
    status = uh.get("status")
    if status == "not_applicable":
        return "URLhaus: not applicable"
    if status == "not_found":
        return "URLhaus: not found"
    if status == "error":
        return f"URLhaus: error ({uh.get('reason', 'unknown')})"
    if status == "ok":
        url_count = uh.get("url_count", 0)
        raw = url_count * Config.SCORE_URLHAUS_PER_URL
        contrib = min(raw, Config.SCORE_URLHAUS_MAX)
        capped = " (capped)" if raw > Config.SCORE_URLHAUS_MAX else ""
        return f"URLhaus: {url_count} malicious URLs → +{contrib}{capped}"
    return "URLhaus: unknown status"


def _rationale_otx(otx: dict) -> str:
    status = otx.get("status")
    if status == "not_applicable":
        return "OTX: not applicable"
    if status == "not_found":
        return "OTX: not found"
    if status == "error":
        return f"OTX: error ({otx.get('reason', 'unknown')})"
    if status == "ok":
        pulse_count = otx.get("pulse_count", 0)
        # OTX scoring is capped at 20 points (2 per pulse, per scoring.py)
        raw = pulse_count * 2
        contrib = min(raw, 20)
        capped = " (capped)" if raw > 20 else ""
        return f"OTX: {pulse_count} community pulses → +{contrib}{capped}"
    return "OTX: unknown status"
