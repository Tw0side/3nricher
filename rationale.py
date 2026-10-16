"""
Score rationale builder for 3nricher.

Given the source results for an IOC, produce a human-readable list of
score contributions. This is what turns a raw number into an analyst-
friendly explanation.

Example output:
    [
        "VirusTotal: 30/63 malicious (48%) → +30",
        "AbuseIPDB: 100% abuse confidence → +25",
        "MalwareBazaar: not applicable",
        "URLhaus: not applicable",
        "OTX: 50 community pulses → +20 (capped)",
        "GreyNoise: not applicable",
        "ThreatFox: not_found",
        "Feodo: not applicable",
        "Total: 75 (Critical)",
    ]

Design:
- The rationale MUST match the scoring logic exactly. If calculate_risk
  awards 25 points for AbuseIPDB, the rationale says "+25". To keep this
  guarantee, both modules share the same weights from Config, and this
  module imports _vt_hybrid_score directly from scoring.py.
- Not-applicable sources are included for completeness (analysts want to
  see that a source was consulted, not silently skipped).
- Error sources are called out explicitly.
- If label is "Unknown", the total line explains why.
- Allowlisted IOCs get a short, clean rationale — no per-source noise.
"""
import logging

from config import Config

log = logging.getLogger("3nricher.rationale")


def build_rationale(
    sources: dict,
    score: int,
    label: str,
    ioc: str = "",
    ioc_type: str = "",
) -> list[str]:
    """
    Build a list of human-readable rationale lines for an IOC's score.

    Args:
        sources:  Dict of {source_name: {"status": ..., ...}}
        score:    Final numeric score from calculate_risk().
        label:    Final label from calculate_risk().
        ioc:      Optional IOC value, used for allowlist check.
        ioc_type: Optional IOC type, used for allowlist check.

    Returns:
        List of strings, one per source + a final total line.
    """
    # ---- Allowlist short-circuits the rationale ----
    # If the IOC is allowlisted, calculate_risk() returns (0, "Low") without
    # examining sources. The rationale should match — no per-source noise.
    if ioc and ioc_type:
        from scoring import _is_allowlisted
        if _is_allowlisted(ioc, ioc_type):
            return [
                f"Allowlisted: {ioc} ({ioc_type})",
                "Total: 0 (Low — allowlisted)",
            ]

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

    # ---- GreyNoise ----
    gn = sources.get("greynoise", {})
    lines.append(_rationale_greynoise(gn))

    # ---- ThreatFox ----
    tf = sources.get("threatfox", {})
    lines.append(_rationale_threatfox(tf))

    # ---- Feodo ----
    fe = sources.get("feodo", {})
    lines.append(_rationale_feodo(fe))

    # ---- Final total ----
    if label == "Unknown":
        lines.append(
            f"Total: {score} (Unknown — no source returned data)"
        )
    else:
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
        harmless = vt.get("harmless", 0)
        undetected = vt.get("undetected", 0)

        total = malicious + suspicious + harmless + undetected

        # If no engine has actually produced a verdict, VT has no data
        if (malicious + suspicious + harmless) == 0:
            return "VirusTotal: no engine verdicts (not yet analyzed)"

        # Use the SAME hybrid scoring function as scoring.py
        from scoring import _vt_hybrid_score
        contrib = _vt_hybrid_score(vt)

        weighted = malicious + (suspicious * 0.5)
        ratio = weighted / total
        ratio_pct = int(ratio * 100)

        return (
            f"VirusTotal: {malicious}/{total} malicious "
            f"({ratio_pct}%) → +{contrib}"
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
        raw = pulse_count * 2
        contrib = min(raw, 20)
        capped = " (capped)" if raw > 20 else ""
        return f"OTX: {pulse_count} community pulses → +{contrib}{capped}"
    return "OTX: unknown status"


def _rationale_greynoise(gn: dict) -> str:
    status = gn.get("status")
    if status == "not_applicable":
        return "GreyNoise: not applicable"
    if status == "not_found":
        return "GreyNoise: not found"
    if status == "error":
        return f"GreyNoise: error ({gn.get('reason', 'unknown')})"
    if status == "ok":
        classification = gn.get("classification", "")
        scanner_name = gn.get("name", "")

        if classification == "malicious":
            contrib = 15
        elif classification == "unknown":
            contrib = 5
        else:
            contrib = 0

        label = classification or "unknown"
        # Only append scanner name if it's actually useful
        if scanner_name and scanner_name.lower() not in ("unknown", ""):
            label = f"{label} ({scanner_name})"

        return f"GreyNoise: {label} → +{contrib}"
    return "GreyNoise: unknown status"


def _rationale_threatfox(tf: dict) -> str:
    status = tf.get("status")
    if status == "not_applicable":
        return "ThreatFox: not applicable"
    if status == "not_found":
        return "ThreatFox: not found"
    if status == "error":
        return f"ThreatFox: error ({tf.get('reason', 'unknown')})"
    if status == "ok":
        malware = tf.get("malware", "unknown")
        threat_type = tf.get("threat_type", "")
        detail = malware
        if threat_type:
            detail = f"{malware} ({threat_type})"
        return f"ThreatFox: {detail} → +30"
    return "ThreatFox: unknown status"


def _rationale_feodo(fe: dict) -> str:
    status = fe.get("status")
    if status == "not_applicable":
        return "Feodo: not applicable"
    if status == "not_found":
        return "Feodo: not found"
    if status == "error":
        return f"Feodo: error ({fe.get('reason', 'unknown')})"
    if status == "ok":
        malware = fe.get("malware", "unknown")
        status_detail = fe.get("status_detail", "")
        detail = malware
        if status_detail:
            detail = f"{malware} ({status_detail})"
        return f"Feodo: {detail} → +25"
    return "Feodo: unknown status"
