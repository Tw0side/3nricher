"""
Multi-source risk scoring for 3nricher.

Combines signals from VirusTotal, AbuseIPDB, MalwareBazaar, and URLhaus
into a single 0–100 score and a categorical label.

Design notes:
- MalwareBazaar hit always floors the label at High (confirmed malware
  should never be labeled Medium).
- AbuseIPDB abuse_score of 100 also floors at High.
- Allowlisted IOCs (well-known clean infrastructure) are forced to Low,
  overriding all other signals.
- Thresholds and weights are configurable via config.py.
"""
import logging

from config import Config

log = logging.getLogger("3nricher.scoring")


# Label ordering for floor comparisons
_LABEL_ORDER = {"Low": 0, "Medium": 1, "High": 2, "Critical": 3}


def _apply_floor(label: str, floor: str) -> str:
    """Return the higher of two labels."""
    if _LABEL_ORDER.get(floor, 0) > _LABEL_ORDER.get(label, 0):
        return floor
    return label


def _is_allowlisted(ioc: str, ioc_type: str) -> bool:
    """Check if IOC is in the allowlist."""
    if ioc_type == "ip" and ioc in Config.ALLOWLIST_IPS:
        return True
    if ioc_type == "domain":
        for allowed in Config.ALLOWLIST_DOMAINS:
            if ioc == allowed or ioc.endswith("." + allowed):
                return True
    return False


def _score_to_label(score: int) -> str:
    """Convert numeric score to categorical label."""
    if score >= Config.THRESHOLD_CRITICAL:
        return "Critical"
    if score >= Config.THRESHOLD_HIGH:
        return "High"
    if score >= Config.THRESHOLD_MEDIUM:
        return "Medium"
    return "Low"


def calculate_risk(sources: dict, ioc: str = "", ioc_type: str = "") -> tuple[int, str]:
    """
    Compute a numeric risk score (0–100) and a categorical label.

    Args:
        sources: Dict of {source_name: {"status": ..., ...}}
        ioc:     The IOC value (used for allowlist checks)
        ioc_type: The IOC type (ip, domain, md5, sha1, sha256)

    Returns:
        (score, label)
    """
    # Allowlist short-circuits everything
    if ioc and ioc_type and _is_allowlisted(ioc, ioc_type):
        log.debug("Allowlisted: %s (%s)", ioc, ioc_type)
        return 0, "Low"

    score = 0

    # ---- VirusTotal ----
    vt = sources.get("virustotal", {})
    if vt.get("status") == "ok":
        score += min(
            vt.get("malicious", 0) * Config.SCORE_VT_PER_MALICIOUS
            + vt.get("suspicious", 0) * Config.SCORE_VT_PER_SUSPICIOUS,
            Config.SCORE_VT_MAX,
        )

    # ---- AbuseIPDB ----
    abuse = sources.get("abuseipdb", {})
    if abuse.get("status") == "ok":
        score += min(
            int(abuse.get("abuse_score", 0) * Config.SCORE_ABUSE_MULTIPLIER),
            Config.SCORE_ABUSE_MAX,
        )

    # ---- MalwareBazaar ----
    mb = sources.get("malwarebazaar", {})
    if mb.get("status") == "ok":
        score += Config.SCORE_MB_HIT

    # ---- URLhaus ----
    uh = sources.get("urlhaus", {})
    if uh.get("status") == "ok":
        score += min(
            uh.get("url_count", 0) * Config.SCORE_URLHAUS_PER_URL,
            Config.SCORE_URLHAUS_MAX,
        )
        
    # ---- OTX: up to 20 pts ----
    otx = sources.get("otx", {})
    if otx.get("status") == "ok":
        pulse_count = otx.get("pulse_count", 0)
        score += min(pulse_count * 2, 20)

    # Cap
    score = min(score, 100)

    # Base label from score
    label = _score_to_label(score)

    # Apply source-based floors
    if mb.get("status") == "ok":
        label = _apply_floor(label, Config.FLOOR_MB_LABEL)
        # Bump score if MB floor changed the label
        if label == "High" and score < Config.THRESHOLD_HIGH:
            score = Config.THRESHOLD_HIGH

    if abuse.get("status") == "ok" and abuse.get("abuse_score", 0) >= 100:
        label = _apply_floor(label, Config.FLOOR_ABUSE_100_LABEL)

    return score, label
