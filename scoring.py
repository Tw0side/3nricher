"""
Multi-source risk scoring for 3nricher.

Combines signals from 8 threat intel sources into a single 0–100 score
and a categorical label.

Design notes:
- Zero-signal IOCs (no source returned meaningful data) get label "Unknown".
  * "VT returned ok with 0 verdicts" counts as no data. The "undetected"
    field counts engines that haven't analyzed the IOC — not meaningful.
  * "OTX returned ok with 0 pulses" counts as no data (no community signal).
- MalwareBazaar hit always floors the label at High.
- AbuseIPDB abuse_score of 100 also floors at High.
- ThreatFox C2 hit floors at High.
- Feodo C2 hit floors at High.
- Allowlisted IOCs (well-known clean infrastructure) are forced to Low.
- VirusTotal uses a HYBRID score:
    * Detection RATIO (0-30 pts) rewards proportional confidence
    * Absolute MALICIOUS COUNT (0-20 pts) rewards multiple independent
      detections — a real signal even at low ratio
  This prevents both false-positive escalation (1/92 detections) and
  false-negative dismissal (13/92 detections on genuinely malicious domains).
- Thresholds and weights are configurable via config.py.
"""
import logging

from config import Config
from recency import recency_multiplier

log = logging.getLogger("3nricher.scoring")


# Label ordering for floor comparisons
_LABEL_ORDER = {
    "Unknown": -1,
    "Low": 0,
    "Medium": 1,
    "High": 2,
    "Critical": 3,
}


# ---------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------
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


def _vt_has_meaningful_data(vt: dict) -> bool:
    """
    Return True if VT has actually analyzed the IOC.

    VT returns status: "ok" with 0 verdicts for domains it has indexed
    but not yet analyzed. The "undetected" field counts engines that
    haven't produced a verdict — it is NOT meaningful data.

    Meaningful data = at least one engine said malicious, suspicious,
    or harmless. "undetected" is deliberately excluded.
    """
    malicious = vt.get("malicious", 0)
    suspicious = vt.get("suspicious", 0)
    harmless = vt.get("harmless", 0)
    return (malicious + suspicious + harmless) > 0


def _otx_has_meaningful_data(otx: dict) -> bool:
    """
    Return True if OTX has a real community signal for the IOC.

    OTX returns status: "ok" with 0 pulses for IOCs it has indexed but
    nobody has reported. That's not meaningful data.
    """
    return otx.get("pulse_count", 0) > 0


def _has_any_source_data(sources: dict) -> bool:
    """
    Return True if at least one source returned meaningful data.

    Sources that return "ok" but have no actual signal are treated
    as no data for the purposes of the Unknown verdict:

    - VT with 0 verdicts = indexed but not analyzed
    - OTX with 0 pulses = community hasn't reported anything

    All errors, not_found, and not_applicable statuses count as no data.
    """
    for name, s in sources.items():
        if s.get("status") != "ok":
            continue

        # VT: 0 verdicts = no data
        if name == "virustotal" and not _vt_has_meaningful_data(s):
            continue

        # OTX: 0 pulses = no community signal
        if name == "otx" and not _otx_has_meaningful_data(s):
            continue

        # Any other source returning "ok" is meaningful
        return True

    return False


def _vt_hybrid_score(vt: dict) -> int:
    """
    Compute VT contribution using a HYBRID of ratio + absolute count.

    - Ratio component (0-30 pts): proportional to fraction of engines
      that flagged the IOC
    - Count component (0-20 pts): rewards absolute malicious detections
      since multiple independent AVs agreeing is a real signal

    Examples:
        1/92 (1%)      → 0 + 2  = 2 pts
        10/92 (11%)    → 3 + 10 = 13 pts
        13/92 (15%)    → 4 + 13 = 17 pts
        30/92 (33%)    → 10 + 20 = 30 pts
        50/92 (54%)    → 16 + 20 = 36 pts
        62/92 (67%)    → 20 + 20 = 40 pts
    """
    malicious = vt.get("malicious", 0)
    suspicious = vt.get("suspicious", 0)
    harmless = vt.get("harmless", 0)
    undetected = vt.get("undetected", 0)

    total = malicious + suspicious + harmless + undetected
    if total == 0:
        return 0

    # Ratio component (0-30 pts)
    weighted = malicious + (suspicious * 0.5)
    ratio = weighted / total
    ratio_score = ratio * 30

    # Count component (0-20 pts)
    if malicious >= 3:
        count_score = min(malicious, 20)
    else:
        count_score = malicious * 2

    return int(ratio_score + count_score)


# ---------------------------------------------------------------
# Confidence indicator
# ---------------------------------------------------------------
def compute_confidence(sources: dict) -> str:
    """
    Compute a confidence indicator based on how many sources contributed.

    Returns one of: "High", "Medium", "Low", "None"

    - High: >= 80% of applicable sources returned meaningful data
    - Medium: >= 50% of applicable sources returned meaningful data
    - Low: < 50% returned data (but at least 1)
    - None: no applicable source returned meaningful data
    """
    applicable = [
        s for s in sources.values()
        if s.get("status") != "not_applicable"
    ]
    if not applicable:
        return "None"

    # Count sources with meaningful data (same logic as _has_any_source_data)
    def _counts(name: str, s: dict) -> bool:
        if s.get("status") != "ok":
            return False
        if name == "virustotal" and not _vt_has_meaningful_data(s):
            return False
        if name == "otx" and not _otx_has_meaningful_data(s):
            return False
        return True

    with_data = [name for name, s in sources.items() if _counts(name, s)]

    if not with_data:
        return "None"

    ratio = len(with_data) / len(applicable)
    if ratio >= 0.8:
        return "High"
    if ratio >= 0.5:
        return "Medium"
    return "Low"


# ---------------------------------------------------------------
# Main scoring
# ---------------------------------------------------------------
def calculate_risk(
    sources: dict,
    ioc: str = "",
    ioc_type: str = "",
) -> tuple[int, str]:
    """
    Compute a numeric risk score (0–100) and a categorical label.

    Args:
        sources: Dict of {source_name: {"status": ..., ...}}
        ioc:     The IOC value (used for allowlist checks)
        ioc_type: The IOC type (ip, domain, md5, sha1, sha256)

    Returns:
        (score, label) where label is one of:
            Unknown, Low, Medium, High, Critical
    """
    # ---- 1. Allowlist short-circuits everything ----
    if ioc and ioc_type and _is_allowlisted(ioc, ioc_type):
        log.debug("Allowlisted: %s (%s)", ioc, ioc_type)
        return 0, "Low"

    # ---- 2. Unknown verdict for zero-signal IOCs ----
    if not _has_any_source_data(sources):
        log.debug("Zero-signal IOC (no source returned meaningful data): %s", ioc)
        return 0, "Unknown"

    # ---- 3. Compute weighted score ----
    score = 0

    # VirusTotal (hybrid ratio + count)
    vt = sources.get("virustotal", {})
    if vt.get("status") == "ok" and _vt_has_meaningful_data(vt):
        score += _vt_hybrid_score(vt)

    # AbuseIPDB (with recency weighting)
    abuse = sources.get("abuseipdb", {})
    if abuse.get("status") == "ok":
        raw = min(
            int(abuse.get("abuse_score", 0) * Config.SCORE_ABUSE_MULTIPLIER),
            Config.SCORE_ABUSE_MAX,
        )
        mult = recency_multiplier(abuse.get("last_reported"))
        score += int(raw * mult)

    # MalwareBazaar
    mb = sources.get("malwarebazaar", {})
    if mb.get("status") == "ok":
        score += Config.SCORE_MB_HIT

    # URLhaus (with recency weighting)
    uh = sources.get("urlhaus", {})
    if uh.get("status") == "ok":
        raw = min(
            uh.get("url_count", 0) * Config.SCORE_URLHAUS_PER_URL,
            Config.SCORE_URLHAUS_MAX,
        )
        mult = recency_multiplier(uh.get("first_seen"))
        score += int(raw * mult)

    # OTX (only count pulses)
    otx = sources.get("otx", {})
    if otx.get("status") == "ok":
        score += min(otx.get("pulse_count", 0) * 2, 20)

    # GreyNoise
    gn = sources.get("greynoise", {})
    if gn.get("status") == "ok":
        classification = gn.get("classification", "")
        if classification == "malicious":
            score += 15
        elif classification == "unknown":
            score += 5

    # ThreatFox
    tf = sources.get("threatfox", {})
    if tf.get("status") == "ok":
        score += 30

    # Feodo
    fe = sources.get("feodo", {})
    if fe.get("status") == "ok":
        score += 25

    # Cap
    score = min(score, 100)

    # ---- 4. Base label from score ----
    label = _score_to_label(score)

    # ---- 5. Apply source-based floors ----
    if mb.get("status") == "ok":
        label = _apply_floor(label, Config.FLOOR_MB_LABEL)
        if label == "High" and score < Config.THRESHOLD_HIGH:
            score = Config.THRESHOLD_HIGH

    if abuse.get("status") == "ok" and abuse.get("abuse_score", 0) >= 100:
        label = _apply_floor(label, Config.FLOOR_ABUSE_100_LABEL)

    if tf.get("status") == "ok":
        label = _apply_floor(label, "High")
        if label == "High" and score < Config.THRESHOLD_HIGH:
            score = Config.THRESHOLD_HIGH

    if fe.get("status") == "ok":
        label = _apply_floor(label, "High")
        if label == "High" and score < Config.THRESHOLD_HIGH:
            score = Config.THRESHOLD_HIGH

    return score, label
