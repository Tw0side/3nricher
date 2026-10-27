"""
CLI query mode for 3nricher.

Handles the `3nricher query <ioc>` subcommand — enriching a single IOC
and printing a human-readable summary to stdout.

Unlike the batch `enrich` mode, this:
- Prints to stdout (not to report files)
- Shows prior enrichment history from the DB if available
- Returns an exit code based on the risk level (for scripting)

Exit codes:
    0 = Low or Medium risk
    1 = High or Critical risk
    2 = Unknown or error
"""
import logging
import sys

from enrichment import enrich_one
from storage.history import get_ioc_history

log = logging.getLogger("3nricher.cli_query")


# Exit codes by risk level (for shell scripting)
_EXIT_CODES = {
    "Low": 0,
    "Medium": 0,
    "High": 1,
    "Critical": 1,
    "Unknown": 2,
}


def run_query(ioc: str, show_history: bool = True) -> int:
    """
    Enrich a single IOC and print a formatted summary.

    Args:
        ioc:           The IOC to enrich.
        show_history:  If True, show prior enrichments from the DB.

    Returns:
        Exit code (0/1/2).
    """
    ioc = ioc.strip()
    if not ioc:
        print("ERROR: empty IOC", file=sys.stderr)
        return 2

    print(f"Enriching {ioc} ...\n")

    try:
        result = enrich_one(ioc)
    except Exception as e:
        print(f"ERROR: enrichment failed: {e}", file=sys.stderr)
        return 2

    _print_summary(result)

    if show_history:
        _print_history(ioc)

    return _EXIT_CODES.get(result.get("risk", "Unknown"), 2)


# ---------------------------------------------------------------
# Formatting
# ---------------------------------------------------------------
def _print_summary(result: dict) -> None:
    """Print the enrichment summary."""
    risk = result.get("risk", "Unknown")
    score = result.get("risk_score", 0)
    confidence = result.get("confidence", "Unknown")

    print(f"IOC:         {result.get('ioc', '')}")
    print(f"Type:        {result.get('type', '')}")
    print(f"Risk:        {risk} ({score})")
    print(f"Confidence:  {confidence}")

    # Compact ATT&CK summary if any techniques were found
    attack = result.get("attack", [])
    if attack:
        ids = ", ".join(t.get("id", "") for t in attack)
        print(f"ATT&CK:      {ids}")

    print()

    # ATT&CK techniques
    if attack:
        print("MITRE ATT&CK:")
        for tech in attack:
            tech_id = tech.get("id", "")
            name = tech.get("name", "")
            tactic = tech.get("tactic", "")
            source = tech.get("source", "")
            tactic_str = f" [{tactic}]" if tactic else ""
            print(f"  {tech_id:12s} {name}{tactic_str}")
            if source:
                print(f"               Source: {source}")
        print()

    # Sources
    print("Sources:")
    sources = result.get("sources", {})
    for name in (
        "virustotal", "abuseipdb", "malwarebazaar", "urlhaus", "otx",
        "greynoise", "threatfox", "feodo",
    ):
        s = sources.get(name, {})
        status = s.get("status", "unknown")
        detail = _source_detail(name, s)
        print(f"  {name:14s} {status:13s} {detail}")

    print()
    # Freshness
    freshness = result.get("freshness", {})
    f_status = freshness.get("status", "unknown")
    f_detail = _freshness_detail(freshness)
    print(f"Freshness:   {f_status:13s} {f_detail}")

    print()
    # Rationale
    print("Rationale:")
    for line in result.get("rationale", []):
        print(f"  {line}")


def _source_detail(name: str, s: dict) -> str:
    """Return a human-readable detail string for a source result."""
    status = s.get("status")

    if status == "not_applicable":
        return f"({s.get('reason', 'not applicable')})"
    if status == "not_found":
        return ""
    if status == "error":
        return f"({s.get('reason', 'error')})"
    if status != "ok":
        return ""

    # Source-specific formatting
    if name == "virustotal":
        return (
            f"{s.get('malicious', 0)} malicious / "
            f"{s.get('harmless', 0)} harmless"
        )
    if name == "abuseipdb":
        return (
            f"{s.get('abuse_score', 0)}% abuse, "
            f"{s.get('country', '')}, {s.get('isp', '')}"
        )
    if name == "malwarebazaar":
        sig = s.get("signature", "unknown")
        return f"signature: {sig}"
    if name == "urlhaus":
        return f"{s.get('url_count', 0)} malicious URLs"
    if name == "otx":
        return f"{s.get('pulse_count', 0)} pulses"

    # ---- Iteration 6 sources ----
    if name == "greynoise":
        classification = s.get("classification", "unknown")
        scanner_name = s.get("name", "")
        if scanner_name:
            return f"{classification} ({scanner_name})"
        return classification

    if name == "threatfox":
        malware = s.get("malware", "")
        threat_type = s.get("threat_type", "")
        if malware and threat_type:
            return f"{malware} ({threat_type})"
        return malware or threat_type

    if name == "feodo":
        malware = s.get("malware", "")
        status_detail = s.get("status_detail", "")
        if malware and status_detail:
            return f"{malware} ({status_detail})"
        return malware

    return ""


def _print_history(ioc: str) -> None:
    """Print prior enrichments for this IOC, if any."""
    try:
        history = get_ioc_history(ioc, limit=5)
    except Exception as e:
        log.debug("Failed to read history for %s: %s", ioc, e)
        return

    if not history:
        return

    print()
    print(f"History: {len(history)} prior enrichment(s)")
    for h in history[:5]:
        ts = h.get("enriched_at", "")
        label = h.get("risk_label", "")
        score = h.get("risk_score", "")
        run = h.get("run_id", "")[:8]
        print(f"  [{ts}] {label} ({score}) — run {run}")
def _freshness_detail(f: dict) -> str:
    """Return a human-readable detail string for a freshness result."""
    status = f.get("status")

    if status == "ok":
        points = f.get("points", 0)
        if f.get("source") == "ipinfo":
            geo = f.get("geo") or {}
            parts = [f"{f.get('asn', '')} {f.get('as_name', '')}".strip()]
            place = ", ".join(
                p for p in (geo.get("city"), geo.get("region"),
                            geo.get("country")) if p
            )
            if place:
                parts.append(place)
            loc = geo.get("loc", "")
            if loc:
                lat, _, lon = loc.partition(",")
                parts.append(f"{lat},{lon}")
            if f.get("flag") == "bulletproof_asn":
                parts.append("BULLETPROOF ASN")
            return f"{' · '.join(parts)} (+{points})"
        age = f.get("age_days", 0)
        date = f.get("date", "unknown")
        return f"registered {date} ({age} days old, +{points})"
    if status == "not_found":
        return f"({f.get('reason', 'not found')})"
    if status == "error":
        return f"({f.get('reason', 'error')})"
    if status == "not_applicable":
        return f"({f.get('reason', 'not applicable')})"
    return ""


if __name__ == "__main__":
    if len(sys.argv) < 2:
        print("Usage: python cli_query.py <ioc>", file=sys.stderr)
        sys.exit(2)
    sys.exit(run_query(sys.argv[1]))
