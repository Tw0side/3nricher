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
    2 = Error during enrichment
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

    print(f"IOC:   {result.get('ioc', '')}")
    print(f"Type:  {result.get('type', '')}")
    print(f"Risk:  {risk} ({score})")

    # Compact ATT&CK summary if any techniques were found
    attack = result.get("attack", [])
    if attack:
        ids = ", ".join(t.get("id", "") for t in attack)
        print(f"ATT&CK: {ids}")

    print()

    # ATT&CK techniques
    attack = result.get("attack", [])
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
    for name in ("virustotal", "abuseipdb", "malwarebazaar", "urlhaus", "otx","greynoise", "threatfox", "feodo"):
        s = sources.get(name, {})
        status = s.get("status", "unknown")
        detail = _source_detail(name, s)
        print(f"  {name:14s} {status:13s} {detail}")

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
