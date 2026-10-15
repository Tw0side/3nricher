"""
ATT&CK technique mapper.

Given a dict of per-source enrichment results, extract malware family
names and ATT&CK-relevant tags, look them up in the YAML mappings, and
return a deduplicated list of techniques with provenance.

Usage:
    from attck import map_to_attck

    techniques = map_to_attck(sources_dict)
    # [
    #   {"id": "T1486", "name": "Data Encrypted for Impact",
    #    "tactic": "impact", "source": "malwarebazaar:WannaCry"},
    #   ...
    # ]
"""
import logging

from attck_loader import lookup_by_name

log = logging.getLogger("3nricher.attck")


# Sources that return malware family names we can look up
# Format: (source_key, field_name)
MALWARE_NAME_SOURCES = [
    ("malwarebazaar", "signature"),
    ("threatfox", "malware"),
]


def _extract_candidates(sources: dict) -> list[tuple[str, str]]:
    """
    Extract candidate (name, source) tuples from source data.

    Returns a list of (raw_name, source_label) tuples, e.g.:
        [("WannaCry", "malwarebazaar"), ("ransomware", "otx")]
    """
    candidates: list[tuple[str, str]] = []

    # Malware family names from MalwareBazaar, ThreatFox, etc.
    for source_key, field_name in MALWARE_NAME_SOURCES:
        src = sources.get(source_key, {})
        if src.get("status") != "ok":
            continue

        value = src.get(field_name, "")
        if value and isinstance(value, str):
            candidates.append((value, source_key))

    # Tags from OTX pulses
    otx = sources.get("otx", {})
    if otx.get("status") == "ok":
        for tag in otx.get("tags", []) or []:
            if tag and isinstance(tag, str):
                candidates.append((tag, "otx"))

    return candidates


def map_to_attck(sources: dict) -> list[dict]:
    """
    Map enriched source data to ATT&CK techniques.

    Args:
        sources: dict of {source_name: {"status": ..., ...}}

    Returns:
        A list of technique dicts, deduplicated by technique ID.
        Each entry includes:
            - id: ATT&CK technique ID (e.g., "T1486")
            - name: technique name
            - tactic: optional ATT&CK tactic
            - source: provenance string (e.g., "malwarebazaar:WannaCry")
    """
    techniques: list[dict] = []
    seen_ids: set[str] = set()

    candidates = _extract_candidates(sources)

    for raw_name, source_label in candidates:
        mapping = lookup_by_name(raw_name)
        if not mapping:
            continue

        for tech in mapping.get("techniques", []):
            tech_id = tech.get("id")
            if not tech_id or tech_id in seen_ids:
                continue

            seen_ids.add(tech_id)
            techniques.append({
                "id": tech_id,
                "name": tech.get("name", ""),
                "tactic": tech.get("tactic", ""),
                "source": f"{source_label}:{raw_name}",
            })

    # Sort by technique ID for deterministic output
    techniques.sort(key=lambda t: t["id"])

    return techniques


def format_techniques(techniques: list[dict]) -> str:
    """
    Format a list of techniques for CLI display.

    Example output:
        T1486        Data Encrypted for Impact              (malwarebazaar:WannaCry)
        T1529        System Shutdown/Reboot                 (malwarebazaar:WannaCry)
    """
    if not techniques:
        return "  (none)"

    lines = []
    for t in techniques:
        tech_id = t.get("id", "")
        name = t.get("name", "")
        source = t.get("source", "")
        lines.append(f"  {tech_id:12s} {name:40s} ({source})")
    return "\n".join(lines)
