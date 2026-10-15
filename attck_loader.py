"""
ATT&CK mapping loader.

Loads all YAML files from attck_mappings/ at import time, builds a
normalized lookup dictionary, and exposes functions to query it.

The loader normalizes keys (lowercase, strip punctuation) so that
variants like "WannaCry", "wannacry", and "WANNACRY" all match.

Usage:
    from attck_loader import lookup_by_name, all_malware_names

    mapping = lookup_by_name("wannacry")
    if mapping:
        for tech in mapping["techniques"]:
            print(tech["id"], tech["name"])
"""
import logging
import re
from pathlib import Path

import yaml

log = logging.getLogger("3nricher.attck_loader")


# Directory layout
PROJECT_ROOT = Path(__file__).resolve().parent
MAPPINGS_DIR = PROJECT_ROOT / "attck_mappings"


# In-memory caches (populated on first access)
_name_lookup: dict[str, dict] | None = None   # normalized name → mapping dict
_loaded_files: list[Path] = []


def _normalize(name: str) -> str:
    """
    Normalize a malware name or tag for lookup.

    - Lowercase
    - Strip surrounding whitespace
    - Replace underscores/hyphens with spaces
    - Collapse multiple spaces
    - Strip common prefixes/suffixes
    """
    if not name:
        return ""

    name = name.strip().lower()
    name = re.sub(r"[_\-]+", " ", name)          # underscores/hyphens → spaces
    name = re.sub(r"\s+", " ", name)             # collapse whitespace
    name = name.strip()

    # Strip common malware naming prefixes
    for prefix in ("win.", "win32.", "win64.", "osx.", "linux.", "android."):
        if name.startswith(prefix):
            name = name[len(prefix):]

    return name


def _load_file(path: Path) -> dict | None:
    """
    Load a single YAML mapping file.

    Returns the parsed dict, or None on error.
    """
    try:
        data = yaml.safe_load(path.read_text(encoding="utf-8"))
    except yaml.YAMLError as e:
        log.warning("YAML parse error in %s: %s", path.name, e)
        return None
    except OSError as e:
        log.warning("Failed to read %s: %s", path.name, e)
        return None

    if not isinstance(data, dict):
        log.warning("Skipping %s — not a dict", path.name)
        return None

    if "malware" not in data or "techniques" not in data:
        log.warning("Skipping %s — missing required fields", path.name)
        return None

    return data


def _load_all() -> dict[str, dict]:
    """
    Load all YAML files from official/ and community/ directories.

    Returns a dict of {normalized_name: mapping_dict}.
    """
    global _loaded_files

    lookup: dict[str, dict] = {}
    _loaded_files = []

    if not MAPPINGS_DIR.exists():
        log.warning("Mappings directory not found: %s", MAPPINGS_DIR)
        return lookup

    # Load official first, then community (community can override)
    for subdir in ("official", "community"):
        directory = MAPPINGS_DIR / subdir
        if not directory.exists():
            continue

        for path in sorted(directory.glob("*.yaml")):
            # Skip template files
            if path.name.startswith("_"):
                continue

            data = _load_file(path)
            if data is None:
                continue

            _loaded_files.append(path)

            # Register the primary name
            primary = _normalize(data["malware"])
            if primary:
                lookup[primary] = data

            # Register all aliases
            for alias in data.get("aliases", []) or []:
                normalized_alias = _normalize(str(alias))
                if normalized_alias:
                    lookup[normalized_alias] = data

    log.info(
        "Loaded %d ATT&CK mappings from %d files",
        len(lookup),
        len(_loaded_files),
    )
    return lookup


def _ensure_loaded() -> dict[str, dict]:
    """Ensure the lookup dict is populated (lazy load)."""
    global _name_lookup
    if _name_lookup is None:
        _name_lookup = _load_all()
    return _name_lookup


def lookup_by_name(name: str) -> dict | None:
    """
    Look up a malware name or alias.

    Returns the mapping dict (with 'malware', 'techniques', etc.) or None.
    """
    if not name:
        return None

    lookup = _ensure_loaded()
    normalized = _normalize(name)

    # Direct match
    if normalized in lookup:
        return lookup[normalized]

    # Try stripping version numbers (e.g., "lockbit 2.0" → "lockbit")
    simplified = re.sub(r"\s*\d+(\.\d+)*$", "", normalized).strip()
    if simplified and simplified in lookup:
        return lookup[simplified]

    return None


def all_malware_names() -> list[str]:
    """Return a sorted list of all primary malware names."""
    lookup = _ensure_loaded()
    names = {entry["malware"] for entry in lookup.values()}
    return sorted(names)


def stats() -> dict:
    """Return a summary of the loaded mappings."""
    lookup = _ensure_loaded()
    unique_entries = {id(v): v for v in lookup.values()}.values()

    total_techniques = 0
    for entry in unique_entries:
        total_techniques += len(entry.get("techniques", []))

    return {
        "files_loaded": len(_loaded_files),
        "unique_malware": len(unique_entries),
        "aliases": len(lookup),
        "total_techniques": total_techniques,
    }


def reload() -> None:
    """Force a reload of all mappings (for tests)."""
    global _name_lookup
    _name_lookup = None
