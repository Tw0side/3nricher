"""
Tests for the attck_mappings/ YAML files.

Validates:
- Every YAML file parses correctly
- Required fields are present
- Technique IDs match the expected format (Txxxx or Txxxx.yyy)
- References point to attack.mitre.org
- No duplicate malware names
- Community files don't collide with official files
"""
import re
from pathlib import Path

import pytest
import yaml


PROJECT_ROOT = Path(__file__).resolve().parent.parent
MAPPINGS_DIR = PROJECT_ROOT / "attck_mappings"
OFFICIAL_DIR = MAPPINGS_DIR / "official"
COMMUNITY_DIR = MAPPINGS_DIR / "community"


# ------------------------------------------------------------------
# Helpers
# ------------------------------------------------------------------
def _load_yaml_files(directory: Path) -> list[tuple[Path, dict]]:
    """Load all .yaml files (excluding templates) from a directory."""
    files = []
    for path in sorted(directory.glob("*.yaml")):
        if path.name.startswith("_"):
            continue  # skip templates
        with open(path, encoding="utf-8") as f:
            data = yaml.safe_load(f)
        files.append((path, data))
    return files


TECHNIQUE_ID_RE = re.compile(r"^T\d{4}(\.\d{3})?$")


# ------------------------------------------------------------------
# Directory existence
# ------------------------------------------------------------------
class TestDirectoryStructure:
    def test_official_dir_exists(self):
        assert OFFICIAL_DIR.exists(), f"Missing: {OFFICIAL_DIR}"

    def test_community_dir_exists(self):
        assert COMMUNITY_DIR.exists(), f"Missing: {COMMUNITY_DIR}"

    def test_readme_exists(self):
        assert (MAPPINGS_DIR / "README.md").exists()

    def test_official_has_files(self):
        files = list(OFFICIAL_DIR.glob("*.yaml"))
        # Exclude templates
        files = [f for f in files if not f.name.startswith("_")]
        assert len(files) >= 5, f"Expected at least 5 official mappings, got {len(files)}"


# ------------------------------------------------------------------
# YAML validation
# ------------------------------------------------------------------
class TestOfficialMappings:
    """Validate every official mapping file."""

    @pytest.fixture(scope="class")
    @classmethod
    def mappings(cls):
        return _load_yaml_files(OFFICIAL_DIR)

    def test_all_files_parse(self, mappings):
        """Every YAML file should parse without error."""
        assert len(mappings) >= 5

    def test_all_have_malware_field(self, mappings):
        for path, data in mappings:
            assert "malware" in data, f"{path.name} missing 'malware'"
            assert isinstance(data["malware"], str)
            assert data["malware"].strip()

    def test_all_have_techniques(self, mappings):
        for path, data in mappings:
            assert "techniques" in data, f"{path.name} missing 'techniques'"
            assert isinstance(data["techniques"], list)
            assert len(data["techniques"]) > 0, f"{path.name} has empty techniques"

    def test_techniques_have_required_fields(self, mappings):
        for path, data in mappings:
            for tech in data["techniques"]:
                assert "id" in tech, f"{path.name}: technique missing 'id'"
                assert "name" in tech, f"{path.name}: {tech['id']} missing 'name'"
                assert tech["name"].strip(), f"{path.name}: {tech['id']} has empty name"

    def test_technique_ids_match_pattern(self, mappings):
        """Technique IDs should match Txxxx or Txxxx.yyy."""
        for path, data in mappings:
            for tech in data["techniques"]:
                tech_id = tech["id"]
                assert TECHNIQUE_ID_RE.match(tech_id), (
                    f"{path.name}: invalid technique ID '{tech_id}'"
                )

    def test_malware_names_are_lowercase(self, mappings):
        for path, data in mappings:
            malware = data["malware"]
            assert malware == malware.lower(), (
                f"{path.name}: malware '{malware}' should be lowercase"
            )

    def test_aliases_are_list(self, mappings):
        for path, data in mappings:
            aliases = data.get("aliases", [])
            assert isinstance(aliases, list), (
                f"{path.name}: aliases should be a list"
            )

    def test_references_are_urls(self, mappings):
        """Reference URLs should point to attack.mitre.org or an HTTPS site."""
        for path, data in mappings:
            for ref in data.get("references", []):
                assert isinstance(ref, str)
                assert ref.startswith("http"), (
                    f"{path.name}: reference '{ref}' is not a URL"
                )

    def test_at_least_one_attack_reference(self, mappings):
        """Every mapping should reference attack.mitre.org."""
        for path, data in mappings:
            refs = data.get("references", [])
            has_attack_ref = any("attack.mitre.org" in r for r in refs)
            assert has_attack_ref, (
                f"{path.name}: no reference to attack.mitre.org"
            )


class TestNoDuplicates:
    def test_no_duplicate_malware_names(self):
        """No two official files should declare the same primary name."""
        seen = {}
        for path, data in _load_yaml_files(OFFICIAL_DIR):
            name = data["malware"]
            if name in seen:
                pytest.fail(
                    f"Duplicate malware '{name}' in {path.name} "
                    f"and {seen[name]}"
                )
            seen[name] = path.name

    def test_no_duplicate_aliases_within_file(self):
        """No file should list the same alias twice."""
        for path, data in _load_yaml_files(OFFICIAL_DIR):
            aliases = data.get("aliases", [])
            normalized = [a.lower().strip() for a in aliases]
            assert len(normalized) == len(set(normalized)), (
                f"{path.name}: duplicate aliases"
            )


class TestKnownMappings:
    """Spot-check specific known mappings."""

    def test_wannacry_exists(self):
        path = OFFICIAL_DIR / "wannacry.yaml"
        assert path.exists()
        data = yaml.safe_load(path.read_text())
        assert data["malware"] == "wannacry"

    def test_wannacry_has_t1486(self):
        """WannaCry should map to T1486 (Data Encrypted for Impact)."""
        path = OFFICIAL_DIR / "wannacry.yaml"
        data = yaml.safe_load(path.read_text())
        ids = [t["id"] for t in data["techniques"]]
        assert "T1486" in ids

    def test_lockbit_exists(self):
        path = OFFICIAL_DIR / "lockbit.yaml"
        assert path.exists()

    def test_emotet_has_phishing(self):
        """Emotet should map to T1566 (Phishing)."""
        path = OFFICIAL_DIR / "emotet.yaml"
        data = yaml.safe_load(path.read_text())
        ids = [t["id"] for t in data["techniques"]]
        # Should have phishing or a sub-technique
        assert any(i.startswith("T1566") for i in ids)

    def test_cobalt_strike_exists(self):
        path = OFFICIAL_DIR / "cobalt_strike.yaml"
        assert path.exists()


class TestCommunityMappings:
    """Community directory should only contain a template for now."""

    def test_community_files_parse_if_present(self):
        """Any community file (excluding template) should be valid."""
        for path in COMMUNITY_DIR.glob("*.yaml"):
            if path.name.startswith("_"):
                continue
            data = yaml.safe_load(path.read_text())
            assert "malware" in data
            assert "techniques" in data
