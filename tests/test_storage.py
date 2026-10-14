"""
Tests for storage/db.py and storage/history.py — persistence layer.

Covers:
- Schema initialization
- Recording enrichment runs
- IOC deduplication
- History queries
- Stats reporting
- JSON field encoding/decoding
"""
import json
from pathlib import Path

import pytest

from storage import db, history


@pytest.fixture(autouse=True)
def isolated_db(monkeypatch, tmp_path):
    """Use a temp DB file for each test."""
    test_db = tmp_path / "test.db"
    monkeypatch.setenv("DB_PATH", str(test_db))
    yield
    # Cleanup
    if test_db.exists():
        test_db.unlink()
    # WAL files
    for suffix in ("-wal", "-shm"):
        wal = Path(str(test_db) + suffix)
        if wal.exists():
            wal.unlink()


def _sample_result(ioc="8.8.8.8", type_="ip", risk="Low", score=0):
    """Helper to build a sample enrichment result."""
    return {
        "ioc": ioc,
        "type": type_,
        "risk": risk,
        "risk_score": score,
        "rationale": ["Test rationale line 1", "Test rationale line 2"],
        "sources": {
            "virustotal": {"status": "ok", "malicious": 0, "harmless": 53},
        },
    }


class TestSchema:
    def test_init_creates_tables(self):
        """init_schema creates iocs and enrichments tables."""
        db.init_schema()
        with db.transaction() as conn:
            cur = conn.execute(
                "SELECT name FROM sqlite_master WHERE type='table'"
            )
            tables = {row[0] for row in cur.fetchall()}
        assert "iocs" in tables
        assert "enrichments" in tables

    def test_init_is_idempotent(self):
        """Calling init_schema twice doesn't error."""
        db.init_schema()
        db.init_schema()  # should not raise


class TestRecordRun:
    def test_record_single_result(self):
        """Recording one IOC persists it."""
        history.record_run([_sample_result()], run_id="test-1")
        stats = history.get_stats()
        assert stats["unique_iocs"] == 1
        assert stats["enrichments"] == 1
        assert stats["runs"] == 1

    def test_record_multiple_results(self):
        """Recording multiple IOCs persists all."""
        results = [
            _sample_result("8.8.8.8", "ip"),
            _sample_result("google.com", "domain"),
            _sample_result("a" * 64, "sha256"),
        ]
        history.record_run(results, run_id="test-2")
        stats = history.get_stats()
        assert stats["unique_iocs"] == 3
        assert stats["enrichments"] == 3

    def test_record_empty_list_is_noop(self):
        """Empty results don't create runs."""
        history.record_run([], run_id="empty")
        stats = history.get_stats()
        assert stats["runs"] == 0

    def test_record_generates_run_id_if_missing(self):
        """Without run_id, a UUID is generated."""
        run_id = history.record_run([_sample_result()])
        assert run_id  # non-empty
        assert len(run_id) > 10  # looks like a UUID

    def test_record_deduplicates_iocs(self):
        """Same IOC enriched twice → 1 ioc row, 2 enrichment rows."""
        history.record_run([_sample_result("8.8.8.8")], run_id="run-a")
        history.record_run([_sample_result("8.8.8.8")], run_id="run-b")

        stats = history.get_stats()
        assert stats["unique_iocs"] == 1
        assert stats["enrichments"] == 2
        assert stats["runs"] == 2


class TestIocHistory:
    def test_history_for_known_ioc(self):
        """
        get_ioc_history returns prior enrichments.

        Both entries must be present. We do NOT assert order here because
        SQLite's CURRENT_TIMESTAMP has 1-second precision — two rows written
        in the same second have identical timestamps, so ordering between
        them is undefined.
        """
        history.record_run([_sample_result("1.1.1.1", risk="Low")], run_id="r1")
        history.record_run(
            [_sample_result("1.1.1.1", risk="High", score=60)],
            run_id="r2",
        )

        entries = history.get_ioc_history("1.1.1.1")
        assert len(entries) == 2

        # Set-based assertion — order-independent
        risks = {e["risk_label"] for e in entries}
        assert risks == {"Low", "High"}

        # Verify the High-risk entry has the correct score
        high_entry = next(e for e in entries if e["risk_label"] == "High")
        assert high_entry["risk_score"] == 60

    def test_history_for_unknown_ioc_is_empty(self):
        """Unknown IOC returns empty list."""
        entries = history.get_ioc_history("9.9.9.9")
        assert entries == []

    def test_history_decodes_json_fields(self):
        """rationale and sources are decoded from JSON strings."""
        history.record_run([_sample_result()], run_id="json-test")
        entries = history.get_ioc_history("8.8.8.8")

        assert isinstance(entries[0]["rationale"], list)
        assert "Test rationale line 1" in entries[0]["rationale"]
        assert isinstance(entries[0]["sources"], dict)

    def test_history_respects_limit(self):
        """Limit parameter caps the number of returned entries."""
        for i in range(5):
            history.record_run([_sample_result("2.2.2.2")], run_id=f"r{i}")

        entries = history.get_ioc_history("2.2.2.2", limit=3)
        assert len(entries) == 3


class TestRecentRuns:
    def test_recent_runs_lists_runs(self):
        """get_recent_runs groups by run_id."""
        history.record_run([_sample_result("a.com", "domain")], run_id="run-x")
        history.record_run([_sample_result("b.com", "domain")], run_id="run-y")

        runs = history.get_recent_runs(limit=10)
        run_ids = {r["run_id"] for r in runs}
        assert "run-x" in run_ids
        assert "run-y" in run_ids

    def test_recent_runs_empty_initially(self):
        """No runs recorded → empty list."""
        assert history.get_recent_runs() == []


class TestStats:
    def test_stats_empty_initially(self):
        """Fresh DB has all zeros."""
        stats = history.get_stats()
        assert stats == {"unique_iocs": 0, "enrichments": 0, "runs": 0}

    def test_stats_accumulate(self):
        """Stats grow with each run."""
        history.record_run([_sample_result("a.com", "domain")], run_id="r1")
        history.record_run([_sample_result("b.com", "domain")], run_id="r2")

        stats = history.get_stats()
        assert stats["unique_iocs"] == 2
        assert stats["enrichments"] == 2
        assert stats["runs"] == 2
