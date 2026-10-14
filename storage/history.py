"""
Enrichment history storage.

Wraps storage/db.py with domain-specific helpers:

    record_run(results)         → Persist a batch of enriched IOCs
    get_ioc_history(value)      → All enrichments for a specific IOC
    get_recent_runs(limit)      → Latest N enrichment runs
    get_stats()                 → Summary counts

All functions are safe to call repeatedly. Schemas are created on first use.
"""
import json
import logging
import uuid
from datetime import datetime, timezone

from storage.db import transaction, init_schema

log = logging.getLogger("3nricher.storage.history")


def _utc_now_iso() -> str:
    """UTC timestamp in ISO 8601 format."""
    return datetime.now(timezone.utc).isoformat()


def _get_or_create_ioc(conn, value: str, type_: str) -> int:
    """
    Return the IOC's database id, creating the row if missing.

    Also bumps last_seen on existing rows.
    """
    row = conn.execute(
        "SELECT id FROM iocs WHERE value = ?", (value,)
    ).fetchone()

    if row:
        ioc_id = row["id"]
        conn.execute(
            "UPDATE iocs SET last_seen = ? WHERE id = ?",
            (_utc_now_iso(), ioc_id),
        )
        return ioc_id

    cur = conn.execute(
        "INSERT INTO iocs (value, type) VALUES (?, ?)",
        (value, type_),
    )
    return cur.lastrowid


def record_run(results: list[dict], run_id: str | None = None) -> str:
    """
    Persist a batch of enrichment results.

    Args:
        results: List of dicts from enrichment.enrich_all() (must have
                 ioc, type, risk, risk_score, rationale, sources).
        run_id:  Optional identifier. If None, a UUID is generated.

    Returns:
        The run_id used.
    """
    if not results:
        log.debug("record_run: empty results, nothing to store")
        return run_id or ""

    init_schema()
    run_id = run_id or str(uuid.uuid4())

    with transaction() as conn:
        for r in results:
            ioc_value = r.get("ioc")
            if not ioc_value:
                continue

            ioc_id = _get_or_create_ioc(
                conn,
                value=ioc_value,
                type_=r.get("type", "unknown"),
            )

            rationale = json.dumps(r.get("rationale", []), ensure_ascii=False)
            sources_json = json.dumps(r.get("sources", {}), ensure_ascii=False)

            conn.execute(
                """
                INSERT INTO enrichments
                    (ioc_id, run_id, risk_label, risk_score, rationale, sources_json)
                VALUES (?, ?, ?, ?, ?, ?)
                """,
                (
                    ioc_id,
                    run_id,
                    r.get("risk", ""),
                    r.get("risk_score", 0),
                    rationale,
                    sources_json,
                ),
            )

    log.info("Recorded run %s: %d enrichments persisted", run_id, len(results))
    return run_id


def get_ioc_history(value: str, limit: int = 50) -> list[dict]:
    """
    Return all enrichments for a specific IOC, newest first.
    """
    init_schema()
    with transaction() as conn:
        cur = conn.execute(
            """
            SELECT
                e.id, e.run_id, e.risk_label, e.risk_score,
                e.rationale, e.sources_json, e.enriched_at,
                i.value, i.type, i.first_seen, i.last_seen
            FROM enrichments e
            JOIN iocs i ON i.id = e.ioc_id
            WHERE i.value = ?
            ORDER BY e.enriched_at DESC
            LIMIT ?
            """,
            (value, limit),
        )
        rows = cur.fetchall()

    return [_row_to_dict(r) for r in rows]


def get_recent_runs(limit: int = 20) -> list[dict]:
    """
    Return the most recent distinct runs.

    Each entry includes the run_id, timestamp, and IOC count.
    """
    init_schema()
    with transaction() as conn:
        cur = conn.execute(
            """
            SELECT
                run_id,
                MIN(enriched_at)  AS started_at,
                MAX(enriched_at)  AS finished_at,
                COUNT(*)          AS ioc_count
            FROM enrichments
            GROUP BY run_id
            ORDER BY finished_at DESC
            LIMIT ?
            """,
            (limit,),
        )
        rows = cur.fetchall()

    return [
        {
            "run_id": r["run_id"],
            "started_at": r["started_at"],
            "finished_at": r["finished_at"],
            "ioc_count": r["ioc_count"],
        }
        for r in rows
    ]


def get_stats() -> dict:
    """Return summary counts."""
    init_schema()
    with transaction() as conn:
        ioc_count = conn.execute("SELECT COUNT(*) FROM iocs").fetchone()[0]
        enrichment_count = conn.execute("SELECT COUNT(*) FROM enrichments").fetchone()[0]
        run_count = conn.execute(
            "SELECT COUNT(DISTINCT run_id) FROM enrichments"
        ).fetchone()[0]

    return {
        "unique_iocs": ioc_count,
        "enrichments": enrichment_count,
        "runs": run_count,
    }


def _row_to_dict(row) -> dict:
    """Convert a sqlite3.Row to a plain dict, decoding JSON fields."""
    d = dict(row)
    if "rationale" in d and d["rationale"]:
        try:
            d["rationale"] = json.loads(d["rationale"])
        except (json.JSONDecodeError, TypeError):
            pass
    if "sources_json" in d and d["sources_json"]:
        try:
            d["sources"] = json.loads(d.pop("sources_json"))
        except (json.JSONDecodeError, TypeError):
            pass
    return d
