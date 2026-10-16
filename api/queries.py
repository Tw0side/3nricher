"""
Database query helpers for the API.

Wraps storage/history.py and storage/db.py with the specific queries
the API needs. Kept separate from api/main.py so queries can be tested
independently of FastAPI.
"""
import json
import logging
from typing import Any

from storage.db import transaction, init_schema

log = logging.getLogger("3nricher.api.queries")


def _row_to_dict(row) -> dict:
    """Convert a sqlite3.Row to a dict, decoding JSON fields."""
    d = dict(row)
    for field in ("rationale", "sources_json"):
        if field in d and d[field]:
            try:
                decoded = json.loads(d[field])
                if field == "sources_json":
                    d["sources"] = decoded
                    del d["sources_json"]
                else:
                    d[field] = decoded
            except (json.JSONDecodeError, TypeError):
                pass
    return d


# ---------------------------------------------------------------
# Aggregates
# ---------------------------------------------------------------
def get_stats() -> dict[str, Any]:
    """
    Aggregate stats for the dashboard header.

    Returns:
        {
            "total_iocs": int,
            "total_enrichments": int,
            "total_runs": int,
            "risk_distribution": {"Low": int, "Medium": int, ...},
            "last_run": str | None,
        }
    """
    init_schema()

    with transaction() as conn:
        total_iocs = conn.execute("SELECT COUNT(*) FROM iocs").fetchone()[0]
        total_enrichments = conn.execute("SELECT COUNT(*) FROM enrichments").fetchone()[0]
        total_runs = conn.execute(
            "SELECT COUNT(DISTINCT run_id) FROM enrichments"
        ).fetchone()[0]

        # Risk distribution: count distinct IOCs at each risk level.
        # Use the most recent enrichment per IOC (per risk_label).
        # Simpler: count all enrichments by label.
        cur = conn.execute("""
            SELECT risk_label, COUNT(*) as cnt
            FROM enrichments
            GROUP BY risk_label
        """)
        risk_distribution = {row["risk_label"] or "Unknown": row["cnt"] for row in cur}

        # Last run timestamp
        row = conn.execute(
            "SELECT MAX(enriched_at) FROM enrichments"
        ).fetchone()
        last_run = row[0] if row else None

    return {
        "total_iocs": total_iocs,
        "total_enrichments": total_enrichments,
        "total_runs": total_runs,
        "risk_distribution": risk_distribution,
        "last_run": last_run,
    }


# ---------------------------------------------------------------
# IOC listing
# ---------------------------------------------------------------
def list_iocs(
    risk: str | None = None,
    limit: int = 100,
) -> list[dict]:
    """
    List IOCs with their most recent enrichment.

    Args:
        risk:  Optional filter ("Low", "Medium", "High", "Critical", "Unknown")
        limit: Max rows to return

    Returns:
        List of dicts with ioc, type, risk, risk_score, confidence, enriched_at
    """
    init_schema()

    # Subquery: latest enrichment per IOC
    query = """
        SELECT
            i.value   AS ioc,
            i.type    AS type,
            e.risk_label    AS risk,
            e.risk_score    AS risk_score,
            e.enriched_at   AS enriched_at,
            e.rationale     AS rationale,
            e.sources_json  AS sources_json
        FROM iocs i
        JOIN enrichments e ON e.ioc_id = i.id
        WHERE e.id = (
            SELECT id FROM enrichments
            WHERE ioc_id = i.id
            ORDER BY enriched_at DESC, id DESC
            LIMIT 1
        )
    """
    params: list[Any] = []

    if risk:
        query += " AND e.risk_label = ?"
        params.append(risk)

    query += " ORDER BY e.enriched_at DESC LIMIT ?"
    params.append(limit)

    with transaction() as conn:
        cur = conn.execute(query, params)
        rows = cur.fetchall()

    return [_row_to_dict(r) for r in rows]


# ---------------------------------------------------------------
# IOC detail + history
# ---------------------------------------------------------------
def get_ioc_detail(value: str) -> dict | None:
    """
    Return full detail for one IOC plus its enrichment history.

    Returns None if the IOC has never been enriched.
    """
    init_schema()

    with transaction() as conn:
        # IOC metadata
        row = conn.execute(
            "SELECT id, value, type, first_seen, last_seen FROM iocs WHERE value = ?",
            (value,),
        ).fetchone()
        if not row:
            return None

        ioc_id = row["id"]

        # All enrichments for this IOC, newest first
        cur = conn.execute("""
            SELECT
                e.id, e.run_id, e.risk_label, e.risk_score,
                e.rationale, e.sources_json, e.enriched_at
            FROM enrichments e
            WHERE e.ioc_id = ?
            ORDER BY e.enriched_at DESC, e.id DESC
        """, (ioc_id,))
        enrichment_rows = cur.fetchall()

    enrichments = [_row_to_dict(r) for r in enrichment_rows]
    latest = enrichments[0] if enrichments else None

    return {
        "ioc": row["value"],
        "type": row["type"],
        "first_seen": row["first_seen"],
        "last_seen": row["last_seen"],
        "latest": latest,
        "history": enrichments[1:] if len(enrichments) > 1 else [],
    }


# ---------------------------------------------------------------
# Recent runs
# ---------------------------------------------------------------
def list_runs(limit: int = 20) -> list[dict]:
    """
    Return recent enrichment runs grouped by run_id.

    Returns:
        List of {run_id, started_at, finished_at, ioc_count, high_count}
    """
    init_schema()

    with transaction() as conn:
        cur = conn.execute("""
            SELECT
                run_id,
                MIN(enriched_at) AS started_at,
                MAX(enriched_at) AS finished_at,
                COUNT(*)         AS ioc_count,
                SUM(CASE WHEN risk_label IN ('High', 'Critical') THEN 1 ELSE 0 END) AS high_count
            FROM enrichments
            GROUP BY run_id
            ORDER BY finished_at DESC
            LIMIT ?
        """, (limit,))
        rows = cur.fetchall()

    return [
        {
            "run_id": r["run_id"],
            "started_at": r["started_at"],
            "finished_at": r["finished_at"],
            "ioc_count": r["ioc_count"],
            "high_count": r["high_count"] or 0,
        }
        for r in rows
    ]
