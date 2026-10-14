"""
SQLite database connection and schema for 3nricher.

Stores:
- iocs: unique IOC values (deduplication table)
- enrichments: one row per (IOC, run) pair with the full result

Design:
- Single SQLite file (default: data/3nricher.db)
- Schema initialized automatically on first use
- Thread-safe via per-call connections (SQLite handles locking)

Usage:
    from storage.db import get_connection, init_schema

    init_schema()
    with get_connection() as conn:
        conn.execute("INSERT INTO iocs (value, type) VALUES (?, ?)", ("8.8.8.8", "ip"))
"""
import logging
import os
import sqlite3
from contextlib import contextmanager
from pathlib import Path

log = logging.getLogger("3nricher.storage.db")


DEFAULT_DB_PATH = "data/3nricher.db"


SCHEMA_SQL = """
-- IOC deduplication table
CREATE TABLE IF NOT EXISTS iocs (
    id          INTEGER PRIMARY KEY AUTOINCREMENT,
    value       TEXT NOT NULL UNIQUE,
    type        TEXT NOT NULL,
    first_seen  TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,
    last_seen   TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP
);

-- One row per enrichment of an IOC in a given run
CREATE TABLE IF NOT EXISTS enrichments (
    id            INTEGER PRIMARY KEY AUTOINCREMENT,
    ioc_id        INTEGER NOT NULL REFERENCES iocs(id) ON DELETE CASCADE,
    run_id        TEXT NOT NULL,
    risk_label    TEXT,
    risk_score    INTEGER,
    rationale     TEXT,          -- JSON array of strings
    sources_json  TEXT,          -- JSON object with per-source data
    enriched_at   TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP
);

-- Indices for common queries
CREATE INDEX IF NOT EXISTS idx_iocs_value ON iocs(value);
CREATE INDEX IF NOT EXISTS idx_enrichments_ioc ON enrichments(ioc_id);
CREATE INDEX IF NOT EXISTS idx_enrichments_run ON enrichments(run_id);
CREATE INDEX IF NOT EXISTS idx_enrichments_ts ON enrichments(enriched_at DESC);
"""


def _get_db_path() -> str:
    """Read DB_PATH from env (default: data/3nricher.db)."""
    path = os.getenv("DB_PATH", DEFAULT_DB_PATH)
    Path(path).parent.mkdir(parents=True, exist_ok=True)
    return path


def get_connection() -> sqlite3.Connection:
    """
    Open a new SQLite connection with sensible defaults.

    Callers should use it as a context manager:

        with get_connection() as conn:
            ...
    """
    path = _get_db_path()
    conn = sqlite3.connect(path, timeout=30.0)
    conn.row_factory = sqlite3.Row
    # Foreign key enforcement is off by default in SQLite
    conn.execute("PRAGMA foreign_keys = ON")
    # WAL mode for better concurrency
    conn.execute("PRAGMA journal_mode = WAL")
    return conn


@contextmanager
def transaction():
    """
    Context manager for an atomic transaction.

    Commits on clean exit, rolls back on exception.
    """
    conn = get_connection()
    try:
        yield conn
        conn.commit()
    except Exception:
        conn.rollback()
        raise
    finally:
        conn.close()


def init_schema() -> None:
    """Create tables and indices if they don't exist."""
    path = _get_db_path()
    log.debug("Initializing schema at %s", path)
    with transaction() as conn:
        conn.executescript(SCHEMA_SQL)


def reset_database() -> None:
    """
    Drop all tables and recreate the schema.

    For tests and dev use only — never call this in production.
    """
    log.warning("Resetting database (dropping all tables)")
    with transaction() as conn:
        conn.executescript("""
            DROP TABLE IF EXISTS enrichments;
            DROP TABLE IF EXISTS iocs;
        """)
        conn.executescript(SCHEMA_SQL)
