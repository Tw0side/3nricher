"""
FastAPI application for the 3nricher web dashboard.

Serves the read-only JSON API consumed by the frontend. Reads from the
SQLite enrichment history database written by the CLI.

Run:
    uvicorn api.main:app --reload

Then open:
    http://localhost:8000/
    http://localhost:8000/docs   (auto-generated API docs)
"""
import logging
from pathlib import Path

from fastapi import FastAPI, HTTPException, Query
from fastapi.responses import FileResponse
from fastapi.staticfiles import StaticFiles

from api import queries
from logging_setup import setup_logging

# Configure logging
setup_logging()
log = logging.getLogger("3nricher.api")

# ---------------------------------------------------------------
# App
# ---------------------------------------------------------------
app = FastAPI(
    title="3nricher API",
    description="Read-only API over the 3nricher enrichment history.",
    version="0.8.0",
)

# Static files directory
STATIC_DIR = Path(__file__).parent / "static"
if STATIC_DIR.exists():
    app.mount("/static", StaticFiles(directory=STATIC_DIR), name="static")


# ---------------------------------------------------------------
# Root — serve the dashboard
# ---------------------------------------------------------------
@app.get("/", include_in_schema=False)
def root():
    """Serve the dashboard HTML."""
    index = STATIC_DIR / "index.html"
    if not index.exists():
        return {
            "message": "3nricher API is running.",
            "docs": "/docs",
            "hint": "Dashboard not yet built. API endpoints are live.",
        }
    return FileResponse(index)


# ---------------------------------------------------------------
# API — Stats
# ---------------------------------------------------------------
@app.get("/api/stats")
def api_stats():
    """
    Aggregate stats: IOC count, enrichment count, run count,
    risk distribution, last run timestamp.
    """
    return queries.get_stats()


# ---------------------------------------------------------------
# API — IOC list
# ---------------------------------------------------------------
@app.get("/api/iocs")
def api_iocs(
    risk: str | None = Query(
        default=None,
        description="Filter by risk label (Low, Medium, High, Critical, Unknown)",
    ),
    limit: int = Query(default=100, ge=1, le=1000),
):
    """
    List IOCs with their most recent enrichment, newest first.
    """
    iocs = queries.list_iocs(risk=risk, limit=limit)
    return {"count": len(iocs), "iocs": iocs}


# ---------------------------------------------------------------
# API — IOC detail
# ---------------------------------------------------------------
@app.get("/api/ioc/{value:path}")
def api_ioc_detail(value: str):
    """
    Full detail + history for a single IOC.
    """
    detail = queries.get_ioc_detail(value)
    if detail is None:
        raise HTTPException(
            status_code=404,
            detail=f"IOC not found in history: {value}",
        )
    return detail


# ---------------------------------------------------------------
# API — Recent runs
# ---------------------------------------------------------------
@app.get("/api/runs")
def api_runs(limit: int = Query(default=20, ge=1, le=200)):
    """
    List recent enrichment runs, newest first.
    """
    runs = queries.list_runs(limit=limit)
    return {"count": len(runs), "runs": runs}


# ---------------------------------------------------------------
# Health check
# ---------------------------------------------------------------
@app.get("/api/health")
def health():
    """Simple health check for monitoring."""
    return {"status": "ok", "version": app.version}
