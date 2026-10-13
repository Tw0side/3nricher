"""
Parallel enrichment orchestration for 3nricher.

Provides two entry points:

    enrich_all_sequential(iocs)
        Simple loop — same behavior as Iteration 2/3, useful for debugging
        and small IOC lists.

    enrich_all_parallel(iocs, workers=10)
        Uses ThreadPoolExecutor to enrich multiple IOCs concurrently.
        All workers share the same rate-limited source modules, so the
        API rate limits (not thread count) are the true bottleneck.

Design notes:
- Results preserve input order, so output is deterministic regardless of
  which worker finishes first.
- A single IOC failure (unhandled exception) does not crash the run.
  The failed IOC gets an error result and the pool continues.
- Progress is shown via tqdm (optional dependency). If tqdm is missing,
  we fall back to periodic print statements.
"""
import logging
from concurrent.futures import ThreadPoolExecutor, as_completed

from sources import virustotal, abuseipdb, malwarebazaar, urlhaus, otx
from scoring import calculate_risk
from rationale import build_rationale

log = logging.getLogger("3nricher.enrichment")

# Optional progress bar
try:
    from tqdm import tqdm
    _HAS_TQDM = True
except ImportError:
    _HAS_TQDM = False


# ---------------------------------------------------------------
# IOC type detection (imported lazily to avoid circular imports)
# ---------------------------------------------------------------
def _detect_ioc_type(ioc: str) -> str:
    """Local wrapper — imports 3nricher lazily to avoid a circular import."""
    import importlib
    mod = importlib.import_module("3nricher")
    return mod.detect_ioc_type(ioc)


# ---------------------------------------------------------------
# Single IOC enrichment
# ---------------------------------------------------------------
def enrich_one(ioc: str) -> dict:
    """
    Enrich a single IOC across all sources.

    Returns a normalized dict with:
        ioc, type, risk, risk_score, rationale, sources
    """
    ioc_type = _detect_ioc_type(ioc)

    sources_result = {
        "virustotal": virustotal.query(ioc, ioc_type),
        "abuseipdb": abuseipdb.query(ioc, ioc_type),
        "malwarebazaar": malwarebazaar.query(ioc, ioc_type),
        "urlhaus": urlhaus.query(ioc, ioc_type),
        "otx": otx.query(ioc, ioc_type),
    }

    score, risk = calculate_risk(
        sources_result, ioc=ioc, ioc_type=ioc_type
    )

    rationale = build_rationale(sources_result, score, risk)

    return {
        "ioc": ioc,
        "type": ioc_type,
        "risk": risk,
        "risk_score": score,
        "rationale": rationale,
        "sources": sources_result,
    }


def _error_result(ioc: str, reason: str) -> dict:
    """Build a result dict for an IOC that failed catastrophically."""
    return {
        "ioc": ioc,
        "type": "unknown",
        "risk": "Unknown",
        "risk_score": 0,
        "rationale": [f"Enrichment failed: {reason}"],
        "sources": {},
        "error": reason,
    }


# ---------------------------------------------------------------
# Sequential enrichment
# ---------------------------------------------------------------
def enrich_all_sequential(iocs: list[str]) -> list[dict]:
    """
    Enrich a list of IOCs one at a time.

    Useful for debugging, small lists, or when rate-limit behavior needs
    to be predictable.
    """
    results = []
    total = len(iocs)
    for i, ioc in enumerate(iocs, 1):
        print(f"[{i}/{total}] Enriching {ioc} ...", end=" ", flush=True)
        try:
            result = enrich_one(ioc)
        except Exception as e:
            log.exception("Unexpected error enriching %s", ioc)
            result = _error_result(ioc, str(e))
        results.append(result)
        print(f"{result['risk']} ({result['risk_score']})")
    return results


# ---------------------------------------------------------------
# Parallel enrichment
# ---------------------------------------------------------------
def enrich_all_parallel(iocs: list[str], workers: int = 10) -> list[dict]:
    """
    Enrich a list of IOCs using a thread pool.

    Args:
        iocs:    List of IOC strings.
        workers: Number of concurrent worker threads.

    Returns:
        List of result dicts, in the same order as the input.
    """
    if workers < 1:
        workers = 1

    results: list[dict | None] = [None] * len(iocs)

    with ThreadPoolExecutor(max_workers=workers) as pool:
        # Map each future to its original index to preserve order
        futures = {
            pool.submit(enrich_one, ioc): i
            for i, ioc in enumerate(iocs)
        }

        iterator = as_completed(futures)
        if _HAS_TQDM:
            iterator = tqdm(
                iterator,
                total=len(futures),
                desc="Enriching",
                unit="ioc",
            )

        for future in iterator:
            idx = futures[future]
            ioc = iocs[idx]
            try:
                results[idx] = future.result()
            except Exception as e:
                log.exception("Unexpected error enriching %s", ioc)
                results[idx] = _error_result(ioc, str(e))

    # Type narrowing: results should now be all dicts
    return [r if r is not None else _error_result(iocs[i], "missing")
            for i, r in enumerate(results)]


# ---------------------------------------------------------------
# Dispatcher
# ---------------------------------------------------------------
def enrich_all(iocs: list[str], parallel: bool = True,
               workers: int = 10) -> list[dict]:
    """
    Enrich a list of IOCs, choosing sequential or parallel based on args.

    Args:
        iocs:     List of IOC strings.
        parallel: If True (default), use thread pool. If False, sequential.
        workers:  Number of worker threads (ignored if parallel=False).

    Returns:
        List of result dicts, in input order.
    """
    if not iocs:
        return []

    # Small lists: sequential overhead is lower
    if parallel and len(iocs) < 3:
        log.debug("Small IOC list (%d) — running sequential", len(iocs))
        return enrich_all_sequential(iocs)

    if parallel:
        log.info("Parallel enrichment: %d IOCs, %d workers", len(iocs), workers)
        return enrich_all_parallel(iocs, workers=workers)

    log.info("Sequential enrichment: %d IOCs", len(iocs))
    return enrich_all_sequential(iocs)
