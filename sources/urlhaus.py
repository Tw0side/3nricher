"""
URLhaus (abuse.ch) enrichment.

Enriches: domains and IPs.
Auth: Auth-Key header.
Docs: https://urlhaus-api.abuse.ch/

URLhaus catalogs URLs that distribute malware. The host endpoint returns
the number of malicious URLs hosted on a given domain or IP, along with
blacklist status.
"""
import logging

from config import Config
from sources.base import safe_request, http_error_reason

log = logging.getLogger("3nricher.sources.urlhaus")

URLHAUS_HOST_URL = "https://urlhaus-api.abuse.ch/v1/host/"


def query(ioc: str, ioc_type: str) -> dict:
    """Query URLhaus for a domain or IP."""
    if ioc_type not in ("domain", "ip"):
        return {
            "status": "not_applicable",
            "reason": "URLhaus supports domains and IPs only",
        }

    api_key = Config.ABUSE_CH_API_KEY
    if not api_key:
        return {"status": "error", "reason": "ABUSE_CH_API_KEY not set"}

    headers = {"Auth-Key": api_key}
    data = {"host": ioc}

    r, err = safe_request(
        "POST",
        URLHAUS_HOST_URL,
        headers=headers,
        data=data,
        timeout=Config.HTTP_TIMEOUT,
    )
    if err:
        return err

    if r.status_code != 200:
        return {"status": "error", "reason": http_error_reason(r.status_code)}

    try:
        j = r.json()
    except ValueError as e:
        log.warning("Malformed JSON from URLhaus for %s: %s", ioc, e)
        return {"status": "error", "reason": "malformed JSON"}

    query_status = j.get("query_status")

    if query_status == "ok":
        return {
            "status": "ok",
            "url_count": j.get("urls_online", 0),
            "blacklists": j.get("blacklists", {}),
            "first_seen": j.get("firstseen", ""),
            "threat": j.get("threat", ""),
        }

    if query_status in ("no_results", "invalid_host"):
        return {"status": "not_found", "reason": "host not in URLhaus"}

    return {"status": "error", "reason": f"unexpected query_status: {query_status}"}
