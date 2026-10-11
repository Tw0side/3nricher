"""
AbuseIPDB enrichment.

Enriches: IPs only.
Auth: Key header.
Docs: https://docs.abuseipdb.com/
"""
import logging

from config import Config
from sources.base import safe_request, http_error_reason

log = logging.getLogger("3nricher.sources.abuseipdb")

ABUSE_URL = "https://api.abuseipdb.com/api/v2/check"


def query(ioc: str, ioc_type: str) -> dict:
    """Query AbuseIPDB for an IP."""
    if ioc_type != "ip":
        return {
            "status": "not_applicable",
            "reason": "AbuseIPDB only supports IPs",
        }

    api_key = Config.ABUSE_API_KEY
    if not api_key:
        return {"status": "error", "reason": "ABUSE_API_KEY not set"}

    headers = {"Key": api_key, "Accept": "application/json"}
    params = {"ipAddress": ioc, "maxAgeInDays": 90}

    r, err = safe_request(
        "GET",
        ABUSE_URL,
        headers=headers,
        params=params,
        timeout=Config.HTTP_TIMEOUT,
    )
    if err:
        return err

    if r.status_code == 200:
        try:
            data = r.json().get("data", {})
        except ValueError as e:
            log.warning("Unexpected AbuseIPDB response for %s: %s", ioc, e)
            return {"status": "error", "reason": "unexpected response shape"}

        return {
            "status": "ok",
            "abuse_score": data.get("abuseConfidenceScore", 0),
            "country": data.get("countryCode", ""),
            "isp": data.get("isp", ""),
            "domain": data.get("domain", ""),
            "total_reports": data.get("totalReports", 0),
            "last_reported": data.get("lastReportedAt", ""),
        }

    return {"status": "error", "reason": http_error_reason(r.status_code)}
