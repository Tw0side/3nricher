
"""
VirusTotal v3 API enrichment.

Enriches: IPs, domains, file hashes.
Auth: x-apikey header.
Docs: https://developers.virustotal.com/reference/overview
"""
import logging

from config import Config
from sources.base import safe_request, http_error_reason

log = logging.getLogger("3nricher.sources.virustotal")

VT_ENDPOINTS = {
    "ip": "ip_addresses",
    "domain": "domains",
    "md5": "files",
    "sha1": "files",
    "sha256": "files",
}

BASE_URL = "https://www.virustotal.com/api/v3"


def query(ioc: str, ioc_type: str) -> dict:
    """Query VirusTotal for a single IOC."""
    endpoint = VT_ENDPOINTS.get(ioc_type)
    if not endpoint:
        return {
            "status": "not_applicable",
            "reason": f"VT does not support type: {ioc_type}",
        }

    api_key = Config.VT_API_KEY
    if not api_key:
        return {"status": "error", "reason": "VT_API_KEY not set"}

    url = f"{BASE_URL}/{endpoint}/{ioc}"
    headers = {"x-apikey": api_key}

    r, err = safe_request("GET", url, headers=headers, timeout=Config.HTTP_TIMEOUT)
    if err:
        return err

    if r.status_code == 200:
        try:
            stats = r.json()["data"]["attributes"]["last_analysis_stats"]
        except (KeyError, ValueError) as e:
            log.warning("Unexpected VT response shape for %s: %s", ioc, e)
            return {"status": "error", "reason": "unexpected response shape"}

        return {
            "status": "ok",
            "malicious": stats.get("malicious", 0),
            "suspicious": stats.get("suspicious", 0),
            "harmless": stats.get("harmless", 0),
            "undetected": stats.get("undetected", 0),
        }

    if r.status_code == 404:
        return {"status": "not_found", "reason": "IOC not in VT database"}

    return {"status": "error", "reason": http_error_reason(r.status_code)}
