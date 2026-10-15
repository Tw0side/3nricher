"""
ThreatFox (abuse.ch) enrichment.

Enriches: IPs, domains, file hashes.
Auth: Same Auth-Key as MalwareBazaar + URLhaus.
Docs: https://threatfox.abuse.ch/api/

ThreatFox tracks malware C2 infrastructure — the servers malware talks to.
A match here indicates confirmed C2 association, which is a high-confidence
malicious signal.

NOTE: ThreatFox requires the request body to be JSON, not form-encoded.
"""
import logging

from config import Config
from sources.base import safe_request, http_error_reason

log = logging.getLogger("3nricher.sources.threatfox")

BASE_URL = "https://threatfox-api.abuse.ch/api/v1/"


def query(ioc: str, ioc_type: str) -> dict:
    """Query ThreatFox for an IOC."""
    # ThreatFox supports: IPs, domains, URLs, hashes
    if ioc_type not in ("ip", "domain", "md5", "sha1", "sha256"):
        return {
            "status": "not_applicable",
            "reason": f"ThreatFox does not support type: {ioc_type}",
        }

    api_key = Config.ABUSE_CH_API_KEY
    if not api_key:
        return {"status": "error", "reason": "ABUSE_CH_API_KEY not set"}

    headers = {"Auth-Key": api_key}
    json_body = {"query": "search_ioc", "search_term": ioc}

    r, err = safe_request(
        "POST",
        BASE_URL,
        headers=headers,
        json_body=json_body,
        timeout=Config.HTTP_TIMEOUT,
    )
    if err:
        return err

    if r.status_code != 200:
        return {"status": "error", "reason": http_error_reason(r.status_code)}

    try:
        j = r.json()
    except ValueError as e:
        log.warning("Malformed JSON from ThreatFox for %s: %s", ioc, e)
        return {"status": "error", "reason": "malformed JSON"}

    query_status = j.get("query_status")

    if query_status == "ok":
        entries = j.get("data", [])
        if not entries:
            return {"status": "not_found", "reason": "no entries"}

        entry = entries[0]
        return {
            "status": "ok",
            "malware": entry.get("malware_printable", "") or entry.get("malware", ""),
            "threat_type": entry.get("threat_type", ""),
            "confidence_level": entry.get("confidence_level", 0),
            "first_seen": entry.get("first_seen", ""),
            "last_seen": entry.get("last_seen", ""),
            "reference": entry.get("reference", ""),
        }

    if query_status in ("no_result", "illegal_search_term", "no_json"):
        return {"status": "not_found", "reason": f"query_status: {query_status}"}

    return {"status": "error", "reason": f"unexpected query_status: {query_status}"}
