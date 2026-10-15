"""
Feodo Tracker (abuse.ch) enrichment.

Enriches: IPs only.
Auth: Optional abuse.ch Auth-Key.
Docs: https://feodotracker.abuse.ch/

Feodo Tracker tracks the C2 servers used by banking trojans and botnets
(Emotet, Dridex, QakBot, TrickBot, etc.). A match here is a high-confidence
C2 signal — the IP is actively being used for malicious infrastructure.
"""
import logging

from config import Config
from sources.base import safe_request, http_error_reason

log = logging.getLogger("3nricher.sources.feodo")

BASE_URL = "https://feodotracker.abuse.ch/downloads/ipblocklist.json"


def query(ioc: str, ioc_type: str) -> dict:
    """Query Feodo Tracker for an IP."""
    if ioc_type != "ip":
        return {
            "status": "not_applicable",
            "reason": "Feodo Tracker only supports IPs",
        }

    # Feodo has no per-IP API; we download the blocklist and search it.
    # The list is small (~200-500 IPs), so this is efficient.
    # Cache makes repeat calls fast.
    headers = {}
    api_key = Config.ABUSE_CH_API_KEY
    if api_key:
        headers["Auth-Key"] = api_key

    r, err = safe_request(
        "GET", BASE_URL, headers=headers, timeout=Config.HTTP_TIMEOUT
    )
    if err:
        return err

    if r.status_code != 200:
        return {"status": "error", "reason": http_error_reason(r.status_code)}

    try:
        entries = r.json()
    except ValueError as e:
        log.warning("Malformed JSON from Feodo for %s: %s", ioc, e)
        return {"status": "error", "reason": "malformed JSON"}

    if not isinstance(entries, list):
        return {"status": "error", "reason": "unexpected response shape"}

    # Search for the IP
    for entry in entries:
        if entry.get("ip_address") == ioc:
            return {
                "status": "ok",
                "malware": entry.get("malware", ""),
                "status_detail": entry.get("status", ""),
                "first_seen": entry.get("first_seen", ""),
                "last_online": entry.get("last_online", ""),
                "port": entry.get("port"),
                "asn": entry.get("as_number"),
                "country": entry.get("country"),
            }

    return {"status": "not_found", "reason": "IP not in Feodo blocklist"}
