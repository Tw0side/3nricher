"""
GreyNoise enrichment.

Enriches: IPs only.
Auth: API key in 'key' header (or query param).
Docs: https://docs.greynoise.io/

GreyNoise classifies IPs into:
- RIOT (benign): Common business services (Google, Cloudflare, etc.)
- Noise (mass scanner): Opportunistic scanners (Shodan, Censys, etc.)
- Malicious: Targeted attackers with malicious intent
- Unknown: Not seen or not classified

This is a strong signal for prioritization. A "malicious" classification
indicates targeted activity; "noise" indicates opportunistic scanning that
most SOCs deprioritize.
"""
import logging

from config import Config
from sources.base import safe_request, http_error_reason

log = logging.getLogger("3nricher.sources.greynoise")

BASE_URL = "https://api.greynoise.io/v3/community"


def query(ioc: str, ioc_type: str) -> dict:
    """Query GreyNoise for an IP."""
    if ioc_type != "ip":
        return {
            "status": "not_applicable",
            "reason": "GreyNoise only supports IPs",
        }

    api_key = Config.GREYNOISE_API_KEY
    if not api_key:
        return {"status": "error", "reason": "GREYNOISE_API_KEY not set"}

    url = f"{BASE_URL}/{ioc}"
    headers = {"key": api_key, "Accept": "application/json"}

    r, err = safe_request(
        "GET", url, headers=headers, timeout=Config.HTTP_TIMEOUT
    )
    if err:
        return err

    if r.status_code == 200:
        try:
            data = r.json()
        except ValueError as e:
            log.warning("Unexpected GreyNoise response for %s: %s", ioc, e)
            return {"status": "error", "reason": "unexpected response shape"}

        return {
            "status": "ok",
            "classification": data.get("classification", ""),
            "name": data.get("name", ""),
            "noise": data.get("noise", False),
            "riot": data.get("riot", False),
            "last_seen": data.get("last_seen", ""),
            "link": data.get("link", ""),
        }

    if r.status_code == 404:
        return {"status": "not_found", "reason": "IP not in GreyNoise"}

    return {"status": "error", "reason": http_error_reason(r.status_code)}
