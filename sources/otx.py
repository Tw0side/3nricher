"""
AlienVault OTX enrichment.

Enriches: IPs, domains, file hashes, URLs, CVEs.
Auth: X-OTX-API-KEY header.
Docs: https://otx.alienvault.com/api

OTX provides community-sourced threat intelligence. Each IOC may be
referenced in "pulses" (threat reports contributed by researchers). A
high pulse count means the IOC is widely reported as malicious.
"""
import logging

from config import Config
from sources.base import safe_request, http_error_reason

log = logging.getLogger("3nricher.sources.otx")

BASE_URL = "https://otx.alienvault.com/api/v1/indicators"

# Map our internal types to OTX URL path segments
OTX_TYPE_MAP = {
    "ip": "IPv4",
    "domain": "domain",
    "md5": "file",
    "sha1": "file",
    "sha256": "file",
    "url": "url",
}


def query(ioc: str, ioc_type: str) -> dict:
    """Query AlienVault OTX for a single IOC."""
    otx_type = OTX_TYPE_MAP.get(ioc_type)
    if not otx_type:
        return {
            "status": "not_applicable",
            "reason": f"OTX does not support type: {ioc_type}",
        }

    api_key = Config.OTX_API_KEY
    if not api_key:
        return {"status": "error", "reason": "OTX_API_KEY not set"}

    url = f"{BASE_URL}/{otx_type}/{ioc}/general"
    headers = {"X-OTX-API-KEY": api_key}

    r, err = safe_request("GET", url, headers=headers, timeout=Config.HTTP_TIMEOUT)
    if err:
        return err

    if r.status_code == 200:
        try:
            data = r.json()
        except ValueError as e:
            log.warning("Unexpected OTX response for %s: %s", ioc, e)
            return {"status": "error", "reason": "unexpected response shape"}

        pulse_info = data.get("pulse_info", {}) or {}
        pulses = pulse_info.get("pulses", []) or []

        # Extract up to 3 pulse names for context
        pulse_names = [p.get("name", "") for p in pulses[:3] if p.get("name")]

              # Extract tags from pulses (top 5 unique).
        # OTX sometimes returns "a, b, c" as one string, so split on commas
        # and trim whitespace before deduplicating.
        tags: list[str] = []
        for p in pulses:
            for raw_tag in (p.get("tags") or []):
                # Split in case the tag contains comma-separated values
                for tag in str(raw_tag).split(","):
                    tag = tag.strip()
                    if tag and tag not in tags:
                        tags.append(tag)
                    if len(tags) >= 5:
                        break
                if len(tags) >= 5:
                    break
            if len(tags) >= 5:
                break

        return {
            "status": "ok",
            "pulse_count": pulse_info.get("count", 0),
            "pulse_names": pulse_names,
            "tags": tags,
        }

    if r.status_code == 404:
        return {"status": "not_found", "reason": "IOC not in OTX"}

    return {"status": "error", "reason": http_error_reason(r.status_code)}
