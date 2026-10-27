"""IPinfo enrichment source.

Looks up ASN, organization, and country data (Lite API), plus
city/region/coordinates/timezone (Core API) for IP addresses.
"""

from config import Config
from sources.base import safe_request

LITE_URL = "https://api.ipinfo.io/lite/{ip}"
CORE_URL = "https://ipinfo.io/{ip}/json"


def _get_token():
    """Read the IPinfo token from the centralized config."""
    return (Config.IPINFO_API_KEY or "").strip()


def _get_geo(ip: str, token: str) -> dict:
    """Best-effort city-level geolocation. Returns {} on any failure."""
    resp, err = safe_request(
        "GET", CORE_URL.format(ip=ip),
        params={"token": token},
        timeout=15,
    )
    if resp is None or err or resp.status_code != 200:
        return {}
    try:
        g = resp.json()
    except ValueError:
        return {}
    return {
        "city": g.get("city", ""),
        "region": g.get("region", ""),
        "country": g.get("country", ""),
        "loc": g.get("loc", ""),
        "timezone": g.get("timezone", ""),
        "postal": g.get("postal", ""),
    }


def query(ioc: str, ioc_type: str) -> dict:
    """Look up ASN, organization, and geolocation for an IP address."""
    if ioc_type != "ip":
        return {"status": "not_applicable",
                "reason": "IPinfo only supports IPs"}

    token = _get_token()
    if not token:
        return {"status": "error",
                "reason": "IPINFO_API_KEY not set in .env"}

    resp, err = safe_request(
        "GET", LITE_URL.format(ip=ioc),
        params={"token": token},
        timeout=15,
    )

    if resp is not None and resp.status_code == 404:
        return {"status": "not_found",
                "reason": "IP not found in IPinfo"}
    if resp is None or err:
        reason = (err or {}).get("reason", "IPinfo request failed")
        return {"status": "error", "reason": reason}
    if resp.status_code in (401, 403):
        return {"status": "error",
                "reason": "IPinfo rejected the token (check IPINFO_API_KEY)"}
    if resp.status_code >= 400:
        return {"status": "error",
                "reason": f"IPinfo HTTP {resp.status_code}"}

    try:
        data = resp.json()
    except ValueError:
        return {"status": "error",
                "reason": "IPinfo returned invalid JSON"}

    asn = data.get("asn", "")
    if not asn:
        return {"status": "not_found",
                "reason": "no ASN data in IPinfo response"}

    return {
        "status": "ok",
        "asn": asn,
        "as_name": data.get("as_name", ""),
        "as_domain": data.get("as_domain", ""),
        "country_code": data.get("country_code", ""),
        "geo": _get_geo(ioc, token),
        "source": "ipinfo",
    }
