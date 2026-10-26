"""IPinfo Lite enrichment source.

Looks up ASN, organization, and country data for IP addresses
using the free IPinfo Lite API.
"""

from config import Config
from sources.base import safe_request

LITE_URL = "https://api.ipinfo.io/lite/{ip}"


def _get_token():
    """Read the IPinfo token from the centralized config."""
    return (Config.IPINFO_API_KEY or "").strip()


def query(ioc: str, ioc_type: str) -> dict:
    """Look up ASN and organization data for an IP address."""
    if ioc_type != "ip":
        return {"status": "not_applicable",
                "reason": "IPinfo only supports IPs"}

    token = _get_token()
    if not token:
        return {"status": "error",
                "reason": "IPINFO_API_KEY not set in .env"}

    url = LITE_URL.format(ip=ioc)
    resp, err = safe_request(
        "GET", url,
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
        "source": "ipinfo",
    }
