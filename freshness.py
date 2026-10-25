"""Freshness detection: how new is an IOC?

Currently supports domain age via RDAP (registry data, no API key).
Returns the same status contract as the modules in sources/.
"""
import logging
from datetime import datetime, timezone

from sources.base import safe_request

log = logging.getLogger(__name__)

RDAP_URL = "https://rdap.org/domain/{domain}"

# (max_age_days_exclusive, points) - checked in order
AGE_TIERS = [(7, 25), (30, 15), (90, 5)]


def parse_registration_date(rdap_data):
    """Return the registration datetime (UTC) from an RDAP dict, or None."""
    for event in rdap_data.get("events") or []:
        if event.get("eventAction") == "registration":
            raw = event.get("eventDate")
            if not raw:
                return None
            try:
                dt = datetime.fromisoformat(raw.replace("Z", "+00:00"))
            except ValueError:
                return None
            if dt.tzinfo is None:
                dt = dt.replace(tzinfo=timezone.utc)
            return dt.astimezone(timezone.utc)
    return None


def age_in_days(registered, now=None):
    """Whole days since registration. Never negative."""
    now = now or datetime.now(timezone.utc)
    return max((now - registered).days, 0)


def freshness_points(age_days):
    """Score contribution for a domain of this age."""
    for limit, points in AGE_TIERS:
        if age_days < limit:
            return points
    return 0


def check_domain_age(domain, now=None):
    """Look up domain registration date via RDAP."""
    url = RDAP_URL.format(domain=domain.strip().lower())
    resp, err = safe_request("GET", url, timeout=15)

    if resp is not None and resp.status_code == 404:
        return {"status": "not_found",
                "reason": "domain not registered (RDAP 404)"}
    if resp is None or err:
        reason = (err or {}).get("reason", "RDAP request failed")
        return {"status": "error", "reason": reason}
    if resp.status_code >= 400:
        return {"status": "error",
                "reason": f"RDAP HTTP {resp.status_code}"}

    try:
        data = resp.json()
    except ValueError:
        return {"status": "error", "reason": "RDAP returned invalid JSON"}

    registered = parse_registration_date(data)
    if registered is None:
        return {"status": "not_found",
                "reason": "no registration date in RDAP response"}

    days = age_in_days(registered, now)
    return {
        "status": "ok",
        "kind": "domain_age",
        "date": registered.date().isoformat(),
        "age_days": days,
        "points": freshness_points(days),
        "source": "rdap",
    }


def check_freshness(ioc, ioc_type):
    """Entry point. Only domains are supported for now."""
    if ioc_type != "domain":
        return {"status": "not_applicable",
                "reason": f"freshness not supported for {ioc_type}"}
    return check_domain_age(ioc)

