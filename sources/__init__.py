
"""
3nricher sources package.

Each source module exposes a single function:

    query(ioc: str, ioc_type: str) -> dict

The returned dict MUST include a "status" key. Valid values:

    "ok"              — source returned data
    "not_found"       — source queried successfully, IOC unknown
    "not_applicable"  — source does not support this IOC type
    "error"           — API error (include "reason")

Modules should never raise exceptions to the caller; all failures are
reported via the "error" status.

Modules:
    virustotal      — VT v3 API (IPs, domains, file hashes)
    abuseipdb       — AbuseIPDB v2 API (IPs)
    malwarebazaar   — MalwareBazaar API (file hashes)
    urlhaus         — URLhaus API (domains)
"""
