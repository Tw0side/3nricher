# Adding a New Source

This guide walks through adding a new threat intelligence source to 3nricher,
end-to-end. Follow it exactly the first time. After you've done it once, you'll
know which steps you can skip.

## Overview

Each source is a self-contained module in `sources/`. The module exposes one
function that the enrichment pipeline calls for every IOC. The orchestrator
(`enrichment.py`) doesn't know anything about specific sources — it just calls
`query()` and merges the results.

This is why adding a source doesn't require modifying the orchestrator's logic.
If you find yourself editing `enrichment.py::enrich_one()`, stop and re-read
this guide.

## The Contract

Every source module MUST expose:

```python
def query(ioc: str, ioc_type: str) -> dict:
    """Query the source for a single IOC."""
Args:

ioc — The IOC value as a string (e.g., "8.8.8.8", "google.com", "84c828...")

ioc_type — One of: "ip", "domain", "md5", "sha1", "sha256", "unknown"

Returns: a dict with a "status" key. Valid values:

Status	When	Required fields
"ok"	Source returned data	source-specific fields
"not_found"	Source queried successfully, IOC unknown	"reason"
"not_applicable"	Source doesn't support this IOC type	"reason"
"error"	API error (network, auth, malformed response)	"reason"
Rules:

Never raise exceptions. Always return a status dict.

Never return None.

Return not_applicable early — before making any HTTP calls.

Include a reason on every non-ok status.

Complete Walkthrough
Let's add a hypothetical source called ExampleIntel that enriches IPs with a
reputation score.

Step 1: Create the Source Module
Create sources/exampleintel.py:

python
"""
ExampleIntel enrichment.

Enriches: IPs only.
Auth: API key in X-API-Key header.
Docs: https://example.com/api/docs
"""
import logging

from config import Config
from sources.base import safe_request, http_error_reason

log = logging.getLogger("3nricher.sources.exampleintel")

BASE_URL = "https://api.exampleintel.com/v1/ip"


def query(ioc: str, ioc_type: str) -> dict:
    """Query ExampleIntel for an IP."""
    # 1. Self-declare applicability — do this FIRST
    if ioc_type != "ip":
        return {
            "status": "not_applicable",
            "reason": "ExampleIntel only supports IPs",
        }

    # 2. Check API key
    api_key = Config.EXAMPLEINTEL_API_KEY
    if not api_key:
        return {"status": "error", "reason": "EXAMPLEINTEL_API_KEY not set"}

    # 3. Build the request
    url = f"{BASE_URL}/{ioc}"
    headers = {"X-API-Key": api_key}

    # 4. Make the request via safe_request (retry + cache built in)
    r, err = safe_request(
        "GET",
        url,
        headers=headers,
        timeout=Config.HTTP_TIMEOUT,
    )
    if err:
        return err

    # 5. Handle response by status code
    if r.status_code == 200:
        try:
            data = r.json()
        except ValueError as e:
            log.warning("Unexpected ExampleIntel response for %s: %s", ioc, e)
            return {"status": "error", "reason": "unexpected response shape"}

        return {
            "status": "ok",
            "reputation": data.get("reputation", ""),
            "score": data.get("score", 0),
            "tags": data.get("tags", []),
        }

    if r.status_code == 404:
        return {"status": "not_found", "reason": "IP not in ExampleIntel"}

    return {"status": "error", "reason": http_error_reason(r.status_code)}
Notes on this pattern:

safe_request() returns (response, None) on success or (None, error_dict) on failure.

http_error_reason() maps HTTP codes to human strings (401 → "invalid API key").

log.warning() for unexpected shapes — never crash, always return.

Step 2: Add the API Key to config.py
Open config.py and find the Config class.

Add to the API keys section:

python
    EXAMPLEINTEL_API_KEY: str | None = os.getenv("EXAMPLEINTEL_API_KEY")
Add to the validate() method:

python
        if not cls.EXAMPLEINTEL_API_KEY:
            warnings.append(
                "EXAMPLEINTEL_API_KEY not set — ExampleIntel enrichment disabled"
            )
Add to redacted_summary():

python
            "EXAMPLEINTEL_API_KEY": redact(cls.EXAMPLEINTEL_API_KEY),
Step 3: Update .env.example
Add:

text
# ExampleIntel API key — https://example.com/signup
EXAMPLEINTEL_API_KEY=your_key_here
Also add the real key to your local .env (never commit this file).

Step 4: Register the Source in enrichment.py
Update the imports:

python
from sources import (
    virustotal, abuseipdb, malwarebazaar, urlhaus, otx,
    greynoise, threatfox, feodo, exampleintel,
)
Add to the sources_result dict inside enrich_one():

python
    sources_result = {
        "virustotal": virustotal.query(ioc, ioc_type),
        "abuseipdb": abuseipdb.query(ioc, ioc_type),
        "malwarebazaar": malwarebazaar.query(ioc, ioc_type),
        "urlhaus": urlhaus.query(ioc, ioc_type),
        "otx": otx.query(ioc, ioc_type),
        "greynoise": greynoise.query(ioc, ioc_type),
        "threatfox": threatfox.query(ioc, ioc_type),
        "feodo": feodo.query(ioc, ioc_type),
        "exampleintel": exampleintel.query(ioc, ioc_type),
    }
Important: Every source MUST be called for every IOC. Sources self-declare
applicability — the orchestrator doesn't decide.

Step 5: Add Scoring Logic in scoring.py
Find calculate_risk(). Add a block for the new source, positioned near similar sources:

python
    # ExampleIntel
    ei = sources.get("exampleintel", {})
    if ei.get("status") == "ok":
        score += min(ei.get("score", 0), 20)
Pick a max contribution that makes sense. Guidance:

Source type	Typical max
AV verdicts (VirusTotal)	50
Confirmed malware corpus (MalwareBazaar)	40
C2 infrastructure (ThreatFox, Feodo)	25–30
Abuse reputation (AbuseIPDB)	25
URL hosting (URLhaus)	25
Community pulses (OTX)	20
Scanner classification (GreyNoise)	15
Add a floor if the source is a high-confidence signal:

python
    if ei.get("status") == "ok" and ei.get("reputation") == "malicious":
        label = _apply_floor(label, "High")
        if label == "High" and score < Config.THRESHOLD_HIGH:
            score = Config.THRESHOLD_HIGH
Step 6: Add Rationale in rationale.py
Add a function at the bottom of rationale.py:

python
def _rationale_exampleintel(ei: dict) -> str:
    status = ei.get("status")
    if status == "not_applicable":
        return "ExampleIntel: not applicable"
    if status == "not_found":
        return "ExampleIntel: not found"
    if status == "error":
        return f"ExampleIntel: error ({ei.get('reason', 'unknown')})"
    if status == "ok":
        score = ei.get("score", 0)
        contribution = min(score, 20)
        return f"ExampleIntel: score {score} → +{contribution}"
    return "ExampleIntel: unknown status"
Register it in build_rationale():

python
    # ---- ExampleIntel ----
    ei = sources.get("exampleintel", {})
    lines.append(_rationale_exampleintel(ei))
The rationale MUST match the scoring. If scoring awards 15 points for
ExampleIntel, the rationale says +15. Both modules share weights from
config.py — keep them consistent.

Step 7: Add Tests in tests/test_sources_extended.py
Add a new test class:

python
class TestExampleIntel:
    @responses.activate
    def test_success(self):
        responses.add(
            responses.GET,
            "https://api.exampleintel.com/v1/ip/45.155.205.233",
            json={"reputation": "malicious", "score": 80},
            status=200,
        )
        result = exampleintel.query("45.155.205.233", "ip")
        assert result["status"] == "ok"
        assert result["reputation"] == "malicious"
        assert result["score"] == 80

    @responses.activate
    def test_not_found(self):
        responses.add(
            responses.GET,
            "https://api.exampleintel.com/v1/ip/1.2.3.4",
            status=404,
        )
        result = exampleintel.query("1.2.3.4", "ip")
        assert result["status"] == "not_found"

    @responses.activate
    def test_rate_limited(self):
        responses.add(
            responses.GET,
            "https://api.exampleintel.com/v1/ip/1.2.3.4",
            status=429,
        )
        result = exampleintel.query("1.2.3.4", "ip")
        assert result["status"] == "error"

    def test_not_applicable_for_domain(self):
        result = exampleintel.query("google.com", "domain")
        assert result["status"] == "not_applicable"

    def test_not_applicable_for_hash(self):
        result = exampleintel.query("a" * 64, "sha256")
        assert result["status"] == "not_applicable"
Don't forget to import the module at the top of the test file:

python
from sources import greynoise, threatfox, feodo, exampleintel
Step 8: Run the Tests
bash
python -m pytest -q
All tests must pass. If they don't, read the failure output and fix.

If the failure is responses not registered, you forgot to add the mock.
If the failure is a missing import, check that you registered the module.

Step 9: Verify With a Real IOC
Once tests pass, run a real query against a live API:

bash
python 3nricher.py query 45.155.205.233
Look for your source in the output. Confirm the status, detail line, and score
contribution are what you expect.

Step 10: Update the README
Add your source to the Sources table in README.md:

markdown
| [ExampleIntel](https://example.com/) | IP | `X-API-Key` header | Reputation score |
Also update the Applicability Matrix table:

IOC Type	VT	AbuseIPDB	...	ExampleIntel
IP	✅	✅	...	✅
Domain	✅	⏭️	...	⏭️
Hash	✅	⏭️	...	⏭️
Step 11: Commit
Stage the right files and commit with a conventional message:

bash
git add sources/exampleintel.py \
        config.py \
        .env.example \
        enrichment.py \
        scoring.py \
        rationale.py \
        tests/test_sources_extended.py \
        README.md

git commit -m "feat: add ExampleIntel source integration"
Check git status before committing. Do not stage .env, report.json,
report.csv, cache/, data/, or out/.

Step 12: Open a Pull Request
Push your branch and open a PR. The PR template will guide you through the
checklist.

Common Pitfalls
Forgetting the not_applicable early return
Problem: You make an HTTP call for a domain when your source only supports IPs.

Fix: Return not_applicable at the top of query():

python
if ioc_type != "ip":
    return {"status": "not_applicable", "reason": "only supports IPs"}
Raising exceptions
Problem: Your code does raise ValueError(...) when the response is unexpected.

Fix: Catch the exception and return an error status:

python
try:
    data = r.json()
except ValueError as e:
    log.warning("Malformed JSON from ExampleIntel: %s", e)
    return {"status": "error", "reason": "malformed JSON"}
The orchestrator doesn't catch exceptions from sources. If you raise, the
whole enrichment run for that IOC fails.

Not registering the source
Problem: You created sources/yoursource.py but the output never includes it.

Fix: Add it to the sources_result dict in enrichment.py::enrich_one().

Scoring and rationale mismatch
Problem: Scoring awards 15 points, rationale says +20. Now the total
doesn't add up.

Fix: Import the weight from config.py or use the same computation in
both places. If you need to change the weight later, change it in one place.

Wrong HTTP method
Problem: Some APIs need POST with JSON body. requests.post(url, data=...)
sends form-encoded data, not JSON.

Fix: Use the json_body parameter of safe_request:

python
r, err = safe_request(
    "POST",
    url,
    headers=headers,
    json_body={"query": "search_ioc", "search_term": ioc},
)
ThreatFox is an example of a source that needs this.

Reference Sources
Good examples to study:

Source	File	What it demonstrates
VirusTotal	sources/virustotal.py	Multiple IOC types, header auth
AbuseIPDB	sources/abuseipdb.py	Simple GET, header auth, nested response
MalwareBazaar	sources/malwarebazaar.py	POST form data, abuse.ch Auth-Key
ThreatFox	sources/threatfox.py	POST JSON body, deduplication
Feodo	sources/feodo.py	Bulk blocklist download + search
GreyNoise	sources/greynoise.py	Classification-only response
Checklist
Before opening your PR, confirm:

□ sources/yoursource.py exists with query() matching the contract
□ API key added to config.py, .env.example, and local .env
□ Source registered in enrichment.py::enrich_one()
□ Scoring logic added in scoring.py
□ Rationale function added in rationale.py and registered in build_rationale()
□ Tests added in tests/test_sources_extended.py
□ All existing tests still pass (python -m pytest -q)
□ Real IOC query tested and output verified
□ README Sources table and Applicability Matrix updated
□ No secrets in the diff (git diff --staged should show no .env)
Need Help?
Open a GitHub issue with the question label

Reference existing sources for the pattern

Read docs/architecture.md for how modules fit together
