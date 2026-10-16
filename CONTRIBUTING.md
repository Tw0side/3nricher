# Contributing to 3nricher

Thanks for your interest in contributing. This document covers the workflow,
code standards, and expectations for contributors.

## Getting Started

### 1. Fork and Clone

1. Fork this repository on GitHub (click "Fork" top-right).
2. Clone your fork:

```bash
git clone git@github.com:<your-username>/3nricher.git
cd 3nricher
Add the upstream remote so you can pull future changes:

bash
git remote add upstream https://github.com/Tw0side/3nricher.git
Create a virtual environment:

bash
python -m venv venv
source venv/bin/activate     # Windows: venv\Scripts\activate
pip install -r requirements.txt
Copy .env.example to .env and add your own API keys:

bash
cp .env.example .env
# Edit .env — at minimum, add VT_API_KEY
Get a free VirusTotal API key here:
https://www.virustotal.com/gui/my-apikey

2. Verify Your Setup
bash
python -m pytest -q
You should see 172 passed. If not, open an issue before continuing.

Development Workflow
Always Work on a Branch
Never commit directly to main.

bash
git checkout -b feat/your-feature-name
Branch naming convention:

Prefix	Use for
feat/	New features
fix/	Bug fixes
docs/	Documentation only
test/	Tests only
refactor/	Code restructuring without behavior change
Make Changes
Match existing code style (see standards below).

Add tests for any new behavior.

Run python -m pytest -q frequently.

Commit in small, logical chunks.

Commit Messages
Follow Conventional Commits:

text
feat: add IPinfo source integration
fix: correct VT detection ratio for zero-verdict responses
docs: expand adding-a-source guide with retry examples
test: add coverage for freshness detection tiers
refactor: extract HTTP retry logic into base.py
Rules:

Subject under 72 characters

Imperative mood ("add", not "added")

No period at the end

Body (optional) explains why, not what

Push and Open a Pull Request
bash
git push origin feat/your-feature-name
Then open a PR against Tw0side/3nricher:main.

The PR template will guide you through the checklist.

Code Standards
Python
4-space indentation, no tabs

Max line length: 100 characters

Type hints on all function signatures

Docstrings on all public functions

Use logging, never print() for diagnostics

Good:

python
def query(ioc: str, ioc_type: str) -> dict:
    """
    Query ExampleSource for an IOC.

    Returns a dict with a "status" key. Never raises.
    """
    if ioc_type != "ip":
        return {
            "status": "not_applicable",
            "reason": "ExampleSource only supports IPs",
        }
    ...
Bad:

python
def query(ioc, ioc_type):
    if ioc_type != "ip": return {"status": "not_applicable"}
    ...
The Source Module Contract
Every module in sources/ must expose:

python
def query(ioc: str, ioc_type: str) -> dict:
    """Query <source> for an IOC."""
Return values MUST include a status key:

Status	Meaning
"ok"	Source returned data
"not_found"	Source queried, IOC unknown
"not_applicable"	Source doesn't support this IOC type
"error"	API error (include "reason")
Rules:

Never raise exceptions to the caller.

Never return None.

Return not_applicable early for unsupported types — don't make an HTTP call first.

Always include a reason on error and not_found.

HTTP Requests
All HTTP goes through safe_request() from sources/base.py:

python
from sources.base import safe_request, http_error_reason

r, err = safe_request("GET", url, headers=headers, timeout=Config.HTTP_TIMEOUT)
if err:
    return err
This gives you:

Automatic retry with exponential backoff

Respect for Retry-After header

SQLite-backed response caching

Structured error dicts (no exceptions)

For JSON request bodies, use json_body=, not data=:

python
r, err = safe_request("POST", url, headers=headers, json_body={"query": "..."})
Tests
Use pytest and the responses library for HTTP mocking.

No live API calls in tests.

Every new source needs at least three tests: success, not_found, not_applicable.

Every new scoring rule needs a test.

Example:

python
class TestExampleSource:
    @responses.activate
    def test_success(self):
        responses.add(
            responses.GET,
            "https://api.example.com/ip/8.8.8.8",
            json={"status": "ok", "reputation": "clean"},
            status=200,
        )
        result = example.query("8.8.8.8", "ip")
        assert result["status"] == "ok"

    def test_not_applicable_for_domain(self):
        result = example.query("google.com", "domain")
        assert result["status"] == "not_applicable"
Adding a New Source
See docs/adding-a-source.md for the complete walkthrough. This is the most common type of contribution.

Adding an ATT&CK Mapping
See attck_mappings/README.md for the schema.

Community mappings live in attck_mappings/community/. Each mapping is one
YAML file. Include a reference URL from attack.mitre.org when possible.

Pull Request Checklist
Before opening a PR, confirm all of these:

□ Tests pass locally (python -m pytest -q — all 172+ pass)
□ New code has tests
□ No hardcoded API keys or secrets in the diff
□ No .env, report.json, report.csv, cache/, data/, or out/ in the diff
□ Commit messages follow conventional style
□ README or docs updated if behavior changed
□ You've run at least one real IOC query and confirmed the output
Review Process
Maintainer reviews PRs within ~1 week.

Expect feedback. Small, focused PRs get merged faster.

If you're unsure about a design decision, open an issue first.

Questions?
Open a GitHub issue with the question label.

Code of Conduct
Be respectful. Technical disagreements are fine; personal attacks are not.
See CODE_OF_CONDUCT.md.



