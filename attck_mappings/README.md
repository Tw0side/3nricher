# ATT&CK Mappings

YAML files that map a malware family to MITRE ATT&CK techniques.

The enrichment pipeline loads these files at startup. When a source (for
example MalwareBazaar) returns a malware family name for an IOC, the pipeline
looks up that name here and adds the matching techniques to the output.

- [Layout](#layout)
- [Quick Start](#quick-start)
- [Schema](#schema)
- [Full Example](#full-example)
- [Naming Rules](#naming-rules)
- [Matching Rules](#matching-rules)
- [Official vs Community](#official-vs-community)
- [Output and Provenance](#output-and-provenance)
- [Quality Rules](#quality-rules)
- [Validation](#validation)
- [Contributing](#contributing)
- [Review Checklist](#review-checklist)
- [Troubleshooting](#troubleshooting)
- [Security](#security)
- [License](#license)

---

## Layout

```
attck_mappings/
├── README.md             This file
├── official/             Reviewed. Owned by maintainers.
│   ├── wannacry.yaml
│   ├── lockbit.yaml
│   ├── emotet.yaml
│   ├── qakbot.yaml
│   └── cobalt_strike.yaml
└── community/            Contributed. Lower trust.
    ├── _template.yaml    Copy this to start a new mapping
    └── ...
```

Files that start with `_` are ignored by the loader.

---

## Quick Start

```bash
cp attck_mappings/community/_template.yaml attck_mappings/community/my_malware.yaml
# edit the file
python -m enricher.validate attck_mappings/community/my_malware.yaml
```

Then open a PR. See [Contributing](#contributing).

---

## Schema

```yaml
malware: <lowercase-name>          # required
aliases:                           # optional
  - <alternate-name>
category: <category>               # optional
attack_version: "<version>"        # optional
references:                        # optional, but see Quality Rules
  - <url>
techniques:                        # required, at least one
  - id: T<number>[.<sub>]          # required
    name: <technique-name>         # required
    tactic: <tactic>               # optional
    note: <short text>             # optional
```

### Field Reference

| Field | Required | Type | Description |
|-------|----------|------|-------------|
| `malware` | Yes | string | Primary name. Lowercase. Spaces allowed. |
| `aliases` | No | list of strings | Other names used by sources. |
| `category` | No | string | One of the values listed below. |
| `attack_version` | No | string | ATT&CK release the IDs were checked against (e.g. `"15.1"`). |
| `references` | No* | list of URLs | Public reports that back the mapping. |
| `techniques` | Yes | list | One or more technique entries. |
| `techniques[].id` | Yes | string | ATT&CK ID. Format `T####` or `T####.###`. |
| `techniques[].name` | Yes | string | Name exactly as in ATT&CK. |
| `techniques[].tactic` | No | string | Tactic short name. See list below. |
| `techniques[].note` | No | string | Why this technique applies. One line. |

\* Required for `official/`. Strongly advised for `community/`.

### Allowed `category` values

`ransomware`, `trojan`, `rat`, `worm`, `loader`, `stealer`, `botnet`,
`backdoor`, `post-exploitation`, `wiper`, `other`

### Allowed `tactic` values

Use the ATT&CK short names (lowercase, hyphens):

`reconnaissance`, `resource-development`, `initial-access`, `execution`,
`persistence`, `privilege-escalation`, `defense-evasion`,
`credential-access`, `discovery`, `lateral-movement`, `collection`,
`command-and-control`, `exfiltration`, `impact`

One technique can fit more than one tactic. List it once per tactic if the
pipeline should show both.

### ID format

| Valid | Invalid |
|-------|---------|
| `T1486` | `1486` |
| `T1059.003` | `T1059-003` |
| `T1566.001` | `t1566.001` |

Regex: `^T\d{4}(\.\d{3})?$`

---

## Full Example

```yaml
malware: wannacry
aliases:
  - wanacry
  - wcry
  - wanacrypt0r
  - wannacrypt
category: ransomware
attack_version: "15.1"
references:
  - https://attack.mitre.org/software/S0366/
techniques:
  - id: T1486
    name: Data Encrypted for Impact
    tactic: impact
  - id: T1490
    name: Inhibit System Recovery
    tactic: impact
  - id: T1210
    name: Exploitation of Remote Services
    tactic: lateral-movement
  - id: T1543.003
    name: "Create or Modify System Process: Windows Service"
    tactic: persistence
```

Always quote `name` if it contains a colon.

See `official/wannacry.yaml` for the live file.

---

## Naming Rules

| Item | Rule | Good | Bad |
|------|------|------|-----|
| Filename | lowercase, underscores, `.yaml` | `cobalt_strike.yaml` | `Cobalt Strike.yaml`, `QBot.yml` |
| `malware` | lowercase, spaces allowed | `cobalt strike` | `CobaltStrike` |
| `aliases` | any spelling seen in the wild | `qbot`, `pinkslipbot` | (none) |

Filename should match `malware` with spaces turned into underscores.

---

## Matching Rules

How the pipeline turns a source string into a mapping:

1. Source name is lowercased and trimmed.
2. Exact match against `malware` and every `aliases` entry.
3. No fuzzy match. A typo from a source will not match. Add it as an alias.

Rules for names:

- Each name or alias must belong to **one** file only.
- If two files claim the same name, the loader logs a warning. `official/`
  wins over `community/`.
- Do not use generic words as aliases (`trojan`, `loader`, `malware`).

---

## Official vs Community

| | `official/` | `community/` |
|---|-------------|--------------|
| Who edits | Maintainers | Anyone via PR |
| References | Required | Advised |
| Review | Two maintainers | One maintainer |
| Wins on name clash | Yes | No |
| Output tag | `trust: official` | `trust: community` |

A community file can be promoted to `official/` after review.

---

## Output and Provenance

Each technique in the enriched output carries where it came from:

```json
{
  "id": "T1486",
  "name": "Data Encrypted for Impact",
  "tactic": "impact",
  "source": "malwarebazaar:WannaCry"
}
```

`source` is `<feed>:<family string the feed returned>`.

Analysts use this to judge confidence. A mapping reached through an alias
from one feed is weaker than one reached by exact name from several feeds.

These are mappings by **family**, not proof of behaviour for one sample.
Treat them as leads, not facts.

---

## Quality Rules

- Map only what public reporting supports.
- Cite at least one reference. Best source: `attack.mitre.org/software/S####/`.
  Vendor reports and CISA advisories are fine too.
- Use sub-techniques when the report is specific.
  - Better: `T1566.001` Spearphishing Attachment
  - Weaker: `T1566` Phishing
- Do not pad. Ten solid techniques beat forty guesses.
- One family per file. Do not merge variants unless sources treat them as one.
  Version splits (for example `lockbit` 2.0 vs 3.0) can use `note` or a
  separate file.
- Check that the ID and name pair exists in the ATT&CK release you target.
  Set `attack_version`.
- Do not copy long text from reports. Link to them.

---

## Validation

Run before every PR:

```bash
python -m enricher.validate attck_mappings/
```

The check fails when:

- YAML does not parse
- `malware` or `techniques` is missing or empty
- A technique has no `id` or `name`
- An `id` does not match the regex
- `tactic` or `category` is not in the allowed list
- Same technique `id` appears twice in one file with the same `tactic`
- A name or alias appears in more than one file
- Filename does not match `malware`

CI runs the same command on every PR.

---

## Contributing

1. Fork the repo.
2. Copy `community/_template.yaml` to `community/<name>.yaml`.
3. Fill in the schema.
4. Add at least one reference URL.
5. Run the validator.
6. Open a PR titled `attck: add <malware-name> mapping`.

To fix an existing file, title the PR `attck: fix <malware-name> mapping`
and say what source supports the change.

In the PR body, give:

- Source links for each technique you added or removed
- Why an alias was added (which feed returned it)

---

## Review Checklist

For maintainers:

- [ ] Validator passes
- [ ] Filename and `malware` match
- [ ] References open and support the claims
- [ ] No unsupported techniques
- [ ] Sub-techniques used where the source is specific
- [ ] No alias clash with another file
- [ ] `attack_version` set and IDs exist in that release
- [ ] Nothing copied from copyrighted text

---

## Troubleshooting

| Problem | Likely cause | Fix |
|---------|--------------|-----|
| No techniques in output | Family string not matched | Check the exact string from the feed. Add it as an alias. |
| File ignored | Name starts with `_` or ext is not `.yaml` | Rename. |
| Loader warning: duplicate name | Same name or alias in two files | Remove it from one. |
| YAML parse error | Unquoted colon in `name` | Wrap the value in quotes. |
| Wrong technique shown | Alias too broad | Remove or narrow the alias. |
| Old data after edit | Files load at startup | Restart the pipeline. |

---

## Security

- Files are data only. The loader uses `yaml.safe_load`. Never add tags like
  `!!python/object`. PRs that do will be rejected.
- Do not put IOCs, samples, or credentials in these files. Mappings only.
- Reference links must be public. No paywalled or private URLs.

---

## License

Mappings are released under the project license. See the `LICENSE` file at
the repo root. ATT&CK is a trademark of The MITRE Corporation. Technique IDs
and names come from ATT&CK, used under the MITRE ATT&CK terms of use.
