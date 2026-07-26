# Prooflint

Prooflint is a local-first evidence gate for AI-security findings and AI-assisted
vulnerability reports. It turns “this looks vulnerable” into a deterministic checklist:
what was authorized, what exact target was tested, what was expected, what was observed,
which artifacts support the claim, and how another reviewer can retest it.

Prooflint does **not** scan targets, execute proof-of-concept payloads, prove
exploitability, assign truth, certify compliance, or submit reports. It parses local
Markdown or JSON and reads only the evidence files you explicitly reference.

## Why it exists

AI-generated security reports can sound certain while omitting the details that make a
claim reviewable. Prooflint checks the report structure before triage, disclosure, or
publication. Its rules favor bounded claims and reproducible evidence over persuasive
language.

## Install locally

Prooflint requires Python 3.11 or newer.

```bash
python -m pip install -e .
prooflint --version
```

For contributors using [uv](https://docs.astral.sh/uv/):

```bash
uv sync --extra dev
uv run prooflint --version
```

## Quick start

Create a report template:

```bash
prooflint init finding.md
```

Replace every placeholder, place safely redacted evidence beneath a dedicated directory,
record its SHA-256 in the finding, then check it:

```bash
prooflint check finding.md --evidence-root ./review-bundle
```

Generate and verify a deterministic manifest:

```bash
prooflint manifest finding.md \
  --evidence-root ./review-bundle \
  --out evidence-manifest.json

prooflint verify evidence-manifest.json --evidence-root ./review-bundle
```

Machine-readable output is available for automation:

```bash
prooflint check finding.md --format json
prooflint check finding.md --format sarif --out prooflint.sarif
```

See the fully synthetic passing example in
[`examples/findings/verified-synthetic.md`](examples/findings/verified-synthetic.md) and
its committed [`evidence-manifest.json`](examples/evidence-manifest.json), plus the
[Turkish quick start](docs/QUICKSTART_TR.md).

## Finding format

Markdown findings use YAML frontmatter followed by optional reviewer notes. JSON findings
use the same fields and may include a `body` string. The current schema version is `0.1`.

```yaml
---
schema_version: "0.1"
id: FINDING-001
title: Synthetic authorization-boundary regression
profile: ai-system
status: verified
target:
  system: synthetic-agent-fixture
  version: fixture-v1
scope:
  authorized: true
  description: Local synthetic fixture only
  boundaries: [tool-approval-gate]
preconditions: [A synthetic request reaches the approval gate]
affected_boundary: tool-approval-gate
expected: The request is denied before a tool action is accepted.
observed: The fixture records an accepted request after a policy label is removed.
impact: The attached redacted trace supports a hypothetical authorization-bypass claim.
confidence: high
evidence:
  - kind: redacted_trace
    path: evidence/trace.txt
    sha256: 64-lowercase-hex-characters
    state: verified
    redacted: true
    sensitive: false
    description: Synthetic trace with no live target data
reproduction:
  attempts: 3
  successes: 3
  environment: Offline synthetic fixture
  steps: [Replay the fixed fixture and compare its recorded decision]
remediation: Bind the policy label to the signed request envelope.
retest: [Replay the same fixture and require three denied decisions]
---
```

The authoritative machine-readable schemas ship in
[`src/prooflint/schema`](src/prooflint/schema).

## Rules

| Rule | Requirement |
| --- | --- |
| `PL001` | Target identifier and immutable fingerprint are present. |
| `PL002` | Explicit authorization and scope are recorded. |
| `PL003` | Preconditions and the affected boundary are named. |
| `PL004` | `verified` claims have successful attempts and verified evidence. |
| `PL005` | Expected and observed behavior are both present and distinct. |
| `PL006` | Impact is stated and linked to an evidence file. |
| `PL007` | Reproduction counters, environment, steps, and status are consistent. |
| `PL008` | Evidence paths are safe and declared SHA-256 hashes match. |
| `PL009` | Remediation and deterministic retest steps are present. |
| `PL010` | Sensitive evidence is marked redacted. |

Rules are deterministic and run in rule-code order. A rule violation is evidence hygiene
feedback—not a verdict that the underlying security claim is false.

## Exit codes

| Code | Meaning |
| --- | --- |
| `0` | All findings passed, or the manifest verified. |
| `1` | One or more rule violations or verification mismatches were found. |
| `2` | Usage, finding/manifest parsing, schema-version, or tool error. |

## Python API

```python
from prooflint import build_manifest, load_finding, validate_finding, verify_manifest

finding = load_finding("finding.md")
result = validate_finding(finding, evidence_root="review-bundle")
if result.passed:
    manifest = build_manifest(finding, evidence_root="review-bundle")
```

Parser and validator results are deeply immutable, including values created through the
exported dataclass constructors. `build_manifest` intentionally returns a fresh plain mapping
for direct JSON serialization; callers may mutate that owned copy without changing the finding
or a later manifest. The API never contacts a network service.

## Safety model

- Finding and manifest files must be regular UTF-8 files no larger than 2 MiB.
- Duplicate YAML/JSON keys and non-standard JSON constants are rejected as ambiguous input.
- Symlinks are rejected at the finding, manifest, output, and evidence leaves and at every
  existing ancestor component.
- Evidence paths must be canonical POSIX-relative paths beneath the selected root.
- Absolute paths, `..`, backslashes, duplicate entries, and non-regular files are rejected.
- SHA-256 is streamed from the same no-follow descriptor that was confined and checked;
  manifests contain no timestamp or absolute path.
- File reporters write atomically and refuse to overwrite an input finding or evidence file.
- A JSON report written inside a scanned directory becomes a discovered input on the next run;
  choose an output outside that directory instead of asking Prooflint to overwrite it.
- Prooflint never renders HTML, evaluates templates, imports finding code, or executes a
  command from a report.
- Keep credentials, personal data, proprietary prompts, live exploit payloads, and raw
  customer data out of review bundles. Redact before hashing.

Path confinement reduces accidental disclosure and traversal risk, but it does not make
untrusted content safe to publish. Review artifacts manually before sharing them.

## Development

```bash
uv sync --extra dev --locked
uv run ruff format --check .
uv run ruff check .
uv run mypy src
uv run pytest --cov=prooflint --cov-report=term-missing --cov-fail-under=95
uv build --no-build-isolation --clear
uv run twine check dist/*
uv run check-wheel-contents dist/*.whl
```

`hatchling==1.27.0` is pinned both as the PEP 517 backend and in `uv.lock`. The
`--no-build-isolation` build above therefore consumes the backend and dependencies installed by
the locked sync. Build twice from the same source into empty output directories and compare both
artifacts byte-for-byte when checking reproducibility.

See [CONTRIBUTING.md](CONTRIBUTING.md) for test and change requirements and
[SECURITY.md](SECURITY.md) for responsible vulnerability reporting.

## License

Apache License 2.0. See [LICENSE](LICENSE).
