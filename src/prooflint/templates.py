"""Built-in, synthetic finding templates."""

FINDING_TEMPLATE = """---
schema_version: \"0.1\"
id: FINDING-001
title: Replace with a concise finding title
profile: ai-system
status: unverified
target:
  system: replace-with-authorized-target
  version: replace-with-version-or-revision
scope:
  authorized: false
  description: Replace with the explicit authorization and test scope
  boundaries:
    - Replace with an in-scope boundary
preconditions:
  - Replace with a required condition
affected_boundary: Replace with the affected trust boundary
expected: Replace with the expected safe behavior
observed: Replace with the observed behavior
impact: Replace with an evidence-linked impact statement
confidence: low
evidence:
  - kind: redacted_trace
    path: evidence/replace-me.txt
    sha256: replace-with-64-character-sha256
    state: unverified
    redacted: true
    sensitive: false
    description: Synthetic or safely redacted supporting material
reproduction:
  attempts: 0
  successes: 0
  environment: Replace with a controlled test environment
  steps:
    - Replace with a deterministic, authorized validation step
remediation: Replace with a bounded remediation
retest:
  - Replace with a deterministic regression check
---

## Notes

Keep secrets, live exploit payloads, and personal data out of this report.
Prooflint validates evidence hygiene; it does not execute tests or prove exploitability.
"""
