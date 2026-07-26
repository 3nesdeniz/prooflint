---
schema_version: "0.1"
id: SYNTH-001
title: Synthetic policy-label binding regression
profile: ai-system
status: verified
target:
  system: synthetic-agent-fixture
  version: fixture-v1
scope:
  authorized: true
  description: Offline synthetic fixture owned by the test author
  boundaries:
    - tool-approval-gate
preconditions:
  - The fixed synthetic request reaches the approval gate
  - The fixture omits its synthetic policy label
affected_boundary: tool-approval-gate
expected: The fixture records a denied decision before any synthetic action is accepted.
observed: The fixture records an accepted decision when the synthetic policy label is absent.
impact: The attached redacted trace supports a hypothetical authorization-boundary regression.
confidence: high
evidence:
  - kind: redacted_trace
    path: evidence/verified/synthetic-trace.txt
    sha256: 402b9c878d2862b14210f0adb9d83b0ac72c91e803f350549377bf07bbf924bc
    state: verified
    redacted: true
    sensitive: false
    description: Harmless synthetic trace containing no live target data
reproduction:
  attempts: 3
  successes: 3
  environment: Offline deterministic fixture; no network or target interaction
  steps:
    - Read the fixed synthetic trace
    - Compare expected_decision with observed_decision
    - Repeat the same comparison three times
remediation: Bind the synthetic policy label to the signed request envelope before evaluation.
retest:
  - Replay the unchanged fixture and require three denied decisions
---

## Reviewer note

This example is fictional. It demonstrates report structure, not a vulnerability in a real
system.
