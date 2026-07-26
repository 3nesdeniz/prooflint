# Security policy

## Supported versions

Prooflint is pre-1.0. Security fixes are applied to the latest released minor version.

## Reporting a vulnerability

Do not open a public issue containing exploit details, credentials, personal data, or
private evidence. Use the repository's GitHub **Private vulnerability reporting** channel
when it is available. If that channel is unavailable, open a public issue containing only
a request for a private coordination channel—do not include the vulnerability itself.

Include the affected Prooflint version, operating system, minimal safe reproduction, impact,
and whether the report concerns path confinement, parser behavior, hash verification, or
output handling. Use synthetic files wherever possible.

You should receive acknowledgement when a maintainer has reviewed the private report. No
fixed response or remediation deadline is promised. Please allow time to reproduce and
coordinate a safe release before public disclosure.

## Scope

Security-sensitive areas include unsafe path traversal, symlink bypasses, unintended code
execution, parser resource exhaustion, hash-verification bypasses, and disclosure of local
paths or file contents. A rule's inability to determine whether an external vulnerability
claim is true is not a Prooflint security defect: Prooflint is an evidence-hygiene linter,
not a scanner or exploitability oracle.
