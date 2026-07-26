# Contributing

Contributions that make evidence requirements clearer, safer, or more deterministic are
welcome.

## Before proposing a change

1. Explain the evidence-hygiene problem and the false-positive trade-off.
2. Keep target interaction, payload execution, report submission, and network collection out
   of scope.
3. For a rule change, include passing, failing, contradiction, and boundary tests.
4. Preserve stable rule codes and output schemas. A semantic change requires a changelog
   entry and, when incompatible, a new schema version.

## Local checks

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

Tests must not contact external services, execute report content, depend on wall-clock time,
or include real vulnerability data. Use temporary directories and synthetic artifacts.

## Commit and review hygiene

Keep changes focused. Do not commit generated virtual environments, caches, local findings,
or unredacted evidence. Security issues follow [SECURITY.md](SECURITY.md), not the public
issue tracker.
