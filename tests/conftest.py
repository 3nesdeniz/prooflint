from __future__ import annotations

from pathlib import Path

import pytest

from tests.helpers import write_bundle


@pytest.fixture
def evidence_bundle(tmp_path: Path) -> tuple[Path, str, str]:
    return write_bundle(tmp_path)
