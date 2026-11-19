from __future__ import annotations

from pathlib import Path

import pytest
from cloudrecon.config import Settings


@pytest.fixture
def settings(tmp_path: Path) -> Settings:
    return Settings(mode="demo", database_path=str(tmp_path / "cloudrecon.db"))
