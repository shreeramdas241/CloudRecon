"""Interval runner with bounded retry. It does not patch instances."""

from __future__ import annotations

from collections.abc import Callable
from time import sleep as default_sleep

from cloudrecon.logging_utils import get_logger

LOGGER = get_logger(__name__)


class ScanScheduler:
    def __init__(
        self,
        runner: Callable[[], None],
        *,
        interval_seconds: int,
        backoff_seconds: int = 30,
        sleeper: Callable[[float], None] = default_sleep,
        on_failure: Callable[[Exception], None] | None = None,
    ) -> None:
        self.runner = runner
        self.interval_seconds = interval_seconds
        self.backoff_seconds = backoff_seconds
        self.sleeper = sleeper
        self.on_failure = on_failure

    def run(self, max_iterations: int | None = None) -> int:
        completed = 0
        while max_iterations is None or completed < max_iterations:
            try:
                self.runner()
            except Exception as exc:
                LOGGER.warning("scheduled assessment failed: %s", exc)
                if self.on_failure:
                    self.on_failure(exc)
                self.sleeper(self.backoff_seconds)
                completed += 1
                continue
            completed += 1
            if max_iterations is None or completed < max_iterations:
                self.sleeper(self.interval_seconds)
        return completed
