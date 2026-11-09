from typing import Protocol

from ai_sentinel.schemas.job import Job


class AssessmentWorker(Protocol):
    """Execution boundary for a separately isolated worker process."""

    def execute(self, job: Job) -> None: ...
