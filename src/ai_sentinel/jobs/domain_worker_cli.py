import argparse
import json
import sys

from ai_sentinel.config import Settings
from ai_sentinel.db.json_repository import JsonRepository
from ai_sentinel.db.repository import PersistenceError
from ai_sentinel.logging_config import configure_logging
from ai_sentinel.scanners.domain_worker import (
    DomainWorkerError,
    PassiveDomainCheckWorker,
)


def main() -> int:
    parser = argparse.ArgumentParser(
        description="Execute a queued passive domain assessment."
    )
    parser.add_argument("--job-id", required=True)
    arguments = parser.parse_args()
    settings = Settings.from_environment()
    configure_logging(settings.log_level)
    repository = JsonRepository(settings.data_file)
    worker = PassiveDomainCheckWorker(repository)
    try:
        assessment = worker.execute(arguments.job_id)
    except (DomainWorkerError, PersistenceError, ValueError) as exc:
        print(str(exc), file=sys.stderr)
        return 1
    print(
        json.dumps(
            {
                "assessment_id": assessment.assessment_id,
                "assessment_status": assessment.status.value,
                "domain_checks": next(
                    (
                        item.model_dump(mode="json")
                        for item in assessment.coverage_preview
                        if item.control == "domain_checks"
                    ),
                    None,
                ),
            }
        )
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
