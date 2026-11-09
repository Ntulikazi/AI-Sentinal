import argparse
import json
from datetime import UTC, datetime
from pathlib import Path

from ai_sentinel.db.sql_auth_store import SqlAuthStore
from ai_sentinel.db.models import Tenant, User
from ai_sentinel.db.repository import CollectionName, RecordConflictError
from ai_sentinel.db.sql_repository import SqlRepository
from ai_sentinel.schemas.assessment import Assessment
from ai_sentinel.schemas.evidence import Evidence
from ai_sentinel.schemas.evaluation import EvaluationRun
from ai_sentinel.schemas.finding import Finding
from ai_sentinel.schemas.job import Job
from ai_sentinel.schemas.report import AssessmentReport
from ai_sentinel.schemas.target import Target
from ai_sentinel.schemas.test_result import TestResult


_RECORD_TYPES = {
    CollectionName.TARGETS: Target,
    CollectionName.ASSESSMENTS: Assessment,
    CollectionName.JOBS: Job,
    CollectionName.TESTS: TestResult,
    CollectionName.FINDINGS: Finding,
    CollectionName.EVIDENCE: Evidence,
    CollectionName.EVALUATIONS: EvaluationRun,
    CollectionName.REPORTS: AssessmentReport,
}
_ID_FIELDS = {
    CollectionName.TARGETS: "target_id",
    CollectionName.ASSESSMENTS: "assessment_id",
    CollectionName.JOBS: "job_id",
    CollectionName.TESTS: "test_id",
    CollectionName.FINDINGS: "finding_id",
    CollectionName.EVIDENCE: "evidence_id",
    CollectionName.EVALUATIONS: "evaluation_run_id",
    CollectionName.REPORTS: "assessment_id",
}


def migrate_json_store(repository: SqlRepository, data_file: Path) -> dict[str, int]:
    document = json.loads(data_file.read_text(encoding="utf-8"))
    counts = {collection.value: 0 for collection in CollectionName}
    for collection in CollectionName:
        record_type = _RECORD_TYPES[collection]
        id_field = _ID_FIELDS[collection]
        for raw in document["collections"][collection.value]:
            record = record_type.model_validate(raw)
            try:
                repository.create_record(collection, record, id_field=id_field)
            except RecordConflictError:
                continue
            counts[collection.value] += 1
    return counts


def main() -> int:
    parser = argparse.ArgumentParser(description="Migrate the JSON store into PostgreSQL.")
    parser.add_argument("data_file", type=Path)
    parser.add_argument("--database-url", required=True)
    parser.add_argument("--auth-file", type=Path)
    args = parser.parse_args()
    repository = SqlRepository(args.database_url)
    repository.check_ready()
    counts = migrate_json_store(repository, args.data_file)
    if args.auth_file:
        auth_document = json.loads(args.auth_file.read_text(encoding="utf-8"))
        auth_store = SqlAuthStore(repository.sessions)
        for raw in auth_document.get("users", {}).values():
            if auth_store.get_user(raw["email"]) is None:
                with repository.sessions.begin() as session:
                    tenant_id = raw.get("tenant_id") or raw["user_id"]
                    if session.get(Tenant, tenant_id) is None:
                        now = datetime.now(UTC)
                        session.add(Tenant(tenant_id=tenant_id, created_at=now, updated_at=now))
                    session.add(
                        User(
                            user_id=raw["user_id"],
                            tenant_id=tenant_id,
                            email=raw["email"].lower(),
                            full_name=raw["full_name"],
                            password_salt=raw["password_salt"],
                            password_hash=raw["password_hash"],
                            terms_accepted_at=raw["terms_accepted_at"],
                            created_at=datetime.now(UTC),
                            updated_at=datetime.now(UTC),
                        )
                    )
    print(json.dumps(counts))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
