import json
from datetime import UTC, datetime, timedelta

from fastapi.testclient import TestClient

from ai_sentinel.api.app import create_app
from ai_sentinel.config import Settings
from ai_sentinel.db.json_repository import JsonRepository
from ai_sentinel.db.repository import CollectionName
from ai_sentinel.schemas.assessment import Assessment
from ai_sentinel.schemas.job import Job


def _client(tmp_path, **settings_values):
    app = create_app(
        Settings(
            data_file=tmp_path / "store.json",
            development_identity_enabled=True,
            **settings_values,
        )
    )
    return TestClient(app), {"X-Development-User": "alice"}


def _create_target(client: TestClient, headers: dict[str, str]) -> str:
    response = client.post(
        "/api/v1/targets",
        headers=headers,
        json={
            "name": "Assessment Lab",
            "domain": "https://app.example.test",
            "repository": {
                "owner": "example",
                "name": "assessment-lab",
                "ref": "main",
            },
            "environment": "staging",
        },
    )
    assert response.status_code == 201
    return response.json()["target_id"]


def _create_assessment(
    client: TestClient, headers: dict[str, str], target_id: str
) -> dict[str, object]:
    response = client.post(
        "/api/v1/assessments",
        headers=headers,
        json={
            "target_id": target_id,
            "mode": "repository_only",
            "scope": {
                "repository_ref": "main",
                "excluded_paths": ["/tests/fixtures"],
                "active_testing_allowed": False,
            },
            "options": {
                "run_secret_scan": True,
                "run_dependency_scan": True,
                "run_static_analysis": True,
                "run_domain_checks": False,
                "run_llm_evaluations": False,
            },
        },
    )
    assert response.status_code == 201
    return response.json()


def test_missing_queued_job_repairs_assessment_for_retry(tmp_path) -> None:
    client, headers = _client(tmp_path)
    target_id = _create_target(client, headers)
    assessment = _create_assessment(client, headers, target_id)
    assessment_id = assessment["assessment_id"]
    authorization = client.post(
        f"/api/v1/assessments/{assessment_id}/authorize",
        headers=headers,
        json={
            "authorization_type": "owner_attestation",
            "scope_summary": "Read-only repository analysis.",
            "expires_at": (datetime.now(UTC) + timedelta(days=2)).isoformat(),
        },
    )
    assert authorization.status_code == 200
    queued = client.post(f"/api/v1/assessments/{assessment_id}/start", headers=headers)
    assert queued.status_code == 202
    job_id = queued.json()["job_id"]

    store_path = client.app.state.repository.data_file
    document = json.loads(store_path.read_text(encoding="utf-8"))
    document["collections"]["jobs"] = [
        record
        for record in document["collections"]["jobs"]
        if record["job_id"] != job_id
    ]
    store_path.write_text(json.dumps(document), encoding="utf-8")

    response = client.get(f"/api/v1/assessments/{assessment_id}", headers=headers)

    assert response.status_code == 200
    assert response.json()["status"] == "READY"
    assert response.json()["job_id"] is None


def test_assessment_authorization_queue_poll_and_cancel(tmp_path) -> None:
    client, headers = _client(tmp_path, max_concurrent_jobs_per_user=1)
    target_id = _create_target(client, headers)
    assessment = _create_assessment(client, headers, target_id)
    assessment_id = assessment["assessment_id"]

    assert assessment["status"] == "DRAFT"
    assert assessment["coverage_preview"][0] == {
        "control": "secret_scan",
        "tested": False,
        "reason": "Pending worker execution.",
    }
    assert assessment["coverage_preview"][3]["tested"] is False
    assert assessment["coverage_preview"][3]["reason"] == ("Not requested.")

    early_start = client.post(
        f"/api/v1/assessments/{assessment_id}/start", headers=headers
    )
    assert early_start.status_code == 409

    approved = client.post(
        f"/api/v1/assessments/{assessment_id}/authorize",
        headers=headers,
        json={
            "authorization_type": "owner_attestation",
            "scope_summary": "Read-only analysis of the registered repository.",
            "expires_at": (datetime.now(UTC) + timedelta(days=2)).isoformat(),
            "ticket_reference": "TEST-4",
        },
    )
    assert approved.status_code == 200
    assert approved.json()["status"] == "READY"
    assert approved.json()["authorization"]["approved_by"] == "alice"

    queued = client.post(f"/api/v1/assessments/{assessment_id}/start", headers=headers)
    assert queued.status_code == 202
    job = queued.json()
    assert job["status"] == "QUEUED"
    assert job["current_stage"] == "queued"
    assert job["progress"] == 0
    assert job["limits"] == {
        "max_duration_seconds": 1800,
        "max_tool_calls": 100,
        "max_retries": 0,
        "max_output_bytes": 1000000,
        "max_workflow_steps": 20,
        "max_llm_tokens": 0,
        "max_llm_cost_microusd": 0,
    }
    assert client.get(f"/api/v1/jobs/{job['job_id']}", headers=headers).json() == job
    premature_approval = client.post(
        f"/api/v1/jobs/{job['job_id']}/approve-sensitive-tests",
        headers=headers,
        json={"confirmed": True},
    )
    assert premature_approval.status_code == 409

    repeated_start = client.post(
        f"/api/v1/assessments/{assessment_id}/start", headers=headers
    )
    assert repeated_start.status_code == 202
    assert repeated_start.json()["job_id"] == job["job_id"]

    assert (
        client.get(f"/api/v1/assessments/{assessment_id}/tests", headers=headers).json()
        == []
    )
    assert (
        client.get(
            f"/api/v1/assessments/{assessment_id}/coverage", headers=headers
        ).json()[0]["tested"]
        is False
    )
    event_names = [
        event["event_type"]
        for event in client.get(
            f"/api/v1/assessments/{assessment_id}/events", headers=headers
        ).json()
    ]
    assert event_names == [
        "assessment.created",
        "assessment.authorized",
        "assessment.queued",
    ]

    cancelled = client.post(f"/api/v1/jobs/{job['job_id']}/cancel", headers=headers)
    assert cancelled.status_code == 200
    assert cancelled.json()["status"] == "CANCELLED"
    assert cancelled.json()["cancellation_requested"] is True
    assert (
        client.get(f"/api/v1/assessments/{assessment_id}", headers=headers).json()[
            "status"
        ]
        == "CANCELLED"
    )


def test_assessment_cancel_accepts_records_without_new_optional_fields(
    tmp_path,
) -> None:
    client, headers = _client(tmp_path)
    target_id = _create_target(client, headers)
    assessment = _create_assessment(client, headers, target_id)
    assessment_id = assessment["assessment_id"]
    authorization = client.post(
        f"/api/v1/assessments/{assessment_id}/authorize",
        headers=headers,
        json={
            "authorization_type": "owner_attestation",
            "scope_summary": "Read-only analysis.",
            "expires_at": (datetime.now(UTC) + timedelta(days=2)).isoformat(),
        },
    )
    assert authorization.status_code == 200
    queued = client.post(f"/api/v1/assessments/{assessment_id}/start", headers=headers)
    assert queued.status_code == 202
    job_id = queued.json()["job_id"]

    store_path = client.app.state.repository.data_file
    document = json.loads(store_path.read_text(encoding="utf-8"))
    stored_assessment = next(
        record
        for record in document["collections"]["assessments"]
        if record["assessment_id"] == assessment_id
    )
    stored_job = next(
        record
        for record in document["collections"]["jobs"]
        if record["job_id"] == job_id
    )
    for field in (
        "retest_of_assessment_id",
        "retest_of_finding_id",
        "change_reference",
    ):
        stored_assessment.pop(field, None)
    stored_job.pop("retest_of_finding_id", None)
    store_path.write_text(json.dumps(document), encoding="utf-8")

    response = client.post(
        f"/api/v1/assessments/{assessment_id}/cancel", headers=headers
    )

    assert response.status_code == 200
    assert response.json()["status"] == "CANCELLED"
    repository = JsonRepository(store_path)
    persisted_assessment = repository.get_record(
        CollectionName.ASSESSMENTS,
        assessment_id,
        Assessment,
        id_field="assessment_id",
    )
    persisted_job = repository.get_record(
        CollectionName.JOBS, job_id, Job, id_field="job_id"
    )
    assert persisted_assessment is not None
    assert persisted_assessment.status.value == "CANCELLED"
    assert persisted_job is not None
    assert persisted_job.status.value == "CANCELLED"
    assert persisted_job.cancellation_requested is True
    assert persisted_job.completed_at is not None
    assert any(
        event.event_type == "assessment.cancellation_requested"
        and event.resource_id == assessment_id
        for event in repository.list_audit_events()
    )


def test_assessment_and_job_ownership_is_concealed(tmp_path) -> None:
    client, alice_headers = _client(tmp_path)
    target_id = _create_target(client, alice_headers)
    assessment = _create_assessment(client, alice_headers, target_id)
    assessment_id = assessment["assessment_id"]

    bob_headers = {"X-Development-User": "bob"}
    assert (
        client.get(
            f"/api/v1/assessments/{assessment_id}", headers=bob_headers
        ).status_code
        == 404
    )
    assert (
        client.get(
            f"/api/v1/assessments/{assessment_id}/events", headers=bob_headers
        ).status_code
        == 404
    )
    assert client.get("/api/v1/assessments", headers=bob_headers).json() == []

    authorization = client.post(
        f"/api/v1/assessments/{assessment_id}/authorize",
        headers=alice_headers,
        json={
            "authorization_type": "owner_attestation",
            "scope_summary": "Read-only analysis.",
            "expires_at": (datetime.now(UTC) + timedelta(days=2)).isoformat(),
        },
    )
    assert authorization.status_code == 200
    job = client.post(
        f"/api/v1/assessments/{assessment_id}/start", headers=alice_headers
    ).json()
    assert (
        client.get(f"/api/v1/jobs/{job['job_id']}", headers=bob_headers).status_code
        == 404
    )


def test_assessment_mode_and_target_scope_are_validated(tmp_path) -> None:
    client, headers = _client(tmp_path)
    target_response = client.post(
        "/api/v1/targets",
        headers=headers,
        json={
            "name": "Domain only",
            "domain": "https://app.example.test",
            "environment": "staging",
        },
    )
    target_id = target_response.json()["target_id"]
    invalid_mode = client.post(
        "/api/v1/assessments",
        headers=headers,
        json={
            "target_id": target_id,
            "mode": "repository_only",
            "scope": {"repository_ref": "main"},
        },
    )
    assert invalid_mode.status_code == 422

    assessment = _create_assessment(client, headers, _create_target(client, headers))
    changed_target = client.patch(
        f"/api/v1/targets/{assessment['target_id']}",
        headers=headers,
        json={"scope": {"excluded_paths": ["/new-exclusion"]}},
    )
    assert changed_target.status_code == 200
    approval_after_scope_change = client.post(
        f"/api/v1/assessments/{assessment['assessment_id']}/authorize",
        headers=headers,
        json={
            "authorization_type": "owner_attestation",
            "scope_summary": "Read-only analysis.",
            "expires_at": (datetime.now(UTC) + timedelta(days=2)).isoformat(),
        },
    )
    assert approval_after_scope_change.status_code == 409


def test_start_enforces_per_user_concurrency_limit(tmp_path) -> None:
    client, headers = _client(tmp_path, max_concurrent_jobs_per_user=1)
    target_id = _create_target(client, headers)
    first = _create_assessment(client, headers, target_id)
    second = _create_assessment(client, headers, target_id)

    for assessment in (first, second):
        response = client.post(
            f"/api/v1/assessments/{assessment['assessment_id']}/authorize",
            headers=headers,
            json={
                "authorization_type": "owner_attestation",
                "scope_summary": "Read-only analysis.",
                "expires_at": (datetime.now(UTC) + timedelta(days=2)).isoformat(),
            },
        )
        assert response.status_code == 200

    first_start = client.post(
        f"/api/v1/assessments/{first['assessment_id']}/start", headers=headers
    )
    second_start = client.post(
        f"/api/v1/assessments/{second['assessment_id']}/start", headers=headers
    )
    assert first_start.status_code == 202
    assert second_start.status_code == 429
