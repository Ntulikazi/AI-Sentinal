from fastapi.testclient import TestClient

from ai_sentinel.api.app import create_app
from ai_sentinel.config import Settings
from ai_sentinel.db.repository import CollectionName
from ai_sentinel.db.schemas import AuditEvent
from ai_sentinel.schemas.target import Target


def _client(tmp_path):
    app = create_app(
        Settings(
            data_file=tmp_path / "store.json",
            development_identity_enabled=True,
        )
    )
    return TestClient(app), app.state.repository


def _target_body() -> dict[str, object]:
    return {
        "name": "Local Security Lab",
        "domain": "HTTPS://App.Example.Test:443/",
        "repository": {
            "owner": "Example-Org",
            "name": "Security-Lab",
            "ref": "main",
        },
        "environment": "staging",
        "scope": {
            "included_hosts": ["app.example.test"],
            "excluded_paths": ["/logout"],
        },
    }


def test_target_registration_normalizes_data_and_audits_atomically(tmp_path) -> None:
    client, repository = _client(tmp_path)

    response = client.post(
        "/api/v1/targets",
        json=_target_body(),
        headers={"X-Development-User": "alice"},
    )

    assert response.status_code == 201
    target = response.json()
    assert target["target_id"].startswith("tgt_")
    assert target["owner_id"] == "alice"
    assert target["tenant_id"] == "local-development"
    assert target["domain"] == "https://app.example.test"
    assert target["repository"]["owner"] == "example-org"
    assert target["repository"]["name"] == "security-lab"
    assert target["scope"]["active_testing_allowed"] is False
    assert target["archived_at"] is None
    assert "authorization_status" not in target
    events = repository.list_audit_events()
    assert [event.event_type for event in events] == ["target.created"]
    assert events[0].actor_id == "alice"


def test_target_routes_require_authenticated_development_identity(tmp_path) -> None:
    client, _ = _client(tmp_path)

    missing = client.get("/api/v1/targets")
    malformed = client.get(
        "/api/v1/targets",
        headers={"X-Development-User": "alice with spaces"},
    )

    assert missing.status_code == 401
    assert malformed.status_code == 401
    assert missing.json()["error"]["code"] == "UNAUTHENTICATED"


def test_development_identity_is_disabled_outside_development(tmp_path) -> None:
    app = create_app(
        Settings(environment="production", data_file=tmp_path / "store.json")
    )
    client = TestClient(app)

    response = client.get(
        "/api/v1/targets",
        headers={"X-Development-User": "alice"},
    )

    assert response.status_code == 401


def test_target_owner_is_never_client_controlled(tmp_path) -> None:
    client, _ = _client(tmp_path)
    body = {**_target_body(), "owner_id": "victim"}

    response = client.post(
        "/api/v1/targets",
        json=body,
        headers={"X-Development-User": "alice"},
    )

    assert response.status_code == 422
    assert response.json()["error"]["code"] == "VALIDATION_ERROR"


def test_owner_filtering_conceals_another_users_target(tmp_path) -> None:
    client, _ = _client(tmp_path)
    created = client.post(
        "/api/v1/targets",
        json=_target_body(),
        headers={"X-Development-User": "alice"},
    ).json()
    target_id = created["target_id"]

    assert (
        client.get(
            "/api/v1/targets",
            headers={"X-Development-User": "bob"},
        ).json()
        == []
    )
    assert (
        client.get(
            f"/api/v1/targets/{target_id}",
            headers={"X-Development-User": "bob"},
        ).status_code
        == 404
    )
    assert (
        client.patch(
            f"/api/v1/targets/{target_id}",
            json={"name": "Hijacked"},
            headers={"X-Development-User": "bob"},
        ).status_code
        == 404
    )
    assert (
        client.delete(
            f"/api/v1/targets/{target_id}",
            headers={"X-Development-User": "bob"},
        ).status_code
        == 404
    )

    still_owned = client.get(
        f"/api/v1/targets/{target_id}",
        headers={"X-Development-User": "alice"},
    )
    assert still_owned.status_code == 200
    assert still_owned.json()["name"] == "Local Security Lab"


def test_target_scope_changes_and_archive_are_audited_and_preserved(tmp_path) -> None:
    client, repository = _client(tmp_path)
    headers = {"X-Development-User": "alice"}
    created = client.post(
        "/api/v1/targets", json=_target_body(), headers=headers
    ).json()
    target_id = created["target_id"]

    updated = client.patch(
        f"/api/v1/targets/{target_id}",
        json={
            "scope": {
                "included_hosts": ["app.example.test"],
                "excluded_paths": ["/logout", "/admin"],
                "active_testing_allowed": False,
            }
        },
        headers=headers,
    )
    assert updated.status_code == 200
    assert updated.json()["scope"]["excluded_paths"] == ["/admin", "/logout"]
    assert (
        client.delete(f"/api/v1/targets/{target_id}", headers=headers).status_code
        == 204
    )
    assert (
        client.get(f"/api/v1/targets/{target_id}", headers=headers).status_code == 404
    )

    events: list[AuditEvent] = repository.list_audit_events()
    assert [event.event_type for event in events] == [
        "target.created",
        "target.scope_changed",
        "target.archived",
    ]
    assert "previous_scope" in events[1].metadata
    assert "current_scope" in events[1].metadata
    targets = repository.list_records(CollectionName.TARGETS, Target)
    assert len(targets) == 1
    assert targets[0].archived_at is not None


def test_invalid_domains_and_scope_are_rejected_without_persistence(tmp_path) -> None:
    client, repository = _client(tmp_path)
    headers = {"X-Development-User": "alice"}

    for domain in (
        "ftp://app.example.test",
        "http://127.0.0.1",
        "http://localhost",
        "http://169.254.169.254",
    ):
        response = client.post(
            "/api/v1/targets",
            json={**_target_body(), "domain": domain},
            headers=headers,
        )
        assert response.status_code == 422

    response = client.post(
        "/api/v1/targets",
        json={
            **_target_body(),
            "scope": {
                "included_hosts": ["outside.example.org"],
                "excluded_paths": [],
            },
        },
        headers=headers,
    )
    assert response.status_code == 422
    assert repository.list_audit_events() == []


def test_target_scope_updates_reject_identifier_changes_and_empty_patch(
    tmp_path,
) -> None:
    client, _ = _client(tmp_path)
    headers = {"X-Development-User": "alice"}
    created = client.post(
        "/api/v1/targets", json=_target_body(), headers=headers
    ).json()
    target_id = created["target_id"]

    empty_patch = client.patch(f"/api/v1/targets/{target_id}", json={}, headers=headers)
    domain_change = client.patch(
        f"/api/v1/targets/{target_id}",
        json={"domain": "https://other.example.test"},
        headers=headers,
    )

    assert empty_patch.status_code == 422
    assert domain_change.status_code == 422


def test_meta_only_advertises_target_registration_when_identity_is_enabled(
    tmp_path,
) -> None:
    client, _ = _client(tmp_path)

    response = client.get("/api/v1/meta")

    assert response.status_code == 200
    assert response.json()["features"]["target_registration"] is True


def test_openapi_has_findings_reports_and_approval_routes_without_scanner_execution(
    tmp_path,
) -> None:
    client, _ = _client(tmp_path)

    paths = client.get("/openapi.json").json()["paths"]

    assert set(paths) == {
        "/health/live",
        "/health/ready",
        "/health/worker",
        "/api/v1/meta",
        "/api/v1/auth/session",
        "/api/v1/auth/register",
        "/api/v1/auth/login",
        "/api/v1/auth/logout",
        "/api/v1/targets",
        "/api/v1/targets/{target_id}",
        "/api/v1/assessments",
        "/api/v1/assessments/{assessment_id}",
        "/api/v1/assessments/{assessment_id}/authorize",
        "/api/v1/assessments/{assessment_id}/start",
        "/api/v1/assessments/{assessment_id}/cancel",
        "/api/v1/assessments/{assessment_id}/tests",
        "/api/v1/assessments/{assessment_id}/findings",
        "/api/v1/assessments/{assessment_id}/coverage",
        "/api/v1/assessments/{assessment_id}/events",
        "/api/v1/assessments/{assessment_id}/evaluations",
        "/api/v1/assessments/{assessment_id}/report",
        "/api/v1/assessments/{assessment_id}/report.md",
        "/api/v1/jobs/{job_id}",
        "/api/v1/jobs/{job_id}/approve-sensitive-tests",
        "/api/v1/jobs/{job_id}/cancel",
        "/api/v1/evaluations/{evaluation_run_id}",
        "/api/v1/evaluations/{evaluation_run_id}/cases",
        "/api/v1/findings/{finding_id}",
        "/api/v1/findings/{finding_id}/state",
        "/api/v1/findings/{finding_id}/retest",
        "/api/v1/findings/{finding_id}/evidence",
        "/api/v1/evidence/{evidence_id}",
    }
    assert set(paths["/api/v1/targets"]) == {"get", "post"}
    assert set(paths["/api/v1/targets/{target_id}"]) == {
        "delete",
        "get",
        "patch",
    }


def test_store_transaction_keeps_target_and_audit_consistent_on_write_failure(
    tmp_path, monkeypatch
) -> None:
    client, repository = _client(tmp_path)
    repository.check_ready()
    original_write = repository._atomic_write

    def fail_write(destination, document):
        raise OSError("simulated disk failure")

    monkeypatch.setattr(repository, "_atomic_write", fail_write)
    response = client.post(
        "/api/v1/targets",
        json=_target_body(),
        headers={"X-Development-User": "alice"},
    )
    monkeypatch.setattr(repository, "_atomic_write", original_write)

    assert response.status_code == 500
    assert repository.list_audit_events() == []
    assert repository.list_records(CollectionName.TARGETS, Target) == []
