import json
from concurrent.futures import ThreadPoolExecutor

from fastapi.testclient import TestClient

from ai_sentinel.api.app import create_app
from ai_sentinel.api.auth_store import AuthStore
from ai_sentinel.config import Settings
from ai_sentinel.db.repository import RecordConflictError


def _client(tmp_path) -> TestClient:
    return TestClient(create_app(Settings(data_file=tmp_path / "store.json")))


def _registration_payload(**updates: object) -> dict[str, object]:
    return {
        "full_name": "Ada Lovelace",
        "email": "Ada@Example.com",
        "password": "Correct-Horse-42",
        "accept_terms": True,
        **updates,
    }


def test_registration_normalizes_email_and_persists_only_password_hash(
    tmp_path,
) -> None:
    client = _client(tmp_path)

    response = client.post("/api/v1/auth/register", json=_registration_payload())

    assert response.status_code == 201
    assert response.json() == {"message": "Account created. Sign in to continue."}
    auth_file = tmp_path / "store.auth.json"
    stored = json.loads(auth_file.read_text(encoding="utf-8"))
    user = stored["users"]["ada@example.com"]
    assert user["email"] == "ada@example.com"
    assert user["password_hash"] != "Correct-Horse-42"
    assert user["password_salt"]
    assert "password" not in user
    assert "Correct-Horse-42" not in auth_file.read_text(encoding="utf-8")


def test_registration_rejects_duplicate_email_case_insensitively(tmp_path) -> None:
    client = _client(tmp_path)
    response = client.post(
        "/api/v1/auth/register",
        json=_registration_payload(),
    )
    assert response.status_code == 201

    duplicate = client.post(
        "/api/v1/auth/register",
        json=_registration_payload(email="ada@example.com"),
    )

    assert duplicate.status_code == 409
    assert duplicate.json()["error"]["code"] == "EMAIL_ALREADY_REGISTERED"


def test_registration_requires_terms_and_password_policy(tmp_path) -> None:
    client = _client(tmp_path)

    no_terms = client.post(
        "/api/v1/auth/register",
        json=_registration_payload(accept_terms=False),
    )
    weak_password = client.post(
        "/api/v1/auth/register",
        json=_registration_payload(password="too-short"),
    )
    missing_fields = client.post("/api/v1/auth/register", json={})

    assert no_terms.status_code == 422
    assert weak_password.status_code == 422
    assert missing_fields.status_code == 422


def test_login_uses_generic_failure_and_issues_revocable_cookie(tmp_path) -> None:
    client = _client(tmp_path)
    client.post("/api/v1/auth/register", json=_registration_payload())

    unknown_email = client.post(
        "/api/v1/auth/login",
        json={"email": "unknown@example.com", "password": "wrong-password"},
    )
    wrong_password = client.post(
        "/api/v1/auth/login",
        json={"email": "ada@example.com", "password": "wrong-password"},
    )

    assert unknown_email.status_code == wrong_password.status_code == 401
    assert (
        unknown_email.json()["error"]["code"]
        == wrong_password.json()["error"]["code"]
    )
    assert (
        unknown_email.json()["error"]["message"]
        == wrong_password.json()["error"]["message"]
    )

    logged_in = client.post(
        "/api/v1/auth/login",
        json={"email": "ADA@example.com", "password": "Correct-Horse-42"},
    )
    cookie = logged_in.headers["set-cookie"]
    assert logged_in.status_code == 200
    assert logged_in.json()["user"]["email"] == "ada@example.com"
    assert "HttpOnly" in cookie
    assert "SameSite=lax" in cookie
    assert "ai_sentinel_session" not in logged_in.text
    session = client.get("/api/v1/auth/session")
    assert session.status_code == 200
    assert session.json()["user"]["email"] == "ada@example.com"
    assert client.get("/api/v1/targets").status_code == 200

    logout = client.post(
        "/api/v1/auth/logout",
        headers={"Origin": "http://testserver"},
    )
    assert logout.status_code == 204
    assert client.get("/api/v1/targets").status_code == 401


def test_presentation_account_can_view_local_development_assessments(tmp_path) -> None:
    app = create_app(
        Settings(
            data_file=tmp_path / "store.json",
            development_identity_enabled=True,
        )
    )
    client = TestClient(app)
    target_response = client.post(
        "/api/v1/targets",
        headers={"X-Development-User": "local-developer"},
        json={
            "name": "Presentation target",
            "domain": "https://app.example.test",
            "repository": {
                "owner": "example-org",
                "name": "presentation",
                "ref": "main",
            },
            "environment": "staging",
            "scope": {"included_hosts": ["app.example.test"]},
        },
    )
    assert target_response.status_code == 201

    app.state.auth_store.create_user(
        "Presentation Account",
        "presentation@example.test",
        "a-long-demo-password",
        user_id="local-developer",
        tenant_id="local-development",
    )
    login = client.post(
        "/api/v1/auth/login",
        json={
            "email": "presentation@example.test",
            "password": "a-long-demo-password",
        },
    )

    assert login.status_code == 200
    targets = client.get("/api/v1/targets")
    assert targets.status_code == 200
    target_id = target_response.json()["target_id"]
    assert any(
        target["target_id"] == target_id
        for target in targets.json()
    )


def test_cookie_authenticated_mutations_require_trusted_origin(tmp_path) -> None:
    client = _client(tmp_path)
    client.post("/api/v1/auth/register", json=_registration_payload())
    client.post(
        "/api/v1/auth/login",
        json={"email": "ada@example.com", "password": "Correct-Horse-42"},
    )

    rejected = client.post("/api/v1/auth/logout", headers={"Origin": "https://evil.example"})

    assert rejected.status_code == 403
    assert rejected.json()["error"]["code"] == "CSRF_REJECTED"
    assert client.get("/api/v1/targets").status_code == 200


def test_production_cookie_is_secure_and_exact_cors_is_allowed(tmp_path) -> None:
    app = create_app(
        Settings(
            environment="production",
            data_file=tmp_path / "store.json",
            cors_allowed_origins=("https://app.example.com",),
        )
    )
    client = TestClient(app)
    client.post("/api/v1/auth/register", json=_registration_payload())

    login = client.post(
        "/api/v1/auth/login",
        json={"email": "ada@example.com", "password": "Correct-Horse-42"},
    )

    assert login.status_code == 200
    assert "Secure" in login.headers["set-cookie"]
    assert login.headers["set-cookie"].find("HttpOnly") >= 0


def test_authentication_routes_have_a_dedicated_rate_limit(tmp_path) -> None:
    client = TestClient(
        create_app(
            Settings(
                data_file=tmp_path / "store.json",
                max_auth_requests_per_minute_per_ip=1,
            )
        )
    )

    first = client.post("/api/v1/auth/login", json={})
    limited = client.post("/api/v1/auth/login", json={})

    assert first.status_code == 422
    assert first.headers["X-RateLimit-Limit"] == "1"
    assert limited.status_code == 429
    assert limited.headers["X-RateLimit-Policy"] == "auth"


def test_expired_session_is_rejected(tmp_path) -> None:
    client = _client(tmp_path)
    client.post("/api/v1/auth/register", json=_registration_payload())
    client.post(
        "/api/v1/auth/login",
        json={"email": "ada@example.com", "password": "Correct-Horse-42"},
    )
    auth_file = tmp_path / "store.auth.json"
    stored = json.loads(auth_file.read_text(encoding="utf-8"))
    session_id = next(iter(stored["sessions"]))
    stored["sessions"][session_id]["expires_at"] = 0
    auth_file.write_text(json.dumps(stored), encoding="utf-8")

    expired = client.get("/api/v1/auth/session")

    assert expired.status_code == 401
    assert client.get("/api/v1/targets").status_code == 401


def test_concurrent_registration_cannot_create_duplicate_emails(tmp_path) -> None:
    store = AuthStore(tmp_path / "auth.json")

    def create_account() -> bool:
        try:
            store.create_user("Ada Lovelace", "ada@example.com", "Correct-Horse-42")
        except RecordConflictError:
            return False
        return True

    with ThreadPoolExecutor(max_workers=2) as executor:
        results = list(executor.map(lambda _: create_account(), range(2)))

    assert sum(results) == 1
    assert len(json.loads((tmp_path / "auth.json").read_text())["users"]) == 1
