import hashlib
import json
import os
import secrets
import tempfile
import threading
import time
import uuid
from collections.abc import Iterator
from contextlib import contextmanager
from pathlib import Path
from typing import TypedDict

from fastapi import Request
from pydantic import BaseModel, ConfigDict, ValidationError

from ai_sentinel.api.identity import (
    IdentityProvider,
    Principal,
)
from ai_sentinel.db.repository import PersistenceError, RecordConflictError

_store_locks: dict[str, threading.RLock] = {}
_store_locks_guard = threading.Lock()
_SESSION_LIFETIME_SECONDS = 60 * 60 * 24 * 7


class AuthUser(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True)

    user_id: str
    tenant_id: str | None = None
    full_name: str
    email: str
    password_salt: str
    password_hash: str
    terms_accepted_at: str


class AuthSession(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True)

    session_id: str
    user_id: str
    expires_at: int


class AuthStoreDocument(TypedDict):
    users: dict[str, dict[str, str]]
    sessions: dict[str, dict[str, int | str]]


def hash_password(password: str, salt: bytes | None = None) -> tuple[str, str]:
    password_salt = salt or secrets.token_bytes(16)
    password_hash = hashlib.scrypt(
        password.encode("utf-8"),
        salt=password_salt,
        n=2**14,
        r=8,
        p=1,
        dklen=64,
    )
    return password_salt.hex(), password_hash.hex()


def verify_password(password: str, salt_hex: str, expected_hash: str) -> bool:
    try:
        salt = bytes.fromhex(salt_hex)
        expected = bytes.fromhex(expected_hash)
    except ValueError:
        return False
    _, actual_hash = hash_password(password, salt)
    return secrets.compare_digest(actual_hash, expected.hex())


class AuthStore:
    def __init__(self, path: Path) -> None:
        self.path = path
        self.lock_path = path.with_name(f"{path.name}.lock")

    def create_user(
        self,
        full_name: str,
        email: str,
        password: str,
        *,
        user_id: str | None = None,
        tenant_id: str | None = None,
    ) -> AuthUser:
        salt, password_hash = hash_password(password)
        resolved_user_id = user_id or uuid.uuid4().hex
        user = AuthUser(
            user_id=resolved_user_id,
            tenant_id=tenant_id or resolved_user_id,
            full_name=full_name,
            email=email,
            password_salt=salt,
            password_hash=password_hash,
            terms_accepted_at=time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
        )
        with self._locked():
            document = self._read()
            if email in document["users"] or any(
                existing["user_id"] == resolved_user_id
                for existing in document["users"].values()
            ):
                raise RecordConflictError("An account already exists for this email.")
            document["users"][email] = user.model_dump(mode="json")
            self._write(document)
        return user

    def get_user(self, email: str) -> AuthUser | None:
        with self._locked():
            document = self._read()
            record = document["users"].get(email)
        return AuthUser.model_validate(record) if record is not None else None

    def get_user_by_id(self, user_id: str) -> AuthUser | None:
        with self._locked():
            document = self._read()
            record = next(
                (
                    user
                    for user in document["users"].values()
                    if user["user_id"] == user_id
                ),
                None,
            )
        return AuthUser.model_validate(record) if record is not None else None

    def create_session(self, user_id: str) -> str:
        token = secrets.token_urlsafe(32)
        token_hash = hashlib.sha256(token.encode("ascii")).hexdigest()
        session = AuthSession(
            session_id=token_hash,
            user_id=user_id,
            expires_at=int(time.time()) + _SESSION_LIFETIME_SECONDS,
        )
        with self._locked():
            document = self._read()
            document["sessions"] = {
                key: value
                for key, value in document["sessions"].items()
                if int(value["expires_at"]) > int(time.time())
            }
            document["sessions"][session.session_id] = session.model_dump(mode="json")
            self._write(document)
        return token

    def authenticate(self, token: str) -> Principal | None:
        token_hash = hashlib.sha256(token.encode("utf-8")).hexdigest()
        with self._locked():
            document = self._read()
            session_data = document["sessions"].get(token_hash)
            if (
                session_data is None
                or int(session_data["expires_at"]) <= int(time.time())
            ):
                return None
            session = AuthSession.model_validate(session_data)
            user_data = next(
                (
                    record
                    for record in document["users"].values()
                    if record["user_id"] == session.user_id
                ),
                None,
            )
        if user_data is None:
            return None
        user = AuthUser.model_validate(user_data)
        return Principal(
            subject_id=user.user_id,
            tenant_id=user.tenant_id or user.user_id,
        )

    def revoke_session(self, token: str) -> None:
        token_hash = hashlib.sha256(token.encode("utf-8")).hexdigest()
        with self._locked():
            document = self._read()
            if document["sessions"].pop(token_hash, None) is not None:
                self._write(document)

    @contextmanager
    def _locked(self) -> Iterator[None]:
        lock_key = str(self.lock_path.resolve())
        with _store_locks_guard:
            process_lock = _store_locks.setdefault(lock_key, threading.RLock())
        try:
            self.path.parent.mkdir(parents=True, exist_ok=True)
            with process_lock, self.lock_path.open("a+b") as lock_stream:
                if os.name == "nt":
                    import msvcrt

                    lock_stream.seek(0, os.SEEK_END)
                    if lock_stream.tell() == 0:
                        lock_stream.write(b"\0")
                        lock_stream.flush()
                    lock_stream.seek(0)
                    msvcrt.locking(lock_stream.fileno(), msvcrt.LK_LOCK, 1)
                    try:
                        yield
                    finally:
                        lock_stream.seek(0)
                        msvcrt.locking(lock_stream.fileno(), msvcrt.LK_UNLCK, 1)
                else:
                    import fcntl

                    lock_function = getattr(fcntl, "flock")
                    lock_ex = getattr(fcntl, "LOCK_EX")
                    lock_unlock = getattr(fcntl, "LOCK_UN")
                    lock_function(lock_stream.fileno(), lock_ex)
                    try:
                        yield
                    finally:
                        lock_function(lock_stream.fileno(), lock_unlock)
        except PersistenceError:
            raise
        except OSError as exc:
            raise PersistenceError(
                "The authentication store could not be accessed. Check its "
                "directory permissions and available disk space."
            ) from exc

    def _read(self) -> AuthStoreDocument:
        try:
            with self.path.open("r", encoding="utf-8") as store:
                document = json.load(store)
        except FileNotFoundError:
            return {"users": {}, "sessions": {}}
        except (OSError, UnicodeDecodeError, json.JSONDecodeError) as exc:
            raise PersistenceError("The authentication store is unreadable.") from exc
        if (
            not isinstance(document, dict)
            or set(document) != {"users", "sessions"}
            or not isinstance(document["users"], dict)
            or not isinstance(document["sessions"], dict)
        ):
            raise PersistenceError("The authentication store has an invalid format.")
        try:
            users = {}
            for email, user_record in document["users"].items():
                user = AuthUser.model_validate(user_record)
                if user.email != email:
                    raise PersistenceError(
                        "The authentication store contains an invalid user index."
                    )
                users[email] = user.model_dump(mode="json")
            sessions = {}
            for session_id, session_record in document["sessions"].items():
                session = AuthSession.model_validate(session_record)
                if session.session_id != session_id:
                    raise PersistenceError(
                        "The authentication store contains an invalid session index."
                    )
                sessions[session_id] = session.model_dump(mode="json")
        except PersistenceError:
            raise
        except ValidationError as exc:
            raise PersistenceError(
                "The authentication store contains an invalid record."
            ) from exc
        return {"users": users, "sessions": sessions}

    def _write(self, document: AuthStoreDocument) -> None:
        temporary_path: Path | None = None
        try:
            descriptor, temporary_name = tempfile.mkstemp(
                prefix=f".{self.path.name}.",
                suffix=".tmp",
                dir=self.path.parent,
            )
            temporary_path = Path(temporary_name)
            with os.fdopen(descriptor, "w", encoding="utf-8", newline="\n") as store:
                json.dump(document, store, ensure_ascii=True, indent=2, sort_keys=True)
                store.write("\n")
                store.flush()
                os.fsync(store.fileno())
            for attempt in range(4):
                try:
                    os.replace(temporary_path, self.path)
                    break
                except PermissionError:
                    if attempt == 3:
                        raise
                    time.sleep(0.01 * (attempt + 1))
            temporary_path = None
            if os.name != "nt":
                self.path.chmod(0o600)
        except (OSError, TypeError, ValueError) as exc:
            raise PersistenceError(
                "The authentication store could not be written atomically."
            ) from exc
        finally:
            if temporary_path is not None:
                try:
                    temporary_path.unlink(missing_ok=True)
                except OSError:
                    pass


class CookieIdentityProvider:
    def __init__(
        self,
        store: AuthStore,
        development_provider: IdentityProvider | None = None,
    ) -> None:
        self._store = store
        self._development_provider = development_provider
        self.enabled = (
            development_provider.enabled
            if development_provider is not None
            else False
        )

    def authenticate(self, request: Request) -> Principal | None:
        token = request.cookies.get("ai_sentinel_session")
        if token:
            principal = self._store.authenticate(token)
            if principal is not None:
                return principal
        if self._development_provider is not None:
            return self._development_provider.authenticate(request)
        return None
