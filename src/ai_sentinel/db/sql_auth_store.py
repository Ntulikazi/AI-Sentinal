import hashlib
import logging
import secrets
import time
import uuid
from datetime import UTC, datetime

from sqlalchemy import delete, select
from sqlalchemy.exc import IntegrityError, SQLAlchemyError
from sqlalchemy.orm import sessionmaker

from ai_sentinel.api.auth_store import AuthSession, AuthUser, hash_password
from ai_sentinel.api.identity import Principal
from ai_sentinel.db.models import AuthSession as AuthSessionRow
from ai_sentinel.db.models import Tenant, User
from ai_sentinel.db.repository import PersistenceError, RecordConflictError


logger = logging.getLogger(__name__)
_SESSION_LIFETIME_SECONDS = 60 * 60 * 24 * 7


class SqlAuthStore:
    def __init__(self, sessions: sessionmaker) -> None:
        self.sessions = sessions

    def create_user(self, full_name, email, password, *, user_id=None, tenant_id=None):
        salt, password_hash = hash_password(password)
        resolved_user_id = user_id or uuid.uuid4().hex
        resolved_tenant_id = tenant_id or resolved_user_id
        user = AuthUser(
            user_id=resolved_user_id,
            tenant_id=resolved_tenant_id,
            full_name=full_name,
            email=email,
            password_salt=salt,
            password_hash=password_hash,
            terms_accepted_at=time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
        )
        try:
            with self.sessions.begin() as session:
                now = datetime.now(UTC)
                if session.get(Tenant, resolved_tenant_id) is None:
                    session.add(Tenant(tenant_id=resolved_tenant_id, created_at=now, updated_at=now))
                session.add(
                    User(
                        user_id=user.user_id,
                        tenant_id=user.tenant_id or resolved_tenant_id,
                        email=user.email.lower(),
                        full_name=user.full_name,
                        password_salt=user.password_salt,
                        password_hash=user.password_hash,
                        terms_accepted_at=user.terms_accepted_at,
                        created_at=now,
                        updated_at=now,
                    )
                )
            return user
        except IntegrityError as exc:
            raise RecordConflictError("An account already exists for this email.") from exc
        except SQLAlchemyError as exc:
            logger.exception("Authentication user persistence failed")
            raise PersistenceError("The account could not be created.") from exc

    def get_user(self, email: str) -> AuthUser | None:
        try:
            with self.sessions() as session:
                row = session.scalar(select(User).where(User.email == email.lower()))
                return self._auth_user(row) if row else None
        except SQLAlchemyError as exc:
            raise PersistenceError("The account could not be read.") from exc

    def get_user_by_id(self, user_id: str) -> AuthUser | None:
        try:
            with self.sessions() as session:
                row = session.get(User, user_id)
                return self._auth_user(row) if row else None
        except SQLAlchemyError as exc:
            raise PersistenceError("The account could not be read.") from exc

    def create_session(self, user_id: str) -> str:
        token = secrets.token_urlsafe(32)
        token_hash = hashlib.sha256(token.encode("ascii")).hexdigest()
        session_record = AuthSession(
            session_id=token_hash,
            user_id=user_id,
            expires_at=int(time.time()) + _SESSION_LIFETIME_SECONDS,
        )
        try:
            with self.sessions.begin() as session:
                session.add(
                    AuthSessionRow(
                        session_id=session_record.session_id,
                        user_id=session_record.user_id,
                        expires_at=session_record.expires_at,
                    )
                )
                session.execute(delete(AuthSessionRow).where(AuthSessionRow.expires_at <= int(time.time())))
            return token
        except SQLAlchemyError as exc:
            raise PersistenceError("The session could not be created.") from exc

    def authenticate(self, token: str) -> Principal | None:
        token_hash = hashlib.sha256(token.encode("utf-8")).hexdigest()
        try:
            with self.sessions() as session:
                record = session.get(AuthSessionRow, token_hash)
                if record is None or record.expires_at <= int(time.time()):
                    return None
                user = session.get(User, record.user_id)
                if user is None:
                    return None
                return Principal(subject_id=user.user_id, tenant_id=user.tenant_id or user.user_id)
        except SQLAlchemyError as exc:
            raise PersistenceError("Authentication could not be verified.") from exc

    def revoke_session(self, token: str) -> None:
        token_hash = hashlib.sha256(token.encode("ascii")).hexdigest()
        try:
            with self.sessions.begin() as session:
                session.execute(delete(AuthSessionRow).where(AuthSessionRow.session_id == token_hash))
        except SQLAlchemyError as exc:
            raise PersistenceError("The session could not be revoked.") from exc

    @staticmethod
    def _auth_user(row: User) -> AuthUser:
        return AuthUser(
            user_id=row.user_id,
            tenant_id=row.tenant_id,
            full_name=row.full_name,
            email=row.email,
            password_salt=row.password_salt,
            password_hash=row.password_hash,
            terms_accepted_at=row.terms_accepted_at,
        )
