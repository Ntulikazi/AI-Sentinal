from datetime import datetime
from typing import Any

from sqlalchemy import JSON, DateTime, ForeignKey, String
from sqlalchemy.dialects.postgresql import JSONB
from sqlalchemy.orm import DeclarativeBase, Mapped, mapped_column


JSONType = JSON().with_variant(JSONB, "postgresql")


class Base(DeclarativeBase):
    pass


class Tenant(Base):
    __tablename__ = "tenants"
    tenant_id: Mapped[str] = mapped_column(String(200), primary_key=True)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True))
    updated_at: Mapped[datetime] = mapped_column(DateTime(timezone=True))


class User(Base):
    __tablename__ = "users"
    user_id: Mapped[str] = mapped_column(String(200), primary_key=True)
    tenant_id: Mapped[str] = mapped_column(
        String(200),
        ForeignKey("tenants.tenant_id", ondelete="CASCADE"),
        index=True,
    )
    email: Mapped[str] = mapped_column(String(320), unique=True, index=True)
    full_name: Mapped[str] = mapped_column(String(200))
    password_salt: Mapped[str] = mapped_column(String(32))
    password_hash: Mapped[str] = mapped_column(String(128))
    terms_accepted_at: Mapped[str] = mapped_column(String(40))
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True))
    updated_at: Mapped[datetime] = mapped_column(DateTime(timezone=True))


class AuthSession(Base):
    __tablename__ = "auth_sessions"
    session_id: Mapped[str] = mapped_column(String(64), primary_key=True)
    user_id: Mapped[str] = mapped_column(
        String(200), ForeignKey("users.user_id", ondelete="CASCADE"), index=True
    )
    expires_at: Mapped[int] = mapped_column(index=True)


class Target(Base):
    __tablename__ = "targets"
    target_id: Mapped[str] = mapped_column(String(200), primary_key=True)
    owner_id: Mapped[str] = mapped_column(String(200), index=True)
    tenant_id: Mapped[str] = mapped_column(
        String(200), ForeignKey("tenants.tenant_id", ondelete="CASCADE"), index=True
    )
    payload: Mapped[dict[str, Any]] = mapped_column(JSONType)


class Assessment(Base):
    __tablename__ = "assessments"
    assessment_id: Mapped[str] = mapped_column(String(200), primary_key=True)
    target_id: Mapped[str] = mapped_column(
        String(200), ForeignKey("targets.target_id", ondelete="RESTRICT"), index=True
    )
    owner_id: Mapped[str] = mapped_column(String(200), index=True)
    tenant_id: Mapped[str] = mapped_column(
        String(200), ForeignKey("tenants.tenant_id", ondelete="CASCADE"), index=True
    )
    status: Mapped[str] = mapped_column(String(40), index=True)
    payload: Mapped[dict[str, Any]] = mapped_column(JSONType)


class Job(Base):
    __tablename__ = "assessment_jobs"
    job_id: Mapped[str] = mapped_column(String(200), primary_key=True)
    assessment_id: Mapped[str] = mapped_column(
        String(200),
        ForeignKey("assessments.assessment_id", ondelete="CASCADE"),
        unique=True,
        index=True,
    )
    owner_id: Mapped[str] = mapped_column(String(200), index=True)
    tenant_id: Mapped[str] = mapped_column(
        String(200), ForeignKey("tenants.tenant_id", ondelete="CASCADE"), index=True
    )
    status: Mapped[str] = mapped_column(String(40), index=True)
    payload: Mapped[dict[str, Any]] = mapped_column(JSONType)
    claimed_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))


class TestResult(Base):
    __tablename__ = "scanner_test_results"
    test_id: Mapped[str] = mapped_column(String(200), primary_key=True)
    assessment_id: Mapped[str] = mapped_column(
        String(200), ForeignKey("assessments.assessment_id", ondelete="CASCADE"), index=True
    )
    target_id: Mapped[str | None] = mapped_column(String(200), index=True)
    status: Mapped[str] = mapped_column(String(40), index=True)
    payload: Mapped[dict[str, Any]] = mapped_column(JSONType)


class Finding(Base):
    __tablename__ = "findings"
    finding_id: Mapped[str] = mapped_column(String(200), primary_key=True)
    assessment_id: Mapped[str] = mapped_column(
        String(200), ForeignKey("assessments.assessment_id", ondelete="CASCADE"), index=True
    )
    target_id: Mapped[str] = mapped_column(String(200), index=True)
    severity: Mapped[str] = mapped_column(String(20), index=True)
    state: Mapped[str] = mapped_column(String(40), index=True)
    payload: Mapped[dict[str, Any]] = mapped_column(JSONType)


class Evidence(Base):
    __tablename__ = "evidence"
    evidence_id: Mapped[str] = mapped_column(String(200), primary_key=True)
    assessment_id: Mapped[str] = mapped_column(
        String(200), ForeignKey("assessments.assessment_id", ondelete="CASCADE"), index=True
    )
    target_id: Mapped[str] = mapped_column(String(200), index=True)
    payload: Mapped[dict[str, Any]] = mapped_column(JSONType)


class Evaluation(Base):
    __tablename__ = "evaluations"
    evaluation_run_id: Mapped[str] = mapped_column(String(200), primary_key=True)
    assessment_id: Mapped[str] = mapped_column(
        String(200), ForeignKey("assessments.assessment_id", ondelete="CASCADE"), index=True
    )
    payload: Mapped[dict[str, Any]] = mapped_column(JSONType)


class Report(Base):
    __tablename__ = "reports"
    assessment_id: Mapped[str] = mapped_column(
        String(200), ForeignKey("assessments.assessment_id", ondelete="CASCADE"), primary_key=True
    )
    payload: Mapped[dict[str, Any]] = mapped_column(JSONType)


class AuditEvent(Base):
    __tablename__ = "audit_events"
    event_id: Mapped[str] = mapped_column(String(200), primary_key=True)
    tenant_id: Mapped[str | None] = mapped_column(String(200), index=True)
    event_type: Mapped[str] = mapped_column(String(200), index=True)
    resource_type: Mapped[str] = mapped_column(String(200), index=True)
    resource_id: Mapped[str | None] = mapped_column(String(200), index=True)
    payload: Mapped[dict[str, Any]] = mapped_column(JSONType)
