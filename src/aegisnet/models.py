"""Persistence models for telemetry, detections, indicators and analyst audit."""

from __future__ import annotations

from datetime import datetime

from sqlalchemy import DateTime, ForeignKey, Index, Integer, String, Text, UniqueConstraint
from sqlalchemy.orm import Mapped, mapped_column, relationship

from .database import Base


class Event(Base):
    __tablename__ = "events"
    __table_args__ = (
        Index("ix_events_src_type_time", "src_ip", "event_type", "timestamp"),
        Index("ix_events_asset_time", "asset", "timestamp"),
    )

    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    event_uid: Mapped[str] = mapped_column(String(128), unique=True, index=True)
    timestamp: Mapped[datetime] = mapped_column(DateTime(timezone=True), index=True)
    source: Mapped[str] = mapped_column(String(80), default="unknown")
    event_type: Mapped[str] = mapped_column(String(40), index=True)
    src_ip: Mapped[str | None] = mapped_column(String(64), nullable=True, index=True)
    dst_ip: Mapped[str | None] = mapped_column(String(64), nullable=True)
    dst_port: Mapped[int | None] = mapped_column(Integer, nullable=True)
    username: Mapped[str | None] = mapped_column(String(128), nullable=True)
    asset: Mapped[str | None] = mapped_column(String(160), nullable=True)
    action: Mapped[str | None] = mapped_column(String(120), nullable=True)
    outcome: Mapped[str | None] = mapped_column(String(40), nullable=True)
    domain: Mapped[str | None] = mapped_column(String(253), nullable=True, index=True)
    bytes_out: Mapped[int] = mapped_column(Integer, default=0)
    process_name: Mapped[str | None] = mapped_column(String(160), nullable=True)
    hash_sha256: Mapped[str | None] = mapped_column(String(64), nullable=True)
    raw_json: Mapped[str] = mapped_column(Text, default="{}")


class Alert(Base):
    __tablename__ = "alerts"

    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    fingerprint: Mapped[str] = mapped_column(String(240), unique=True, index=True)
    rule_id: Mapped[str] = mapped_column(String(40), index=True)
    title: Mapped[str] = mapped_column(String(180))
    description: Mapped[str] = mapped_column(Text)
    severity: Mapped[str] = mapped_column(String(16), index=True)
    risk_score: Mapped[int] = mapped_column(Integer, default=0)
    status: Mapped[str] = mapped_column(String(24), default="open", index=True)
    src_ip: Mapped[str | None] = mapped_column(String(64), nullable=True, index=True)
    asset: Mapped[str | None] = mapped_column(String(160), nullable=True)
    username: Mapped[str | None] = mapped_column(String(128), nullable=True)
    mitre_technique: Mapped[str | None] = mapped_column(String(32), nullable=True)
    mitre_tactic: Mapped[str | None] = mapped_column(String(80), nullable=True)
    event_count: Mapped[int] = mapped_column(Integer, default=1)
    evidence_json: Mapped[str] = mapped_column(Text, default="[]")
    assignee: Mapped[str | None] = mapped_column(String(100), nullable=True)
    first_seen: Mapped[datetime] = mapped_column(DateTime(timezone=True))
    last_seen: Mapped[datetime] = mapped_column(DateTime(timezone=True), index=True)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True))
    updated_at: Mapped[datetime] = mapped_column(DateTime(timezone=True))
    audit_entries: Mapped[list[AuditEntry]] = relationship(
        back_populates="alert", cascade="all, delete-orphan", order_by="AuditEntry.created_at"
    )


class AuditEntry(Base):
    __tablename__ = "audit_entries"

    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    alert_id: Mapped[int] = mapped_column(ForeignKey("alerts.id", ondelete="CASCADE"), index=True)
    actor: Mapped[str] = mapped_column(String(100), default="system")
    action: Mapped[str] = mapped_column(String(80))
    from_status: Mapped[str | None] = mapped_column(String(24), nullable=True)
    to_status: Mapped[str | None] = mapped_column(String(24), nullable=True)
    note: Mapped[str] = mapped_column(Text, default="")
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True))
    alert: Mapped[Alert] = relationship(back_populates="audit_entries")


class IOC(Base):
    __tablename__ = "iocs"
    __table_args__ = (UniqueConstraint("kind", "indicator", name="uq_ioc_kind_indicator"),)

    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    kind: Mapped[str] = mapped_column(String(16), index=True)
    indicator: Mapped[str] = mapped_column(String(253), index=True)
    threat_type: Mapped[str] = mapped_column(String(100), default="suspicious")
    source: Mapped[str] = mapped_column(String(120), default="local-demo-feed")
    confidence: Mapped[int] = mapped_column(Integer, default=80)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True))
