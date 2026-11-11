"""Control plane data model.

Privacy rules baked into the schema:
- Tenant stores only a *reference* to where the Entra client secret lives (vault path,
  key-vault name, password-manager entry) plus its expiry date. Never the secret itself.
- SendLog is metadata only: no subjects, bodies, attachment names or addresses.
"""
from __future__ import annotations

import datetime as dt

from sqlalchemy import (JSON, Boolean, Date, DateTime, Float, ForeignKey, Integer, String,
                        UniqueConstraint)
from sqlalchemy.orm import Mapped, mapped_column, relationship

from .db import Base


def utcnow() -> dt.datetime:
    return dt.datetime.now(dt.timezone.utc).replace(tzinfo=None)


class Tenant(Base):
    __tablename__ = "tenants"
    id: Mapped[int] = mapped_column(primary_key=True)
    name: Mapped[str] = mapped_column(String(200), unique=True)
    entra_tenant_id: Mapped[str] = mapped_column(String(64))
    client_id: Mapped[str] = mapped_column(String(64))
    secret_ref: Mapped[str] = mapped_column(String(300), default="")   # e.g. "vault:msp/acme/scanrelay"
    secret_expires: Mapped[dt.date | None] = mapped_column(Date, nullable=True)
    ingest_key_hash: Mapped[str] = mapped_column(String(64), default="", index=True)  # sha256 of relay key
    created_at: Mapped[dt.datetime] = mapped_column(DateTime, default=utcnow)
    devices: Mapped[list["Device"]] = relationship(back_populates="tenant", cascade="all, delete-orphan")


class Device(Base):
    __tablename__ = "devices"
    __table_args__ = (UniqueConstraint("tenant_id", "name"),)
    id: Mapped[int] = mapped_column(primary_key=True)
    tenant_id: Mapped[int] = mapped_column(ForeignKey("tenants.id", ondelete="CASCADE"), index=True)
    name: Mapped[str] = mapped_column(String(200))        # SMTP login or source IP as the relay sees it
    auth_mode: Mapped[str] = mapped_column(String(16), default="unknown")  # login | ip | both | unknown
    allowed_ips: Mapped[list] = mapped_column(JSON, default=list)
    created_at: Mapped[dt.datetime] = mapped_column(DateTime, default=utcnow)
    tenant: Mapped[Tenant] = relationship(back_populates="devices")
    sends: Mapped[list["SendLog"]] = relationship(back_populates="device", cascade="all, delete-orphan")


class SendLog(Base):
    __tablename__ = "send_log"
    id: Mapped[int] = mapped_column(primary_key=True)
    ts: Mapped[dt.datetime] = mapped_column(DateTime, default=utcnow, index=True)
    device_id: Mapped[int] = mapped_column(ForeignKey("devices.id", ondelete="CASCADE"), index=True)
    recipients: Mapped[int] = mapped_column(Integer, default=0)
    size: Mapped[int] = mapped_column(Integer, default=0)
    status: Mapped[str] = mapped_column(String(16))            # sent | failed | retry
    graph_request_id: Mapped[str] = mapped_column(String(64), default="")
    device: Mapped[Device] = relationship(back_populates="sends")


class AlertRule(Base):
    """Overrides for the built-in alert defaults. tenant_id NULL = applies to every tenant."""
    __tablename__ = "alert_rules"
    id: Mapped[int] = mapped_column(primary_key=True)
    tenant_id: Mapped[int | None] = mapped_column(ForeignKey("tenants.id", ondelete="CASCADE"), nullable=True)
    kind: Mapped[str] = mapped_column(String(32))            # secret_expiry | failure_rate | no_traffic
    threshold: Mapped[float] = mapped_column(Float, default=0.0)
    window_hours: Mapped[int] = mapped_column(Integer, default=24)
    min_sends: Mapped[int] = mapped_column(Integer, default=5)
    enabled: Mapped[bool] = mapped_column(Boolean, default=True)
