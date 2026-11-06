"""API contracts and input validation."""

from __future__ import annotations

import ipaddress
import re
from datetime import UTC, datetime
from typing import Literal

from pydantic import BaseModel, ConfigDict, Field, field_validator, model_validator


class EventIn(BaseModel):
    model_config = ConfigDict(extra="ignore", str_strip_whitespace=True)

    event_id: str | None = Field(default=None, max_length=128)
    timestamp: datetime = Field(default_factory=lambda: datetime.now(UTC))
    source: str = Field(default="manual", min_length=1, max_length=80)
    event_type: str = Field(min_length=2, max_length=40)
    src_ip: str | None = Field(default=None, max_length=64)
    dst_ip: str | None = Field(default=None, max_length=64)
    dst_port: int | None = Field(default=None, ge=1, le=65535)
    username: str | None = Field(default=None, max_length=128)
    asset: str | None = Field(default=None, max_length=160)
    action: str | None = Field(default=None, max_length=120)
    outcome: str | None = Field(default=None, max_length=40)
    domain: str | None = Field(default=None, max_length=253)
    bytes_out: int = Field(default=0, ge=0, le=2**63 - 1)
    process_name: str | None = Field(default=None, max_length=160)
    hash_sha256: str | None = Field(default=None, min_length=64, max_length=64)

    @field_validator("src_ip", "dst_ip")
    @classmethod
    def valid_ip(cls, value: str | None) -> str | None:
        if value is None or value == "":
            return None
        try:
            return str(ipaddress.ip_address(value))
        except ValueError as exc:
            raise ValueError("must be a valid IPv4 or IPv6 address") from exc

    @field_validator("event_type")
    @classmethod
    def clean_event_type(cls, value: str) -> str:
        normalized = value.lower().replace("-", "_")
        if not re.fullmatch(r"[a-z][a-z0-9_]{1,39}", normalized):
            raise ValueError("event_type must contain only letters, digits and underscores")
        return normalized

    @field_validator("hash_sha256")
    @classmethod
    def valid_hash(cls, value: str | None) -> str | None:
        if value is None:
            return None
        value = value.lower()
        if not re.fullmatch(r"[0-9a-f]{64}", value):
            raise ValueError("hash_sha256 must be a 64-character hexadecimal SHA-256 digest")
        return value

    @field_validator("domain")
    @classmethod
    def clean_domain(cls, value: str | None) -> str | None:
        if value is None:
            return None
        value = value.lower().rstrip(".")
        if not value or any(c.isspace() for c in value):
            raise ValueError("domain must be a valid hostname")
        return value


class EventBatch(BaseModel):
    events: list[EventIn] = Field(min_length=1, max_length=500)


class AlertUpdate(BaseModel):
    status: Literal["open", "investigating", "contained", "resolved"]
    note: str = Field(default="", max_length=1000)
    assignee: str | None = Field(default=None, max_length=100)


class IOCIn(BaseModel):
    kind: Literal["ip", "domain", "sha256"]
    indicator: str = Field(min_length=3, max_length=253)
    threat_type: str = Field(default="suspicious", min_length=2, max_length=100)
    source: str = Field(default="analyst", min_length=2, max_length=120)
    confidence: int = Field(default=80, ge=0, le=100)

    @field_validator("indicator")
    @classmethod
    def normalize_indicator(cls, value: str) -> str:
        return value.strip().lower()

    @model_validator(mode="after")
    def validate_indicator_kind(self):
        if self.kind == "ip":
            try:
                ipaddress.ip_address(self.indicator)
            except ValueError as exc:
                raise ValueError("indicator must be a valid IP address when kind=ip") from exc
        elif self.kind == "sha256":
            if not re.fullmatch(r"[0-9a-f]{64}", self.indicator):
                raise ValueError("indicator must be a 64-character hexadecimal digest when kind=sha256")
        elif self.kind == "domain":
            self.indicator = self.indicator.rstrip(".")
            labels = self.indicator.split(".")
            if len(self.indicator) > 253 or any(
                not label or len(label) > 63 or label.startswith("-") or label.endswith("-")
                or not re.fullmatch(r"[a-z0-9-]+", label)
                for label in labels
            ):
                raise ValueError("indicator must be a valid domain name when kind=domain")
        return self
