"""Application services used by HTTP routes and the demo loader."""

from __future__ import annotations

import hashlib
import json

from sqlalchemy.orm import Session

from .detection import DetectionEngine, as_utc_naive, timestamp_text, utcnow_naive
from .models import IOC, Alert, AuditEntry, Event
from .schemas import EventIn


def canonical_event_uid(payload: dict) -> str:
    encoded = json.dumps(payload, sort_keys=True, separators=(",", ":"), default=str).encode()
    return hashlib.sha256(encoded).hexdigest()


def ingest_events(db: Session, events: list[EventIn]) -> dict:
    engine = DetectionEngine()
    accepted = 0
    duplicates = 0
    triggered: set[int] = set()

    for item in events:
        payload = item.model_dump(mode="json", exclude={"event_id"})
        event_uid = item.event_id or canonical_event_uid(payload)
        existing = db.query(Event.id).filter(Event.event_uid == event_uid).first()
        if existing:
            duplicates += 1
            continue

        raw_payload = item.model_dump(mode="json")
        record = Event(
            event_uid=event_uid,
            timestamp=as_utc_naive(item.timestamp),
            source=item.source,
            event_type=item.event_type,
            src_ip=item.src_ip,
            dst_ip=item.dst_ip,
            dst_port=item.dst_port,
            username=item.username,
            asset=item.asset,
            action=item.action,
            outcome=(item.outcome or "").lower() or None,
            domain=item.domain,
            bytes_out=item.bytes_out,
            process_name=item.process_name,
            hash_sha256=(item.hash_sha256 or "").lower() or None,
            raw_json=json.dumps(raw_payload, separators=(",", ":")),
        )
        db.add(record)
        db.flush()
        accepted += 1
        for alert in engine.evaluate(db, record):
            triggered.add(alert.id)

    db.commit()
    return {
        "accepted": accepted,
        "duplicates": duplicates,
        "alerts_touched": len(triggered),
        "alert_ids": sorted(triggered),
    }


def seed_demo_iocs(db: Session) -> int:
    """Insert documentation-only indicators from reserved IP ranges and .invalid."""
    records = [
        IOC(kind="ip", indicator="198.51.100.66", threat_type="command-and-control", source="AegisNet demo feed", confidence=96, created_at=utcnow_naive()),
        IOC(kind="ip", indicator="203.0.113.88", threat_type="suspicious-egress", source="AegisNet demo feed", confidence=88, created_at=utcnow_naive()),
        IOC(kind="domain", indicator="updates-malware.invalid", threat_type="phishing-simulation", source="AegisNet demo feed", confidence=93, created_at=utcnow_naive()),
    ]
    added = 0
    for item in records:
        exists = db.query(IOC.id).filter(IOC.kind == item.kind, IOC.indicator == item.indicator).first()
        if not exists:
            db.add(item)
            added += 1
    db.commit()
    return added


def serialize_alert(alert: Alert) -> dict:
    return {
        "id": alert.id,
        "rule_id": alert.rule_id,
        "title": alert.title,
        "description": alert.description,
        "severity": alert.severity,
        "risk_score": alert.risk_score,
        "status": alert.status,
        "src_ip": alert.src_ip,
        "asset": alert.asset,
        "username": alert.username,
        "mitre_technique": alert.mitre_technique,
        "mitre_tactic": alert.mitre_tactic,
        "event_count": alert.event_count,
        "assignee": alert.assignee,
        "first_seen": timestamp_text(alert.first_seen),
        "last_seen": timestamp_text(alert.last_seen),
        "created_at": timestamp_text(alert.created_at),
        "updated_at": timestamp_text(alert.updated_at),
    }


def serialize_event(event: Event) -> dict:
    return {
        "id": event.id,
        "event_uid": event.event_uid,
        "timestamp": timestamp_text(event.timestamp),
        "source": event.source,
        "event_type": event.event_type,
        "src_ip": event.src_ip,
        "dst_ip": event.dst_ip,
        "dst_port": event.dst_port,
        "username": event.username,
        "asset": event.asset,
        "action": event.action,
        "outcome": event.outcome,
        "domain": event.domain,
        "bytes_out": event.bytes_out,
        "process_name": event.process_name,
    }


def serialize_audit(entry: AuditEntry) -> dict:
    return {
        "id": entry.id,
        "actor": entry.actor,
        "action": entry.action,
        "from_status": entry.from_status,
        "to_status": entry.to_status,
        "note": entry.note,
        "created_at": timestamp_text(entry.created_at),
    }


def serialize_ioc(ioc: IOC) -> dict:
    return {
        "id": ioc.id,
        "kind": ioc.kind,
        "indicator": ioc.indicator,
        "threat_type": ioc.threat_type,
        "source": ioc.source,
        "confidence": ioc.confidence,
        "created_at": timestamp_text(ioc.created_at),
    }
