from __future__ import annotations

from datetime import timedelta

from aegisnet.detection import DetectionEngine, utcnow_naive
from aegisnet.models import IOC, Alert, Event


def make_event(db, *, uid, event_type, minutes_ago=0, **kwargs):
    event = Event(
        event_uid=uid,
        timestamp=utcnow_naive() - timedelta(minutes=minutes_ago),
        source="pytest",
        event_type=event_type,
        raw_json="{}",
        **kwargs,
    )
    db.add(event)
    db.flush()
    return event


def test_brute_force_alert_is_explainable(db_session):
    engine = DetectionEngine()
    for index in range(5):
        event = make_event(
            db_session,
            uid=f"auth-{index}",
            event_type="auth",
            minutes_ago=4-index,
            src_ip="203.0.113.45",
            asset="gateway-1",
            username="root",
            action="login",
            outcome="failure",
        )
        engine.evaluate(db_session, event)
    alert = db_session.query(Alert).filter_by(rule_id="AUTH-001").one()
    assert alert.severity == "high"
    assert alert.mitre_technique == "T1110"
    assert alert.event_count == 5
    assert alert.status == "open"


def test_port_scan_threshold(db_session):
    engine = DetectionEngine()
    for index, port in enumerate([22, 23, 53, 80, 443, 445, 3306, 5432]):
        event = make_event(
            db_session,
            uid=f"scan-{index}",
            event_type="network",
            src_ip="192.0.2.77",
            dst_ip="192.0.2.10",
            dst_port=port,
            action="connection_attempt",
            outcome="denied",
        )
        engine.evaluate(db_session, event)
    alert = db_session.query(Alert).filter_by(rule_id="NET-001").one()
    assert alert.mitre_technique == "T1046"
    assert alert.event_count == 8


def test_local_ioc_match(db_session):
    db_session.add(
        IOC(kind="ip", indicator="198.51.100.66", threat_type="test", source="pytest", confidence=95, created_at=utcnow_naive())
    )
    db_session.flush()
    event = make_event(
        db_session,
        uid="ioc-test",
        event_type="network",
        src_ip="10.0.0.5",
        dst_ip="198.51.100.66",
        dst_port=443,
        action="outbound_connection",
        outcome="allowed",
    )
    DetectionEngine().evaluate(db_session, event)
    alert = db_session.query(Alert).filter_by(rule_id="THREAT-001").one()
    assert alert.severity == "critical"
    assert "198.51.100.66" in alert.title


def test_endpoint_exfiltration_and_dns_rules(db_session):
    engine = DetectionEngine()
    exfil = make_event(
        db_session,
        uid="large-egress",
        event_type="network",
        src_ip="10.0.0.8",
        asset="fileserver-1",
        action="outbound_transfer",
        outcome="allowed",
        bytes_out=12 * 1024 * 1024,
    )
    engine.evaluate(db_session, exfil)

    endpoint = make_event(
        db_session,
        uid="sudo-exec",
        event_type="endpoint",
        src_ip="10.0.0.9",
        asset="admin-ws-1",
        username="operator",
        action="privilege_escalation",
        outcome="success",
        process_name="sudo",
    )
    engine.evaluate(db_session, endpoint)

    dns = make_event(
        db_session,
        uid="entropy-dns",
        event_type="dns",
        src_ip="10.0.0.10",
        asset="workstation-1",
        domain="a83jf9q2m4v7x1p6z0n5c8b3r9t2q4w7.example",
        action="dns_query",
        outcome="success",
    )
    engine.evaluate(db_session, dns)

    rules = {alert.rule_id for alert in db_session.query(Alert).all()}
    assert {"EXFIL-001", "EDR-001", "DNS-001"}.issubset(rules)
