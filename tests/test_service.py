from __future__ import annotations

from datetime import datetime, timezone

from pydantic import ValidationError

from aegisnet.schemas import EventIn
from aegisnet.service import ingest_events
from aegisnet.models import Event


def test_ingestion_is_idempotent_for_event_id(db_session):
    item = EventIn(
        event_id="stable-event-001",
        timestamp=datetime.now(timezone.utc),
        source="test",
        event_type="auth",
        src_ip="203.0.113.2",
        action="login",
        outcome="success",
    )
    result = ingest_events(db_session, [item, item])
    assert result["accepted"] == 1
    assert result["duplicates"] == 1
    assert db_session.query(Event).count() == 1


def test_invalid_source_ip_is_rejected():
    try:
        EventIn(event_type="auth", src_ip="999.999.999.999")
    except ValidationError:
        pass
    else:
        raise AssertionError("Invalid IP should fail schema validation")


def test_ioc_kind_validation():
    from aegisnet.schemas import IOCIn

    try:
        IOCIn(kind="ip", indicator="not-an-ip")
    except ValidationError:
        pass
    else:
        raise AssertionError("An invalid IP indicator must be rejected")
