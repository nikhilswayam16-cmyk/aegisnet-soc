"""FastAPI entry point for the AegisNet SOC demo."""

from __future__ import annotations

import json
import logging
import secrets
from collections import Counter
from contextlib import asynccontextmanager
from datetime import UTC, timedelta
from pathlib import Path

from fastapi import Depends, FastAPI, Header, HTTPException, Query, Request
from fastapi.responses import FileResponse
from fastapi.staticfiles import StaticFiles
from sqlalchemy import func
from sqlalchemy.orm import Session

from .config import settings
from .database import Base, SessionLocal, engine, get_db
from .detection import as_utc_naive, utcnow_naive
from .models import IOC, Alert, AuditEntry, Event
from .schemas import AlertUpdate, EventBatch, EventIn, IOCIn
from .service import (
    ingest_events,
    seed_demo_iocs,
    serialize_alert,
    serialize_audit,
    serialize_event,
    serialize_ioc,
)

logging.basicConfig(level=getattr(logging, settings.log_level, logging.INFO))
logger = logging.getLogger("aegisnet")
PACKAGE_DIR = Path(__file__).resolve().parent
STATIC_DIR = PACKAGE_DIR / "static"


@asynccontextmanager
async def lifespan(app: FastAPI):
    Base.metadata.create_all(bind=engine)
    with SessionLocal() as db:
        seed_demo_iocs(db)
    yield


app = FastAPI(
    title="AegisNet SOC API",
    description="Explainable security telemetry ingestion, detection and incident workflow.",
    version="1.0.0",
    docs_url="/api/docs",
    redoc_url="/api/redoc",
    lifespan=lifespan,
)


@app.middleware("http")
async def security_headers(request: Request, call_next):
    response = await call_next(request)
    response.headers["X-Content-Type-Options"] = "nosniff"
    response.headers["X-Frame-Options"] = "DENY"
    response.headers["Referrer-Policy"] = "no-referrer"
    response.headers["Permissions-Policy"] = "camera=(), microphone=(), geolocation=()"
    response.headers["Cache-Control"] = "no-store" if request.url.path.startswith("/api/") else "no-cache"
    return response


def require_api_key(x_api_key: str | None = Header(default=None)) -> None:
    """Optionally protect write operations when AEGIS_API_KEY is configured."""
    if settings.api_key and not secrets.compare_digest(x_api_key or "", settings.api_key):
        raise HTTPException(status_code=401, detail="A valid X-API-Key header is required")


def _event_window(db: Session, hours: int = 24) -> list[Event]:
    since = utcnow_naive() - timedelta(hours=hours)
    return db.query(Event).filter(Event.timestamp >= since).all()


@app.get("/", include_in_schema=False)
def dashboard():
    return FileResponse(STATIC_DIR / "index.html")


@app.get("/healthz", tags=["system"])
def healthz():
    return {"status": "ok", "service": "aegisnet-soc", "version": "1.0.0"}


@app.get("/api/v1/overview", tags=["operations"])
def overview(db: Session = Depends(get_db)):
    now = utcnow_naive()
    day_start = now - timedelta(hours=24)
    events_total = db.query(func.count(Event.id)).scalar() or 0
    alerts_active = db.query(func.count(Alert.id)).filter(Alert.status != "resolved").scalar() or 0
    high_critical = (
        db.query(func.count(Alert.id))
        .filter(Alert.status != "resolved", Alert.severity.in_(["high", "critical"]))
        .scalar()
        or 0
    )
    assets = (
        db.query(func.count(func.distinct(Event.asset)))
        .filter(Event.asset.is_not(None), Event.asset != "")
        .scalar()
        or 0
    )
    recent_events = db.query(Event).filter(Event.timestamp >= day_start).all()
    hourly = Counter()
    source_counts = Counter()
    for item in recent_events:
        hour_delta = int((now - as_utc_naive(item.timestamp)).total_seconds() // 3600)
        if 0 <= hour_delta < 24:
            hourly[23 - hour_delta] += 1
        source_counts[item.source] += 1
    trend = [
        {"label": f"{(now - timedelta(hours=23 - i)).strftime('%H:00')}", "count": hourly[i]}
        for i in range(24)
    ]
    severities = {
        level: db.query(func.count(Alert.id)).filter(Alert.status != "resolved", Alert.severity == level).scalar() or 0
        for level in ("critical", "high", "medium", "low")
    }
    return {
        "events_total": events_total,
        "events_last_24h": len(recent_events),
        "alerts_active": alerts_active,
        "high_critical": high_critical,
        "assets_observed": assets,
        "severity": severities,
        "trend": trend,
        "top_sources": [{"source": name, "count": count} for name, count in source_counts.most_common(5)],
    }


@app.get("/api/v1/alerts", tags=["operations"])
def list_alerts(
    status: str | None = Query(default=None, pattern="^(open|investigating|contained|resolved)$"),
    severity: str | None = Query(default=None, pattern="^(critical|high|medium|low)$"),
    limit: int = Query(default=100, ge=1, le=500),
    db: Session = Depends(get_db),
):
    query = db.query(Alert)
    if status:
        query = query.filter(Alert.status == status)
    if severity:
        query = query.filter(Alert.severity == severity)
    results = query.order_by(Alert.last_seen.desc()).limit(limit).all()
    return {"items": [serialize_alert(item) for item in results], "count": len(results)}


@app.get("/api/v1/alerts/{alert_id}", tags=["operations"])
def get_alert(alert_id: int, db: Session = Depends(get_db)):
    alert = db.get(Alert, alert_id)
    if alert is None:
        raise HTTPException(status_code=404, detail="Alert not found")
    try:
        evidence = json.loads(alert.evidence_json or "[]")
    except json.JSONDecodeError:
        evidence = []
    audit = db.query(AuditEntry).filter(AuditEntry.alert_id == alert.id).order_by(AuditEntry.created_at.asc()).all()
    result = serialize_alert(alert)
    result["evidence"] = evidence
    result["audit"] = [serialize_audit(item) for item in audit]
    return result


@app.patch("/api/v1/alerts/{alert_id}", tags=["operations"], dependencies=[Depends(require_api_key)])
def update_alert(alert_id: int, update: AlertUpdate, db: Session = Depends(get_db)):
    alert = db.get(Alert, alert_id)
    if alert is None:
        raise HTTPException(status_code=404, detail="Alert not found")

    allowed = {
        "open": {"investigating"},
        "investigating": {"open", "contained", "resolved"},
        "contained": {"investigating", "resolved"},
        "resolved": {"investigating"},
    }
    old_status = alert.status
    if update.status != old_status and update.status not in allowed[old_status]:
        raise HTTPException(
            status_code=409,
            detail=f"Invalid status transition: {old_status} -> {update.status}",
        )
    if update.status in {"contained", "resolved"} and not update.note.strip():
        raise HTTPException(status_code=422, detail="A note is required when containing or resolving an alert")

    alert.status = update.status
    alert.assignee = update.assignee.strip() if update.assignee and update.assignee.strip() else alert.assignee
    alert.updated_at = utcnow_naive()
    if update.status != old_status or update.note.strip():
        db.add(
            AuditEntry(
                alert_id=alert.id,
                actor=update.assignee or "analyst",
                action="status-transition" if update.status != old_status else "analyst-note",
                from_status=old_status,
                to_status=update.status,
                note=update.note.strip() or f"Status changed from {old_status} to {update.status}.",
                created_at=utcnow_naive(),
            )
        )
    db.commit()
    db.refresh(alert)
    return serialize_alert(alert)


@app.get("/api/v1/events", tags=["telemetry"])
def list_events(
    event_type: str | None = None,
    limit: int = Query(default=100, ge=1, le=500),
    db: Session = Depends(get_db),
):
    query = db.query(Event)
    if event_type:
        query = query.filter(Event.event_type == event_type)
    results = query.order_by(Event.timestamp.desc()).limit(limit).all()
    return {"items": [serialize_event(item) for item in results], "count": len(results)}


@app.post("/api/v1/events/batch", tags=["telemetry"], dependencies=[Depends(require_api_key)])
def ingest_batch(batch: EventBatch, db: Session = Depends(get_db)):
    result = ingest_events(db, batch.events)
    logger.info("telemetry_batch accepted=%s duplicates=%s alerts=%s", result["accepted"], result["duplicates"], result["alerts_touched"])
    return result


@app.get("/api/v1/iocs", tags=["threat-intelligence"])
def list_iocs(db: Session = Depends(get_db)):
    items = db.query(IOC).order_by(IOC.confidence.desc(), IOC.indicator.asc()).all()
    return {"items": [serialize_ioc(item) for item in items], "count": len(items)}


@app.post("/api/v1/iocs", tags=["threat-intelligence"], dependencies=[Depends(require_api_key)])
def add_ioc(item: IOCIn, db: Session = Depends(get_db)):
    exists = db.query(IOC).filter(IOC.kind == item.kind, IOC.indicator == item.indicator).one_or_none()
    if exists:
        raise HTTPException(status_code=409, detail="This indicator already exists")
    record = IOC(**item.model_dump(), created_at=utcnow_naive())
    db.add(record)
    db.commit()
    db.refresh(record)
    return serialize_ioc(record)


@app.post("/api/v1/demo/replay", tags=["demo"], dependencies=[Depends(require_api_key)])
def replay_demo(db: Session = Depends(get_db)):
    """Replay bundled synthetic events with timestamps relative to the current time."""
    path = Path.cwd() / "data" / "demo_events.jsonl"
    if not path.exists():
        path = PACKAGE_DIR / "data" / "demo_events.jsonl"
    if not path.exists():
        raise HTTPException(status_code=500, detail="Bundled demo event file is missing")
    now = utcnow_naive()
    items: list[EventIn] = []
    for line in path.read_text(encoding="utf-8").splitlines():
        if not line.strip() or line.lstrip().startswith("#"):
            continue
        payload = json.loads(line)
        minutes_ago = int(payload.pop("minutes_ago", 0))
        payload["timestamp"] = (now - timedelta(minutes=minutes_ago)).replace(tzinfo=UTC).isoformat()
        items.append(EventIn.model_validate(payload))
    return ingest_events(db, items)


app.mount("/static", StaticFiles(directory=STATIC_DIR), name="static")
