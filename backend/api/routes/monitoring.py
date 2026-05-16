from typing import Any, List
from fastapi import APIRouter, Depends
from sqlalchemy.orm import Session
from sqlalchemy import text

from backend.db.session import get_db
from backend.dependencies.auth import get_current_user
from backend.schemas.monitoring_schema import SystemLogResponse

router = APIRouter(prefix="/monitoring", tags=["System Monitoring"])

@router.get("/logs", response_model=List[SystemLogResponse])
async def get_system_logs(
    limit: int = 100,
    current_user: Any = Depends(get_current_user),
    db: Session = Depends(get_db),
):
    from backend.db.models import SystemLog
    return db.query(SystemLog).order_by(SystemLog.timestamp.desc()).limit(limit).all()

@router.get("/stats")
async def get_system_stats(
    current_user: Any = Depends(get_current_user),
    db: Session = Depends(get_db),
):
    """
    All counts use raw SQL to avoid ORM schema-drift crashes.
    The ScanResult table is the source of truth for predictions.
    """
    # ── Alert counts (raw SQL — never touches ORM DetectionAlert) ──
    total_alerts = db.execute(
        text("SELECT COUNT(*) FROM detection_alerts")
    ).scalar() or 0

    critical_threats = db.execute(
        text("SELECT COUNT(*) FROM detection_alerts WHERE severity = 'CRITICAL'")
    ).scalar() or 0

    # ── Prediction counts (raw SQL — avoids ScanResult ORM too) ──
    total_predictions = db.execute(
        text("SELECT COUNT(*) FROM scan_results")
    ).scalar() or 0

    total_uploads = db.execute(
        text("SELECT COUNT(*) FROM scan_results WHERE source_type = 'csv'")
    ).scalar() or 0

    total_scans = total_predictions  # same table

    avg_confidence_raw = db.execute(
        text("SELECT AVG(confidence) FROM scan_results")
    ).scalar()
    avg_confidence = round(float(avg_confidence_raw or 0.0), 4)

    latest_row = db.execute(
        text("SELECT created_at FROM scan_results ORDER BY created_at DESC LIMIT 1")
    ).first()
    latest_prediction_at = latest_row[0].isoformat() if latest_row and latest_row[0] else None

    normal_count = db.execute(
        text("SELECT COUNT(*) FROM scan_results WHERE predicted_label = 'Normal'")
    ).scalar() or 0

    attack_count = db.execute(
        text("SELECT COUNT(*) FROM scan_results WHERE predicted_label != 'Normal'")
    ).scalar() or 0

    return {
        "total_alerts": total_alerts,
        "total_scans": total_scans,
        "total_uploads": total_uploads,
        "total_predictions": total_predictions,
        "avg_confidence": avg_confidence,
        "latest_prediction_at": latest_prediction_at,
        "critical_threats": critical_threats,
        "predictions_by_label": {
            "Normal": normal_count,
            "Attack": attack_count,
        },
    }
