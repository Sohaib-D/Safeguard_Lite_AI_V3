from typing import Any
from uuid import UUID
from fastapi import APIRouter, Depends, HTTPException
from sqlalchemy.orm import Session
from sqlalchemy import text

from backend.db.session import get_db
from backend.dependencies.auth import get_current_user
from backend.services.alert_service import AlertService
from backend.services.ai_service import AIService

router = APIRouter(prefix="/alerts", tags=["Threat Management"])


@router.get("/")
async def get_alerts(
    limit: int = 50,
    current_user: Any = Depends(get_current_user),
    db: Session = Depends(get_db),
):
    """Fetch recent alerts using raw SQL — zero ORM dependency."""
    try:
        result = db.execute(
            text("""
                SELECT id, alert_type, severity, description,
                       src_ip, status, acknowledged, created_at
                FROM detection_alerts
                ORDER BY created_at DESC
                LIMIT :limit
            """),
            {"limit": limit}
        )
        rows = [dict(r._mapping) for r in result.fetchall()]
        return {"alerts": rows, "total": len(rows)}
    except Exception as e:
        return {"alerts": [], "total": 0, "error": str(e)}


@router.get("/{alert_id}/ai-analysis", tags=["AI SOC"])
async def get_ai_guidance(
    alert_id: UUID,
    current_user: Any = Depends(get_current_user),
    db: Session = Depends(get_db),
):
    """Fetch a single alert by ID using raw SQL, then run AI analysis."""
    ai_svc = AIService()
    row = db.execute(
        text("SELECT id, description, metadata_json FROM detection_alerts WHERE id = :aid"),
        {"aid": str(alert_id)}
    ).mappings().first()
    if not row:
        raise HTTPException(status_code=404, detail="Alert not found")
    description = row["description"] or ""
    metadata = row["metadata_json"] or {}
    analysis = await ai_svc.analyze_threat(description, metadata)
    return {"analysis": analysis}


@router.post("/{alert_id}/acknowledge")
async def acknowledge_alert(
    alert_id: UUID,
    db: Session = Depends(get_db),
    current_user: Any = Depends(get_current_user),
):
    alert_svc = AlertService(db)
    result = alert_svc.acknowledge_alert(alert_id, current_user.id)
    if not result:
        raise HTTPException(status_code=404, detail="Alert not found")
    return {"status": "acknowledged"}
