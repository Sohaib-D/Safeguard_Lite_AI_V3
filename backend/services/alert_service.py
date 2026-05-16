import logging
from typing import List, Optional
from uuid import UUID
from sqlalchemy.orm import Session
from backend.db.models import DetectionAlert, ScanResult, SystemLog
from backend.schemas.alert_schema import AlertCreate

logger = logging.getLogger("safeguard.services.alerts")

class AlertService:
    def __init__(self, db: Session):
        self.db = db

    def create_alert(self, alert_data: AlertCreate) -> DetectionAlert:
        alert = DetectionAlert(
            alert_type=alert_data.alert_type,
            severity=alert_data.severity,
            description=alert_data.description,
            metadata_json=alert_data.metadata_json,
            scan_result_id=alert_data.scan_result_id
        )
        self.db.add(alert)
        self.db.commit()
        self.db.refresh(alert)
        
        # Internal Audit Log
        self.log_system_event(
            event_type="threat_alert",
            severity=alert.severity,
            message=f"New {alert.severity} alert: {alert.alert_type}",
            details={"alert_id": str(alert.id)}
        )
        
        return alert

    def log_system_event(self, event_type: str, severity: str, message: str, details: dict = None):
        log = SystemLog(
            event_type=event_type,
            severity=severity,
            message=message,
            details=details
        )
        self.db.add(log)
        self.db.commit()

    def get_recent_alerts(self, limit: int = 50) -> List[dict]:
        from sqlalchemy import text
        rows = self.db.execute(
            text("""
                SELECT id, scan_result_id, alert_type, severity, description,
                       metadata_json, src_ip, status, acknowledged, acknowledged_by, created_at
                FROM detection_alerts
                ORDER BY created_at DESC
                LIMIT :limit
            """),
            {"limit": limit}
        ).mappings().all()
        return [dict(r) for r in rows]

    def acknowledge_alert(self, alert_id: UUID, user_id: UUID) -> Optional[DetectionAlert]:
        alert = self.db.query(DetectionAlert).filter(DetectionAlert.id == alert_id).first()
        if alert:
            alert.acknowledged = True
            alert.acknowledged_by = user_id
            alert.status = "resolved"
            self.db.commit()
            self.db.refresh(alert)
        return alert
