from __future__ import annotations
import json
import logging
from datetime import datetime
from uuid import UUID
from sqlalchemy.orm import Session
from backend.db.models import ResponseAction, ActionAudit
from backend.schemas.response import (
    ResponseActionRequest,
    ResponseActionStatus,
    ResponseActionType,
)

logger = logging.getLogger("safeguard.services.response")

class ResponseEngine:
    """Production-grade response engine for automated and manual threat mitigation."""
    
    def __init__(self, db: Session):
        self.db = db

    def propose_action(self, request: ResponseActionRequest, actor_id: UUID = None) -> UUID:
        """Proposes a mitigation action for analyst approval."""
        action = ResponseAction(
            action_type=request.action_type.value,
            target=request.target,
            status=ResponseActionStatus.PROPOSED.value,
            details={
                "reason": request.reason,
                "parameters": request.parameters,
                "alert_id": str(request.alert_id)
            }
        )
        self.db.add(action)
        self.db.commit()
        self.db.refresh(action)
        
        # Log Audit
        audit = ActionAudit(
            action_id=action.id,
            actor_id=actor_id,
            change_type="PROPOSAL",
            new_status=action.status,
            comment=request.reason
        )
        self.db.add(audit)
        self.db.commit()
        
        return action.id

    def list_pending_actions(self) -> list[ResponseAction]:
        return self.db.query(ResponseAction).filter(
            ResponseAction.status == ResponseActionStatus.PROPOSED.value
        ).all()

    def execute_action(self, action_id: UUID, actor_id: UUID) -> bool:
        """Executes an approved mitigation action."""
        action = self.db.query(ResponseAction).filter(ResponseAction.id == action_id).first()
        if not action:
            return False
        
        # In a real system, this would trigger actual OS-level commands
        # For this prototype, we simulate execution
        try:
            logger.info(f"Executing {action.action_type} on {action.target}...")
            
            # Logic for blocking IP, killing process etc would go here
            
            action.status = ResponseActionStatus.EXECUTED.value
            action.executed_at = datetime.utcnow()
            
            audit = ActionAudit(
                action_id=action.id,
                actor_id=actor_id,
                change_type="EXECUTION",
                new_status=action.status,
                comment="Automated execution successful"
            )
            self.db.add(audit)
            self.db.commit()
            return True
        except Exception as e:
            logger.error(f"Action execution failed: {e}")
            action.status = ResponseActionStatus.FAILED.value
            self.db.commit()
            return False
