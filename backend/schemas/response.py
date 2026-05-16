from __future__ import annotations
from datetime import datetime
from enum import Enum
from typing import Any, Optional
from uuid import UUID
from pydantic import BaseModel, Field, ConfigDict

class ResponseActionStatus(str, Enum):
    PROPOSED = "PROPOSED"
    APPROVED = "APPROVED"
    EXECUTED = "EXECUTED"
    FAILED = "FAILED"
    ROLLED_BACK = "ROLLED_BACK"
    CANCELED = "CANCELED"

class ResponseActionType(str, Enum):
    BLOCK_IP = "BLOCK_IP"
    KILL_PROCESS = "KILL_PROCESS"
    DISABLE_ADAPTER = "DISABLE_ADAPTER"
    FORENSIC_SNAPSHOT = "FORENSIC_SNAPSHOT"
    INCIDENT_REPORT = "INCIDENT_REPORT"

class ResponseActionRequest(BaseModel):
    alert_id: UUID
    action_type: ResponseActionType
    target: str
    parameters: dict[str, Any] = Field(default_factory=dict)
    reason: str

class ResponseActionResponse(BaseModel):
    id: UUID
    action_type: ResponseActionType
    target: str
    status: ResponseActionStatus
    details: Optional[dict[str, Any]] = None
    created_at: datetime
    executed_at: Optional[datetime] = None
    
    model_config = ConfigDict(from_attributes=True)
