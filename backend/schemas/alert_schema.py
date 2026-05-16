from pydantic import BaseModel, ConfigDict
from uuid import UUID
from datetime import datetime
from typing import Optional, Dict, List, Any

class AlertBase(BaseModel):
    alert_type: str
    severity: str
    description: str
    metadata_json: Optional[Dict[str, Any]] = None

class AlertCreate(AlertBase):
    scan_result_id: Optional[UUID] = None

class AlertResponse(AlertBase):
    id: UUID
    acknowledged: bool
    created_at: datetime
    scan_result_id: Optional[UUID] = None
    src_ip: Optional[str] = None
    status: Optional[str] = "active"
    
    model_config = ConfigDict(from_attributes=True)

class ScanResultBase(BaseModel):
    source_type: str
    predicted_label: str
    confidence: float

class ScanResultCreate(ScanResultBase):
    feature_data: Dict[str, Any]
    explanation: Optional[Dict[str, Any]] = None

class ScanResultResponse(ScanResultBase):
    id: UUID
    explanation: Optional[Dict[str, Any]] = None
    created_at: datetime
    
    model_config = ConfigDict(from_attributes=True)
