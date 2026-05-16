from pydantic import BaseModel, ConfigDict
from uuid import UUID
from datetime import datetime
from typing import Optional, Dict, Any

class SystemLogResponse(BaseModel):
    id: UUID
    event_type: str
    severity: str
    message: str
    details: Optional[Dict[str, Any]] = None
    timestamp: datetime
    
    model_config = ConfigDict(from_attributes=True)

class LiveTrafficMetrics(BaseModel):
    timestamp: datetime
    packet_count: int
    threat_ratio: float
    top_sources: Dict[str, int]
