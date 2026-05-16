import uuid
from datetime import datetime
from sqlalchemy import Column, String, Boolean, DateTime, Float, ForeignKey, Text, Index, JSON
from sqlalchemy.dialects.postgresql import UUID
from sqlalchemy.orm import relationship
from backend.db.database import Base

class User(Base):
    __tablename__ = "users"
    
    id = Column(UUID(as_uuid=True), primary_key=True, default=uuid.uuid4)
    username = Column(String(64), unique=True, index=True, nullable=False)
    email = Column(String(128), unique=True, index=True, nullable=True)
    password_hash = Column(String(256), nullable=False)
    is_admin = Column(Boolean, default=False, nullable=False)
    is_active = Column(Boolean, default=True, nullable=False)
    created_at = Column(DateTime, default=datetime.utcnow, nullable=False)
    last_login = Column(DateTime, nullable=True)

class ScanResult(Base):
    __tablename__ = "scan_results"
    
    id = Column(UUID(as_uuid=True), primary_key=True, default=uuid.uuid4)
    source_type = Column(String(32), index=True, nullable=False)  # pcap, csv, live
    predicted_label = Column(String(64), index=True, nullable=False)
    confidence = Column(Float, nullable=False)
    feature_data = Column(JSON, nullable=False)  # Original features
    explanation = Column(JSON, nullable=True)     # SHAP data
    created_by = Column(UUID(as_uuid=True), ForeignKey("users.id"), nullable=True)
    created_at = Column(DateTime, default=datetime.utcnow, index=True, nullable=False)
    
    alerts = relationship("DetectionAlert", back_populates="scan_result", cascade="all, delete-orphan")

class ResponseAction(Base):
    __tablename__ = "response_actions"
    
    id = Column(UUID(as_uuid=True), primary_key=True, default=uuid.uuid4)
    action_type = Column(String(32), index=True, nullable=False)
    target = Column(String(128), nullable=False)
    status = Column(String(32), default="PROPOSED", index=True, nullable=False)
    details = Column(JSON, nullable=True)
    created_at = Column(DateTime, default=datetime.utcnow, index=True, nullable=False)
    executed_at = Column(DateTime, nullable=True)
    
    audits = relationship("ActionAudit", back_populates="action", cascade="all, delete-orphan")

class ActionAudit(Base):
    __tablename__ = "action_audits"
    
    id = Column(UUID(as_uuid=True), primary_key=True, default=uuid.uuid4)
    action_id = Column(UUID(as_uuid=True), ForeignKey("response_actions.id", ondelete="CASCADE"), nullable=False)
    actor_id = Column(UUID(as_uuid=True), ForeignKey("users.id"), nullable=True)
    change_type = Column(String(32), nullable=False)
    old_status = Column(String(32), nullable=True)
    new_status = Column(String(32), nullable=False)
    comment = Column(Text, nullable=True)
    timestamp = Column(DateTime, default=datetime.utcnow, nullable=False)
    
    action = relationship("ResponseAction", back_populates="audits")

class DetectionAlert(Base):
    __tablename__ = "detection_alerts"
    
    id = Column(UUID(as_uuid=True), primary_key=True, default=uuid.uuid4)
    scan_result_id = Column(UUID(as_uuid=True), ForeignKey("scan_results.id", ondelete="CASCADE"), nullable=True)
    alert_type = Column(String(64), index=True, nullable=False)
    severity = Column(String(16), index=True, nullable=False) # LOW, MEDIUM, HIGH, CRITICAL
    description = Column(Text, nullable=False)
    metadata_json = Column(JSON, nullable=True)
    src_ip = Column(String(45), nullable=True)
    status = Column(String(32), default="active", nullable=False)
    acknowledged = Column(Boolean, default=False, index=True, nullable=False)
    acknowledged_by = Column(UUID(as_uuid=True), ForeignKey("users.id"), nullable=True)
    created_at = Column(DateTime, default=datetime.utcnow, index=True, nullable=False)
    
    scan_result = relationship("ScanResult", back_populates="alerts")

class SystemLog(Base):
    __tablename__ = "system_logs"
    
    id = Column(UUID(as_uuid=True), primary_key=True, default=uuid.uuid4)
    event_type = Column(String(64), index=True, nullable=False)
    severity = Column(String(16), index=True, nullable=False)
    message = Column(Text, nullable=False)
    details = Column(JSON, nullable=True)
    actor_id = Column(UUID(as_uuid=True), ForeignKey("users.id"), nullable=True)
    ip_address = Column(String(45), nullable=True)
    timestamp = Column(DateTime, default=datetime.utcnow, index=True, nullable=False)

# Optimized Indexes for high-frequency queries
Index("ix_alerts_severity_created", DetectionAlert.severity, DetectionAlert.created_at)
Index("ix_scans_type_created", ScanResult.source_type, ScanResult.created_at)
