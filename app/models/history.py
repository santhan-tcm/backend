from sqlalchemy import Column, Integer, String, Text, DateTime, JSON, Float
from sqlalchemy.sql import func
from datetime import datetime, timezone
from .database import Base

class ValidationHistory(Base):
    __tablename__ = "validation_history"

    id = Column(Integer, primary_key=True, index=True)
    validation_id = Column(String(50), unique=True, index=True)
    timestamp = Column(DateTime(timezone=True), default=lambda: datetime.now(timezone.utc))
    message_type = Column(String(50))
    status = Column(String(20)) # PASSED, FAILED, WARNING
    total_errors = Column(Integer, default=0)
    total_warnings = Column(Integer, default=0)
    execution_time_ms = Column(Float)
    
    # Store the actual report and message
    report_json = Column(JSON)
    original_message = Column(Text)
