from datetime import datetime, timezone
from pydantic import BaseModel, Field, field_validator
from typing import List, Dict, Any, Optional

class ValidationRequest(BaseModel):
    xml_content: str
    mode: str = "Full 1-5"
    message_type: str = "Auto-detect"
    store_in_history: bool = True

class IssueSchema(BaseModel):
    severity: str
    layer: int
    code: str
    path: str
    message: str
    fix_suggestion: str
    related_test: str

class ValidationResponse(BaseModel):
    validation_id: str
    timestamp: str
    status: str
    schema: str
    message: str
    errors: int
    warnings: int
    total_time_ms: float
    layer_status: Dict[str, Any]
    details: List[IssueSchema]

class HistorySummary(BaseModel):
    id: int
    validation_id: str
    timestamp: Any  # Keep as Any to handle the manual conversion
    message_type: str
    status: str
    total_errors: int
    total_warnings: int
    execution_time_ms: float

    @field_validator('timestamp', mode='before')
    @classmethod
    def format_timestamp(cls, v):
        if isinstance(v, datetime):
            # Ensure it has UTC info and ends with Z for JS compatibility
            if v.tzinfo is None:
                v = v.replace(tzinfo=timezone.utc)
            return v.strftime("%Y-%m-%dT%H:%M:%SZ")
        return v

    class Config:
        from_attributes = True
