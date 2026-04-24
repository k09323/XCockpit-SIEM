from __future__ import annotations

from datetime import datetime
from typing import Any, Optional

from pydantic import BaseModel, Field


class InboundEvent(BaseModel):
    """Raw event as received from XCockpit (push webhook or pull API)."""
    model_config = {"extra": "allow"}

    # Common fields XCockpit may send — all optional since format varies
    alertId: Optional[str] = None
    ruleId: Optional[str] = None
    ruleName: Optional[str] = None
    riskLevel: Optional[str] = None
    sourceIp: Optional[str] = None
    destIp: Optional[str] = None
    sourcePort: Optional[int] = None
    destPort: Optional[int] = None
    protocol: Optional[str] = None
    hostname: Optional[str] = None
    username: Optional[str] = None
    processName: Optional[str] = None
    filePath: Optional[str] = None
    category: Optional[str] = None
    eventType: Optional[str] = None
    description: Optional[str] = None
    detectedAt: Optional[str] = None
    tags: Optional[list[str]] = None


class IngestBatch(BaseModel):
    events: list[dict[str, Any]] = Field(default_factory=list)
    batch_id: Optional[str] = None
    source: str = "xcockpit"
    sourcetype: str = "xcockpit:event"


class IngestResponse(BaseModel):
    accepted: int
    rejected: int
    batch_id: Optional[str]
    errors: list[str] = Field(default_factory=list)


class NormalizedEvent(BaseModel):
    """Internal representation after normalization."""
    _time: datetime
    _indextime: datetime
    source: str
    sourcetype: str
    host: Optional[str]
    severity: Optional[str]
    category: Optional[str]
    event_type: Optional[str]
    src_ip: Optional[str]
    dst_ip: Optional[str]
    src_port: Optional[int]
    dst_port: Optional[int]
    protocol: Optional[str]
    username: Optional[str]
    process_name: Optional[str]
    file_path: Optional[str]
    raw: dict
    message: Optional[str]
    tags: Optional[list[str]]
    xcockpit_event_id: Optional[str]
    xcockpit_rule_id: Optional[str]
    xcockpit_rule_name: Optional[str]
    _hash: str
