from __future__ import annotations

from datetime import datetime
from typing import Any, Optional

from pydantic import BaseModel, Field


class AlertRuleCreate(BaseModel):
    name: str
    description: Optional[str] = None
    query: str
    condition: str
    severity: str = "medium"
    throttle_mins: int = 60


class AlertRuleUpdate(BaseModel):
    name: Optional[str] = None
    description: Optional[str] = None
    query: Optional[str] = None
    condition: Optional[str] = None
    severity: Optional[str] = None
    throttle_mins: Optional[int] = None
    enabled: Optional[bool] = None


class AlertRule(BaseModel):
    id: str
    name: str
    description: Optional[str]
    query: str
    condition: str
    severity: str
    enabled: bool
    throttle_mins: int
    created_at: datetime
    updated_at: datetime


class AlertIncident(BaseModel):
    id: str
    rule_id: str
    rule_name: Optional[str] = None
    triggered_at: datetime
    resolved_at: Optional[datetime]
    metric_value: Optional[float]
    status: str
    details: Optional[Any]
