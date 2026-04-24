from __future__ import annotations

from datetime import datetime
from typing import Any, Optional

from pydantic import BaseModel, Field


class PanelConfig(BaseModel):
    id: str
    title: str
    query: str
    chart_type: str = "timechart"  # timechart | table | stat | pie
    time_range: str = "-24h"
    x: int = 0
    y: int = 0
    w: int = 6
    h: int = 4


class DashboardLayout(BaseModel):
    panels: list[PanelConfig] = Field(default_factory=list)


class DashboardCreate(BaseModel):
    name: str
    description: Optional[str] = None
    layout: DashboardLayout = Field(default_factory=DashboardLayout)


class DashboardUpdate(BaseModel):
    name: Optional[str] = None
    description: Optional[str] = None
    layout: Optional[DashboardLayout] = None


class Dashboard(BaseModel):
    id: str
    name: str
    description: Optional[str]
    layout: DashboardLayout
    created_at: datetime
    updated_at: datetime
