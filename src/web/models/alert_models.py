"""
Alert Response Models

Pydantic models for XDR alert API responses and requests.

Author: AI-SOAR Platform Team
Created: 2025-09-11
"""

from datetime import datetime
from typing import Any, Dict, List, Optional
from uuid import UUID

from pydantic import BaseModel, Field


class AlertResponse(BaseModel):
    """Response model for XDR alert data"""

    id: str = Field(..., description="Alert unique identifier")
    external_id: Optional[str] = Field(None, description="External XDR alert ID")
    name: Optional[str] = Field(None, description="Alert name")
    severity: Optional[str] = Field(None, description="Alert severity level")
    status: Optional[str] = Field(None, description="Processing status")
    created_at: Optional[str] = Field(None, description="Alert creation timestamp")
    configuration_id: Optional[str] = Field(None, description="XDR configuration ID")
    alert_data: Dict[str, Any] = Field(
        default_factory=dict, description="Raw alert data"
    )
    processing_results: Dict[str, Any] = Field(
        default_factory=dict, description="MCP processing results"
    )
    retry_count: int = Field(0, description="Number of processing retries")

    model_config = {
        "from_attributes": True,
        "json_encoders": {datetime: lambda v: v.isoformat()},
    }


class AlertSummary(BaseModel):
    """Summary model for alert statistics"""

    total_alerts: int = Field(0, description="Total number of alerts")
    critical_alerts: int = Field(0, description="Number of critical alerts")
    high_alerts: int = Field(0, description="Number of high severity alerts")
    processed_alerts: int = Field(0, description="Number of processed alerts")
    failed_alerts: int = Field(0, description="Number of failed alerts")
    pending_alerts: int = Field(0, description="Number of pending alerts")


class AlertFilterRequest(BaseModel):
    """Request model for alert filtering"""

    configuration_id: Optional[UUID] = Field(
        None, description="Filter by XDR configuration"
    )
    severity: Optional[str] = Field(None, description="Filter by alert severity")
    status: Optional[str] = Field(None, description="Filter by processing status")
    start_date: Optional[datetime] = Field(
        None, description="Filter alerts from this date"
    )
    end_date: Optional[datetime] = Field(
        None, description="Filter alerts until this date"
    )
    limit: int = Field(50, ge=1, le=100, description="Number of alerts to return")
    offset: int = Field(0, ge=0, description="Offset for pagination")


class ReprocessAlertRequest(BaseModel):
    """Request model for alert reprocessing"""

    force_reprocess: bool = Field(
        False, description="Force reprocessing even if already completed"
    )
    reset_retry_count: bool = Field(False, description="Reset retry count to zero")


class AlertStatistics(BaseModel):
    """Alert statistics response model"""

    time_period_hours: int = Field(..., description="Time period analyzed in hours")
    status_distribution: Dict[str, int] = Field(
        default_factory=dict, description="Alerts by status"
    )
    severity_distribution: Dict[str, int] = Field(
        default_factory=dict, description="Alerts by severity"
    )
    processing_times: Dict[str, float] = Field(
        default_factory=dict, description="Processing time statistics"
    )
    timestamp: str = Field(..., description="Statistics generation timestamp")
