"""
XDR Integration API Router

API endpoints for XDR alert management and polling control.
Integrates with existing XDR client infrastructure.

Author: AI-SOAR Platform Team
Created: 2025-09-10
"""

import logging
from typing import Any, Dict, List, Optional
from uuid import UUID

from fastapi import APIRouter, HTTPException, Query

from ...services.xdr_service import XDRService
from ..models.alert_models import AlertResponse, AlertSummary

logger = logging.getLogger(__name__)
xdr_router = APIRouter()


@xdr_router.get("/alerts", response_model=List[AlertResponse])
async def list_alerts(
    configuration_id: Optional[UUID] = Query(
        None, description="Filter by XDR configuration"
    ),
    severity: Optional[str] = Query(None, description="Filter by alert severity"),
    status: Optional[str] = Query(None, description="Filter by processing status"),
    limit: int = Query(50, ge=1, le=100),
    offset: int = Query(0, ge=0),
):
    """List XDR alerts with filtering options"""
    try:
        xdr_service = XDRService()
        alerts = await xdr_service.list_alerts(
            configuration_id=configuration_id,
            severity=severity,
            status=status,
            limit=limit,
            offset=offset,
        )

        return alerts

    except Exception as e:
        logger.error(f"Error listing XDR alerts: {e}")
        raise HTTPException(status_code=500, detail=f"Failed to list alerts: {str(e)}")


@xdr_router.get("/alerts/{alert_id}", response_model=AlertResponse)
async def get_alert(alert_id: UUID):
    """Get detailed information for a specific alert"""
    try:
        xdr_service = XDRService()
        alert = await xdr_service.get_alert(alert_id)

        if not alert:
            raise HTTPException(status_code=404, detail="Alert not found")

        return alert

    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"Error getting alert {alert_id}: {e}")
        raise HTTPException(status_code=500, detail=f"Failed to get alert: {str(e)}")


@xdr_router.post("/alerts/{alert_id}/reprocess")
async def reprocess_alert(
    alert_id: UUID,
    force_reprocess: bool = Query(
        False, description="Force reprocessing even if already completed"
    ),
):
    """Reprocess an alert through MCP servers"""
    try:
        xdr_service = XDRService()
        result = await xdr_service.reprocess_alert(alert_id, force=force_reprocess)

        return {
            "alert_id": str(alert_id),
            "reprocess_status": result["status"],
            "message": result["message"],
            "processing_started": result.get("processing_started", False),
        }

    except Exception as e:
        logger.error(f"Error reprocessing alert {alert_id}: {e}")
        raise HTTPException(
            status_code=500, detail=f"Failed to reprocess alert: {str(e)}"
        )


@xdr_router.get("/polling-status")
async def get_polling_status():
    """Get current polling status for all XDR configurations"""
    try:
        xdr_service = XDRService()
        status = await xdr_service.get_polling_status()

        return {"polling_status": status, "timestamp": status.get("timestamp")}

    except Exception as e:
        logger.error(f"Error getting polling status: {e}")
        raise HTTPException(
            status_code=500, detail=f"Failed to get polling status: {str(e)}"
        )


@xdr_router.get("/statistics")
async def get_xdr_statistics(
    hours: int = Query(24, ge=1, le=168, description="Hours to analyze")
):
    """Get XDR alert statistics"""
    try:
        xdr_service = XDRService()
        stats = await xdr_service.get_statistics(hours=hours)

        return stats

    except Exception as e:
        logger.error(f"Error getting XDR statistics: {e}")
        raise HTTPException(
            status_code=500, detail=f"Failed to get statistics: {str(e)}"
        )
