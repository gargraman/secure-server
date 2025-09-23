import logging
from datetime import datetime, timedelta
from typing import Any, Dict, List

from fastapi import APIRouter, HTTPException

logger = logging.getLogger(__name__)

router = APIRouter()


@router.get("/")
async def get_incidents():
    """Get all incidents"""
    try:
        # Return mock data when database is not available
        return {
            "timestamp": datetime.utcnow().isoformat(),
            "incidents": [
                {
                    "id": "incident-001",
                    "title": "Multiple Failed Login Attempts",
                    "severity": "medium",
                    "status": "investigating",
                    "created_at": (datetime.utcnow() - timedelta(hours=2)).isoformat(),
                    "assigned_to": "Alice Johnson",
                    "alert_count": 15,
                },
                {
                    "id": "incident-002",
                    "title": "Suspicious Data Transfer",
                    "severity": "high",
                    "status": "contained",
                    "created_at": (datetime.utcnow() - timedelta(hours=6)).isoformat(),
                    "assigned_to": "Bob Smith",
                    "alert_count": 8,
                },
            ],
        }

    except Exception as e:
        logger.error(f"Error getting incidents: {e}")
        return {
            "timestamp": datetime.utcnow().isoformat(),
            "error": f"Failed to load incidents: {str(e)}",
            "incidents": [],
        }


@router.get("/statistics")
async def get_incidents_statistics():
    """Get incidents statistics"""
    try:
        # Return mock data when database is not available
        return {
            "timestamp": datetime.utcnow().isoformat(),
            "statistics": {
                "total_incidents": 24,
                "active_incidents": 8,
                "resolved_today": 3,
                "critical_incidents": 2,
                "avg_resolution_time": 4.5,
            },
        }

    except Exception as e:
        logger.error(f"Error getting incidents statistics: {e}")
        return {
            "timestamp": datetime.utcnow().isoformat(),
            "error": f"Failed to load incidents statistics: {str(e)}",
            "statistics": {
                "total_incidents": 0,
                "active_incidents": 0,
                "resolved_today": 0,
                "critical_incidents": 0,
                "avg_resolution_time": 0,
            },
        }
