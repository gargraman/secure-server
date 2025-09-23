"""
API routers for the AI-SOAR Platform web application.

This module contains all the FastAPI router modules that define
the API endpoints for the platform.
"""

from .alerts import router as alerts_router
from .config import router as config_router
from .dashboard import router as dashboard_router
from .emergency_response import router as emergency_response_router
from .health import router as health_router
from .incidents import router as incidents_router
from .reports import router as reports_router
from .security import router as security_router
from .threat_hunting import router as threat_hunting_router
from .xdr import xdr_router

__all__ = [
    "health_router",
    "config_router",
    "dashboard_router",
    "xdr_router",
    "alerts_router",
    "incidents_router",
    "security_router",
    "threat_hunting_router",
    "reports_router",
    "emergency_response_router",
]
