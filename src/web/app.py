"""
AI-Driven Cybersecurity Automation Platform - Main Web Application

FastAPI application for managing XDR alert polling and MCP server integration
with Google Cloud Vertex AI support.

Author: AI-SOAR Platform Team
Created: 2025-09-10
"""

import json
import logging
import os
from contextlib import asynccontextmanager
from typing import Any, Dict, List

import uvicorn
import vertexai
from fastapi import FastAPI, Request, WebSocket, WebSocketDisconnect
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import HTMLResponse
from fastapi.staticfiles import StaticFiles
from fastapi.templating import Jinja2Templates
# Google Cloud imports
from google.cloud import logging as cloud_logging
from google.cloud import secretmanager
from google.oauth2 import service_account
from vertexai.generative_models import GenerativeModel

# Local imports
from ..config.settings import get_settings
from ..core.exceptions import AISOARException, handle_exception
from ..core.security import RateLimitMiddleware, SecurityHeadersMiddleware
from ..database.connection import Neo4jDatabaseManager
from ..services.vertex_ai_service import VertexAIService
from .routers import (alerts_router, config_router, dashboard_router,
                      emergency_response_router, health_router,
                      incidents_router, reports_router, security_router,
                      threat_hunting_router, xdr_router)


# Configure logging for Google Cloud
def setup_logging():
    """Configure logging for Google Cloud environment"""
    if os.getenv("GOOGLE_CLOUD_PROJECT"):
        # Use Google Cloud Logging in production
        client = cloud_logging.Client()
        client.setup_logging()

    logging.basicConfig(
        level=logging.INFO,
        format="%(asctime)s - %(name)s - %(levelname)s - %(message)s",
    )
    return logging.getLogger(__name__)


logger = setup_logging()


class WebSocketManager:
    """Manages WebSocket connections for real-time updates"""

    def __init__(self):
        self.active_connections: List[WebSocket] = []

    async def connect(self, websocket: WebSocket):
        await websocket.accept()
        self.active_connections.append(websocket)
        logger.info(
            f"WebSocket connected. Total connections: {len(self.active_connections)}"
        )

    def disconnect(self, websocket: WebSocket):
        if websocket in self.active_connections:
            self.active_connections.remove(websocket)
            logger.info(
                f"WebSocket disconnected. Total connections: {len(self.active_connections)}"
            )

    async def send_personal_message(self, message: str, websocket: WebSocket):
        try:
            await websocket.send_text(message)
        except Exception as e:
            logger.error(f"Error sending WebSocket message: {e}")
            self.disconnect(websocket)

    async def broadcast(self, message: str):
        if not self.active_connections:
            return

        disconnected = []
        for connection in self.active_connections:
            try:
                await connection.send_text(message)
            except Exception as e:
                logger.error(f"Error broadcasting to WebSocket: {e}")
                disconnected.append(connection)

        # Remove disconnected connections
        for connection in disconnected:
            self.disconnect(connection)


@asynccontextmanager
async def lifespan(app: FastAPI):
    """Application lifespan manager for startup/shutdown events"""
    logger.info("Starting AI-SOAR Platform Web Application...")

    # Initialize Google Cloud services
    settings = get_settings()

    try:
        # Initialize Vertex AI
        if settings.google_cloud_project:
            vertexai.init(
                project=settings.google_cloud_project,
                location=settings.vertex_ai_location,
            )
            logger.info(
                f"Vertex AI initialized for project: {settings.google_cloud_project}"
            )

            # Initialize Vertex AI service
            vertex_service = VertexAIService()
            app.state.vertex_ai = vertex_service
            logger.info("Vertex AI service initialized")

        # Initialize database connection
        try:
            db_manager = Neo4jDatabaseManager()
            await db_manager.initialize()
            app.state.db = db_manager
            logger.info("Database connection initialized")
        except Exception as db_error:
            logger.warning(
                f"Database connection failed, running in mock mode: {db_error}"
            )
            app.state.db = None

        # Initialize Google Cloud Secret Manager if available
        if settings.google_cloud_project:
            app.state.secret_client = secretmanager.SecretManagerServiceClient()
            logger.info("Secret Manager client initialized")

        # Initialize WebSocket connection manager
        app.state.websocket_manager = WebSocketManager()

        logger.info("Application startup completed successfully")

    except Exception as e:
        logger.error(f"Failed to initialize application: {e}")
        raise

    yield

    # Cleanup on shutdown
    logger.info("Shutting down AI-SOAR Platform...")

    if hasattr(app.state, "db") and app.state.db:
        await app.state.db.close()
        logger.info("Database connection closed")

    logger.info("Application shutdown completed")


# Create FastAPI application
app = FastAPI(
    title="AI-Driven Cybersecurity Automation Platform",
    description="XDR Alert Management and MCP Server Integration Platform",
    version="1.0.0",
    docs_url="/docs",
    redoc_url="/redoc",
    lifespan=lifespan,
)

# Add security middleware
app.add_middleware(SecurityHeadersMiddleware)
app.add_middleware(RateLimitMiddleware, max_requests=100, time_window=60)

# Configure CORS for Google Cloud deployment
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],  # Configure based on your domain in production
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# Mount static files - use absolute path for Docker compatibility
static_dir = os.path.join(os.path.dirname(os.path.dirname(__file__)), "web", "static")
if not os.path.exists(static_dir):
    # Fallback for different deployment scenarios
    static_dir = "/app/src/web/static"
    if not os.path.exists(static_dir):
        static_dir = "static"  # Final fallback

app.mount("/static", StaticFiles(directory=static_dir), name="static")

# Configure templates - use absolute path for Docker compatibility
templates_dir = os.path.join(
    os.path.dirname(os.path.dirname(__file__)), "web", "templates"
)
if not os.path.exists(templates_dir):
    # Fallback for different deployment scenarios
    templates_dir = "/app/src/web/templates"
    if not os.path.exists(templates_dir):
        templates_dir = "templates"  # Final fallback

templates = Jinja2Templates(directory=templates_dir)


# Global exception handler
@app.exception_handler(AISOARException)
async def aisoar_exception_handler(request: Request, exc: AISOARException):
    """Handle AISOAR-specific exceptions"""
    return handle_exception(exc)


@app.exception_handler(Exception)
async def general_exception_handler(request: Request, exc: Exception):
    """Handle all other exceptions"""
    logger.error(f"Unhandled exception: {exc}")
    return handle_exception(exc)


# Include routers
app.include_router(health_router, prefix="/api", tags=["health"])
app.include_router(config_router, prefix="/api/config", tags=["configuration"])
app.include_router(xdr_router, prefix="/api/xdr", tags=["xdr"])
app.include_router(dashboard_router, prefix="/api/dashboard", tags=["dashboard"])
app.include_router(alerts_router, prefix="/api/alerts", tags=["alerts"])
app.include_router(incidents_router, prefix="/api/incidents", tags=["incidents"])
app.include_router(security_router, prefix="/api/security", tags=["security"])
app.include_router(
    threat_hunting_router, prefix="/api/threat-hunting", tags=["threat-hunting"]
)
app.include_router(reports_router, prefix="/api/reports", tags=["reports"])
app.include_router(
    emergency_response_router,
    prefix="/api/emergency-response",
    tags=["emergency-response"],
)


@app.get("/", response_class=HTMLResponse)
async def root(request: Request):
    """Main dashboard page"""
    return templates.TemplateResponse(
        "dashboard.html", {"request": request, "title": "AI-SOAR Platform Dashboard"}
    )


@app.get("/config", response_class=HTMLResponse)
async def config_page(request: Request):
    """Configuration management page"""
    return templates.TemplateResponse(
        "config.html", {"request": request, "title": "XDR Configuration"}
    )


@app.get("/alerts", response_class=HTMLResponse)
async def alerts_page(request: Request):
    """Alert management page"""
    return templates.TemplateResponse(
        "alerts.html", {"request": request, "title": "Alert Management"}
    )


@app.get("/incidents", response_class=HTMLResponse)
async def incidents_page(request: Request):
    """Incident response page"""
    return templates.TemplateResponse(
        "incidents.html", {"request": request, "title": "Incident Response"}
    )


@app.get("/threats", response_class=HTMLResponse)
async def threats_page(request: Request):
    """Threat intelligence page"""
    return templates.TemplateResponse(
        "dashboard.html",  # Placeholder - reuse dashboard for now
        {"request": request, "title": "Threat Intelligence"},
    )


@app.get("/investigations", response_class=HTMLResponse)
async def investigations_page(request: Request):
    """Investigation workspace page"""
    return templates.TemplateResponse(
        "dashboard.html",  # Placeholder - reuse dashboard for now
        {"request": request, "title": "Investigation Workspace"},
    )


@app.get("/graph", response_class=HTMLResponse)
async def graph_page(request: Request):
    """Threat graph explorer page"""
    return templates.TemplateResponse(
        "dashboard.html",  # Placeholder - reuse dashboard for now
        {"request": request, "title": "Threat Graph Explorer"},
    )


@app.get("/health")
async def health_check():
    """Simple health check endpoint"""
    return {"status": "healthy", "service": "ai-soar-platform", "version": "1.0.0"}


@app.get("/meta")
async def service_meta():
    """Service metadata for Google Cloud deployment"""
    settings = get_settings()
    return {
        "service_name": "ai-soar-platform",
        "version": "1.0.0",
        "environment": settings.environment,
        "google_cloud_project": settings.google_cloud_project,
        "vertex_ai_enabled": bool(settings.google_cloud_project),
        "database_connected": hasattr(app.state, "db"),
        "endpoints": {
            "docs": "/docs",
            "health": "/health",
            "api": "/api",
            "dashboard": "/",
            "config": "/config",
            "alerts": "/alerts",
            "incidents": "/incidents",
            "threats": "/threats",
            "investigations": "/investigations",
            "graph": "/graph",
            "websocket": "/ws",
        },
    }


@app.websocket("/ws")
async def websocket_endpoint(websocket: WebSocket):
    """WebSocket endpoint for real-time updates"""
    manager = app.state.websocket_manager
    await manager.connect(websocket)

    try:
        # Send initial connection message
        await manager.send_personal_message(
            json.dumps(
                {
                    "type": "connection",
                    "status": "connected",
                    "message": "Connected to AI-SOAR Platform real-time updates",
                }
            ),
            websocket,
        )

        # Keep connection alive and handle incoming messages
        while True:
            try:
                data = await websocket.receive_text()
                message = json.loads(data)

                # Handle different message types
                if message.get("type") == "ping":
                    await manager.send_personal_message(
                        json.dumps(
                            {"type": "pong", "timestamp": message.get("timestamp")}
                        ),
                        websocket,
                    )
                elif message.get("type") == "subscribe":
                    # Handle subscription requests (dashboard updates, alert notifications, etc.)
                    await manager.send_personal_message(
                        json.dumps(
                            {
                                "type": "subscription",
                                "status": "subscribed",
                                "topic": message.get("topic", "general"),
                            }
                        ),
                        websocket,
                    )

            except json.JSONDecodeError:
                logger.warning("Received invalid JSON from WebSocket")
            except Exception as e:
                logger.error(f"Error handling WebSocket message: {e}")
                break

    except WebSocketDisconnect:
        manager.disconnect(websocket)
    except Exception as e:
        logger.error(f"WebSocket error: {e}")
        manager.disconnect(websocket)


if __name__ == "__main__":
    settings = get_settings()
    uvicorn.run(
        "src.web.app:app",
        host="0.0.0.0",
        port=settings.web_port,
        reload=settings.environment == "development",
        log_level="info",
    )
