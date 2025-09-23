"""
Health Check API Endpoints

Comprehensive health check endpoints for monitoring and observability
in both development and production environments.

Author: AI-SOAR Platform Team
Created: 2025-09-10
"""

import asyncio
import logging
import os
from datetime import datetime, timedelta
from typing import Any, Dict, List

import aiohttp
import psutil
from fastapi import APIRouter, HTTPException, Request
from fastapi.responses import JSONResponse

from ...config.settings import get_settings
from ...database.connection import get_database_manager

logger = logging.getLogger(__name__)
router = APIRouter()

# Cache for health check results to avoid overwhelming downstream services
_health_cache = {}
_cache_duration = timedelta(seconds=30)


def _is_cache_valid(cache_key: str) -> bool:
    """Check if cached health result is still valid"""
    if cache_key not in _health_cache:
        return False

    cached_time = _health_cache[cache_key].get("cached_at")
    if not cached_time:
        return False

    return datetime.utcnow() - cached_time < _cache_duration


def _get_system_metrics() -> Dict[str, Any]:
    """Get system resource metrics"""
    try:
        cpu_percent = psutil.cpu_percent(interval=1)
        memory = psutil.virtual_memory()
        disk = psutil.disk_usage("/")

        return {
            "cpu_percent": cpu_percent,
            "memory_percent": memory.percent,
            "memory_available_gb": round(memory.available / (1024**3), 2),
            "disk_percent": disk.percent,
            "disk_free_gb": round(disk.free / (1024**3), 2),
            "load_average": os.getloadavg() if hasattr(os, "getloadavg") else None,
        }
    except Exception as e:
        logger.warning(f"Could not get system metrics: {e}")
        return {"error": str(e)}


@router.get("/health")
async def health_check():
    """Basic health check endpoint for load balancers and simple monitoring"""
    return {
        "status": "healthy",
        "timestamp": datetime.utcnow().isoformat(),
        "service": "ai-soar-platform",
        "version": "1.0.0",
        "uptime": _get_uptime(),
    }


def _get_uptime() -> str:
    """Get application uptime"""
    try:
        with open("/proc/uptime", "r") as f:
            uptime_seconds = float(f.readline().split()[0])
            return str(timedelta(seconds=int(uptime_seconds)))
    except:
        return "unknown"


@router.get("/health/detailed")
async def detailed_health_check(request: Request):
    """Comprehensive health check including all dependencies and system metrics"""
    cache_key = "detailed_health"

    # Return cached result if still valid
    if _is_cache_valid(cache_key):
        cached_result = _health_cache[cache_key]
        return JSONResponse(
            content=cached_result["data"], status_code=cached_result["status_code"]
        )

    health_status = {
        "status": "healthy",
        "timestamp": datetime.utcnow().isoformat(),
        "service": "ai-soar-platform",
        "version": "1.0.0",
        "environment": os.getenv("ENVIRONMENT", "unknown"),
        "checks": {},
        "metrics": _get_system_metrics(),
        "uptime": _get_uptime(),
    }

    overall_healthy = True

    # Neo4j Database health check
    try:
        db_manager = await get_database_manager()
        db_health = await db_manager.health_check()
        health_status["checks"]["neo4j"] = db_health

        if db_health.get("status") != "healthy":
            overall_healthy = False

    except Exception as e:
        logger.error(f"Neo4j health check failed: {e}")
        health_status["checks"]["neo4j"] = {
            "status": "unhealthy",
            "error": str(e),
            "timestamp": datetime.utcnow().isoformat(),
        }
        overall_healthy = False

    # Google Cloud services health check
    try:
        settings = get_settings()

        gcp_health = {
            "status": "healthy" if settings.google_cloud_project else "not_configured",
            "project": settings.google_cloud_project,
            "vertex_ai_location": settings.vertex_ai_location,
            "vertex_ai_enabled": settings.vertex_ai_enabled
            and bool(settings.google_cloud_project),
            "secret_manager_enabled": settings.secret_manager_enabled,
        }

        # Test Vertex AI if enabled
        if settings.vertex_ai_enabled and settings.google_cloud_project:
            try:
                # Simple test - this would be expanded to actually test Vertex AI connectivity
                gcp_health["vertex_ai_status"] = "configured"
            except Exception as vertex_error:
                gcp_health["vertex_ai_status"] = "error"
                gcp_health["vertex_ai_error"] = str(vertex_error)
                overall_healthy = False

        health_status["checks"]["google_cloud"] = gcp_health

    except Exception as e:
        logger.error(f"Google Cloud health check failed: {e}")
        health_status["checks"]["google_cloud"] = {
            "status": "unhealthy",
            "error": str(e),
            "timestamp": datetime.utcnow().isoformat(),
        }
        overall_healthy = False

    # MCP Servers health check
    mcp_health = await _check_mcp_servers()
    health_status["checks"]["mcp_servers"] = mcp_health
    if mcp_health["status"] != "healthy":
        overall_healthy = False

    # External dependencies health check
    external_health = await _check_external_dependencies()
    health_status["checks"]["external_services"] = external_health
    if external_health["status"] != "healthy":
        overall_healthy = False

    # Set overall status
    health_status["status"] = "healthy" if overall_healthy else "unhealthy"
    status_code = 200 if overall_healthy else 503

    # Cache the result
    _health_cache[cache_key] = {
        "data": health_status,
        "status_code": status_code,
        "cached_at": datetime.utcnow(),
    }

    return JSONResponse(content=health_status, status_code=status_code)


async def _check_mcp_servers() -> Dict[str, Any]:
    """Check health of MCP servers"""
    settings = get_settings()
    mcp_servers = {
        "virustotal": {"port": 8001, "status": "unknown"},
        "servicenow": {"port": 8002, "status": "unknown"},
        "cyberreason": {"port": 8003, "status": "unknown"},
        "custom_rest": {"port": 8004, "status": "unknown"},
        "cloud_ivx": {"port": 8005, "status": "unknown"},
    }

    overall_healthy = True
    healthy_count = 0

    async with aiohttp.ClientSession(timeout=aiohttp.ClientTimeout(total=5)) as session:
        for server_name, server_info in mcp_servers.items():
            try:
                url = f"http://localhost:{server_info['port']}/health"
                async with session.get(url) as response:
                    if response.status == 200:
                        server_info["status"] = "healthy"
                        healthy_count += 1
                    else:
                        server_info["status"] = "unhealthy"
                        server_info["http_status"] = response.status
                        overall_healthy = False
            except Exception as e:
                server_info["status"] = "unreachable"
                server_info["error"] = str(e)
                overall_healthy = False

    return {
        "status": "healthy" if overall_healthy else "degraded",
        "servers": mcp_servers,
        "healthy_count": healthy_count,
        "total_count": len(mcp_servers),
        "timestamp": datetime.utcnow().isoformat(),
    }


async def _check_external_dependencies() -> Dict[str, Any]:
    """Check external service dependencies"""
    dependencies = {
        "status": "healthy",
        "services": {},
        "timestamp": datetime.utcnow().isoformat(),
    }

    # Check internet connectivity (basic)
    try:
        async with aiohttp.ClientSession(
            timeout=aiohttp.ClientTimeout(total=5)
        ) as session:
            async with session.get("https://www.google.com") as response:
                if response.status == 200:
                    dependencies["services"]["internet"] = {"status": "healthy"}
                else:
                    dependencies["services"]["internet"] = {
                        "status": "unhealthy",
                        "http_status": response.status,
                    }
                    dependencies["status"] = "degraded"
    except Exception as e:
        dependencies["services"]["internet"] = {"status": "unhealthy", "error": str(e)}
        dependencies["status"] = "degraded"

    return dependencies


@router.get("/health/neo4j")
async def neo4j_health_check():
    """Dedicated Neo4j health check endpoint"""
    try:
        db_manager = await get_database_manager()
        db_health = await db_manager.health_check()

        if db_health.get("status") != "healthy":
            raise HTTPException(status_code=503, detail=db_health)

        return db_health

    except Exception as e:
        logger.error(f"Neo4j health check failed: {e}")
        error_response = {
            "status": "unhealthy",
            "error": str(e),
            "timestamp": datetime.utcnow().isoformat(),
        }
        raise HTTPException(status_code=503, detail=error_response)


@router.get("/health/mcp")
async def mcp_health_check():
    """Dedicated MCP servers health check endpoint"""
    mcp_health = await _check_mcp_servers()

    if mcp_health["status"] not in ["healthy", "degraded"]:
        raise HTTPException(status_code=503, detail=mcp_health)

    return mcp_health


@router.get("/metrics")
async def metrics_endpoint():
    """Prometheus-style metrics endpoint"""
    settings = get_settings()

    if not settings.metrics_enabled:
        raise HTTPException(status_code=404, detail="Metrics not enabled")

    # Basic metrics in Prometheus format
    metrics = []

    # System metrics
    system_metrics = _get_system_metrics()
    if "cpu_percent" in system_metrics:
        metrics.append(f"system_cpu_percent {system_metrics['cpu_percent']}")
    if "memory_percent" in system_metrics:
        metrics.append(f"system_memory_percent {system_metrics['memory_percent']}")
    if "disk_percent" in system_metrics:
        metrics.append(f"system_disk_percent {system_metrics['disk_percent']}")

    # Service metrics
    metrics.append("service_up 1")
    metrics.append(f'service_version{{version="1.0.0"}} 1')

    # Database metrics
    try:
        db_manager = await get_database_manager()
        db_health = await db_manager.health_check()
        db_status = 1 if db_health.get("status") == "healthy" else 0
        metrics.append(f"neo4j_up {db_status}")
    except:
        metrics.append("neo4j_up 0")

    # MCP server metrics
    mcp_health = await _check_mcp_servers()
    metrics.append(f"mcp_servers_healthy_count {mcp_health['healthy_count']}")
    metrics.append(f"mcp_servers_total_count {mcp_health['total_count']}")

    return "\n".join(metrics) + "\n"


@router.get("/readiness")
async def readiness_check():
    """Kubernetes readiness probe endpoint"""
    try:
        # Test database connection
        db_manager = await get_database_manager()
        db_health = await db_manager.health_check()

        if db_health.get("status") != "healthy":
            raise HTTPException(status_code=503, detail="Neo4j database not ready")

        # Check critical MCP servers
        mcp_health = await _check_mcp_servers()
        if mcp_health["healthy_count"] == 0:
            raise HTTPException(status_code=503, detail="No MCP servers are available")

        return {
            "status": "ready",
            "timestamp": datetime.utcnow().isoformat(),
            "database": "connected",
            "mcp_servers": f"{mcp_health['healthy_count']}/{mcp_health['total_count']} available",
        }

    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"Readiness check failed: {e}")
        raise HTTPException(status_code=503, detail=f"Service not ready: {str(e)}")


@router.get("/liveness")
async def liveness_check():
    """Kubernetes liveness probe endpoint"""
    return {
        "status": "alive",
        "timestamp": datetime.utcnow().isoformat(),
        "pid": os.getpid(),
        "uptime": _get_uptime(),
    }


@router.get("/startup")
async def startup_check():
    """Kubernetes startup probe endpoint"""
    try:
        # More lenient check for startup - just ensure basic connectivity
        db_manager = await get_database_manager()
        await db_manager.verify_connectivity()

        return {"status": "started", "timestamp": datetime.utcnow().isoformat()}

    except Exception as e:
        logger.error(f"Startup check failed: {e}")
        raise HTTPException(status_code=503, detail=f"Service not started: {str(e)}")
