"""
Configuration Management API Endpoints

FastAPI router for managing XDR configurations, MCP server settings,
and system configurations with Google Cloud integration.

Author: AI-SOAR Platform Team
Created: 2025-09-10
"""

import logging
from typing import List, Optional
from uuid import UUID

from fastapi import APIRouter, HTTPException, Query, status
from fastapi.responses import JSONResponse

from ...core.exceptions import AISOARException, handle_exception
from ...database.models import ConfigurationStatus, EnvironmentType
from ...services.config_service import Neo4jConfigurationService
from ...services.vertex_ai_service import VertexAIService
from ..models.config_models import (MCPServerConfigurationCreate,
                                    MCPServerConfigurationResponse,
                                    StartPollingRequest, StopPollingRequest,
                                    SystemConfigurationCreate,
                                    SystemConfigurationResponse,
                                    XDRConfigurationCreate,
                                    XDRConfigurationResponse,
                                    XDRConfigurationUpdate)

logger = logging.getLogger(__name__)
router = APIRouter()


@router.get("/xdr", response_model=List[XDRConfigurationResponse])
async def list_xdr_configurations(
    environment: Optional[EnvironmentType] = Query(
        None, description="Filter by environment"
    ),
    status: Optional[ConfigurationStatus] = Query(None, description="Filter by status"),
    poll_enabled: Optional[bool] = Query(None, description="Filter by polling enabled"),
    limit: int = Query(
        50, ge=1, le=100, description="Number of configurations to return"
    ),
    offset: int = Query(0, ge=0, description="Offset for pagination"),
):
    """List XDR configurations with optional filtering"""
    try:
        config_service = Neo4jConfigurationService()
        configurations = await config_service.list_xdr_configurations(
            environment=environment, status=status, limit=limit, offset=offset
        )

        # Convert to response models
        response_configs = []
        for config in configurations:
            config_response = XDRConfigurationResponse.from_orm(config)

            # Add statistics from service
            stats = await config_service.get_configuration_statistics(str(config.id))
            config_response.total_alerts = stats.get("total_alerts", 0)
            config_response.active_polling_sessions = stats.get("active_sessions", 0)

            response_configs.append(config_response)

        return response_configs

    except AISOARException as e:
        logger.error(f"AISOAR error listing XDR configurations: {e}")
        raise handle_exception(e)
    except Exception as e:
        logger.error(f"Unexpected error listing XDR configurations: {e}")
        raise handle_exception(e)


@router.post(
    "/xdr", response_model=XDRConfigurationResponse, status_code=status.HTTP_201_CREATED
)
async def create_xdr_configuration(config_data: XDRConfigurationCreate):
    """Create a new XDR configuration"""
    try:
        config_service = Neo4jConfigurationService()

        # Validate that auth token secret exists in Google Secret Manager
        # This would be implemented in the service layer

        # Create configuration
        configuration = await config_service.create_xdr_configuration(config_data)

        # Return response model
        return XDRConfigurationResponse.from_orm(configuration)

    except AISOARException as e:
        logger.error(f"AISOAR error creating XDR configuration: {e}")
        raise handle_exception(e)
    except Exception as e:
        logger.error(f"Unexpected error creating XDR configuration: {e}")
        raise handle_exception(e)


@router.get("/xdr/{configuration_id}", response_model=XDRConfigurationResponse)
async def get_xdr_configuration(configuration_id: UUID):
    """Get a specific XDR configuration by ID"""
    try:
        config_service = Neo4jConfigurationService()
        configuration = await config_service.get_xdr_configuration(
            str(configuration_id)
        )

        if not configuration:
            raise HTTPException(status_code=404, detail="Configuration not found")

        # Convert to response model with statistics
        config_response = XDRConfigurationResponse.from_orm(configuration)
        stats = await config_service.get_configuration_statistics(str(configuration_id))
        config_response.total_alerts = stats.get("total_alerts", 0)
        config_response.active_polling_sessions = stats.get("active_sessions", 0)

        return config_response

    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"Error getting XDR configuration {configuration_id}: {e}")
        raise HTTPException(
            status_code=500, detail=f"Failed to get configuration: {str(e)}"
        )


@router.put("/xdr/{configuration_id}", response_model=XDRConfigurationResponse)
async def update_xdr_configuration(
    configuration_id: UUID, config_data: XDRConfigurationUpdate
):
    """Update an existing XDR configuration"""
    try:
        config_service = Neo4jConfigurationService()
        configuration = await config_service.update_xdr_configuration(
            str(configuration_id), config_data
        )

        if not configuration:
            raise HTTPException(status_code=404, detail="Configuration not found")

        return XDRConfigurationResponse.from_orm(configuration)

    except HTTPException:
        raise
    except ValueError as e:
        logger.warning(f"Invalid update data for configuration {configuration_id}: {e}")
        raise HTTPException(status_code=400, detail=str(e))
    except Exception as e:
        logger.error(f"Error updating XDR configuration {configuration_id}: {e}")
        raise HTTPException(
            status_code=500, detail=f"Failed to update configuration: {str(e)}"
        )


@router.delete("/xdr/{configuration_id}", status_code=status.HTTP_204_NO_CONTENT)
async def delete_xdr_configuration(
    configuration_id: UUID,
    force: bool = Query(False, description="Force delete even if polling is active"),
):
    """Delete an XDR configuration"""
    try:
        config_service = Neo4jConfigurationService()
        success = await config_service.delete_xdr_configuration(
            str(configuration_id), force=force
        )

        if not success:
            raise HTTPException(status_code=404, detail="Configuration not found")

    except HTTPException:
        raise
    except ValueError as e:
        logger.warning(f"Cannot delete configuration {configuration_id}: {e}")
        raise HTTPException(status_code=400, detail=str(e))
    except Exception as e:
        logger.error(f"Error deleting XDR configuration {configuration_id}: {e}")
        raise HTTPException(
            status_code=500, detail=f"Failed to delete configuration: {str(e)}"
        )


@router.post("/xdr/{configuration_id}/start-polling")
async def start_xdr_polling(
    configuration_id: UUID, request: Optional[StartPollingRequest] = None
):
    """Start XDR polling for a configuration"""
    try:
        config_service = Neo4jConfigurationService()

        # Validate configuration exists and is ready for polling
        configuration = await config_service.get_xdr_configuration(
            str(configuration_id)
        )
        if not configuration:
            raise HTTPException(status_code=404, detail="Configuration not found")

        if configuration.status != ConfigurationStatus.ACTIVE:
            raise HTTPException(
                status_code=400, detail="Configuration must be active to start polling"
            )

        # Start polling session
        session = await config_service.start_polling_session(
            str(configuration_id),
            override_interval=request.override_interval if request else None,
        )

        return {
            "message": "Polling started successfully",
            "session_id": session.id,
            "configuration_id": str(configuration_id),
            "poll_interval": configuration.poll_interval,
        }

    except HTTPException:
        raise
    except Exception as e:
        logger.error(
            f"Error starting polling for configuration {configuration_id}: {e}"
        )
        raise HTTPException(
            status_code=500, detail=f"Failed to start polling: {str(e)}"
        )


@router.post("/xdr/{configuration_id}/stop-polling")
async def stop_xdr_polling(
    configuration_id: UUID, request: Optional[StopPollingRequest] = None
):
    """Stop XDR polling for a configuration"""
    try:
        config_service = Neo4jConfigurationService()

        success = await config_service.stop_polling_session(
            str(configuration_id), force_stop=request.force_stop if request else False
        )

        if not success:
            raise HTTPException(
                status_code=404, detail="No active polling session found"
            )

        return {
            "message": "Polling stopped successfully",
            "configuration_id": str(configuration_id),
        }

    except HTTPException:
        raise
    except Exception as e:
        logger.error(
            f"Error stopping polling for configuration {configuration_id}: {e}"
        )
        raise HTTPException(status_code=500, detail=f"Failed to stop polling: {str(e)}")


@router.get("/mcp-servers", response_model=List[MCPServerConfigurationResponse])
async def list_mcp_servers(
    enabled: Optional[bool] = Query(None, description="Filter by enabled status"),
    server_type: Optional[str] = Query(None, description="Filter by server type"),
    limit: int = Query(50, ge=1, le=100),
    offset: int = Query(0, ge=0),
):
    """List MCP server configurations"""
    try:
        config_service = Neo4jConfigurationService()
        servers = await config_service.list_mcp_server_configurations(
            server_type=server_type,
            enabled_only=enabled or False,
            limit=limit,
            offset=offset,
        )

        # Convert to response models (removing sensitive auth data)
        response_servers = []
        for server in servers:
            server_response = MCPServerConfigurationResponse.from_orm(server)
            server_response.auth_configured = bool(server.auth_config)
            response_servers.append(server_response)

        return response_servers

    except Exception as e:
        logger.error(f"Error listing MCP servers: {e}")
        raise HTTPException(
            status_code=500, detail=f"Failed to list MCP servers: {str(e)}"
        )


@router.post(
    "/mcp-servers",
    response_model=MCPServerConfigurationResponse,
    status_code=status.HTTP_201_CREATED,
)
async def create_mcp_server(server_data: MCPServerConfigurationCreate):
    """Create a new MCP server configuration"""
    try:
        config_service = Neo4jConfigurationService()
        server = await config_service.create_mcp_server_configuration(server_data)

        # Return response model without sensitive auth data
        server_response = MCPServerConfigurationResponse.from_orm(server)
        server_response.auth_configured = bool(server.auth_config)

        return server_response

    except ValueError as e:
        logger.warning(f"Invalid MCP server data: {e}")
        raise HTTPException(status_code=400, detail=str(e))
    except Exception as e:
        logger.error(f"Error creating MCP server: {e}")
        raise HTTPException(
            status_code=500, detail=f"Failed to create MCP server: {str(e)}"
        )


@router.get("/system", response_model=List[SystemConfigurationResponse])
async def list_system_configurations(
    config_type: Optional[str] = Query(
        None, description="Filter by configuration type"
    ),
    environment: Optional[EnvironmentType] = Query(
        None, description="Filter by environment"
    ),
):
    """List system configurations"""
    try:
        config_service = Neo4jConfigurationService()
        configurations = await config_service.list_system_configurations(
            config_type=config_type, environment=environment
        )

        return [
            SystemConfigurationResponse.from_orm(config) for config in configurations
        ]

    except Exception as e:
        logger.error(f"Error listing system configurations: {e}")
        raise HTTPException(
            status_code=500, detail=f"Failed to list system configurations: {str(e)}"
        )


@router.post(
    "/system",
    response_model=SystemConfigurationResponse,
    status_code=status.HTTP_201_CREATED,
)
async def create_system_configuration(config_data: SystemConfigurationCreate):
    """Create a new system configuration"""
    try:
        config_service = Neo4jConfigurationService()
        configuration = await config_service.create_system_configuration(config_data)

        return SystemConfigurationResponse.from_orm(configuration)

    except ValueError as e:
        logger.warning(f"Invalid system configuration data: {e}")
        raise HTTPException(status_code=400, detail=str(e))
    except Exception as e:
        logger.error(f"Error creating system configuration: {e}")
        raise HTTPException(
            status_code=500, detail=f"Failed to create system configuration: {str(e)}"
        )


@router.get("/vertex-ai/models")
async def list_vertex_ai_models():
    """List available Vertex AI models"""
    try:
        vertex_service = VertexAIService()
        models = await vertex_service.list_available_models()

        return {
            "available_models": models,
            "default_model": vertex_service.get_default_model(),
            "supported_features": vertex_service.get_supported_features(),
        }

    except Exception as e:
        logger.error(f"Error listing Vertex AI models: {e}")
        raise HTTPException(
            status_code=500, detail=f"Failed to list Vertex AI models: {str(e)}"
        )


@router.post("/test-connection")
async def test_xdr_connection(configuration_id: UUID):
    """Test connection to XDR API for a configuration"""
    try:
        config_service = Neo4jConfigurationService()
        result = await config_service.test_xdr_connection(str(configuration_id))

        return {
            "configuration_id": str(configuration_id),
            "connection_status": result["status"],
            "response_time_ms": result.get("response_time_ms"),
            "api_version": result.get("api_version"),
            "error_message": result.get("error"),
        }

    except Exception as e:
        logger.error(f"Error testing XDR connection for {configuration_id}: {e}")
        raise HTTPException(
            status_code=500, detail=f"Failed to test connection: {str(e)}"
        )
