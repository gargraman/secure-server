"""
Legacy Configuration Service Compatibility Layer

Provides backward compatibility for existing code that depends on
Neo4jConfigurationService while delegating to the new decomposed services.

Author: AI-SOAR Platform Team
Created: 2025-09-18 - Service Decomposition Refactoring
"""

import logging
from datetime import datetime, timezone
from typing import Any, Dict, List, Optional
from uuid import UUID

from ..database.connection import Neo4jDatabaseManager
from ..database.models import (Alert, MCPServerConfiguration, PollingSession,
                               SystemConfiguration, XDRConfiguration)
from ..web.models.config_models import (MCPServerConfigurationCreate,
                                        SystemConfigurationCreate,
                                        XDRConfigurationCreate,
                                        XDRConfigurationUpdate)
from .service_coordinator import get_service_coordinator

logger = logging.getLogger(__name__)


class Neo4jConfigurationService:
    """
    Legacy compatibility layer for Neo4jConfigurationService.

    This class maintains backward compatibility by delegating method calls
    to the appropriate decomposed services.
    """

    def __init__(self, db_manager: Neo4jDatabaseManager = None):
        self.db_manager = db_manager
        self._service_coordinator = None

    async def _get_coordinator(self):
        """Get the service coordinator"""
        if not self._service_coordinator:
            self._service_coordinator = await get_service_coordinator()
        return self._service_coordinator

    # XDR Configuration Methods (delegate to XDRConfigurationService)
    async def create_xdr_configuration(
        self, config_data: XDRConfigurationCreate
    ) -> XDRConfiguration:
        """Create XDR configuration - delegated to XDRConfigurationService"""
        coordinator = await self._get_coordinator()
        xdr_service = await coordinator.xdr_config
        return await xdr_service.create_xdr_configuration(config_data)

    async def get_xdr_configuration(self, config_id: str) -> Optional[XDRConfiguration]:
        """Get XDR configuration - delegated to XDRConfigurationService"""
        coordinator = await self._get_coordinator()
        xdr_service = await coordinator.xdr_config
        return await xdr_service.get_xdr_configuration(config_id)

    async def update_xdr_configuration(
        self, config_id: str, update_data: XDRConfigurationUpdate
    ) -> XDRConfiguration:
        """Update XDR configuration - delegated to XDRConfigurationService"""
        coordinator = await self._get_coordinator()
        xdr_service = await coordinator.xdr_config
        return await xdr_service.update_xdr_configuration(config_id, update_data)

    async def delete_xdr_configuration(self, config_id: str) -> bool:
        """Delete XDR configuration - delegated to XDRConfigurationService"""
        coordinator = await self._get_coordinator()
        xdr_service = await coordinator.xdr_config
        return await xdr_service.delete_xdr_configuration(config_id)

    async def list_xdr_configurations(
        self, environment=None, status=None, limit: int = 100, offset: int = 0
    ) -> List[XDRConfiguration]:
        """List XDR configurations - delegated to XDRConfigurationService"""
        coordinator = await self._get_coordinator()
        xdr_service = await coordinator.xdr_config
        return await xdr_service.list_xdr_configurations(
            environment, status, limit, offset
        )

    async def test_xdr_connection(self, config_id: str) -> Dict[str, Any]:
        """Test XDR connection - delegated to XDRConfigurationService"""
        coordinator = await self._get_coordinator()
        xdr_service = await coordinator.xdr_config
        return await xdr_service.test_xdr_connection(config_id)

    # MCP Server Methods (delegate to MCPServerService)
    async def create_mcp_server(
        self, server_data: MCPServerConfigurationCreate
    ) -> MCPServerConfiguration:
        """Create MCP server - delegated to MCPServerService"""
        coordinator = await self._get_coordinator()
        mcp_service = await coordinator.mcp_servers
        return await mcp_service.create_mcp_server(server_data)

    async def get_mcp_server(self, server_id: str) -> Optional[MCPServerConfiguration]:
        """Get MCP server - delegated to MCPServerService"""
        coordinator = await self._get_coordinator()
        mcp_service = await coordinator.mcp_servers
        return await mcp_service.get_mcp_server(server_id)

    async def list_mcp_servers(
        self,
        server_type: Optional[str] = None,
        enabled_only: bool = False,
        limit: int = 100,
        offset: int = 0,
    ) -> List[MCPServerConfiguration]:
        """List MCP servers - delegated to MCPServerService"""
        coordinator = await self._get_coordinator()
        mcp_service = await coordinator.mcp_servers
        return await mcp_service.list_mcp_servers(
            server_type, enabled_only, limit, offset
        )

    async def update_mcp_server_health(
        self,
        server_id: str,
        health_status: str,
        health_details: Optional[Dict[str, Any]] = None,
    ) -> bool:
        """Update MCP server health - delegated to MCPServerService"""
        coordinator = await self._get_coordinator()
        mcp_service = await coordinator.mcp_servers
        return await mcp_service.update_mcp_server_health(
            server_id, health_status, health_details
        )

    async def enable_mcp_server(self, server_id: str) -> bool:
        """Enable MCP server - delegated to MCPServerService"""
        coordinator = await self._get_coordinator()
        mcp_service = await coordinator.mcp_servers
        return await mcp_service.enable_mcp_server(server_id)

    async def disable_mcp_server(self, server_id: str) -> bool:
        """Disable MCP server - delegated to MCPServerService"""
        coordinator = await self._get_coordinator()
        mcp_service = await coordinator.mcp_servers
        return await mcp_service.disable_mcp_server(server_id)

    async def delete_mcp_server(self, server_id: str) -> bool:
        """Delete MCP server - delegated to MCPServerService"""
        coordinator = await self._get_coordinator()
        mcp_service = await coordinator.mcp_servers
        return await mcp_service.delete_mcp_server(server_id)

    async def get_servers_by_type(
        self, server_type: str
    ) -> List[MCPServerConfiguration]:
        """Get servers by type - delegated to MCPServerService"""
        coordinator = await self._get_coordinator()
        mcp_service = await coordinator.mcp_servers
        return await mcp_service.get_servers_by_type(server_type)

    # Alert Processing Methods (delegate to AlertProcessingService)
    async def store_enhanced_alert(self, alert_data: Dict[str, Any]) -> Alert:
        """Store enhanced alert - delegated to AlertProcessingService"""
        coordinator = await self._get_coordinator()
        alert_service = await coordinator.alert_processing
        return await alert_service.store_enhanced_alert(alert_data)

    async def get_alert(self, alert_id: str) -> Optional[Alert]:
        """Get alert - delegated to AlertProcessingService"""
        coordinator = await self._get_coordinator()
        alert_service = await coordinator.alert_processing
        return await alert_service.get_alert(alert_id)

    async def update_processing_status(
        self,
        alert_id: str,
        status,
        mcp_server: Optional[str] = None,
        processing_results: Optional[Dict[str, Any]] = None,
        error_details: Optional[Dict[str, Any]] = None,
    ) -> bool:
        """Update processing status - delegated to AlertProcessingService"""
        coordinator = await self._get_coordinator()
        alert_service = await coordinator.alert_processing
        return await alert_service.update_processing_status(
            alert_id, status, mcp_server, processing_results, error_details
        )

    async def get_alerts_by_classification(
        self, classification, limit: int = 100, offset: int = 0
    ) -> List[Alert]:
        """Get alerts by classification - delegated to AlertProcessingService"""
        coordinator = await self._get_coordinator()
        alert_service = await coordinator.alert_processing
        return await alert_service.get_alerts_by_classification(
            classification, limit, offset
        )

    # Polling Session Methods (delegate to PollingSessionService)
    async def start_polling_session(
        self, configuration_id: str, override_interval: Optional[int] = None
    ) -> PollingSession:
        """Start polling session - delegated to PollingSessionService"""
        coordinator = await self._get_coordinator()
        polling_service = await coordinator.polling_sessions
        return await polling_service.start_polling_session(
            configuration_id, override_interval
        )

    async def end_polling_session(
        self, session_id: str, final_status: str = "completed"
    ) -> bool:
        """End polling session - delegated to PollingSessionService"""
        coordinator = await self._get_coordinator()
        polling_service = await coordinator.polling_sessions
        return await polling_service.end_polling_session(session_id, final_status)

    async def update_polling_metrics(
        self,
        session_id: str,
        polls_executed: Optional[int] = None,
        alerts_fetched: Optional[int] = None,
        alerts_processed: Optional[int] = None,
        errors_encountered: Optional[int] = None,
        last_error: Optional[str] = None,
    ) -> bool:
        """Update polling metrics - delegated to PollingSessionService"""
        coordinator = await self._get_coordinator()
        polling_service = await coordinator.polling_sessions
        return await polling_service.update_polling_metrics(
            session_id,
            polls_executed,
            alerts_fetched,
            alerts_processed,
            errors_encountered,
            last_error,
        )

    async def get_polling_session(self, session_id: str) -> Optional[PollingSession]:
        """Get polling session - delegated to PollingSessionService"""
        coordinator = await self._get_coordinator()
        polling_service = await coordinator.polling_sessions
        return await polling_service.get_polling_session(session_id)

    async def get_active_sessions(self) -> List[PollingSession]:
        """Get active sessions - delegated to PollingSessionService"""
        coordinator = await self._get_coordinator()
        polling_service = await coordinator.polling_sessions
        return await polling_service.get_active_sessions()

    # Secret Manager Methods (delegate to SecretManagerService)
    async def get_secret(self, secret_id: str, version: str = "latest") -> str:
        """Get secret - delegated to SecretManagerService"""
        coordinator = await self._get_coordinator()
        return await coordinator.secrets.get_secret(secret_id, version)

    async def secret_exists(self, secret_id: str) -> bool:
        """Check secret exists - delegated to SecretManagerService"""
        coordinator = await self._get_coordinator()
        return await coordinator.secrets.secret_exists(secret_id)

    async def get_xdr_auth_token(self, secret_name: str) -> str:
        """Get XDR auth token - delegated to SecretManagerService"""
        coordinator = await self._get_coordinator()
        return await coordinator.secrets.get_xdr_auth_token(secret_name)

    # Legacy method aliases for backward compatibility
    async def _validate_secret_exists(self, secret_name: str) -> None:
        """Legacy method - validate secret exists"""
        coordinator = await self._get_coordinator()
        await coordinator.secrets.validate_secret_exists(secret_name)

    async def get_db_manager(self) -> Neo4jDatabaseManager:
        """Get database manager - maintained for compatibility"""
        coordinator = await self._get_coordinator()
        return await coordinator.get_db_manager()

    # Additional legacy methods that may be needed
    async def create_system_configuration(
        self, config_data: SystemConfigurationCreate
    ) -> SystemConfiguration:
        """Create system configuration - placeholder for future implementation"""
        logger.warning(
            "create_system_configuration not yet implemented in decomposed services"
        )
        raise NotImplementedError("System configuration management not yet decomposed")

    async def get_system_configuration(
        self, config_key: str
    ) -> Optional[SystemConfiguration]:
        """Get system configuration - placeholder for future implementation"""
        logger.warning(
            "get_system_configuration not yet implemented in decomposed services"
        )
        raise NotImplementedError("System configuration management not yet decomposed")
