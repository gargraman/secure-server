"""
Service Coordinator

Unified coordinator for all decomposed services, providing a single interface
for managing the cybersecurity automation platform's services.

Author: AI-SOAR Platform Team
Created: 2025-09-18 - Service Decomposition Refactoring
"""

import logging
from datetime import datetime
from typing import Any, Dict, List, Optional

from ..config.settings import get_settings
from ..database.connection import Neo4jDatabaseManager, get_database_manager
from .alert_processing_service import AlertProcessingService
from .enhanced_neo4j_population_service import EnhancedNeo4jPopulationService
from .mcp_server_service import MCPServerService
from .polling_session_service import PollingSessionService
from .secret_manager_service import SecretManagerService
from .xdr_configuration_service import XDRConfigurationService

logger = logging.getLogger(__name__)


class ServiceCoordinator:
    """
    Unified coordinator for all platform services.

    Provides a single interface for accessing decomposed services while
    maintaining clear separation of concerns.
    """

    def __init__(self, db_manager: Neo4jDatabaseManager = None):
        self.db_manager = db_manager
        self._db_manager_cache = None
        self.settings = get_settings()

        # Initialize decomposed services
        self._xdr_config_service = None
        self._mcp_server_service = None
        self._alert_processing_service = None
        self._secret_manager_service = None
        self._polling_session_service = None
        self._enhanced_neo4j_service = None

    async def get_db_manager(self) -> Neo4jDatabaseManager:
        """Get database manager instance with proper error handling"""
        if self.db_manager:
            return self.db_manager
        if not self._db_manager_cache:
            self._db_manager_cache = await get_database_manager()
        return self._db_manager_cache

    @property
    async def xdr_config(self) -> XDRConfigurationService:
        """Get XDR configuration service"""
        if not self._xdr_config_service:
            db_manager = await self.get_db_manager()
            self._xdr_config_service = XDRConfigurationService(db_manager)
        return self._xdr_config_service

    @property
    async def mcp_servers(self) -> MCPServerService:
        """Get MCP server service"""
        if not self._mcp_server_service:
            db_manager = await self.get_db_manager()
            self._mcp_server_service = MCPServerService(db_manager)
        return self._mcp_server_service

    @property
    async def alert_processing(self) -> AlertProcessingService:
        """Get alert processing service"""
        if not self._alert_processing_service:
            db_manager = await self.get_db_manager()
            self._alert_processing_service = AlertProcessingService(db_manager)
        return self._alert_processing_service

    @property
    def secrets(self) -> SecretManagerService:
        """Get secret manager service"""
        if not self._secret_manager_service:
            self._secret_manager_service = SecretManagerService()
        return self._secret_manager_service

    @property
    async def polling_sessions(self) -> PollingSessionService:
        """Get polling session service"""
        if not self._polling_session_service:
            db_manager = await self.get_db_manager()
            self._polling_session_service = PollingSessionService(db_manager)
        return self._polling_session_service

    @property
    async def enhanced_neo4j(self) -> EnhancedNeo4jPopulationService:
        """Get enhanced Neo4j population service"""
        if not self._enhanced_neo4j_service:
            db_manager = await self.get_db_manager()
            self._enhanced_neo4j_service = EnhancedNeo4jPopulationService(db_manager)
        return self._enhanced_neo4j_service

    async def initialize_all_services(self) -> Dict[str, bool]:
        """Initialize all services and return their status"""
        initialization_status = {}

        try:
            # Initialize database manager
            db_manager = await self.get_db_manager()
            initialization_status["database"] = True
            logger.info("Database manager initialized")

            # Initialize XDR configuration service
            self._xdr_config_service = XDRConfigurationService(db_manager)
            initialization_status["xdr_config"] = True
            logger.info("XDR configuration service initialized")

            # Initialize MCP server service
            self._mcp_server_service = MCPServerService(db_manager)
            initialization_status["mcp_servers"] = True
            logger.info("MCP server service initialized")

            # Initialize alert processing service
            self._alert_processing_service = AlertProcessingService(db_manager)
            initialization_status["alert_processing"] = True
            logger.info("Alert processing service initialized")

            # Initialize secret manager service
            self._secret_manager_service = SecretManagerService()
            initialization_status[
                "secrets"
            ] = self._secret_manager_service.is_available()
            if initialization_status["secrets"]:
                logger.info("Secret manager service initialized")
            else:
                logger.warning(
                    "Secret manager service not available (not in Google Cloud)"
                )

            # Initialize polling session service
            self._polling_session_service = PollingSessionService(db_manager)
            initialization_status["polling_sessions"] = True
            logger.info("Polling session service initialized")

            # Initialize enhanced Neo4j population service
            self._enhanced_neo4j_service = EnhancedNeo4jPopulationService(db_manager)
            initialization_status["enhanced_neo4j"] = True
            logger.info("Enhanced Neo4j population service initialized")

            logger.info("All services initialized successfully")
            return initialization_status

        except Exception as e:
            logger.error(f"Error initializing services: {e}")
            initialization_status["error"] = str(e)
            return initialization_status

    async def health_check(self) -> Dict[str, Any]:
        """Perform health check on all services"""
        health_status = {
            "overall_status": "healthy",
            "services": {},
            "timestamp": datetime.now().isoformat(),
        }

        try:
            # Database health check
            db_manager = await self.get_db_manager()
            db_health = await db_manager.health_check()
            health_status["services"]["database"] = {
                "status": "healthy"
                if db_health.get("connected", False)
                else "unhealthy",
                "details": db_health,
            }

            # XDR configuration service health
            if self._xdr_config_service:
                health_status["services"]["xdr_config"] = {"status": "healthy"}
            else:
                health_status["services"]["xdr_config"] = {"status": "not_initialized"}

            # MCP server service health
            if self._mcp_server_service:
                mcp_health = await self._mcp_server_service.get_server_health_summary()
                health_status["services"]["mcp_servers"] = {
                    "status": "healthy",
                    "details": mcp_health,
                }
            else:
                health_status["services"]["mcp_servers"] = {"status": "not_initialized"}

            # Alert processing service health
            if self._alert_processing_service:
                health_status["services"]["alert_processing"] = {"status": "healthy"}
            else:
                health_status["services"]["alert_processing"] = {
                    "status": "not_initialized"
                }

            # Secret manager service health
            if self._secret_manager_service:
                health_status["services"]["secrets"] = {
                    "status": "healthy"
                    if self._secret_manager_service.is_available()
                    else "unavailable",
                    "project_id": self._secret_manager_service.get_project_id(),
                }
            else:
                health_status["services"]["secrets"] = {"status": "not_initialized"}

            # Polling session service health
            if self._polling_session_service:
                active_sessions = (
                    await self._polling_session_service.get_active_sessions()
                )
                health_status["services"]["polling_sessions"] = {
                    "status": "healthy",
                    "active_sessions": len(active_sessions),
                }
            else:
                health_status["services"]["polling_sessions"] = {
                    "status": "not_initialized"
                }

            # Enhanced Neo4j population service health
            if self._enhanced_neo4j_service:
                health_status["services"]["enhanced_neo4j"] = {"status": "healthy"}
            else:
                health_status["services"]["enhanced_neo4j"] = {
                    "status": "not_initialized"
                }

            # Determine overall status
            unhealthy_services = [
                name
                for name, service in health_status["services"].items()
                if service.get("status") in ["unhealthy", "error"]
            ]

            if unhealthy_services:
                health_status["overall_status"] = "degraded"
                health_status["unhealthy_services"] = unhealthy_services

        except Exception as e:
            health_status["overall_status"] = "error"
            health_status["error"] = str(e)
            logger.error(f"Error during health check: {e}")

        return health_status

    async def shutdown_all_services(self) -> None:
        """Gracefully shutdown all services"""
        try:
            logger.info("Shutting down all services...")

            # Close database connections
            if self._db_manager_cache:
                await self._db_manager_cache.close()
                logger.info("Database connections closed")

            # Reset service instances
            self._xdr_config_service = None
            self._mcp_server_service = None
            self._alert_processing_service = None
            self._secret_manager_service = None
            self._polling_session_service = None
            self._enhanced_neo4j_service = None

            logger.info("All services shut down successfully")

        except Exception as e:
            logger.error(f"Error during service shutdown: {e}")
            raise


# Global service coordinator instance
_service_coordinator: Optional[ServiceCoordinator] = None


async def get_service_coordinator() -> ServiceCoordinator:
    """Get the global service coordinator instance"""
    global _service_coordinator
    if not _service_coordinator:
        _service_coordinator = ServiceCoordinator()
        await _service_coordinator.initialize_all_services()
    return _service_coordinator


async def shutdown_services() -> None:
    """Shutdown the global service coordinator"""
    global _service_coordinator
    if _service_coordinator:
        await _service_coordinator.shutdown_all_services()
        _service_coordinator = None
