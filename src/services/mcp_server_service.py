"""
MCP Server Management Service

Focused service for managing MCP server configurations and health monitoring.
Extracted from Neo4jConfigurationService for better separation of concerns.

Author: AI-SOAR Platform Team
Created: 2025-09-18 - Service Decomposition Refactoring
"""

import logging
from datetime import datetime, timezone
from typing import Any, Dict, List, Optional

from neo4j import AsyncSession
from neo4j.exceptions import Neo4jError

from ..config.settings import get_settings
from ..core.exceptions import (ConfigurationException,
                               Neo4jConnectionException, Neo4jQueryException,
                               ValidationException)
from ..core.security import (audit_log, sanitize_cypher_input,
                             validate_input_length)
from ..database.connection import Neo4jDatabaseManager, get_database_manager
from ..database.models import MCPServerConfiguration, create_node_query
from ..web.models.config_models import MCPServerConfigurationCreate

logger = logging.getLogger(__name__)


class MCPServerService:
    """Service for managing MCP server configurations and health monitoring"""

    def __init__(self, db_manager: Neo4jDatabaseManager = None):
        self.db_manager = db_manager
        self._db_manager_cache = None
        self.settings = get_settings()

    async def get_db_manager(self) -> Neo4jDatabaseManager:
        """Get database manager instance with proper error handling"""
        try:
            if self.db_manager:
                return self.db_manager
            if not self._db_manager_cache:
                self._db_manager_cache = await get_database_manager()
            return self._db_manager_cache
        except Exception as e:
            logger.error(f"Failed to get database manager: {e}")
            raise Neo4jConnectionException(
                "Failed to connect to Neo4j database",
                error_code="DB_CONNECTION_FAILED",
                details={"original_error": str(e)},
            )

    async def create_mcp_server(
        self, server_data: MCPServerConfigurationCreate
    ) -> MCPServerConfiguration:
        """Create a new MCP server configuration"""
        try:
            # Input validation and sanitization
            server_name = validate_input_length(server_data.name, 255, "server_name")
            server_name = sanitize_cypher_input(server_name)

            server_type = validate_input_length(
                server_data.server_type, 100, "server_type"
            )
            server_type = sanitize_cypher_input(server_type)

            # Create server configuration
            mcp_server = MCPServerConfiguration(
                name=server_name,
                server_type=server_type,
                base_url=str(server_data.base_url),
                enabled=server_data.enabled,
                priority=server_data.priority,
                timeout=server_data.timeout,
                auth_config=server_data.auth_config or {},
                alert_filters=server_data.alert_filters or {},
                processing_config=server_data.processing_config or {},
                status="active",
                health_status="unknown",
            )

            # Store in Neo4j
            db_manager = await self.get_db_manager()
            query, params = create_node_query(
                mcp_server, ["MCPServerConfiguration", "Configuration"]
            )

            async with db_manager.get_session() as session:
                result = await session.run(query, params)
                created_node = await result.single()

                if not created_node:
                    raise Neo4jQueryException(
                        "Failed to create MCP server configuration node"
                    )

                # Audit log
                await audit_log(
                    action="CREATE_MCP_SERVER",
                    resource_id=mcp_server.id,
                    details={
                        "name": server_name,
                        "server_type": server_type,
                        "base_url": mcp_server.base_url,
                    },
                    session=session,
                )

                logger.info(f"Created MCP server configuration: {mcp_server.id}")
                return mcp_server

        except ValidationException:
            raise
        except Neo4jError as e:
            logger.error(f"Neo4j error creating MCP server: {e}")
            raise Neo4jQueryException(
                "Database error creating MCP server configuration",
                error_code="CREATE_MCP_SERVER_FAILED",
                details={"neo4j_error": str(e)},
            )
        except Exception as e:
            logger.error(f"Unexpected error creating MCP server: {e}")
            raise ConfigurationException(
                "Failed to create MCP server configuration",
                error_code="MCP_SERVER_CREATE_ERROR",
                details={"error": str(e)},
            )

    async def get_mcp_server(self, server_id: str) -> Optional[MCPServerConfiguration]:
        """Retrieve MCP server configuration by ID"""
        try:
            server_id = sanitize_cypher_input(server_id)
            db_manager = await self.get_db_manager()

            query = """
            MATCH (server:MCPServerConfiguration {id: $server_id})
            RETURN server
            """

            async with db_manager.get_session() as session:
                result = await session.run(query, {"server_id": server_id})
                record = await result.single()

                if not record:
                    return None

                server_data = record["server"]
                return MCPServerConfiguration(**server_data)

        except Neo4jError as e:
            logger.error(f"Neo4j error retrieving MCP server {server_id}: {e}")
            raise Neo4jQueryException(
                "Database error retrieving MCP server configuration",
                error_code="GET_MCP_SERVER_FAILED",
                details={"server_id": server_id, "neo4j_error": str(e)},
            )
        except Exception as e:
            logger.error(f"Unexpected error retrieving MCP server {server_id}: {e}")
            raise ConfigurationException(
                "Failed to retrieve MCP server configuration",
                error_code="MCP_SERVER_RETRIEVE_ERROR",
                details={"server_id": server_id, "error": str(e)},
            )

    async def list_mcp_servers(
        self,
        server_type: Optional[str] = None,
        enabled_only: bool = False,
        limit: int = 100,
        offset: int = 0,
    ) -> List[MCPServerConfiguration]:
        """List MCP server configurations with optional filtering"""
        try:
            db_manager = await self.get_db_manager()

            # Build filter conditions
            where_conditions = []
            params = {"limit": limit, "offset": offset}

            if server_type:
                where_conditions.append("server.server_type = $server_type")
                params["server_type"] = sanitize_cypher_input(server_type)

            if enabled_only:
                where_conditions.append("server.enabled = true")

            where_clause = (
                f"WHERE {' AND '.join(where_conditions)}" if where_conditions else ""
            )

            query = f"""
            MATCH (server:MCPServerConfiguration)
            {where_clause}
            RETURN server
            ORDER BY server.priority ASC, server.created_at DESC
            SKIP $offset
            LIMIT $limit
            """

            async with db_manager.get_session() as session:
                result = await session.run(query, params)
                servers = []

                async for record in result:
                    server_data = record["server"]
                    servers.append(MCPServerConfiguration(**server_data))

                logger.debug(f"Retrieved {len(servers)} MCP server configurations")
                return servers

        except Neo4jError as e:
            logger.error(f"Neo4j error listing MCP servers: {e}")
            raise Neo4jQueryException(
                "Database error listing MCP server configurations",
                error_code="LIST_MCP_SERVERS_FAILED",
                details={"neo4j_error": str(e)},
            )
        except Exception as e:
            logger.error(f"Unexpected error listing MCP servers: {e}")
            raise ConfigurationException(
                "Failed to list MCP server configurations",
                error_code="MCP_SERVER_LIST_ERROR",
                details={"error": str(e)},
            )

    async def update_mcp_server_health(
        self,
        server_id: str,
        health_status: str,
        health_details: Optional[Dict[str, Any]] = None,
    ) -> bool:
        """Update MCP server health status"""
        try:
            server_id = sanitize_cypher_input(server_id)
            health_status = sanitize_cypher_input(health_status)

            db_manager = await self.get_db_manager()
            update_params = {
                "server_id": server_id,
                "health_status": health_status,
                "last_health_check": datetime.now(timezone.utc).isoformat(),
                "updated_at": datetime.now(timezone.utc).isoformat(),
            }

            query = """
            MATCH (server:MCPServerConfiguration {id: $server_id})
            SET server.health_status = $health_status,
                server.last_health_check = $last_health_check,
                server.updated_at = $updated_at
            RETURN server
            """

            async with db_manager.get_session() as session:
                result = await session.run(query, update_params)
                updated_record = await result.single()

                if not updated_record:
                    logger.warning(
                        f"MCP server not found for health update: {server_id}"
                    )
                    return False

                # Audit log for health changes
                await audit_log(
                    action="UPDATE_MCP_SERVER_HEALTH",
                    resource_id=server_id,
                    details={
                        "health_status": health_status,
                        "health_details": health_details,
                    },
                    session=session,
                )

                logger.debug(
                    f"Updated MCP server health: {server_id} -> {health_status}"
                )
                return True

        except Neo4jError as e:
            logger.error(f"Neo4j error updating MCP server health {server_id}: {e}")
            raise Neo4jQueryException(
                "Database error updating MCP server health",
                error_code="UPDATE_MCP_HEALTH_FAILED",
                details={"server_id": server_id, "neo4j_error": str(e)},
            )
        except Exception as e:
            logger.error(
                f"Unexpected error updating MCP server health {server_id}: {e}"
            )
            raise ConfigurationException(
                "Failed to update MCP server health",
                error_code="MCP_HEALTH_UPDATE_ERROR",
                details={"server_id": server_id, "error": str(e)},
            )

    async def enable_mcp_server(self, server_id: str) -> bool:
        """Enable an MCP server configuration"""
        return await self._toggle_mcp_server(server_id, True)

    async def disable_mcp_server(self, server_id: str) -> bool:
        """Disable an MCP server configuration"""
        return await self._toggle_mcp_server(server_id, False)

    async def _toggle_mcp_server(self, server_id: str, enabled: bool) -> bool:
        """Toggle MCP server enabled status"""
        try:
            server_id = sanitize_cypher_input(server_id)
            db_manager = await self.get_db_manager()

            query = """
            MATCH (server:MCPServerConfiguration {id: $server_id})
            SET server.enabled = $enabled,
                server.updated_at = $updated_at
            RETURN server
            """

            async with db_manager.get_session() as session:
                result = await session.run(
                    query,
                    {
                        "server_id": server_id,
                        "enabled": enabled,
                        "updated_at": datetime.now(timezone.utc).isoformat(),
                    },
                )
                updated_record = await result.single()

                if not updated_record:
                    return False

                # Audit log
                action = "ENABLE_MCP_SERVER" if enabled else "DISABLE_MCP_SERVER"
                await audit_log(
                    action=action,
                    resource_id=server_id,
                    details={"enabled": enabled},
                    session=session,
                )

                logger.info(
                    f"{'Enabled' if enabled else 'Disabled'} MCP server: {server_id}"
                )
                return True

        except Neo4jError as e:
            logger.error(f"Neo4j error toggling MCP server {server_id}: {e}")
            raise Neo4jQueryException(
                "Database error toggling MCP server",
                error_code="TOGGLE_MCP_SERVER_FAILED",
                details={"server_id": server_id, "neo4j_error": str(e)},
            )
        except Exception as e:
            logger.error(f"Unexpected error toggling MCP server {server_id}: {e}")
            raise ConfigurationException(
                "Failed to toggle MCP server",
                error_code="MCP_SERVER_TOGGLE_ERROR",
                details={"server_id": server_id, "error": str(e)},
            )

    async def delete_mcp_server(self, server_id: str) -> bool:
        """Delete MCP server configuration"""
        try:
            server_id = sanitize_cypher_input(server_id)
            db_manager = await self.get_db_manager()

            query = """
            MATCH (server:MCPServerConfiguration {id: $server_id})
            OPTIONAL MATCH (server)-[r]-()
            DELETE r, server
            RETURN count(server) as deleted_count
            """

            async with db_manager.get_session() as session:
                result = await session.run(query, {"server_id": server_id})
                deletion_result = await result.single()

                deleted_count = deletion_result["deleted_count"]
                if deleted_count == 0:
                    return False

                # Audit log
                await audit_log(
                    action="DELETE_MCP_SERVER",
                    resource_id=server_id,
                    details={"deleted": True},
                    session=session,
                )

                logger.info(f"Deleted MCP server configuration: {server_id}")
                return True

        except Neo4jError as e:
            logger.error(f"Neo4j error deleting MCP server {server_id}: {e}")
            raise Neo4jQueryException(
                "Database error deleting MCP server",
                error_code="DELETE_MCP_SERVER_FAILED",
                details={"server_id": server_id, "neo4j_error": str(e)},
            )
        except Exception as e:
            logger.error(f"Unexpected error deleting MCP server {server_id}: {e}")
            raise ConfigurationException(
                "Failed to delete MCP server",
                error_code="MCP_SERVER_DELETE_ERROR",
                details={"server_id": server_id, "error": str(e)},
            )

    async def get_servers_by_type(
        self, server_type: str
    ) -> List[MCPServerConfiguration]:
        """Get all enabled MCP servers of a specific type"""
        try:
            server_type = sanitize_cypher_input(server_type)
            return await self.list_mcp_servers(
                server_type=server_type, enabled_only=True
            )
        except Exception as e:
            logger.error(f"Error getting MCP servers by type {server_type}: {e}")
            raise ConfigurationException(
                f"Failed to get MCP servers of type {server_type}",
                error_code="GET_SERVERS_BY_TYPE_ERROR",
                details={"server_type": server_type, "error": str(e)},
            )

    async def get_server_health_summary(self) -> Dict[str, Any]:
        """Get health summary for all MCP servers"""
        try:
            db_manager = await self.get_db_manager()

            query = """
            MATCH (server:MCPServerConfiguration)
            RETURN
                count(server) as total_servers,
                sum(CASE WHEN server.enabled = true THEN 1 ELSE 0 END) as enabled_servers,
                sum(CASE WHEN server.health_status = 'healthy' THEN 1 ELSE 0 END) as healthy_servers,
                sum(CASE WHEN server.health_status = 'degraded' THEN 1 ELSE 0 END) as degraded_servers,
                sum(CASE WHEN server.health_status = 'offline' THEN 1 ELSE 0 END) as offline_servers,
                collect(DISTINCT server.server_type) as server_types
            """

            async with db_manager.get_session() as session:
                result = await session.run(query)
                summary = await result.single()

                return {
                    "total_servers": summary["total_servers"] or 0,
                    "enabled_servers": summary["enabled_servers"] or 0,
                    "healthy_servers": summary["healthy_servers"] or 0,
                    "degraded_servers": summary["degraded_servers"] or 0,
                    "offline_servers": summary["offline_servers"] or 0,
                    "server_types": summary["server_types"] or [],
                }

        except Neo4jError as e:
            logger.error(f"Neo4j error getting MCP server health summary: {e}")
            raise Neo4jQueryException(
                "Database error getting server health summary",
                error_code="GET_HEALTH_SUMMARY_FAILED",
                details={"neo4j_error": str(e)},
            )
        except Exception as e:
            logger.error(f"Unexpected error getting MCP server health summary: {e}")
            raise ConfigurationException(
                "Failed to get server health summary",
                error_code="HEALTH_SUMMARY_ERROR",
                details={"error": str(e)},
            )
