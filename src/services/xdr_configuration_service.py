"""
XDR Configuration Management Service

Focused service for managing XDR system configurations and connections.
Extracted from Neo4jConfigurationService for better separation of concerns.

Author: AI-SOAR Platform Team
Created: 2025-09-18 - Service Decomposition Refactoring
"""

import logging
from datetime import datetime, timezone
from typing import Any, Dict, List, Optional
from uuid import UUID

from neo4j import AsyncSession
from neo4j.exceptions import Neo4jError

from ..client.xdr_alert_client import XDRAlertClient, XDRConfig
from ..config.settings import get_settings
from ..core.exceptions import (ConfigurationException,
                               Neo4jConnectionException, Neo4jQueryException,
                               ValidationException, XDRConnectionException)
from ..core.security import (audit_log, sanitize_cypher_input,
                             validate_input_length)
from ..database.connection import Neo4jDatabaseManager, get_database_manager
from ..database.models import (ConfigurationStatus, EnvironmentType,
                               XDRConfiguration, create_node_query)
from ..web.models.config_models import (XDRConfigurationCreate,
                                        XDRConfigurationUpdate)

logger = logging.getLogger(__name__)


class XDRConfigurationService:
    """Service for managing XDR system configurations"""

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

    async def create_xdr_configuration(
        self, config_data: XDRConfigurationCreate
    ) -> XDRConfiguration:
        """Create a new XDR configuration node with security validation"""
        try:
            # Input validation and sanitization
            config_name = validate_input_length(
                config_data.name, 255, "configuration_name"
            )
            config_name = sanitize_cypher_input(config_name)

            description = None
            if config_data.description:
                description = validate_input_length(
                    config_data.description, 1000, "description"
                )
                description = sanitize_cypher_input(description)

            # Create configuration node
            configuration = XDRConfiguration(
                name=config_name,
                description=description,
                base_url=str(config_data.base_url),
                auth_token_secret_name=config_data.auth_token_secret_name,
                poll_interval=config_data.poll_interval,
                poll_enabled=config_data.poll_enabled,
                max_alerts_per_poll=config_data.max_alerts_per_poll,
                severity_filter=config_data.severity_filter,
                entity_types=config_data.entity_types or {},
                status=ConfigurationStatus.INACTIVE,
                environment=config_data.environment or EnvironmentType.DEVELOPMENT,
            )

            # Store in Neo4j
            db_manager = await self.get_db_manager()
            query, params = create_node_query(
                configuration, ["XDRConfiguration", "Configuration"]
            )

            async with db_manager.get_session() as session:
                result = await session.run(query, params)
                created_node = await result.single()

                if not created_node:
                    raise Neo4jQueryException("Failed to create XDR configuration node")

                # Audit log
                await audit_log(
                    action="CREATE_XDR_CONFIGURATION",
                    resource_id=configuration.id,
                    details={"name": config_name, "base_url": configuration.base_url},
                    session=session,
                )

                logger.info(f"Created XDR configuration: {configuration.id}")
                return configuration

        except ValidationException:
            raise
        except Neo4jError as e:
            logger.error(f"Neo4j error creating XDR configuration: {e}")
            raise Neo4jQueryException(
                "Database error creating XDR configuration",
                error_code="CREATE_CONFIG_FAILED",
                details={"neo4j_error": str(e)},
            )
        except Exception as e:
            logger.error(f"Unexpected error creating XDR configuration: {e}")
            raise ConfigurationException(
                "Failed to create XDR configuration",
                error_code="CONFIG_CREATE_ERROR",
                details={"error": str(e)},
            )

    async def get_xdr_configuration(self, config_id: str) -> Optional[XDRConfiguration]:
        """Retrieve XDR configuration by ID"""
        try:
            config_id = sanitize_cypher_input(config_id)
            db_manager = await self.get_db_manager()

            query = """
            MATCH (config:XDRConfiguration {id: $config_id})
            RETURN config
            """

            async with db_manager.get_session() as session:
                result = await session.run(query, {"config_id": config_id})
                record = await result.single()

                if not record:
                    return None

                config_data = record["config"]
                return XDRConfiguration(**config_data)

        except Neo4jError as e:
            logger.error(f"Neo4j error retrieving XDR configuration {config_id}: {e}")
            raise Neo4jQueryException(
                "Database error retrieving XDR configuration",
                error_code="GET_CONFIG_FAILED",
                details={"config_id": config_id, "neo4j_error": str(e)},
            )
        except Exception as e:
            logger.error(
                f"Unexpected error retrieving XDR configuration {config_id}: {e}"
            )
            raise ConfigurationException(
                "Failed to retrieve XDR configuration",
                error_code="CONFIG_RETRIEVE_ERROR",
                details={"config_id": config_id, "error": str(e)},
            )

    async def update_xdr_configuration(
        self, config_id: str, update_data: XDRConfigurationUpdate
    ) -> XDRConfiguration:
        """Update XDR configuration with validation"""
        try:
            config_id = sanitize_cypher_input(config_id)

            # Build update parameters
            update_params = {
                "config_id": config_id,
                "updated_at": datetime.now(timezone.utc).isoformat(),
            }
            set_clauses = ["config.updated_at = $updated_at"]

            if update_data.name is not None:
                name = validate_input_length(
                    update_data.name, 255, "configuration_name"
                )
                name = sanitize_cypher_input(name)
                update_params["name"] = name
                set_clauses.append("config.name = $name")

            if update_data.description is not None:
                description = validate_input_length(
                    update_data.description, 1000, "description"
                )
                description = sanitize_cypher_input(description)
                update_params["description"] = description
                set_clauses.append("config.description = $description")

            if update_data.base_url is not None:
                update_params["base_url"] = str(update_data.base_url)
                set_clauses.append("config.base_url = $base_url")

            if update_data.poll_interval is not None:
                update_params["poll_interval"] = update_data.poll_interval
                set_clauses.append("config.poll_interval = $poll_interval")

            if update_data.poll_enabled is not None:
                update_params["poll_enabled"] = update_data.poll_enabled
                set_clauses.append("config.poll_enabled = $poll_enabled")

            if update_data.status is not None:
                update_params["status"] = update_data.status.value
                set_clauses.append("config.status = $status")

            # Execute update
            db_manager = await self.get_db_manager()
            query = f"""
            MATCH (config:XDRConfiguration {{id: $config_id}})
            SET {', '.join(set_clauses)}
            RETURN config
            """

            async with db_manager.get_session() as session:
                result = await session.run(query, update_params)
                updated_record = await result.single()

                if not updated_record:
                    raise ConfigurationException(
                        f"XDR configuration not found: {config_id}",
                        error_code="CONFIG_NOT_FOUND",
                    )

                # Audit log
                await audit_log(
                    action="UPDATE_XDR_CONFIGURATION",
                    resource_id=config_id,
                    details={"updated_fields": list(update_params.keys())},
                    session=session,
                )

                config_data = updated_record["config"]
                logger.info(f"Updated XDR configuration: {config_id}")
                return XDRConfiguration(**config_data)

        except ValidationException:
            raise
        except Neo4jError as e:
            logger.error(f"Neo4j error updating XDR configuration {config_id}: {e}")
            raise Neo4jQueryException(
                "Database error updating XDR configuration",
                error_code="UPDATE_CONFIG_FAILED",
                details={"config_id": config_id, "neo4j_error": str(e)},
            )
        except Exception as e:
            logger.error(
                f"Unexpected error updating XDR configuration {config_id}: {e}"
            )
            raise ConfigurationException(
                "Failed to update XDR configuration",
                error_code="CONFIG_UPDATE_ERROR",
                details={"config_id": config_id, "error": str(e)},
            )

    async def delete_xdr_configuration(self, config_id: str) -> bool:
        """Delete XDR configuration and related data"""
        try:
            config_id = sanitize_cypher_input(config_id)
            db_manager = await self.get_db_manager()

            query = """
            MATCH (config:XDRConfiguration {id: $config_id})
            OPTIONAL MATCH (config)-[r]-()
            DELETE r, config
            RETURN count(config) as deleted_count
            """

            async with db_manager.get_session() as session:
                result = await session.run(query, {"config_id": config_id})
                deletion_result = await result.single()

                deleted_count = deletion_result["deleted_count"]
                if deleted_count == 0:
                    return False

                # Audit log
                await audit_log(
                    action="DELETE_XDR_CONFIGURATION",
                    resource_id=config_id,
                    details={"deleted": True},
                    session=session,
                )

                logger.info(f"Deleted XDR configuration: {config_id}")
                return True

        except Neo4jError as e:
            logger.error(f"Neo4j error deleting XDR configuration {config_id}: {e}")
            raise Neo4jQueryException(
                "Database error deleting XDR configuration",
                error_code="DELETE_CONFIG_FAILED",
                details={"config_id": config_id, "neo4j_error": str(e)},
            )
        except Exception as e:
            logger.error(
                f"Unexpected error deleting XDR configuration {config_id}: {e}"
            )
            raise ConfigurationException(
                "Failed to delete XDR configuration",
                error_code="CONFIG_DELETE_ERROR",
                details={"config_id": config_id, "error": str(e)},
            )

    async def list_xdr_configurations(
        self,
        environment: Optional[EnvironmentType] = None,
        status: Optional[ConfigurationStatus] = None,
        limit: int = 100,
        offset: int = 0,
    ) -> List[XDRConfiguration]:
        """List XDR configurations with optional filtering"""
        try:
            db_manager = await self.get_db_manager()

            # Build filter conditions
            where_conditions = []
            params = {"limit": limit, "offset": offset}

            if environment:
                where_conditions.append("config.environment = $environment")
                params["environment"] = environment.value

            if status:
                where_conditions.append("config.status = $status")
                params["status"] = status.value

            where_clause = (
                f"WHERE {' AND '.join(where_conditions)}" if where_conditions else ""
            )

            query = f"""
            MATCH (config:XDRConfiguration)
            {where_clause}
            RETURN config
            ORDER BY config.created_at DESC
            SKIP $offset
            LIMIT $limit
            """

            async with db_manager.get_session() as session:
                result = await session.run(query, params)
                configurations = []

                async for record in result:
                    config_data = record["config"]
                    configurations.append(XDRConfiguration(**config_data))

                logger.debug(f"Retrieved {len(configurations)} XDR configurations")
                return configurations

        except Neo4jError as e:
            logger.error(f"Neo4j error listing XDR configurations: {e}")
            raise Neo4jQueryException(
                "Database error listing XDR configurations",
                error_code="LIST_CONFIGS_FAILED",
                details={"neo4j_error": str(e)},
            )
        except Exception as e:
            logger.error(f"Unexpected error listing XDR configurations: {e}")
            raise ConfigurationException(
                "Failed to list XDR configurations",
                error_code="CONFIG_LIST_ERROR",
                details={"error": str(e)},
            )

    async def test_xdr_connection(self, config_id: str) -> Dict[str, Any]:
        """Test XDR API connection for a configuration"""
        try:
            # Get configuration
            configuration = await self.get_xdr_configuration(config_id)
            if not configuration:
                raise ConfigurationException(
                    f"XDR configuration not found: {config_id}",
                    error_code="CONFIG_NOT_FOUND",
                )

            # Create XDR client config (without real auth token for testing)
            xdr_config = XDRConfig(
                base_url=configuration.base_url,
                auth_token="test-token",  # Use test token
                timeout=30,
                poll_interval=configuration.poll_interval,
            )

            # Test connection
            async with XDRAlertClient(xdr_config) as client:
                try:
                    # Attempt to make a test request
                    test_result = await client.get_all_alerts(page_limit=1)

                    # Update configuration status to active
                    await self.update_xdr_configuration(
                        config_id,
                        XDRConfigurationUpdate(status=ConfigurationStatus.ACTIVE),
                    )

                    return {
                        "success": True,
                        "message": "XDR connection successful",
                        "response_data": test_result.get("meta", {}),
                    }

                except Exception as e:
                    # Update configuration status to error
                    await self.update_xdr_configuration(
                        config_id,
                        XDRConfigurationUpdate(status=ConfigurationStatus.ERROR),
                    )

                    raise XDRConnectionException(
                        f"XDR connection test failed: {str(e)}",
                        error_code="XDR_CONNECTION_FAILED",
                        details={"config_id": config_id, "error": str(e)},
                    )

        except ConfigurationException:
            raise
        except XDRConnectionException:
            raise
        except Exception as e:
            logger.error(f"Unexpected error testing XDR connection {config_id}: {e}")
            raise ConfigurationException(
                "Failed to test XDR connection",
                error_code="XDR_TEST_ERROR",
                details={"config_id": config_id, "error": str(e)},
            )
