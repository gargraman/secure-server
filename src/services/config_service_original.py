"""
Neo4j Configuration Management Service

Service layer for managing XDR configurations, MCP server settings, and system
configurations using Neo4j graph database with Google Cloud Secret Manager integration.
Refactored from SQLAlchemy to use Cypher queries for enhanced graph-based operations.

Author: AI-SOAR Platform Team
Created: 2025-09-10
Refactored: 2025-09-10 - Migrated from PostgreSQL to Neo4j
"""

import logging
from datetime import datetime, timezone
from typing import Any, Dict, List, Optional
from uuid import UUID

from google.cloud import secretmanager
from google.cloud.exceptions import GoogleCloudError
from neo4j import AsyncSession
from neo4j.exceptions import Neo4jError

from ..client.xdr_alert_client import XDRAlertClient, XDRConfig
from ..config.settings import get_settings
from ..core.exceptions import (ConfigurationException,
                               Neo4jConnectionException, Neo4jQueryException,
                               SecretManagerException, ValidationException,
                               XDRConnectionException)
from ..core.security import (audit_log, sanitize_cypher_input,
                             validate_input_length)
from ..database.connection import Neo4jDatabaseManager, get_database_manager
from ..database.models import (Alert, ConfigurationStatus,
                               MCPServerConfiguration, PollingSession,
                               Relationship, SystemConfiguration,
                               XDRConfiguration, create_node_query,
                               create_relationship_query)
from ..web.models.config_models import (MCPServerConfigurationCreate,
                                        SystemConfigurationCreate,
                                        XDRConfigurationCreate,
                                        XDRConfigurationUpdate)

logger = logging.getLogger(__name__)


class Neo4jConfigurationService:
    """Neo4j-based service for managing platform configurations"""

    def __init__(self, db_manager: Neo4jDatabaseManager = None):
        self.db_manager = db_manager
        self._db_manager_cache = None
        self.settings = get_settings()
        self.secret_client = None

        # Initialize Secret Manager client if in Google Cloud
        if self.settings.google_cloud_project:
            try:
                self.secret_client = secretmanager.SecretManagerServiceClient()
            except Exception as e:
                logger.warning(f"Failed to initialize Secret Manager client: {e}")

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

            if config_data.description:
                description = validate_input_length(
                    config_data.description, 1000, "description"
                )
                description = sanitize_cypher_input(description)
            else:
                description = None

            # Validate auth token secret exists
            if self.secret_client:
                await self._validate_secret_exists(config_data.auth_token_secret_name)

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
                entity_types=config_data.entity_types.dict()
                if config_data.entity_types
                else {},
                environment=config_data.environment,
                status=ConfigurationStatus.PENDING,
            )

            # Create Cypher query
            query, parameters = create_node_query(
                configuration, ["XDRConfiguration", "Configuration"]
            )

            # Execute query
            db_manager = await self.get_db_manager()
            async with db_manager.get_session() as session:
                result = await session.run(query, parameters)
                created_record = await result.single()

                if not created_record:
                    raise Exception("Failed to create XDR configuration node")

                # Convert back to object
                node_data = dict(created_record["n"])
                configuration.id = node_data["id"]

            # Test configuration and update status
            await self._test_and_update_configuration_status(configuration)

            # Audit log
            audit_log(
                action="CREATE_XDR_CONFIGURATION",
                resource=f"xdr_config:{configuration.id}",
                details={
                    "configuration_name": configuration.name,
                    "environment": configuration.environment.value
                    if configuration.environment
                    else None,
                    "poll_enabled": configuration.poll_enabled,
                },
            )

            logger.info(f"Created XDR configuration: {configuration.name}")
            return configuration

        except Neo4jError as e:
            logger.error(f"Neo4j error creating XDR configuration: {e}")
            raise Neo4jQueryException(
                "Failed to create XDR configuration in database",
                error_code="CREATE_CONFIG_FAILED",
                details={"configuration_name": config_data.name, "neo4j_error": str(e)},
            )
        except SecretManagerException:
            raise  # Re-raise SecretManager exceptions as-is
        except Exception as e:
            logger.error(f"Unexpected error creating XDR configuration: {e}")
            raise ConfigurationException(
                "Failed to create XDR configuration",
                error_code="CONFIG_CREATE_ERROR",
                details={"configuration_name": config_data.name, "error": str(e)},
            )

    async def update_xdr_configuration(
        self, configuration_id: str, config_data: XDRConfigurationUpdate
    ) -> Optional[XDRConfiguration]:
        """Update an existing XDR configuration node"""
        try:
            # Get existing configuration
            configuration = await self.get_xdr_configuration(configuration_id)
            if not configuration:
                return None

            # Prepare update data
            update_data = config_data.dict(exclude_unset=True)
            if "base_url" in update_data:
                update_data["base_url"] = str(update_data["base_url"])
            if "entity_types" in update_data and update_data["entity_types"]:
                update_data["entity_types"] = update_data["entity_types"].dict()

            # Add updated timestamp
            update_data["updated_at"] = datetime.now(timezone.utc).isoformat()

            # Build SET clauses for Cypher
            set_clauses = []
            for key, value in update_data.items():
                set_clauses.append(f"n.{key} = ${key}")

            query = f"""
            MATCH (n:XDRConfiguration {{id: $configuration_id}})
            SET {', '.join(set_clauses)}
            RETURN n
            """

            parameters = {"configuration_id": configuration_id, **update_data}

            # Execute update
            db_manager = await self.get_db_manager()
            async with db_manager.get_session() as session:
                result = await session.run(query, parameters)
                updated_record = await result.single()

                if not updated_record:
                    return None

                # Convert back to object
                node_data = dict(updated_record["n"])
                updated_config = XDRConfiguration(
                    **{
                        k: v
                        for k, v in node_data.items()
                        if k in XDRConfiguration.__dataclass_fields__
                    }
                )

            # Test updated configuration
            await self._test_and_update_configuration_status(updated_config)

            logger.info(f"Updated XDR configuration: {updated_config.name}")
            return updated_config

        except Exception as e:
            logger.error(f"Failed to update XDR configuration {configuration_id}: {e}")
            raise

    async def delete_xdr_configuration(
        self, configuration_id: str, force: bool = False
    ) -> bool:
        """Delete an XDR configuration node and its relationships"""
        try:
            # Check if polling is active unless force is specified
            if not force:
                active_session_query = """
                MATCH (ps:PollingSession {configuration_id: $configuration_id, status: 'active'})
                RETURN ps
                """

                db_manager = await self.get_db_manager()
            async with db_manager.get_session() as session:
                result = await session.run(
                    active_session_query, {"configuration_id": configuration_id}
                )
                active_session = await result.single()

                if active_session:
                    raise ValueError(
                        "Cannot delete configuration with active polling session. Stop polling first or use force=True."
                    )

            # Delete configuration and all related nodes/relationships
            delete_query = """
            MATCH (config:XDRConfiguration {id: $configuration_id})
            OPTIONAL MATCH (config)<-[r1:CONFIGURED_BY]-(ps:PollingSession)
            OPTIONAL MATCH (config)<-[r2:USES_CONFIG]-(alert:Alert)
            DETACH DELETE config, ps
            RETURN count(config) as deleted_count
            """

            db_manager = await self.get_db_manager()
            async with db_manager.get_session() as session:
                result = await session.run(
                    delete_query, {"configuration_id": configuration_id}
                )
                delete_result = await result.single()

                deleted_count = delete_result["deleted_count"]
                if deleted_count == 0:
                    return False

            logger.info(f"Deleted XDR configuration: {configuration_id}")
            return True

        except Exception as e:
            logger.error(f"Failed to delete XDR configuration {configuration_id}: {e}")
            raise

    async def get_xdr_configuration(
        self, configuration_id: str
    ) -> Optional[XDRConfiguration]:
        """Get XDR configuration by ID"""
        try:
            query = """
            MATCH (config:XDRConfiguration {id: $configuration_id})
            RETURN config
            """

            db_manager = await self.get_db_manager()
            async with db_manager.get_session() as session:
                result = await session.run(
                    query, {"configuration_id": configuration_id}
                )
                record = await result.single()

                if not record:
                    return None

                # Convert to XDRConfiguration object
                node_data = dict(record["config"])
                return XDRConfiguration(
                    **{
                        k: v
                        for k, v in node_data.items()
                        if k in XDRConfiguration.__dataclass_fields__
                    }
                )

        except Exception as e:
            logger.error(f"Failed to get XDR configuration {configuration_id}: {e}")
            return None

    async def list_xdr_configurations(
        self,
        environment: Optional[str] = None,
        status: Optional[str] = None,
        poll_enabled: Optional[bool] = None,
        limit: int = 100,
        offset: int = 0,
    ) -> List[XDRConfiguration]:
        """List XDR configurations with optional filters"""
        try:
            # Build WHERE clauses
            where_clauses = []
            parameters = {"limit": limit, "offset": offset}

            if environment:
                where_clauses.append("config.environment = $environment")
                parameters["environment"] = environment

            if status:
                where_clauses.append("config.status = $status")
                parameters["status"] = status

            if poll_enabled is not None:
                where_clauses.append("config.poll_enabled = $poll_enabled")
                parameters["poll_enabled"] = poll_enabled

            where_clause = (
                "WHERE " + " AND ".join(where_clauses) if where_clauses else ""
            )

            query = f"""
            MATCH (config:XDRConfiguration)
            {where_clause}
            RETURN config
            ORDER BY config.created_at DESC
            SKIP $offset
            LIMIT $limit
            """

            configurations = []
            db_manager = await self.get_db_manager()
            async with db_manager.get_session() as session:
                result = await session.run(query, parameters)
                async for record in result:
                    node_data = dict(record["config"])
                    config = XDRConfiguration(
                        **{
                            k: v
                            for k, v in node_data.items()
                            if k in XDRConfiguration.__dataclass_fields__
                        }
                    )
                    configurations.append(config)

            return configurations

        except Exception as e:
            logger.error(f"Failed to list XDR configurations: {e}")
            return []

    async def start_polling_session(
        self, configuration_id: str, override_interval: Optional[int] = None
    ) -> PollingSession:
        """Start a polling session for a configuration"""
        try:
            # Get and validate configuration
            configuration = await self.get_xdr_configuration(configuration_id)
            if not configuration:
                raise ValueError("Configuration not found")

            if configuration.status != ConfigurationStatus.ACTIVE:
                raise ValueError("Configuration must be active to start polling")

            # Check if already polling
            existing_session_query = """
            MATCH (ps:PollingSession {configuration_id: $configuration_id, status: 'active'})
            RETURN ps
            """

            db_manager = await self.get_db_manager()
            async with db_manager.get_session() as session:
                result = await session.run(
                    existing_session_query, {"configuration_id": configuration_id}
                )
                existing_session = await result.single()

                if existing_session:
                    raise ValueError(
                        "Polling session already active for this configuration"
                    )

                # Create new polling session
                session_node = PollingSession(
                    configuration_id=configuration_id, status="active"
                )

                # Create session node and relationship
                session_query, session_params = create_node_query(
                    session_node, ["PollingSession"]
                )
                session_result = await session.run(session_query, session_params)
                session_record = await session_result.single()

                if not session_record:
                    raise Exception("Failed to create polling session")

                # Create relationship to configuration
                rel_query = """
                MATCH (ps:PollingSession {id: $session_id})
                MATCH (config:XDRConfiguration {id: $configuration_id})
                CREATE (ps)-[:CONFIGURED_BY]->(config)
                """

                await session.run(
                    rel_query,
                    {
                        "session_id": session_node.id,
                        "configuration_id": configuration_id,
                    },
                )

                # Update configuration polling status
                update_config_query = """
                MATCH (config:XDRConfiguration {id: $configuration_id})
                SET config.poll_enabled = true
                """
                if override_interval:
                    update_config_query += ", config.poll_interval = $poll_interval"
                    session_params["poll_interval"] = override_interval

                session_params["configuration_id"] = configuration_id
                await session.run(update_config_query, session_params)

            logger.info(
                f"Started polling session for configuration: {configuration.name}"
            )
            return session_node

        except Exception as e:
            logger.error(f"Failed to start polling session for {configuration_id}: {e}")
            raise

    async def stop_polling_session(
        self, configuration_id: str, force_stop: bool = False
    ) -> bool:
        """Stop active polling session for a configuration"""
        try:
            db_manager = await self.get_db_manager()
            async with db_manager.get_session() as session:
                # Update session and configuration
                stop_query = """
                MATCH (ps:PollingSession {configuration_id: $configuration_id, status: 'active'})
                MATCH (config:XDRConfiguration {id: $configuration_id})
                SET ps.status = 'stopped',
                    ps.session_end = $end_time,
                    config.poll_enabled = false
                RETURN ps
                """

                result = await session.run(
                    stop_query,
                    {
                        "configuration_id": configuration_id,
                        "end_time": datetime.now(timezone.utc).isoformat(),
                    },
                )

                stopped_session = await result.single()
                if not stopped_session:
                    return False

            logger.info(
                f"Stopped polling session for configuration ID: {configuration_id}"
            )
            return True

        except Exception as e:
            logger.error(f"Failed to stop polling session for {configuration_id}: {e}")
            raise

    async def test_xdr_connection(self, configuration_id: str) -> Dict[str, Any]:
        """Test connection to XDR API for a configuration"""
        try:
            configuration = await self.get_xdr_configuration(configuration_id)
            if not configuration:
                return {"status": "error", "error": "Configuration not found"}

            # Get auth token from Secret Manager
            auth_token = await self._get_secret_value(
                configuration.auth_token_secret_name
            )
            if not auth_token:
                return {"status": "error", "error": "Failed to retrieve auth token"}

            # Create XDR config for testing
            xdr_config = XDRConfig(
                base_url=configuration.base_url,
                auth_token=auth_token,
                poll_interval=configuration.poll_interval,
                poll_enabled=False,  # Don't start polling for test
            )

            # Test connection
            start_time = datetime.now(timezone.utc)

            async with XDRAlertClient(xdr_config) as client:
                # Try to fetch a small number of alerts to test connectivity
                await client.get_alerts(limit=1)

            end_time = datetime.now(timezone.utc)
            response_time = (end_time - start_time).total_seconds() * 1000

            return {
                "status": "success",
                "response_time_ms": round(response_time, 2),
                "api_version": "1.0",  # Could be determined from actual API response
            }

        except Exception as e:
            logger.error(f"XDR connection test failed for {configuration_id}: {e}")
            return {"status": "error", "error": str(e)}

    async def create_mcp_server_configuration(
        self, server_data: MCPServerConfigurationCreate
    ) -> MCPServerConfiguration:
        """Create MCP server configuration node"""
        try:
            server = MCPServerConfiguration(
                name=server_data.name,
                server_type=server_data.server_type,
                base_url=str(server_data.base_url),
                enabled=server_data.enabled,
                priority=server_data.priority,
                timeout=server_data.timeout,
                auth_config=server_data.auth_config,
                alert_filters=server_data.alert_filters,
                processing_config=server_data.processing_config,
            )

            query, parameters = create_node_query(
                server, ["MCPServerConfiguration", "Configuration"]
            )

            db_manager = await self.get_db_manager()
            async with db_manager.get_session() as session:
                result = await session.run(query, parameters)
                created_record = await result.single()

                if not created_record:
                    raise Exception("Failed to create MCP server configuration node")

            logger.info(f"Created MCP server configuration: {server.name}")
            return server

        except Exception as e:
            logger.error(f"Failed to create MCP server configuration: {e}")
            raise

    async def create_system_configuration(
        self, config_data: SystemConfigurationCreate
    ) -> SystemConfiguration:
        """Create system configuration node"""
        try:
            configuration = SystemConfiguration(
                config_key=config_data.config_key,
                config_value=config_data.config_value,
                config_type=config_data.config_type,
                description=config_data.description,
                environment=config_data.environment,
            )

            query, parameters = create_node_query(
                configuration, ["SystemConfiguration", "Configuration"]
            )

            db_manager = await self.get_db_manager()
            async with db_manager.get_session() as session:
                result = await session.run(query, parameters)
                created_record = await result.single()

                if not created_record:
                    raise Exception("Failed to create system configuration node")

            logger.info(f"Created system configuration: {configuration.config_key}")
            return configuration

        except Exception as e:
            logger.error(f"Failed to create system configuration: {e}")
            raise

    async def list_mcp_server_configurations(
        self,
        enabled: Optional[bool] = None,
        server_type: Optional[str] = None,
        limit: int = 50,
        offset: int = 0,
    ) -> List[MCPServerConfiguration]:
        """List MCP server configurations with optional filtering"""
        try:
            # Build query conditions
            conditions = []
            parameters = {"limit": limit, "offset": offset}

            if enabled is not None:
                conditions.append("server.enabled = $enabled")
                parameters["enabled"] = enabled

            if server_type:
                conditions.append("server.server_type = $server_type")
                parameters["server_type"] = server_type

            where_clause = "WHERE " + " AND ".join(conditions) if conditions else ""

            query = f"""
            MATCH (server:MCPServerConfiguration)
            {where_clause}
            RETURN server
            ORDER BY server.priority, server.name
            SKIP $offset
            LIMIT $limit
            """

            db_manager = await self.get_db_manager()
            async with db_manager.get_session() as session:
                result = await session.run(query, parameters)
                records = await result.data()

                servers = []
                for record in records:
                    server_data = record["server"]
                    server = MCPServerConfiguration(
                        **{
                            k: v
                            for k, v in server_data.items()
                            if k in MCPServerConfiguration.__dataclass_fields__
                        }
                    )
                    servers.append(server)

                return servers

        except Exception as e:
            logger.error(f"Failed to list MCP server configurations: {e}")
            raise

    async def list_system_configurations(
        self, config_type: Optional[str] = None, environment: Optional[str] = None
    ) -> List[SystemConfiguration]:
        """List system configurations with optional filtering"""
        try:
            # Build query conditions
            conditions = []
            parameters = {}

            if config_type:
                conditions.append("config.config_type = $config_type")
                parameters["config_type"] = config_type

            if environment:
                conditions.append("config.environment = $environment")
                parameters["environment"] = environment

            where_clause = "WHERE " + " AND ".join(conditions) if conditions else ""

            query = f"""
            MATCH (config:SystemConfiguration)
            {where_clause}
            RETURN config
            ORDER BY config.config_type, config.config_key
            """

            db_manager = await self.get_db_manager()
            async with db_manager.get_session() as session:
                result = await session.run(query, parameters)
                records = await result.data()

                configurations = []
                for record in records:
                    config_data = record["config"]
                    config = SystemConfiguration(
                        **{
                            k: v
                            for k, v in config_data.items()
                            if k in SystemConfiguration.__dataclass_fields__
                        }
                    )
                    configurations.append(config)

                return configurations

        except Exception as e:
            logger.error(f"Failed to list system configurations: {e}")
            raise

    async def create_alert_from_xdr_data(
        self, alert_data: Dict[str, Any], configuration_id: str
    ) -> Alert:
        """Create an Alert node from XDR alert data with enhanced security classification"""
        try:
            # Extract basic alert properties from XDR data
            alert = Alert(
                tenant_id=alert_data.get("tenantId"),
                customer_id=alert_data.get("customerId"),
                name=alert_data.get("name"),
                message=alert_data.get("message"),
                severity=alert_data.get("severity", 0),
                score=alert_data.get("score", 0),
                confidence=alert_data.get("confidence", 0),
                risk=alert_data.get("risk", 0),
                rule_id=alert_data.get("ruleId"),
                generated_by=alert_data.get("generatedBy"),
                sources=alert_data.get("sources", []),
                is_intel_available=alert_data.get("isIntelAvailable", False),
                is_correlated=alert_data.get("isCorrelated", False),
                total_event_match_count=alert_data.get("totalEventMatchCount", 0),
                alert_aggregation_count=alert_data.get("alertAggregationCount", 0),
                configuration_id=configuration_id,
                external_alert_id=alert_data.get("id"),
                alert_data=alert_data,
                related_entities=alert_data.get("relatedEntities", {}),
            )

            # Apply enhanced security classification
            attacks = alert_data.get("attacks", [])
            from ..database.models import (calculate_composite_risk_score,
                                           determine_classification,
                                           determine_escalation_level,
                                           determine_response_sla,
                                           determine_workflow_classification)

            alert.classification = determine_classification(alert, attacks)
            alert.workflow_classification = determine_workflow_classification(alert)
            alert.response_sla = determine_response_sla(
                alert.classification, alert.severity
            )
            alert.escalation_level = determine_escalation_level(alert)
            alert.composite_risk_score = calculate_composite_risk_score(
                alert, len(alert.related_entities.get("assets", []))
            )

            # Create alert node with multiple labels based on classification
            labels = ["Alert"]
            if alert.classification.value == "CRITICAL":
                labels.append("CriticalThreat")
            elif alert.classification.value == "HIGH":
                labels.append("HighThreat")
            elif alert.classification.value == "MEDIUM":
                labels.append("MediumThreat")

            query, parameters = create_node_query(alert, labels)

            db_manager = await self.get_db_manager()
            async with db_manager.get_session() as session:
                result = await session.run(query, parameters)
                created_record = await result.single()

                if not created_record:
                    raise Exception("Failed to create alert node")

                # Create relationship to configuration
                config_rel_query = """
                MATCH (alert:Alert {id: $alert_id})
                MATCH (config:XDRConfiguration {id: $config_id})
                CREATE (alert)-[:USES_CONFIG]->(config)
                """

                await session.run(
                    config_rel_query,
                    {"alert_id": alert.id, "config_id": configuration_id},
                )

            logger.info(
                f"Created alert node: {alert.name} (Classification: {alert.classification.value})"
            )
            return alert

        except Exception as e:
            logger.error(f"Failed to create alert from XDR data: {e}")
            raise

    async def _validate_secret_exists(self, secret_name: str) -> bool:
        """Validate that a secret exists in Google Secret Manager"""
        if not self.secret_client or not self.settings.google_cloud_project:
            return True  # Skip validation in non-GCP environments

        try:
            name = (
                f"projects/{self.settings.google_cloud_project}/secrets/{secret_name}"
            )
            self.secret_client.get_secret(request={"name": name})
            return True
        except GoogleCloudError as e:
            logger.error(f"Google Cloud error validating secret {secret_name}: {e}")
            raise SecretManagerException(
                f"Secret '{secret_name}' not found in Google Secret Manager",
                error_code="SECRET_NOT_FOUND",
                details={"secret_name": secret_name, "gcp_error": str(e)},
            )
        except Exception as e:
            logger.error(f"Unexpected error validating secret {secret_name}: {e}")
            raise SecretManagerException(
                "Failed to validate secret in Google Secret Manager",
                error_code="SECRET_VALIDATION_ERROR",
                details={"secret_name": secret_name, "error": str(e)},
            )

    async def _get_secret_value(self, secret_name: str) -> Optional[str]:
        """Get secret value from Google Secret Manager"""
        if not self.secret_client or not self.settings.google_cloud_project:
            # In development, return a dummy token or get from environment
            return "dummy-token-for-development"

        try:
            name = f"projects/{self.settings.google_cloud_project}/secrets/{secret_name}/versions/latest"
            response = self.secret_client.access_secret_version(request={"name": name})
            return response.payload.data.decode("UTF-8")
        except Exception as e:
            logger.error(f"Failed to get secret value for {secret_name}: {e}")
            return None

    async def get_configuration_statistics(
        self, configuration_id: str
    ) -> Dict[str, Any]:
        """Get statistics for a specific XDR configuration"""
        try:
            db_manager = await self.get_db_manager()

            # Query for alert count
            alert_count_query = """
            MATCH (alert:Alert)-[:USES_CONFIG]->(config:XDRConfiguration {id: $config_id})
            RETURN count(alert) as total_alerts
            """

            # Query for active polling sessions
            active_sessions_query = """
            MATCH (session:PollingSession {configuration_id: $config_id, status: 'active'})
            RETURN count(session) as active_sessions
            """

            async with db_manager.get_session() as session:
                # Get alert count
                alert_result = await session.run(
                    alert_count_query, {"config_id": configuration_id}
                )
                alert_record = await alert_result.single()
                total_alerts = alert_record["total_alerts"] if alert_record else 0

                # Get active sessions count
                session_result = await session.run(
                    active_sessions_query, {"config_id": configuration_id}
                )
                session_record = await session_result.single()
                active_sessions = (
                    session_record["active_sessions"] if session_record else 0
                )

                return {
                    "total_alerts": total_alerts,
                    "active_sessions": active_sessions,
                    "configuration_id": configuration_id,
                }

        except Neo4jError as e:
            logger.error(f"Neo4j error getting configuration statistics: {e}")
            raise Neo4jQueryException(
                "Failed to get configuration statistics",
                error_code="CONFIG_STATS_QUERY_FAILED",
                details={"configuration_id": configuration_id, "neo4j_error": str(e)},
            )
        except Exception as e:
            logger.error(f"Error getting configuration statistics: {e}")
            return {
                "total_alerts": 0,
                "active_sessions": 0,
                "configuration_id": configuration_id,
            }

    async def _test_and_update_configuration_status(
        self, configuration: XDRConfiguration
    ):
        """Test configuration and update its status"""
        try:
            test_result = await self.test_xdr_connection(configuration.id)

            new_status = (
                ConfigurationStatus.ACTIVE
                if test_result["status"] == "success"
                else ConfigurationStatus.ERROR
            )

            # Update status in Neo4j
            update_query = """
            MATCH (config:XDRConfiguration {id: $config_id})
            SET config.status = $status, config.updated_at = $updated_at
            RETURN config
            """

            db_manager = await self.get_db_manager()
            async with db_manager.get_session() as session:
                await session.run(
                    update_query,
                    {
                        "config_id": configuration.id,
                        "status": new_status.value,
                        "updated_at": datetime.now(timezone.utc).isoformat(),
                    },
                )

            configuration.status = new_status

        except Exception as e:
            logger.error(f"Failed to test configuration {configuration.id}: {e}")
            # Update to error status
            try:
                db_manager = await self.get_db_manager()
                async with db_manager.get_session() as session:
                    await session.run(
                        "MATCH (config:XDRConfiguration {id: $config_id}) SET config.status = 'error'",
                        {"config_id": configuration.id},
                    )
            except:
                pass  # Don't fail the main operation if status update fails


# Backwards compatibility alias
ConfigurationService = Neo4jConfigurationService
