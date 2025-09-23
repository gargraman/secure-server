"""
Polling Session Service

Focused service for managing XDR polling sessions and tracking.
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
from ..core.security import audit_log, sanitize_cypher_input
from ..database.connection import Neo4jDatabaseManager, get_database_manager
from ..database.models import PollingSession, create_node_query

logger = logging.getLogger(__name__)


class PollingSessionService:
    """Service for managing XDR polling sessions and tracking"""

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

    async def start_polling_session(
        self, configuration_id: str, override_interval: Optional[int] = None
    ) -> PollingSession:
        """Start a new polling session for a configuration"""
        try:
            configuration_id = sanitize_cypher_input(configuration_id)

            # Create polling session
            session = PollingSession(
                configuration_id=configuration_id,
                session_start=datetime.now(timezone.utc),
                status="active",
                polls_executed=0,
                alerts_fetched=0,
                alerts_processed=0,
                errors_encountered=0,
            )

            # Store in Neo4j
            db_manager = await self.get_db_manager()
            query, params = create_node_query(session, ["PollingSession", "Session"])

            async with db_manager.get_session() as db_session:
                result = await db_session.run(query, params)
                created_node = await result.single()

                if not created_node:
                    raise Neo4jQueryException("Failed to create polling session node")

                # Create relationship to configuration
                rel_query = """
                MATCH (session:PollingSession {id: $session_id})
                MATCH (config:XDRConfiguration {id: $config_id})
                CREATE (session)-[:TRACKS_POLLING_FOR]->(config)
                """

                await db_session.run(
                    rel_query, {"session_id": session.id, "config_id": configuration_id}
                )

                # Audit log
                await audit_log(
                    action="START_POLLING_SESSION",
                    resource_id=session.id,
                    details={"configuration_id": configuration_id},
                    session=db_session,
                )

                logger.info(
                    f"Started polling session: {session.id} for config: {configuration_id}"
                )
                return session

        except Neo4jError as e:
            logger.error(f"Neo4j error starting polling session: {e}")
            raise Neo4jQueryException(
                "Database error starting polling session",
                error_code="START_POLLING_SESSION_FAILED",
                details={"configuration_id": configuration_id, "neo4j_error": str(e)},
            )
        except Exception as e:
            logger.error(f"Unexpected error starting polling session: {e}")
            raise ConfigurationException(
                "Failed to start polling session",
                error_code="POLLING_SESSION_START_ERROR",
                details={"configuration_id": configuration_id, "error": str(e)},
            )

    async def end_polling_session(
        self, session_id: str, final_status: str = "completed"
    ) -> bool:
        """End a polling session"""
        try:
            session_id = sanitize_cypher_input(session_id)
            final_status = sanitize_cypher_input(final_status)

            db_manager = await self.get_db_manager()

            query = """
            MATCH (session:PollingSession {id: $session_id})
            SET session.session_end = $session_end,
                session.status = $status,
                session.updated_at = $updated_at
            RETURN session
            """

            async with db_manager.get_session() as db_session:
                result = await db_session.run(
                    query,
                    {
                        "session_id": session_id,
                        "session_end": datetime.now(timezone.utc).isoformat(),
                        "status": final_status,
                        "updated_at": datetime.now(timezone.utc).isoformat(),
                    },
                )

                updated_record = await result.single()
                if not updated_record:
                    return False

                # Audit log
                await audit_log(
                    action="END_POLLING_SESSION",
                    resource_id=session_id,
                    details={"final_status": final_status},
                    session=db_session,
                )

                logger.info(
                    f"Ended polling session: {session_id} with status: {final_status}"
                )
                return True

        except Neo4jError as e:
            logger.error(f"Neo4j error ending polling session {session_id}: {e}")
            raise Neo4jQueryException(
                "Database error ending polling session",
                error_code="END_POLLING_SESSION_FAILED",
                details={"session_id": session_id, "neo4j_error": str(e)},
            )
        except Exception as e:
            logger.error(f"Unexpected error ending polling session {session_id}: {e}")
            raise ConfigurationException(
                "Failed to end polling session",
                error_code="POLLING_SESSION_END_ERROR",
                details={"session_id": session_id, "error": str(e)},
            )

    async def update_polling_metrics(
        self,
        session_id: str,
        polls_executed: Optional[int] = None,
        alerts_fetched: Optional[int] = None,
        alerts_processed: Optional[int] = None,
        errors_encountered: Optional[int] = None,
        last_error: Optional[str] = None,
    ) -> bool:
        """Update polling session metrics"""
        try:
            session_id = sanitize_cypher_input(session_id)
            db_manager = await self.get_db_manager()

            # Build update parameters
            update_params = {
                "session_id": session_id,
                "last_poll_timestamp": datetime.now(timezone.utc).isoformat(),
                "updated_at": datetime.now(timezone.utc).isoformat(),
            }

            set_clauses = [
                "session.last_poll_timestamp = $last_poll_timestamp",
                "session.updated_at = $updated_at",
            ]

            if polls_executed is not None:
                update_params["polls_executed"] = polls_executed
                set_clauses.append("session.polls_executed = $polls_executed")

            if alerts_fetched is not None:
                update_params["alerts_fetched"] = alerts_fetched
                set_clauses.append("session.alerts_fetched = $alerts_fetched")

            if alerts_processed is not None:
                update_params["alerts_processed"] = alerts_processed
                set_clauses.append("session.alerts_processed = $alerts_processed")

            if errors_encountered is not None:
                update_params["errors_encountered"] = errors_encountered
                set_clauses.append("session.errors_encountered = $errors_encountered")

            if last_error is not None:
                update_params["last_error"] = sanitize_cypher_input(last_error)
                set_clauses.append("session.last_error = $last_error")

            query = f"""
            MATCH (session:PollingSession {{id: $session_id}})
            SET {', '.join(set_clauses)}
            RETURN session
            """

            async with db_manager.get_session() as db_session:
                result = await db_session.run(query, update_params)
                updated_record = await result.single()

                if not updated_record:
                    return False

                logger.debug(f"Updated polling metrics for session: {session_id}")
                return True

        except Neo4jError as e:
            logger.error(f"Neo4j error updating polling metrics {session_id}: {e}")
            raise Neo4jQueryException(
                "Database error updating polling metrics",
                error_code="UPDATE_POLLING_METRICS_FAILED",
                details={"session_id": session_id, "neo4j_error": str(e)},
            )
        except Exception as e:
            logger.error(f"Unexpected error updating polling metrics {session_id}: {e}")
            raise ConfigurationException(
                "Failed to update polling metrics",
                error_code="POLLING_METRICS_UPDATE_ERROR",
                details={"session_id": session_id, "error": str(e)},
            )

    async def get_polling_session(self, session_id: str) -> Optional[PollingSession]:
        """Retrieve polling session by ID"""
        try:
            session_id = sanitize_cypher_input(session_id)
            db_manager = await self.get_db_manager()

            query = """
            MATCH (session:PollingSession {id: $session_id})
            RETURN session
            """

            async with db_manager.get_session() as db_session:
                result = await db_session.run(query, {"session_id": session_id})
                record = await result.single()

                if not record:
                    return None

                session_data = record["session"]
                return PollingSession(**session_data)

        except Neo4jError as e:
            logger.error(f"Neo4j error retrieving polling session {session_id}: {e}")
            raise Neo4jQueryException(
                "Database error retrieving polling session",
                error_code="GET_POLLING_SESSION_FAILED",
                details={"session_id": session_id, "neo4j_error": str(e)},
            )
        except Exception as e:
            logger.error(
                f"Unexpected error retrieving polling session {session_id}: {e}"
            )
            raise ConfigurationException(
                "Failed to retrieve polling session",
                error_code="POLLING_SESSION_RETRIEVE_ERROR",
                details={"session_id": session_id, "error": str(e)},
            )

    async def get_active_sessions(self) -> List[PollingSession]:
        """Get all active polling sessions"""
        try:
            db_manager = await self.get_db_manager()

            query = """
            MATCH (session:PollingSession)
            WHERE session.status = 'active'
            RETURN session
            ORDER BY session.session_start DESC
            """

            async with db_manager.get_session() as db_session:
                result = await db_session.run(query)
                sessions = []

                async for record in result:
                    session_data = record["session"]
                    sessions.append(PollingSession(**session_data))

                return sessions

        except Neo4jError as e:
            logger.error(f"Neo4j error getting active sessions: {e}")
            raise Neo4jQueryException(
                "Database error getting active sessions",
                error_code="GET_ACTIVE_SESSIONS_FAILED",
                details={"neo4j_error": str(e)},
            )
        except Exception as e:
            logger.error(f"Unexpected error getting active sessions: {e}")
            raise ConfigurationException(
                "Failed to get active sessions",
                error_code="ACTIVE_SESSIONS_ERROR",
                details={"error": str(e)},
            )

    async def get_sessions_for_configuration(
        self, configuration_id: str, limit: int = 50, offset: int = 0
    ) -> List[PollingSession]:
        """Get polling sessions for a specific configuration"""
        try:
            configuration_id = sanitize_cypher_input(configuration_id)
            db_manager = await self.get_db_manager()

            query = """
            MATCH (session:PollingSession {configuration_id: $configuration_id})
            RETURN session
            ORDER BY session.session_start DESC
            SKIP $offset
            LIMIT $limit
            """

            async with db_manager.get_session() as db_session:
                result = await db_session.run(
                    query,
                    {
                        "configuration_id": configuration_id,
                        "limit": limit,
                        "offset": offset,
                    },
                )

                sessions = []
                async for record in result:
                    session_data = record["session"]
                    sessions.append(PollingSession(**session_data))

                return sessions

        except Neo4jError as e:
            logger.error(
                f"Neo4j error getting sessions for config {configuration_id}: {e}"
            )
            raise Neo4jQueryException(
                "Database error getting sessions for configuration",
                error_code="GET_CONFIG_SESSIONS_FAILED",
                details={"configuration_id": configuration_id, "neo4j_error": str(e)},
            )
        except Exception as e:
            logger.error(
                f"Unexpected error getting sessions for config {configuration_id}: {e}"
            )
            raise ConfigurationException(
                "Failed to get sessions for configuration",
                error_code="CONFIG_SESSIONS_ERROR",
                details={"configuration_id": configuration_id, "error": str(e)},
            )

    async def get_polling_statistics(
        self, configuration_id: Optional[str] = None
    ) -> Dict[str, Any]:
        """Get polling statistics, optionally filtered by configuration"""
        try:
            db_manager = await self.get_db_manager()

            # Build query based on filter
            if configuration_id:
                configuration_id = sanitize_cypher_input(configuration_id)
                where_clause = "WHERE session.configuration_id = $configuration_id"
                params = {"configuration_id": configuration_id}
            else:
                where_clause = ""
                params = {}

            query = f"""
            MATCH (session:PollingSession)
            {where_clause}
            RETURN
                count(session) as total_sessions,
                sum(session.polls_executed) as total_polls,
                sum(session.alerts_fetched) as total_alerts_fetched,
                sum(session.alerts_processed) as total_alerts_processed,
                sum(session.errors_encountered) as total_errors,
                sum(CASE WHEN session.status = 'active' THEN 1 ELSE 0 END) as active_sessions,
                avg(session.alerts_processed * 1.0 / CASE WHEN session.polls_executed = 0 THEN 1 ELSE session.polls_executed END) as avg_alerts_per_poll
            """

            async with db_manager.get_session() as db_session:
                result = await db_session.run(query, params)
                stats = await result.single()

                return {
                    "total_sessions": stats["total_sessions"] or 0,
                    "total_polls": stats["total_polls"] or 0,
                    "total_alerts_fetched": stats["total_alerts_fetched"] or 0,
                    "total_alerts_processed": stats["total_alerts_processed"] or 0,
                    "total_errors": stats["total_errors"] or 0,
                    "active_sessions": stats["active_sessions"] or 0,
                    "avg_alerts_per_poll": round(stats["avg_alerts_per_poll"] or 0, 2),
                }

        except Neo4jError as e:
            logger.error(f"Neo4j error getting polling statistics: {e}")
            raise Neo4jQueryException(
                "Database error getting polling statistics",
                error_code="GET_POLLING_STATS_FAILED",
                details={"neo4j_error": str(e)},
            )
        except Exception as e:
            logger.error(f"Unexpected error getting polling statistics: {e}")
            raise ConfigurationException(
                "Failed to get polling statistics",
                error_code="POLLING_STATS_ERROR",
                details={"error": str(e)},
            )

    async def cleanup_old_sessions(self, days_old: int = 30) -> int:
        """Clean up old completed polling sessions"""
        try:
            db_manager = await self.get_db_manager()

            # Calculate cutoff date
            cutoff_date = datetime.now(timezone.utc).replace(
                hour=0, minute=0, second=0, microsecond=0
            )
            cutoff_date = cutoff_date.replace(day=cutoff_date.day - days_old)

            query = """
            MATCH (session:PollingSession)
            WHERE session.status <> 'active'
              AND datetime(session.session_start) < datetime($cutoff_date)
            WITH session, count(session) as sessions_to_delete
            DETACH DELETE session
            RETURN sessions_to_delete
            """

            async with db_manager.get_session() as db_session:
                result = await db_session.run(
                    query, {"cutoff_date": cutoff_date.isoformat()}
                )

                cleanup_result = await result.single()
                deleted_count = (
                    cleanup_result["sessions_to_delete"] if cleanup_result else 0
                )

                if deleted_count > 0:
                    logger.info(f"Cleaned up {deleted_count} old polling sessions")

                return deleted_count

        except Neo4jError as e:
            logger.error(f"Neo4j error cleaning up old sessions: {e}")
            raise Neo4jQueryException(
                "Database error cleaning up old sessions",
                error_code="CLEANUP_SESSIONS_FAILED",
                details={"neo4j_error": str(e)},
            )
        except Exception as e:
            logger.error(f"Unexpected error cleaning up old sessions: {e}")
            raise ConfigurationException(
                "Failed to cleanup old sessions",
                error_code="SESSION_CLEANUP_ERROR",
                details={"error": str(e)},
            )
