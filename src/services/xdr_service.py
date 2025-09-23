"""
XDR Service

Service layer for XDR alert management and polling operations using Neo4j.
Handles alert retrieval, processing, and statistics with graph-based queries.

Author: AI-SOAR Platform Team
Created: 2025-09-11
"""

import logging
from datetime import datetime, timedelta
from typing import Any, Dict, List, Optional, Union
from uuid import UUID

from neo4j import AsyncSession

from ..database.connection import get_database_manager
from ..database.models import (Alert, AlertClassification, AlertSeverity,
                               ProcessingStatus)
from ..web.models.alert_models import AlertResponse, AlertSummary

logger = logging.getLogger(__name__)


class XDRService:
    """Service for XDR alert operations using Neo4j graph database"""

    def __init__(self, neo4j_session: AsyncSession = None):
        """Initialize XDR service with Neo4j session"""
        self.neo4j_session = neo4j_session
        self._db_manager = None

    async def get_db_manager(self):
        """Get database manager instance"""
        if not self._db_manager:
            self._db_manager = await get_database_manager()
        return self._db_manager

    async def list_alerts(
        self,
        configuration_id: Optional[UUID] = None,
        severity: Optional[str] = None,
        status: Optional[str] = None,
        limit: int = 50,
        offset: int = 0,
    ) -> List[AlertResponse]:
        """List XDR alerts with filtering options using Neo4j"""
        try:
            db_manager = await self.get_db_manager()

            # Build Cypher query with filters
            conditions = []
            parameters = {"limit": limit, "offset": offset}

            if configuration_id:
                conditions.append("a.configuration_id = $configuration_id")
                parameters["configuration_id"] = str(configuration_id)

            if severity:
                conditions.append("a.severity = $severity")
                parameters["severity"] = severity

            if status:
                conditions.append("a.processing_status = $status")
                parameters["status"] = status

            where_clause = "WHERE " + " AND ".join(conditions) if conditions else ""

            query = f"""
            MATCH (a:Alert)
            {where_clause}
            RETURN a
            ORDER BY a.created_at DESC
            SKIP $offset
            LIMIT $limit
            """

            async with db_manager.get_session() as session:
                result = await session.run(query, parameters)
                records = await result.data()

                alerts = []
                for record in records:
                    alert_data = record["a"]
                    # Convert to AlertResponse model
                    alert_response = AlertResponse(
                        id=alert_data.get("id"),
                        external_id=alert_data.get("external_alert_id"),
                        name=alert_data.get("name"),
                        severity=alert_data.get("severity"),
                        status=alert_data.get("processing_status"),
                        created_at=alert_data.get("created_at"),
                        configuration_id=alert_data.get("configuration_id"),
                        alert_data=alert_data.get("alert_data", {}),
                        processing_results=alert_data.get("processing_results", {}),
                        retry_count=alert_data.get("retry_count", 0),
                    )
                    alerts.append(alert_response)

                return alerts

        except Exception as e:
            logger.error(f"Error listing alerts: {e}")
            raise

    async def get_alert(self, alert_id: UUID) -> Optional[AlertResponse]:
        """Get detailed information for a specific alert"""
        try:
            db_manager = await self.get_db_manager()

            query = """
            MATCH (a:Alert {id: $alert_id})
            RETURN a
            """

            async with db_manager.get_session() as session:
                result = await session.run(query, {"alert_id": str(alert_id)})
                record = await result.single()

                if not record:
                    return None

                alert_data = record["a"]
                return AlertResponse(
                    id=alert_data.get("id"),
                    external_id=alert_data.get("external_alert_id"),
                    name=alert_data.get("name"),
                    severity=alert_data.get("severity"),
                    status=alert_data.get("processing_status"),
                    created_at=alert_data.get("created_at"),
                    configuration_id=alert_data.get("configuration_id"),
                    alert_data=alert_data.get("alert_data", {}),
                    processing_results=alert_data.get("processing_results", {}),
                    retry_count=alert_data.get("retry_count", 0),
                )

        except Exception as e:
            logger.error(f"Error getting alert {alert_id}: {e}")
            raise

    async def reprocess_alert(
        self, alert_id: UUID, force: bool = False
    ) -> Dict[str, Any]:
        """Reprocess an alert through MCP servers"""
        try:
            db_manager = await self.get_db_manager()

            # Check current status
            query = """
            MATCH (a:Alert {id: $alert_id})
            RETURN a.processing_status as status, a.retry_count as retry_count
            """

            async with db_manager.get_session() as session:
                result = await session.run(query, {"alert_id": str(alert_id)})
                record = await result.single()

                if not record:
                    return {
                        "status": "error",
                        "message": "Alert not found",
                        "processing_started": False,
                    }

                current_status = record["status"]
                retry_count = record["retry_count"] or 0

                # Check if reprocessing is allowed
                if current_status == ProcessingStatus.COMPLETED.value and not force:
                    return {
                        "status": "skipped",
                        "message": "Alert already processed. Use force=true to reprocess.",
                        "processing_started": False,
                    }

                if retry_count >= 3 and not force:
                    return {
                        "status": "error",
                        "message": "Maximum retries exceeded. Use force=true to reprocess.",
                        "processing_started": False,
                    }

                # Reset alert for reprocessing
                update_query = """
                MATCH (a:Alert {id: $alert_id})
                SET
                    a.processing_status = $status,
                    a.processing_started_at = datetime(),
                    a.processing_completed_at = null,
                    a.retry_count = $retry_count
                RETURN a
                """

                await session.run(
                    update_query,
                    {
                        "alert_id": str(alert_id),
                        "status": ProcessingStatus.PENDING.value,
                        "retry_count": 0 if force else retry_count + 1,
                    },
                )

                return {
                    "status": "success",
                    "message": "Alert queued for reprocessing",
                    "processing_started": True,
                }

        except Exception as e:
            logger.error(f"Error reprocessing alert {alert_id}: {e}")
            raise

    async def get_polling_status(self) -> Dict[str, Any]:
        """Get current polling status for all XDR configurations"""
        try:
            db_manager = await self.get_db_manager()

            query = """
            MATCH (config:XDRConfiguration)
            OPTIONAL MATCH (config)<-[:CONFIGURED_BY]-(session:PollingSession {status: 'active'})
            RETURN
                config.id as config_id,
                config.name as config_name,
                config.poll_enabled as poll_enabled,
                config.status as config_status,
                session.id as session_id,
                session.session_start as session_start,
                session.polls_executed as polls_executed,
                session.alerts_fetched as alerts_fetched
            ORDER BY config.name
            """

            async with db_manager.get_session() as session:
                result = await session.run(query)
                records = await result.data()

                configurations = []
                for record in records:
                    config_status = {
                        "configuration_id": record["config_id"],
                        "configuration_name": record["config_name"],
                        "poll_enabled": record["poll_enabled"],
                        "status": record["config_status"],
                        "active_session": {
                            "session_id": record["session_id"],
                            "session_start": record["session_start"],
                            "polls_executed": record["polls_executed"] or 0,
                            "alerts_fetched": record["alerts_fetched"] or 0,
                        }
                        if record["session_id"]
                        else None,
                    }
                    configurations.append(config_status)

                return {
                    "configurations": configurations,
                    "total_configurations": len(configurations),
                    "active_sessions": len(
                        [c for c in configurations if c["active_session"]]
                    ),
                    "timestamp": datetime.utcnow().isoformat(),
                }

        except Exception as e:
            logger.error(f"Error getting polling status: {e}")
            raise

    async def get_statistics(self, hours: int = 24) -> Dict[str, Any]:
        """Get XDR alert statistics"""
        try:
            db_manager = await self.get_db_manager()
            cutoff_time = datetime.utcnow() - timedelta(hours=hours)

            # Alert count by status
            status_query = """
            MATCH (a:Alert)
            WHERE datetime(a.created_at) >= datetime($cutoff_time)
            RETURN a.processing_status as status, count(a) as count
            """

            # Alert count by severity
            severity_query = """
            MATCH (a:Alert)
            WHERE datetime(a.created_at) >= datetime($cutoff_time)
            RETURN a.severity as severity, count(a) as count
            """

            # Processing time statistics
            time_query = """
            MATCH (a:Alert)
            WHERE datetime(a.created_at) >= datetime($cutoff_time)
              AND a.processing_completed_at IS NOT NULL
              AND a.processing_started_at IS NOT NULL
            WITH duration.between(
                datetime(a.processing_started_at),
                datetime(a.processing_completed_at)
            ).seconds as processing_seconds
            RETURN
                avg(processing_seconds) as avg_seconds,
                max(processing_seconds) as max_seconds,
                count(*) as processed_count
            """

            async with db_manager.get_session() as session:
                # Execute queries
                status_result = await session.run(
                    status_query, {"cutoff_time": cutoff_time.isoformat()}
                )
                status_data = await status_result.data()

                severity_result = await session.run(
                    severity_query, {"cutoff_time": cutoff_time.isoformat()}
                )
                severity_data = await severity_result.data()

                time_result = await session.run(
                    time_query, {"cutoff_time": cutoff_time.isoformat()}
                )
                time_data = await time_result.single()

                return {
                    "time_period_hours": hours,
                    "status_distribution": {
                        record["status"]: record["count"] for record in status_data
                    },
                    "severity_distribution": {
                        record["severity"]: record["count"] for record in severity_data
                    },
                    "processing_times": {
                        "average_seconds": float(time_data["avg_seconds"] or 0)
                        if time_data
                        else 0,
                        "maximum_seconds": float(time_data["max_seconds"] or 0)
                        if time_data
                        else 0,
                        "processed_count": time_data["processed_count"] or 0
                        if time_data
                        else 0,
                    },
                    "timestamp": datetime.utcnow().isoformat(),
                }

        except Exception as e:
            logger.error(f"Error getting statistics: {e}")
            raise
