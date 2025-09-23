"""
Alert Processing Service

Focused service for processing security alerts, enhanced analysis, and storage.
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
from ..core.exceptions import (AlertProcessingException,
                               Neo4jConnectionException, Neo4jQueryException,
                               ValidationException)
from ..core.security import audit_log, sanitize_cypher_input
from ..database.connection import Neo4jDatabaseManager, get_database_manager
from ..database.models import (Alert, AlertClassification, EscalationLevel,
                               ProcessingStatus, Relationship, ResponseSLA,
                               WorkflowClassification,
                               calculate_composite_risk_score,
                               create_node_query, create_relationship_query,
                               determine_classification,
                               determine_escalation_level,
                               determine_response_sla,
                               determine_workflow_classification)
from .enhanced_neo4j_population_service import EnhancedNeo4jPopulationService

logger = logging.getLogger(__name__)


class AlertProcessingService:
    """Service for processing and analyzing security alerts"""

    def __init__(self, db_manager: Neo4jDatabaseManager = None):
        self.db_manager = db_manager
        self._db_manager_cache = None
        self.settings = get_settings()
        self.enhanced_population_service = None

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

    async def get_enhanced_population_service(self) -> EnhancedNeo4jPopulationService:
        """Get enhanced Neo4j population service instance"""
        if not self.enhanced_population_service:
            db_manager = await self.get_db_manager()
            self.enhanced_population_service = EnhancedNeo4jPopulationService(
                db_manager
            )
        return self.enhanced_population_service

    async def store_enhanced_alert(self, alert_data: Dict[str, Any]) -> Alert:
        """Store alert with comprehensive enhanced security analysis using the new population service"""
        try:
            # Check if this is comprehensive enhanced data from XDR poller
            if "comprehensive_data" in alert_data:
                # Use the enhanced population service for full schema population
                enhanced_service = await self.get_enhanced_population_service()
                alert = await enhanced_service.populate_comprehensive_alert_data(
                    alert_data
                )
                logger.info(
                    f"Stored comprehensive enhanced alert: {alert.id} (Classification: {alert.classification.value})"
                )
                return alert
            else:
                # Fallback to basic enhanced alert storage for backward compatibility
                return await self._store_basic_enhanced_alert(alert_data)

        except ValidationException:
            raise
        except Neo4jError as e:
            logger.error(f"Neo4j error storing enhanced alert: {e}")
            raise Neo4jQueryException(
                "Database error storing enhanced alert",
                error_code="STORE_ENHANCED_ALERT_FAILED",
                details={"neo4j_error": str(e)},
            )
        except Exception as e:
            logger.error(f"Unexpected error storing enhanced alert: {e}")
            raise AlertProcessingException(
                "Failed to store enhanced alert",
                error_code="ENHANCED_ALERT_STORE_ERROR",
                details={"error": str(e)},
            )

    async def _store_basic_enhanced_alert(self, alert_data: Dict[str, Any]) -> Alert:
        """Store basic enhanced alert (fallback method for backward compatibility)"""
        try:
            # Extract and validate alert information
            alert_id = alert_data.get("id")
            if not alert_id:
                raise ValidationException("Alert ID is required")

            attributes = alert_data.get("attributes", {})

            # Create alert object with enhanced analysis
            alert = Alert(
                id=sanitize_cypher_input(str(alert_id)),
                tenant_id=attributes.get("tenantId"),
                customer_id=attributes.get("customerId"),
                name=attributes.get("name"),
                message=attributes.get("message"),
                severity=attributes.get("severity", 0),
                score=attributes.get("score", 0),
                confidence=attributes.get("confidence", 0),
                risk=attributes.get("risk", 0),
                rule_id=attributes.get("ruleId"),
                generated_by=attributes.get("generatedBy"),
                sources=attributes.get("sources", []),
                is_silent=attributes.get("isSilent", False),
                is_intel_available=attributes.get("isIntelAvailable", False),
                is_suppressed=attributes.get("isSuppressed", False),
                status=attributes.get("status", "NEW"),
                assignee=attributes.get("assignee"),
                alert_metadata_suppressed=attributes.get(
                    "alertMetadataSuppressed", False
                ),
                genai_name=attributes.get("genai_name"),
                genai_summary=attributes.get("genai_summary"),
                rule_origin=attributes.get("ruleOrigin"),
                is_correlated=attributes.get("isCorrelated", False),
                total_event_match_count=attributes.get("totalEventMatchCount", 0),
                alert_aggregation_count=attributes.get("alertAggregationCount", 0),
                in_timeline=attributes.get("inTimeline", False),
                in_pin=attributes.get("inPin", False),
                alert_data=alert_data,
                related_entities=self._extract_related_entities(alert_data),
                processing_status=ProcessingStatus.PENDING,
            )

            # Enhanced security analysis
            await self._perform_enhanced_analysis(alert)

            # Store in Neo4j
            db_manager = await self.get_db_manager()
            query, params = create_node_query(
                alert, ["Alert", alert.classification.value]
            )

            async with db_manager.get_session() as session:
                result = await session.run(query, params)
                created_node = await result.single()

                if not created_node:
                    raise Neo4jQueryException("Failed to create alert node")

                # Create relationships for enhanced correlation
                await self._create_alert_relationships(alert, session)

                # Audit log
                await audit_log(
                    action="STORE_BASIC_ENHANCED_ALERT",
                    resource_id=alert.id,
                    details={
                        "classification": alert.classification.value,
                        "risk_score": alert.composite_risk_score,
                        "workflow": alert.workflow_classification.value,
                    },
                    session=session,
                )

                logger.info(
                    f"Stored basic enhanced alert: {alert.id} (Classification: {alert.classification.value})"
                )
                return alert

        except Exception as e:
            logger.error(f"Error storing basic enhanced alert: {e}")
            raise

    async def _perform_enhanced_analysis(self, alert: Alert) -> None:
        """Perform enhanced security analysis on alert"""
        try:
            # Extract attack techniques for classification
            attacks = self._extract_attack_techniques(alert.alert_data)

            # Determine security classification
            alert.classification = determine_classification(alert, attacks)

            # Determine workflow classification
            alert.workflow_classification = determine_workflow_classification(alert)

            # Determine response SLA
            asset_count = len(alert.related_entities.get("assets", []))
            alert.response_sla = determine_response_sla(
                alert.classification, alert.severity, asset_count
            )

            # Determine escalation level
            alert.escalation_level = determine_escalation_level(alert)

            # Calculate composite risk score
            max_tactic_priority = self._get_max_tactic_priority(attacks)
            alert.composite_risk_score = calculate_composite_risk_score(
                alert, asset_count, max_tactic_priority
            )

        except Exception as e:
            logger.error(f"Error performing enhanced analysis: {e}")
            # Set defaults on analysis failure
            alert.classification = AlertClassification.INFORMATIONAL
            alert.workflow_classification = WorkflowClassification.MANUAL_REQUIRED
            alert.response_sla = ResponseSLA.TWENTY_FOUR_HOUR
            alert.escalation_level = EscalationLevel.NONE
            alert.composite_risk_score = 0.0

    def _extract_related_entities(self, alert_data: Dict[str, Any]) -> Dict[str, Any]:
        """Extract related entities from alert data"""
        entities = {"assets": [], "events": [], "iocs": [], "users": []}

        # Extract assets
        if "relationships" in alert_data:
            relationships = alert_data["relationships"]
            if "assets" in relationships:
                entities["assets"] = relationships["assets"].get("data", [])
            if "events" in relationships:
                entities["events"] = relationships["events"].get("data", [])

        # Extract IOCs from events or attributes
        attributes = alert_data.get("attributes", {})
        if "artefacts" in attributes:
            entities["iocs"] = attributes["artefacts"]

        return entities

    def _extract_attack_techniques(self, alert_data: Dict[str, Any]) -> List[str]:
        """Extract MITRE ATT&CK techniques from alert data"""
        attacks = []

        # Look for attack techniques in various places
        attributes = alert_data.get("attributes", {})

        # Check for MITRE techniques in rule data
        if "ruleId" in attributes:
            rule_id = attributes["ruleId"]
            # Map common rule patterns to MITRE techniques
            if "privilege" in rule_id.lower():
                attacks.append("TA0004")  # Privilege Escalation
            elif "lateral" in rule_id.lower():
                attacks.append("TA0008")  # Lateral Movement
            elif "exfil" in rule_id.lower():
                attacks.append("TA0010")  # Exfiltration

        # Check for techniques in message or description
        message = attributes.get("message", "").lower()
        if "command and control" in message or "c2" in message:
            attacks.append("TA0011")  # Command and Control
        elif "credential" in message:
            attacks.append("TA0006")  # Credential Access
        elif "discovery" in message:
            attacks.append("TA0007")  # Discovery

        return attacks

    def _get_max_tactic_priority(self, attacks: List[str]) -> int:
        """Get maximum tactic priority from attack list"""
        tactic_priorities = {
            "TA0001": 1,  # Initial Access
            "TA0002": 2,  # Execution
            "TA0003": 3,  # Persistence
            "TA0004": 4,  # Privilege Escalation
            "TA0005": 3,  # Defense Evasion
            "TA0006": 4,  # Credential Access
            "TA0007": 2,  # Discovery
            "TA0008": 4,  # Lateral Movement
            "TA0009": 3,  # Collection
            "TA0010": 5,  # Exfiltration
            "TA0011": 5,  # Command and Control
            "TA0040": 5,  # Impact
        }

        if not attacks:
            return 0

        return max(tactic_priorities.get(attack, 0) for attack in attacks)

    async def _create_alert_relationships(
        self, alert: Alert, session: AsyncSession
    ) -> None:
        """Create relationships for alert correlation"""
        try:
            # Create relationships to assets
            for asset_data in alert.related_entities.get("assets", []):
                asset_id = asset_data.get("id")
                if asset_id:
                    relationship = Relationship(
                        type="AFFECTS",
                        properties={
                            "severity_impact": alert.severity,
                            "confidence": alert.confidence,
                            "discovered_at": datetime.now(timezone.utc).isoformat(),
                        },
                    )

                    # Create relationship query (simplified for this example)
                    rel_query = """
                    MATCH (alert:Alert {id: $alert_id})
                    MATCH (asset:Asset {id: $asset_id})
                    MERGE (alert)-[r:AFFECTS {
                        severity_impact: $severity_impact,
                        confidence: $confidence,
                        discovered_at: $discovered_at
                    }]->(asset)
                    """

                    await session.run(
                        rel_query,
                        {
                            "alert_id": alert.id,
                            "asset_id": str(asset_id),
                            **relationship.properties,
                        },
                    )

            # Create relationships to events
            for event_data in alert.related_entities.get("events", []):
                event_id = event_data.get("id")
                if event_id:
                    relationship = Relationship(
                        type="RELATED_TO",
                        properties={
                            "correlation_confidence": alert.confidence,
                            "timeline_position": event_data.get("sequence", 0),
                            "event_timestamp": event_data.get(
                                "time", datetime.now(timezone.utc).isoformat()
                            ),
                        },
                    )

                    rel_query = """
                    MATCH (alert:Alert {id: $alert_id})
                    MATCH (event:Event {id: $event_id})
                    MERGE (alert)-[r:RELATED_TO {
                        correlation_confidence: $correlation_confidence,
                        timeline_position: $timeline_position,
                        event_timestamp: $event_timestamp
                    }]->(event)
                    """

                    await session.run(
                        rel_query,
                        {
                            "alert_id": alert.id,
                            "event_id": str(event_id),
                            **relationship.properties,
                        },
                    )

        except Exception as e:
            logger.error(f"Error creating alert relationships: {e}")
            # Don't fail the entire operation for relationship errors

    async def get_alert(self, alert_id: str) -> Optional[Alert]:
        """Retrieve alert by ID"""
        try:
            alert_id = sanitize_cypher_input(alert_id)
            db_manager = await self.get_db_manager()

            query = """
            MATCH (alert:Alert {id: $alert_id})
            RETURN alert
            """

            async with db_manager.get_session() as session:
                result = await session.run(query, {"alert_id": alert_id})
                record = await result.single()

                if not record:
                    return None

                alert_data = record["alert"]
                return Alert(**alert_data)

        except Neo4jError as e:
            logger.error(f"Neo4j error retrieving alert {alert_id}: {e}")
            raise Neo4jQueryException(
                "Database error retrieving alert",
                error_code="GET_ALERT_FAILED",
                details={"alert_id": alert_id, "neo4j_error": str(e)},
            )
        except Exception as e:
            logger.error(f"Unexpected error retrieving alert {alert_id}: {e}")
            raise AlertProcessingException(
                "Failed to retrieve alert",
                error_code="ALERT_RETRIEVE_ERROR",
                details={"alert_id": alert_id, "error": str(e)},
            )

    async def update_processing_status(
        self,
        alert_id: str,
        status: ProcessingStatus,
        mcp_server: Optional[str] = None,
        processing_results: Optional[Dict[str, Any]] = None,
        error_details: Optional[Dict[str, Any]] = None,
    ) -> bool:
        """Update alert processing status"""
        try:
            alert_id = sanitize_cypher_input(alert_id)
            db_manager = await self.get_db_manager()

            update_params = {
                "alert_id": alert_id,
                "processing_status": status.value,
                "updated_at": datetime.now(timezone.utc).isoformat(),
            }

            set_clauses = [
                "alert.processing_status = $processing_status",
                "alert.updated_at = $updated_at",
            ]

            if status == ProcessingStatus.PROCESSING:
                update_params["processing_started_at"] = datetime.now(
                    timezone.utc
                ).isoformat()
                set_clauses.append(
                    "alert.processing_started_at = $processing_started_at"
                )
            elif status == ProcessingStatus.COMPLETED:
                update_params["processing_completed_at"] = datetime.now(
                    timezone.utc
                ).isoformat()
                set_clauses.append(
                    "alert.processing_completed_at = $processing_completed_at"
                )

            if mcp_server:
                # Add to processed servers list
                set_clauses.append(
                    "alert.mcp_servers_processed = CASE "
                    "WHEN $mcp_server IN alert.mcp_servers_processed THEN alert.mcp_servers_processed "
                    "ELSE alert.mcp_servers_processed + $mcp_server END"
                )
                update_params["mcp_server"] = mcp_server

            if processing_results:
                update_params["processing_results"] = processing_results
                set_clauses.append("alert.processing_results = $processing_results")

            if error_details:
                update_params["processing_errors"] = error_details
                set_clauses.append("alert.processing_errors = $processing_errors")

            query = f"""
            MATCH (alert:Alert {{id: $alert_id}})
            SET {', '.join(set_clauses)}
            RETURN alert
            """

            async with db_manager.get_session() as session:
                result = await session.run(query, update_params)
                updated_record = await result.single()

                if not updated_record:
                    return False

                logger.debug(
                    f"Updated alert processing status: {alert_id} -> {status.value}"
                )
                return True

        except Neo4jError as e:
            logger.error(f"Neo4j error updating processing status {alert_id}: {e}")
            raise Neo4jQueryException(
                "Database error updating processing status",
                error_code="UPDATE_PROCESSING_STATUS_FAILED",
                details={"alert_id": alert_id, "neo4j_error": str(e)},
            )
        except Exception as e:
            logger.error(f"Unexpected error updating processing status {alert_id}: {e}")
            raise AlertProcessingException(
                "Failed to update processing status",
                error_code="PROCESSING_STATUS_UPDATE_ERROR",
                details={"alert_id": alert_id, "error": str(e)},
            )

    async def get_alerts_by_classification(
        self, classification: AlertClassification, limit: int = 100, offset: int = 0
    ) -> List[Alert]:
        """Get alerts by security classification"""
        try:
            db_manager = await self.get_db_manager()

            query = """
            MATCH (alert:Alert)
            WHERE alert.classification = $classification
            RETURN alert
            ORDER BY alert.composite_risk_score DESC, alert.created_at DESC
            SKIP $offset
            LIMIT $limit
            """

            async with db_manager.get_session() as session:
                result = await session.run(
                    query,
                    {
                        "classification": classification.value,
                        "limit": limit,
                        "offset": offset,
                    },
                )

                alerts = []
                async for record in result:
                    alert_data = record["alert"]
                    alerts.append(Alert(**alert_data))

                return alerts

        except Neo4jError as e:
            logger.error(f"Neo4j error getting alerts by classification: {e}")
            raise Neo4jQueryException(
                "Database error getting alerts by classification",
                error_code="GET_ALERTS_BY_CLASS_FAILED",
                details={"neo4j_error": str(e)},
            )
        except Exception as e:
            logger.error(f"Unexpected error getting alerts by classification: {e}")
            raise AlertProcessingException(
                "Failed to get alerts by classification",
                error_code="GET_ALERTS_BY_CLASS_ERROR",
                details={"error": str(e)},
            )

    async def get_alert_with_comprehensive_relationships(
        self, alert_id: str
    ) -> Optional[Dict[str, Any]]:
        """Get alert with all comprehensive relationships using enhanced service"""
        try:
            enhanced_service = await self.get_enhanced_population_service()
            return await enhanced_service.get_alert_with_relationships(alert_id)
        except Exception as e:
            logger.error(
                f"Error retrieving alert with comprehensive relationships: {e}"
            )
            # Fallback to basic alert retrieval
            return await self.get_alert(alert_id)

    async def get_enhanced_security_metrics(
        self, customer_id: str = None
    ) -> Dict[str, Any]:
        """Get enhanced security metrics for dashboard"""
        try:
            db_manager = await self.get_db_manager()

            # Build base query with optional customer filter
            customer_filter = (
                "WHERE alert.customer_id = $customer_id" if customer_id else ""
            )

            metrics_query = f"""
            MATCH (alert:Alert)
            {customer_filter}
            WITH alert
            OPTIONAL MATCH (alert)-[:AFFECTS]->(asset:Asset)
            OPTIONAL MATCH (alert)-[:MITIGATES]->(attack:Attack)
            OPTIONAL MATCH (alert)-[:ATTRIBUTED_TO]->(ta:ThreatActor)
            OPTIONAL MATCH (alert)-[:INDICATES]->(intel:IntelContext)
            RETURN
                count(alert) as total_alerts,
                count(CASE WHEN alert.classification = 'CRITICAL' THEN 1 END) as critical_alerts,
                count(CASE WHEN alert.classification = 'HIGH' THEN 1 END) as high_alerts,
                count(CASE WHEN alert.classification = 'MEDIUM' THEN 1 END) as medium_alerts,
                count(CASE WHEN alert.classification = 'LOW' THEN 1 END) as low_alerts,
                count(CASE WHEN alert.escalation_level = 'SOC_Manager' THEN 1 END) as soc_manager_escalations,
                count(CASE WHEN alert.escalation_level = 'Security_Engineering' THEN 1 END) as security_eng_escalations,
                count(DISTINCT asset) as affected_assets,
                count(DISTINCT attack) as mitre_techniques,
                count(DISTINCT ta) as threat_actors,
                count(DISTINCT intel) as intel_indicators,
                avg(alert.composite_risk_score) as avg_risk_score,
                max(alert.composite_risk_score) as max_risk_score,
                count(CASE WHEN alert.workflow_classification = 'Auto-Containable' THEN 1 END) as auto_containable,
                count(CASE WHEN alert.workflow_classification = 'Auto-Enrichable' THEN 1 END) as auto_enrichable,
                count(CASE WHEN alert.workflow_classification = 'Manual-Required' THEN 1 END) as manual_required
            """

            params = {"customer_id": customer_id} if customer_id else {}

            async with db_manager.get_session() as session:
                result = await session.run(metrics_query, params)
                record = await result.single()

                if not record:
                    return {}

                return {
                    "total_alerts": record["total_alerts"],
                    "classification_breakdown": {
                        "critical": record["critical_alerts"],
                        "high": record["high_alerts"],
                        "medium": record["medium_alerts"],
                        "low": record["low_alerts"],
                    },
                    "escalation_metrics": {
                        "soc_manager": record["soc_manager_escalations"],
                        "security_engineering": record["security_eng_escalations"],
                    },
                    "correlation_metrics": {
                        "affected_assets": record["affected_assets"],
                        "mitre_techniques": record["mitre_techniques"],
                        "threat_actors": record["threat_actors"],
                        "intel_indicators": record["intel_indicators"],
                    },
                    "risk_metrics": {
                        "average_risk_score": float(record["avg_risk_score"] or 0),
                        "maximum_risk_score": float(record["max_risk_score"] or 0),
                    },
                    "workflow_metrics": {
                        "auto_containable": record["auto_containable"],
                        "auto_enrichable": record["auto_enrichable"],
                        "manual_required": record["manual_required"],
                    },
                }

        except Exception as e:
            logger.error(f"Error retrieving enhanced security metrics: {e}")
            return {}
