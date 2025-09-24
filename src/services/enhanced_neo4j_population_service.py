"""
Enhanced Neo4j Database Population Service

Comprehensive service for populating Neo4j database with enhanced security schema including
all node types (Alert, Event, Asset, Attack, IntelContext, ThreatActor) and relationships
with proper security classification, risk scoring, and threat intelligence correlation.

Based on the enhanced schema from NEO4J_SCHEMA_ENHANCED.md

Author: AI-SOAR Platform Team
Created: 2025-09-22 - Enhanced Neo4j Database Population
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
from ..database.models import (Alert, AlertClassification, Asset, Attack,
                               BusinessImpact, EscalationLevel, Event,
                               IntelContext, ProcessingStatus, Relationship,
                               ResponseSLA, ThreatActor,
                               WorkflowClassification,
                               calculate_composite_risk_score,
                               convert_risk_to_numeric,
                               convert_severity_to_numeric, create_node_query,
                               determine_classification,
                               determine_escalation_level,
                               determine_response_sla,
                               determine_workflow_classification,
                               normalize_attacks_field,
                               normalize_recommended_actions)

logger = logging.getLogger(__name__)


class EnhancedNeo4jPopulationService:
    """Enhanced service for comprehensive Neo4j database population with security analysis"""

    def __init__(self, db_manager: Neo4jDatabaseManager = None):
        self.db_manager = db_manager
        self._db_manager_cache = None
        self.settings = get_settings()

        # MITRE ATT&CK tactic mapping with priorities
        self.mitre_tactics = {
            "TA0001": ("Initial Access", 1),
            "TA0002": ("Execution", 2),
            "TA0003": ("Persistence", 3),
            "TA0004": ("Privilege Escalation", 4),
            "TA0005": ("Defense Evasion", 3),
            "TA0006": ("Credential Access", 4),
            "TA0007": ("Discovery", 2),
            "TA0008": ("Lateral Movement", 4),
            "TA0009": ("Collection", 3),
            "TA0010": ("Exfiltration", 5),
            "TA0011": ("Command and Control", 5),
            "TA0040": ("Impact", 5),
            "TA0043": ("Reconnaissance", 1),
        }

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

    async def populate_comprehensive_alert_data(
        self, enhanced_alert_data: Dict[str, Any]
    ) -> Alert:
        """
        Populate Neo4j with comprehensive alert data including all entities and relationships

        Args:
            enhanced_alert_data: Enhanced alert data from XDR poller with comprehensive_data

        Returns:
            Populated Alert object with full security analysis
        """
        try:
            db_manager = await self.get_db_manager()
            logger.debug(f"Got database manager of type: {type(db_manager)}")

            # Use write transaction for better atomicity
            async with db_manager.get_session() as session:
                try:
                    # Use write transaction for atomicity
                    async def _populate_transaction(tx):
                        # 1. Create main alert node with enhanced analysis
                        alert = await self._create_enhanced_alert_node(
                            enhanced_alert_data, tx
                        )

                        # 2. Create and link asset nodes
                        assets = await self._create_asset_nodes(
                            enhanced_alert_data, alert, tx
                        )

                        # 3. Create and link event nodes
                        events = await self._create_event_nodes(
                            enhanced_alert_data, alert, tx
                        )

                        # 4. Create and link MITRE ATT&CK technique nodes
                        attacks = await self._create_attack_nodes(
                            enhanced_alert_data, alert, tx
                        )

                        # 5. Create and link threat intelligence nodes
                        intel_contexts = await self._create_intel_context_nodes(
                            enhanced_alert_data, alert, tx
                        )

                        # 6. Create and link IOCs and artifacts
                        await self._create_ioc_relationships(
                            enhanced_alert_data, alert, events, tx
                        )

                        # 7. Create correlation relationships with other alerts
                        await self._create_correlation_relationships(alert, tx)

                        # 8. Create threat actor attribution if available
                        await self._create_threat_actor_relationships(
                            alert, intel_contexts, tx
                        )

                        # 9. Apply security classification labels
                        await self._apply_security_labels(alert, tx)

                        # 10. Create audit trail
                        await audit_log(
                            action="POPULATE_COMPREHENSIVE_ALERT",
                            resource_id=alert.id,
                            details={
                                "classification": alert.classification.value,
                                "risk_score": alert.composite_risk_score,
                                "assets_count": len(assets),
                                "events_count": len(events),
                                "attacks_count": len(attacks),
                                "intel_count": len(intel_contexts),
                            },
                            session=tx,
                        )

                        return alert

                    # Execute in write transaction
                    alert = await session.execute_write(_populate_transaction)

                    logger.info(
                        f"Successfully populated comprehensive alert data: {alert.id}"
                    )
                    return alert

                except Exception as tx_error:
                    logger.error(f"Transaction error in alert population: {tx_error}")
                    raise

        except Neo4jError as e:
            logger.error(f"Neo4j error populating comprehensive alert data: {e}")
            raise AlertProcessingException(
                "Neo4j database error during alert population",
                error_code="NEO4J_POPULATION_ERROR",
                details={"neo4j_error": str(e)},
            )
        except Exception as e:
            logger.error(f"Error populating comprehensive alert data: {e}")
            raise AlertProcessingException(
                "Failed to populate comprehensive alert data",
                error_code="COMPREHENSIVE_POPULATION_ERROR",
                details={"error": str(e)},
            )

    async def _create_enhanced_alert_node(
        self, enhanced_alert_data: Dict[str, Any], tx: AsyncSession
    ) -> Alert:
        """Create enhanced alert node with comprehensive security analysis"""

        alert_id = enhanced_alert_data.get("id")
        if not alert_id:
            raise ValidationException("Alert ID is required")

        attributes = enhanced_alert_data.get("attributes", {})
        comprehensive_data = enhanced_alert_data.get("comprehensive_data", {})

        # Create base alert object with proper field conversion
        alert = Alert(
            id=sanitize_cypher_input(str(alert_id)),
            tenant_id=attributes.get("tenantId"),
            customer_id=attributes.get("customerId"),
            name=attributes.get("name"),
            message=attributes.get("message"),
            # Handle severity conversion - API returns string, we store both
            severity=attributes.get("severity"),
            severity_numeric=convert_severity_to_numeric(attributes.get("severity")),
            score=attributes.get("score", 0),
            confidence=attributes.get("confidence", 0),
            # Handle risk conversion - API may return string or numeric
            risk=attributes.get("risk"),
            risk_numeric=convert_risk_to_numeric(attributes.get("risk")),
            rule_id=attributes.get("ruleId"),
            generated_by=attributes.get("generatedBy"),
            sources=attributes.get("sources", []),
            is_silent=attributes.get("isSilent", False),
            is_intel_available=attributes.get("isIntelAvailable", False),
            is_suppressed=attributes.get("isSuppressed", False),
            status=attributes.get("status", "NEW"),
            assignee=attributes.get("assignee"),
            alert_metadata_suppressed=attributes.get("alertMetadataSuppressed", False),
            genai_name=attributes.get("genai_name"),
            genai_summary=attributes.get("genai_summary"),
            rule_origin=attributes.get("ruleOrigin"),
            is_correlated=attributes.get("isCorrelated", False),
            total_event_match_count=attributes.get("totalEventMatchCount", 0),
            alert_aggregation_count=attributes.get("alertAggregationCount", 0),
            # New XDR API specific fields
            attacks=normalize_attacks_field(attributes.get("attacks")),
            recommended_actions=normalize_recommended_actions(
                attributes.get("recommendedActions")
            ),
            assets_count=attributes.get("assetsCount", 0),
            supporting_data=attributes.get("supportingData", {}),
            alert_data=enhanced_alert_data,
            related_entities=self._extract_related_entities(enhanced_alert_data),
            processing_status=ProcessingStatus.PROCESSING,
        )

        # Parse timestamps
        if attributes.get("createdAt"):
            try:
                alert.created_at = datetime.fromisoformat(
                    attributes["createdAt"].replace("Z", "+00:00")
                )
            except ValueError:
                logger.warning(
                    f"Invalid createdAt timestamp format: {attributes['createdAt']}"
                )

        if attributes.get("time"):
            try:
                alert.time = datetime.fromisoformat(
                    attributes["time"].replace("Z", "+00:00")
                )
            except ValueError:
                logger.warning(f"Invalid time timestamp format: {attributes['time']}")

        if attributes.get("updatedAt"):
            try:
                alert.updated_at = datetime.fromisoformat(
                    attributes["updatedAt"].replace("Z", "+00:00")
                )
            except ValueError:
                logger.warning(
                    f"Invalid updatedAt timestamp format: {attributes['updatedAt']}"
                )

        if attributes.get("lastAggregatedTime"):
            try:
                alert.last_aggregated_time = datetime.fromisoformat(
                    attributes["lastAggregatedTime"].replace("Z", "+00:00")
                )
            except ValueError:
                logger.warning(
                    f"Invalid lastAggregatedTime timestamp format: {attributes['lastAggregatedTime']}"
                )

        # Enhanced security analysis
        await self._perform_enhanced_security_analysis(alert, comprehensive_data)

        # Create alert node with security classification labels
        labels = ["Alert", alert.classification.value]
        query, params = create_node_query(alert, labels)

        result = await tx.run(query, params)
        created_node = await result.single()

        if not created_node:
            raise Neo4jQueryException("Failed to create enhanced alert node")

        logger.debug(
            f"Created enhanced alert node: {alert.id} (Classification: {alert.classification.value})"
        )
        return alert

    async def _perform_enhanced_security_analysis(
        self, alert: Alert, comprehensive_data: Dict[str, Any]
    ) -> None:
        """Perform comprehensive security analysis on alert"""

        try:
            # Extract attack techniques and assets for analysis
            mitre_techniques = comprehensive_data.get("mitre_techniques", [])
            assets_data = comprehensive_data.get("assets", [])
            threat_intel = comprehensive_data.get("threat_intelligence", [])

            # Get attack tactic IDs for classification
            attack_tactics = [
                tech.get("technique_id")
                for tech in mitre_techniques
                if tech.get("technique_id")
            ]

            # Determine security classification
            alert.classification = determine_classification(alert, attack_tactics)

            # Determine workflow classification
            alert.workflow_classification = determine_workflow_classification(alert)

            # Determine response SLA
            asset_count = len(assets_data)
            alert.response_sla = determine_response_sla(
                alert.classification, alert.severity, asset_count
            )

            # Determine escalation level
            alert.escalation_level = determine_escalation_level(alert)

            # Calculate composite risk score
            max_tactic_priority = self._get_max_tactic_priority(attack_tactics)
            alert.composite_risk_score = calculate_composite_risk_score(
                alert, asset_count, max_tactic_priority
            )

            # Add threat intelligence factor
            if threat_intel:
                high_confidence_intel = [
                    ti for ti in threat_intel if ti.get("confidence", 0) >= 4
                ]
                if high_confidence_intel:
                    alert.composite_risk_score += len(high_confidence_intel) * 1.5

            # Cap the risk score
            alert.composite_risk_score = min(alert.composite_risk_score, 25.0)

        except Exception as e:
            logger.error(f"Error in enhanced security analysis: {e}")
            # Set safe defaults
            alert.classification = AlertClassification.INFORMATIONAL
            alert.workflow_classification = WorkflowClassification.MANUAL_REQUIRED
            alert.response_sla = ResponseSLA.TWENTY_FOUR_HOUR
            alert.escalation_level = EscalationLevel.NONE
            alert.composite_risk_score = 0.0

    async def _create_asset_nodes(
        self, enhanced_alert_data: Dict[str, Any], alert: Alert, tx: AsyncSession
    ) -> List[Asset]:
        """Create asset nodes and relationships"""

        assets = []
        comprehensive_data = enhanced_alert_data.get("comprehensive_data", {})
        assets_data = comprehensive_data.get("assets", [])

        for asset_data in assets_data:
            try:
                asset = Asset(
                    id=sanitize_cypher_input(
                        str(asset_data.get("id", f"asset_{len(assets)}"))
                    ),
                    tenant_id=alert.tenant_id,
                    customer_id=alert.customer_id,
                    name=asset_data.get("name"),
                    type=asset_data.get("type"),
                    hash=asset_data.get("hash"),
                    source=asset_data.get("source"),
                    status=asset_data.get("status", "NOT_CONTAINED"),
                    criticality=asset_data.get("criticality", 1),
                    business_impact=BusinessImpact(
                        asset_data.get("business_impact", "LOW")
                    ),
                    location=asset_data.get("location"),
                    owner=asset_data.get("owner"),
                )

                # Create asset node
                labels = ["Asset"]
                if asset.criticality >= 4:
                    labels.append("HighValueAsset")

                query, params = create_node_query(asset, labels)
                result = await tx.run(query, params)
                created_node = await result.single()

                if created_node:
                    assets.append(asset)

                    # Create AFFECTS relationship
                    affects_rel = Relationship(
                        type="AFFECTS",
                        properties={
                            "severity_impact": alert.severity,
                            "confidence": alert.confidence,
                            "criticality_impact": asset.criticality,
                            "business_impact": asset.business_impact.value,
                            "discovered_at": datetime.now(timezone.utc).isoformat(),
                        },
                    )

                    rel_query = """
                    MATCH (alert:Alert {id: $alert_id})
                    MATCH (asset:Asset {id: $asset_id})
                    MERGE (alert)-[r:AFFECTS {
                        severity_impact: $severity_impact,
                        confidence: $confidence,
                        criticality_impact: $criticality_impact,
                        business_impact: $business_impact,
                        discovered_at: $discovered_at
                    }]->(asset)
                    """

                    await tx.run(
                        rel_query,
                        {
                            "alert_id": alert.id,
                            "asset_id": asset.id,
                            **affects_rel.properties,
                        },
                    )

            except Exception as e:
                logger.error(f"Error creating asset node: {e}")
                continue

        logger.debug(f"Created {len(assets)} asset nodes for alert {alert.id}")
        return assets

    async def _create_event_nodes(
        self, enhanced_alert_data: Dict[str, Any], alert: Alert, tx: AsyncSession
    ) -> List[Event]:
        """Create event nodes and relationships"""

        events = []
        comprehensive_data = enhanced_alert_data.get("comprehensive_data", {})
        events_data = comprehensive_data.get("events", [])

        for event_data in events_data:
            try:
                event = Event(
                    id=sanitize_cypher_input(
                        str(event_data.get("id", f"event_{len(events)}"))
                    ),
                    tenant_id=alert.tenant_id,
                    customer_id=alert.customer_id,
                    name=event_data.get("name"),
                    source=event_data.get("source"),
                    message=event_data.get("message"),
                    severity=event_data.get("severity", 0),
                    score=event_data.get("score", 0),
                    confidence=event_data.get("confidence", 0),
                    risk=event_data.get("risk"),
                    artefact_type=event_data.get("artefact_type"),
                    sanitized=event_data.get("sanitized", False),
                    genai_name=event_data.get("genai_name"),
                    genai_summary=event_data.get("genai_summary"),
                    primary_secondary_fields=event_data.get("iocs", {}),
                )

                # Parse event timestamp
                if event_data.get("time"):
                    try:
                        event.time = datetime.fromisoformat(
                            event_data["time"].replace("Z", "+00:00")
                        )
                    except ValueError:
                        logger.warning(f"Invalid event timestamp: {event_data['time']}")

                # Create event node
                labels = ["Event"]
                if event.severity >= 4:
                    labels.append("HighSeverityEvent")

                query, params = create_node_query(event, labels)
                result = await tx.run(query, params)
                created_node = await result.single()

                if created_node:
                    events.append(event)

                    # Create RELATED_TO relationship
                    related_rel = Relationship(
                        type="RELATED_TO",
                        properties={
                            "correlation_confidence": event_data.get(
                                "correlation_confidence", "medium"
                            ),
                            "timeline_position": len(events),
                            "event_timestamp": event.time.isoformat()
                            if event.time
                            else datetime.now(timezone.utc).isoformat(),
                            "event_source": event.source,
                        },
                    )

                    rel_query = """
                    MATCH (alert:Alert {id: $alert_id})
                    MATCH (event:Event {id: $event_id})
                    MERGE (alert)-[r:RELATED_TO {
                        correlation_confidence: $correlation_confidence,
                        timeline_position: $timeline_position,
                        event_timestamp: $event_timestamp,
                        event_source: $event_source
                    }]->(event)
                    """

                    await tx.run(
                        rel_query,
                        {
                            "alert_id": alert.id,
                            "event_id": event.id,
                            **related_rel.properties,
                        },
                    )

            except Exception as e:
                logger.error(f"Error creating event node: {e}")
                continue

        logger.debug(f"Created {len(events)} event nodes for alert {alert.id}")
        return events

    async def _create_attack_nodes(
        self, enhanced_alert_data: Dict[str, Any], alert: Alert, tx: AsyncSession
    ) -> List[Attack]:
        """Create MITRE ATT&CK technique nodes and relationships"""

        attacks = []
        comprehensive_data = enhanced_alert_data.get("comprehensive_data", {})
        mitre_techniques = comprehensive_data.get("mitre_techniques", [])

        for technique_data in mitre_techniques:
            try:
                technique_id = technique_data.get("technique_id")
                if not technique_id or technique_id not in self.mitre_tactics:
                    continue

                tactic_name, tactic_priority = self.mitre_tactics[technique_id]

                attack = Attack(
                    id=f"attack_{technique_id}_{alert.id}",
                    technique_id=technique_id,
                    name=technique_data.get("name", f"Technique {technique_id}"),
                    tactic=f"{technique_id} - {tactic_name}",
                    tactic_priority=tactic_priority,
                    tactic_name=tactic_name,
                    tactic_id=technique_id,
                )

                # Create or merge attack node (techniques can be reused)
                # labels = ["Attack", "MITRETechnique"]  # Not used in current implementation

                merge_query = """
                MERGE (attack:Attack:MITRETechnique {technique_id: $technique_id})
                ON CREATE SET attack = $attack_properties
                ON MATCH SET attack.updated_at = $updated_at
                RETURN attack
                """

                attack_properties = attack.to_dict()
                result = await tx.run(
                    merge_query,
                    {
                        "technique_id": technique_id,
                        "attack_properties": attack_properties,
                        "updated_at": datetime.now(timezone.utc).isoformat(),
                    },
                )

                created_node = await result.single()
                if created_node:
                    attacks.append(attack)

                    # Create MITIGATES relationship
                    mitigates_rel = Relationship(
                        type="MITIGATES",
                        properties={
                            "confidence": technique_data.get("confidence", "medium"),
                            "detection_method": technique_data.get(
                                "detection_method", "rule_analysis"
                            ),
                            "evidence": str(technique_data.get("evidence", {})),
                            "tactic_priority": tactic_priority,
                        },
                    )

                    rel_query = """
                    MATCH (alert:Alert {id: $alert_id})
                    MATCH (attack:Attack {technique_id: $technique_id})
                    MERGE (alert)-[r:MITIGATES {
                        confidence: $confidence,
                        detection_method: $detection_method,
                        evidence: $evidence,
                        tactic_priority: $tactic_priority
                    }]->(attack)
                    """

                    await tx.run(
                        rel_query,
                        {
                            "alert_id": alert.id,
                            "technique_id": technique_id,
                            **mitigates_rel.properties,
                        },
                    )

            except Exception as e:
                logger.error(f"Error creating attack node: {e}")
                continue

        logger.debug(f"Created {len(attacks)} attack nodes for alert {alert.id}")
        return attacks

    async def _create_intel_context_nodes(
        self, enhanced_alert_data: Dict[str, Any], alert: Alert, tx: AsyncSession
    ) -> List[IntelContext]:
        """Create threat intelligence context nodes and relationships"""

        intel_contexts = []
        comprehensive_data = enhanced_alert_data.get("comprehensive_data", {})
        threat_intelligence = comprehensive_data.get("threat_intelligence", [])

        for intel_data in threat_intelligence:
            try:
                intel_context = IntelContext(
                    id=f"intel_{intel_data.get('type', 'unknown')}_{len(intel_contexts)}_{alert.id}",
                    type=intel_data.get("type"),
                    value=intel_data.get("value"),
                    source=intel_data.get("source"),
                    confidence=intel_data.get("confidence", 0),
                    severity=intel_data.get("severity"),
                    threat_actors=intel_data.get("threat_actors", []),
                    campaigns=intel_data.get("campaigns", []),
                    lethality=intel_data.get("lethality"),
                    determinism=intel_data.get("determinism"),
                    comment=intel_data.get("comment"),
                )

                # Parse timestamps
                if intel_data.get("first_seen"):
                    try:
                        intel_context.first_seen = datetime.fromisoformat(
                            intel_data["first_seen"].replace("Z", "+00:00")
                        )
                    except ValueError:
                        pass

                # Create intel context node
                labels = ["IntelContext"]
                if intel_context.confidence >= 4:
                    labels.append("HighConfidenceIntel")
                if intel_context.threat_actors:
                    labels.append("APTIntel")

                query, params = create_node_query(intel_context, labels)
                result = await tx.run(query, params)
                created_node = await result.single()

                if created_node:
                    intel_contexts.append(intel_context)

                    # Create INDICATES relationship
                    indicates_rel = Relationship(
                        type="INDICATES",
                        properties={
                            "first_seen_in_event": intel_context.first_seen.isoformat()
                            if intel_context.first_seen
                            else datetime.now(timezone.utc).isoformat(),
                            "confidence": intel_context.confidence
                            / 5.0,  # Normalize to 0-1
                            "intel_source": intel_context.source,
                            "threat_level": intel_context.severity or "unknown",
                        },
                    )

                    rel_query = """
                    MATCH (alert:Alert {id: $alert_id})
                    MATCH (intel:IntelContext {id: $intel_id})
                    MERGE (alert)-[r:INDICATES {
                        first_seen_in_event: $first_seen_in_event,
                        confidence: $confidence,
                        intel_source: $intel_source,
                        threat_level: $threat_level
                    }]->(intel)
                    """

                    await tx.run(
                        rel_query,
                        {
                            "alert_id": alert.id,
                            "intel_id": intel_context.id,
                            **indicates_rel.properties,
                        },
                    )

            except Exception as e:
                logger.error(f"Error creating intel context node: {e}")
                continue

        logger.debug(
            f"Created {len(intel_contexts)} intel context nodes for alert {alert.id}"
        )
        return intel_contexts

    async def _create_ioc_relationships(
        self,
        enhanced_alert_data: Dict[str, Any],
        _alert: Alert,  # Renamed to indicate intentional non-use
        events: List[Event],
        tx: AsyncSession,
    ) -> None:
        """Create IOC and artifact relationships"""

        comprehensive_data = enhanced_alert_data.get("comprehensive_data", {})
        iocs_data = comprehensive_data.get("iocs", [])

        for ioc_data in iocs_data:
            try:
                # Create IOC as a property on events or create separate nodes if needed
                for event in events:
                    if (
                        ioc_data.get("event_id") == event.id
                        or ioc_data.get("source") == "xdr_event_fields"
                    ):
                        # Add IOC data to event's primary_secondary_fields
                        ioc_update_query = """
                        MATCH (event:Event {id: $event_id})
                        SET event.ioc_data = COALESCE(event.ioc_data, []) + [$ioc_data]
                        """

                        await tx.run(
                            ioc_update_query,
                            {"event_id": event.id, "ioc_data": ioc_data},
                        )

            except Exception as e:
                logger.error(f"Error creating IOC relationship: {e}")
                continue

    async def _create_correlation_relationships(
        self, alert: Alert, tx: AsyncSession
    ) -> None:
        """Create correlation relationships with other alerts"""

        try:
            # Find similar alerts for correlation (simplified logic)
            correlation_query = """
            MATCH (existing:Alert)
            WHERE existing.id <> $alert_id
            AND existing.customer_id = $customer_id
            AND existing.rule_id = $rule_id
            AND existing.created_at > datetime() - duration('PT4H')
            RETURN existing.id as existing_id, existing.severity as existing_severity
            LIMIT 5
            """

            result = await tx.run(
                correlation_query,
                {
                    "alert_id": alert.id,
                    "customer_id": alert.customer_id,
                    "rule_id": alert.rule_id,
                },
            )

            correlated_alerts = []
            async for record in result:
                correlated_alerts.append(
                    {
                        "id": record["existing_id"],
                        "severity": record["existing_severity"],
                    }
                )

            # Create correlation relationships
            for correlated in correlated_alerts:
                correlation_rel = Relationship(
                    type="CORRELATED_TO",
                    properties={
                        "correlation_type": "peer",
                        "correlation_reason": "same_rule_recent",
                        "correlation_strength": 0.8,
                        "time_window": "4-hour",
                    },
                )

                rel_query = """
                MATCH (alert1:Alert {id: $alert_id})
                MATCH (alert2:Alert {id: $correlated_id})
                MERGE (alert1)-[r:CORRELATED_TO {
                    correlation_type: $correlation_type,
                    correlation_reason: $correlation_reason,
                    correlation_strength: $correlation_strength,
                    time_window: $time_window
                }]->(alert2)
                """

                await tx.run(
                    rel_query,
                    {
                        "alert_id": alert.id,
                        "correlated_id": correlated["id"],
                        **correlation_rel.properties,
                    },
                )

        except Exception as e:
            logger.error(f"Error creating correlation relationships: {e}")

    async def _create_threat_actor_relationships(
        self, alert: Alert, intel_contexts: List[IntelContext], tx: AsyncSession
    ) -> None:
        """Create threat actor attribution relationships"""

        try:
            # Extract threat actors from intel contexts
            threat_actors = set()
            for intel in intel_contexts:
                threat_actors.update(intel.threat_actors)

            for actor_name in threat_actors:
                if not actor_name:
                    continue

                # Create or merge threat actor node
                actor = ThreatActor(
                    id=f"threat_actor_{actor_name.lower().replace(' ', '_')}",
                    name=actor_name,
                    attribution_confidence="Medium",  # Default
                    first_seen=datetime.now(timezone.utc),
                    last_seen=datetime.now(timezone.utc),
                )

                merge_query = """
                MERGE (ta:ThreatActor {name: $actor_name})
                ON CREATE SET ta = $actor_properties
                ON MATCH SET ta.last_seen = $last_seen, ta.updated_at = $updated_at
                RETURN ta
                """

                actor_properties = actor.to_dict()
                result = await tx.run(
                    merge_query,
                    {
                        "actor_name": actor_name,
                        "actor_properties": actor_properties,
                        "last_seen": datetime.now(timezone.utc).isoformat(),
                        "updated_at": datetime.now(timezone.utc).isoformat(),
                    },
                )

                created_node = await result.single()
                if created_node:
                    # Create ATTRIBUTED_TO relationship
                    attribution_rel = Relationship(
                        type="ATTRIBUTED_TO",
                        properties={
                            "confidence": "Medium",
                            "evidence": f"Threat intelligence correlation",
                            "first_seen": datetime.now(timezone.utc).isoformat(),
                            "attribution_method": "intel_correlation",
                        },
                    )

                    rel_query = """
                    MATCH (alert:Alert {id: $alert_id})
                    MATCH (ta:ThreatActor {name: $actor_name})
                    MERGE (alert)-[r:ATTRIBUTED_TO {
                        confidence: $confidence,
                        evidence: $evidence,
                        first_seen: $first_seen,
                        attribution_method: $attribution_method
                    }]->(ta)
                    """

                    await tx.run(
                        rel_query,
                        {
                            "alert_id": alert.id,
                            "actor_name": actor_name,
                            **attribution_rel.properties,
                        },
                    )

        except Exception as e:
            logger.error(f"Error creating threat actor relationships: {e}")

    async def _apply_security_labels(self, alert: Alert, tx: AsyncSession) -> None:
        """Apply security classification labels to nodes"""

        try:
            # Apply security labels to alert
            security_labels = []

            if alert.classification == AlertClassification.CRITICAL:
                security_labels.append("CriticalThreat")
            elif alert.classification == AlertClassification.HIGH:
                security_labels.append("HighThreat")
            elif alert.classification == AlertClassification.MEDIUM:
                security_labels.append("MediumThreat")
            elif alert.classification == AlertClassification.LOW:
                security_labels.append("LowThreat")
            else:
                security_labels.append("Informational")

            # Add workflow labels
            if alert.workflow_classification == WorkflowClassification.AUTO_CONTAINABLE:
                security_labels.append("AutoContainable")
            elif (
                alert.workflow_classification == WorkflowClassification.AUTO_ENRICHABLE
            ):
                security_labels.append("AutoEnrichable")

            # Add escalation labels
            if alert.escalation_level == EscalationLevel.SOC_MANAGER:
                security_labels.append("SOCManagerEscalation")
            elif alert.escalation_level == EscalationLevel.SECURITY_ENGINEERING:
                security_labels.append("SecurityEngineeringEscalation")

            # Apply labels
            for label in security_labels:
                label_query = f"""
                MATCH (alert:Alert {{id: $alert_id}})
                SET alert:{label}
                """
                await tx.run(label_query, {"alert_id": alert.id})

        except Exception as e:
            logger.error(f"Error applying security labels: {e}")

    def _extract_related_entities(self, alert_data: Dict[str, Any]) -> Dict[str, Any]:
        """Extract related entities from alert data"""
        entities = {"assets": [], "events": [], "iocs": [], "users": []}

        # Extract from relationships
        if "relationships" in alert_data:
            relationships = alert_data["relationships"]
            if "assets" in relationships:
                entities["assets"] = relationships["assets"].get("data", [])
            if "events" in relationships:
                entities["events"] = relationships["events"].get("data", [])

        # Extract from comprehensive data
        comprehensive_data = alert_data.get("comprehensive_data", {})
        if "assets" in comprehensive_data:
            entities["assets"].extend(comprehensive_data["assets"])
        if "events" in comprehensive_data:
            entities["events"].extend(comprehensive_data["events"])
        if "iocs" in comprehensive_data:
            entities["iocs"] = comprehensive_data["iocs"]

        return entities

    def _get_max_tactic_priority(self, attack_tactics: List[str]) -> int:
        """Get maximum tactic priority from attack list"""
        if not attack_tactics:
            return 0

        max_priority = 0
        for tactic in attack_tactics:
            if tactic in self.mitre_tactics:
                _, priority = self.mitre_tactics[tactic]
                max_priority = max(max_priority, priority)

        return max_priority

    async def get_alert_with_relationships(
        self, alert_id: str
    ) -> Optional[Dict[str, Any]]:
        """Retrieve alert with all relationships for analysis"""
        try:
            alert_id = sanitize_cypher_input(alert_id)
            db_manager = await self.get_db_manager()

            query = """
            MATCH (alert:Alert {id: $alert_id})
            OPTIONAL MATCH (alert)-[r1:AFFECTS]->(asset:Asset)
            OPTIONAL MATCH (alert)-[r2:RELATED_TO]->(event:Event)
            OPTIONAL MATCH (alert)-[r3:MITIGATES]->(attack:Attack)
            OPTIONAL MATCH (alert)-[r4:INDICATES]->(intel:IntelContext)
            OPTIONAL MATCH (alert)-[r5:ATTRIBUTED_TO]->(ta:ThreatActor)
            OPTIONAL MATCH (alert)-[r6:CORRELATED_TO]->(correlated:Alert)
            RETURN alert,
                   collect(DISTINCT {relationship: r1, node: asset}) as assets,
                   collect(DISTINCT {relationship: r2, node: event}) as events,
                   collect(DISTINCT {relationship: r3, node: attack}) as attacks,
                   collect(DISTINCT {relationship: r4, node: intel}) as intel_contexts,
                   collect(DISTINCT {relationship: r5, node: ta}) as threat_actors,
                   collect(DISTINCT {relationship: r6, node: correlated}) as correlated_alerts
            """

            async with db_manager.get_session() as session:
                result = await session.run(query, {"alert_id": alert_id})
                record = await result.single()

                if not record:
                    return None

                return {
                    "alert": dict(record["alert"]),
                    "assets": [
                        {
                            "relationship": dict(item["relationship"]),
                            "node": dict(item["node"]),
                        }
                        for item in record["assets"]
                        if item["node"]
                    ],
                    "events": [
                        {
                            "relationship": dict(item["relationship"]),
                            "node": dict(item["node"]),
                        }
                        for item in record["events"]
                        if item["node"]
                    ],
                    "attacks": [
                        {
                            "relationship": dict(item["relationship"]),
                            "node": dict(item["node"]),
                        }
                        for item in record["attacks"]
                        if item["node"]
                    ],
                    "intel_contexts": [
                        {
                            "relationship": dict(item["relationship"]),
                            "node": dict(item["node"]),
                        }
                        for item in record["intel_contexts"]
                        if item["node"]
                    ],
                    "threat_actors": [
                        {
                            "relationship": dict(item["relationship"]),
                            "node": dict(item["node"]),
                        }
                        for item in record["threat_actors"]
                        if item["node"]
                    ],
                    "correlated_alerts": [
                        {
                            "relationship": dict(item["relationship"]),
                            "node": dict(item["node"]),
                        }
                        for item in record["correlated_alerts"]
                        if item["node"]
                    ],
                }

        except Neo4jError as e:
            logger.error(
                f"Neo4j error retrieving alert with relationships {alert_id}: {e}"
            )
            raise Neo4jQueryException(
                "Database error retrieving alert with relationships",
                error_code="GET_ALERT_RELATIONSHIPS_FAILED",
                details={"alert_id": alert_id, "neo4j_error": str(e)},
            )
        except Exception as e:
            logger.error(
                f"Unexpected error retrieving alert with relationships {alert_id}: {e}"
            )
            raise AlertProcessingException(
                "Failed to retrieve alert with relationships",
                error_code="ALERT_RELATIONSHIPS_RETRIEVE_ERROR",
                details={"alert_id": alert_id, "error": str(e)},
            )
