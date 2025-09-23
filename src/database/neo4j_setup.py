"""
Neo4j Database Setup and Optimization

Sets up indexes, constraints, and other optimizations for the AI-SOAR Platform
Neo4j database based on the enhanced security schema.

Author: AI-SOAR Platform Team
Created: 2025-09-10
"""

import asyncio
import logging
from typing import Any, Dict, List

from .connection import Neo4jDatabaseManager, get_database_manager

logger = logging.getLogger(__name__)


class Neo4jSetup:
    """Handles Neo4j database setup, indexes, and constraints"""

    def __init__(self, db_manager: Neo4jDatabaseManager):
        self.db_manager = db_manager

    async def setup_all(self):
        """Run complete database setup"""
        logger.info("Starting Neo4j database setup...")

        await self.create_constraints()
        await self.create_indexes()
        await self.setup_security_labels()

        logger.info("Neo4j database setup completed successfully")

    async def create_constraints(self):
        """Create unique constraints for primary keys"""
        logger.info("Creating Neo4j constraints...")

        constraints = [
            # Unique constraints for primary keys
            "CREATE CONSTRAINT alert_id_unique IF NOT EXISTS FOR (a:Alert) REQUIRE a.id IS UNIQUE",
            "CREATE CONSTRAINT event_id_unique IF NOT EXISTS FOR (e:Event) REQUIRE e.id IS UNIQUE",
            "CREATE CONSTRAINT asset_id_unique IF NOT EXISTS FOR (asset:Asset) REQUIRE asset.id IS UNIQUE",
            "CREATE CONSTRAINT user_id_unique IF NOT EXISTS FOR (u:User) REQUIRE u.id IS UNIQUE",
            "CREATE CONSTRAINT attack_technique_unique IF NOT EXISTS FOR (att:Attack) REQUIRE att.technique_id IS UNIQUE",
            "CREATE CONSTRAINT case_id_unique IF NOT EXISTS FOR (c:Case) REQUIRE c.id IS UNIQUE",
            "CREATE CONSTRAINT tag_id_unique IF NOT EXISTS FOR (t:Tag) REQUIRE t.id IS UNIQUE",
            "CREATE CONSTRAINT note_id_unique IF NOT EXISTS FOR (n:Note) REQUIRE n.id IS UNIQUE",
            "CREATE CONSTRAINT intel_context_unique IF NOT EXISTS FOR (ic:IntelContext) REQUIRE (ic.type, ic.value) IS UNIQUE",
            "CREATE CONSTRAINT threat_actor_id_unique IF NOT EXISTS FOR (ta:ThreatActor) REQUIRE ta.id IS UNIQUE",
            # Configuration constraints
            "CREATE CONSTRAINT xdr_config_id_unique IF NOT EXISTS FOR (xdr:XDRConfiguration) REQUIRE xdr.id IS UNIQUE",
            "CREATE CONSTRAINT polling_session_id_unique IF NOT EXISTS FOR (ps:PollingSession) REQUIRE ps.id IS UNIQUE",
            "CREATE CONSTRAINT mcp_server_id_unique IF NOT EXISTS FOR (mcp:MCPServerConfiguration) REQUIRE mcp.id IS UNIQUE",
            "CREATE CONSTRAINT system_config_key_unique IF NOT EXISTS FOR (sc:SystemConfiguration) REQUIRE sc.config_key IS UNIQUE",
            # Business logic constraints
            "CREATE CONSTRAINT xdr_config_name_env_unique IF NOT EXISTS FOR (xdr:XDRConfiguration) REQUIRE (xdr.name, xdr.environment) IS UNIQUE",
            "CREATE CONSTRAINT mcp_server_name_unique IF NOT EXISTS FOR (mcp:MCPServerConfiguration) REQUIRE mcp.name IS UNIQUE",
        ]

        async with self.db_manager.get_session() as session:
            for constraint in constraints:
                try:
                    await session.run(constraint)
                    logger.debug(f"Created constraint: {constraint}")
                except Exception as e:
                    logger.warning(f"Failed to create constraint {constraint}: {e}")

    async def create_indexes(self):
        """Create performance indexes"""
        logger.info("Creating Neo4j indexes...")

        indexes = [
            # Alert indexes for common queries
            "CREATE INDEX alert_severity_idx IF NOT EXISTS FOR (a:Alert) ON (a.severity)",
            "CREATE INDEX alert_classification_idx IF NOT EXISTS FOR (a:Alert) ON (a.classification)",
            "CREATE INDEX alert_status_idx IF NOT EXISTS FOR (a:Alert) ON (a.status)",
            "CREATE INDEX alert_assignee_idx IF NOT EXISTS FOR (a:Alert) ON (a.assignee)",
            "CREATE INDEX alert_created_at_idx IF NOT EXISTS FOR (a:Alert) ON (a.created_at)",
            "CREATE INDEX alert_composite_risk_idx IF NOT EXISTS FOR (a:Alert) ON (a.composite_risk_score)",
            "CREATE INDEX alert_customer_id_idx IF NOT EXISTS FOR (a:Alert) ON (a.customer_id)",
            "CREATE INDEX alert_tenant_id_idx IF NOT EXISTS FOR (a:Alert) ON (a.tenant_id)",
            "CREATE INDEX alert_external_id_idx IF NOT EXISTS FOR (a:Alert) ON (a.external_alert_id)",
            "CREATE INDEX alert_escalation_level_idx IF NOT EXISTS FOR (a:Alert) ON (a.escalation_level)",
            "CREATE INDEX alert_response_sla_idx IF NOT EXISTS FOR (a:Alert) ON (a.response_sla)",
            # Event indexes
            "CREATE INDEX event_severity_idx IF NOT EXISTS FOR (e:Event) ON (e.severity)",
            "CREATE INDEX event_created_at_idx IF NOT EXISTS FOR (e:Event) ON (e.created_at)",
            "CREATE INDEX event_source_idx IF NOT EXISTS FOR (e:Event) ON (e.source)",
            "CREATE INDEX event_customer_id_idx IF NOT EXISTS FOR (e:Event) ON (e.customer_id)",
            "CREATE INDEX event_time_idx IF NOT EXISTS FOR (e:Event) ON (e.time)",
            # Asset indexes
            "CREATE INDEX asset_type_idx IF NOT EXISTS FOR (asset:Asset) ON (asset.type)",
            "CREATE INDEX asset_criticality_idx IF NOT EXISTS FOR (asset:Asset) ON (asset.criticality)",
            "CREATE INDEX asset_business_impact_idx IF NOT EXISTS FOR (asset:Asset) ON (asset.business_impact)",
            "CREATE INDEX asset_status_idx IF NOT EXISTS FOR (asset:Asset) ON (asset.status)",
            "CREATE INDEX asset_owner_idx IF NOT EXISTS FOR (asset:Asset) ON (asset.owner)",
            "CREATE INDEX asset_customer_id_idx IF NOT EXISTS FOR (asset:Asset) ON (asset.customer_id)",
            # User indexes
            "CREATE INDEX user_email_idx IF NOT EXISTS FOR (u:User) ON (u.email)",
            "CREATE INDEX user_role_idx IF NOT EXISTS FOR (u:User) ON (u.role)",
            "CREATE INDEX user_department_idx IF NOT EXISTS FOR (u:User) ON (u.department)",
            # Attack/MITRE indexes
            "CREATE INDEX attack_tactic_idx IF NOT EXISTS FOR (att:Attack) ON (att.tactic)",
            "CREATE INDEX attack_tactic_id_idx IF NOT EXISTS FOR (att:Attack) ON (att.tactic_id)",
            "CREATE INDEX attack_priority_idx IF NOT EXISTS FOR (att:Attack) ON (att.tactic_priority)",
            # Case indexes
            "CREATE INDEX case_status_idx IF NOT EXISTS FOR (c:Case) ON (c.status)",
            "CREATE INDEX case_priority_idx IF NOT EXISTS FOR (c:Case) ON (c.priority)",
            "CREATE INDEX case_customer_id_idx IF NOT EXISTS FOR (c:Case) ON (c.customer_id)",
            # Intelligence context indexes
            "CREATE INDEX intel_type_idx IF NOT EXISTS FOR (ic:IntelContext) ON (ic.type)",
            "CREATE INDEX intel_source_idx IF NOT EXISTS FOR (ic:IntelContext) ON (ic.source)",
            "CREATE INDEX intel_confidence_idx IF NOT EXISTS FOR (ic:IntelContext) ON (ic.confidence)",
            "CREATE INDEX intel_first_seen_idx IF NOT EXISTS FOR (ic:IntelContext) ON (ic.first_seen)",
            "CREATE INDEX intel_last_seen_idx IF NOT EXISTS FOR (ic:IntelContext) ON (ic.last_seen)",
            # Threat actor indexes
            "CREATE INDEX threat_actor_name_idx IF NOT EXISTS FOR (ta:ThreatActor) ON (ta.name)",
            "CREATE INDEX threat_actor_country_idx IF NOT EXISTS FOR (ta:ThreatActor) ON (ta.country)",
            "CREATE INDEX threat_actor_confidence_idx IF NOT EXISTS FOR (ta:ThreatActor) ON (ta.attribution_confidence)",
            # Configuration indexes
            "CREATE INDEX xdr_config_status_idx IF NOT EXISTS FOR (xdr:XDRConfiguration) ON (xdr.status)",
            "CREATE INDEX xdr_config_environment_idx IF NOT EXISTS FOR (xdr:XDRConfiguration) ON (xdr.environment)",
            "CREATE INDEX xdr_config_poll_enabled_idx IF NOT EXISTS FOR (xdr:XDRConfiguration) ON (xdr.poll_enabled)",
            "CREATE INDEX xdr_config_name_idx IF NOT EXISTS FOR (xdr:XDRConfiguration) ON (xdr.name)",
            # Polling session indexes
            "CREATE INDEX polling_session_status_idx IF NOT EXISTS FOR (ps:PollingSession) ON (ps.status)",
            "CREATE INDEX polling_session_start_idx IF NOT EXISTS FOR (ps:PollingSession) ON (ps.session_start)",
            "CREATE INDEX polling_session_config_id_idx IF NOT EXISTS FOR (ps:PollingSession) ON (ps.configuration_id)",
            # MCP server indexes
            "CREATE INDEX mcp_server_type_idx IF NOT EXISTS FOR (mcp:MCPServerConfiguration) ON (mcp.server_type)",
            "CREATE INDEX mcp_server_enabled_idx IF NOT EXISTS FOR (mcp:MCPServerConfiguration) ON (mcp.enabled)",
            "CREATE INDEX mcp_server_priority_idx IF NOT EXISTS FOR (mcp:MCPServerConfiguration) ON (mcp.priority)",
            # System configuration indexes
            "CREATE INDEX system_config_type_idx IF NOT EXISTS FOR (sc:SystemConfiguration) ON (sc.config_type)",
            "CREATE INDEX system_config_environment_idx IF NOT EXISTS FOR (sc:SystemConfiguration) ON (sc.environment)",
        ]

        # Composite indexes for common query patterns
        composite_indexes = [
            # Customer + Classification filtering
            "CREATE INDEX alert_customer_classification_idx IF NOT EXISTS FOR (a:Alert) ON (a.customer_id, a.classification)",
            "CREATE INDEX alert_customer_status_idx IF NOT EXISTS FOR (a:Alert) ON (a.customer_id, a.status)",
            "CREATE INDEX alert_customer_severity_idx IF NOT EXISTS FOR (a:Alert) ON (a.customer_id, a.severity)",
            "CREATE INDEX alert_customer_risk_score_idx IF NOT EXISTS FOR (a:Alert) ON (a.customer_id, a.composite_risk_score)",
            # Time-based queries
            "CREATE INDEX alert_created_status_idx IF NOT EXISTS FOR (a:Alert) ON (a.created_at, a.status)",
            "CREATE INDEX event_time_source_idx IF NOT EXISTS FOR (e:Event) ON (e.time, e.source)",
            # Asset criticality queries
            "CREATE INDEX asset_customer_criticality_idx IF NOT EXISTS FOR (asset:Asset) ON (asset.customer_id, asset.criticality)",
            # Configuration environment queries
            "CREATE INDEX config_env_status_idx IF NOT EXISTS FOR (xdr:XDRConfiguration) ON (xdr.environment, xdr.status)",
        ]

        all_indexes = indexes + composite_indexes

        async with self.db_manager.get_session() as session:
            for index in all_indexes:
                try:
                    await session.run(index)
                    logger.debug(f"Created index: {index}")
                except Exception as e:
                    logger.warning(f"Failed to create index {index}: {e}")

    async def setup_security_labels(self):
        """Setup security classification labels"""
        logger.info("Setting up security classification labels...")

        # Create label indexes for security classifications
        security_label_indexes = [
            "CREATE INDEX critical_threat_idx IF NOT EXISTS FOR (a:CriticalThreat) ON (a.created_at)",
            "CREATE INDEX high_threat_idx IF NOT EXISTS FOR (a:HighThreat) ON (a.created_at)",
            "CREATE INDEX medium_threat_idx IF NOT EXISTS FOR (a:MediumThreat) ON (a.created_at)",
            "CREATE INDEX low_threat_idx IF NOT EXISTS FOR (a:LowThreat) ON (a.created_at)",
            "CREATE INDEX apt_threat_idx IF NOT EXISTS FOR (a:APT) ON (a.created_at)",
            "CREATE INDEX ransomware_threat_idx IF NOT EXISTS FOR (a:Ransomware) ON (a.created_at)",
            "CREATE INDEX data_exfil_threat_idx IF NOT EXISTS FOR (a:DataExfiltration) ON (a.created_at)",
        ]

        async with self.db_manager.get_session() as session:
            for index in security_label_indexes:
                try:
                    await session.run(index)
                    logger.debug(f"Created security label index: {index}")
                except Exception as e:
                    logger.warning(
                        f"Failed to create security label index {index}: {e}"
                    )

    async def create_mitre_attack_data(self):
        """Populate MITRE ATT&CK framework data"""
        logger.info("Creating MITRE ATT&CK framework data...")

        # Common MITRE ATT&CK tactics with priorities
        mitre_tactics = [
            {"technique_id": "TA0001", "name": "Initial Access", "tactic_priority": 1},
            {"technique_id": "TA0002", "name": "Execution", "tactic_priority": 2},
            {"technique_id": "TA0003", "name": "Persistence", "tactic_priority": 3},
            {
                "technique_id": "TA0004",
                "name": "Privilege Escalation",
                "tactic_priority": 4,
            },
            {"technique_id": "TA0005", "name": "Defense Evasion", "tactic_priority": 3},
            {
                "technique_id": "TA0006",
                "name": "Credential Access",
                "tactic_priority": 5,
            },
            {"technique_id": "TA0007", "name": "Discovery", "tactic_priority": 2},
            {
                "technique_id": "TA0008",
                "name": "Lateral Movement",
                "tactic_priority": 4,
            },
            {"technique_id": "TA0009", "name": "Collection", "tactic_priority": 3},
            {"technique_id": "TA0010", "name": "Exfiltration", "tactic_priority": 5},
            {
                "technique_id": "TA0011",
                "name": "Command and Control",
                "tactic_priority": 5,
            },
            {"technique_id": "TA0040", "name": "Impact", "tactic_priority": 5},
            {"technique_id": "TA0043", "name": "Reconnaissance", "tactic_priority": 1},
        ]

        create_tactic_query = """
        MERGE (att:Attack {technique_id: $technique_id})
        SET att.name = $name,
            att.tactic = $technique_id + ' - ' + $name,
            att.tactic_priority = $tactic_priority,
            att.tactic_name = $name,
            att.tactic_id = $technique_id,
            att.created_at = datetime(),
            att.updated_at = datetime()
        RETURN att
        """

        async with self.db_manager.get_session() as session:
            for tactic in mitre_tactics:
                try:
                    await session.run(create_tactic_query, tactic)
                    logger.debug(f"Created MITRE tactic: {tactic['technique_id']}")
                except Exception as e:
                    logger.warning(
                        f"Failed to create MITRE tactic {tactic['technique_id']}: {e}"
                    )

    async def get_database_stats(self) -> Dict[str, Any]:
        """Get database statistics after setup"""
        logger.info("Collecting database statistics...")

        stats_queries = {
            "total_nodes": "MATCH (n) RETURN count(n) as count",
            "total_relationships": "MATCH ()-[r]->() RETURN count(r) as count",
            "alerts": "MATCH (a:Alert) RETURN count(a) as count",
            "events": "MATCH (e:Event) RETURN count(e) as count",
            "assets": "MATCH (asset:Asset) RETURN count(asset) as count",
            "configurations": "MATCH (c:XDRConfiguration) RETURN count(c) as count",
            "critical_alerts": "MATCH (a:CriticalThreat) RETURN count(a) as count",
            "high_alerts": "MATCH (a:HighThreat) RETURN count(a) as count",
            "constraints": "SHOW CONSTRAINTS YIELD name RETURN count(name) as count",
            "indexes": "SHOW INDEXES YIELD name RETURN count(name) as count",
        }

        stats = {}
        async with self.db_manager.get_session() as session:
            for stat_name, query in stats_queries.items():
                try:
                    result = await session.run(query)
                    record = await result.single()
                    stats[stat_name] = record["count"] if record else 0
                except Exception as e:
                    logger.warning(f"Failed to get stat {stat_name}: {e}")
                    stats[stat_name] = 0

        logger.info(f"Database statistics: {stats}")
        return stats

    async def validate_setup(self) -> bool:
        """Validate that the database setup is correct"""
        logger.info("Validating database setup...")

        try:
            # Check basic connectivity
            async with self.db_manager.get_session() as session:
                result = await session.run("RETURN 1 as test")
                test_record = await result.single()
                if not test_record or test_record["test"] != 1:
                    return False

            # Get statistics to validate setup
            stats = await self.get_database_stats()

            # Basic validation checks
            if stats.get("constraints", 0) < 10:
                logger.warning("Insufficient constraints created")
                return False

            if stats.get("indexes", 0) < 20:
                logger.warning("Insufficient indexes created")
                return False

            logger.info("Database setup validation passed")
            return True

        except Exception as e:
            logger.error(f"Database setup validation failed: {e}")
            return False


async def setup_neo4j_database():
    """Main setup function"""
    try:
        db_manager = await get_database_manager()
        setup = Neo4jSetup(db_manager)

        await setup.setup_all()
        await setup.create_mitre_attack_data()

        # Validate setup
        if await setup.validate_setup():
            logger.info("Neo4j database setup completed successfully")
            return True
        else:
            logger.error("Neo4j database setup validation failed")
            return False

    except Exception as e:
        logger.error(f"Neo4j database setup failed: {e}")
        return False


if __name__ == "__main__":
    logging.basicConfig(level=logging.INFO)
    asyncio.run(setup_neo4j_database())
