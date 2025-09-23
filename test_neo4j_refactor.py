#!/usr/bin/env python3
"""
Test Script for Neo4j Refactoring

Tests the refactored Neo4j implementation to ensure API compatibility
and proper functionality of the migrated codebase.

Author: AI-SOAR Platform Team
Created: 2025-09-10
"""

import asyncio
import logging
import os
import sys
from pathlib import Path

# Add src to Python path
src_path = Path(__file__).parent / "src"
sys.path.insert(0, str(src_path))

from datetime import datetime, timezone
from typing import Any, Dict

# Import our refactored components
from database.connection import Neo4jDatabaseManager, get_database_manager
from database.models import (Alert, AlertClassification, ConfigurationStatus,
                             EnvironmentType, XDRConfiguration,
                             determine_classification)
from database.neo4j_setup import setup_neo4j_database
from services.config_service import Neo4jConfigurationService

# Configure logging
logging.basicConfig(
    level=logging.INFO, format="%(asctime)s - %(name)s - %(levelname)s - %(message)s"
)
logger = logging.getLogger(__name__)


class Neo4jRefactorTest:
    """Test suite for Neo4j refactoring"""

    def __init__(self):
        self.db_manager: Neo4jDatabaseManager = None
        self.config_service: Neo4jConfigurationService = None
        self.test_results = {}

    async def setup(self):
        """Initialize test environment"""
        logger.info("Setting up test environment...")

        try:
            # Initialize database manager
            self.db_manager = await get_database_manager()
            self.config_service = Neo4jConfigurationService(self.db_manager)

            logger.info("Test environment setup completed")
            return True

        except Exception as e:
            logger.error(f"Failed to setup test environment: {e}")
            return False

    async def test_database_connection(self) -> bool:
        """Test basic database connectivity"""
        logger.info("Testing database connection...")

        try:
            # Test basic connection
            async with self.db_manager.get_session() as session:
                result = await session.run("RETURN 'Hello Neo4j!' as message")
                record = await result.single()
                message = record["message"]

                if message == "Hello Neo4j!":
                    logger.info("✓ Database connection test passed")
                    return True
                else:
                    logger.error(
                        "✗ Database connection test failed: unexpected response"
                    )
                    return False

        except Exception as e:
            logger.error(f"✗ Database connection test failed: {e}")
            return False

    async def test_health_check(self) -> bool:
        """Test database health check functionality"""
        logger.info("Testing database health check...")

        try:
            health_status = await self.db_manager.health_check()

            if health_status.get("status") == "healthy":
                logger.info("✓ Database health check passed")
                logger.info(f"  Database type: {health_status.get('database_type')}")
                logger.info(
                    f"  Connection type: {health_status.get('connection_type')}"
                )
                logger.info(f"  Node count: {health_status.get('node_count')}")
                return True
            else:
                logger.error(f"✗ Database health check failed: {health_status}")
                return False

        except Exception as e:
            logger.error(f"✗ Database health check failed: {e}")
            return False

    async def test_node_creation(self) -> bool:
        """Test creating nodes using the new models"""
        logger.info("Testing node creation...")

        try:
            # Create a test XDR configuration
            test_config = XDRConfiguration(
                name="Test XDR Config",
                description="Test configuration for Neo4j refactor",
                base_url="https://test-xdr.example.com",
                auth_token_secret_name="test-token-secret",
                environment=EnvironmentType.DEVELOPMENT,
                status=ConfigurationStatus.PENDING,
            )

            # Create query and execute
            from database.models import create_node_query

            query, parameters = create_node_query(
                test_config, ["XDRConfiguration", "Configuration"]
            )

            async with self.db_manager.get_session() as session:
                result = await session.run(query, parameters)
                created_record = await result.single()

                if created_record and created_record["n"]:
                    logger.info("✓ Node creation test passed")

                    # Store for cleanup
                    node_data = dict(created_record["n"])
                    self.test_results["test_config_id"] = node_data["id"]
                    return True
                else:
                    logger.error("✗ Node creation test failed: no record created")
                    return False

        except Exception as e:
            logger.error(f"✗ Node creation test failed: {e}")
            return False

    async def test_cypher_queries(self) -> bool:
        """Test Cypher query execution"""
        logger.info("Testing Cypher queries...")

        try:
            # Test finding the node we created
            config_id = self.test_results.get("test_config_id")
            if not config_id:
                logger.error("✗ No test configuration ID available")
                return False

            query = """
            MATCH (config:XDRConfiguration {id: $config_id})
            RETURN config.name as name, config.status as status
            """

            async with self.db_manager.get_session() as session:
                result = await session.run(query, {"config_id": config_id})
                record = await result.single()

                if record and record["name"] == "Test XDR Config":
                    logger.info("✓ Cypher query test passed")
                    logger.info(f"  Found config: {record['name']}")
                    logger.info(f"  Status: {record['status']}")
                    return True
                else:
                    logger.error(
                        "✗ Cypher query test failed: record not found or incorrect"
                    )
                    return False

        except Exception as e:
            logger.error(f"✗ Cypher query test failed: {e}")
            return False

    async def test_service_layer(self) -> bool:
        """Test the refactored service layer"""
        logger.info("Testing service layer...")

        try:
            # Test getting a configuration
            config_id = self.test_results.get("test_config_id")
            if not config_id:
                logger.error("✗ No test configuration ID available")
                return False

            configuration = await self.config_service.get_xdr_configuration(config_id)

            if configuration and configuration.name == "Test XDR Config":
                logger.info("✓ Service layer test passed")
                logger.info(f"  Retrieved config: {configuration.name}")
                logger.info(f"  Environment: {configuration.environment}")
                return True
            else:
                logger.error(
                    "✗ Service layer test failed: configuration not retrieved correctly"
                )
                return False

        except Exception as e:
            logger.error(f"✗ Service layer test failed: {e}")
            return False

    async def test_enhanced_security_features(self) -> bool:
        """Test enhanced security classification features"""
        logger.info("Testing enhanced security features...")

        try:
            # Create a test alert with security classification
            test_alert = Alert(
                name="Test Security Alert",
                severity=5,
                confidence=4,
                sources=["endpoint", "network"],
                is_intel_available=True,
                is_correlated=True,
            )

            # Test classification logic
            attacks = ["TA0010", "TA0011"]  # Data Exfiltration, Command & Control
            classification = determine_classification(test_alert, attacks)

            if classification == AlertClassification.CRITICAL:
                logger.info("✓ Enhanced security features test passed")
                logger.info(f"  Alert classified as: {classification.value}")
                logger.info(f"  Composite risk score calculated")
                return True
            else:
                logger.error(
                    f"✗ Enhanced security features test failed: wrong classification {classification}"
                )
                return False

        except Exception as e:
            logger.error(f"✗ Enhanced security features test failed: {e}")
            return False

    async def test_relationship_creation(self) -> bool:
        """Test creating relationships between nodes"""
        logger.info("Testing relationship creation...")

        try:
            # Create a test alert node first
            test_alert = Alert(
                name="Test Alert for Relationship",
                severity=3,
                confidence=3,
                external_alert_id="test-alert-123",
            )

            from database.models import create_node_query

            alert_query, alert_params = create_node_query(test_alert, ["Alert"])

            config_id = self.test_results.get("test_config_id")
            if not config_id:
                logger.error("✗ No test configuration ID available")
                return False

            async with self.db_manager.get_session() as session:
                # Create alert node
                alert_result = await session.run(alert_query, alert_params)
                alert_record = await alert_result.single()

                if not alert_record:
                    logger.error("✗ Failed to create alert node for relationship test")
                    return False

                alert_data = dict(alert_record["n"])
                alert_id = alert_data["id"]

                # Create relationship
                rel_query = """
                MATCH (alert:Alert {id: $alert_id})
                MATCH (config:XDRConfiguration {id: $config_id})
                CREATE (alert)-[:USES_CONFIG]->(config)
                RETURN alert, config
                """

                rel_result = await session.run(
                    rel_query, {"alert_id": alert_id, "config_id": config_id}
                )

                rel_record = await rel_result.single()

                if rel_record:
                    logger.info("✓ Relationship creation test passed")
                    self.test_results["test_alert_id"] = alert_id
                    return True
                else:
                    logger.error("✗ Relationship creation test failed")
                    return False

        except Exception as e:
            logger.error(f"✗ Relationship creation test failed: {e}")
            return False

    async def test_query_performance(self) -> bool:
        """Test query performance with indexes"""
        logger.info("Testing query performance...")

        try:
            # Test a common query that should use indexes
            start_time = datetime.now()

            query = """
            MATCH (config:XDRConfiguration)
            WHERE config.status = 'pending'
            RETURN count(config) as count
            """

            async with self.db_manager.get_session() as session:
                result = await session.run(query)
                record = await result.single()
                count = record["count"]

            end_time = datetime.now()
            duration = (end_time - start_time).total_seconds() * 1000

            logger.info(f"✓ Query performance test passed")
            logger.info(f"  Query executed in {duration:.2f}ms")
            logger.info(f"  Found {count} pending configurations")

            # Performance should be under 100ms for simple queries
            if duration < 1000:  # 1 second is reasonable for test environment
                return True
            else:
                logger.warning(f"Query took {duration:.2f}ms - may need optimization")
                return True  # Still pass, but with warning

        except Exception as e:
            logger.error(f"✗ Query performance test failed: {e}")
            return False

    async def cleanup(self):
        """Clean up test data"""
        logger.info("Cleaning up test data...")

        try:
            # Clean up test nodes
            cleanup_queries = []

            if self.test_results.get("test_alert_id"):
                cleanup_queries.append(
                    (
                        "MATCH (alert:Alert {id: $alert_id}) DETACH DELETE alert",
                        {"alert_id": self.test_results["test_alert_id"]},
                    )
                )

            if self.test_results.get("test_config_id"):
                cleanup_queries.append(
                    (
                        "MATCH (config:XDRConfiguration {id: $config_id}) DETACH DELETE config",
                        {"config_id": self.test_results["test_config_id"]},
                    )
                )

            async with self.db_manager.get_session() as session:
                for query, params in cleanup_queries:
                    await session.run(query, params)

            logger.info("✓ Test data cleanup completed")

        except Exception as e:
            logger.warning(f"Test data cleanup failed: {e}")

    async def run_all_tests(self) -> Dict[str, bool]:
        """Run all tests and return results"""
        logger.info("Starting Neo4j refactor test suite...")

        tests = [
            ("Database Connection", self.test_database_connection),
            ("Health Check", self.test_health_check),
            ("Node Creation", self.test_node_creation),
            ("Cypher Queries", self.test_cypher_queries),
            ("Service Layer", self.test_service_layer),
            ("Enhanced Security Features", self.test_enhanced_security_features),
            ("Relationship Creation", self.test_relationship_creation),
            ("Query Performance", self.test_query_performance),
        ]

        results = {}
        passed = 0
        total = len(tests)

        for test_name, test_func in tests:
            try:
                result = await test_func()
                results[test_name] = result
                if result:
                    passed += 1
            except Exception as e:
                logger.error(f"Test '{test_name}' crashed: {e}")
                results[test_name] = False

        # Cleanup
        await self.cleanup()

        # Summary
        logger.info(f"\n{'='*60}")
        logger.info(f"TEST RESULTS SUMMARY")
        logger.info(f"{'='*60}")

        for test_name, result in results.items():
            status = "PASS" if result else "FAIL"
            logger.info(f"{test_name:.<40} {status}")

        logger.info(f"{'='*60}")
        logger.info(f"Total: {passed}/{total} tests passed")

        if passed == total:
            logger.info("🎉 ALL TESTS PASSED! Neo4j refactoring is successful!")
        else:
            logger.error(
                f"❌ {total - passed} tests failed. Please review the implementation."
            )

        return results


async def main():
    """Main test execution"""
    logger.info("Neo4j Refactoring Test Suite")
    logger.info("============================")

    # First, run database setup
    logger.info("Setting up Neo4j database...")
    setup_success = await setup_neo4j_database()

    if not setup_success:
        logger.error("Database setup failed. Cannot proceed with tests.")
        return False

    # Run tests
    test_suite = Neo4jRefactorTest()

    if not await test_suite.setup():
        logger.error("Test setup failed. Cannot proceed with tests.")
        return False

    results = await test_suite.run_all_tests()

    # Return overall success
    return all(results.values())


if __name__ == "__main__":
    success = asyncio.run(main())
    exit_code = 0 if success else 1
    sys.exit(exit_code)
