#!/usr/bin/env python3
"""
Test Enhanced Neo4j Integration

Comprehensive test script to validate the enhanced Neo4j database population
with security analysis, MITRE ATT&CK mapping, and threat intelligence correlation.

Usage:
    python test_enhanced_neo4j_integration.py

Author: AI-SOAR Platform Team
Created: 2025-09-22 - Enhanced Neo4j Integration Testing
"""

import asyncio
import json
import logging
import sys
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Dict, List

# Configure logging
logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s - %(name)s - %(levelname)s - %(message)s",
    handlers=[
        logging.StreamHandler(sys.stdout),
        logging.FileHandler("test_enhanced_neo4j.log"),
    ],
)
logger = logging.getLogger("test_enhanced_neo4j")

# Add src to path for imports
sys.path.append(str(Path(__file__).parent / "src"))

from database.models import AlertClassification, WorkflowClassification
from services.enhanced_neo4j_population_service import \
    EnhancedNeo4jPopulationService
from services.service_coordinator import get_service_coordinator


class EnhancedNeo4jIntegrationTester:
    """Comprehensive tester for enhanced Neo4j integration"""

    def __init__(self):
        self.service_coordinator = None
        self.enhanced_service = None
        self.test_results = {"passed": 0, "failed": 0, "errors": [], "test_details": []}

    async def setup(self) -> bool:
        """Setup test environment"""
        try:
            logger.info("Setting up test environment...")

            # Initialize service coordinator
            self.service_coordinator = await get_service_coordinator()

            # Get enhanced Neo4j service
            self.enhanced_service = await self.service_coordinator.enhanced_neo4j

            # Test database connectivity
            db_manager = await self.enhanced_service.get_db_manager()
            health = await db_manager.health_check()

            if not health.get("connected", False):
                logger.error("Database connection failed")
                return False

            logger.info("Test environment setup complete")
            return True

        except Exception as e:
            logger.error(f"Failed to setup test environment: {e}")
            return False

    def create_comprehensive_test_alert(self) -> Dict[str, Any]:
        """Create a comprehensive test alert with all enhanced data"""
        return {
            "id": f"test_alert_{int(datetime.now().timestamp())}",
            "type": "alert",
            "attributes": {
                "tenantId": "test-tenant-123",
                "customerId": "test-customer-456",
                "name": "Critical APT Attack - Privilege Escalation and Data Exfiltration",
                "message": "Detected sophisticated attack with privilege escalation, lateral movement, and potential data exfiltration. IOCs include suspicious IP 192.168.1.100 and domain evil.com. Hash: d41d8cd98f00b204e9800998ecf8427e",
                "severity": 5,
                "score": 85,
                "confidence": 4,
                "risk": 5,
                "ruleId": "apt_privilege_escalation_exfiltration",
                "generatedBy": "Trellix",
                "sources": ["endpoint", "network", "email"],
                "isSilent": False,
                "isIntelAvailable": True,
                "isSuppressed": False,
                "status": "NEW",
                "assignee": None,
                "alertMetadataSuppressed": False,
                "genai_name": "AI-Generated: Advanced Persistent Threat Campaign",
                "genai_summary": "Multi-stage attack with clear APT characteristics including privilege escalation and data exfiltration attempts",
                "ruleOrigin": "Custom",
                "createdAt": datetime.now(timezone.utc).isoformat(),
                "isCorrelated": True,
                "totalEventMatchCount": 15,
                "alertAggregationCount": 3,
                "lastAggregatedTime": datetime.now(timezone.utc).isoformat(),
                "inTimeline": True,
                "inPin": False,
            },
            "comprehensive_data": {
                "assets": [
                    {
                        "id": "asset_workstation_001",
                        "type": "workstation",
                        "name": "EXEC-PC-001",
                        "hash": "sha256:abc123def456",
                        "source": "xdr_relationships",
                        "criticality": 5,
                        "business_impact": "CRITICAL",
                        "status": "NOT_CONTAINED",
                        "location": "Executive Floor",
                        "owner": "ceo@company.com",
                        "discovery_timestamp": datetime.now(timezone.utc).isoformat(),
                    },
                    {
                        "id": "asset_server_001",
                        "type": "server",
                        "name": "FILE-SRV-001",
                        "source": "xdr_relationships",
                        "criticality": 4,
                        "business_impact": "HIGH",
                        "status": "PENDING",
                        "location": "Data Center",
                        "discovery_timestamp": datetime.now(timezone.utc).isoformat(),
                    },
                ],
                "events": [
                    {
                        "id": "event_001",
                        "type": "security_event",
                        "name": "Privilege Escalation Attempt",
                        "source": "xdr_relationships",
                        "message": "User attempted to escalate privileges using exploit",
                        "severity": 4,
                        "confidence": 4,
                        "time": datetime.now(timezone.utc).isoformat(),
                        "artefact_type": "process",
                        "sanitized": False,
                        "discovery_timestamp": datetime.now(timezone.utc).isoformat(),
                        "correlation_confidence": "high",
                        "iocs": {
                            "process_name": "malicious.exe",
                            "process_path": "C:\\temp\\malicious.exe",
                            "command_line": "malicious.exe -escalate -stealth",
                        },
                    },
                    {
                        "id": "event_002",
                        "type": "security_event",
                        "name": "Lateral Movement Detected",
                        "source": "xdr_relationships",
                        "message": "Suspicious network activity indicating lateral movement",
                        "severity": 4,
                        "confidence": 3,
                        "time": datetime.now(timezone.utc).isoformat(),
                        "artefact_type": "network",
                        "sanitized": False,
                        "discovery_timestamp": datetime.now(timezone.utc).isoformat(),
                        "correlation_confidence": "medium",
                    },
                ],
                "mitre_techniques": [
                    {
                        "technique_id": "TA0004",
                        "tactic_name": "Privilege Escalation",
                        "tactic_priority": 4,
                        "confidence": "high",
                        "detection_method": "rule_analysis",
                        "evidence": {
                            "rule_id": "apt_privilege_escalation_exfiltration",
                            "message_keywords": "privilege escalation exploit",
                        },
                        "discovery_timestamp": datetime.now(timezone.utc).isoformat(),
                    },
                    {
                        "technique_id": "TA0008",
                        "tactic_name": "Lateral Movement",
                        "tactic_priority": 4,
                        "confidence": "medium",
                        "detection_method": "rule_analysis",
                        "evidence": {
                            "rule_id": "apt_privilege_escalation_exfiltration",
                            "message_keywords": "lateral movement network",
                        },
                        "discovery_timestamp": datetime.now(timezone.utc).isoformat(),
                    },
                    {
                        "technique_id": "TA0010",
                        "tactic_name": "Exfiltration",
                        "tactic_priority": 5,
                        "confidence": "medium",
                        "detection_method": "rule_analysis",
                        "evidence": {
                            "rule_id": "apt_privilege_escalation_exfiltration",
                            "message_keywords": "data exfiltration",
                        },
                        "discovery_timestamp": datetime.now(timezone.utc).isoformat(),
                    },
                ],
                "threat_intelligence": [
                    {
                        "type": "ip",
                        "value": "192.168.1.100",
                        "source": "TIP",
                        "confidence": 4,
                        "severity": "HIGH",
                        "threat_actors": ["APT29", "Cozy Bear"],
                        "campaigns": ["SolarWinds Campaign"],
                        "first_seen": datetime.now(timezone.utc).isoformat(),
                        "comment": "Known APT29 command and control infrastructure",
                        "discovery_timestamp": datetime.now(timezone.utc).isoformat(),
                    },
                    {
                        "type": "domain",
                        "value": "evil.com",
                        "source": "Mandiant",
                        "confidence": 5,
                        "severity": "CRITICAL",
                        "threat_actors": ["APT29"],
                        "campaigns": ["Operation Ghost"],
                        "first_seen": datetime.now(timezone.utc).isoformat(),
                        "comment": "APT29 exfiltration domain",
                        "discovery_timestamp": datetime.now(timezone.utc).isoformat(),
                    },
                    {
                        "type": "md5",
                        "value": "d41d8cd98f00b204e9800998ecf8427e",
                        "source": "Internal",
                        "confidence": 3,
                        "severity": "MEDIUM",
                        "threat_actors": [],
                        "campaigns": [],
                        "first_seen": datetime.now(timezone.utc).isoformat(),
                        "comment": "Suspicious hash found in alert content",
                        "discovery_timestamp": datetime.now(timezone.utc).isoformat(),
                    },
                ],
                "iocs": [
                    {
                        "type": "artifact",
                        "value": "malicious.exe",
                        "source": "xdr_artefacts",
                        "discovery_timestamp": datetime.now(timezone.utc).isoformat(),
                        "sanitized": False,
                    },
                    {
                        "type": "event_field",
                        "field_name": "source_ip",
                        "value": "192.168.1.100",
                        "source": "xdr_event_fields",
                        "event_id": "event_001",
                        "discovery_timestamp": datetime.now(timezone.utc).isoformat(),
                        "sanitized": False,
                    },
                ],
                "analysis_metadata": {
                    "collection_timestamp": datetime.now(timezone.utc).isoformat(),
                    "data_sources": [
                        "xdr_api",
                        "asset_management",
                        "event_correlation",
                        "mitre_mapping",
                        "threat_intelligence",
                    ],
                    "correlation_status": "completed",
                },
            },
        }

    async def test_comprehensive_alert_population(self) -> bool:
        """Test comprehensive alert population with all entities and relationships"""
        test_name = "Comprehensive Alert Population"
        logger.info(f"Running test: {test_name}")

        try:
            # Create test alert
            test_alert_data = self.create_comprehensive_test_alert()

            # Populate alert in Neo4j
            populated_alert = (
                await self.enhanced_service.populate_comprehensive_alert_data(
                    test_alert_data
                )
            )

            # Validate alert creation
            if not populated_alert:
                raise Exception("Alert not created")

            # Validate security classification
            expected_classification = (
                AlertClassification.CRITICAL
            )  # Should be CRITICAL due to TA0010 (Exfiltration)
            if populated_alert.classification != expected_classification:
                raise Exception(
                    f"Expected classification {expected_classification}, got {populated_alert.classification}"
                )

            # Validate composite risk score
            if populated_alert.composite_risk_score <= 0:
                raise Exception(
                    f"Invalid composite risk score: {populated_alert.composite_risk_score}"
                )

            # Validate workflow classification
            if populated_alert.workflow_classification not in [
                WorkflowClassification.AUTO_CONTAINABLE,
                WorkflowClassification.MANUAL_REQUIRED,
            ]:
                raise Exception(
                    f"Unexpected workflow classification: {populated_alert.workflow_classification}"
                )

            logger.info(f"✅ {test_name} PASSED")
            logger.info(f"   Alert ID: {populated_alert.id}")
            logger.info(f"   Classification: {populated_alert.classification.value}")
            logger.info(f"   Risk Score: {populated_alert.composite_risk_score}")
            logger.info(f"   Workflow: {populated_alert.workflow_classification.value}")

            self.test_results["test_details"].append(
                {
                    "test": test_name,
                    "status": "PASSED",
                    "alert_id": populated_alert.id,
                    "classification": populated_alert.classification.value,
                    "risk_score": populated_alert.composite_risk_score,
                }
            )

            return True

        except Exception as e:
            logger.error(f"❌ {test_name} FAILED: {e}")
            self.test_results["errors"].append(f"{test_name}: {e}")
            self.test_results["test_details"].append(
                {"test": test_name, "status": "FAILED", "error": str(e)}
            )
            return False

    async def test_alert_relationships_retrieval(self) -> bool:
        """Test retrieval of alert with all comprehensive relationships"""
        test_name = "Alert Relationships Retrieval"
        logger.info(f"Running test: {test_name}")

        try:
            # Get the most recent test alert
            recent_test_details = [
                t for t in self.test_results["test_details"] if t["status"] == "PASSED"
            ]
            if not recent_test_details:
                raise Exception("No successful alert to test with")

            alert_id = recent_test_details[-1]["alert_id"]

            # Retrieve alert with relationships
            alert_with_relationships = (
                await self.enhanced_service.get_alert_with_relationships(alert_id)
            )

            if not alert_with_relationships:
                raise Exception("Alert with relationships not found")

            # Validate relationships
            required_relationships = ["assets", "events", "attacks", "intel_contexts"]
            for rel_type in required_relationships:
                if rel_type not in alert_with_relationships:
                    raise Exception(f"Missing relationship type: {rel_type}")

            # Validate assets
            assets = alert_with_relationships["assets"]
            if len(assets) < 1:
                raise Exception("Expected at least 1 asset relationship")

            # Validate events
            events = alert_with_relationships["events"]
            if len(events) < 1:
                raise Exception("Expected at least 1 event relationship")

            # Validate attacks (MITRE techniques)
            attacks = alert_with_relationships["attacks"]
            if len(attacks) < 1:
                raise Exception("Expected at least 1 attack technique relationship")

            # Validate intel contexts
            intel_contexts = alert_with_relationships["intel_contexts"]
            if len(intel_contexts) < 1:
                raise Exception("Expected at least 1 intel context relationship")

            logger.info(f"✅ {test_name} PASSED")
            logger.info(f"   Assets: {len(assets)}")
            logger.info(f"   Events: {len(events)}")
            logger.info(f"   Attacks: {len(attacks)}")
            logger.info(f"   Intel Contexts: {len(intel_contexts)}")
            logger.info(
                f"   Threat Actors: {len(alert_with_relationships.get('threat_actors', []))}"
            )

            self.test_results["test_details"].append(
                {
                    "test": test_name,
                    "status": "PASSED",
                    "alert_id": alert_id,
                    "relationships": {
                        "assets": len(assets),
                        "events": len(events),
                        "attacks": len(attacks),
                        "intel_contexts": len(intel_contexts),
                        "threat_actors": len(
                            alert_with_relationships.get("threat_actors", [])
                        ),
                    },
                }
            )

            return True

        except Exception as e:
            logger.error(f"❌ {test_name} FAILED: {e}")
            self.test_results["errors"].append(f"{test_name}: {e}")
            self.test_results["test_details"].append(
                {"test": test_name, "status": "FAILED", "error": str(e)}
            )
            return False

    async def test_security_metrics_retrieval(self) -> bool:
        """Test enhanced security metrics retrieval"""
        test_name = "Security Metrics Retrieval"
        logger.info(f"Running test: {test_name}")

        try:
            # Get alert processing service
            alert_service = await self.service_coordinator.alert_processing

            # Get enhanced security metrics
            metrics = await alert_service.get_enhanced_security_metrics(
                "test-customer-456"
            )

            # Validate metrics structure
            required_metrics = [
                "total_alerts",
                "classification_breakdown",
                "escalation_metrics",
                "correlation_metrics",
                "risk_metrics",
                "workflow_metrics",
            ]

            for metric in required_metrics:
                if metric not in metrics:
                    raise Exception(f"Missing metric: {metric}")

            # Validate some basic values
            if metrics["total_alerts"] < 1:
                raise Exception("Expected at least 1 alert in metrics")

            if "critical" not in metrics["classification_breakdown"]:
                raise Exception("Missing critical classification in breakdown")

            logger.info(f"✅ {test_name} PASSED")
            logger.info(f"   Total Alerts: {metrics['total_alerts']}")
            logger.info(
                f"   Critical Alerts: {metrics['classification_breakdown']['critical']}"
            )
            logger.info(
                f"   Average Risk Score: {metrics['risk_metrics']['average_risk_score']:.2f}"
            )

            self.test_results["test_details"].append(
                {"test": test_name, "status": "PASSED", "metrics": metrics}
            )

            return True

        except Exception as e:
            logger.error(f"❌ {test_name} FAILED: {e}")
            self.test_results["errors"].append(f"{test_name}: {e}")
            self.test_results["test_details"].append(
                {"test": test_name, "status": "FAILED", "error": str(e)}
            )
            return False

    async def test_service_coordinator_integration(self) -> bool:
        """Test service coordinator integration with enhanced Neo4j service"""
        test_name = "Service Coordinator Integration"
        logger.info(f"Running test: {test_name}")

        try:
            # Test service coordinator health
            health_status = await self.service_coordinator.health_check()

            if health_status["overall_status"] not in ["healthy", "degraded"]:
                raise Exception(
                    f"Service coordinator unhealthy: {health_status['overall_status']}"
                )

            # Check enhanced_neo4j service in health status
            if "enhanced_neo4j" not in health_status["services"]:
                raise Exception("Enhanced Neo4j service not found in health status")

            enhanced_neo4j_status = health_status["services"]["enhanced_neo4j"]
            if enhanced_neo4j_status["status"] not in ["healthy", "not_initialized"]:
                raise Exception(
                    f"Enhanced Neo4j service unhealthy: {enhanced_neo4j_status['status']}"
                )

            # Test direct access to enhanced service
            enhanced_service = await self.service_coordinator.enhanced_neo4j
            if not enhanced_service:
                raise Exception(
                    "Could not access enhanced Neo4j service via coordinator"
                )

            logger.info(f"✅ {test_name} PASSED")
            logger.info(f"   Overall Status: {health_status['overall_status']}")
            logger.info(f"   Enhanced Neo4j Status: {enhanced_neo4j_status['status']}")

            self.test_results["test_details"].append(
                {"test": test_name, "status": "PASSED", "health_status": health_status}
            )

            return True

        except Exception as e:
            logger.error(f"❌ {test_name} FAILED: {e}")
            self.test_results["errors"].append(f"{test_name}: {e}")
            self.test_results["test_details"].append(
                {"test": test_name, "status": "FAILED", "error": str(e)}
            )
            return False

    async def run_all_tests(self) -> Dict[str, Any]:
        """Run all integration tests"""
        logger.info("=" * 80)
        logger.info("Enhanced Neo4j Integration Test Suite")
        logger.info("=" * 80)

        # Setup
        if not await self.setup():
            return {"status": "SETUP_FAILED", "results": self.test_results}

        # Define tests
        tests = [
            self.test_service_coordinator_integration,
            self.test_comprehensive_alert_population,
            self.test_alert_relationships_retrieval,
            self.test_security_metrics_retrieval,
        ]

        # Run tests
        for test in tests:
            try:
                if await test():
                    self.test_results["passed"] += 1
                else:
                    self.test_results["failed"] += 1
            except Exception as e:
                logger.error(f"Test execution error: {e}")
                self.test_results["failed"] += 1
                self.test_results["errors"].append(f"Test execution error: {e}")

        # Results summary
        total_tests = self.test_results["passed"] + self.test_results["failed"]
        pass_rate = (
            (self.test_results["passed"] / total_tests * 100) if total_tests > 0 else 0
        )

        logger.info("=" * 80)
        logger.info("Test Results Summary")
        logger.info("=" * 80)
        logger.info(f"Total Tests: {total_tests}")
        logger.info(f"Passed: {self.test_results['passed']}")
        logger.info(f"Failed: {self.test_results['failed']}")
        logger.info(f"Pass Rate: {pass_rate:.1f}%")

        if self.test_results["errors"]:
            logger.info("\nErrors:")
            for error in self.test_results["errors"]:
                logger.info(f"  - {error}")

        final_status = "PASSED" if self.test_results["failed"] == 0 else "FAILED"
        logger.info(f"\nOverall Status: {final_status}")

        return {
            "status": final_status,
            "pass_rate": pass_rate,
            "results": self.test_results,
        }

    async def cleanup(self):
        """Cleanup test environment"""
        try:
            if self.service_coordinator:
                await self.service_coordinator.shutdown_all_services()
            logger.info("Test cleanup complete")
        except Exception as e:
            logger.error(f"Error during cleanup: {e}")


async def main():
    """Main test execution"""
    tester = EnhancedNeo4jIntegrationTester()

    try:
        results = await tester.run_all_tests()

        # Save results to file
        results_file = f"test_results_{int(datetime.now().timestamp())}.json"
        with open(results_file, "w") as f:
            json.dump(results, f, indent=2, default=str)

        logger.info(f"Test results saved to: {results_file}")

        # Exit with appropriate code
        sys.exit(0 if results["status"] == "PASSED" else 1)

    except Exception as e:
        logger.error(f"Fatal test error: {e}")
        sys.exit(1)
    finally:
        await tester.cleanup()


if __name__ == "__main__":
    asyncio.run(main())
