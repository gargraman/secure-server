#!/usr/bin/env python3
"""
Test Script for Enhanced XDR Security Data Polling Service

This script tests the enhanced XDR poller functionality by:
1. Testing service initialization
2. Creating mock alert data
3. Testing comprehensive data extraction
4. Verifying enhanced alert processing
5. Testing graph database integration

Author: AI-SOAR Platform Team
Created: 2025-09-18 - Enhanced Poller Testing
"""

import asyncio
import json
import logging
import os
import sys
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Dict, List

# Add the project root to path for imports
project_root = Path(__file__).parent
if str(project_root) not in sys.path:
    sys.path.insert(0, str(project_root))

from src.core.exceptions import Neo4jConnectionException
from src.database.connection import get_database_manager
from src.database.models import Alert, AlertClassification, ProcessingStatus
# Import enhanced poller components
from src.services.alert_processing_service import AlertProcessingService

# Configure logging
logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s - %(name)s - %(levelname)s - %(message)s",
    handlers=[logging.StreamHandler(sys.stdout)],
)
logger = logging.getLogger("enhanced_poller_test")


def create_mock_alert_data() -> Dict[str, Any]:
    """Create comprehensive mock alert data for testing"""
    return {
        "id": "test-alert-123e4567-e89b-12d3-a456-426614174000",
        "type": "alert",
        "attributes": {
            "tenantId": "test-tenant-001",
            "customerId": "test-customer-001",
            "name": "Suspicious Privilege Escalation Detected",
            "message": "Potential privilege escalation attempt detected on critical server involving credential access and lateral movement techniques",
            "severity": 4,
            "score": 85,
            "confidence": 4,
            "risk": 4,
            "ruleId": "PRIV_ESC_001_lateral_movement",
            "generatedBy": "XDR-Engine-v2.5",
            "sources": ["endpoint", "network", "identity"],
            "status": "NEW",
            "assignee": None,
            "isSilent": False,
            "isIntelAvailable": True,
            "isSuppressed": False,
            "isCorrelated": True,
            "totalEventMatchCount": 5,
            "alertAggregationCount": 3,
            "inTimeline": True,
            "inPin": False,
            "createdAt": "2025-09-18T10:30:00.000Z",
            "updatedAt": "2025-09-18T10:30:00.000Z",
            "assetsCount": 2,
            "artefacts": [
                "192.168.1.100",
                "suspicious-script.ps1",
                "admin@company.com",
            ],
            "genaiSummary": "Multi-stage attack involving credential access and privilege escalation",
        },
        "relationships": {
            "assets": {
                "data": [
                    {"id": "asset-srv-001", "type": "asset"},
                    {"id": "asset-ws-042", "type": "asset"},
                ]
            },
            "events": {
                "data": [
                    {"id": "event-001", "type": "event"},
                    {"id": "event-002", "type": "event"},
                    {"id": "event-003", "type": "event"},
                ]
            },
        },
        "included": [
            {
                "id": "asset-srv-001",
                "type": "asset",
                "attributes": {
                    "name": "CRITICAL-SERVER-01",
                    "type": "server",
                    "status": "NOT_CONTAINED",
                    "location": "DataCenter-1",
                    "hash": "a1b2c3d4e5f6",
                },
            },
            {
                "id": "asset-ws-042",
                "type": "asset",
                "attributes": {
                    "name": "WORKSTATION-042",
                    "type": "workstation",
                    "status": "NOT_CONTAINED",
                    "location": "Office-Floor-2",
                },
            },
            {
                "id": "event-001",
                "type": "event",
                "attributes": {
                    "name": "Credential Access Attempt",
                    "message": "Suspicious credential dumping activity detected",
                    "severity": 4,
                    "confidence": 4,
                    "time": "2025-09-18T10:28:00.000Z",
                    "artefactType": "process",
                    "sanitized": False,
                    "primarySecondaryFields": {
                        "process_name": "mimikatz.exe",
                        "user": "SYSTEM",
                        "command_line": "mimikatz.exe privilege::debug sekurlsa::logonpasswords",
                        "parent_process": "powershell.exe",
                    },
                },
            },
            {
                "id": "event-002",
                "type": "event",
                "attributes": {
                    "name": "Lateral Movement Activity",
                    "message": "Unusual network connection to critical server",
                    "severity": 3,
                    "confidence": 3,
                    "time": "2025-09-18T10:29:00.000Z",
                    "artefactType": "network",
                    "sanitized": False,
                    "primarySecondaryFields": {
                        "source_ip": "192.168.1.42",
                        "destination_ip": "192.168.1.100",
                        "port": "445",
                        "protocol": "SMB",
                    },
                },
            },
            {
                "id": "event-003",
                "type": "event",
                "attributes": {
                    "name": "Privilege Escalation",
                    "message": "Process elevated to SYSTEM privileges",
                    "severity": 4,
                    "confidence": 4,
                    "time": "2025-09-18T10:29:30.000Z",
                    "artefactType": "process",
                    "sanitized": False,
                    "primarySecondaryFields": {
                        "process_name": "cmd.exe",
                        "user": "SYSTEM",
                        "elevation_method": "UAC_bypass",
                        "target_privileges": "SeDebugPrivilege",
                    },
                },
            },
        ],
    }


async def test_service_initialization():
    """Test service initialization"""
    logger.info("Testing service initialization...")

    try:
        # Test database manager
        db_manager = await get_database_manager()
        logger.info("✓ Database manager initialized successfully")

        # Test alert processing service
        alert_service = AlertProcessingService(db_manager)
        logger.info("✓ Alert processing service initialized successfully")

        return True, alert_service

    except Neo4jConnectionException as e:
        logger.warning(
            f"Database connection failed (expected in test environment): {e}"
        )
        return False, None
    except Exception as e:
        logger.error(f"Service initialization failed: {e}")
        return False, None


async def test_comprehensive_data_extraction():
    """Test comprehensive security data extraction"""
    logger.info("Testing comprehensive data extraction...")

    # Import the enhanced extraction functions
    sys.path.insert(0, str(Path(__file__).parent))
    from xdr_poller import (extract_assets_data, extract_events_data,
                            extract_iocs_artifacts, extract_mitre_techniques,
                            extract_threat_intelligence)

    mock_alert = create_mock_alert_data()

    try:
        # Test asset extraction
        assets = await extract_assets_data(mock_alert)
        logger.info(f"✓ Extracted {len(assets)} assets")
        for asset in assets:
            logger.info(
                f"  - Asset: {asset.get('name', asset.get('id'))} (type: {asset.get('type')})"
            )

        # Test event extraction
        events = await extract_events_data(mock_alert)
        logger.info(f"✓ Extracted {len(events)} events")
        for event in events:
            logger.info(
                f"  - Event: {event.get('name', event.get('id'))} (confidence: {event.get('correlation_confidence')})"
            )

        # Test MITRE technique extraction
        techniques = await extract_mitre_techniques(mock_alert)
        logger.info(f"✓ Extracted {len(techniques)} MITRE techniques")
        for technique in techniques:
            logger.info(
                f"  - Technique: {technique.get('technique_id')} - {technique.get('tactic_name')} (priority: {technique.get('tactic_priority')})"
            )

        # Test threat intelligence extraction
        threat_intel = await extract_threat_intelligence(mock_alert)
        logger.info(f"✓ Extracted {len(threat_intel)} threat intelligence items")
        for intel in threat_intel:
            logger.info(
                f"  - Intel: {intel.get('type')} = {intel.get('value', 'N/A')} (confidence: {intel.get('confidence')})"
            )

        # Test IOC extraction
        iocs = await extract_iocs_artifacts(mock_alert)
        logger.info(f"✓ Extracted {len(iocs)} IOCs/artifacts")
        for ioc in iocs:
            logger.info(f"  - IOC: {ioc.get('type')} = {ioc.get('value', 'N/A')}")

        return True

    except Exception as e:
        logger.error(f"Comprehensive data extraction failed: {e}")
        return False


async def test_enhanced_alert_processing(alert_service: AlertProcessingService):
    """Test enhanced alert processing and classification"""
    logger.info("Testing enhanced alert processing...")

    if not alert_service:
        logger.warning("Skipping enhanced processing test - service not available")
        return False

    mock_alert = create_mock_alert_data()

    try:
        # Test enhanced alert storage
        processed_alert = await alert_service.store_enhanced_alert(mock_alert)
        logger.info(f"✓ Enhanced alert processed successfully")
        logger.info(f"  - Alert ID: {processed_alert.id}")
        logger.info(f"  - Classification: {processed_alert.classification.value}")
        logger.info(f"  - Workflow: {processed_alert.workflow_classification.value}")
        logger.info(f"  - Response SLA: {processed_alert.response_sla.value}")
        logger.info(f"  - Escalation Level: {processed_alert.escalation_level.value}")
        logger.info(
            f"  - Composite Risk Score: {processed_alert.composite_risk_score:.2f}"
        )

        # Test alert retrieval
        retrieved_alert = await alert_service.get_alert(processed_alert.id)
        if retrieved_alert:
            logger.info("✓ Alert retrieval successful")
        else:
            logger.warning("Alert retrieval returned None")

        return True

    except Exception as e:
        logger.error(f"Enhanced alert processing failed: {e}")
        return False


def test_file_storage():
    """Test enhanced file storage functionality"""
    logger.info("Testing enhanced file storage...")

    # Import file storage function
    from xdr_poller import save_enhanced_alert_to_file

    mock_alert = create_mock_alert_data()

    # Add comprehensive data structure
    mock_alert["comprehensive_data"] = {
        "assets": [
            {"id": "test-asset", "name": "Test Asset", "criticality": 3},
        ],
        "events": [
            {"id": "test-event", "name": "Test Event", "severity": 4},
        ],
        "mitre_techniques": [
            {
                "technique_id": "TA0004",
                "tactic_name": "Privilege Escalation",
                "tactic_priority": 4,
            },
        ],
        "threat_intelligence": [
            {"type": "ip", "value": "192.168.1.100", "confidence": 3},
        ],
        "iocs": [
            {"type": "artifact", "value": "suspicious-script.ps1"},
        ],
        "analysis_metadata": {
            "collection_timestamp": datetime.now(timezone.utc).isoformat(),
            "data_sources": ["xdr_api", "mitre_mapping"],
            "correlation_status": "completed",
        },
    }

    try:
        save_enhanced_alert_to_file(mock_alert)

        # Check if files were created
        alert_id = mock_alert["id"]
        alerts_dir = Path("alerts")

        enhanced_files = list(alerts_dir.glob(f"enhanced_alert_{alert_id}_*.json"))
        summary_files = list(alerts_dir.glob(f"summary_{alert_id}_*.json"))

        if enhanced_files and summary_files:
            logger.info("✓ Enhanced file storage successful")
            logger.info(f"  - Enhanced file: {enhanced_files[0].name}")
            logger.info(f"  - Summary file: {summary_files[0].name}")

            # Verify file contents
            with open(enhanced_files[0], "r") as f:
                stored_data = json.load(f)
                if "comprehensive_data" in stored_data:
                    logger.info("✓ Comprehensive data structure preserved in file")

            return True
        else:
            logger.error("Enhanced files not created")
            return False

    except Exception as e:
        logger.error(f"Enhanced file storage failed: {e}")
        return False


async def run_comprehensive_test():
    """Run comprehensive test suite"""
    logger.info("=" * 80)
    logger.info("Enhanced XDR Security Data Polling Service - Comprehensive Test Suite")
    logger.info("=" * 80)

    results = []

    # Test 1: Service Initialization
    logger.info("\n" + "=" * 50)
    logger.info("TEST 1: Service Initialization")
    logger.info("=" * 50)
    service_success, alert_service = await test_service_initialization()
    results.append(("Service Initialization", service_success))

    # Test 2: Comprehensive Data Extraction
    logger.info("\n" + "=" * 50)
    logger.info("TEST 2: Comprehensive Data Extraction")
    logger.info("=" * 50)
    extraction_success = await test_comprehensive_data_extraction()
    results.append(("Data Extraction", extraction_success))

    # Test 3: Enhanced Alert Processing (if services available)
    logger.info("\n" + "=" * 50)
    logger.info("TEST 3: Enhanced Alert Processing")
    logger.info("=" * 50)
    processing_success = await test_enhanced_alert_processing(alert_service)
    results.append(("Alert Processing", processing_success))

    # Test 4: Enhanced File Storage
    logger.info("\n" + "=" * 50)
    logger.info("TEST 4: Enhanced File Storage")
    logger.info("=" * 50)
    storage_success = test_file_storage()
    results.append(("File Storage", storage_success))

    # Results Summary
    logger.info("\n" + "=" * 80)
    logger.info("TEST RESULTS SUMMARY")
    logger.info("=" * 80)

    passed = 0
    total = len(results)

    for test_name, success in results:
        status = "PASS" if success else "FAIL"
        logger.info(f"{test_name:<30} : {status}")
        if success:
            passed += 1

    logger.info("-" * 80)
    logger.info(f"Tests Passed: {passed}/{total}")
    logger.info(f"Success Rate: {(passed/total)*100:.1f}%")

    if passed == total:
        logger.info("🎉 All tests passed! Enhanced XDR poller is working correctly.")
    elif passed >= total * 0.75:
        logger.info(
            "✅ Most tests passed. Enhanced features are functional with minor issues."
        )
    else:
        logger.info("⚠️  Some tests failed. Check configuration and dependencies.")

    logger.info("=" * 80)


if __name__ == "__main__":
    try:
        asyncio.run(run_comprehensive_test())
    except KeyboardInterrupt:
        logger.info("Test interrupted by user")
    except Exception as e:
        logger.error(f"Test suite failed: {e}")
        sys.exit(1)
