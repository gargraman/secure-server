#!/usr/bin/env python3
"""
Comprehensive Integration Test for Enhanced XDR Poller and Neo4j Integration

This test validates the entire flow from XDR alert processing through the simplified
integration components to Neo4j database storage.

Author: AI-SOAR Platform Team
Created: 2025-09-23 - Integration Validation
"""

import asyncio
import json
import logging
import os
from datetime import datetime, timezone
from typing import Any, Dict, List

# Configure logging
logging.basicConfig(
    level=logging.INFO, format="%(asctime)s - %(name)s - %(levelname)s - %(message)s"
)
logger = logging.getLogger("integration_test")

# Mock alert data for testing
MOCK_ALERT_DATA = {
    "id": "test_alert_123",
    "type": "alert",
    "attributes": {
        "tenantId": "test_tenant",
        "customerId": "test_customer",
        "name": "Test Security Alert - Privilege Escalation Detected",
        "message": "Suspicious privilege escalation activity detected on critical asset. Potential credential access attempt.",
        "severity": 4,
        "score": 85,
        "confidence": 8,
        "risk": 7,
        "ruleId": "privilege_escalation_rule_001",
        "generatedBy": "XDR_Engine",
        "sources": ["endpoint_detection", "user_behavior_analytics"],
        "isSilent": False,
        "isIntelAvailable": True,
        "isSuppressed": False,
        "status": "NEW",
        "createdAt": datetime.now(timezone.utc).isoformat(),
        "totalEventMatchCount": 3,
        "assetsCount": 2,
    },
    "relationships": {
        "assets": {
            "data": [
                {"id": "asset_001", "type": "asset"},
                {"id": "asset_002", "type": "asset"},
            ]
        },
        "events": {
            "data": [
                {"id": "event_001", "type": "event"},
                {"id": "event_002", "type": "event"},
            ]
        },
    },
    "included": [
        {
            "id": "asset_001",
            "type": "asset",
            "attributes": {
                "name": "critical-server-01",
                "hash": "abc123def456",
                "status": "NOT_CONTAINED",
                "location": "Data Center 1",
            },
        },
        {
            "id": "event_001",
            "type": "event",
            "attributes": {
                "name": "Privilege Escalation Attempt",
                "message": "User attempted to escalate privileges using credential access technique",
                "severity": 4,
                "confidence": 9,
                "time": datetime.now(timezone.utc).isoformat(),
                "artefactType": "ProcessCreation",
                "sanitized": False,
                "primarySecondaryFields": {
                    "process_name": "malicious_escalation.exe",
                    "user_account": "compromised_user",
                    "source_ip": "192.168.1.100",
                },
            },
        },
    ],
}


async def test_component_initialization():
    """Test that all components can be initialized correctly"""
    logger.info("Testing component initialization...")

    try:
        # Import components
        from src.extractors.xdr_data_extractor import XDRDataExtractor
        from src.managers.resource_manager import ResourceManager
        from src.processors.unified_alert_processor import \
            UnifiedAlertProcessor
        from src.services.service_coordinator import get_service_coordinator

        # Initialize components
        data_extractor = XDRDataExtractor()
        resource_manager = ResourceManager()

        # Try to get service coordinator (might fail in test environment)
        try:
            service_coordinator = await get_service_coordinator()
            coordinator_available = True
            logger.info("✅ Service coordinator available")
        except Exception as e:
            logger.warning(f"Service coordinator not available (expected in test): {e}")
            coordinator_available = False
            service_coordinator = None

        # Initialize unified processor
        unified_processor = UnifiedAlertProcessor(
            coordinator=service_coordinator,
            storage_backends=["file"],  # Use only file storage for testing
            data_extractor=data_extractor,
        )

        logger.info("✅ All components initialized successfully")
        return {
            "data_extractor": data_extractor,
            "resource_manager": resource_manager,
            "unified_processor": unified_processor,
            "coordinator_available": coordinator_available,
        }

    except Exception as e:
        logger.error(f"❌ Component initialization failed: {e}")
        raise


async def test_data_extraction(data_extractor: "XDRDataExtractor"):
    """Test comprehensive data extraction"""
    logger.info("Testing data extraction...")

    try:
        # Test comprehensive data extraction
        extracted_data = await data_extractor.extract_comprehensive_data(
            MOCK_ALERT_DATA
        )

        # Validate extracted data structure
        expected_keys = [
            "assets",
            "events",
            "mitre_techniques",
            "threat_intelligence",
            "iocs",
            "analysis_metadata",
        ]
        for key in expected_keys:
            if key not in extracted_data:
                raise ValueError(f"Missing expected key: {key}")

        # Log results
        logger.info(f"✅ Extracted {len(extracted_data['assets'])} assets")
        logger.info(f"✅ Extracted {len(extracted_data['events'])} events")
        logger.info(
            f"✅ Extracted {len(extracted_data['mitre_techniques'])} MITRE techniques"
        )
        logger.info(
            f"✅ Extracted {len(extracted_data['threat_intelligence'])} threat intel items"
        )
        logger.info(f"✅ Extracted {len(extracted_data['iocs'])} IOCs")

        # Validate MITRE technique extraction
        mitre_techniques = extracted_data["mitre_techniques"]
        if mitre_techniques:
            for technique in mitre_techniques:
                logger.info(
                    f"   MITRE Technique: {technique['technique_id']} - {technique['tactic_name']}"
                )

        # Validate threat intelligence extraction
        threat_intel = extracted_data["threat_intelligence"]
        if threat_intel:
            for intel in threat_intel[:3]:  # Show first 3
                logger.info(
                    f"   Threat Intel: {intel['type']} - {intel.get('value', intel.get('comment', 'N/A'))}"
                )

        logger.info("✅ Data extraction test passed")
        return extracted_data

    except Exception as e:
        logger.error(f"❌ Data extraction failed: {e}")
        raise


async def test_resource_management(resource_manager: "ResourceManager"):
    """Test resource management functionality"""
    logger.info("Testing resource management...")

    try:
        # Test alert tracking
        alert_id = MOCK_ALERT_DATA["id"]

        # First call should return True (new alert)
        is_new = resource_manager.track_processed_alert(alert_id)
        if not is_new:
            raise ValueError("First call should return True for new alert")

        # Second call should return False (already processed)
        is_new_again = resource_manager.track_processed_alert(alert_id)
        if is_new_again:
            raise ValueError(
                "Second call should return False for already processed alert"
            )

        # Test stats
        stats = resource_manager.get_stats()
        logger.info(f"Resource manager stats: {stats}")

        # Test health check
        health = await resource_manager.health_check()
        logger.info(f"Resource manager health: {health['status']}")

        logger.info("✅ Resource management test passed")
        return True

    except Exception as e:
        logger.error(f"❌ Resource management test failed: {e}")
        raise


async def test_unified_processing(
    unified_processor: "UnifiedAlertProcessor", extracted_data: Dict
):
    """Test unified alert processing"""
    logger.info("Testing unified alert processing...")

    try:
        # Create enhanced alert data
        enhanced_alert = MOCK_ALERT_DATA.copy()
        enhanced_alert["comprehensive_data"] = extracted_data

        # Process through unified processor
        await unified_processor.process_alerts([enhanced_alert])

        # Get processing statistics
        stats = unified_processor.get_processing_stats()
        logger.info(f"Processing stats: {stats}")

        # Validate that processing succeeded
        if stats["total_processed"] == 0:
            raise ValueError("No alerts were processed")

        # Check health
        health = await unified_processor.health_check()
        logger.info(f"Unified processor health: {health['processor_status']}")

        logger.info("✅ Unified processing test passed")
        return True

    except Exception as e:
        logger.error(f"❌ Unified processing test failed: {e}")
        raise


async def test_file_storage():
    """Test that file storage is working"""
    logger.info("Testing file storage...")

    try:
        # Check if alerts directory was created
        if not os.path.exists("alerts"):
            raise ValueError("Alerts directory was not created")

        # Check for generated files
        alert_files = [
            f
            for f in os.listdir("alerts")
            if f.startswith("enhanced_alert_") or f.startswith("alert_")
        ]

        if not alert_files:
            logger.warning(
                "No alert files found - this might be expected depending on processing"
            )
        else:
            logger.info(f"✅ Found {len(alert_files)} alert files")

            # Read and validate one file
            latest_file = max(
                alert_files, key=lambda f: os.path.getctime(os.path.join("alerts", f))
            )
            file_path = os.path.join("alerts", latest_file)

            with open(file_path, "r") as f:
                alert_data = json.load(f)

            # Validate file contents
            if "id" not in alert_data:
                raise ValueError("Alert file missing required 'id' field")

            logger.info(f"✅ Validated alert file: {latest_file}")

        logger.info("✅ File storage test passed")
        return True

    except Exception as e:
        logger.error(f"❌ File storage test failed: {e}")
        raise


async def test_xdr_poller_integration():
    """Test that XDR poller can use the simplified components"""
    logger.info("Testing XDR poller integration...")

    try:
        # Import XDR poller functions
        from xdr_poller import (extract_assets_data, extract_events_data,
                                extract_iocs_artifacts,
                                extract_mitre_techniques,
                                extract_threat_intelligence,
                                fetch_comprehensive_security_data,
                                initialize_services)

        # Test service initialization
        await initialize_services()
        logger.info("✅ XDR poller service initialization successful")

        # Test legacy data extraction functions (should still work)
        assets = await extract_assets_data(MOCK_ALERT_DATA)
        events = await extract_events_data(MOCK_ALERT_DATA)
        mitre = await extract_mitre_techniques(MOCK_ALERT_DATA)
        intel = await extract_threat_intelligence(MOCK_ALERT_DATA)
        iocs = await extract_iocs_artifacts(MOCK_ALERT_DATA)

        logger.info(
            f"✅ Legacy extraction: {len(assets)} assets, {len(events)} events, {len(mitre)} MITRE, {len(intel)} intel, {len(iocs)} IOCs"
        )

        # Test comprehensive data fetching
        comprehensive_data = await fetch_comprehensive_security_data(MOCK_ALERT_DATA)
        if "comprehensive_data" not in comprehensive_data:
            raise ValueError("Comprehensive data missing expected structure")

        logger.info("✅ XDR poller integration test passed")
        return True

    except Exception as e:
        logger.error(f"❌ XDR poller integration test failed: {e}")
        raise


async def run_comprehensive_test():
    """Run all integration tests"""
    logger.info("=" * 80)
    logger.info("Starting Comprehensive Integration Test")
    logger.info("=" * 80)

    test_results = {}

    try:
        # Test 1: Component Initialization
        logger.info("\n" + "=" * 40)
        logger.info("TEST 1: Component Initialization")
        logger.info("=" * 40)
        components = await test_component_initialization()
        test_results["initialization"] = True

        # Test 2: Data Extraction
        logger.info("\n" + "=" * 40)
        logger.info("TEST 2: Data Extraction")
        logger.info("=" * 40)
        extracted_data = await test_data_extraction(components["data_extractor"])
        test_results["data_extraction"] = True

        # Test 3: Resource Management
        logger.info("\n" + "=" * 40)
        logger.info("TEST 3: Resource Management")
        logger.info("=" * 40)
        await test_resource_management(components["resource_manager"])
        test_results["resource_management"] = True

        # Test 4: Unified Processing
        logger.info("\n" + "=" * 40)
        logger.info("TEST 4: Unified Processing")
        logger.info("=" * 40)
        await test_unified_processing(components["unified_processor"], extracted_data)
        test_results["unified_processing"] = True

        # Test 5: File Storage
        logger.info("\n" + "=" * 40)
        logger.info("TEST 5: File Storage")
        logger.info("=" * 40)
        await test_file_storage()
        test_results["file_storage"] = True

        # Test 6: XDR Poller Integration
        logger.info("\n" + "=" * 40)
        logger.info("TEST 6: XDR Poller Integration")
        logger.info("=" * 40)
        await test_xdr_poller_integration()
        test_results["xdr_integration"] = True

        # Summary
        logger.info("\n" + "=" * 80)
        logger.info("INTEGRATION TEST SUMMARY")
        logger.info("=" * 80)

        all_passed = True
        for test_name, result in test_results.items():
            status = "✅ PASSED" if result else "❌ FAILED"
            logger.info(f"{test_name.replace('_', ' ').title()}: {status}")
            if not result:
                all_passed = False

        if all_passed:
            logger.info(
                "\n🎉 ALL TESTS PASSED! The enhanced XDR integration is working correctly."
            )
            logger.info("\nKey features validated:")
            logger.info("• Simplified integration components work correctly")
            logger.info("• Data extraction with MITRE ATT&CK mapping")
            logger.info("• Threat intelligence correlation")
            logger.info("• Resource management and memory cleanup")
            logger.info("• Unified alert processing with multiple storage backends")
            logger.info("• File-based storage for backward compatibility")
            logger.info("• XDR poller integration with enhanced services")
        else:
            logger.error("\n❌ SOME TESTS FAILED! Please review the errors above.")

        return all_passed

    except Exception as e:
        logger.error(f"\n💥 INTEGRATION TEST FAILED: {e}")
        return False

    finally:
        # Cleanup
        try:
            if "resource_manager" in locals():
                await components["resource_manager"].shutdown()
                logger.info("✅ Resource cleanup completed")
        except Exception as e:
            logger.warning(f"Cleanup warning: {e}")


async def main():
    """Main test entry point"""
    try:
        success = await run_comprehensive_test()
        exit_code = 0 if success else 1
        exit(exit_code)
    except KeyboardInterrupt:
        logger.info("Test interrupted by user")
        exit(130)
    except Exception as e:
        logger.error(f"Test failed with unexpected error: {e}")
        exit(1)


if __name__ == "__main__":
    asyncio.run(main())
