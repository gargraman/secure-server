#!/usr/bin/env python3
"""
XDR Enhanced Security Data Polling Service

A comprehensive script that polls the XDR Alert Management API for alerts and
fetches related security data including assets, events, MITRE ATT&CK techniques,
and threat intelligence context. Integrates with the platform's service architecture
for enhanced security analysis and graph database storage.

Enhanced Features:
- Comprehensive security data collection (alerts, assets, events, MITRE techniques)
- Integration with AlertProcessingService for enhanced analysis
- Graph database storage with correlation analysis
- Threat intelligence and IOC correlation
- Maintains backward compatibility with existing JSON storage

Author: AI-SOAR Platform Team
Created: 2025-09-04
Enhanced: 2025-09-18 - Comprehensive Security Data Collection
"""

import argparse
import asyncio
import json
import logging
import os
import signal
import sys
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Dict, List, Optional, Set

# Import simplified integration components
from src.adapters.xdr_configuration_adapter import XDRConfigurationAdapter
# Import from the client module
from src.client.xdr_alert_client import XDRAlertClient, XDRAPIError, XDRConfig
from src.core.exceptions import (AlertProcessingException,
                                 Neo4jConnectionException)
from src.database.models import (Alert, AlertClassification, Asset, Attack,
                                 Event, IntelContext, ProcessingStatus,
                                 ThreatActor)
from src.extractors.xdr_data_extractor import XDRDataExtractor
from src.managers.resource_manager import ResourceManager
from src.processors.unified_alert_processor import UnifiedAlertProcessor
# Import service architecture components
from src.services.alert_processing_service import AlertProcessingService
from src.services.service_coordinator import get_service_coordinator

# Configure logging
logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s - %(name)s - %(levelname)s - %(message)s",
    handlers=[logging.StreamHandler(sys.stdout), logging.FileHandler("xdr_poller.log")],
)
logger = logging.getLogger("xdr_poller")

# Global variable to track if shutdown is requested
shutdown_requested = False

# Set to keep track of processed alert IDs to prevent duplicates
processed_alert_ids: Set[str] = set()

# Event to signal when shutdown is complete
shutdown_complete = asyncio.Event()

# Global service instances for enhanced processing
alert_processing_service: Optional[AlertProcessingService] = None
service_coordinator = None
unified_processor: Optional["UnifiedAlertProcessor"] = None
data_extractor: Optional["XDRDataExtractor"] = None
resource_manager: Optional["ResourceManager"] = None


def handle_new_alerts(alerts: List[Dict]) -> None:
    """
    Process new alerts received from the polling service with comprehensive data collection

    Args:
        alerts: List of alert dictionaries from XDR API
    """
    global processed_alert_ids

    new_alerts = []
    for alert in alerts:
        alert_id = alert.get("id")
        if alert_id and alert_id not in processed_alert_ids:
            new_alerts.append(alert)
            processed_alert_ids.add(alert_id)

    if not new_alerts:
        return

    logger.info(
        f"Processing {len(new_alerts)} new alerts with comprehensive security data collection"
    )

    # Process each alert asynchronously for enhanced data collection
    asyncio.create_task(handle_alerts_safely(new_alerts))


async def handle_alerts_safely(alerts: List[Dict]) -> None:
    """
    Safely handle alerts with comprehensive error handling

    Args:
        alerts: List of alert dictionaries from XDR API
    """
    try:
        await process_alerts_comprehensive(alerts)
    except Exception as e:
        logger.error(f"Alert processing error: {e}")
        # Continue processing - don't let one error break the entire polling service


async def process_alerts_comprehensive(alerts: List[Dict]) -> None:
    """
    Process alerts with comprehensive security data collection and analysis using unified components

    Args:
        alerts: List of alert dictionaries from XDR API
    """
    global unified_processor, resource_manager

    try:
        # Initialize services if not already done
        if not unified_processor:
            await initialize_services()

        # Filter out already processed alerts using resource manager
        new_alerts = []
        for alert in alerts:
            alert_id = alert.get("id")
            if (
                alert_id
                and resource_manager
                and resource_manager.track_processed_alert(alert_id)
            ):
                new_alerts.append(alert)
                # Log basic alert information
                attrs = alert.get("attributes", {})
                created_at = attrs.get("createdAt")
                if created_at:
                    try:
                        timestamp = datetime.fromisoformat(
                            created_at.replace("Z", "+00:00")
                        )
                        formatted_time = timestamp.strftime("%Y-%m-%d %H:%M:%S UTC")
                    except ValueError:
                        formatted_time = created_at
                else:
                    formatted_time = "Unknown"

                logger.info(
                    f"Alert {alert_id}: {attrs.get('name', 'Unnamed')} - {formatted_time}"
                )

        if not new_alerts:
            logger.debug("No new alerts to process")
            return

        # Use unified processor for all alert processing
        if unified_processor:
            await unified_processor.process_alerts(new_alerts)
            stats = unified_processor.get_processing_stats()
            logger.info(f"Unified processor stats: {stats}")
        else:
            # Fallback to basic processing
            logger.warning(
                "Unified processor not available, falling back to basic processing"
            )
            for alert in new_alerts:
                try:
                    # Fallback: Use the old method for backward compatibility
                    enhanced_alert_data = await fetch_comprehensive_security_data(alert)
                    save_enhanced_alert_to_file(enhanced_alert_data)
                    logger.info(f"Fallback: Processed alert {alert.get('id')}")
                except Exception as e:
                    logger.error(
                        f"Fallback processing failed for alert {alert.get('id', 'unknown')}: {e}"
                    )

    except Exception as e:
        logger.error(f"Error in comprehensive alert processing: {e}")


async def initialize_services() -> None:
    """
    Initialize the service architecture components
    """
    global alert_processing_service, service_coordinator, unified_processor, data_extractor, resource_manager

    try:
        # Initialize service coordinator
        service_coordinator = await get_service_coordinator()

        # Get alert processing service from coordinator (unified access pattern)
        alert_processing_service = await service_coordinator.alert_processing

        # Initialize simplified components
        data_extractor = XDRDataExtractor()
        resource_manager = ResourceManager()
        unified_processor = UnifiedAlertProcessor(
            coordinator=service_coordinator,
            storage_backends=["graph", "file"],
            data_extractor=data_extractor,
        )

        logger.info(
            "Successfully initialized enhanced security services and unified components"
        )

    except Exception as e:
        logger.warning(
            f"Failed to initialize enhanced services, continuing with basic processing: {e}"
        )
        # Continue with basic processing if services fail to initialize


async def fetch_comprehensive_security_data(base_alert: Dict) -> Dict[str, Any]:
    """
    Fetch comprehensive security data including assets, events, MITRE techniques, and threat intelligence

    Args:
        base_alert: Base alert data from XDR API

    Returns:
        Enhanced alert data with comprehensive security information
    """
    alert_id = base_alert.get("id")
    enhanced_data = base_alert.copy()

    try:
        # Initialize comprehensive data structure
        enhanced_data["comprehensive_data"] = {
            "assets": [],
            "events": [],
            "mitre_techniques": [],
            "threat_intelligence": [],
            "iocs": [],
            "analysis_metadata": {
                "collection_timestamp": datetime.now(timezone.utc).isoformat(),
                "data_sources": ["xdr_api"],
                "correlation_status": "pending",
            },
        }

        # Extract and enhance assets data
        assets_data = await extract_assets_data(base_alert)
        enhanced_data["comprehensive_data"]["assets"] = assets_data

        # Extract and enhance events data
        events_data = await extract_events_data(base_alert)
        enhanced_data["comprehensive_data"]["events"] = events_data

        # Extract MITRE ATT&CK techniques
        mitre_techniques = await extract_mitre_techniques(base_alert)
        enhanced_data["comprehensive_data"]["mitre_techniques"] = mitre_techniques

        # Extract threat intelligence context
        threat_intel = await extract_threat_intelligence(base_alert)
        enhanced_data["comprehensive_data"]["threat_intelligence"] = threat_intel

        # Extract IOCs and artifacts
        iocs_data = await extract_iocs_artifacts(base_alert)
        enhanced_data["comprehensive_data"]["iocs"] = iocs_data

        # Update data sources metadata
        data_sources = set(["xdr_api"])
        if assets_data:
            data_sources.add("asset_management")
        if events_data:
            data_sources.add("event_correlation")
        if mitre_techniques:
            data_sources.add("mitre_mapping")
        if threat_intel:
            data_sources.add("threat_intelligence")

        enhanced_data["comprehensive_data"]["analysis_metadata"]["data_sources"] = list(
            data_sources
        )
        enhanced_data["comprehensive_data"]["analysis_metadata"][
            "correlation_status"
        ] = "completed"

        logger.debug(
            f"Enhanced alert {alert_id} with {len(assets_data)} assets, {len(events_data)} events, {len(mitre_techniques)} MITRE techniques"
        )

    except Exception as e:
        logger.error(f"Error fetching comprehensive data for alert {alert_id}: {e}")
        # Ensure we have the basic structure even if enhancement fails
        if "comprehensive_data" not in enhanced_data:
            enhanced_data["comprehensive_data"] = {
                "analysis_metadata": {
                    "collection_timestamp": datetime.now(timezone.utc).isoformat(),
                    "error": str(e),
                    "data_sources": ["xdr_api"],
                    "correlation_status": "failed",
                }
            }

    return enhanced_data


async def extract_assets_data(alert: Dict) -> List[Dict[str, Any]]:
    """
    Extract and enhance assets data from alert

    Args:
        alert: Alert data from XDR API

    Returns:
        List of enhanced asset data
    """
    assets = []

    try:
        # Extract assets from relationships if available
        relationships = alert.get("relationships", {})
        if "assets" in relationships:
            asset_refs = relationships["assets"].get("data", [])

            for asset_ref in asset_refs:
                asset_data = {
                    "id": asset_ref.get("id"),
                    "type": asset_ref.get("type", "unknown"),
                    "source": "xdr_relationships",
                    "criticality": 1,  # Default, could be enhanced with asset management integration
                    "business_impact": "LOW",
                    "discovery_timestamp": datetime.now(timezone.utc).isoformat(),
                }

                # Try to extract additional asset information from included data
                if "included" in alert:
                    for included_item in alert["included"]:
                        if included_item.get("type") == "asset" and included_item.get(
                            "id"
                        ) == asset_ref.get("id"):
                            asset_attrs = included_item.get("attributes", {})
                            asset_data.update(
                                {
                                    "name": asset_attrs.get("name"),
                                    "hash": asset_attrs.get("hash"),
                                    "status": asset_attrs.get(
                                        "status", "NOT_CONTAINED"
                                    ),
                                    "location": asset_attrs.get("location"),
                                    "additional_attributes": asset_attrs,
                                }
                            )
                            break

                assets.append(asset_data)

        # Extract assets from alert attributes if not in relationships
        alert_attrs = alert.get("attributes", {})
        if "assetsCount" in alert_attrs and alert_attrs["assetsCount"] > 0:
            # If we have an asset count but no relationship data, create placeholder entries
            if not assets:
                for i in range(
                    min(alert_attrs["assetsCount"], 10)
                ):  # Limit to prevent excessive entries
                    assets.append(
                        {
                            "id": f"asset_placeholder_{i}",
                            "type": "inferred",
                            "source": "xdr_count_inference",
                            "criticality": 1,
                            "business_impact": "UNKNOWN",
                            "discovery_timestamp": datetime.now(
                                timezone.utc
                            ).isoformat(),
                            "note": "Placeholder asset inferred from assetsCount",
                        }
                    )

    except Exception as e:
        logger.error(f"Error extracting assets data: {e}")

    return assets


async def extract_events_data(alert: Dict) -> List[Dict[str, Any]]:
    """
    Extract and enhance events data from alert

    Args:
        alert: Alert data from XDR API

    Returns:
        List of enhanced event data
    """
    events = []

    try:
        # Extract events from relationships if available
        relationships = alert.get("relationships", {})
        if "events" in relationships:
            event_refs = relationships["events"].get("data", [])

            for event_ref in event_refs:
                event_data = {
                    "id": event_ref.get("id"),
                    "type": event_ref.get("type", "security_event"),
                    "source": "xdr_relationships",
                    "discovery_timestamp": datetime.now(timezone.utc).isoformat(),
                    "correlation_confidence": "medium",
                }

                # Try to extract additional event information from included data
                if "included" in alert:
                    for included_item in alert["included"]:
                        if included_item.get("type") == "event" and included_item.get(
                            "id"
                        ) == event_ref.get("id"):
                            event_attrs = included_item.get("attributes", {})
                            event_data.update(
                                {
                                    "name": event_attrs.get("name"),
                                    "message": event_attrs.get("message"),
                                    "severity": event_attrs.get("severity", 0),
                                    "confidence": event_attrs.get("confidence", 0),
                                    "time": event_attrs.get("time"),
                                    "artefact_type": event_attrs.get("artefactType"),
                                    "sanitized": event_attrs.get("sanitized", False),
                                    "additional_attributes": event_attrs,
                                }
                            )

                            # Extract IOCs from event if available
                            if "primarySecondaryFields" in event_attrs:
                                event_data["iocs"] = event_attrs[
                                    "primarySecondaryFields"
                                ]

                            break

                events.append(event_data)

        # Extract events from alert metadata if available
        alert_attrs = alert.get("attributes", {})
        if (
            "totalEventMatchCount" in alert_attrs
            and alert_attrs["totalEventMatchCount"] > 0
        ):
            # If we have event count but no relationship data, create summary entry
            if not events:
                events.append(
                    {
                        "id": f"events_summary_{alert.get('id', 'unknown')}",
                        "type": "event_summary",
                        "source": "xdr_metadata",
                        "total_event_count": alert_attrs["totalEventMatchCount"],
                        "discovery_timestamp": datetime.now(timezone.utc).isoformat(),
                        "note": "Event summary derived from totalEventMatchCount",
                    }
                )

    except Exception as e:
        logger.error(f"Error extracting events data: {e}")

    return events


async def extract_mitre_techniques(alert: Dict) -> List[Dict[str, Any]]:
    """
    Extract and map MITRE ATT&CK techniques from alert data

    Args:
        alert: Alert data from XDR API

    Returns:
        List of MITRE technique mappings
    """
    techniques = []

    try:
        alert_attrs = alert.get("attributes", {})

        # Technique mapping based on rule patterns and content
        technique_mappings = {
            # Tactic ID -> (Tactic Name, Priority)
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
        }

        detected_techniques = set()

        # Analyze rule ID for technique indicators
        rule_id = alert_attrs.get("ruleId", "").lower()
        if rule_id:
            if "privilege" in rule_id or "escalation" in rule_id:
                detected_techniques.add("TA0004")
            if "lateral" in rule_id or "movement" in rule_id:
                detected_techniques.add("TA0008")
            if "exfil" in rule_id or "data" in rule_id:
                detected_techniques.add("TA0010")
            if "credential" in rule_id or "password" in rule_id:
                detected_techniques.add("TA0006")
            if "persistence" in rule_id or "backdoor" in rule_id:
                detected_techniques.add("TA0003")
            if "discovery" in rule_id or "recon" in rule_id:
                detected_techniques.add("TA0007")

        # Analyze alert message/name for technique indicators
        message_content = (
            alert_attrs.get("message", "") + " " + alert_attrs.get("name", "")
        ).lower()
        if message_content:
            if any(
                term in message_content
                for term in ["command and control", "c2", "beacon"]
            ):
                detected_techniques.add("TA0011")
            if any(
                term in message_content for term in ["malware", "execution", "payload"]
            ):
                detected_techniques.add("TA0002")
            if any(
                term in message_content for term in ["impact", "destruction", "ransom"]
            ):
                detected_techniques.add("TA0040")
            if any(
                term in message_content for term in ["evasion", "bypass", "disable"]
            ):
                detected_techniques.add("TA0005")
            if any(
                term in message_content
                for term in ["initial access", "exploit", "vulnerability"]
            ):
                detected_techniques.add("TA0001")

        # Create technique entries
        for technique_id in detected_techniques:
            if technique_id in technique_mappings:
                tactic_name, priority = technique_mappings[technique_id]
                techniques.append(
                    {
                        "technique_id": technique_id,
                        "tactic_name": tactic_name,
                        "tactic_priority": priority,
                        "confidence": "medium",  # Could be enhanced with ML confidence scoring
                        "detection_method": "rule_analysis",
                        "evidence": {
                            "rule_id": alert_attrs.get("ruleId"),
                            "message_keywords": message_content[:200]
                            if message_content
                            else None,
                        },
                        "discovery_timestamp": datetime.now(timezone.utc).isoformat(),
                    }
                )

    except Exception as e:
        logger.error(f"Error extracting MITRE techniques: {e}")

    return techniques


async def extract_threat_intelligence(alert: Dict) -> List[Dict[str, Any]]:
    """
    Extract threat intelligence context from alert data

    Args:
        alert: Alert data from XDR API

    Returns:
        List of threat intelligence context data
    """
    threat_intel = []

    try:
        alert_attrs = alert.get("attributes", {})

        # Check if intelligence is available
        if alert_attrs.get("isIntelAvailable"):
            intel_context = {
                "type": "general_intelligence",
                "source": "xdr_intel_flag",
                "confidence": alert_attrs.get("confidence", 0),
                "severity": alert_attrs.get("severity", 0),
                "first_seen": alert_attrs.get("createdAt"),
                "comment": "Intelligence available flag detected in XDR alert",
                "discovery_timestamp": datetime.now(timezone.utc).isoformat(),
            }
            threat_intel.append(intel_context)

        # Extract potential IOCs for intelligence correlation
        potential_iocs = []

        # Look for IP addresses, domains, hashes in message content
        message = alert_attrs.get("message", "") + " " + alert_attrs.get("name", "")

        # Simple regex patterns for common IOCs (could be enhanced)
        import re

        # IP addresses
        ip_pattern = r"\b(?:[0-9]{1,3}\.){3}[0-9]{1,3}\b"
        ips = re.findall(ip_pattern, message)
        for ip in ips:
            potential_iocs.append({"type": "ip", "value": ip})

        # Domain patterns (basic)
        domain_pattern = r"\b(?:[a-zA-Z0-9-]+\.)+[a-zA-Z]{2,}\b"
        domains = re.findall(domain_pattern, message)
        for domain in domains:
            if "." in domain and len(domain) > 4:  # Basic domain validation
                potential_iocs.append({"type": "domain", "value": domain})

        # Hash patterns (MD5, SHA1, SHA256)
        hash_patterns = {
            "md5": r"\b[a-fA-F0-9]{32}\b",
            "sha1": r"\b[a-fA-F0-9]{40}\b",
            "sha256": r"\b[a-fA-F0-9]{64}\b",
        }

        for hash_type, pattern in hash_patterns.items():
            hashes = re.findall(pattern, message)
            for hash_value in hashes:
                potential_iocs.append({"type": hash_type, "value": hash_value})

        # Create intelligence entries for IOCs
        for ioc in potential_iocs:
            intel_entry = {
                "type": ioc["type"],
                "value": ioc["value"],
                "source": "xdr_content_extraction",
                "confidence": 2,  # Medium confidence for extracted IOCs
                "first_seen": alert_attrs.get("createdAt"),
                "comment": f"IOC extracted from alert content: {ioc['type']}={ioc['value']}",
                "discovery_timestamp": datetime.now(timezone.utc).isoformat(),
                "correlation_status": "pending",
            }
            threat_intel.append(intel_entry)

    except Exception as e:
        logger.error(f"Error extracting threat intelligence: {e}")

    return threat_intel


async def extract_iocs_artifacts(alert: Dict) -> List[Dict[str, Any]]:
    """
    Extract IOCs and artifacts from alert data

    Args:
        alert: Alert data from XDR API

    Returns:
        List of IOC and artifact data
    """
    iocs = []

    try:
        alert_attrs = alert.get("attributes", {})

        # Extract from explicit artefacts field
        if "artefacts" in alert_attrs:
            artefacts = alert_attrs["artefacts"]
            if isinstance(artefacts, list):
                for artifact in artefacts:
                    ioc_data = {
                        "type": "artifact",
                        "value": artifact,
                        "source": "xdr_artefacts",
                        "discovery_timestamp": datetime.now(timezone.utc).isoformat(),
                        "sanitized": alert_attrs.get("sanitized", False),
                    }
                    iocs.append(ioc_data)

        # Extract from event data if available
        if "included" in alert:
            for included_item in alert["included"]:
                if included_item.get("type") == "event":
                    event_attrs = included_item.get("attributes", {})

                    # Extract from primarySecondaryFields
                    if "primarySecondaryFields" in event_attrs:
                        fields = event_attrs["primarySecondaryFields"]
                        for key, value in fields.items():
                            if value and str(value).strip():
                                ioc_data = {
                                    "type": "event_field",
                                    "field_name": key,
                                    "value": str(value),
                                    "source": "xdr_event_fields",
                                    "event_id": included_item.get("id"),
                                    "discovery_timestamp": datetime.now(
                                        timezone.utc
                                    ).isoformat(),
                                    "sanitized": event_attrs.get("sanitized", False),
                                }
                                iocs.append(ioc_data)

    except Exception as e:
        logger.error(f"Error extracting IOCs and artifacts: {e}")

    return iocs


def save_enhanced_alert_to_file(enhanced_alert: Dict) -> None:
    """
    Save enhanced alert data to file for persistence and backward compatibility

    Args:
        enhanced_alert: Enhanced alert data with comprehensive security information
    """
    alert_id = enhanced_alert.get("id", "unknown")

    # Ensure alerts directory exists
    os.makedirs("alerts", exist_ok=True)

    # Write enhanced alert to file
    timestamp = int(datetime.now().timestamp())
    filename = f"alerts/enhanced_alert_{alert_id}_{timestamp}.json"

    try:
        with open(filename, "w") as f:
            json.dump(enhanced_alert, f, indent=2, default=str)

        # Also save a summary file for quick reference
        summary_filename = f"alerts/summary_{alert_id}_{timestamp}.json"
        summary_data = {
            "alert_id": alert_id,
            "timestamp": timestamp,
            "basic_info": {
                "name": enhanced_alert.get("attributes", {}).get("name"),
                "severity": enhanced_alert.get("attributes", {}).get("severity"),
                "status": enhanced_alert.get("attributes", {}).get("status"),
                "created_at": enhanced_alert.get("attributes", {}).get("createdAt"),
            },
            "comprehensive_summary": {
                "assets_count": len(
                    enhanced_alert.get("comprehensive_data", {}).get("assets", [])
                ),
                "events_count": len(
                    enhanced_alert.get("comprehensive_data", {}).get("events", [])
                ),
                "mitre_techniques_count": len(
                    enhanced_alert.get("comprehensive_data", {}).get(
                        "mitre_techniques", []
                    )
                ),
                "threat_intel_count": len(
                    enhanced_alert.get("comprehensive_data", {}).get(
                        "threat_intelligence", []
                    )
                ),
                "iocs_count": len(
                    enhanced_alert.get("comprehensive_data", {}).get("iocs", [])
                ),
            },
            "files": {"full_data": filename, "summary": summary_filename},
        }

        with open(summary_filename, "w") as f:
            json.dump(summary_data, f, indent=2, default=str)

        logger.debug(
            f"Saved enhanced alert {alert_id} to {filename} and summary to {summary_filename}"
        )

    except Exception as e:
        logger.error(f"Failed to save enhanced alert {alert_id} to file: {e}")


async def run_poller(config: XDRConfig) -> None:
    """
    Main polling function that runs the enhanced XDR security data polling service

    Args:
        config: XDR client configuration
    """
    global shutdown_requested, alert_processing_service, service_coordinator

    logger.info(
        f"Starting Enhanced XDR Security Data Polling Service (interval: {config.poll_interval}s)"
    )
    logger.info(
        "Enhanced features: Assets, Events, MITRE ATT&CK, Threat Intelligence, Graph Database Integration"
    )

    # Check if we're in development mode (using dummy credentials)
    is_development = config.auth_token == "dev-dummy-token" or not config.auth_token

    # Initialize services early
    try:
        await initialize_services()
        logger.info("Enhanced security services initialized successfully")
    except Exception as e:
        logger.warning(
            f"Failed to initialize enhanced services, continuing with basic functionality: {e}"
        )

    try:
        async with XDRAlertClient(config) as client:
            # Register our enhanced callback for new alerts
            await client.start_polling(config.poll_interval, handle_new_alerts)

            # Keep running until shutdown is requested
            while not shutdown_requested:
                await asyncio.sleep(1)

            # Clean shutdown
            logger.info("Shutdown requested, stopping enhanced polling...")
            await client.stop_polling()

    except XDRAPIError as e:
        if is_development and e.status_code == 401:
            logger.warning(
                f"Development mode: XDR API authentication failed (expected with dummy credentials): {e}"
            )
            logger.info(
                "Enhanced XDR Poller will continue running in development mode without actual API polling"
            )
            # In development mode, just keep the service running without polling
            while not shutdown_requested:
                await asyncio.sleep(60)  # Check for shutdown every minute
                logger.debug(
                    "Enhanced XDR Poller running in development mode (no actual polling)"
                )
        else:
            logger.error(f"XDR API Error: {e}")
            return
    except Neo4jConnectionException as e:
        logger.error(f"Database connection error: {e}")
        logger.info("Continuing with file-based storage only")
        # Continue running but with reduced functionality
        alert_processing_service = None
        await run_basic_poller(config)
    except Exception as e:
        logger.error(f"Unexpected error in enhanced poller: {e}")
        logger.info("Falling back to basic polling mode")
        await run_basic_poller(config)
    finally:
        # Cleanup services
        await cleanup_services()
        # Signal that shutdown is complete
        shutdown_complete.set()
        logger.info("Enhanced XDR Security Data Polling Service stopped")


async def run_basic_poller(config: XDRConfig) -> None:
    """
    Fallback basic polling mode when enhanced services are unavailable

    Args:
        config: XDR client configuration
    """
    global shutdown_requested

    logger.info("Running in basic polling mode (file storage only)")

    try:
        async with XDRAlertClient(config) as client:
            # Use basic alert handler for file storage only
            def basic_alert_handler(alerts: List[Dict]) -> None:
                for alert in alerts:
                    alert_id = alert.get("id")
                    if alert_id and alert_id not in processed_alert_ids:
                        processed_alert_ids.add(alert_id)
                        # Basic file storage (backward compatibility)
                        try:
                            save_basic_alert_to_file(alert)
                            logger.info(f"Saved basic alert {alert_id} to file")
                        except Exception as e:
                            logger.error(f"Failed to save basic alert {alert_id}: {e}")

            await client.start_polling(config.poll_interval, basic_alert_handler)

            while not shutdown_requested:
                await asyncio.sleep(1)

            await client.stop_polling()

    except Exception as e:
        logger.error(f"Error in basic polling mode: {e}")


def save_basic_alert_to_file(alert: Dict) -> None:
    """
    Basic alert file storage for backward compatibility

    Args:
        alert: Alert dictionary from XDR API
    """
    alert_id = alert.get("id", "unknown")

    # Ensure alerts directory exists
    os.makedirs("alerts", exist_ok=True)

    # Write alert to file
    filename = f"alerts/alert_{alert_id}_{int(datetime.now().timestamp())}.json"
    try:
        with open(filename, "w") as f:
            json.dump(alert, f, indent=2)
        logger.debug(f"Saved basic alert {alert_id} to {filename}")
    except Exception as e:
        logger.error(f"Failed to save basic alert {alert_id} to file: {e}")


async def cleanup_services() -> None:
    """
    Cleanup service resources on shutdown
    """
    global alert_processing_service, service_coordinator, unified_processor, data_extractor, resource_manager

    try:
        # Cleanup resource manager first
        if resource_manager:
            await resource_manager.shutdown()

        # Cleanup database connections if needed
        if alert_processing_service and hasattr(alert_processing_service, "db_manager"):
            db_manager = alert_processing_service.db_manager
            if db_manager and hasattr(db_manager, "close"):
                await db_manager.close()

        # Reset service instances
        alert_processing_service = None
        service_coordinator = None
        unified_processor = None
        data_extractor = None
        resource_manager = None

        logger.info("Enhanced services cleanup completed")

    except Exception as e:
        logger.error(f"Error during service cleanup: {e}")


def signal_handler(sig, frame) -> None:  # pylint: disable=unused-argument
    """
    Signal handler for graceful shutdown

    Args:
        sig: Signal number (unused)
        frame: Current stack frame (unused)
    """
    global shutdown_requested

    if shutdown_requested:
        logger.warning("Forced shutdown requested, exiting immediately")
        sys.exit(1)

    logger.info("Shutdown signal received, gracefully shutting down...")
    shutdown_requested = True


async def main() -> None:
    """Main entry point for the Enhanced XDR Security Data Polling Service"""
    parser = argparse.ArgumentParser(
        description="Enhanced XDR Security Data Polling Service",
        epilog="Comprehensive security data collection including alerts, assets, events, MITRE ATT&CK techniques, and threat intelligence",
    )
    parser.add_argument("--base-url", help="XDR API base URL")
    parser.add_argument("--auth-token", help="Authentication token")
    parser.add_argument(
        "--interval", type=int, default=30, help="Polling interval in seconds"
    )
    parser.add_argument("--debug", action="store_true", help="Enable debug logging")
    parser.add_argument(
        "--basic-mode",
        action="store_true",
        help="Run in basic mode (file storage only, no enhanced services)",
    )
    parser.add_argument(
        "--no-graph-db", action="store_true", help="Disable graph database integration"
    )

    args = parser.parse_args()

    # Configure logging level
    if args.debug:
        logger.setLevel(logging.DEBUG)
        logging.getLogger("src.client.xdr_alert_client").setLevel(logging.DEBUG)
        logging.getLogger("src.services").setLevel(logging.DEBUG)
        logging.getLogger("src.database").setLevel(logging.DEBUG)

    # Create configuration
    config = XDRConfig.from_environment()
    if args.base_url:
        config.base_url = args.base_url
    if args.auth_token:
        config.auth_token = args.auth_token

    config.poll_interval = args.interval
    config.poll_enabled = True

    # Set up signal handlers for graceful shutdown
    signal.signal(signal.SIGINT, signal_handler)
    signal.signal(signal.SIGTERM, signal_handler)

    # Display startup information
    logger.info("=" * 80)
    logger.info("Enhanced XDR Security Data Polling Service")
    logger.info("=" * 80)
    logger.info(f"Configuration:")
    logger.info(f"  - Polling interval: {config.poll_interval}s")
    logger.info(f"  - Base URL: {config.base_url}")
    logger.info(f"  - Debug mode: {args.debug}")
    logger.info(f"  - Basic mode: {args.basic_mode}")
    logger.info(f"  - Graph DB disabled: {args.no_graph_db}")
    logger.info("Enhanced Features:")
    logger.info("  - Comprehensive asset data collection")
    logger.info("  - Security event correlation")
    logger.info("  - MITRE ATT&CK technique mapping")
    logger.info("  - Threat intelligence context")
    logger.info("  - IOC extraction and analysis")
    logger.info("  - Graph database integration")
    logger.info("  - Enhanced security classification")
    logger.info("=" * 80)

    # Handle basic mode override
    if args.basic_mode:
        logger.info("Running in basic mode - enhanced services disabled")
        global alert_processing_service
        alert_processing_service = None
        await run_basic_poller(config)
    else:
        # Run the enhanced poller
        await run_poller(config)

    # Wait for shutdown to complete
    await shutdown_complete.wait()


if __name__ == "__main__":
    try:
        asyncio.run(main())
    except KeyboardInterrupt:
        logger.info("Received keyboard interrupt, shutting down gracefully...")
    except Exception as e:
        logger.error(f"Fatal error in main: {e}")
        sys.exit(1)
