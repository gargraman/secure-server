"""
XDR Data Extractor

Unified data extraction with configurable extractors to eliminate redundant
extraction functions. Consolidates all data extraction logic into a single,
maintainable class with consistent error handling.

Author: AI-SOAR Platform Team
Created: 2025-09-22
"""

import logging
import re
from datetime import datetime, timezone
from typing import Any, Callable, Dict, List

logger = logging.getLogger(__name__)


class XDRDataExtractor:
    """Unified data extraction with configurable extractors"""

    def __init__(self):
        """Initialize data extractor with all extraction methods"""
        self.extractors = {
            "assets": self._extract_assets,
            "events": self._extract_events,
            "mitre_techniques": self._extract_mitre_techniques,
            "threat_intelligence": self._extract_threat_intelligence,
            "iocs": self._extract_iocs_artifacts,
        }

        # MITRE ATT&CK technique mappings
        self.mitre_mappings = {
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

        # Regex patterns for IOC extraction
        self.ioc_patterns = {
            "ip": r"\b(?:[0-9]{1,3}\.){3}[0-9]{1,3}\b",
            "domain": r"\b(?:[a-zA-Z0-9-]+\.)+[a-zA-Z]{2,}\b",
            "md5": r"\b[a-fA-F0-9]{32}\b",
            "sha1": r"\b[a-fA-F0-9]{40}\b",
            "sha256": r"\b[a-fA-F0-9]{64}\b",
        }

    async def extract_comprehensive_data(self, alert: Dict) -> Dict[str, Any]:
        """
        Single method for all data extraction with consistent error handling

        Args:
            alert: Alert dictionary from XDR API

        Returns:
            Dictionary with all extracted data types
        """
        results = {}
        extraction_errors = []

        for data_type, extractor in self.extractors.items():
            try:
                results[data_type] = await extractor(alert)
                logger.debug(f"Extracted {len(results[data_type])} {data_type} items")
            except Exception as e:
                logger.warning(f"Failed to extract {data_type}: {e}")
                results[data_type] = []
                extraction_errors.append(f"{data_type}: {str(e)}")

        # Add extraction metadata
        results["analysis_metadata"] = {
            "collection_timestamp": datetime.now(timezone.utc).isoformat(),
            "data_sources": self._determine_data_sources(results),
            "extraction_errors": extraction_errors,
            "correlation_status": "completed" if not extraction_errors else "partial",
        }

        return results

    async def _extract_assets(self, alert: Dict) -> List[Dict[str, Any]]:
        """
        Extract and enhance assets data from alert

        Args:
            alert: Alert data from XDR API

        Returns:
            List of enhanced asset data
        """
        assets = []

        try:
            # Extract from relationships
            relationships = alert.get("relationships", {})
            if "assets" in relationships:
                asset_refs = relationships["assets"].get("data", [])

                for asset_ref in asset_refs:
                    asset_data = {
                        "id": asset_ref.get("id"),
                        "type": asset_ref.get("type", "unknown"),
                        "source": "xdr_relationships",
                        "criticality": 1,  # Default criticality
                        "business_impact": "LOW",
                        "discovery_timestamp": datetime.now(timezone.utc).isoformat(),
                    }

                    # Enhance with included data
                    asset_data = self._enhance_asset_from_included(alert, asset_data)
                    assets.append(asset_data)

            # Handle asset count inference
            alert_attrs = alert.get("attributes", {})
            assets_count = alert_attrs.get("assetsCount", 0)
            if assets_count > 0 and not assets:
                # Create placeholder assets based on count
                for i in range(
                    min(assets_count, 10)
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
            raise

        return assets

    async def _extract_events(self, alert: Dict) -> List[Dict[str, Any]]:
        """
        Extract and enhance events data from alert

        Args:
            alert: Alert data from XDR API

        Returns:
            List of enhanced event data
        """
        events = []

        try:
            # Extract from relationships
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

                    # Enhance with included data
                    event_data = self._enhance_event_from_included(alert, event_data)
                    events.append(event_data)

            # Handle event count summary
            alert_attrs = alert.get("attributes", {})
            total_events = alert_attrs.get("totalEventMatchCount", 0)
            if total_events > 0 and not events:
                events.append(
                    {
                        "id": f"events_summary_{alert.get('id', 'unknown')}",
                        "type": "event_summary",
                        "source": "xdr_metadata",
                        "total_event_count": total_events,
                        "discovery_timestamp": datetime.now(timezone.utc).isoformat(),
                        "note": "Event summary derived from totalEventMatchCount",
                    }
                )

        except Exception as e:
            logger.error(f"Error extracting events data: {e}")
            raise

        return events

    async def _extract_mitre_techniques(self, alert: Dict) -> List[Dict[str, Any]]:
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
            detected_techniques = set()

            # Analyze rule ID for technique indicators
            rule_id = alert_attrs.get("ruleId", "").lower()
            detected_techniques.update(self._analyze_rule_for_techniques(rule_id))

            # Analyze message content for technique indicators
            message_content = (
                alert_attrs.get("message", "") + " " + alert_attrs.get("name", "")
            ).lower()
            detected_techniques.update(
                self._analyze_message_for_techniques(message_content)
            )

            # Create technique entries
            for technique_id in detected_techniques:
                if technique_id in self.mitre_mappings:
                    tactic_name, priority = self.mitre_mappings[technique_id]
                    techniques.append(
                        {
                            "technique_id": technique_id,
                            "tactic_name": tactic_name,
                            "tactic_priority": priority,
                            "confidence": "medium",
                            "detection_method": "rule_analysis",
                            "evidence": {
                                "rule_id": alert_attrs.get("ruleId"),
                                "message_keywords": message_content[:200]
                                if message_content
                                else None,
                            },
                            "discovery_timestamp": datetime.now(
                                timezone.utc
                            ).isoformat(),
                        }
                    )

        except Exception as e:
            logger.error(f"Error extracting MITRE techniques: {e}")
            raise

        return techniques

    async def _extract_threat_intelligence(self, alert: Dict) -> List[Dict[str, Any]]:
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

            # Check for intelligence availability flag
            if alert_attrs.get("isIntelAvailable"):
                threat_intel.append(
                    {
                        "type": "general_intelligence",
                        "source": "xdr_intel_flag",
                        "confidence": alert_attrs.get("confidence", 0),
                        "severity": alert_attrs.get("severity", 0),
                        "first_seen": alert_attrs.get("createdAt"),
                        "comment": "Intelligence available flag detected in XDR alert",
                        "discovery_timestamp": datetime.now(timezone.utc).isoformat(),
                    }
                )

            # Extract IOCs from content for intelligence correlation
            message = alert_attrs.get("message", "") + " " + alert_attrs.get("name", "")
            iocs = self._extract_iocs_from_text(message)

            # Create intelligence entries for IOCs
            for ioc in iocs:
                threat_intel.append(
                    {
                        "type": ioc["type"],
                        "value": ioc["value"],
                        "source": "xdr_content_extraction",
                        "confidence": 2,  # Medium confidence for extracted IOCs
                        "first_seen": alert_attrs.get("createdAt"),
                        "comment": f"IOC extracted from alert content: {ioc['type']}={ioc['value']}",
                        "discovery_timestamp": datetime.now(timezone.utc).isoformat(),
                        "correlation_status": "pending",
                    }
                )

        except Exception as e:
            logger.error(f"Error extracting threat intelligence: {e}")
            raise

        return threat_intel

    async def _extract_iocs_artifacts(self, alert: Dict) -> List[Dict[str, Any]]:
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
                        iocs.append(
                            {
                                "type": "artifact",
                                "value": artifact,
                                "source": "xdr_artefacts",
                                "discovery_timestamp": datetime.now(
                                    timezone.utc
                                ).isoformat(),
                                "sanitized": alert_attrs.get("sanitized", False),
                            }
                        )

            # Extract from event data
            if "included" in alert:
                iocs.extend(self._extract_iocs_from_events(alert["included"]))

        except Exception as e:
            logger.error(f"Error extracting IOCs and artifacts: {e}")
            raise

        return iocs

    def _enhance_asset_from_included(self, alert: Dict, asset_data: Dict) -> Dict:
        """Enhance asset data from included items"""
        if "included" in alert:
            for included_item in alert["included"]:
                if included_item.get("type") == "asset" and included_item.get(
                    "id"
                ) == asset_data.get("id"):
                    asset_attrs = included_item.get("attributes", {})
                    asset_data.update(
                        {
                            "name": asset_attrs.get("name"),
                            "hash": asset_attrs.get("hash"),
                            "status": asset_attrs.get("status", "NOT_CONTAINED"),
                            "location": asset_attrs.get("location"),
                            "additional_attributes": asset_attrs,
                        }
                    )
                    break
        return asset_data

    def _enhance_event_from_included(self, alert: Dict, event_data: Dict) -> Dict:
        """Enhance event data from included items"""
        if "included" in alert:
            for included_item in alert["included"]:
                if included_item.get("type") == "event" and included_item.get(
                    "id"
                ) == event_data.get("id"):
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
                        event_data["iocs"] = event_attrs["primarySecondaryFields"]
                    break
        return event_data

    def _analyze_rule_for_techniques(self, rule_id: str) -> set:
        """Analyze rule ID for MITRE technique indicators"""
        techniques = set()

        rule_mappings = {
            "privilege": "TA0004",
            "escalation": "TA0004",
            "lateral": "TA0008",
            "movement": "TA0008",
            "exfil": "TA0010",
            "data": "TA0010",
            "credential": "TA0006",
            "password": "TA0006",
            "persistence": "TA0003",
            "backdoor": "TA0003",
            "discovery": "TA0007",
            "recon": "TA0007",
        }

        for keyword, technique in rule_mappings.items():
            if keyword in rule_id:
                techniques.add(technique)

        return techniques

    def _analyze_message_for_techniques(self, message_content: str) -> set:
        """Analyze message content for MITRE technique indicators"""
        techniques = set()

        message_mappings = {
            "TA0011": ["command and control", "c2", "beacon"],
            "TA0002": ["malware", "execution", "payload"],
            "TA0040": ["impact", "destruction", "ransom"],
            "TA0005": ["evasion", "bypass", "disable"],
            "TA0001": ["initial access", "exploit", "vulnerability"],
        }

        for technique_id, keywords in message_mappings.items():
            if any(keyword in message_content for keyword in keywords):
                techniques.add(technique_id)

        return techniques

    def _extract_iocs_from_text(self, text: str) -> List[Dict[str, str]]:
        """Extract IOCs from text using regex patterns"""
        iocs = []

        for ioc_type, pattern in self.ioc_patterns.items():
            matches = re.findall(pattern, text)
            for match in matches:
                # Basic validation for domains
                if ioc_type == "domain" and ("." not in match or len(match) <= 4):
                    continue

                iocs.append({"type": ioc_type, "value": match})

        return iocs

    def _extract_iocs_from_events(
        self, included_items: List[Dict]
    ) -> List[Dict[str, Any]]:
        """Extract IOCs from event data in included items"""
        iocs = []

        for included_item in included_items:
            if included_item.get("type") == "event":
                event_attrs = included_item.get("attributes", {})

                # Extract from primarySecondaryFields
                if "primarySecondaryFields" in event_attrs:
                    fields = event_attrs["primarySecondaryFields"]
                    for key, value in fields.items():
                        if value and str(value).strip():
                            iocs.append(
                                {
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
                            )

        return iocs

    def _determine_data_sources(self, results: Dict[str, Any]) -> List[str]:
        """Determine data sources based on extraction results"""
        data_sources = set(["xdr_api"])

        if results.get("assets"):
            data_sources.add("asset_management")
        if results.get("events"):
            data_sources.add("event_correlation")
        if results.get("mitre_techniques"):
            data_sources.add("mitre_mapping")
        if results.get("threat_intelligence"):
            data_sources.add("threat_intelligence")

        return list(data_sources)
