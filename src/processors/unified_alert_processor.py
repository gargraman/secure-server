"""
Unified Alert Processor

Consolidated alert processing with configurable storage backends and simplified
data processing pipeline. Replaces the complex multiple processing modes with
a single, unified approach that gracefully handles failures.

Author: AI-SOAR Platform Team
Created: 2025-09-22
"""

import json
import logging
import os
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Callable, Dict, List, Optional

from src.database.models import AlertClassification
from src.services.service_coordinator import ServiceCoordinator

logger = logging.getLogger(__name__)


class UnifiedAlertProcessor:
    """Unified alert processing with configurable storage backends"""

    def __init__(
        self,
        coordinator: ServiceCoordinator,
        storage_backends: Optional[List[str]] = None,
        data_extractor: Optional[Any] = None,
    ):
        """
        Initialize unified alert processor

        Args:
            coordinator: Service coordinator for accessing services
            storage_backends: List of storage backends ('graph', 'file', 'both')
            data_extractor: Optional data extractor for comprehensive data collection
        """
        self.coordinator = coordinator
        self.storage_backends = storage_backends or ["graph", "file"]
        self.data_extractor = data_extractor

        # Processing statistics
        self.stats = {
            "total_processed": 0,
            "successful_enhanced": 0,
            "fallback_basic": 0,
            "storage_failures": 0,
        }

    async def process_alerts(self, alerts: List[Dict]) -> None:
        """
        Single method for all alert processing with graceful degradation

        Args:
            alerts: List of alert dictionaries from XDR API
        """
        if not alerts:
            return

        logger.info(f"Processing {len(alerts)} alerts with unified processor")

        for alert in alerts:
            await self._process_single_alert(alert)

        # Log processing statistics
        logger.info(f"Processing stats: {self.stats}")

    async def _process_single_alert(self, alert: Dict) -> None:
        """
        Process a single alert with comprehensive error handling

        Args:
            alert: Alert dictionary from XDR API
        """
        alert_id = alert.get("id", "unknown")

        try:
            self.stats["total_processed"] += 1

            # Attempt enhanced processing
            enhanced_alert = await self._enhance_alert_data(alert)

            if enhanced_alert.get("comprehensive_data"):
                self.stats["successful_enhanced"] += 1
                await self._store_alert(enhanced_alert, enhanced=True)
                logger.debug(f"Successfully processed enhanced alert {alert_id}")
            else:
                # Fall back to basic processing
                self.stats["fallback_basic"] += 1
                await self._store_alert(alert, enhanced=False)
                logger.info(f"Processed alert {alert_id} in basic mode")

        except Exception as e:
            logger.error(f"Failed to process alert {alert_id}: {e}")
            self.stats["fallback_basic"] += 1

            # Last resort: store basic alert
            try:
                await self._store_basic_alert(alert)
            except Exception as storage_error:
                logger.error(f"Failed to store basic alert {alert_id}: {storage_error}")
                self.stats["storage_failures"] += 1

    async def _enhance_alert_data(self, alert: Dict) -> Dict[str, Any]:
        """
        Enhance alert data with comprehensive security information

        Args:
            alert: Base alert data

        Returns:
            Enhanced alert data or original alert if enhancement fails
        """
        try:
            if not self.data_extractor:
                # No data extractor available, return original alert
                return alert

            # Use data extractor for comprehensive data collection
            comprehensive_data = await self.data_extractor.extract_comprehensive_data(
                alert
            )

            # Create enhanced alert structure
            enhanced_alert = alert.copy()
            enhanced_alert["comprehensive_data"] = comprehensive_data
            enhanced_alert["comprehensive_data"]["analysis_metadata"] = {
                "collection_timestamp": datetime.now(timezone.utc).isoformat(),
                "processor_version": "unified_v1",
                "enhancement_status": "completed",
            }

            return enhanced_alert

        except Exception as e:
            logger.warning(f"Alert enhancement failed for {alert.get('id')}: {e}")
            # Return original alert with error metadata
            alert_copy = alert.copy()
            alert_copy["enhancement_error"] = {
                "error_message": str(e),
                "timestamp": datetime.now(timezone.utc).isoformat(),
                "enhancement_status": "failed",
            }
            return alert_copy

    async def _store_alert(self, alert_data: Dict, enhanced: bool = False) -> None:
        """
        Store alert using configured backends

        Args:
            alert_data: Alert data to store
            enhanced: Whether this is enhanced alert data
        """
        storage_tasks = []

        # Graph database storage
        if "graph" in self.storage_backends:
            storage_tasks.append(self._store_to_graph(alert_data, enhanced))

        # File storage
        if "file" in self.storage_backends:
            storage_tasks.append(self._store_to_file(alert_data, enhanced))

        # Execute storage operations
        for task in storage_tasks:
            try:
                await task
            except Exception as e:
                logger.warning(f"Storage backend failed: {e}")
                # Continue with other storage backends

    async def _store_to_graph(self, alert_data: Dict, enhanced: bool) -> None:
        """
        Store alert to graph database

        Args:
            alert_data: Alert data to store
            enhanced: Whether this is enhanced data
        """
        try:
            alert_service = await self.coordinator.alert_processing

            if enhanced and "comprehensive_data" in alert_data:
                # Store enhanced alert
                processed_alert = await alert_service.store_enhanced_alert(alert_data)
                logger.debug(
                    f"Enhanced alert stored with classification: "
                    f"{processed_alert.classification.value}"
                )
            else:
                # Store basic alert (convert to enhanced format if needed)
                basic_enhanced = self._convert_to_enhanced_format(alert_data)
                processed_alert = await alert_service.store_enhanced_alert(
                    basic_enhanced
                )
                logger.debug(f"Basic alert stored in graph database")

        except Exception as e:
            logger.error(f"Graph storage failed: {e}")
            raise

    async def _store_to_file(self, alert_data: Dict, enhanced: bool) -> None:
        """
        Store alert to file system

        Args:
            alert_data: Alert data to store
            enhanced: Whether this is enhanced data
        """
        try:
            alert_id = alert_data.get("id", "unknown")
            timestamp = int(datetime.now().timestamp())

            # Ensure alerts directory exists
            os.makedirs("alerts", exist_ok=True)

            # Choose filename based on enhancement status
            if enhanced and "comprehensive_data" in alert_data:
                filename = f"alerts/enhanced_alert_{alert_id}_{timestamp}.json"
                summary_filename = (
                    f"alerts/enhanced_summary_{alert_id}_{timestamp}.json"
                )
                self._save_enhanced_alert_files(alert_data, filename, summary_filename)
            else:
                filename = f"alerts/alert_{alert_id}_{timestamp}.json"
                self._save_basic_alert_file(alert_data, filename)

            logger.debug(f"Alert {alert_id} saved to {filename}")

        except Exception as e:
            logger.error(f"File storage failed: {e}")
            raise

    def _save_enhanced_alert_files(
        self, alert_data: Dict, filename: str, summary_filename: str
    ) -> None:
        """Save enhanced alert with summary file"""

        # Save full alert data
        with open(filename, "w") as f:
            json.dump(alert_data, f, indent=2, default=str)

        # Create and save summary
        comprehensive_data = alert_data.get("comprehensive_data", {})
        summary_data = {
            "alert_id": alert_data.get("id"),
            "timestamp": int(datetime.now().timestamp()),
            "basic_info": {
                "name": alert_data.get("attributes", {}).get("name"),
                "severity": alert_data.get("attributes", {}).get("severity"),
                "status": alert_data.get("attributes", {}).get("status"),
                "created_at": alert_data.get("attributes", {}).get("createdAt"),
            },
            "comprehensive_summary": {
                "assets_count": len(comprehensive_data.get("assets", [])),
                "events_count": len(comprehensive_data.get("events", [])),
                "mitre_techniques_count": len(
                    comprehensive_data.get("mitre_techniques", [])
                ),
                "threat_intel_count": len(
                    comprehensive_data.get("threat_intelligence", [])
                ),
                "iocs_count": len(comprehensive_data.get("iocs", [])),
            },
            "files": {"full_data": filename, "summary": summary_filename},
        }

        with open(summary_filename, "w") as f:
            json.dump(summary_data, f, indent=2, default=str)

    def _save_basic_alert_file(self, alert_data: Dict, filename: str) -> None:
        """Save basic alert file"""
        with open(filename, "w") as f:
            json.dump(alert_data, f, indent=2, default=str)

    async def _store_basic_alert(self, alert: Dict) -> None:
        """
        Emergency basic alert storage when all else fails

        Args:
            alert: Basic alert data
        """
        try:
            # Force file storage only for emergency situations
            await self._store_to_file(alert, enhanced=False)
            logger.info(f"Emergency: Basic alert {alert.get('id')} stored to file")
        except Exception as e:
            logger.critical(f"Emergency alert storage failed: {e}")
            raise

    def _convert_to_enhanced_format(self, basic_alert: Dict) -> Dict[str, Any]:
        """
        Convert basic alert to enhanced format for consistent processing

        Args:
            basic_alert: Basic alert data

        Returns:
            Alert in enhanced format with minimal comprehensive_data
        """
        enhanced = basic_alert.copy()
        enhanced["comprehensive_data"] = {
            "assets": [],
            "events": [],
            "mitre_techniques": [],
            "threat_intelligence": [],
            "iocs": [],
            "analysis_metadata": {
                "collection_timestamp": datetime.now(timezone.utc).isoformat(),
                "data_sources": ["xdr_api"],
                "correlation_status": "basic_mode",
                "enhancement_status": "not_enhanced",
            },
        }
        return enhanced

    def get_processing_stats(self) -> Dict[str, Any]:
        """
        Get processing statistics

        Returns:
            Dictionary with processing statistics
        """
        return {
            **self.stats,
            "success_rate": (
                self.stats["successful_enhanced"] + self.stats["fallback_basic"]
            )
            / max(self.stats["total_processed"], 1)
            * 100,
            "enhancement_rate": (
                self.stats["successful_enhanced"]
                / max(self.stats["total_processed"], 1)
                * 100
            ),
        }

    async def health_check(self) -> Dict[str, Any]:
        """
        Perform health check on the processor

        Returns:
            Health check results
        """
        try:
            # Check service coordinator health
            coordinator_health = await self.coordinator.health_check()

            # Check storage backends
            storage_health = {}
            if "graph" in self.storage_backends:
                try:
                    alert_service = await self.coordinator.alert_processing
                    storage_health["graph"] = (
                        "healthy" if alert_service else "unavailable"
                    )
                except Exception:
                    storage_health["graph"] = "unhealthy"

            if "file" in self.storage_backends:
                try:
                    # Test file write capability
                    test_path = Path("alerts")
                    test_path.mkdir(exist_ok=True)
                    storage_health["file"] = "healthy"
                except Exception:
                    storage_health["file"] = "unhealthy"

            return {
                "processor_status": "healthy",
                "coordinator_health": coordinator_health,
                "storage_backends": storage_health,
                "processing_stats": self.get_processing_stats(),
            }

        except Exception as e:
            return {
                "processor_status": "unhealthy",
                "error": str(e),
                "processing_stats": self.get_processing_stats(),
            }
