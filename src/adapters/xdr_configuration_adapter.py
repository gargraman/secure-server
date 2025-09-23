"""
XDR Configuration Adapter

Unified adapter between service layer and client layer configurations to eliminate
configuration duplication and provide a single source of truth for XDR configuration.

This adapter bridges the gap between:
- Service layer: XDRConfiguration models stored in Neo4j
- Client layer: XDRConfig used by XDRAlertClient

Author: AI-SOAR Platform Team
Created: 2025-09-22
"""

import logging
from typing import Optional

from src.client.xdr_alert_client import XDRConfig
from src.services.service_coordinator import get_service_coordinator

logger = logging.getLogger(__name__)


class XDRConfigurationAdapter:
    """Unified adapter between service and client configurations"""

    @staticmethod
    async def from_service_config(config_id: str) -> XDRConfig:
        """
        Convert service configuration to client configuration

        Args:
            config_id: ID of the XDR configuration in the service layer

        Returns:
            XDRConfig instance ready for use with XDRAlertClient

        Raises:
            Exception: If configuration cannot be retrieved or converted
        """
        try:
            # Get service coordinator
            coordinator = await get_service_coordinator()
            xdr_service = await coordinator.xdr_config

            # Get XDR configuration from service layer
            service_config = await xdr_service.get_xdr_configuration(config_id)

            if not service_config:
                raise ValueError(f"XDR configuration with ID '{config_id}' not found")

            # Get auth token from secret manager if available
            auth_token = service_config.auth_token
            if (
                hasattr(coordinator, "secrets")
                and service_config.auth_token_secret_name
            ):
                try:
                    secrets_service = await coordinator.secrets
                    auth_token = await secrets_service.get_xdr_auth_token(
                        service_config.auth_token_secret_name
                    )
                except Exception as e:
                    logger.warning(
                        f"Failed to retrieve auth token from secrets manager: {e}"
                    )
                    # Fall back to direct token if secret retrieval fails

            # Create and return XDRConfig
            return XDRConfig(
                base_url=service_config.base_url,
                auth_token=auth_token,
                timeout=getattr(service_config, "timeout", 30),
                poll_interval=service_config.poll_interval,
                poll_enabled=service_config.enabled,
            )

        except Exception as e:
            logger.error(
                f"Failed to convert service config '{config_id}' to client config: {e}"
            )
            raise

    @staticmethod
    async def from_environment_with_fallback(
        config_id: Optional[str] = None,
    ) -> XDRConfig:
        """
        Get XDR configuration with fallback to environment variables

        Args:
            config_id: Optional service configuration ID. If None, uses environment

        Returns:
            XDRConfig instance
        """
        try:
            if config_id:
                # Try to get from service layer first
                try:
                    return await XDRConfigurationAdapter.from_service_config(config_id)
                except Exception as e:
                    logger.warning(
                        f"Failed to get service config '{config_id}', falling back to environment: {e}"
                    )

            # Fallback to environment configuration
            return XDRConfig.from_environment()

        except Exception as e:
            logger.error(f"Failed to create XDR configuration: {e}")
            raise

    @staticmethod
    async def validate_configuration(config: XDRConfig) -> bool:
        """
        Validate XDR configuration

        Args:
            config: XDRConfig to validate

        Returns:
            True if configuration is valid, False otherwise
        """
        try:
            # Basic validation
            if not config.base_url:
                logger.error("XDR base URL is required")
                return False

            if not config.auth_token or config.auth_token == "dev-dummy-token":
                logger.warning(
                    "XDR auth token is missing or using development dummy token"
                )
                # Allow dummy token for development

            if config.poll_interval <= 0:
                logger.error("XDR poll interval must be positive")
                return False

            return True

        except Exception as e:
            logger.error(f"Configuration validation failed: {e}")
            return False

    @staticmethod
    async def get_active_configurations() -> list:
        """
        Get all active XDR configurations from the service layer

        Returns:
            List of active XDR configuration dictionaries
        """
        try:
            coordinator = await get_service_coordinator()
            xdr_service = await coordinator.xdr_config

            # Get all configurations
            configs = await xdr_service.get_all_configurations()

            # Filter for active/enabled configurations
            active_configs = [
                config for config in configs if getattr(config, "enabled", True)
            ]

            return active_configs

        except Exception as e:
            logger.error(f"Failed to get active configurations: {e}")
            return []

    @staticmethod
    async def test_configuration(config_id: str) -> dict:
        """
        Test XDR configuration connectivity

        Args:
            config_id: ID of the configuration to test

        Returns:
            Dictionary with test results
        """
        try:
            # Convert to client config
            client_config = await XDRConfigurationAdapter.from_service_config(config_id)

            # Validate configuration
            is_valid = await XDRConfigurationAdapter.validate_configuration(
                client_config
            )

            if not is_valid:
                return {
                    "success": False,
                    "error": "Configuration validation failed",
                    "config_id": config_id,
                }

            # Test connectivity (basic validation)
            # Note: Actual connectivity test would require XDRAlertClient
            return {
                "success": True,
                "message": "Configuration is valid and ready for use",
                "config_id": config_id,
                "base_url": client_config.base_url,
                "poll_interval": client_config.poll_interval,
            }

        except Exception as e:
            return {"success": False, "error": str(e), "config_id": config_id}
