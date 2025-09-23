"""
XDR Assets API Client
===================

Client module for interacting with XDR Assets API endpoints.
"""

import logging
from typing import Any, Dict, List, Optional, Union
from uuid import UUID

import httpx

from ..client import XDRAPIError, XDRClient, XDRConfig

# Configure logging
logger = logging.getLogger(__name__)


class XDRAssetClient(XDRClient):
    """
    Client for interacting with XDR Assets API

    Provides methods to:
    - Get assets for a specific alert
    - Get asset statistics
    """

    async def get_alert_assets(
        self,
        alert_id: Union[str, UUID],
        fields: Optional[List[str]] = None,
        page_limit: int = 10,
        page_offset: int = 0,
        sort: str = "-updatedAt",
        filters: Optional[Dict[str, str]] = None,
    ) -> Dict[str, Any]:
        """
        Fetch assets associated with a specific alert

        Args:
            alert_id: UUID of the alert
            fields: List of fields to include in the response
            page_limit: Number of assets per page
            page_offset: Page offset for pagination
            sort: Sort order (default: "-updatedAt")
            filters: Dictionary of filters to apply

        Returns:
            Dict containing assets data and metadata

        Raises:
            XDRAPIError: If the API request fails
        """
        # Validate UUID format
        try:
            if isinstance(alert_id, str):
                UUID(alert_id)  # This will raise ValueError if invalid
        except ValueError:
            raise XDRAPIError(f"Invalid UUID format: {alert_id}")

        logger.info(f"Fetching assets for alert: {alert_id}")

        # Default fields if none specified
        if fields is None:
            fields = ["id", "name", "hostname", "ipAddress", "type", "risk", "details"]

        # Build query parameters
        params = {
            "fields": ",".join(fields),
            "page[limit]": page_limit,
            "page[offset]": page_offset,
            "sort": sort,
        }

        # Add filters if provided
        if filters:
            for key, value in filters.items():
                params[f"filter[{key}]"] = value

        url = f"{self.config.base_url}/api/v1/alerts/{alert_id}/assets"

        try:
            logger.debug(f"Requesting URL: {url}")
            logger.debug(f"Request params: {params}")
            response = await self.client.get(url, params=params)
            logger.debug(f"Response status: {response.status_code}")
            return self._handle_response(response)
        except httpx.RequestError as e:
            logger.error(
                f"Network error while fetching assets for alert {alert_id}: {e}"
            )
            raise XDRAPIError(f"Network error: {e}")

    async def get_asset_stats(self, alert_id: Union[str, UUID]) -> Dict[str, Any]:
        """
        Fetch asset statistics for a specific alert

        Args:
            alert_id: UUID of the alert

        Returns:
            Dict containing asset statistics

        Raises:
            XDRAPIError: If the API request fails
        """
        # Validate UUID format
        try:
            if isinstance(alert_id, str):
                UUID(alert_id)  # This will raise ValueError if invalid
        except ValueError:
            raise XDRAPIError(f"Invalid UUID format: {alert_id}")

        logger.info(f"Fetching asset statistics for alert: {alert_id}")

        url = f"{self.config.base_url}/api/v1/alerts/{alert_id}/assets/stats"

        try:
            logger.debug(f"Requesting URL: {url}")
            response = await self.client.get(url)
            logger.debug(f"Response status: {response.status_code}")
            return self._handle_response(response)
        except httpx.RequestError as e:
            logger.error(
                f"Network error while fetching asset stats for alert {alert_id}: {e}"
            )
            raise XDRAPIError(f"Network error: {e}")

    async def search_assets(
        self,
        search_text: Optional[str] = None,
        fields: Optional[List[str]] = None,
        page_limit: int = 10,
        page_offset: int = 0,
        sort: str = "-updatedAt",
        filters: Optional[Dict[str, str]] = None,
    ) -> Dict[str, Any]:
        """
        Search assets across all alerts

        Args:
            search_text: Text to search for in assets
            fields: List of fields to include in the response
            page_limit: Number of assets per page
            page_offset: Page offset for pagination
            sort: Sort order (default: "-updatedAt")
            filters: Dictionary of filters to apply

        Returns:
            Dict containing assets data and metadata

        Raises:
            XDRAPIError: If the API request fails
        """
        logger.info(f"Searching assets with query: {search_text}")

        # Default fields if none specified
        if fields is None:
            fields = [
                "id",
                "name",
                "hostname",
                "ipAddress",
                "type",
                "risk",
                "details",
                "alertId",
            ]

        # Build query parameters
        params = {
            "fields": ",".join(fields),
            "page[limit]": page_limit,
            "page[offset]": page_offset,
            "sort": sort,
        }

        # Add search text if provided
        if search_text:
            params["searchText"] = search_text

        # Add filters if provided
        if filters:
            for key, value in filters.items():
                params[f"filter[{key}]"] = value

        url = f"{self.config.base_url}/api/v1/assets"

        try:
            logger.debug(f"Requesting URL: {url}")
            logger.debug(f"Request params: {params}")
            response = await self.client.get(url, params=params)
            logger.debug(f"Response status: {response.status_code}")
            return self._handle_response(response)
        except httpx.RequestError as e:
            logger.error(f"Network error while searching assets: {e}")
            raise XDRAPIError(f"Network error: {e}")

    async def get_asset_details(
        self, asset_id: Union[str, UUID], fields: Optional[List[str]] = None
    ) -> Dict[str, Any]:
        """
        Fetch details for a specific asset

        Args:
            asset_id: UUID of the asset
            fields: List of fields to include in the response

        Returns:
            Dict containing asset details

        Raises:
            XDRAPIError: If the API request fails
        """
        # Validate UUID format
        try:
            if isinstance(asset_id, str):
                UUID(asset_id)  # This will raise ValueError if invalid
        except ValueError:
            raise XDRAPIError(f"Invalid UUID format: {asset_id}")

        logger.info(f"Fetching details for asset: {asset_id}")

        # Default fields if none specified
        if fields is None:
            fields = [
                "id",
                "name",
                "hostname",
                "ipAddress",
                "type",
                "risk",
                "details",
                "alerts",
            ]

        params = {"fields": ",".join(fields)}
        url = f"{self.config.base_url}/api/v1/assets/{asset_id}"

        try:
            logger.debug(f"Requesting URL: {url}")
            logger.debug(f"Request params: {params}")
            response = await self.client.get(url, params=params)
            logger.debug(f"Response status: {response.status_code}")
            return self._handle_response(response)
        except httpx.RequestError as e:
            logger.error(f"Network error while fetching asset {asset_id}: {e}")
            raise XDRAPIError(f"Network error: {e}")
