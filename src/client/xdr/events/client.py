"""
XDR Events API Client
===================

Client module for interacting with XDR Events API endpoints.
"""

import logging
from typing import Any, Dict, List, Optional, Union
from uuid import UUID

import httpx

from ..client import XDRAPIError, XDRClient, XDRConfig

# Configure logging
logger = logging.getLogger(__name__)


class XDREventClient(XDRClient):
    """
    Client for interacting with XDR Events API

    Provides methods to:
    - Get events for a specific alert
    - Get event statistics
    - Update event timeline
    """

    async def get_alert_events(
        self,
        alert_id: Union[str, UUID],
        fields: Optional[List[str]] = None,
        page_limit: int = 10,
        page_offset: int = 0,
        sort: str = "-time",
        filters: Optional[Dict[str, str]] = None,
    ) -> Dict[str, Any]:
        """
        Fetch events associated with a specific alert

        Args:
            alert_id: UUID of the alert
            fields: List of fields to include in the response
            page_limit: Number of events per page
            page_offset: Page offset for pagination
            sort: Sort order (default: "-time")
            filters: Dictionary of filters to apply

        Returns:
            Dict containing events data and metadata

        Raises:
            XDRAPIError: If the API request fails
        """
        # Validate UUID format
        try:
            if isinstance(alert_id, str):
                UUID(alert_id)  # This will raise ValueError if invalid
        except ValueError:
            raise XDRAPIError(f"Invalid UUID format: {alert_id}")

        logger.info(f"Fetching events for alert: {alert_id}")

        # Default fields if none specified
        if fields is None:
            fields = ["id", "type", "time", "source", "details"]

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

        url = f"{self.config.base_url}/api/v1/alerts/{alert_id}/events"

        try:
            logger.debug(f"Requesting URL: {url}")
            logger.debug(f"Request params: {params}")
            response = await self.client.get(url, params=params)
            logger.debug(f"Response status: {response.status_code}")
            return self._handle_response(response)
        except httpx.RequestError as e:
            logger.error(
                f"Network error while fetching events for alert {alert_id}: {e}"
            )
            raise XDRAPIError(f"Network error: {e}")

    async def get_event_stats(self, alert_id: Union[str, UUID]) -> Dict[str, Any]:
        """
        Fetch event statistics for a specific alert

        Args:
            alert_id: UUID of the alert

        Returns:
            Dict containing event statistics

        Raises:
            XDRAPIError: If the API request fails
        """
        # Validate UUID format
        try:
            if isinstance(alert_id, str):
                UUID(alert_id)  # This will raise ValueError if invalid
        except ValueError:
            raise XDRAPIError(f"Invalid UUID format: {alert_id}")

        logger.info(f"Fetching event statistics for alert: {alert_id}")

        url = f"{self.config.base_url}/api/v1/alerts/{alert_id}/events/stats"

        try:
            logger.debug(f"Requesting URL: {url}")
            response = await self.client.get(url)
            logger.debug(f"Response status: {response.status_code}")
            return self._handle_response(response)
        except httpx.RequestError as e:
            logger.error(
                f"Network error while fetching event stats for alert {alert_id}: {e}"
            )
            raise XDRAPIError(f"Network error: {e}")

    async def update_events_timeline(
        self, alert_id: Union[str, UUID], event_updates: Dict[str, Any]
    ) -> Dict[str, Any]:
        """
        Update the events timeline for a specific alert

        Args:
            alert_id: UUID of the alert
            event_updates: Dictionary containing event timeline updates

        Returns:
            Dict containing response data

        Raises:
            XDRAPIError: If the API request fails
        """
        # Validate UUID format
        try:
            if isinstance(alert_id, str):
                UUID(alert_id)  # This will raise ValueError if invalid
        except ValueError:
            raise XDRAPIError(f"Invalid UUID format: {alert_id}")

        logger.info(f"Updating events timeline for alert: {alert_id}")

        url = f"{self.config.base_url}/api/v1/alerts/{alert_id}/events"

        try:
            logger.debug(f"Requesting URL: {url}")
            logger.debug(f"Request data: {event_updates}")
            response = await self.client.patch(url, json=event_updates)
            logger.debug(f"Response status: {response.status_code}")
            return self._handle_response(response)
        except httpx.RequestError as e:
            logger.error(
                f"Network error while updating events timeline for alert {alert_id}: {e}"
            )
            raise XDRAPIError(f"Network error: {e}")

    async def search_events(
        self,
        search_text: Optional[str] = None,
        fields: Optional[List[str]] = None,
        page_limit: int = 10,
        page_offset: int = 0,
        sort: str = "-time",
        filters: Optional[Dict[str, str]] = None,
    ) -> Dict[str, Any]:
        """
        Search events across all alerts

        Args:
            search_text: Text to search for in events
            fields: List of fields to include in the response
            page_limit: Number of events per page
            page_offset: Page offset for pagination
            sort: Sort order (default: "-time")
            filters: Dictionary of filters to apply

        Returns:
            Dict containing events data and metadata

        Raises:
            XDRAPIError: If the API request fails
        """
        logger.info(f"Searching events with query: {search_text}")

        # Default fields if none specified
        if fields is None:
            fields = ["id", "type", "time", "source", "details", "alertId"]

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

        url = f"{self.config.base_url}/api/v1/events"

        try:
            logger.debug(f"Requesting URL: {url}")
            logger.debug(f"Request params: {params}")
            response = await self.client.get(url, params=params)
            logger.debug(f"Response status: {response.status_code}")
            return self._handle_response(response)
        except httpx.RequestError as e:
            logger.error(f"Network error while searching events: {e}")
            raise XDRAPIError(f"Network error: {e}")
