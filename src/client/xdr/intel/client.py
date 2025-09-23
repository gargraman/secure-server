"""
XDR Intel API Client
===================

Client module for interacting with XDR Intelligence API endpoints.
"""

import logging
from typing import Any, Dict, List, Optional, Union
from uuid import UUID

import httpx

from ..client import XDRAPIError, XDRClient, XDRConfig

# Configure logging
logger = logging.getLogger(__name__)


class XDRIntelClient(XDRClient):
    """
    Client for interacting with XDR Intel API

    Provides methods to:
    - Get intelligence information for a specific alert
    - Get case-related intelligence
    - Search threat intelligence
    """

    async def get_alert_intel(
        self, alert_id: Union[str, UUID], fields: Optional[List[str]] = None
    ) -> Dict[str, Any]:
        """
        Fetch intelligence information for a specific alert

        Args:
            alert_id: UUID of the alert
            fields: List of fields to include in the response

        Returns:
            Dict containing intelligence data

        Raises:
            XDRAPIError: If the API request fails
        """
        # Validate UUID format
        try:
            if isinstance(alert_id, str):
                UUID(alert_id)  # This will raise ValueError if invalid
        except ValueError:
            raise XDRAPIError(f"Invalid UUID format: {alert_id}")

        logger.info(f"Fetching intelligence for alert: {alert_id}")

        # Default fields if none specified
        if fields is None:
            fields = ["id", "analysis", "source", "indicators", "tactics", "techniques"]

        params = {"fields": ",".join(fields)}
        url = f"{self.config.base_url}/api/v1/alerts/{alert_id}/intelligence"

        try:
            logger.debug(f"Requesting URL: {url}")
            logger.debug(f"Request params: {params}")
            response = await self.client.get(url, params=params)
            logger.debug(f"Response status: {response.status_code}")
            return self._handle_response(response)
        except httpx.RequestError as e:
            logger.error(
                f"Network error while fetching intelligence for alert {alert_id}: {e}"
            )
            raise XDRAPIError(f"Network error: {e}")

    async def get_intel_context(
        self, search_params: Dict[str, Any], fields: Optional[List[str]] = None
    ) -> Dict[str, Any]:
        """
        Fetch intelligence context based on search parameters

        Args:
            search_params: Dictionary of search parameters
            fields: List of fields to include in the response

        Returns:
            Dict containing intelligence context

        Raises:
            XDRAPIError: If the API request fails
        """
        logger.info(f"Fetching intelligence context with params: {search_params}")

        # Default fields if none specified
        if fields is None:
            fields = ["id", "analysis", "source", "indicators", "tactics", "techniques"]

        url = f"{self.config.base_url}/api/v1/intelContext"

        try:
            # Add fields to request body
            request_body = search_params.copy()
            request_body["fields"] = fields

            logger.debug(f"Requesting URL: {url}")
            logger.debug(f"Request body: {request_body}")
            response = await self.client.post(url, json=request_body)
            logger.debug(f"Response status: {response.status_code}")
            return self._handle_response(response)
        except httpx.RequestError as e:
            logger.error(f"Network error while fetching intelligence context: {e}")
            raise XDRAPIError(f"Network error: {e}")

    async def get_case_intel(
        self, case_id: str, fields: Optional[List[str]] = None
    ) -> Dict[str, Any]:
        """
        Fetch intelligence related to a specific case

        Args:
            case_id: ID of the case
            fields: List of fields to include in the response

        Returns:
            Dict containing case intelligence data

        Raises:
            XDRAPIError: If the API request fails
        """
        logger.info(f"Fetching intelligence for case: {case_id}")

        # Default fields if none specified
        if fields is None:
            fields = ["id", "analysis", "source", "indicators", "tactics", "techniques"]

        params = {"fields": ",".join(fields), "caseId": case_id}
        url = f"{self.config.base_url}/api/v1/intelContext/case"

        try:
            logger.debug(f"Requesting URL: {url}")
            logger.debug(f"Request params: {params}")
            response = await self.client.get(url, params=params)
            logger.debug(f"Response status: {response.status_code}")
            return self._handle_response(response)
        except httpx.RequestError as e:
            logger.error(
                f"Network error while fetching intelligence for case {case_id}: {e}"
            )
            raise XDRAPIError(f"Network error: {e}")

    async def search_intel(
        self,
        search_text: str,
        fields: Optional[List[str]] = None,
        page_limit: int = 10,
        page_offset: int = 0,
        sort: str = "-createdAt",
        filters: Optional[Dict[str, str]] = None,
    ) -> Dict[str, Any]:
        """
        Search for intelligence across all alerts

        Args:
            search_text: Text to search for in intelligence data
            fields: List of fields to include in the response
            page_limit: Number of results per page
            page_offset: Page offset for pagination
            sort: Sort order (default: "-createdAt")
            filters: Dictionary of filters to apply

        Returns:
            Dict containing intelligence data and metadata

        Raises:
            XDRAPIError: If the API request fails
        """
        logger.info(f"Searching intelligence with query: {search_text}")

        # Default fields if none specified
        if fields is None:
            fields = [
                "id",
                "analysis",
                "source",
                "indicators",
                "tactics",
                "techniques",
                "alertId",
            ]

        # Build query parameters
        params = {
            "fields": ",".join(fields),
            "page[limit]": page_limit,
            "page[offset]": page_offset,
            "sort": sort,
            "searchText": search_text,
        }

        # Add filters if provided
        if filters:
            for key, value in filters.items():
                params[f"filter[{key}]"] = value

        url = f"{self.config.base_url}/api/v1/intel"

        try:
            logger.debug(f"Requesting URL: {url}")
            logger.debug(f"Request params: {params}")
            response = await self.client.get(url, params=params)
            logger.debug(f"Response status: {response.status_code}")
            return self._handle_response(response)
        except httpx.RequestError as e:
            logger.error(f"Network error while searching intelligence: {e}")
            raise XDRAPIError(f"Network error: {e}")

    async def get_intel_details(
        self, intel_id: Union[str, UUID], fields: Optional[List[str]] = None
    ) -> Dict[str, Any]:
        """
        Fetch details for specific intelligence

        Args:
            intel_id: UUID of the intelligence
            fields: List of fields to include in the response

        Returns:
            Dict containing intelligence details

        Raises:
            XDRAPIError: If the API request fails
        """
        # Validate UUID format
        try:
            if isinstance(intel_id, str):
                UUID(intel_id)  # This will raise ValueError if invalid
        except ValueError:
            raise XDRAPIError(f"Invalid UUID format: {intel_id}")

        logger.info(f"Fetching details for intelligence: {intel_id}")

        # Default fields if none specified
        if fields is None:
            fields = [
                "id",
                "analysis",
                "source",
                "indicators",
                "tactics",
                "techniques",
                "alerts",
            ]

        params = {"fields": ",".join(fields)}
        url = f"{self.config.base_url}/api/v1/intel/{intel_id}"

        try:
            logger.debug(f"Requesting URL: {url}")
            logger.debug(f"Request params: {params}")
            response = await self.client.get(url, params=params)
            logger.debug(f"Response status: {response.status_code}")
            return self._handle_response(response)
        except httpx.RequestError as e:
            logger.error(f"Network error while fetching intelligence {intel_id}: {e}")
            raise XDRAPIError(f"Network error: {e}")
