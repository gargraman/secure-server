"""
XDR MITRE ATT&CK API Client
=========================

Client module for interacting with XDR MITRE ATT&CK API endpoints.
"""

import logging
from typing import Any, Dict, List, Optional, Union

import httpx

from ..client import XDRAPIError, XDRClient, XDRConfig

# Configure logging
logger = logging.getLogger(__name__)


class XDRMitreAttackClient(XDRClient):
    """
    Client for interacting with XDR MITRE ATT&CK API

    Provides methods to:
    - Get MITRE ATT&CK matrix details
    - Get specific technique information
    - Get tactics information
    """

    async def get_mitre_matrix(
        self,
        version: Optional[str] = None,
        fields: Optional[List[str]] = None,
        filters: Optional[Dict[str, str]] = None,
    ) -> Dict[str, Any]:
        """
        Fetch MITRE ATT&CK matrix details

        Args:
            version: MITRE ATT&CK version (e.g., "v9.0")
            fields: List of fields to include in the response
            filters: Dictionary of filters to apply

        Returns:
            Dict containing MITRE matrix data

        Raises:
            XDRAPIError: If the API request fails
        """
        logger.info(f"Fetching MITRE ATT&CK matrix version: {version}")

        # Default fields if none specified
        if fields is None:
            fields = ["id", "name", "tactics", "techniques"]

        # Build query parameters
        params = {"fields": ",".join(fields)}

        # Add version if specified
        if version:
            params["version"] = version

        # Add filters if provided
        if filters:
            for key, value in filters.items():
                params[f"filter[{key}]"] = value

        url = f"{self.config.base_url}/api/v1/mitreAttack"

        try:
            logger.debug(f"Requesting URL: {url}")
            logger.debug(f"Request params: {params}")
            response = await self.client.get(url, params=params)
            logger.debug(f"Response status: {response.status_code}")
            return self._handle_response(response)
        except httpx.RequestError as e:
            logger.error(f"Network error while fetching MITRE matrix: {e}")
            raise XDRAPIError(f"Network error: {e}")

    async def get_technique_details(
        self,
        technique_id: str,
        version: Optional[str] = None,
        fields: Optional[List[str]] = None,
    ) -> Dict[str, Any]:
        """
        Fetch details for a specific MITRE ATT&CK technique

        Args:
            technique_id: ID of the technique (e.g., "T1059")
            version: MITRE ATT&CK version (e.g., "v9.0")
            fields: List of fields to include in the response

        Returns:
            Dict containing technique details

        Raises:
            XDRAPIError: If the API request fails
        """
        logger.info(f"Fetching details for MITRE technique: {technique_id}")

        # Default fields if none specified
        if fields is None:
            fields = [
                "id",
                "name",
                "description",
                "tactics",
                "subtechniques",
                "detection",
                "mitigation",
            ]

        # Build query parameters
        params = {"fields": ",".join(fields)}

        # Add version if specified
        if version:
            params["version"] = version

        url = f"{self.config.base_url}/api/v1/mitreAttack/techniques/{technique_id}"

        try:
            logger.debug(f"Requesting URL: {url}")
            logger.debug(f"Request params: {params}")
            response = await self.client.get(url, params=params)
            logger.debug(f"Response status: {response.status_code}")
            return self._handle_response(response)
        except httpx.RequestError as e:
            logger.error(f"Network error while fetching technique {technique_id}: {e}")
            raise XDRAPIError(f"Network error: {e}")

    async def get_tactic_details(
        self,
        tactic_id: str,
        version: Optional[str] = None,
        fields: Optional[List[str]] = None,
    ) -> Dict[str, Any]:
        """
        Fetch details for a specific MITRE ATT&CK tactic

        Args:
            tactic_id: ID of the tactic (e.g., "TA0001")
            version: MITRE ATT&CK version (e.g., "v9.0")
            fields: List of fields to include in the response

        Returns:
            Dict containing tactic details

        Raises:
            XDRAPIError: If the API request fails
        """
        logger.info(f"Fetching details for MITRE tactic: {tactic_id}")

        # Default fields if none specified
        if fields is None:
            fields = ["id", "name", "description", "techniques"]

        # Build query parameters
        params = {"fields": ",".join(fields)}

        # Add version if specified
        if version:
            params["version"] = version

        url = f"{self.config.base_url}/api/v1/mitreAttack/tactics/{tactic_id}"

        try:
            logger.debug(f"Requesting URL: {url}")
            logger.debug(f"Request params: {params}")
            response = await self.client.get(url, params=params)
            logger.debug(f"Response status: {response.status_code}")
            return self._handle_response(response)
        except httpx.RequestError as e:
            logger.error(f"Network error while fetching tactic {tactic_id}: {e}")
            raise XDRAPIError(f"Network error: {e}")

    async def get_mitre_versions(self) -> Dict[str, Any]:
        """
        Fetch available MITRE ATT&CK versions

        Returns:
            Dict containing available MITRE versions

        Raises:
            XDRAPIError: If the API request fails
        """
        logger.info("Fetching available MITRE ATT&CK versions")

        url = f"{self.config.base_url}/api/v1/mitreAttack/versions"

        try:
            logger.debug(f"Requesting URL: {url}")
            response = await self.client.get(url)
            logger.debug(f"Response status: {response.status_code}")
            return self._handle_response(response)
        except httpx.RequestError as e:
            logger.error(f"Network error while fetching MITRE versions: {e}")
            raise XDRAPIError(f"Network error: {e}")

    async def get_alerts_by_technique(
        self,
        technique_id: str,
        page_limit: int = 10,
        page_offset: int = 0,
        sort: str = "-createdAt",
        fields: Optional[List[str]] = None,
        filters: Optional[Dict[str, str]] = None,
    ) -> Dict[str, Any]:
        """
        Fetch alerts associated with a specific MITRE ATT&CK technique

        Args:
            technique_id: ID of the technique (e.g., "T1059")
            page_limit: Number of alerts per page
            page_offset: Page offset for pagination
            sort: Sort order (default: "-createdAt")
            fields: List of fields to include in the response
            filters: Dictionary of filters to apply

        Returns:
            Dict containing alerts data

        Raises:
            XDRAPIError: If the API request fails
        """
        logger.info(f"Fetching alerts for MITRE technique: {technique_id}")

        # Default fields if none specified
        if fields is None:
            fields = ["id", "name", "message", "severity", "status", "time"]

        # Build query parameters
        params = {
            "fields": ",".join(fields),
            "page[limit]": page_limit,
            "page[offset]": page_offset,
            "sort": sort,
            "filter[technique]": technique_id,
        }

        # Add additional filters if provided
        if filters:
            for key, value in filters.items():
                params[f"filter[{key}]"] = value

        url = f"{self.config.base_url}/api/v1/alerts"

        try:
            logger.debug(f"Requesting URL: {url}")
            logger.debug(f"Request params: {params}")
            response = await self.client.get(url, params=params)
            logger.debug(f"Response status: {response.status_code}")
            return self._handle_response(response)
        except httpx.RequestError as e:
            logger.error(
                f"Network error while fetching alerts for technique {technique_id}: {e}"
            )
            raise XDRAPIError(f"Network error: {e}")
