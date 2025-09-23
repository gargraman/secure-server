"""
XDR Client Base Module
====================

Base client module for XDR APIs with common functionality.
"""

import asyncio
import logging
import os
from dataclasses import dataclass
from typing import Optional

import httpx

# Configure logging
logging.basicConfig(
    level=logging.INFO, format="%(asctime)s - %(name)s - %(levelname)s - %(message)s"
)
logger = logging.getLogger(__name__)


@dataclass
class XDRConfig:
    """Configuration class for XDR API"""

    base_url: str
    auth_token: Optional[str] = None
    timeout: int = 30
    max_retries: int = 3
    poll_interval: int = 30  # Default polling interval in seconds
    poll_enabled: bool = False  # Whether to enable automatic polling

    @classmethod
    def from_environment(cls) -> "XDRConfig":
        """Create configuration from environment variables"""
        return cls(
            base_url=os.getenv(
                "XDR_BASE_URL",
                "https://staging.apps.fireeye.com/alert/id/hexload02org01",
            ),
            auth_token=os.getenv("XDR_AUTH_TOKEN"),
            timeout=int(os.getenv("XDR_TIMEOUT", "30")),
            max_retries=int(os.getenv("XDR_MAX_RETRIES", "3")),
            poll_interval=int(os.getenv("XDR_POLL_INTERVAL", "30")),
            poll_enabled=os.getenv("XDR_POLL_ENABLED", "").lower() == "true",
        )


class XDRAPIError(Exception):
    """Custom exception for XDR API errors"""

    def __init__(
        self, message: str, status_code: int = None, response_data: dict = None
    ):
        super().__init__(message)
        self.status_code = status_code
        self.response_data = response_data


class XDRClient:
    """
    Base client for interacting with XDR APIs

    This class provides common functionality for all XDR API clients.
    Specific API clients (Alerts, Events, Assets, etc.) extend this base class.
    """

    def __init__(self, config: XDRConfig):
        """Initialize the XDR Client"""
        self.config = config
        self.client = httpx.AsyncClient(
            timeout=config.timeout,
            headers={"Accept": "application/json", "Content-Type": "application/json"},
            follow_redirects=True,  # Automatically follow redirects
            max_redirects=5,  # Set a reasonable limit for redirects
        )

        # Add authentication header if token is provided
        if config.auth_token:
            logger.debug(f"Using XDR API key: {config.auth_token}")
            self.client.headers["x-fireeye-api-key"] = f"{config.auth_token}"

        logger.debug(
            f"Using XDR HEADER key: {self.client.headers.get('x-fireeye-api-key')}"
        )

    async def __aenter__(self):
        """Async context manager entry"""
        return self

    async def __aexit__(self, exc_type, exc_val, exc_tb):
        """Async context manager exit"""
        await self.client.aclose()
        return False  # Allow exceptions to propagate

    def _handle_response(self, response: httpx.Response) -> dict:
        """
        Handle API response and raise appropriate exceptions for error status codes

        Args:
            response: HTTP response object

        Returns:
            Dict: Parsed JSON response data

        Raises:
            XDRAPIError: For various HTTP error status codes
        """
        status_code = response.status_code

        try:
            response_data = response.json()
        except Exception:
            response_data = {"error": "Invalid JSON response"}

        # Handle successful responses
        if status_code == 200:
            logger.info(f"Request successful: {response.url}")
            return response_data

        # Handle redirect responses (although httpx should follow them automatically)
        if status_code in (301, 302, 303, 307, 308):
            redirect_url = response.headers.get("Location", "Unknown")
            logger.info(f"Redirect detected from {response.url} to {redirect_url}")
            # The client is configured to follow redirects automatically,
            # but if we reach here, it means the redirect wasn't followed successfully
            raise XDRAPIError(
                f"Redirect was not followed automatically to {redirect_url}",
                status_code,
                {"redirect_url": redirect_url},
            )

        # Handle different error status codes
        error_messages = {
            400: "Bad Request - The request is malformed or invalid",
            401: "Unauthorized - Authentication credentials are missing or invalid",
            403: "Forbidden - Access denied to the requested resource",
            404: "Not Found - The requested resource does not exist",
            422: "Unprocessable Entity - Request validation failed",
            500: "Internal Server Error - Server encountered an unexpected condition",
        }

        error_message = error_messages.get(
            status_code, f"HTTP {status_code} error occurred"
        )
        logger.error(f"API Error {status_code}: {error_message} - URL: {response.url}")

        if response_data.get("errors"):
            error_message += f" - Details: {response_data['errors']}"

        raise XDRAPIError(error_message, status_code, response_data)

    async def test_redirect_handling(self, test_url: str) -> dict:
        """Test redirect handling with a specific URL

        Args:
            test_url: URL to test redirect handling with

        Returns:
            Dict containing response data

        Raises:
            XDRAPIError: If the API request fails
        """
        try:
            logger.debug(f"Requesting URL: {test_url}")
            response = await self.client.get(
                test_url,
                follow_redirects=True,  # Explicitly enable redirect following for this request
            )
            logger.debug(f"Response status: {response.status_code}")
            # Log information about any redirects that occurred
            if response.history:
                redirect_chain = [str(r.url) for r in response.history]
                logger.info(
                    f"Redirect chain: {' -> '.join(redirect_chain)} -> {response.url}"
                )
            return self._handle_response(response)
        except httpx.RequestError as e:
            logger.error(f"Network error during redirect test: {e}")
            raise XDRAPIError(f"Network error: {e}")
