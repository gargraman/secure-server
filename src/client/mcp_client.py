import asyncio
import json
import logging
from typing import Any, Dict, List, Optional

import aiohttp

# Configure logging
logging.basicConfig(
    level=logging.INFO, format="%(asctime)s - %(name)s - %(levelname)s - %(message)s"
)
logger = logging.getLogger(__name__)


class MCPClient:
    """Client for communicating with MCP servers"""

    def __init__(self, server_configs: Dict[str, Dict[str, Any]]):
        self.server_configs = server_configs
        self.session = None
        logger.info(
            "MCPClient initialized with %d server configurations", len(server_configs)
        )

    async def get_session(self):
        """Get or create aiohttp session"""
        if self.session is None:
            self.session = aiohttp.ClientSession()
        return self.session

    async def call_server(
        self, server_name: str, action: str, parameters: Dict[str, Any]
    ) -> Dict[str, Any]:
        """Call a specific MCP server action"""

        if server_name not in self.server_configs:
            logger.error("Unknown server: %s", server_name)
            raise ValueError(f"Unknown server: {server_name}")

        server_config = self.server_configs[server_name]
        base_url = server_config["base_url"]

        # Build endpoint URL
        endpoint_url = f"{base_url}/{action}"
        logger.info(
            "Calling server %s at %s with action %s", server_name, endpoint_url, action
        )
        logger.debug("Parameters: %s", parameters)

        session = await self.get_session()

        # Prepare headers
        headers = {"Content-Type": "application/json"}
        if "auth_headers" in server_config:
            headers.update(server_config["auth_headers"])

        try:
            async with session.post(
                endpoint_url, json=parameters, headers=headers
            ) as response:
                if response.status == 200:
                    result = await response.json()
                    logger.info(
                        "Successfully called server %s action %s", server_name, action
                    )
                    logger.debug("Response: %s", result)
                    return result
                else:
                    error_text = await response.text()
                    logger.error(
                        "Server %s returned %d: %s",
                        server_name,
                        response.status,
                        error_text,
                    )
                    # Update server health on HTTP error
                    if response.status >= 500:
                        self.server_health[server_name] = {
                            "status": "degraded",
                            "error": f"HTTP {response.status}",
                        }
                    raise Exception(
                        f"Server {server_name} returned {response.status}: {error_text}"
                    )

        except aiohttp.ClientError as e:
            logger.error("Failed to connect to %s: %s", server_name, str(e))
            # Update server health on connection failure
            self.server_health[server_name] = {"status": "offline", "error": str(e)}
            raise Exception(f"Failed to connect to {server_name}: {str(e)}")

    async def get_server_capabilities(self, server_name: str) -> Dict[str, Any]:
        """Get server capabilities via /meta endpoint"""

        if server_name not in self.server_configs:
            logger.error("Unknown server: %s", server_name)
            raise ValueError(f"Unknown server: {server_name}")

        server_config = self.server_configs[server_name]
        base_url = server_config["base_url"]
        meta_url = f"{base_url}/meta"
        logger.info(
            "Fetching capabilities for server %s from %s", server_name, meta_url
        )

        session = await self.get_session()

        try:
            async with session.get(meta_url) as response:
                if response.status == 200:
                    result = await response.json()
                    logger.info(
                        "Successfully fetched capabilities for server %s", server_name
                    )
                    logger.debug("Capabilities: %s", result)
                    return result
                else:
                    logger.error(
                        "Failed to get capabilities for server %s: %d",
                        server_name,
                        response.status,
                    )
                    return {"error": f"Failed to get capabilities: {response.status}"}

        except aiohttp.ClientError as e:
            logger.error(
                "Failed to connect to server %s for capabilities: %s",
                server_name,
                str(e),
            )
            return {"error": f"Failed to connect: {str(e)}"}

    async def test_all_servers(self) -> Dict[str, Dict[str, Any]]:
        """Test connectivity to all configured servers"""
        results = {}
        logger.info(
            "Testing connectivity to all %d configured servers",
            len(self.server_configs),
        )

        for server_name in self.server_configs:
            logger.info("Testing server: %s", server_name)
            try:
                capabilities = await self.get_server_capabilities(server_name)
                results[server_name] = {
                    "status": "online",
                    "capabilities": capabilities,
                }
                logger.info("Server %s is online", server_name)
            except Exception as e:
                logger.error("Server %s is offline: %s", server_name, str(e))
                results[server_name] = {"status": "offline", "error": str(e)}

        logger.info("Completed server connectivity tests")
        return results

    async def close(self):
        """Close the aiohttp session"""
        if self.session:
            logger.info("Closing aiohttp session")
            await self.session.close()
            self.session = None
            logger.info("aiohttp session closed successfully")
