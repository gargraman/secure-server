#!/usr/bin/env python3
"""
XDR Client Test Script
=====================

Test script to verify XDR API connectivity and responses locally.
"""

import asyncio
import logging
import os
import sys
from pathlib import Path

# Add src directory to path
sys.path.insert(0, str(Path(__file__).parent / "src"))

from client.xdr.client import XDRAPIError, XDRClient, XDRConfig

# Configure logging
logging.basicConfig(
    level=logging.DEBUG, format="%(asctime)s - %(name)s - %(levelname)s - %(message)s"
)
logger = logging.getLogger(__name__)


async def test_basic_connectivity(client: XDRClient):
    """Test basic connectivity to XDR API"""
    print("\n" + "=" * 50)
    print("TESTING BASIC CONNECTIVITY")
    print("=" * 50)

    test_endpoints = [
        "/api/v1/alerts",
        "/api/v1/events",
        "/api/v1/mitre",
        "/helix/search",
        "/api/alerts",
        "/",  # Root endpoint
    ]

    for endpoint in test_endpoints:
        try:
            full_url = f"{client.config.base_url.rstrip('/')}{endpoint}"
            print(f"\nTesting endpoint: {full_url}")

            response = await client.client.get(full_url)

            print(f"Status Code: {response.status_code}")
            print(f"Headers: {dict(response.headers)}")

            if response.status_code == 200:
                try:
                    data = response.json()
                    print(f"Response Data (first 200 chars): {str(data)[:200]}...")
                except:
                    print(f"Response Text (first 200 chars): {response.text[:200]}...")
            else:
                print(f"Error Response: {response.text[:200]}...")

        except Exception as e:
            print(f"Exception occurred: {type(e).__name__}: {e}")


async def test_authentication_methods(base_url: str, auth_token: str):
    """Test different authentication header formats"""
    print("\n" + "=" * 50)
    print("TESTING AUTHENTICATION METHODS")
    print("=" * 50)

    auth_methods = [
        {"x-fireeye-api-key": auth_token},
        {"Authorization": f"Bearer {auth_token}"},
        {"X-FeApi-Token": auth_token},
        {"X-Auth-Token": auth_token},
        {"Api-Key": auth_token},
    ]

    for i, headers in enumerate(auth_methods, 1):
        print(f"\nMethod {i}: {list(headers.keys())[0]}")

        try:
            async with XDRClient(XDRConfig(base_url=base_url)) as client:
                # Override headers
                client.client.headers.update(headers)

                response = await client.client.get(f"{base_url}/api/v1/alerts")
                print(f"Status: {response.status_code}")

                if response.status_code != 401:  # Not unauthorized
                    print("✓ Authentication method might be working!")
                    print(f"Response: {response.text[:100]}...")
                else:
                    print("✗ Unauthorized - wrong auth method")

        except Exception as e:
            print(f"Error: {e}")


async def test_url_variations(auth_token: str):
    """Test different base URL variations"""
    print("\n" + "=" * 50)
    print("TESTING URL VARIATIONS")
    print("=" * 50)

    url_variations = [
        "https://staging.apps.fireeye.com/helix/id/hexload02org01",
        "https://staging.apps.fireeye.com/alert/id/hexload02org01",
    ]

    for url in url_variations:
        print(f"\nTesting base URL: {url}")

        try:
            config = XDRConfig(base_url=url, auth_token=auth_token)
            async with XDRClient(config) as client:
                response = await client.client.get(f"{url}/api/v1/alerts")
                print(f"Status: {response.status_code}")

                if response.status_code == 200:
                    print("✓ SUCCESS! This URL works")
                elif response.status_code == 404:
                    print("✗ Not Found - wrong URL path")
                elif response.status_code == 401:
                    print("? Unauthorized - URL might be correct, auth issue")
                else:
                    print(f"? Status {response.status_code} - {response.text[:100]}")

        except Exception as e:
            print(f"Error: {e}")


async def main():
    """Main test function"""
    print("XDR CLIENT CONNECTIVITY TEST")
    print("=" * 50)

    # Configuration
    base_url = "https://staging.apps.fireeye.com/alert/id/hexload02org01"
    auth_token = "eyJhbGciOiJSUzI1NiIsInR5cCI6IkpXVCIsImtpZCI6ImJmYzg2ODU1ZWRkZTQyNzc5YjE3YjUyNTNiOGQyY2Y3Y2ZiZDgzN2ZmYmRlZjM2M2I2YzBiYjYxNDcxZTI5NTAifQ.eyJ0b2tlbl90eXBlIjoiYXBpLWtleSIsInN1YiI6IjQ2ODk1MWU5LWYwMjMtNDNkNi04MWY4LTVmZjlkN2E5ZWRkMSIsIm9yZyI6ImI5NzQxYjdiLTQzZmYtNGQzYy04ZDhhLWQ0NWI1NDhmNjgxMyIsImlkcyI6IjgzMjJhNjE1LTA1Y2ItNGUzYi1iODhjLTI3YjY1NTQwYTU4NiA1YWJiMmZhZC1iYThjLTQyNGUtOWY0My1hMjAwNGNlOWQ3NWYiLCJqdGkiOiIyYjg3NWE5NC01OTZiLTRkODAtYWMzMy0wNzdiZWQyZjUxYzUiLCJpc3MiOiJodHRwczovL2lkcC1pYW0tc3RnLmZpcmVleWUuY29tIiwiaWF0IjoxNzU2OTY3NDc1LCJleHAiOjE3NzMzODM0NzV9.aXiA7gDNsY7hKHIxEfjWl0WJ67S5D7DotKA-zfLzQOQbEibiBRVzQkUlq2S7Dq-UwNwF4E04pX3HsZy_Gf-n3RUL8MnWYk22Iyb0nDvhNwh3BLzE-d4ncrMk-r9JuYL6iRiGYtAr6YNB_kgw7yUB5-tnq-Ly8LEORbbTRNg9xsh3aJF2qaPxVXhtinyBAuvK5UvuDb77z8GKvl1nJ39Ea7U3dk5I3emaG6zv5KKI-vF1OIkM0EtrXezUPZK8K0mEWe8G2-8vQJrZl0DVKXsjJ8UbelbVS2taf3RCxz2EsgoXDDkxeXNriEym4nB_D7KSYvi_PfQGnIqsnUjF6oFQbA"

    print(f"Base URL: {base_url}")
    print(f"Auth Token: {auth_token[:20]}... (truncated)")

    # Test 1: Basic connectivity with current setup
    config = XDRConfig(base_url=base_url, auth_token=auth_token)
    async with XDRClient(config) as client:
        await test_basic_connectivity(client)

    # Test 2: Different authentication methods
    await test_authentication_methods(base_url, auth_token)

    # Test 3: Different URL variations
    await test_url_variations(auth_token)

    print("\n" + "=" * 50)
    print("TEST COMPLETE")
    print("=" * 50)


if __name__ == "__main__":
    asyncio.run(main())
