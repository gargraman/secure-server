# XDR API Client

A comprehensive Python client for interacting with XDR Alert Management API.

## Features

- **Alert Management**: Fetch alerts, get specific alert details, and extract common fields
- **Event Management**: Get alert events, event statistics, search events
- **Asset Management**: Get alert assets, asset statistics, asset details
- **Intel Management**: Get intelligence information, search threat intelligence
- **MITRE ATT&CK**: Get MITRE matrix details, technique details, alerts by technique

## Installation

```bash
# Install the package in development mode
pip install -e .
```

## Usage

### Python API

```python
import asyncio
from src.client.xdr_client import XDRAlertClient, XDREventClient, XDRConfig

async def main():
    # Create configuration
    config = XDRConfig.from_environment()

    # Use Alert Client
    async with XDRAlertClient(config) as client:
        # Get all alerts
        alerts = await client.get_all_alerts()
        print(f"Found {len(alerts.get('data', []))} alerts")

        # Get specific alert
        alert_id = "12345678-1234-5678-1234-567812345678"
        alert = await client.get_alert_by_id(alert_id)
        print(f"Alert details: {alert}")

    # Use Event Client
    async with XDREventClient(config) as client:
        # Get events for an alert
        events = await client.get_alert_events(alert_id)
        print(f"Found {len(events.get('data', []))} events for alert {alert_id}")

# Run the async function
asyncio.run(main())
```

### Command Line Interface

The XDR client includes a comprehensive CLI for interacting with the API:

```bash
# Run the CLI
./scripts/xdr-cli --help

# Get all alerts
./scripts/xdr-cli alerts list

# Get specific alert
./scripts/xdr-cli alerts get 12345678-1234-5678-1234-567812345678

# Get events for an alert
./scripts/xdr-cli events list 12345678-1234-5678-1234-567812345678

# Get asset statistics for an alert
./scripts/xdr-cli assets stats 12345678-1234-5678-1234-567812345678

# Get intelligence for an alert
./scripts/xdr-cli intel get 12345678-1234-5678-1234-567812345678

# Get MITRE ATT&CK matrix
./scripts/xdr-cli mitre matrix

# Get specific MITRE technique
./scripts/xdr-cli mitre technique T1059
```

## Configuration

The client can be configured using environment variables:

```bash
# XDR API configuration
export XDR_BASE_URL="https://alert-mgt.xdr.trellix.com/xdr-alert"
export XDR_AUTH_TOKEN="your-api-key"
export XDR_TIMEOUT=30
export XDR_MAX_RETRIES=3
export XDR_POLL_INTERVAL=30
export XDR_POLL_ENABLED=false
```

## Directory Structure

```
src/client/xdr/
├── __init__.py
├── client.py           # Base client class
├── cli.py              # CLI implementation
├── __main__.py         # CLI entry point
├── alerts/             # Alert management API
├── events/             # Event management API
├── assets/             # Asset management API
├── intel/              # Intelligence API
└── mitreattack/        # MITRE ATT&CK API
```

## Error Handling

All XDR API errors are wrapped in `XDRAPIError` with helpful error messages:

```python
from src.client.xdr_client import XDRAlertClient, XDRConfig, XDRAPIError

async def example():
    config = XDRConfig.from_environment()
    try:
        async with XDRAlertClient(config) as client:
            alerts = await client.get_all_alerts()
    except XDRAPIError as e:
        print(f"API Error: {e} (Status Code: {e.status_code})")
        if e.response_data:
            print(f"Error details: {e.response_data}")
```

## Development

Add new endpoints by extending the appropriate client class and implementing the relevant methods.
