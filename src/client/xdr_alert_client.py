"""
XDR Alert Management API Client Wrapper

A wrapper for the XDR Alert Management API Client that provides a CLI interface.
This file imports and re-exports the main implementation from src/client/xdr/alerts/client.py.

This is a convenience wrapper for direct usage from the command line.
For programmatic usage, prefer importing from src.client.xdr.alerts.

Author: AI-SOAR Platform Team
Created: 2025-09-03
"""

import sys
from pathlib import Path

# Add the parent directory to the path for imports
parent_dir = str(Path(__file__).parent.parent)
if parent_dir not in sys.path:
    sys.path.insert(0, parent_dir)

# Import from the consolidated implementation
from .xdr.alerts.client import cli  # Import the CLI interface
from .xdr.alerts.client import (AlertPersistenceManager, XDRAlertClient,
                                XDRAPIError, XDRConfig)

# This file simply re-exports the CLI functionality

if __name__ == "__main__":
    cli()
