"""
XDR Client
=========

Main entry point for XDR API Client.
"""

from .xdr import XDRClient
from .xdr.alerts import XDRAlertClient
from .xdr.assets import XDRAssetClient
from .xdr.client import XDRAPIError, XDRConfig
from .xdr.events import XDREventClient
from .xdr.intel import XDRIntelClient
from .xdr.mitreattack import XDRMitreAttackClient

__all__ = [
    "XDRClient",
    "XDRAlertClient",
    "XDREventClient",
    "XDRAssetClient",
    "XDRIntelClient",
    "XDRMitreAttackClient",
    "XDRConfig",
    "XDRAPIError",
]
