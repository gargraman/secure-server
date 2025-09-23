"""
Core Platform Components

Core utilities, exceptions, and base classes for the AI-SOAR platform.
"""

from .exceptions import (AISOARException, AlertProcessingException,
                         AuthenticationException, AuthorizationException,
                         ConfigurationException, DatabaseException,
                         MCPServerException, Neo4jConnectionException,
                         Neo4jQueryException, SecretManagerException,
                         ValidationException, VertexAIException,
                         XDRConnectionException, create_http_exception,
                         handle_exception, map_exception_to_http_status)

__all__ = [
    "AISOARException",
    "DatabaseException",
    "Neo4jConnectionException",
    "Neo4jQueryException",
    "ConfigurationException",
    "XDRConnectionException",
    "MCPServerException",
    "AuthenticationException",
    "AuthorizationException",
    "ValidationException",
    "VertexAIException",
    "SecretManagerException",
    "AlertProcessingException",
    "handle_exception",
    "create_http_exception",
    "map_exception_to_http_status",
]
