"""
Core Exception Classes

Centralized exception handling for the AI-SOAR platform with
structured error messages and proper HTTP status code mapping.

Author: AI-SOAR Platform Team
Created: 2025-09-11
"""

from typing import Any, Dict, Optional

from fastapi import HTTPException


class AISOARException(Exception):
    """Base exception for AI-SOAR platform"""

    def __init__(
        self,
        message: str,
        error_code: Optional[str] = None,
        details: Optional[Dict[str, Any]] = None,
    ):
        self.message = message
        self.error_code = error_code or self.__class__.__name__
        self.details = details or {}
        super().__init__(self.message)


class DatabaseException(AISOARException):
    """Exception for database-related errors"""

    pass


class Neo4jConnectionException(DatabaseException):
    """Exception for Neo4j connection issues"""

    pass


class Neo4jQueryException(DatabaseException):
    """Exception for Neo4j query execution errors"""

    pass


class ConfigurationException(AISOARException):
    """Exception for configuration-related errors"""

    pass


class XDRConnectionException(AISOARException):
    """Exception for XDR API connection issues"""

    pass


class MCPServerException(AISOARException):
    """Exception for MCP server communication errors"""

    pass


class AuthenticationException(AISOARException):
    """Exception for authentication failures"""

    pass


class AuthorizationException(AISOARException):
    """Exception for authorization failures"""

    pass


class ValidationException(AISOARException):
    """Exception for data validation errors"""

    pass


class VertexAIException(AISOARException):
    """Exception for Vertex AI service errors"""

    pass


class SecretManagerException(AISOARException):
    """Exception for Google Secret Manager errors"""

    pass


class AlertProcessingException(AISOARException):
    """Exception for alert processing errors"""

    pass


def create_http_exception(
    exception: AISOARException, status_code: int = 500
) -> HTTPException:
    """Convert AISOARException to FastAPI HTTPException"""
    detail = {
        "error_code": exception.error_code,
        "message": exception.message,
        "details": exception.details,
    }
    return HTTPException(status_code=status_code, detail=detail)


def map_exception_to_http_status(exception: AISOARException) -> int:
    """Map exception types to appropriate HTTP status codes"""
    mapping = {
        ValidationException: 400,
        AuthenticationException: 401,
        AuthorizationException: 403,
        ConfigurationException: 404,
        XDRConnectionException: 502,
        MCPServerException: 502,
        VertexAIException: 502,
        SecretManagerException: 502,
        DatabaseException: 503,
        Neo4jConnectionException: 503,
        Neo4jQueryException: 500,
        AlertProcessingException: 500,
    }
    return mapping.get(type(exception), 500)


def handle_exception(exception: Exception) -> HTTPException:
    """Central exception handler that converts exceptions to HTTP responses"""
    if isinstance(exception, AISOARException):
        status_code = map_exception_to_http_status(exception)
        return create_http_exception(exception, status_code)

    # Handle standard exceptions
    if isinstance(exception, ValueError):
        return HTTPException(
            status_code=400,
            detail={
                "error_code": "VALIDATION_ERROR",
                "message": str(exception),
                "details": {},
            },
        )

    if isinstance(exception, ConnectionError):
        return HTTPException(
            status_code=503,
            detail={
                "error_code": "CONNECTION_ERROR",
                "message": "Service temporarily unavailable",
                "details": {"original_error": str(exception)},
            },
        )

    # Generic exception handling
    return HTTPException(
        status_code=500,
        detail={
            "error_code": "INTERNAL_SERVER_ERROR",
            "message": "An unexpected error occurred",
            "details": {"error_type": type(exception).__name__},
        },
    )
