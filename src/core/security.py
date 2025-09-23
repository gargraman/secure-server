"""
Security Middleware and Authentication

Security utilities for the AI-SOAR platform including authentication,
authorization, and security headers.

Author: AI-SOAR Platform Team
Created: 2025-09-11
"""

import hashlib
import hmac
import logging
import secrets
from datetime import datetime, timedelta
from functools import wraps
from typing import Any, Dict, List, Optional

from fastapi import Depends, HTTPException, Request, status
from fastapi.security import HTTPAuthorizationCredentials, HTTPBearer
from starlette.middleware.base import BaseHTTPMiddleware
from starlette.responses import Response

from .exceptions import AuthenticationException, AuthorizationException

logger = logging.getLogger(__name__)

# Security configuration
SECURITY_HEADERS = {
    "X-Content-Type-Options": "nosniff",
    "X-Frame-Options": "DENY",
    "X-XSS-Protection": "1; mode=block",
    "Strict-Transport-Security": "max-age=31536000; includeSubDomains",
    "Content-Security-Policy": "default-src 'self'; script-src 'self' 'unsafe-inline' https://cdn.jsdelivr.net https://cdnjs.cloudflare.com https://cdn.datatables.net https://unpkg.com https://d3js.org; style-src 'self' 'unsafe-inline' https://cdn.jsdelivr.net https://cdnjs.cloudflare.com https://cdn.datatables.net https://unpkg.com; img-src 'self' data: https:; font-src 'self' https://cdn.jsdelivr.net https://cdnjs.cloudflare.com; connect-src 'self' https://cdn.jsdelivr.net https://cdnjs.cloudflare.com https://cdn.datatables.net https://unpkg.com https://d3js.org;",
    "Referrer-Policy": "strict-origin-when-cross-origin",
    "Permissions-Policy": "camera=(), microphone=(), geolocation=()",
}

# Rate limiting configuration
RATE_LIMIT_CONFIG = {
    "max_requests": 100,
    "time_window": 60,  # seconds
    "burst_limit": 20,
}


class SecurityHeadersMiddleware(BaseHTTPMiddleware):
    """Middleware to add security headers to all responses"""

    async def dispatch(self, request: Request, call_next):
        response = await call_next(request)

        # Add security headers
        for header, value in SECURITY_HEADERS.items():
            response.headers[header] = value

        return response


class RateLimitMiddleware(BaseHTTPMiddleware):
    """Simple in-memory rate limiting middleware"""

    def __init__(self, app, max_requests: int = 100, time_window: int = 60):
        super().__init__(app)
        self.max_requests = max_requests
        self.time_window = time_window
        self.requests = {}  # In production, use Redis or similar

    async def dispatch(self, request: Request, call_next):
        client_ip = self._get_client_ip(request)
        current_time = datetime.utcnow()

        # Clean old entries
        self._cleanup_old_entries(current_time)

        # Check rate limit
        if self._is_rate_limited(client_ip, current_time):
            raise HTTPException(
                status_code=status.HTTP_429_TOO_MANY_REQUESTS,
                detail="Rate limit exceeded",
            )

        # Record request
        self._record_request(client_ip, current_time)

        return await call_next(request)

    def _get_client_ip(self, request: Request) -> str:
        """Get client IP with proxy support"""
        forwarded = request.headers.get("X-Forwarded-For")
        if forwarded:
            return forwarded.split(",")[0].strip()
        return request.client.host

    def _cleanup_old_entries(self, current_time: datetime):
        """Remove entries older than time window"""
        cutoff_time = current_time - timedelta(seconds=self.time_window)
        for ip in list(self.requests.keys()):
            self.requests[ip] = [
                req_time for req_time in self.requests[ip] if req_time > cutoff_time
            ]
            if not self.requests[ip]:
                del self.requests[ip]

    def _is_rate_limited(self, client_ip: str, current_time: datetime) -> bool:
        """Check if client is rate limited"""
        if client_ip not in self.requests:
            return False
        return len(self.requests[client_ip]) >= self.max_requests

    def _record_request(self, client_ip: str, current_time: datetime):
        """Record a request for rate limiting"""
        if client_ip not in self.requests:
            self.requests[client_ip] = []
        self.requests[client_ip].append(current_time)


class APIKeyAuth:
    """Simple API key authentication"""

    def __init__(self):
        self.security = HTTPBearer(auto_error=False)
        # In production, store these in Secret Manager or database
        self.valid_keys = set()
        self._load_api_keys()

    def _load_api_keys(self):
        """Load API keys from configuration"""
        # This is a placeholder - in production, load from secure storage
        self.valid_keys.add("aisoar-dev-key-2025")
        logger.info("Loaded API keys for authentication")

    async def __call__(
        self,
        credentials: Optional[HTTPAuthorizationCredentials] = Depends(
            HTTPBearer(auto_error=False)
        ),
    ):
        """Authenticate API key"""
        if not credentials:
            raise AuthenticationException(
                "Missing authentication credentials", error_code="MISSING_CREDENTIALS"
            )

        if credentials.scheme.lower() != "bearer":
            raise AuthenticationException(
                "Invalid authentication scheme", error_code="INVALID_AUTH_SCHEME"
            )

        if not self._is_valid_key(credentials.credentials):
            raise AuthenticationException(
                "Invalid API key", error_code="INVALID_API_KEY"
            )

        return {"api_key": credentials.credentials, "authenticated": True}

    def _is_valid_key(self, key: str) -> bool:
        """Validate API key"""
        return key in self.valid_keys


def validate_input_length(
    value: str, max_length: int = 1000, field_name: str = "input"
) -> str:
    """Validate input string length to prevent DoS attacks"""
    if len(value) > max_length:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail=f"{field_name} exceeds maximum length of {max_length} characters",
        )
    return value


def sanitize_cypher_input(value: str) -> str:
    """Sanitize input to prevent Cypher injection"""
    # Remove potentially dangerous characters
    dangerous_chars = [";", "--", "/*", "*/", "\\", "'", '"']
    sanitized = value
    for char in dangerous_chars:
        sanitized = sanitized.replace(char, "")

    # Limit length
    return validate_input_length(sanitized, 500, "cypher_input")


def generate_secure_token(length: int = 32) -> str:
    """Generate a cryptographically secure random token"""
    return secrets.token_urlsafe(length)


def hash_sensitive_data(data: str, salt: Optional[str] = None) -> str:
    """Hash sensitive data with salt"""
    if salt is None:
        salt = secrets.token_hex(16)

    # Use PBKDF2 for password hashing
    hashed = hashlib.pbkdf2_hmac("sha256", data.encode(), salt.encode(), 100000)
    return f"{salt}:{hashed.hex()}"


def verify_hash(data: str, hashed_data: str) -> bool:
    """Verify hashed data"""
    try:
        salt, hash_value = hashed_data.split(":", 1)
        expected_hash = hashlib.pbkdf2_hmac(
            "sha256", data.encode(), salt.encode(), 100000
        )
        return hmac.compare_digest(hash_value, expected_hash.hex())
    except (ValueError, TypeError):
        return False


def require_permissions(required_permissions: List[str]):
    """Decorator to require specific permissions"""

    def decorator(func):
        @wraps(func)
        async def wrapper(*args, **kwargs):
            # In a real implementation, extract user permissions from JWT token
            # For now, this is a placeholder
            user_permissions = kwargs.get("user_permissions", [])

            if not all(perm in user_permissions for perm in required_permissions):
                raise AuthorizationException(
                    "Insufficient permissions",
                    error_code="INSUFFICIENT_PERMISSIONS",
                    details={
                        "required": required_permissions,
                        "user_permissions": user_permissions,
                    },
                )

            return await func(*args, **kwargs)

        return wrapper

    return decorator


async def audit_log(
    action: str,
    resource_id: str,
    user_id: Optional[str] = None,
    details: Optional[Dict[str, Any]] = None,
    session: Optional[Any] = None,
):
    """Log security-relevant actions for audit purposes"""
    audit_entry = {
        "timestamp": datetime.utcnow().isoformat(),
        "action": action,
        "resource_id": resource_id,
        "user_id": user_id,
        "details": details or {},
        "level": "AUDIT",
    }

    # In production, send to dedicated audit log system
    logger.info(f"AUDIT: {audit_entry}")

    # If session is provided, we could also log to database
    if session:
        try:
            # Create audit log entry in database
            audit_query = """
            CREATE (audit:AuditLog {
                timestamp: $timestamp,
                action: $action,
                resource_id: $resource_id,
                user_id: $user_id,
                details: $details,
                level: $level
            })
            """
            await session.run(audit_query, audit_entry)
        except Exception as e:
            logger.warning(f"Failed to create database audit log: {e}")


def audit_log_sync(
    action: str,
    resource: str,
    user_id: Optional[str] = None,
    details: Optional[Dict[str, Any]] = None,
):
    """Synchronous version of audit_log for backward compatibility"""
    audit_entry = {
        "timestamp": datetime.utcnow().isoformat(),
        "action": action,
        "resource": resource,
        "user_id": user_id,
        "details": details or {},
        "level": "AUDIT",
    }

    # In production, send to dedicated audit log system
    logger.info(f"AUDIT: {audit_entry}")


# Global authentication instance
api_key_auth = APIKeyAuth()


# Security dependencies for FastAPI
def get_authenticated_user(auth_data: dict = Depends(api_key_auth)):
    """Dependency to get authenticated user"""
    return auth_data


def require_admin_permissions(auth_data: dict = Depends(get_authenticated_user)):
    """Dependency to require admin permissions"""
    # In a real implementation, check user roles/permissions
    # For now, all authenticated users have admin access
    return auth_data
