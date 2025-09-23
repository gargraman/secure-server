"""
Pydantic models for XDR configuration management.

Models for creating, updating, and validating XDR system configurations
with Google Cloud integration.

Author: AI-SOAR Platform Team
Created: 2025-09-10
"""

from datetime import datetime
from enum import Enum
from typing import Any, Dict, List, Optional

from pydantic import BaseModel, Field, HttpUrl, SecretStr, field_validator


class EnvironmentType(str, Enum):
    """Environment types for configurations"""

    DEVELOPMENT = "development"
    STAGING = "staging"
    PRODUCTION = "production"


class ConfigurationStatus(str, Enum):
    """Status of XDR configuration"""

    ACTIVE = "active"
    INACTIVE = "inactive"
    ERROR = "error"
    PENDING = "pending"


class AlertSeverity(str, Enum):
    """Alert severity levels"""

    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"
    CRITICAL = "critical"


class EntityTypes(BaseModel):
    """Configuration for which entity types to fetch with alerts"""

    fetch_assets: bool = Field(default=True, description="Fetch related assets")
    fetch_events: bool = Field(default=True, description="Fetch related events")
    fetch_intel: bool = Field(default=True, description="Fetch threat intelligence")
    fetch_network_data: bool = Field(default=False, description="Fetch network data")
    fetch_endpoint_data: bool = Field(default=True, description="Fetch endpoint data")


class XDRConfigurationCreate(BaseModel):
    """Model for creating a new XDR configuration"""

    name: str = Field(
        ..., min_length=1, max_length=255, description="Configuration name"
    )
    description: Optional[str] = Field(
        None, max_length=1000, description="Configuration description"
    )

    # XDR API Configuration
    base_url: HttpUrl = Field(..., description="XDR API base URL")
    auth_token_secret_name: str = Field(
        ...,
        min_length=1,
        max_length=255,
        description="Google Secret Manager secret name for auth token",
    )

    # Polling Configuration
    poll_interval: int = Field(
        30, ge=10, le=3600, description="Polling interval in seconds (10-3600)"
    )
    poll_enabled: bool = Field(False, description="Enable automatic polling")
    max_alerts_per_poll: int = Field(
        100, ge=1, le=1000, description="Maximum alerts to fetch per poll (1-1000)"
    )

    # Filtering and Processing
    severity_filter: Optional[List[AlertSeverity]] = Field(
        None, description="Filter alerts by severity levels"
    )
    entity_types: Optional[EntityTypes] = Field(
        default_factory=EntityTypes, description="Entity types to fetch"
    )

    # Environment
    environment: EnvironmentType = Field(
        EnvironmentType.DEVELOPMENT, description="Deployment environment"
    )

    model_config = {"json_encoders": {HttpUrl: str}}


class XDRConfigurationUpdate(BaseModel):
    """Model for updating an existing XDR configuration"""

    name: Optional[str] = Field(None, min_length=1, max_length=255)
    description: Optional[str] = Field(None, max_length=1000)

    # XDR API Configuration
    base_url: Optional[HttpUrl] = None
    auth_token_secret_name: Optional[str] = Field(None, min_length=1, max_length=255)

    # Polling Configuration
    poll_interval: Optional[int] = Field(None, ge=10, le=3600)
    poll_enabled: Optional[bool] = None
    max_alerts_per_poll: Optional[int] = Field(None, ge=1, le=1000)

    # Filtering and Processing
    severity_filter: Optional[List[AlertSeverity]] = None
    entity_types: Optional[EntityTypes] = None

    model_config = {"json_encoders": {HttpUrl: str}}


class XDRConfigurationResponse(BaseModel):
    """Model for XDR configuration API responses"""

    id: str
    name: str
    description: Optional[str]

    # XDR API Configuration
    base_url: str
    auth_token_secret_name: str

    # Polling Configuration
    poll_interval: int
    poll_enabled: bool
    max_alerts_per_poll: int

    # Filtering and Processing
    severity_filter: Optional[List[AlertSeverity]]
    entity_types: Optional[EntityTypes]

    # Status and Metadata
    status: ConfigurationStatus
    environment: EnvironmentType

    # Timestamps
    created_at: datetime
    updated_at: datetime
    last_poll_at: Optional[datetime]

    # Statistics (populated by service layer)
    total_alerts: Optional[int] = Field(None, description="Total alerts fetched")
    active_polling_sessions: Optional[int] = Field(
        None, description="Number of active polling sessions"
    )

    model_config = {
        "from_attributes": True,
        "json_encoders": {datetime: lambda v: v.isoformat()},
    }


class PollingSessionResponse(BaseModel):
    """Model for polling session API responses"""

    id: str
    configuration_id: str
    configuration_name: Optional[str] = None

    # Session Details
    session_start: datetime
    session_end: Optional[datetime]
    status: str

    # Statistics
    polls_executed: int
    alerts_fetched: int
    alerts_processed: int
    errors_encountered: int

    # Last Poll Information
    last_poll_timestamp: Optional[datetime]
    last_error: Optional[str]

    model_config = {
        "from_attributes": True,
        "json_encoders": {datetime: lambda v: v.isoformat()},
    }


class StartPollingRequest(BaseModel):
    """Request model for starting XDR polling"""

    configuration_id: str = Field(
        ..., description="XDR configuration ID to start polling"
    )
    override_interval: Optional[int] = Field(
        None, ge=10, le=3600, description="Override polling interval for this session"
    )


class StopPollingRequest(BaseModel):
    """Request model for stopping XDR polling"""

    configuration_id: str = Field(
        ..., description="XDR configuration ID to stop polling"
    )
    force_stop: bool = Field(False, description="Force stop even if processing alerts")


class MCPServerConfigurationCreate(BaseModel):
    """Model for creating MCP server configuration"""

    name: str = Field(..., min_length=1, max_length=255, description="Server name")
    server_type: str = Field(
        ...,
        min_length=1,
        max_length=100,
        description="Server type (virustotal, servicenow, etc.)",
    )
    base_url: HttpUrl = Field(..., description="MCP server base URL")

    # Configuration
    enabled: bool = Field(True, description="Enable this server")
    priority: int = Field(
        100, ge=1, le=1000, description="Processing priority (lower = higher priority)"
    )
    timeout: int = Field(30, ge=5, le=300, description="Request timeout in seconds")

    # Authentication
    auth_config: Optional[Dict[str, Any]] = Field(
        None, description="Authentication configuration"
    )

    # Processing Rules
    alert_filters: Optional[Dict[str, Any]] = Field(
        None, description="Alert filtering rules"
    )
    processing_config: Optional[Dict[str, Any]] = Field(
        None, description="Server-specific processing configuration"
    )

    model_config = {"json_encoders": {HttpUrl: str}}


class MCPServerConfigurationResponse(BaseModel):
    """Model for MCP server configuration API responses"""

    id: str
    name: str
    server_type: str
    base_url: str

    # Configuration
    enabled: bool
    priority: int
    timeout: int

    # Authentication (sensitive data removed)
    auth_configured: bool = Field(description="Whether authentication is configured")

    # Processing Rules
    alert_filters: Optional[Dict[str, Any]]
    processing_config: Optional[Dict[str, Any]]

    # Status
    status: str
    last_health_check: Optional[datetime]
    health_status: Optional[str]

    # Timestamps
    created_at: datetime
    updated_at: datetime

    model_config = {
        "from_attributes": True,
        "json_encoders": {datetime: lambda v: v.isoformat()},
    }


class SystemConfigurationCreate(BaseModel):
    """Model for creating system configuration"""

    config_key: str = Field(
        ..., min_length=1, max_length=255, description="Configuration key"
    )
    config_value: Dict[str, Any] = Field(..., description="Configuration value")
    config_type: str = Field(
        ..., min_length=1, max_length=50, description="Configuration type"
    )
    description: Optional[str] = Field(
        None, max_length=1000, description="Configuration description"
    )
    environment: EnvironmentType = Field(
        EnvironmentType.DEVELOPMENT, description="Environment"
    )


class SystemConfigurationResponse(BaseModel):
    """Model for system configuration API responses"""

    id: str
    config_key: str
    config_value: Dict[str, Any]
    config_type: str
    description: Optional[str]
    environment: EnvironmentType
    created_at: datetime
    updated_at: datetime

    model_config = {
        "from_attributes": True,
        "json_encoders": {datetime: lambda v: v.isoformat()},
    }
