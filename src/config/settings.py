"""
Application Settings and Configuration

Centralized configuration management using Pydantic Settings
with Google Cloud and environment-specific configurations.

Author: AI-SOAR Platform Team
Created: 2025-09-10
"""

import os
from functools import lru_cache
from typing import List, Optional

from pydantic import Field, field_validator
from pydantic_settings import BaseSettings


class Settings(BaseSettings):
    """Application settings with environment variable support"""

    # Application Settings
    app_name: str = "AI-SOAR Platform"
    app_version: str = "1.0.0"
    environment: str = Field(default="development", env="ENVIRONMENT")
    debug: bool = Field(default=False, env="DEBUG")

    # Web Server Settings
    web_host: str = Field(default="0.0.0.0", env="WEB_HOST")
    web_port: int = Field(default=8080, env="WEB_PORT")

    # Neo4j Database Settings
    neo4j_uri: str = Field(default="neo4j://localhost:7687", env="NEO4J_URI")
    neo4j_username: str = Field(default="neo4j", env="NEO4J_USERNAME")
    neo4j_password: str = Field(default="password", env="NEO4J_PASSWORD")
    neo4j_database: str = Field(default="neo4j", env="NEO4J_DATABASE")
    neo4j_max_connection_lifetime: int = Field(
        default=3600, env="NEO4J_MAX_CONNECTION_LIFETIME"
    )
    neo4j_max_connection_pool_size: int = Field(
        default=50, env="NEO4J_MAX_CONNECTION_POOL_SIZE"
    )
    neo4j_connection_timeout: int = Field(default=30, env="NEO4J_CONNECTION_TIMEOUT")
    neo4j_encrypted: bool = Field(default=True, env="NEO4J_ENCRYPTED")

    # Legacy Database Settings (deprecated)
    database_url: Optional[str] = Field(default=None, env="DATABASE_URL")
    database_host: str = Field(default="localhost", env="DB_HOST")
    database_port: int = Field(default=5432, env="DB_PORT")
    database_name: str = Field(default="aisoar", env="DB_NAME")
    database_user: str = Field(default="aisoar", env="DB_USER")
    database_password: str = Field(default="password", env="DB_PASSWORD")
    database_echo: bool = Field(default=False, env="DB_ECHO")

    # Google Cloud SQL Settings (deprecated)
    use_cloud_sql: bool = Field(default=False, env="USE_CLOUD_SQL")
    cloud_sql_connection_name: Optional[str] = Field(
        default=None, env="CLOUD_SQL_CONNECTION_NAME"
    )

    # Google Cloud Settings
    google_cloud_project: Optional[str] = Field(
        default=None, env="GOOGLE_CLOUD_PROJECT"
    )
    google_application_credentials: Optional[str] = Field(
        default=None, env="GOOGLE_APPLICATION_CREDENTIALS"
    )

    # Vertex AI Settings
    vertex_ai_location: str = Field(default="us-central1", env="VERTEX_AI_LOCATION")
    vertex_ai_model: str = Field(default="gemini-1.5-pro", env="VERTEX_AI_MODEL")
    vertex_ai_enabled: bool = Field(default=True, env="VERTEX_AI_ENABLED")

    # Secret Manager Settings
    secret_manager_enabled: bool = Field(default=True, env="SECRET_MANAGER_ENABLED")

    # XDR Settings
    default_poll_interval: int = Field(default=30, env="DEFAULT_POLL_INTERVAL")
    max_alerts_per_poll: int = Field(default=100, env="MAX_ALERTS_PER_POLL")

    # MCP Server Settings
    mcp_server_timeout: int = Field(default=30, env="MCP_SERVER_TIMEOUT")
    mcp_server_retries: int = Field(default=3, env="MCP_SERVER_RETRIES")

    # Logging Settings
    log_level: str = Field(default="INFO", env="LOG_LEVEL")
    log_format: str = Field(
        default="%(asctime)s - %(name)s - %(levelname)s - %(message)s", env="LOG_FORMAT"
    )

    # Security Settings
    cors_origins: str = Field(default="*", env="CORS_ORIGINS")
    allowed_hosts: str = Field(default="*", env="ALLOWED_HOSTS")

    # Redis/Cache Settings (for future use)
    redis_url: Optional[str] = Field(default=None, env="REDIS_URL")
    cache_enabled: bool = Field(default=False, env="CACHE_ENABLED")

    # Monitoring Settings
    metrics_enabled: bool = Field(default=True, env="METRICS_ENABLED")
    health_check_interval: int = Field(default=60, env="HEALTH_CHECK_INTERVAL")

    # Alert Processing Settings
    alert_retention_days: int = Field(default=90, env="ALERT_RETENTION_DAYS")
    processing_batch_size: int = Field(default=50, env="PROCESSING_BATCH_SIZE")
    max_processing_retries: int = Field(default=3, env="MAX_PROCESSING_RETRIES")

    # Kafka/Messaging Settings
    kafka_bootstrap_servers: Optional[str] = Field(
        default=None, env="KAFKA_BOOTSTRAP_SERVERS"
    )
    kafka_enabled: bool = Field(default=False, env="KAFKA_ENABLED")

    model_config = {"env_parse_none_str": "", "extra": "ignore"}

    @field_validator("cors_origins", "allowed_hosts", mode="after")
    @classmethod
    def parse_list_from_string(cls, v):
        """Parse comma-separated string into list"""
        if isinstance(v, str):
            return [item.strip() for item in v.split(",") if item.strip()]
        return v

    @field_validator("environment")
    @classmethod
    def validate_environment(cls, v):
        """Validate environment setting"""
        valid_environments = ["development", "staging", "production"]
        if v not in valid_environments:
            raise ValueError(f"Environment must be one of: {valid_environments}")
        return v

    @field_validator("log_level")
    @classmethod
    def validate_log_level(cls, v):
        """Validate log level"""
        valid_levels = ["DEBUG", "INFO", "WARNING", "ERROR", "CRITICAL"]
        if v.upper() not in valid_levels:
            raise ValueError(f"Log level must be one of: {valid_levels}")
        return v.upper()

    @property
    def is_production(self) -> bool:
        """Check if running in production"""
        return self.environment == "production"

    @property
    def is_development(self) -> bool:
        """Check if running in development"""
        return self.environment == "development"

    @property
    def database_url_computed(self) -> str:
        """Get computed database URL"""
        if self.database_url:
            return self.database_url

        if self.use_cloud_sql and self.cloud_sql_connection_name:
            # Cloud SQL connection string will be handled by the connection manager
            return f"postgresql+asyncpg://{self.database_user}:{self.database_password}@/{self.database_name}"

        return (
            f"postgresql+asyncpg://{self.database_user}:{self.database_password}"
            f"@{self.database_host}:{self.database_port}/{self.database_name}"
        )

    @property
    def google_cloud_enabled(self) -> bool:
        """Check if Google Cloud integration is enabled"""
        return bool(self.google_cloud_project)

    def get_mcp_server_config(self) -> dict:
        """Get MCP server configuration"""
        return {
            "timeout": self.mcp_server_timeout,
            "retries": self.mcp_server_retries,
            "enabled_servers": self._get_enabled_mcp_servers(),
        }

    def _get_enabled_mcp_servers(self) -> List[str]:
        """Get list of enabled MCP servers from environment"""
        servers_env = os.getenv(
            "ENABLED_MCP_SERVERS", "virustotal,servicenow,cyberreason,cloud_ivx"
        )
        return [server.strip() for server in servers_env.split(",") if server.strip()]

    def get_vertex_ai_config(self) -> dict:
        """Get Vertex AI configuration"""
        return {
            "project": self.google_cloud_project,
            "location": self.vertex_ai_location,
            "model": self.vertex_ai_model,
            "enabled": self.vertex_ai_enabled and self.google_cloud_enabled,
        }

    def get_neo4j_config(self) -> dict:
        """Get Neo4j database configuration"""
        return {
            "uri": self.neo4j_uri,
            "username": self.neo4j_username,
            "password": self.neo4j_password,
            "database": self.neo4j_database,
            "max_connection_lifetime": self.neo4j_max_connection_lifetime,
            "max_connection_pool_size": self.neo4j_max_connection_pool_size,
            "connection_timeout": self.neo4j_connection_timeout,
            "encrypted": self.neo4j_encrypted,
        }

    def get_database_config(self) -> dict:
        """Get legacy database configuration (deprecated)"""
        return {
            "url": self.database_url_computed,
            "echo": self.database_echo,
            "use_cloud_sql": self.use_cloud_sql,
            "connection_name": self.cloud_sql_connection_name,
        }


def get_settings() -> Settings:
    """Get settings instance"""
    return Settings()


# Global settings instance
settings = get_settings()
