"""
Neo4j Models for AI-SOAR Platform

Neo4j node and relationship classes for storing XDR configurations, alert data,
and enhanced security analysis. Based on the enhanced security schema for
comprehensive threat analysis and correlation.

Author: AI-SOAR Platform Team
Created: 2025-09-10
Refactored: 2025-09-10 - Migrated from SQLAlchemy to Neo4j
"""

import json
import uuid
from dataclasses import dataclass, field
from datetime import datetime, timezone
from enum import Enum
from typing import Any, Dict, List, Optional


# Enums for data consistency
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


class ProcessingStatus(str, Enum):
    """Alert processing status"""

    PENDING = "pending"
    PROCESSING = "processing"
    COMPLETED = "completed"
    FAILED = "failed"
    SKIPPED = "skipped"


class AlertClassification(str, Enum):
    """Security threat classification"""

    CRITICAL = "CRITICAL"
    HIGH = "HIGH"
    MEDIUM = "MEDIUM"
    LOW = "LOW"
    INFORMATIONAL = "INFORMATIONAL"


class WorkflowClassification(str, Enum):
    """Workflow automation classification"""

    AUTO_CONTAINABLE = "Auto-Containable"
    AUTO_ENRICHABLE = "Auto-Enrichable"
    MANUAL_REQUIRED = "Manual-Required"


class ResponseSLA(str, Enum):
    """Response SLA timeframes"""

    FIFTEEN_MINUTE = "15-minute"
    ONE_HOUR = "1-hour"
    FOUR_HOUR = "4-hour"
    TWENTY_FOUR_HOUR = "24-hour"


class EscalationLevel(str, Enum):
    """Escalation levels"""

    SOC_MANAGER = "SOC_Manager"
    SECURITY_ENGINEERING = "Security_Engineering"
    NONE = "None"


class BusinessImpact(str, Enum):
    """Business impact levels"""

    LOW = "LOW"
    MEDIUM = "MEDIUM"
    HIGH = "HIGH"
    CRITICAL = "CRITICAL"


# Base Node Classes
@dataclass
class BaseNode:
    """Base class for all Neo4j nodes"""

    id: str = field(default_factory=lambda: str(uuid.uuid4()))
    created_at: datetime = field(default_factory=lambda: datetime.now(timezone.utc))
    updated_at: datetime = field(default_factory=lambda: datetime.now(timezone.utc))

    def to_dict(self) -> Dict[str, Any]:
        """Convert node to dictionary for Neo4j"""
        result = {}
        for key, value in self.__dict__.items():
            if isinstance(value, datetime):
                result[key] = value.isoformat()
            elif isinstance(value, Enum):
                result[key] = value.value
            elif isinstance(value, (list, dict)):
                result[key] = value
            else:
                result[key] = value
        return result


# Core Security Nodes
@dataclass
class Alert(BaseNode):
    """Enhanced Alert node with comprehensive security properties"""

    tenant_id: Optional[str] = None
    customer_id: Optional[str] = None
    name: Optional[str] = None
    message: Optional[str] = None
    severity: Optional[
        str
    ] = None  # API returns string values like "Unknown", "Low", "High", "Critical"
    severity_numeric: int = 0  # 0-5 scale for internal calculations
    score: int = 0
    confidence: int = 0  # 0-5 scale
    risk: Optional[str] = None  # API returns string or numeric, handle both
    risk_numeric: int = 0  # 0-5 scale for internal calculations
    rule_id: Optional[str] = None
    generated_by: Optional[str] = None
    sources: List[str] = field(default_factory=list)
    is_silent: bool = False
    is_intel_available: bool = False
    is_suppressed: bool = False
    status: str = "NEW"  # NEW, IN_PROGRESS, ACK_COMPLETE, ACK_FP, SUPPRESS
    assignee: Optional[str] = None
    alert_metadata_suppressed: bool = False
    suppressed_time: Optional[datetime] = None
    genai_name: Optional[str] = None
    genai_summary: Optional[str] = None
    rule_origin: Optional[str] = None
    is_correlated: bool = False
    total_event_match_count: int = 0
    alert_aggregation_count: int = 0
    last_aggregated_time: Optional[datetime] = None

    # XDR API specific fields
    attacks: List[str] = field(default_factory=list)  # MITRE ATT&CK technique IDs
    recommended_actions: List[str] = field(
        default_factory=list
    )  # Response recommendations
    assets_count: int = 0  # Asset count from API
    supporting_data: Dict[str, Any] = field(default_factory=dict)  # Additional context
    time: Optional[datetime] = None  # Event time from API

    # Enhanced security classification properties
    classification: AlertClassification = AlertClassification.INFORMATIONAL
    workflow_classification: WorkflowClassification = (
        WorkflowClassification.MANUAL_REQUIRED
    )
    response_sla: ResponseSLA = ResponseSLA.TWENTY_FOUR_HOUR
    escalation_level: EscalationLevel = EscalationLevel.NONE
    composite_risk_score: float = 0.0

    # XDR configuration reference
    configuration_id: Optional[str] = None
    external_alert_id: Optional[str] = None
    alert_data: Dict[str, Any] = field(default_factory=dict)
    related_entities: Dict[str, Any] = field(default_factory=dict)

    # Processing status
    processing_status: ProcessingStatus = ProcessingStatus.PENDING
    mcp_servers_processed: List[str] = field(default_factory=list)
    processing_results: Dict[str, Any] = field(default_factory=dict)
    processing_started_at: Optional[datetime] = None
    processing_completed_at: Optional[datetime] = None
    processing_errors: Dict[str, Any] = field(default_factory=dict)
    retry_count: int = 0
    max_retries: int = 3


@dataclass
class Event(BaseNode):
    """Security event node with IOC data"""

    tenant_id: Optional[str] = None
    customer_id: Optional[str] = None
    name: Optional[str] = None
    source: Optional[str] = None
    message: Optional[str] = None
    severity: int = 0  # 0-5 scale
    score: int = 0
    confidence: int = 0  # 0-5 scale
    risk: Optional[str] = None
    artefact_type: Optional[str] = None
    sanitized: bool = False
    time: Optional[datetime] = None
    genai_name: Optional[str] = None
    genai_summary: Optional[str] = None
    primary_secondary_fields: Dict[str, Any] = field(default_factory=dict)


@dataclass
class Asset(BaseNode):
    """Asset node with criticality metadata"""

    tenant_id: Optional[str] = None
    customer_id: Optional[str] = None
    name: Optional[str] = None
    type: Optional[str] = None
    hash: Optional[str] = None
    source: Optional[str] = None
    ueba_asset_id: Optional[str] = None
    status: str = "NOT_CONTAINED"  # NOT_CONTAINED, PENDING, CONTAINED, FAILED
    criticality: int = 1  # 1-5 scale
    business_impact: BusinessImpact = BusinessImpact.LOW
    location: Optional[str] = None
    owner: Optional[str] = None  # User ID


@dataclass
class Case(BaseNode):
    """Investigation case node"""

    case_id: Optional[int] = None
    customer_id: Optional[str] = None
    tenant_id: Optional[str] = None
    status: Optional[str] = None
    priority: int = 1  # 1-5 scale


@dataclass
class Tag(BaseNode):
    """Tag node for alert categorization"""

    tag_id: Optional[str] = None
    customer_id: Optional[str] = None
    tenant_id: Optional[str] = None
    name: Optional[str] = None


@dataclass
class User(BaseNode):
    """User node for system actors"""

    id: str = field(default_factory=lambda: str(uuid.uuid4()))
    first_name: Optional[str] = None
    last_name: Optional[str] = None
    email: Optional[str] = None
    is_mssp: bool = False
    role: str = "Analyst"  # Analyst, Manager, Engineer, System
    department: Optional[str] = None


@dataclass
class Attack(BaseNode):
    """MITRE ATT&CK technique node"""

    technique_id: Optional[str] = None  # e.g., "T1078"
    name: Optional[str] = None  # e.g., "Valid Accounts"
    tactic: Optional[str] = None  # e.g., "TA0001 - Initial Access"
    tactic_priority: int = 0
    tactic_name: Optional[str] = None  # e.g., "Initial Access"
    tactic_id: Optional[str] = None  # e.g., "TA0001"


@dataclass
class Note(BaseNode):
    """Note node for alert annotations"""

    tenant_id: Optional[str] = None
    customer_id: Optional[str] = None
    alert_id: Optional[str] = None
    message: Optional[str] = None
    path: Optional[str] = None
    source_type: str = "General"  # Assignee, Acknowledgement, Suppress, General


@dataclass
class IntelContext(BaseNode):
    """Threat intelligence context node"""

    type: Optional[str] = None  # ip, domain, hash, email, url
    value: Optional[str] = None
    source: Optional[str] = None  # TIP, Mandiant, Internal
    first_seen: Optional[datetime] = None
    last_seen: Optional[datetime] = None
    confidence: int = 0  # 0-5 scale
    severity: Optional[str] = None
    threat_actors: List[str] = field(default_factory=list)
    campaigns: List[str] = field(default_factory=list)
    lethality: Optional[str] = None
    determinism: Optional[str] = None
    comment: Optional[str] = None


@dataclass
class ThreatActor(BaseNode):
    """Threat actor/APT group node"""

    name: Optional[str] = None
    description: Optional[str] = None
    country: Optional[str] = None
    attribution_confidence: str = "Low"  # High, Medium, Low
    first_seen: Optional[datetime] = None
    last_seen: Optional[datetime] = None
    ttps: List[str] = field(default_factory=list)  # technique IDs


# Configuration Nodes (maintaining compatibility with existing system)
@dataclass
class XDRConfiguration(BaseNode):
    """XDR system configuration node"""

    name: Optional[str] = None
    description: Optional[str] = None
    base_url: Optional[str] = None
    auth_token_secret_name: Optional[str] = None
    poll_interval: int = 30
    poll_enabled: bool = False
    max_alerts_per_poll: int = 100
    severity_filter: Optional[str] = None
    entity_types: Dict[str, Any] = field(default_factory=dict)
    status: ConfigurationStatus = ConfigurationStatus.INACTIVE
    environment: EnvironmentType = EnvironmentType.DEVELOPMENT
    last_poll_at: Optional[datetime] = None


@dataclass
class PollingSession(BaseNode):
    """Polling session tracking node"""

    configuration_id: Optional[str] = None
    session_start: datetime = field(default_factory=lambda: datetime.now(timezone.utc))
    session_end: Optional[datetime] = None
    status: str = "active"
    polls_executed: int = 0
    alerts_fetched: int = 0
    alerts_processed: int = 0
    errors_encountered: int = 0
    last_poll_timestamp: Optional[datetime] = None
    last_error: Optional[str] = None


@dataclass
class MCPServerConfiguration(BaseNode):
    """MCP server configuration node"""

    name: Optional[str] = None
    server_type: Optional[str] = None
    base_url: Optional[str] = None
    enabled: bool = True
    priority: int = 100
    timeout: int = 30
    auth_config: Dict[str, Any] = field(default_factory=dict)
    alert_filters: Dict[str, Any] = field(default_factory=dict)
    processing_config: Dict[str, Any] = field(default_factory=dict)
    status: str = "active"
    last_health_check: Optional[datetime] = None
    health_status: Optional[str] = None


@dataclass
class SystemConfiguration(BaseNode):
    """System configuration node"""

    config_key: Optional[str] = None
    config_value: Dict[str, Any] = field(default_factory=dict)
    config_type: Optional[str] = None
    description: Optional[str] = None
    environment: EnvironmentType = EnvironmentType.DEVELOPMENT


# Relationship Classes
@dataclass
class Relationship:
    """Base relationship class"""

    type: str
    properties: Dict[str, Any] = field(default_factory=dict)
    created_at: datetime = field(default_factory=lambda: datetime.now(timezone.utc))
    updated_at: datetime = field(default_factory=lambda: datetime.now(timezone.utc))


# Utility functions for node creation and management
def create_node_query(node: BaseNode, labels: List[str]) -> tuple[str, Dict[str, Any]]:
    """Generate Cypher CREATE query for a node"""
    labels_str = ":".join(labels)
    properties = node.to_dict()

    # Create property placeholders
    prop_placeholders = ", ".join([f"{key}: ${key}" for key in properties.keys()])

    query = f"CREATE (n:{labels_str} {{{prop_placeholders}}}) RETURN n"

    return query, properties


def create_relationship_query(
    from_id: str,
    to_id: str,
    relationship: Relationship,
    from_labels: List[str],
    to_labels: List[str],
) -> tuple[str, Dict[str, Any]]:
    """Generate Cypher CREATE query for a relationship"""
    from_labels_str = ":".join(from_labels)
    to_labels_str = ":".join(to_labels)

    # Create property placeholders for relationship
    rel_props = relationship.properties.copy()
    rel_props["created_at"] = relationship.created_at.isoformat()
    rel_props["updated_at"] = relationship.updated_at.isoformat()

    prop_placeholders = ", ".join([f"{key}: ${key}" for key in rel_props.keys()])

    query = f"""
    MATCH (from:{from_labels_str} {{id: $from_id}})
    MATCH (to:{to_labels_str} {{id: $to_id}})
    CREATE (from)-[r:{relationship.type} {{{prop_placeholders}}}]->(to)
    RETURN r
    """

    parameters = {"from_id": from_id, "to_id": to_id, **rel_props}

    return query, parameters


# XDR API field conversion utilities
def convert_severity_to_numeric(severity_str: Optional[str]) -> int:
    """Convert XDR API severity string to numeric scale (0-5)"""
    if not severity_str:
        return 0

    severity_map = {
        "unknown": 0,
        "informational": 1,
        "low": 2,
        "medium": 3,
        "high": 4,
        "critical": 5,
    }

    return severity_map.get(str(severity_str).lower(), 0)


def convert_risk_to_numeric(risk_value: Any) -> int:
    """Convert XDR API risk value (string or numeric) to numeric scale (0-5)"""
    if risk_value is None:
        return 0

    # If already numeric, normalize to 0-5 scale
    if isinstance(risk_value, (int, float)):
        return max(0, min(5, int(risk_value)))

    # If string, convert like severity
    risk_map = {"unknown": 0, "low": 2, "medium": 3, "high": 4, "critical": 5}

    return risk_map.get(str(risk_value).lower(), 0)


def normalize_attacks_field(attacks_data: Any) -> List[str]:
    """Normalize attacks field from XDR API to list of technique IDs"""
    if not attacks_data:
        return []

    if isinstance(attacks_data, str):
        # Single attack technique
        return [attacks_data]
    elif isinstance(attacks_data, list):
        # Multiple attack techniques
        return [str(attack) for attack in attacks_data if attack]
    elif isinstance(attacks_data, dict):
        # Extract technique IDs from attack objects
        techniques = []
        if "techniques" in attacks_data:
            techniques.extend(attacks_data["techniques"])
        if "technique_id" in attacks_data:
            techniques.append(attacks_data["technique_id"])
        return techniques

    return []


def normalize_recommended_actions(actions_data: Any) -> List[str]:
    """Normalize recommended actions field from XDR API"""
    if not actions_data:
        return []

    if isinstance(actions_data, str):
        return [actions_data]
    elif isinstance(actions_data, list):
        return [str(action) for action in actions_data if action]

    return []


# Security classification utility functions
def calculate_composite_risk_score(
    alert: Alert, asset_count: int = 0, max_tactic_priority: int = 0
) -> float:
    """Calculate composite risk score based on enhanced security analysis"""
    base_score = (
        (alert.severity_numeric * 2)
        + (alert.confidence * 1.5)
        + (asset_count * 0.5)
        + (max_tactic_priority * 1.0)
        + (0.5 if alert.is_intel_available else 0)
    )

    # Apply correlation multiplier
    if alert.is_correlated:
        base_score *= 1.5

    # Add points for multiple asset types (would need asset type analysis)
    # Add points for high-value assets
    # Add points for active C&C

    return min(base_score, 25.0)  # Cap at 25


def determine_classification(
    alert: Alert, attacks: List[str] = None
) -> AlertClassification:
    """Determine security classification based on alert properties"""
    attacks = attacks or []

    # CRITICAL classification logic
    if (
        (
            alert.severity == 5
            and alert.confidence >= 3
            and any(source in ["endpoint", "network"] for source in alert.sources)
        )
        or ("TA0010" in attacks)
        or (  # Data Exfiltration
            "TA0008" in attacks and alert.total_event_match_count > 1
        )
        or ("TA0011" in attacks)  # Lateral Movement
    ):  # Command & Control
        return AlertClassification.CRITICAL

    # HIGH classification logic
    if (
        ("TA0004" in attacks)
        or ("TA0005" in attacks and alert.severity >= 4)  # Privilege Escalation
        or ("TA0006" in attacks)  # Defense Evasion
        or ("TA0040" in attacks)  # Credential Access
    ):  # Impact
        return AlertClassification.HIGH

    # MEDIUM classification logic
    if (
        ("TA0043" in attacks)
        or ("TA0007" in attacks)
        or (  # Reconnaissance
            alert.sources and "email" in alert.sources and alert.confidence >= 2
        )
    ):
        return AlertClassification.MEDIUM

    # LOW/INFORMATIONAL classification
    if not attacks or alert.severity <= 2 or alert.is_silent:
        return AlertClassification.INFORMATIONAL

    return AlertClassification.LOW


def determine_workflow_classification(alert: Alert) -> WorkflowClassification:
    """Determine workflow automation classification"""
    # Auto-Containable: has assets and IOCs
    if alert.related_entities.get("assets") and alert.related_entities.get("iocs"):
        return WorkflowClassification.AUTO_CONTAINABLE

    # Auto-Enrichable: intel available
    if alert.is_intel_available:
        return WorkflowClassification.AUTO_ENRICHABLE

    # Manual-Required: complex multi-stage attacks or deep correlation
    if alert.is_correlated and alert.alert_aggregation_count > 2:
        return WorkflowClassification.MANUAL_REQUIRED

    return WorkflowClassification.MANUAL_REQUIRED


def determine_response_sla(
    classification: AlertClassification, severity: int, asset_count: int = 0
) -> ResponseSLA:
    """Determine response SLA based on classification and other factors"""
    if classification == AlertClassification.CRITICAL:
        return ResponseSLA.FIFTEEN_MINUTE
    elif severity >= 4 and asset_count > 0:
        return ResponseSLA.ONE_HOUR
    elif severity == 3:
        return ResponseSLA.FOUR_HOUR
    else:
        return ResponseSLA.TWENTY_FOUR_HOUR


def determine_escalation_level(
    alert: Alert, attribution_confidence: int = 0
) -> EscalationLevel:
    """Determine escalation level based on alert properties"""
    # SOC Manager escalation conditions
    if (
        alert.classification == AlertClassification.CRITICAL
        and alert.alert_aggregation_count >= 3
    ) or attribution_confidence >= 4:
        return EscalationLevel.SOC_MANAGER

    # Security Engineering escalation conditions
    if alert.retry_count >= 3:  # High false positive rate indicator
        return EscalationLevel.SECURITY_ENGINEERING

    return EscalationLevel.NONE
