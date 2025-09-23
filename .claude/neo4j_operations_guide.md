# Neo4j Database Operations Guide

## Overview
The platform uses Neo4j graph database for enhanced security analysis, providing advanced correlation capabilities and threat intelligence integration. The schema is optimized for cybersecurity use cases with MITRE ATT&CK integration.

## Core Architecture

### 1. Database Connection Management (`src/database/connection.py`)
- **Async driver**: Neo4j AsyncGraphDatabase for high-performance operations
- **Connection pooling**: 50 concurrent connections with 1-hour lifecycle
- **Environment detection**: Automatic Cloud/Local configuration
- **Health monitoring**: Built-in connection health checks
- **Session management**: Context managers for proper resource cleanup

### 2. Enhanced Security Schema (`src/database/models.py`)
The schema includes specialized nodes and relationships for cybersecurity analysis:

#### Primary Node Types
- **Alert**: Security alerts with threat classification and risk scoring
- **Event**: Security events with IOC data and artifact analysis
- **Asset**: Devices/resources with criticality metadata and business impact
- **User**: System users with roles and assignment tracking
- **Attack**: MITRE ATT&CK techniques with tactic prioritization
- **IntelContext**: Threat intelligence with confidence scoring
- **ThreatActor**: APT groups with attribution and TTP mapping

#### Configuration Nodes
- **XDRConfiguration**: XDR system polling configurations
- **MCPServerConfiguration**: MCP server integration settings
- **PollingSession**: Tracking for polling activities

### 3. Database Setup (`src/database/neo4j_setup.py`)
- **Automated indexing**: 50+ specialized indexes for performance
- **Constraint management**: Unique constraints for data integrity
- **Security labels**: Classification and access control setup

## Key Operations

### 1. Connection Initialization
```python
from database.connection import Neo4jDatabaseManager

async def init_database():
    db_manager = Neo4jDatabaseManager()
    await db_manager.initialize()

    # Health check
    health = await db_manager.health_check()
    print(f"Database health: {health}")
```

### 2. Enhanced Security Analysis

#### Alert Classification Engine
The platform automatically classifies alerts based on:
- **CRITICAL**: Data exfiltration, C&C communication, multi-stage attacks
- **HIGH**: Privilege escalation, credential access, defense evasion
- **MEDIUM**: Reconnaissance, suspicious email activity
- **LOW/INFORMATIONAL**: Low-severity or silent alerts

#### Composite Risk Scoring
```python
def calculate_composite_risk_score(alert, asset_count=0, max_tactic_priority=0):
    base_score = (alert.severity * 2) + \
                 (alert.confidence * 1.5) + \
                 (asset_count * 0.5) + \
                 (max_tactic_priority * 1.0)

    if alert.is_correlated:
        base_score *= 1.5

    return min(base_score, 25.0)
```

### 3. Graph Relationships

#### Core Security Relationships
- **RELATED_TO**: Alert-Event correlation with timeline data
- **AFFECTS**: Alert/Event-Asset impact with criticality scoring
- **CORRELATED_TO**: Alert-Alert correlation with confidence metrics
- **ATTRIBUTED_TO**: Alert-ThreatActor attribution with evidence levels
- **PROGRESSES_TO**: Attack progression chains through MITRE tactics
- **CLUSTERS_WITH**: Behavioral and temporal alert clustering

#### Example Cypher Queries
```cypher
// Find correlated alerts with high confidence
MATCH (a1:Alert)-[r:CORRELATED_TO {confidence: $confidence}]->(a2:Alert)
WHERE r.confidence >= 4
RETURN a1, a2, r

// Identify attack progressions
MATCH (attack1:Attack)-[:PROGRESSES_TO]->(attack2:Attack)
WHERE attack1.tactic_id = 'TA0001' // Initial Access
RETURN attack1, attack2

// Find high-value assets under attack
MATCH (alert:Alert)-[:AFFECTS]->(asset:Asset)
WHERE asset.criticality >= 4 AND alert.classification = 'CRITICAL'
RETURN alert, asset
```

### 4. Performance Optimization

#### Indexing Strategy
- **Primary keys**: UUID indexes on all node types
- **Time-based queries**: Indexes on created_at, updated_at
- **Security fields**: Indexes on classification, severity, confidence
- **Correlation queries**: Composite indexes for relationship traversal
- **Search optimization**: Full-text indexes on names and descriptions

#### Connection Management
```python
async with neo4j_manager.get_session() as session:
    # Session automatically closed after use
    result = await session.run(query, parameters)
    return [record async for record in result]
```

## Environment Configuration

### Local Development
```bash
# Neo4j Local Configuration
NEO4J_URI=neo4j://localhost:7687
NEO4J_USERNAME=neo4j
NEO4J_PASSWORD=password
NEO4J_DATABASE=neo4j
```

### Google Cloud Production
```bash
# Neo4j AuraDB Configuration
NEO4J_URI=neo4j+s://your-instance.databases.neo4j.io
NEO4J_USERNAME=neo4j
NEO4J_PASSWORD=your-auradb-password
NEO4J_ENCRYPTED=true
```

## Operational Commands

### Database Initialization
```bash
# Initialize database with indexes and constraints
cd src
python -m database.neo4j_setup

# Test connectivity
python -c "
from database.connection import get_database_manager
import asyncio
async def test():
    async with get_database_manager() as db:
        health = await db.health_check()
        print(health)
asyncio.run(test())
"
```

### Monitoring and Maintenance
```bash
# Check connection pool status
# Monitor active sessions and performance metrics
# Access Neo4j Browser at http://localhost:7474 (local)
# Use AuraDB Console for cloud instances
```

## Advanced Features

### 1. MITRE ATT&CK Integration
- **Technique mapping**: Automatic technique identification from alerts
- **Tactic progression**: Track attack progression through tactics
- **TTP analysis**: Correlate tactics, techniques, and procedures

### 2. Threat Intelligence Correlation
- **IOC matching**: Correlate alerts with threat intelligence feeds
- **Attribution analysis**: Link alerts to known threat actors
- **Campaign tracking**: Group related attacks by campaign

### 3. Graph-Based Analytics
- **Attack path analysis**: Identify complete attack chains
- **Temporal correlation**: Time-based event correlation
- **Behavioral clustering**: Group similar attack patterns
- **Risk propagation**: Track risk spread across infrastructure
