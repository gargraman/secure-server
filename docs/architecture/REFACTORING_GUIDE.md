# Neo4j Database Refactoring Guide

## Overview

This document describes the refactoring of the AI-SOAR Platform database layer from PostgreSQL/SQLAlchemy to Neo4j graph database. The refactoring enhances the system's ability to handle complex security relationships, threat correlation, and advanced analytics while maintaining API compatibility.

## 🔄 What Changed

### Database Architecture Migration
- **FROM:** PostgreSQL with SQLAlchemy ORM
- **TO:** Neo4j graph database with async Python driver
- **Enhanced:** Security schema with threat intelligence and correlation capabilities

### Key Improvements
1. **Graph-Based Relationships:** Native support for complex security relationships
2. **Enhanced Security Classification:** Comprehensive threat analysis and risk scoring
3. **Performance Optimization:** Graph traversal queries for correlation analysis
4. **Scalability:** Better handling of interconnected security data
5. **Intelligence Integration:** Native threat intelligence and IOC correlation

## 📁 Files Modified

### Core Database Layer
- **`src/database/connection.py`** - Neo4j connection management
- **`src/database/models.py`** - Graph node and relationship models
- **`src/database/neo4j_setup.py`** - Database setup, indexes, and constraints
- **`src/services/config_service.py`** - Service layer with Cypher queries
- **`requirements.txt`** - Updated dependencies

### New Components
- **`test_neo4j_refactor.py`** - Comprehensive test suite
- **`REFACTORING_GUIDE.md`** - This documentation

## 🚀 Getting Started

### Prerequisites
1. **Neo4j Database:**
   - Local: Neo4j Desktop or Docker container
   - Cloud: Neo4j AuraDB instance
2. **Python Dependencies:** Run `pip install -r requirements.txt`

### Environment Configuration
Add these environment variables:

```bash
# Neo4j Configuration
NEO4J_URI=neo4j://localhost:7687  # or neo4j+s://your-aura-instance.databases.neo4j.io
NEO4J_USER=neo4j
NEO4J_PASSWORD=your-password
USE_CLOUD_NEO4J=false  # Set to true for AuraDB

# Google Cloud (if using GCP integration)
GOOGLE_CLOUD_PROJECT=your-project-id
```

### Database Setup
1. **Initialize Database:**
   ```bash
   python -m src.database.neo4j_setup
   ```

2. **Run Tests:**
   ```bash
   python test_neo4j_refactor.py
   ```

## 🏗 Architecture Details

### Node Types

#### Core Security Nodes
- **Alert:** Enhanced security alerts with classification and risk scoring
- **Event:** Security events with IOC data
- **Asset:** Devices/resources with criticality metadata
- **User:** System users and analysts
- **Case:** Investigation cases
- **Tag:** Alert categorization labels

#### Intelligence Nodes
- **Attack:** MITRE ATT&CK techniques and tactics
- **IntelContext:** Threat intelligence indicators
- **ThreatActor:** Known threat actors and APT groups
- **Note:** Alert annotations and comments

#### Configuration Nodes
- **XDRConfiguration:** XDR system configurations
- **PollingSession:** Polling session tracking
- **MCPServerConfiguration:** MCP server settings
- **SystemConfiguration:** System-wide settings

### Relationship Types
- **RELATED_TO:** Alert ↔ Event relationships
- **AFFECTS:** Alert/Event → Asset impacts
- **ASSIGNED_TO:** Alert → User assignments
- **CORRELATED_TO:** Alert ↔ Alert correlations
- **MITIGATES:** Alert → Attack technique mappings
- **ATTRIBUTED_TO:** Alert → ThreatActor attributions
- **INDICATES:** Event → IntelContext intelligence matches

### Enhanced Security Features

#### Automatic Classification
Alerts are automatically classified using advanced logic:
- **CRITICAL:** Data exfiltration, C&C communications, multi-asset lateral movement
- **HIGH:** Privilege escalation, credential access, defense evasion
- **MEDIUM:** Reconnaissance, suspicious email, policy violations
- **LOW/INFORMATIONAL:** Low-risk activities, silent alerts

#### Composite Risk Scoring
Dynamic risk calculation based on:
```python
risk_score = (severity * 2) + (confidence * 1.5) + (asset_count * 0.5) +
             (tactic_priority * 1.0) + (intel_available * 0.5)
```

#### Workflow Automation Classification
- **Auto-Containable:** Has assets and IOCs for automated response
- **Auto-Enrichable:** Intelligence available for automated enrichment
- **Manual-Required:** Complex scenarios requiring analyst intervention

#### Response SLA Determination
- **15-minute:** CRITICAL classification
- **1-hour:** HIGH severity with affected assets
- **4-hour:** MEDIUM severity
- **24-hour:** LOW severity or informational

## 🔍 Usage Examples

### Creating Enhanced Alerts
```python
from src.services.config_service import Neo4jConfigurationService
from src.database.connection import get_database_manager

# Initialize service
db_manager = await get_database_manager()
service = Neo4jConfigurationService(db_manager)

# Create alert from XDR data with automatic classification
alert = await service.create_alert_from_xdr_data(
    alert_data={
        'name': 'Suspicious Process Execution',
        'severity': 4,
        'confidence': 3,
        'sources': ['endpoint'],
        'attacks': ['TA0004', 'TA0005'],  # Privilege Escalation, Defense Evasion
        'relatedEntities': {
            'assets': [{'id': 'asset-123', 'type': 'workstation'}],
            'iocs': [{'type': 'hash', 'value': 'sha256:...'}]
        }
    },
    configuration_id='config-uuid'
)
# Alert automatically classified as HIGH with appropriate SLA
```

### Advanced Cypher Queries
```python
# Find correlated critical alerts
query = """
MATCH (a1:Alert:CriticalThreat)-[:CORRELATED_TO]-(a2:Alert)
WHERE a1.created_at > datetime('2025-01-01T00:00:00Z')
RETURN a1.name, a2.name, a1.composite_risk_score
ORDER BY a1.composite_risk_score DESC
LIMIT 10
"""

# Find attack progression chains
query = """
MATCH path = (a1:Alert)-[:PROGRESSES_TO*1..5]->(a2:Alert)
WHERE a1.classification = 'CRITICAL'
RETURN path, length(path) as chain_length
ORDER BY chain_length DESC
"""

# Find high-risk assets
query = """
MATCH (alert:Alert)-[:AFFECTS]->(asset:Asset)
WHERE alert.classification IN ['CRITICAL', 'HIGH']
RETURN asset.name, asset.criticality, count(alert) as alert_count
ORDER BY alert_count DESC, asset.criticality DESC
LIMIT 20
"""
```

### Service Layer Operations
```python
# List configurations with filtering
configs = await service.list_xdr_configurations(
    environment='production',
    status='active',
    limit=50
)

# Start polling session
session = await service.start_polling_session(
    configuration_id='config-uuid',
    override_interval=60
)

# Test XDR connection
test_result = await service.test_xdr_connection('config-uuid')
```

## 🔧 Configuration

### Neo4j Settings
The system automatically detects cloud vs. local Neo4j:
- **Local Development:** `neo4j://localhost:7687`
- **Cloud AuraDB:** `neo4j+s://instance.databases.neo4j.io`

### Connection Pool Settings
```python
# Configurable in connection.py
_connection_pool_size = 50
_max_connection_lifetime = 3600  # 1 hour
```

### Security Labels
Automatic labeling for performance optimization:
- `:CriticalThreat` - CRITICAL classification alerts
- `:HighThreat` - HIGH classification alerts
- `:MediumThreat` - MEDIUM classification alerts
- `:APT` - APT-attributed alerts
- `:Ransomware` - Ransomware indicators

## 📊 Performance Optimizations

### Indexes Created
- **Node Properties:** severity, classification, status, created_at
- **Composite Indexes:** customer_id + classification, created_at + status
- **Security Labels:** Optimized queries for threat classifications
- **Relationship Indexes:** Correlation and attribution queries

### Query Patterns
- **Use MATCH with labels:** `MATCH (a:Alert:CriticalThreat)`
- **Parameterize queries:** Prevent injection and improve caching
- **Limit results:** Always use LIMIT for large datasets
- **Index hints:** Use WHERE clauses on indexed properties

## 🧪 Testing

### Test Suite Coverage
Run `python test_neo4j_refactor.py` to verify:
- ✅ Database connectivity
- ✅ Health checks
- ✅ Node creation and retrieval
- ✅ Cypher query execution
- ✅ Service layer operations
- ✅ Enhanced security features
- ✅ Relationship management
- ✅ Query performance

### Manual Testing
```bash
# Test database setup
python -m src.database.neo4j_setup

# Validate installation
python -c "import asyncio; from src.database.connection import get_database_manager; asyncio.run(get_database_manager())"
```

## 🔄 Migration Path

### For Existing Deployments
1. **Backup existing PostgreSQL data**
2. **Set up Neo4j instance**
3. **Run database setup script**
4. **Migrate existing data using custom scripts**
5. **Update environment variables**
6. **Test thoroughly**

### Data Migration Script Example
```python
# Create migration script to transfer existing data
async def migrate_postgresql_to_neo4j():
    # Connect to both databases
    # Extract data from PostgreSQL
    # Transform to Neo4j format
    # Create nodes and relationships
    pass
```

## 🚨 Troubleshooting

### Common Issues

#### Connection Errors
- **Issue:** `ServiceUnavailable: Could not connect to Neo4j`
- **Solution:** Check Neo4j service is running and credentials are correct

#### Performance Issues
- **Issue:** Slow queries
- **Solution:** Ensure indexes are created, use PROFILE/EXPLAIN for optimization

#### Memory Issues
- **Issue:** High memory usage
- **Solution:** Adjust connection pool size, add query limits

### Debugging Queries
```cypher
// Check what indexes exist
SHOW INDEXES

// Profile query performance
PROFILE MATCH (a:Alert) WHERE a.severity = 5 RETURN count(a)

// Explain query plan
EXPLAIN MATCH (a:Alert)-[:CORRELATED_TO]->(b:Alert) RETURN a, b
```

## 📈 Monitoring

### Health Check Endpoint
The health check provides comprehensive status:
```json
{
  "status": "healthy",
  "database_type": "Neo4j",
  "connection_type": "local",
  "node_count": 12543,
  "pool_size": 50,
  "components": [...]
}
```

### Performance Metrics
- Connection pool utilization
- Query execution times
- Node/relationship counts
- Index usage statistics

## 🔮 Future Enhancements

### Planned Features
1. **Advanced Analytics:** Graph algorithms for threat hunting
2. **Real-time Correlation:** Stream processing integration
3. **ML Integration:** Graph neural networks for anomaly detection
4. **Visualization:** Graph-based security dashboards
5. **Federation:** Multi-tenant graph isolation

### Optimization Opportunities
- Query optimization with more specific indexes
- Cached frequent query results
- Batch operations for bulk data import
- Graph partitioning for large deployments

## 📚 References

- [Neo4j Python Driver Documentation](https://neo4j.com/docs/python-manual/current/)
- [Cypher Query Language](https://neo4j.com/docs/cypher-manual/current/)
- [Neo4j Performance Tuning](https://neo4j.com/docs/operations-manual/current/performance/)
- [MITRE ATT&CK Framework](https://attack.mitre.org/)

---

**Note:** This refactoring maintains backward compatibility with existing API endpoints while providing enhanced graph-based capabilities for security analysis and threat correlation.
