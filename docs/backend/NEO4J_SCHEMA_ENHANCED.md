# Neo4j Graph Database Schema Design for XDR Alert Management (Enhanced Security Version)

This document outlines an enhanced schema for a Neo4j graph database to store and analyze XDR alert data from the Alert Management API. The schema has been improved based on the security analysis framework to better capture threat classifications, risk scoring, correlation patterns, and intelligence integration.

## Overview

The XDR Alert Management system involves several key entities:
- Alerts with enhanced security classifications
- Events with IOC data
- Assets with criticality metadata
- Cases for investigation tracking
- Tags for custom categorization
- Users (analysts, systems)
- MITRE ATT&CK techniques
- Notes and history for audit trails
- Threat intelligence context

These entities have complex relationships that are well-suited for a graph database representation, especially when considering security correlation patterns.

## Node Types

### 1. Alert
Represents a security alert with enhanced security properties.

**Properties:**
- `id` (UUID, Primary Key)
- `tenantId` (UUID)
- `customerId` (String)
- `name` (String)
- `message` (String)
- `severity` (Integer, 0-5)
- `score` (Integer)
- `confidence` (Integer, 0-5)
- `risk` (Integer, 0-5)
- `ruleId` (String)
- `generatedBy` (String)
- `sources` (List of Strings)
- `isSilent` (Boolean)
- `isIntelAvailable` (Boolean)
- `isSuppressed` (Boolean)
- `status` (String: NEW, IN_PROGRESS, ACK_COMPLETE, ACK_FP, SUPPRESS)
- `assignee` (String - User ID)
- `alertMetadataSuppressed` (Boolean)
- `suppressedTime` (DateTime)
- `genai_name` (String)
- `genai_summary` (String)
- `ruleOrigin` (String)
- `createdAt` (DateTime)
- `updatedAt` (DateTime)
- `isCorrelated` (Boolean)
- `totalEventMatchCount` (Integer)
- `alertAggregationCount` (Integer)
- `lastAggregatedTime` (DateTime)
- `inTimeline` (Boolean)
- `inPin` (Boolean)
- `classification` (String: CRITICAL, HIGH, MEDIUM, LOW, INFORMATIONAL)
- `workflowClassification` (String: Auto-Containable, Auto-Enrichable, Manual-Required)
- `responseSLA` (String: 15-minute, 1-hour, 4-hour, 24-hour)
- `escalationLevel` (String: SOC_Manager, Security_Engineering, None)
- `compositeRiskScore` (Float)

### 2. Event
Represents a security event that contributes to an alert with enhanced IOC data.

**Properties:**
- `id` (String, Primary Key)
- `tenantId` (UUID)
- `customerId` (String)
- `name` (String)
- `source` (String)
- `message` (String)
- `severity` (Integer, 0-5)
- `score` (Integer)
- `confidence` (Integer, 0-5)
- `risk` (String)
- `artefactType` (String)
- `sanitized` (Boolean)
- `time` (DateTime)
- `createdAt` (DateTime)
- `updatedAt` (DateTime)
- `genai_name` (String)
- `genai_summary` (String)
- `primarySecondaryFields` (Map)

### 3. Asset
Represents a device or resource affected by alerts or events with criticality metadata.

**Properties:**
- `id` (UUID, Primary Key)
- `tenantId` (UUID)
- `customerId` (String)
- `name` (String)
- `type` (String)
- `hash` (String)
- `source` (String)
- `uebaAssetId` (UUID)
- `status` (String: NOT_CONTAINED, PENDING, CONTAINED, FAILED)
- `createdAt` (DateTime)
- `updatedAt` (DateTime)
- `criticality` (Integer, 1-5)
- `businessImpact` (String: LOW, MEDIUM, HIGH, CRITICAL)
- `location` (String)
- `owner` (String - User ID)

### 4. Case
Represents an investigation case that may include multiple alerts.

**Properties:**
- `id` (UUID)
- `caseId` (BigInt)
- `customerId` (String)
- `tenantId` (UUID)
- `createdAt` (DateTime)
- `updatedAt` (DateTime)
- `status` (String)
- `priority` (Integer, 1-5)

### 5. Tag
Represents a label that can be applied to alerts.

**Properties:**
- `id` (UUID)
- `tagId` (UUID)
- `customerId` (String)
- `tenantId` (UUID)
- `createdAt` (DateTime)
- `updatedAt` (DateTime)
- `name` (String)

### 6. User
Represents a user who interacts with the system (assignee, note creator, history actor).

**Properties:**
- `id` (String, Primary Key)
- `firstName` (String)
- `lastName` (String)
- `email` (String)
- `isMssp` (Boolean)
- `role` (String: Analyst, Manager, Engineer, System)
- `department` (String)

### 7. Attack
Represents a MITRE ATT&CK technique with priority information.

**Properties:**
- `id` (Integer, Primary Key)
- `techniqueId` (String, e.g., "T1078")
- `name` (String, e.g., "Valid Accounts")
- `tactic` (String, e.g., "TA0001 - Initial Access")
- `tacticPriority` (Integer)
- `tacticName` (String, e.g., "Initial Access")
- `tacticId` (String, e.g., "TA0001")

### 8. Note
Represents a note added to an alert.

**Properties:**
- `id` (UUID, Primary Key)
- `tenantId` (UUID)
- `customerId` (String)
- `alertId` (UUID)
- `message` (String)
- `path` (String)
- `createdAt` (DateTime)
- `updatedAt` (DateTime)
- `sourceType` (String: Assignee, Acknowledgement, Suppress, General)

### 9. IntelContext
Represents threat intelligence context for indicators.

**Properties:**
- `id` (UUID, Primary Key)
- `type` (String: ip, domain, hash, email, url)
- `value` (String)
- `source` (String: TIP, Mandiant, Internal)
- `firstSeen` (DateTime)
- `lastSeen` (DateTime)
- `confidence` (Integer, 0-5)
- `severity` (String)
- `threatActors` (List of Strings)
- `campaigns` (List of Strings)
- `lethality` (String)
- `determinism` (String)
- `comment` (String)
- `createdAt` (DateTime)
- `updatedAt` (DateTime)

### 10. ThreatActor
Represents a known threat actor or APT group.

**Properties:**
- `id` (String, Primary Key)
- `name` (String)
- `description` (String)
- `country` (String)
- `attributionConfidence` (String: High, Medium, Low)
- `firstSeen` (DateTime)
- `lastSeen` (DateTime)
- `ttps` (List of Strings - technique IDs)

## Relationship Types

### 1. RELATED_TO
Connects alerts to their associated events.
- Direction: (Alert)-[:RELATED_TO]->(Event)
- Properties:
  - `inTimeline` (Boolean)
  - `inPin` (Boolean)
  - `eventGroupId` (UUID)
  - `eventGroupName` (String)
  - `createdAt` (DateTime)
  - `updatedAt` (DateTime)

### 2. AFFECTS
Connects alerts or events to the assets they affect.
- Direction: (Alert)-[:AFFECTS]->(Asset) or (Event)-[:AFFECTS]->(Asset)
- Properties:
  - `direction` (String)
  - `createdAt` (DateTime)
  - `updatedAt` (DateTime)
  - `criticalityImpact` (Integer, 1-5)

### 3. ASSIGNED_TO
Connects alerts to the user they are assigned to.
- Direction: (Alert)-[:ASSIGNED_TO]->(User)
- Properties:
  - `assignedAt` (DateTime)
  - `assignedBy` (String - User ID)
  - `notes` (String)

### 4. TAGGED_WITH
Connects alerts to their tags.
- Direction: (Alert)-[:TAGGED_WITH]->(Tag)

### 5. CORRELATED_TO
Connects alerts that are related to each other in a parent-child relationship.
- Direction: (Alert)-[:CORRELATED_TO]->(Alert)
- Properties:
  - `correlationType` (String: parent, child, peer)
  - `correlationReason` (String)
  - `correlationStrength` (Float, 0.0-1.0)
  - `tacticStage` (String: Initial Access, Execution, Persistence, etc.)
  - `createdAt` (DateTime)
  - `updatedAt` (DateTime)

### 6. PART_OF
Connects alerts to the cases they belong to.
- Direction: (Alert)-[:PART_OF]->(Case)
- Properties:
  - `addedAt` (DateTime)
  - `addedBy` (String - User ID)

### 7. MITIGATES
Connects alerts to relevant MITRE ATT&CK techniques.
- Direction: (Alert)-[:MITIGATES]->(Attack)
- Properties:
  - `confidence` (Float, 0.0-1.0)
  - `evidence` (String)

### 8. HAS_NOTE
Connects alerts to notes added by users.
- Direction: (Alert)-[:HAS_NOTE]->(Note)
- Properties:
  - `addedBy` (String - User ID)
  - `sourceType` (String: Assignee, Acknowledgement, Suppress, General)

### 9. CONNECTS
Connects events that are related to each other.
- Direction: (Event)-[:CONNECTS]->(Event)
- Properties:
  - `connectionType` (String)
  - `createdAt` (DateTime)
  - `updatedAt` (DateTime)

### 10. INDICATES
Connects events or alerts to threat intelligence context.
- Direction: (Event)-[:INDICATES]->(IntelContext) or (Alert)-[:INDICATES]->(IntelContext)
- Properties:
  - `firstSeenInEvent` (DateTime)
  - `lastSeenInEvent` (DateTime)
  - `confidence` (Float, 0.0-1.0)

### 11. ATTRIBUTED_TO
Connects alerts or events to threat actors.
- Direction: (Alert)-[:ATTRIBUTED_TO]->(ThreatActor) or (Event)-[:ATTRIBUTED_TO]->(ThreatActor)
- Properties:
  - `confidence` (String: High, Medium, Low)
  - `evidence` (String)
  - `firstSeen` (DateTime)
  - `lastSeen` (DateTime)

### 12. CLUSTERS_WITH
Connects alerts that are part of the same campaign or behavioral pattern.
- Direction: (Alert)-[:CLUSTERS_WITH]->(Alert)
- Properties:
  - `clusterType` (String: Temporal, Behavioral, IOC-Based)
  - `clusterConfidence` (Float, 0.0-1.0)
  - `timeWindow` (String)
  - `sharedIndicators` (List of Strings)

### 13. PROGRESSES_TO
Connects alerts that represent different stages of an attack chain.
- Direction: (Alert)-[:PROGRESSES_TO]->(Alert)
- Properties:
  - `fromTactic` (String)
  - `toTactic` (String)
  - `confidence` (Float, 0.0-1.0)
  - `evidence` (String)

## Security Classification Labels

Nodes can be labeled with security classifications for filtering and prioritization:

1. **:CriticalThreat** - For alerts classified as CRITICAL threat
2. **:HighThreat** - For alerts classified as HIGH threat
3. **:MediumThreat** - For alerts classified as MEDIUM threat
4. **:LowThreat** - For alerts classified as LOW threat
5. **:Informational** - For INFORMATIONAL alerts
6. **:APT** - For alerts with APT attribution
7. **:Ransomware** - For ransomware indicators
8. **:DataExfiltration** - For data exfiltration alerts

## Data Population and Derivation Logic

### Alert Classification

The `classification` property is derived from a combination of alert properties using the security analysis framework:

1. **CRITICAL Classification:**
   ```javascript
   if (
     (alert.severity === 5 && alert.confidence >= 3 &&
      (alert.sources.includes('endpoint') || alert.sources.includes('network'))) ||
     (alert.attacks && alert.attacks.some(tactic => tactic === 'TA0010')) || // Data Exfiltration
     (alert.attacks && alert.attacks.some(tactic => tactic === 'TA0008') &&
      alert.assetCount > 1) || // Lateral Movement with multiple assets
     (alert.attacks && alert.attacks.some(tactic => tactic === 'TA0011')) // Command & Control
   ) {
     classification = 'CRITICAL';
   }
   ```

2. **HIGH Classification:**
   ```javascript
   if (
     (alert.attacks && alert.attacks.some(tactic => tactic === 'TA0004')) || // Privilege Escalation
     (alert.attacks && alert.attacks.some(tactic => tactic === 'TA0005') &&
      alert.severity >= 4) || // Defense Evasion
     (alert.attacks && alert.attacks.some(tactic => tactic === 'TA0006')) || // Credential Access
     (alert.attacks && alert.attacks.some(tactic => tactic === 'TA0040') &&
      alert.artefactType && alert.artefactType.includes('file')) // Ransomware
   ) {
     classification = 'HIGH';
   }
   ```

3. **MEDIUM Classification:**
   ```javascript
   if (
     (alert.attacks &&
      (alert.attacks.some(tactic => tactic === 'TA0043') ||
       alert.attacks.some(tactic => tactic === 'TA0007'))) || // Reconnaissance
     (alert.source === 'email' && alert.confidence >= 2) || // Suspicious Email
     (alert.generatedBy && alert.generatedBy !== 'Trellix') // Policy Violations
   ) {
     classification = 'MEDIUM';
   }
   ```

4. **LOW/INFORMATIONAL Classification:**
   ```javascript
   if (
     !alert.attacks ||
     (alert.severity <= 2 && !alert.attacks) ||
     alert.isSilent === true
   ) {
     classification = 'INFORMATIONAL';
   }
   ```

### Composite Risk Score

The `compositeRiskScore` is calculated using the formula from the security analysis:

```javascript
compositeRiskScore = (alert.severity * 2) +
                     (alert.confidence * 1.5) +
                     (alert.assetCount * 0.5) +
                     (maxTacticPriority * 1.0) +
                     (intelAvailable * 0.5);

// Apply critical risk multipliers
if (alert.isCorrelated) {
  compositeRiskScore *= 1.5;
}

if (alert.assetTypes && alert.assetTypes.length > 1) {
  compositeRiskScore += (alert.assetTypes.length - 1) * 2;
}

// Add points for high-value assets (would need asset criticality data)
if (hasHighValueAssets) {
  compositeRiskScore += 3;
}

// Add points for active C&C (would need IOC analysis)
if (hasActiveCnc) {
  compositeRiskScore += 5;
}
```

### Workflow Classification

The `workflowClassification` is determined based on:

1. **Auto-Containable:**
   ```javascript
   if (
     alert.assetTypes &&
     alert.assetTypes.includes('endpoint') &&
     alert.iocs &&
     alert.iocs.length > 0
   ) {
     workflowClassification = 'Auto-Containable';
   }
   ```

2. **Auto-Enrichable:**
   ```javascript
   if (alert.isIntelAvailable === true) {
     workflowClassification = 'Auto-Enrichable';
   }
   ```

3. **Manual-Required:**
   ```javascript
   if (
     alert.attacks &&
     alert.attacks.length > 3 || // Multi-stage attack
     (alert.isCorrelated && alert.correlationDepth > 2)
   ) {
     workflowClassification = 'Manual-Required';
   }
   ```

### Response SLA

The `responseSLA` is determined based on classification and other factors:

```javascript
if (classification === 'CRITICAL') {
  responseSLA = '15-minute';
} else if (
  alert.severity >= 4 &&
  alert.assetCount > 0
) {
  responseSLA = '1-hour';
} else if (
  alert.severity === 3 ||
  (alert.generatedBy !== 'Trellix' && alert.severity >= 3)
) {
  responseSLA = '4-hour';
} else {
  responseSLA = '24-hour';
}
```

### Escalation Level

The `escalationLevel` is determined by:

```javascript
// Automatic SOC Manager Escalation
if (
  (alert.classification === 'CRITICAL' && alert.correlatedAlertsCount >= 3 &&
   timeWindow <= 1 hour) ||
  (hasExecutiveAsset && alert.classification === 'CRITICAL') ||
  (hasAptTtps && attributionConfidence >= 4)
) {
  escalationLevel = 'SOC_Manager';
}

// Security Engineering Escalation
if (
  (alert.falsePositiveRate >= 0.5 && timeWindow <= 24 hours) || // 50%+ false positives
  isNewAttackTechnique || // Not in current MITRE mapping
  performanceImpact > threshold
) {
  escalationLevel = 'Security_Engineering';
} else {
  escalationLevel = 'None';
}
```

### Asset Criticality

Asset criticality can be derived from asset type and business context:

```javascript
switch(asset.type) {
  case 'server':
  case 'domain-controller':
    criticality = 5;
    businessImpact = 'CRITICAL';
    break;
  case 'workstation':
  case 'laptop':
    if (asset.user && asset.user.role === 'executive') {
      criticality = 4;
      businessImpact = 'HIGH';
    } else {
      criticality = 3;
      businessImpact = 'MEDIUM';
    }
    break;
  case 'network-device':
    criticality = 4;
    businessImpact = 'HIGH';
    break;
  default:
    criticality = 2;
    businessImpact = 'LOW';
}
```

## Example Queries

With the enhanced schema, you can run more sophisticated security queries:

1. Find all critical alerts attributed to a specific APT group:
   ```cypher
   MATCH (a:Alert:CriticalThreat)-[:ATTRIBUTED_TO]->(ta:ThreatActor {name: "APT29"})
   RETURN a.name, a.severity, a.createdAt
   ```

2. Find attack chains progressing through MITRE tactics:
   ```cypher
   MATCH path = (a1:Alert)-[:PROGRESSES_TO*1..5]->(a2:Alert)
   WHERE ALL(rel IN relationships(path) WHERE rel.fromTactic < rel.toTactic)
   RETURN path
   ```

3. Find all assets affected by critical alerts with high business impact:
   ```cypher
   MATCH (a:Alert:CriticalThreat)-[:AFFECTS]->(asset:Asset {businessImpact: "CRITICAL"})
   RETURN asset.name, count(a) as criticalAlertCount
   ORDER BY criticalAlertCount DESC
   ```

4. Find alerts that should be escalated to SOC manager:
   ```cypher
   MATCH (a:Alert {escalationLevel: "SOC_Manager"})
   RETURN a.name, a.classification, a.responseSLA, a.compositeRiskScore
   ```

5. Find correlated alerts within a specific time window:
   ```cypher
   MATCH (a1:Alert)-[c:CLUSTERS_WITH]->(a2:Alert)
   WHERE c.clusterType = "Temporal" AND c.timeWindow = "4-hour"
   RETURN a1.name, a2.name, c.sharedIndicators
   ```

6. Find alerts with high-confidence threat intelligence matches:
   ```cypher
   MATCH (a:Alert)-[i:INDICATES]->(ic:IntelContext)
   WHERE i.confidence > 0.8
   RETURN a.name, ic.type, ic.value, i.confidence
   ```

## Data Ingestion Considerations

1. **Alert Nodes**: Create with all security classification properties when alerts are fetched from the API
2. **Event Nodes**: Create with IOC data when events are fetched
3. **Asset Nodes**: Create with criticality metadata when assets are fetched
4. **User Nodes**: Create when users are first encountered in assignee fields or history
5. **Attack Nodes**: Pre-populate with MITRE ATT&CK framework data
6. **Threat Actor Nodes**: Populate with known threat actor data
7. **Intel Context Nodes**: Create from threat intelligence feeds
8. **Relationships**: Create all relationships based on correlation logic in the security analysis
9. **Labels**: Apply security classification labels based on risk scoring

## Indexes and Constraints

To optimize performance, consider creating the following indexes and constraints:

1. **Unique Constraints**:
   - Constraint on Alert(id)
   - Constraint on Event(id)
   - Constraint on Asset(id)
   - Constraint on User(id)
   - Constraint on Attack(techniqueId)
   - Constraint on IntelContext(type, value)
   - Constraint on ThreatActor(id)

2. **Indexes**:
   - Index on Alert(severity)
   - Index on Alert(classification)
   - Index on Alert(status)
   - Index on Alert(assignee)
   - Index on Alert(createdAt)
   - Index on Alert(compositeRiskScore)
   - Index on Event(severity)
   - Index on Event(createdAt)
   - Index on Asset(type)
   - Index on Asset(criticality)
   - Index on Asset(businessImpact)
   - Index on :CriticalThreat:Alert
   - Index on :HighThreat:Alert
   - Index on Attack(tactic)
   - Index on Attack(tacticPriority)

3. **Composite Indexes**:
   - Index on Alert(customerId, status)
   - Index on Alert(customerId, classification)
   - Index on Alert(customerId, compositeRiskScore)
