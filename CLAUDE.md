# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## Architecture Overview

This is an AI-driven cybersecurity automation platform that:
1. **XDR Alert Polling**: Continuously polls XDR (Extended Detection and Response) APIs for security alerts and related data
2. **MCP Integration**: Processes alerts through configured MCP (Model Context Protocol) servers for AI-powered analysis
3. **Multi-Service Architecture**: Integrates with multiple security platforms (VirusTotal, ServiceNow, CyberReason, Cloud IVX)
4. **Web Application**: FastAPI-based web interface with Google Cloud Vertex AI integration

### Core Components

#### Web Application Layer (Enhanced UX)
- **FastAPI Application** (`src/web/app.py`): Main web server with Google Cloud integration and lifecycle management
- **API Routers** (`src/web/routers/`): RESTful endpoints for configuration, dashboard, health checks, and XDR management
- **Enhanced UI Components** (`src/web/templates/`): Modern cybersecurity-focused interface with accessibility
  - **Dashboard** (`dashboard.html`): Real-time threat monitoring with interactive charts and MITRE visualization
  - **Alert Management** (`alerts.html`): Advanced filtering, bulk operations, and mobile-optimized views
  - **Base Template** (`base.html`): Responsive navigation with accessibility features and skip links
- **Frontend Assets** (`src/web/static/`): Production-ready CSS/JS with security-focused design
  - **Security Theme** (`css/security-theme.css`): Threat-level color coding and MITRE ATT&CK visualization
  - **Responsive Design** (`css/responsive-accessibility.css`): WCAG 2.1 AA compliant mobile-first approach
  - **Dashboard Logic** (`js/dashboard.js`): Real-time updates with accessibility announcements
  - **MITRE Visualization** (`js/mitre-visualization.js`): Interactive ATT&CK framework matrix
  - **Alert Management** (`js/alerts-management.js`): Advanced filtering and bulk operations
- **Service Layer** (`src/services/`): Business logic connecting web API to underlying systems

#### Data Layer (Neo4j Graph Database)
- **Graph Models** (`src/database/models.py`): Enhanced security schema with 10+ node types
  - Alert nodes with automatic threat classification (CRITICAL/HIGH/MEDIUM/LOW)
  - Event nodes with IOC data and artifact analysis
  - Asset nodes with criticality metadata (1-5 scale) and business impact
  - Attack nodes for MITRE ATT&CK technique mapping
  - ThreatActor nodes for APT attribution and TTP correlation
  - IntelContext nodes for threat intelligence integration
- **Connection Manager** (`src/database/connection.py`): Production-grade async Neo4j driver
  - Connection pooling with 50 concurrent connections
  - Automatic AuraDB vs local detection
  - Health monitoring and connection lifecycle management
  - Session context managers for resource cleanup
- **Database Setup** (`src/database/neo4j_setup.py`): Performance optimization engine
  - 50+ specialized indexes for security queries
  - Unique constraints for data integrity
  - Security classification and access control labels
- **Decomposed Services Architecture** (`src/services/`): Focused, single-responsibility services
  - **Service Coordinator** (`service_coordinator.py`): Unified interface for all platform services
  - **XDR Configuration Service** (`xdr_configuration_service.py`): XDR system management
  - **MCP Server Service** (`mcp_server_service.py`): MCP server configuration and health
  - **Alert Processing Service** (`alert_processing_service.py`): Enhanced security analysis with Neo4j population
  - **Enhanced Neo4j Population Service**: Complete schema implementation with security classification
  - **Secret Manager Service** (`secret_manager_service.py`): Google Cloud credential management
  - **Polling Session Service** (`polling_session_service.py`): Session tracking and metrics
  - **Legacy Compatibility Layer** (`config_service.py`): Backward compatibility wrapper
- **Simplified Integration Components** (`src/adapters/`, `src/processors/`, `src/extractors/`, `src/managers/`):
  - **XDR Configuration Adapter** (`xdr_configuration_adapter.py`): Unified config management
  - **Unified Alert Processor** (`unified_alert_processor.py`): Consolidated processing with storage backends
  - **XDR Data Extractor** (`xdr_data_extractor.py`): Comprehensive data extraction from XDR APIs
  - **Resource Manager** (`resource_manager.py`): Memory management and resource lifecycle tracking

#### XDR Integration with Simplified Components
- **XDR Poller** (`xdr_poller.py`): Enhanced standalone service with unified component architecture
  - Async polling with configurable intervals (default 30s)
  - **Unified Alert Processing**: Uses `UnifiedAlertProcessor` for consolidated alert handling
  - **Comprehensive Data Extraction**: `XDRDataExtractor` consolidates all data extraction functions
  - **Resource Management**: `ResourceManager` provides automatic memory cleanup and session tracking
  - **Configuration Adapter**: `XDRConfigurationAdapter` unifies service/client configuration management
  - **Dual Storage**: Enhanced JSON files + Neo4j graph database with full schema implementation
  - **Enhanced Neo4j Population**: Complete implementation of security classification and correlation
  - Development mode support with dummy credentials
  - Production-ready with SIGINT/SIGTERM handling and graceful degradation
  - **Safe Async Processing**: Error-resilient task handling prevents silent failures
- **XDR Alert Client** (`src/client/xdr_alert_client.py`): Async HTTP client wrapper
  - Built with httpx for efficient API communication
  - Callback system for real-time alert processing
  - Comprehensive error handling and retry logic
  - Field selection and pagination support
- **MCP Client** (`src/client/mcp_client.py`): Manages communication with MCP servers for alert processing

#### MCP Servers
- **Individual Servers** (`src/servers/`): Specialized security integrations:
  - VirusTotal Server (`virustotal_server.py`) - IP/domain reputation
  - ServiceNow Server (`servicenow_server.py`) - Incident management
  - CyberReason Server (`cyberreason_server.py`) - Endpoint detection
  - Cloud IVX Server (`cloud_ivx_server.py`) - Trellix threat intelligence

#### AI/ML Integration
- **Vertex AI Service** (`src/services/vertex_ai_service.py`): Google Cloud AI integration for alert analysis and recommendations

### Frontend Architecture & UX Design

#### Security-Focused UI Design System
The platform implements a comprehensive design system optimized for SOC (Security Operations Center) workflows:

**Color-Coded Threat Levels:**
- **Critical**: Red (#dc2626) with pulsing animations for immediate attention
- **High**: Orange (#ea580c) with enhanced visual prominence
- **Medium**: Yellow (#d97706) with moderate emphasis
- **Low**: Green (#059669) with subtle styling
- **Informational**: Blue (#0284c7) for system notifications

**MITRE ATT&CK Integration:**
- Interactive technique matrix with hover states and selection
- Color-coded tactics with priority-based visual hierarchy
- Real-time alert correlation with technique visualization
- Risk assessment with frequency and impact indicators

**Responsive Breakpoints:**
- Mobile: 576px (touch-optimized for on-call analysts)
- Tablet: 768px (SOC workstation secondary displays)
- Laptop: 992px (analyst primary workstations)
- Desktop: 1200px+ (SOC manager overview displays)

#### Accessibility & Performance
- **WCAG 2.1 AA Compliance**: High contrast mode, reduced motion, keyboard navigation
- **Screen Reader Support**: ARIA live regions, semantic markup, skip navigation
- **Touch Optimization**: 44px minimum touch targets, swipe gestures
- **Performance**: Lazy loading, progressive enhancement, optimized animations

### Key Data Flow

**Phase 1 (Web Configuration with Enhanced UX)**:
1. Responsive web interface allows XDR system configuration via `/config` endpoint
2. Real-time connection testing with visual feedback and accessibility announcements
3. Configurations stored in Neo4j with immediate dashboard updates
4. Mobile-optimized configuration for on-call management

**Phase 2 (Alert Processing with Real-Time Visualization)**:
1. XDR poller fetches alerts with unified component architecture
2. Alerts stored as graph nodes with enhanced security classification
3. Real-time dashboard updates with animated value changes and screen reader announcements
4. Interactive MITRE ATT&CK visualization shows attack progression
5. Mobile-responsive alert management with advanced filtering
6. Graph-powered insights displayed through accessible data visualizations

## Development Commands

### Python Environment Setup
```bash
# Create and activate virtual environment
python -m venv myenv
source myenv/bin/activate  # On Windows: myenv\Scripts\activate

# Install dependencies
pip install -r requirements.txt
```

### Running the Services

#### XDR Alert Poller
```bash
# Run with default configuration (30s interval)
python xdr_poller.py

# Custom polling interval and debug mode
python xdr_poller.py --interval 60 --debug

# Production deployment with specific API configuration
python xdr_poller.py --base-url "https://api.xdr.example.com" --auth-token "your-token"

# Development mode (handles dummy credentials gracefully)
XDR_AUTH_TOKEN="dev-dummy-token" python xdr_poller.py

# Background service deployment
nohup python xdr_poller.py > xdr_poller.log 2>&1 &

# Graceful shutdown (sends SIGTERM)
kill -TERM $(pgrep -f xdr_poller.py)
```

#### Web Application Development
```bash
# Run FastAPI web application directly (development)
cd src
python -m uvicorn web.app:app --host 0.0.0.0 --port 8080 --reload

# Access web interface at http://localhost:8080
# API documentation at http://localhost:8080/docs

# Frontend development with live reload (CSS/JS changes)
# Templates auto-reload with --reload flag
# CSS/JS changes require browser refresh
```

#### Frontend Development & Testing
```bash
# Test responsive design across breakpoints
# Use browser dev tools or these viewport sizes:
# Mobile: 375x667 (iPhone SE)
# Tablet: 768x1024 (iPad)
# Laptop: 1366x768 (Standard laptop)
# Desktop: 1920x1080 (SOC workstation)

# Test accessibility features
# Use browser accessibility tools or:
# - Tab navigation through all interactive elements
# - Screen reader testing (VoiceOver on macOS, NVDA on Windows)
# - High contrast mode testing
# - Keyboard-only navigation

# Test MITRE visualization component
python -c "
from src.web.static.js.mitre_visualization import MITREVisualization
# Component auto-initializes when mitreMatrix element present
print('MITRE visualization component loaded')
"

# Validate security color schemes
# Critical alerts should pulse red (#dc2626)
# High priority should be orange (#ea580c)
# All animations respect prefers-reduced-motion
```

#### Production Deployment
```bash
# Deploy using Docker with all services
chmod +x deployment/docker-run.sh
./deployment/docker-run.sh

# Development mode with live reload
./deployment/docker-run.sh --dev --logs

# MCP servers run on ports 8001-8005
```

#### Neo4j Database Operations
```bash
# Initialize database with full security schema (50+ indexes)
cd src
python -m database.neo4j_setup

# Test connectivity and health status
python -c "
from database.connection import get_database_manager
import asyncio
async def test():
    async with get_database_manager() as db:
        health = await db.health_check()
        print(f'Database health: {health}')
        print(f'Active sessions: {db._active_sessions}/{db._max_active_sessions}')
asyncio.run(test())
"

# Test service coordinator and all decomposed services
python -c "
from services.service_coordinator import get_service_coordinator
import asyncio
async def test_services():
    coordinator = await get_service_coordinator()
    health = await coordinator.health_check()
    print(f'Service health: {health}')

    # Test individual services
    xdr_service = await coordinator.xdr_config
    print(f'XDR service initialized: {xdr_service is not None}')

    mcp_service = await coordinator.mcp_servers
    print(f'MCP service initialized: {mcp_service is not None}')
asyncio.run(test_services())
"

# Advanced security queries (examples)
# Access Neo4j Browser at http://localhost:7474 (local)
# Use AuraDB Console for cloud instances

# Example Cypher queries for security analysis:
# Find correlated high-severity alerts:
# MATCH (a1:Alert)-[r:CORRELATED_TO]->(a2:Alert) WHERE a1.severity >= 4 RETURN a1, a2, r

# Identify attack progressions:
# MATCH (attack1:Attack)-[:PROGRESSES_TO]->(attack2:Attack) RETURN attack1.name, attack2.name

# Find critical assets under attack:
# MATCH (alert:Alert)-[:AFFECTS]->(asset:Asset) WHERE asset.criticality >= 4 RETURN alert, asset

# Enhanced XDR poller modes with unified components:
# Enhanced mode (comprehensive data collection with Neo4j-first storage)
python xdr_poller.py --interval 30

# Basic mode (fallback, minimal Neo4j storage when enhanced services unavailable)
python xdr_poller.py --basic-mode

# Debug mode with enhanced logging and Neo4j population statistics
python xdr_poller.py --debug --interval 60

# Test unified components integration with Neo4j storage
python -c "
from src.processors.unified_alert_processor import UnifiedAlertProcessor
from src.extractors.xdr_data_extractor import XDRDataExtractor
from src.managers.resource_manager import ResourceManager
from src.services.service_coordinator import get_service_coordinator
import asyncio
async def test_components():
    coordinator = await get_service_coordinator()
    extractor = XDRDataExtractor()
    resource_manager = ResourceManager()
    processor = UnifiedAlertProcessor(coordinator, ['graph'], extractor)  # Neo4j-first approach
    health = await processor.health_check()
    print(f'Unified components health: {health}')
asyncio.run(test_components())
"
```

### Debugging and Troubleshooting

#### Common Development Issues

**Service Coordinator Property Error**:
The current service coordinator implementation uses async properties which is a Python anti-pattern:
```python
# CURRENT ISSUE: This pattern may not work as expected
coordinator = await get_service_coordinator()
xdr_service = await coordinator.xdr_config  # May fail - can't await property

# WORKAROUND until fixed:
coordinator = await get_service_coordinator()
# Access private attributes after coordinator initialization:
xdr_service = coordinator._xdr_config_service  # Direct access
```

**XDR Poller Connection Issues**:
```bash
# Test XDR poller with enhanced debugging
python xdr_poller.py --debug --interval 60

# Check service initialization with error handling
python -c "
import asyncio
from src.services.service_coordinator import get_service_coordinator
async def test():
    try:
        coordinator = await get_service_coordinator()
        print('✓ Service coordinator initialized')
    except Exception as e:
        print(f'✗ Service coordinator error: {e}')
        import traceback
        traceback.print_exc()
asyncio.run(test())
"
```

**Neo4j Connection Debugging**:
```bash
# Test Neo4j connection with detailed health check
python -c "
import asyncio
from src.database.connection import get_database_manager
async def test():
    try:
        db = await get_database_manager()
        health = await db.health_check()
        print(f'Database health: {health}')
        print(f'Active sessions: {db._active_sessions}/{db._max_active_sessions}')
    except Exception as e:
        print(f'Database connection failed: {e}')
        print('This is expected if Neo4j is not running locally')
asyncio.run(test())
"
```

**Frontend API Routing Issues**:
```bash
# Test API endpoints directly
curl -i http://localhost:8080/api/security/threat-level  # Should return 200
curl -i http://localhost:8080/api/health/detailed        # Should return health status

# Common routing fix - ensure JavaScript uses correct API paths
# API_BASE_URL = '/api' in common.js combines with endpoint paths
# /security/threat-level becomes /api/security/threat-level
```

#### Testing and Development
```bash
# Development environment setup
./scripts/dev-setup.sh

# Run all tests
pytest
pytest test_enhanced_integration.py  # Integration tests
pytest test_enhanced_neo4j_integration.py  # Neo4j tests
pytest test_enhanced_poller.py  # XDR poller tests
pytest test_xdr_client.py  # XDR client tests

# Code formatting and linting (follows .pre-commit-config.yaml)
black src/
isort src/
flake8 src/
bandit -r src/  # Security linting

# Pre-commit hooks (automated on commit)
pre-commit install
pre-commit run --all-files
```

## Configuration

### Environment Variables
Copy `config/deployment/.env.template` to `.env` and configure:

#### XDR Poller Configuration
```bash
# XDR API Settings
XDR_BASE_URL="https://api.xdr.example.com"
XDR_AUTH_TOKEN="your-production-token"
XDR_POLL_INTERVAL=30
XDR_POLL_ENABLED=true
XDR_MAX_ALERTS_PER_POLL=100

# Development Settings
XDR_AUTH_TOKEN="dev-dummy-token"  # For testing without real API
```

#### Neo4j Database Configuration
```bash
# Local Development
NEO4J_URI=neo4j://localhost:7687
NEO4J_USERNAME=neo4j
NEO4J_PASSWORD=password
NEO4J_DATABASE=neo4j

# Production (AuraDB)
NEO4J_URI=neo4j+s://your-instance.databases.neo4j.io
NEO4J_USERNAME=neo4j
NEO4J_PASSWORD=your-auradb-password
NEO4J_ENCRYPTED=true
NEO4J_MAX_CONNECTION_POOL_SIZE=50
NEO4J_MAX_CONNECTION_LIFETIME=3600
```

#### Google Cloud Integration
- Google Cloud project details and service account for Vertex AI integration
- MCP server configurations
- Secret Manager for secure credential storage

### Key Configuration Files
- `src/config/settings.py`: Pydantic settings with environment variable support
- `config/ai-models/gemini_config.json`: Google Gemini AI model configuration
- `config/ai-models/vertex-ai-config.json`: Vertex AI model settings
- `config/deployment/.env.template`: Environment configuration template
- `config/deployment/nginx/nginx.conf`: Nginx reverse proxy configuration
- `config/deployment/logging/fluent.conf`: Logging configuration

## Service Architecture

### Web Application (Port 8080)
- **FastAPI Server**: Main application with async support and Google Cloud integration
- **Neo4j Integration**: Graph database with enhanced security analysis and correlation
- **API Endpoints**:
  - `/api/config/xdr` - XDR configuration management with Cypher queries
  - `/api/dashboard/` - Real-time system overview with graph-powered insights
  - `/api/health/` - Health checks including Neo4j connectivity
  - `/docs` - Interactive API documentation
- **Web Interface**: Bootstrap-based responsive UI with real-time graph analytics

### MCP Servers (Ports 8001-8005)
| Service | Port | Purpose |
|---------|------|---------|
| VirusTotal | 8001 | IP/domain reputation lookups |
| ServiceNow | 8002 | Incident and task management |
| CyberReason | 8003 | Endpoint status and threat detection |
| Cloud IVX | 8005 | Trellix threat intelligence |

### Enhanced Neo4j Graph Schema Implementation
- **Alert Nodes** (61 properties): Security alerts with automatic threat classification (CRITICAL/HIGH/MEDIUM/LOW)
  - Composite risk scoring with multi-factor analysis
  - Workflow classification (Auto-Containable, Auto-Enrichable, Manual-Required)
  - Response SLA assignment (15-minute, 1-hour, 4-hour, 24-hour)
  - Escalation level determination (SOC_Manager, Security_Engineering, None)
- **Event Nodes**: Security events with IOC data and artifact analysis
- **Asset Nodes**: Devices/resources with criticality metadata (1-5 scale) and business impact assessment
- **User Nodes**: System users with roles and assignment tracking
- **Attack Nodes**: MITRE ATT&CK techniques with tactic prioritization and progression tracking
- **IntelContext Nodes**: Threat intelligence with confidence scoring and multi-source correlation
- **ThreatActor Nodes**: APT groups with attribution confidence and TTP correlation
- **Note Nodes**: Investigation notes and audit trails
- **Case Nodes**: Investigation case management with priority tracking

### Enhanced Graph Relationships (13 types)
- **RELATED_TO**: Alert-Event correlation with timeline data and grouping
- **AFFECTS**: Alert/Event-Asset impact with criticality scoring and business impact
- **CORRELATED_TO**: Alert-Alert correlation with confidence metrics and tactic progression
- **ATTRIBUTED_TO**: Alert-ThreatActor attribution with evidence and confidence levels
- **PROGRESSES_TO**: Attack progression chains through MITRE tactics with kill chain analysis
- **CLUSTERS_WITH**: Behavioral and temporal alert clustering with shared indicators
- **MITIGATES**: Alert-Attack technique mapping with detection confidence
- **INDICATES**: Alert/Event-IntelContext threat intelligence correlation
- **ASSIGNED_TO**: Alert-User assignment tracking with notes and timestamps
- **TAGGED_WITH**: Alert-Tag categorization for custom labeling
- **PART_OF**: Alert-Case investigation tracking
- **HAS_NOTE**: Alert-Note annotation system for analyst insights
- **CONNECTS**: Event-Event relationships for complex attack analysis

### Google Cloud Integration
- **Neo4j AuraDB**: Managed graph database with connection pooling
- **Secret Manager**: Secure storage for API keys and Neo4j credentials
- **Vertex AI**: Gemini 1.5 Pro integration for enhanced alert analysis
- **Cloud Logging**: Structured logging with graph query performance metrics

## Key Dependencies

### Core Python Packages
- **FastAPI**: Web framework with async support and automatic API documentation
- **Neo4j Driver**: Async graph database driver for enhanced security analysis
- **Pydantic**: Data validation, serialization, and settings management
- **aiohttp**: Async HTTP client for external API calls
- **Jinja2**: HTML templating for web interface

### Google Cloud Platform
- **google-cloud-aiplatform**: Vertex AI integration for ML model access
- **google-cloud-logging**: Structured logging with automatic routing
- **google-cloud-secretmanager**: Secure credential storage and retrieval
- **vertexai**: Direct Vertex AI API access for Gemini models

### Development Tools
- **uvicorn**: ASGI server with auto-reload for development
- **pytest**: Testing framework with async support for Neo4j operations
- **black/isort/flake8**: Code formatting and linting tools

## Frontend Development Guidelines

### UI Component Architecture
The platform follows a component-based architecture for maintainable and scalable UI development:

#### Core JavaScript Modules
- **common.js**: Base functionality and utility functions for all pages
- **security-operations.js**: SOC-specific workflows and alert management
- **graph-visualization.js**: Network topology and relationship visualization
- **mitre-visualization.js**: Interactive MITRE ATT&CK framework integration

#### CSS Architecture Pattern
```css
/* Layer structure for maintainable styles */
/* 1. Variables and tokens */
:root { --color-threat-critical: #dc3545; }

/* 2. Base styles and resets */
* { box-sizing: border-box; }

/* 3. Component styles */
.alert-card { /* Component styling */ }

/* 4. Utility classes */
.text-threat-high { color: var(--color-threat-high); }

/* 5. Responsive overrides */
@media (max-width: 768px) { /* Mobile adaptations */ }
```

#### Security-Focused Design System

**Threat Level Color Coding**:
```css
:root {
  --threat-critical: #dc3545;    /* Red - Critical threats */
  --threat-high: #fd7e14;        /* Orange - High priority */
  --threat-medium: #ffc107;      /* Yellow - Medium risk */
  --threat-low: #28a745;         /* Green - Low/Normal */
  --threat-info: #17a2b8;        /* Blue - Informational */
}
```

**Interactive Security Elements**:
- Hover states reveal additional threat intelligence
- Click interactions show detailed MITRE technique information
- Progressive disclosure prevents information overload
- Context-sensitive tooltips provide guidance

#### Responsive SOC Operations Design

**Mobile-First Approach**:
```css
/* Base styles for mobile SOC analysts */
.alert-management {
  display: flex;
  flex-direction: column;
  gap: 1rem;
}

/* Tablet and desktop enhancements */
@media (min-width: 768px) {
  .alert-management {
    flex-direction: row;
    gap: 2rem;
  }
}
```

**Touch-Optimized Controls**:
- Minimum 44px touch targets for mobile devices
- Swipe gestures for alert triage on tablets
- Keyboard shortcuts for power users
- Voice commands integration for hands-free operation

### Accessibility Implementation (WCAG 2.1 AA)

#### Semantic HTML Structure
```html
<!-- Proper heading hierarchy -->
<h1>Security Dashboard</h1>
  <h2>Active Threats</h2>
    <h3>Critical Alerts</h3>

<!-- Descriptive link text -->
<a href="/incident/123" aria-describedby="incident-context">
  Incident #123: Ransomware Detection
</a>
<div id="incident-context" class="sr-only">
  Critical severity, 15 affected systems
</div>
```

#### Screen Reader Optimizations
```html
<!-- Skip navigation for keyboard users -->
<a href="#main-content" class="skip-link">Skip to main content</a>

<!-- ARIA landmarks and labels -->
<nav role="navigation" aria-label="Main navigation">
<main id="main-content" role="main">
<aside role="complementary" aria-label="Threat intelligence">

<!-- Live regions for dynamic updates -->
<div aria-live="polite" id="alert-announcements"></div>
<div aria-live="assertive" id="critical-notifications"></div>
```

#### Keyboard Navigation Patterns
```javascript
// Keyboard shortcut implementation
document.addEventListener('keydown', function(e) {
  // Ctrl+/ - Show keyboard shortcuts
  if (e.ctrlKey && e.key === '/') {
    showKeyboardShortcuts();
  }

  // Escape - Close modals and overlays
  if (e.key === 'Escape') {
    closeActiveModal();
  }

  // F1 - Context-sensitive help
  if (e.key === 'F1') {
    e.preventDefault();
    showContextHelp();
  }
});
```

### Interactive MITRE ATT&CK Visualization

#### Technique Mapping and Interaction
```javascript
// MITRE technique click handler with accessibility
handleTechniqueClick: function(techniqueElement) {
  const techniqueId = techniqueElement.dataset.technique;
  const techniqueData = this.mitreData[techniqueId];

  // Update ARIA states
  techniqueElement.setAttribute('aria-expanded', 'true');

  // Show technique details with focus management
  this.showTechniqueDetails(techniqueData);
  this.focusDetailsPanel();
}
```

#### Risk Correlation Visualization
```javascript
// Visual correlation between techniques and threats
updateTechniqueRiskLevel: function(techniqueId, riskLevel) {
  const element = document.querySelector(`[data-technique="${techniqueId}"]`);

  // Update visual indicators
  element.className = `mitre-technique risk-${riskLevel}`;

  // Update screen reader text
  const srText = element.querySelector('.sr-only');
  srText.textContent = `${techniqueId} - Risk level: ${riskLevel}`;
}
```

### Frontend Testing Patterns

#### Component Testing
```javascript
// Test interactive MITRE visualization
describe('MITRE Visualization', () => {
  test('should update technique risk levels correctly', () => {
    const mitreViz = new MITREVisualization();
    mitreViz.updateTechniqueRiskLevel('T1078', 'high');

    const element = document.querySelector('[data-technique="T1078"]');
    expect(element.classList.contains('risk-high')).toBe(true);
  });
});
```

#### Accessibility Testing
```javascript
// Automated accessibility testing
import { axe } from '@axe-core/jest';

test('dashboard should be accessible', async () => {
  const html = await renderDashboard();
  const results = await axe(html);
  expect(results).toHaveNoViolations();
});
```

### Common Development Commands

```bash
# Quick development startup
./scripts/dev-setup.sh                    # One-time setup
source venv/bin/activate                  # Activate environment
python -m uvicorn web.app:app --reload   # Start web server (from src/)
python xdr_poller.py --debug            # Start XDR poller with debug

# Testing and Quality
pytest                                   # Run all tests
pre-commit run --all-files              # Run all quality checks
bandit -r src/                          # Security scan

# Database operations
python -m database.neo4j_setup          # Initialize Neo4j schema (from src/)

# Production deployment
./deployment/docker-run.sh              # Docker deployment
./scripts/deploy_to_gcp.sh              # GCP deployment
```

### Performance Optimization Strategies

#### CSS Optimization
- Critical CSS inlined for above-the-fold content
- Non-critical CSS loaded asynchronously
- CSS Grid and Flexbox for efficient layouts
- Custom properties for consistent theming

#### JavaScript Optimization
- Module-based architecture for tree shaking
- Event delegation for efficient DOM handling
- Intersection Observer for lazy loading
- Service Workers for offline functionality

#### Asset Management
```html
<!-- Optimized asset loading -->
<link rel="preload" href="/css/critical.css" as="style">
<link rel="preload" href="/js/dashboard.js" as="script">

<!-- Progressive enhancement -->
<noscript>
  <link rel="stylesheet" href="/css/no-js-fallback.css">
</noscript>
```

## Deployment

### Docker Deployment
The platform is designed for containerized deployment:
- Multi-stage Dockerfile builds web app and MCP servers
- Docker Compose orchestrates all services
- Nginx reverse proxy handles routing
- Health checks and monitoring included

### Google Cloud Deployment Strategy
The platform is optimized for Google Cloud Platform deployment:
- **Google Cloud VM**: Compute Engine instances with Vertex AI integration
- **Neo4j AuraDB**: Managed graph database with automatic scaling
- **Vertex AI Models**: Gemini 1.5 Pro for enhanced alert analysis
- **Resource requirements**: 4GB+ RAM, 2+ CPU cores for web services
- **Network configuration**: VPC setup for secure service communication
- **SSL/TLS**: Google Cloud Load Balancer with managed certificates

See `deployment/VM_DEPLOYMENT_STRATEGY.md` for detailed setup instructions.

## Important Implementation Notes

### Decomposed Service Architecture
The platform uses a decomposed service architecture with Neo4j graph database:
- **Routers** (`src/web/routers/`) handle HTTP requests and responses with graph queries
- **Service Coordinator** (`src/services/service_coordinator.py`) provides unified access to all services
- **Focused Services** (`src/services/`) contain single-responsibility business logic:
  - **XDRConfigurationService**: XDR system configuration and connection testing
  - **MCPServerService**: MCP server management and health monitoring
  - **AlertProcessingService**: Enhanced security analysis with MITRE ATT&CK integration
  - **SecretManagerService**: Google Cloud Secret Manager integration
  - **PollingSessionService**: XDR polling session tracking and metrics
- **Legacy Compatibility** (`src/services/config_service.py`) maintains backward compatibility
- **Graph Models** (`src/database/models.py`) define Neo4j nodes and relationships
- **Pydantic Models** (`src/web/models/`) handle API validation and serialization

### Enhanced Security Analysis Features
- **Automatic Threat Classification**: CRITICAL, HIGH, MEDIUM, LOW based on multi-factor analysis
  - CRITICAL: Data exfiltration (TA0010), C&C communication, multi-stage attacks
  - HIGH: Privilege escalation (TA0004), credential access (TA0006), defense evasion
  - MEDIUM: Reconnaissance activities, suspicious email patterns
  - LOW/INFORMATIONAL: Low-severity alerts without correlation
- **Composite Risk Scoring**: Algorithm combining severity, confidence, asset impact, and tactics
  - Base score: (severity * 2) + (confidence * 1.5) + (asset_count * 0.5) + (tactic_priority * 1.0)
  - Correlation multiplier: 1.5x for correlated alerts
  - Capped at 25.0 for normalized scoring
- **Graph Correlation**: Native relationship traversal for attack chain analysis
  - RELATED_TO: Alert-Event correlation with timeline analysis
  - CORRELATED_TO: Alert-Alert correlation with confidence metrics
  - PROGRESSES_TO: Attack progression through MITRE tactics
- **MITRE ATT&CK Integration**: Technique mapping with tactic prioritization
  - Automatic technique identification from alert data
  - Tactic progression tracking (TA0001 → TA0004 → TA0010)
  - TTP analysis for threat actor attribution
- **Threat Intelligence**: IOC correlation with confidence scoring
  - Multi-source intelligence feeds (TIP, Mandiant, Internal)
  - Attribution confidence levels (High/Medium/Low)
  - Campaign and threat actor correlation

### Service Decomposition Pattern
The platform follows a decomposed service architecture for better maintainability:
- **Service Coordinator**: Provides unified access via `get_service_coordinator()`
- **Direct Service Access**: Use individual services for new development
- **Legacy Compatibility**: Existing code works unchanged via delegation pattern
- **Dependency Injection**: Services accept database manager in constructor
- **Health Monitoring**: Coordinator provides comprehensive health checks

Example usage patterns:
```python
# CORRECT: New code - use service coordinator with async properties
from services.service_coordinator import get_service_coordinator
coordinator = await get_service_coordinator()
xdr_service = await coordinator.xdr_config  # Note: await needed for async property
alert_service = await coordinator.alert_processing

# Direct service usage (advanced)
from services.xdr_configuration_service import XDRConfigurationService
db_manager = await get_database_manager()
xdr_service = XDRConfigurationService(db_manager)

# Legacy compatibility (existing code works unchanged)
from services.config_service import Neo4jConfigurationService
service = Neo4jConfigurationService()  # Automatically delegates
```

### Frontend Component Architecture

#### Security-Focused Component Design Patterns

**Dashboard Components**:
```javascript
// CORRECT: Use unified Dashboard object for all dashboard interactions
Dashboard.init(); // Initialize with accessibility and real-time updates
Dashboard.loadDashboardData(); // Async data loading with error handling
Dashboard.announceToScreenReader('Critical alert detected'); // Accessibility

// Real-time value animations with accessibility
Dashboard.animateValueChange(element, newValue); // Smooth transitions + screen reader
Dashboard.animateProgressBar(progressElement, targetWidth); // Progress visualization
```

**MITRE ATT&CK Visualization**:
```javascript
// CORRECT: Interactive MITRE matrix with security focus
MITREVisualization.init(); // Auto-initializes on page load
MITREVisualization.loadAlertTechniques(); // Load current threat techniques
MITREVisualization.handleTechniqueClick(element); // Interactive technique details

// Technique risk assessment
const riskLevel = MITREVisualization.calculateTechniqueRisk(techniqueId);
// Returns: 'critical', 'high', 'medium', 'low' based on alert correlation
```

**Alert Management Patterns**:
```javascript
// CORRECT: Comprehensive alert management with accessibility
AlertManagement.init(); // Initialize filtering, sorting, and bulk operations
AlertManagement.renderAlerts(alerts); // Multi-view rendering (list/card/timeline)
AlertManagement.applyFilters(); // Advanced filtering with URL persistence

// Mobile-responsive design
AlertManagement.switchView('cardView'); // Automatic mobile optimization
AlertManagement.renderMobileAlertCard(alert); // Touch-optimized card layout
```

#### Accessibility Implementation Patterns

**Screen Reader Support**:
```javascript
// CORRECT: Comprehensive accessibility announcements
function announceToScreenReader(message) {
    const announcement = document.createElement('div');
    announcement.setAttribute('aria-live', 'polite');
    announcement.className = 'visually-hidden';
    announcement.textContent = message;
    document.body.appendChild(announcement);
    setTimeout(() => document.body.removeChild(announcement), 1000);
}

// Usage for security events
announceToScreenReader('Critical alert: Privilege escalation detected');
announceToScreenReader('5 alerts assigned to current user');
```

**Keyboard Navigation**:
```javascript
// CORRECT: Security card keyboard navigation
document.addEventListener('keydown', (event) => {
    if (event.key === 'Enter' || event.key === ' ') {
        const activeElement = document.activeElement;
        if (activeElement.classList.contains('security-card')) {
            event.preventDefault();
            activeElement.click(); // Activate card interaction
        }
    }
});
```

#### Responsive Design Patterns

**Mobile-First Security Operations**:
```css
/* CORRECT: Touch-optimized controls for SOC analysts */
@media (max-width: 767.98px) {
    .security-card .btn {
        min-height: 44px; /* Accessible touch target */
        width: 100%;
        margin-bottom: 0.5rem;
    }

    .mitre-technique {
        padding: 0.75rem; /* Larger touch area */
        margin-bottom: 0.25rem;
    }
}

/* High contrast mode for accessibility */
@media (prefers-contrast: high) {
    .security-card {
        border-width: 3px;
        border-color: #000000;
    }
}

/* Reduced motion for accessibility */
@media (prefers-reduced-motion: reduce) {
    .security-card:hover,
    .mitre-technique:hover {
        transform: none; /* Disable animations */
    }
}
```

### Async Neo4j Operations
All graph operations use async patterns optimized for performance:
- Neo4j sessions via `async with neo4j_manager.get_session()`
- Connection pooling with 50 concurrent connections and 1-hour lifecycle
- Cypher query optimization with 50+ specialized indexes
- HTTP clients use aiohttp for non-blocking external API requests

### Google Cloud Integration Patterns
- Settings automatically detect Google Cloud environment via `GOOGLE_CLOUD_PROJECT`
- Neo4j AuraDB integration with secure connection management
- Secret Manager stores Neo4j credentials and API keys
- Vertex AI service provides structured AI analysis with enhanced security insights
- Cloud Logging captures graph query performance and security metrics

## Security Features

- **Enhanced Threat Detection**: Graph-based correlation identifies complex attack patterns
- **Automatic Risk Classification**: Multi-factor threat analysis with composite scoring
- **Google Cloud Authentication**: Service account integration with automatic credential detection
- **Secure Credential Management**: Secret Manager for API keys and Neo4j passwords
- **Input Validation**: Pydantic models prevent Cypher injection and data integrity issues
- **Production Security**: CORS, security headers, and encrypted database connections
- **Audit Trails**: Complete graph-based tracking of alert processing and user actions

## Monitoring and Observability

- **Graph Analytics**: Neo4j Browser integration for complex security query visualization
- **Performance Monitoring**: Graph query optimization with 50+ specialized indexes
- **Multi-level Health Checks**: `/health`, `/api/health/detailed`, `/readiness`, `/liveness`
- **Real-time Security Dashboard**: Graph-powered insights with live correlation updates
- **Google Cloud Integration**: Comprehensive logging with graph query performance metrics
- **Connection Pool Monitoring**: Neo4j connection health and automatic recovery
- **MCP Server Health**: Automatic health checks with intelligent retry logic

## Critical Implementation Notes

### XDR Poller Architecture Requirements

**Service Initialization Pattern with Unified Components** (CRITICAL):
```python
# CORRECT: Use service coordinator + unified components
async def initialize_services():
    global alert_processing_service, service_coordinator, unified_processor, data_extractor, resource_manager
    service_coordinator = await get_service_coordinator()
    alert_processing_service = await service_coordinator.alert_processing  # ✅ CORRECT

    # Initialize unified components
    data_extractor = XDRDataExtractor()
    resource_manager = ResourceManager()
    unified_processor = UnifiedAlertProcessor(
        coordinator=service_coordinator,
        storage_backends=['graph', 'file'],
        data_extractor=data_extractor
    )

# WRONG: Creates duplicate service instances
async def initialize_services():
    service_coordinator = await get_service_coordinator()  # Has alert service
    db_manager = await get_database_manager()
    alert_processing_service = AlertProcessingService(db_manager)  # ❌ DUPLICATE!
```

**Async Task Management** (CRITICAL):
```python
# CORRECT: Proper error handling for async tasks
async def handle_alerts_safely(alerts):
    try:
        await process_alerts_comprehensive(alerts)
    except Exception as e:
        logger.error(f"Alert processing error: {e}")

# In sync function:
asyncio.create_task(handle_alerts_safely(alerts))

# WRONG: Fire-and-forget pattern silently ignores errors
asyncio.create_task(process_alerts_comprehensive(alerts))  # ❌ DANGEROUS
```

**Memory Management with ResourceManager** (REQUIRED):
```python
# CORRECT: Use ResourceManager for automatic memory management
resource_manager = ResourceManager(max_processed_alerts=10000)

# Automatic deduplication and memory cleanup
if resource_manager.track_processed_alert(alert_id):
    # Process new alert - automatic LRU cache management
    await unified_processor.process_alerts([alert])

# Periodic cleanup and health monitoring
stats = resource_manager.get_stats()
logger.info(f"Resource manager stats: {stats}")

# WRONG: Manual memory management (error-prone)
global processed_alert_ids
if len(processed_alert_ids) > MAX_PROCESSED_ALERTS:
    old_ids = list(processed_alert_ids)
    processed_alert_ids = set(old_ids[MAX_PROCESSED_ALERTS//2:])  # ❌ MANUAL
```

### Recent Fixes and Critical Patterns

#### Async Task Safety (Fixed in Latest Version)
The XDR poller now uses safe async task handling:

```python
# CORRECT: Safe async task creation with error handling
async def handle_alerts_safely(alerts: List[Dict]) -> None:
    try:
        await process_alerts_comprehensive(alerts)
    except Exception as e:
        logger.error(f"Alert processing error: {e}")

# In sync context:
asyncio.create_task(handle_alerts_safely(alerts))

# WRONG: Fire-and-forget pattern (fixed)
asyncio.create_task(process_alerts_comprehensive(alerts))  # No error handling
```

#### Neo4j Async Context Manager Fix (CRITICAL)
The Neo4j connection manager was fixed to properly support async context managers:

```python
# CORRECT: Fixed implementation in database/connection.py
@asynccontextmanager
async def get_session(self) -> AsyncGenerator[AsyncSession, None]:
    # Proper async context manager with @asynccontextmanager decorator

# Usage (now works correctly):
async with db_manager.get_session() as session:
    result = await session.run("MATCH (n) RETURN n LIMIT 10")
```

#### Resource Management Pattern (Required)
```python
# CORRECT: Use ResourceManager for memory management and deduplication
resource_manager = ResourceManager(max_processed_alerts=10000)
if resource_manager.track_processed_alert(alert_id):
    # Process new alert - automatic deduplication and LRU cache cleanup
    await unified_processor.process_alerts([alert])

# Get memory usage statistics
stats = resource_manager.get_stats()
logger.info(f"Resource manager stats: {stats}")
```

#### Enhanced Neo4j Population Service Pattern
```python
# CORRECT: Use write transactions for atomicity
async def populate_comprehensive_alert_data(self, enhanced_alert_data: Dict[str, Any]) -> Alert:
    async with db_manager.get_session() as session:
        async def _populate_transaction(tx):
            # All database operations in transaction function
            return await self._create_enhanced_alert_node(enhanced_alert_data, tx)

        # Execute in write transaction for proper atomicity
        alert = await session.execute_write(_populate_transaction)
        return alert
```

#### Frontend API Response Structure Fix (Recent)
The JavaScript code was updated to match the actual API response format:

```javascript
// CORRECT: Updated to match API response structure
const threatData = await Utils.apiRequest('/security/threat-level');
const level = threatData.threat_level.current_level.toLowerCase();
const levelText = threatData.threat_level.current_level;

// WRONG: Old pattern expecting different structure (fixed)
const level = threatData.level.toLowerCase();  // ❌ API doesn't return .level
```

**API Response Format**:
```json
{
  "timestamp": "2025-09-24T15:59:37.156077",
  "threat_level": {
    "current_level": "moderate",
    "score": 6.2,
    "trend": "increasing",
    "indicators": {"high": 12, "medium": 28, "low": 45},
    "last_updated": "2025-09-24T15:59:37.156082"
  }
}
```

### Testing Commands

```bash
# Test service coordinator integration (with error handling)
python -c "
from src.services.service_coordinator import get_service_coordinator
import asyncio
async def test():
    try:
        coordinator = await get_service_coordinator()
        # Note: async property pattern may need fixing
        print('✓ Service coordinator initialized')
    except Exception as e:
        print(f'✗ Service error: {e}')
asyncio.run(test())
"

# Test unified components data extraction
python -c "
from src.extractors.xdr_data_extractor import XDRDataExtractor
import asyncio
async def test():
    extractor = XDRDataExtractor()
    test_alert = {'id': 'test', 'attributes': {'ruleId': 'privilege_escalation'}}
    comprehensive_data = await extractor.extract_comprehensive_data(test_alert)
    print(f'Unified extraction: {len(comprehensive_data.get(\"assets\", []))} assets, {len(comprehensive_data.get(\"mitre_techniques\", []))} techniques')
    print(f'Data sources: {comprehensive_data.get(\"analysis_metadata\", {}).get(\"data_sources\", [])}')
asyncio.run(test())
"

# Validate service patterns
python -c "
import ast
import inspect
from xdr_poller import initialize_services
source = inspect.getsource(initialize_services)
if 'AlertProcessingService(db_manager)' in source:
    print('❌ CRITICAL: Duplicate service instance detected')
else:
    print('✅ Service initialization pattern correct')
"
```

## Enhanced Neo4j Schema Implementation

The platform implements a comprehensive Neo4j graph schema as defined in `NEO4J_SCHEMA_ENHANCED.md`:

### Security Classification Logic
```python
# Automatic threat classification based on MITRE tactics and multi-factor analysis
if alert.tactics.includes('TA0010') or alert.tactics.includes('TA0011'):  # Data Exfiltration / C&C
    classification = 'CRITICAL'
elif alert.tactics.includes('TA0004') or alert.tactics.includes('TA0006'):  # Privilege Escalation / Credential Access
    classification = 'HIGH'
elif alert.tactics.includes('TA0007') or alert.source == 'email':  # Discovery / Email threats
    classification = 'MEDIUM'
else:
    classification = 'LOW' or 'INFORMATIONAL'
```

### Composite Risk Scoring Algorithm
```python
# Multi-factor risk calculation with correlation multipliers
base_score = (severity * 2) + (confidence * 1.5) + (asset_count * 0.5) + (tactic_priority * 1.0)
if alert.isCorrelated:
    base_score *= 1.5  # Correlation multiplier
composite_risk_score = min(base_score + threat_intel_bonus + high_value_asset_bonus, 25.0)
```

### Graph Population Commands
```bash
# Test enhanced Neo4j population service
python -c "
from src.services.enhanced_neo4j_population_service import EnhancedNeo4jPopulationService
from src.services.service_coordinator import get_service_coordinator
import asyncio
async def test_neo4j():
    coordinator = await get_service_coordinator()
    enhanced_service = await coordinator.enhanced_neo4j
    test_alert = {
        'id': 'test-001',
        'attributes': {'severity': 5, 'ruleId': 'lateral_movement'},
        'comprehensive_data': {'mitre_techniques': [{'technique_id': 'TA0008'}]}
    }
    result = await enhanced_service.store_enhanced_alert(test_alert)
    print(f'Enhanced alert stored: {result.classification} risk score: {result.composite_risk_score}')
asyncio.run(test_neo4j())
"

# Query enhanced graph data
# Access Neo4j Browser at http://localhost:7474
# Example advanced queries:
# MATCH (a:Alert:CriticalThreat)-[:ATTRIBUTED_TO]->(ta:ThreatActor) RETURN a, ta
# MATCH path = (a1:Alert)-[:PROGRESSES_TO*1..3]->(a2:Alert) RETURN path
# MATCH (a:Alert)-[:AFFECTS]->(asset:Asset {businessImpact: 'CRITICAL'}) RETURN a, asset
```

## Google Cloud Deployment Focus

This platform is specifically optimized for Google Cloud Platform deployment with:
- **Vertex AI Integration**: Gemini 1.5 Pro models for enhanced threat analysis
- **Neo4j AuraDB**: Managed graph database with automatic scaling and backup
- **Enhanced Security Analysis**: Complete MITRE ATT&CK integration with threat intelligence correlation
- **Compute Engine**: Optimized VM configurations for security workloads
- **Secret Manager**: Centralized credential management for all external integrations
- **Cloud Logging**: Structured logging with security-focused log aggregation
- **Load Balancing**: Google Cloud Load Balancer with SSL termination

## Development Workflow

### Pre-commit Quality Gates
The project uses automated quality checks configured in `.pre-commit-config.yaml`:
- **Code Formatting**: Black and isort for consistent style
- **Linting**: Flake8 for code quality
- **Security**: Bandit for security vulnerability scanning
- **General**: Trailing whitespace, JSON/YAML validation, merge conflict detection

### Service Integration Patterns
Always use the service coordinator pattern for new development:
```python
# REQUIRED: Use service coordinator for all new code
from services.service_coordinator import get_service_coordinator
coordinator = await get_service_coordinator()
service = await coordinator.service_name  # Async property access
```

### Testing Strategy
The platform has comprehensive test coverage:
- `test_enhanced_integration.py` - End-to-end integration tests
- `test_enhanced_neo4j_integration.py` - Database integration tests
- `test_enhanced_poller.py` - XDR polling service tests
- `test_neo4j_refactor.py` - Service refactoring validation
- `test_xdr_client.py` - XDR API client tests

## Current Codebase Status and Compatibility

### Known Issues and Workarounds

#### Service Coordinator Async Property Pattern
**Status**: Active issue requiring attention
**Impact**: Service initialization in XDR poller and web application
**Workaround**:
```python
# Current problematic pattern:
coordinator = await get_service_coordinator()
service = await coordinator.xdr_config  # May not work - async property issue

# Temporary workaround:
coordinator = await get_service_coordinator()
service = coordinator._xdr_config_service  # Direct access after initialization
```

#### Template and Static File Path Resolution
The web application uses robust fallback path resolution for deployment flexibility:
```python
# Primary paths (development)
static_dir = "src/web/static/"
templates_dir = "src/web/templates/"

# Docker fallback paths
static_dir = "/app/src/web/static/"
templates_dir = "/app/src/web/templates/"

# Final fallback
static_dir = "static/"
templates_dir = "templates/"
```

#### Database Integration Resilience
Neo4j integration includes graceful degradation:
- Mock data served when database unavailable
- Connection pooling with automatic retry
- Health checks with detailed error reporting
- Development mode supports dummy credentials

### Development Environment Requirements
- **Python**: 3.8+ with asyncio support
- **Neo4j**: 4.4+ (local) or AuraDB (production)
- **Node.js**: Not required (frontend uses CDN resources)
- **Docker**: Optional but recommended for full stack testing
- **Google Cloud**: Optional for Vertex AI integration
