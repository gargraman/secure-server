# AI-Driven Cybersecurity Automation Platform (AI-SOAR)

## Overview

A comprehensive cybersecurity automation platform that integrates Extended Detection and Response (XDR) systems with AI-powered analysis through Model Context Protocol (MCP) servers and graph-based threat intelligence.

## 🏗️ Project Structure

```
secure-server/
├── docs/                          # 📚 Documentation
│   ├── CLAUDE.md                  # Main project documentation & architecture
│   ├── api/                       # API documentation
│   │   └── SERVICE_URLS_REFERENCE.md
│   ├── architecture/              # System architecture & design
│   │   ├── REFACTORING_GUIDE.md
│   │   └── REFACTORING_SUMMARY.md
│   ├── backend/                   # Backend documentation
│   │   ├── NEO4J_SCHEMA_ENHANCED.md
│   │   ├── ENHANCED_NEO4J_IMPLEMENTATION.md
│   │   ├── ENHANCED_XDR_POLLER_SUMMARY.md
│   │   └── xdr-client.md
│   ├── deployment/                # Deployment guides
│   │   ├── DEPLOYMENT_GUIDE.md
│   │   ├── DEPLOYMENT_SUMMARY.md
│   │   ├── README.md
│   │   ├── VM_DEPLOYMENT_STRATEGY.md
│   │   └── WEB_DEPLOYMENT_GUIDE.md
│   ├── frontend/                  # Frontend documentation
│   │   ├── DEPLOYMENT_FRONTEND_INTEGRATION.md
│   │   └── LICENSING_COMPLIANCE.md
│   └── guides/                    # User guides
│       └── scripts.md
├── config/                        # ⚙️ Configuration Management
│   ├── ai-models/                 # AI model configurations
│   │   ├── gemini_config.json
│   │   └── vertex-ai-config.json
│   ├── deployment/                # Deployment configurations
│   │   ├── .env.template
│   │   ├── staging.env
│   │   ├── production.env
│   │   ├── .env.development
│   │   ├── nginx/
│   │   │   └── nginx.conf
│   │   └── logging/
│   │       └── fluent.conf
│   └── secrets-templates/         # Secret templates (DO NOT commit actual secrets)
│       └── README.md
├── src/                           # 🔧 Source Code
│   ├── web/                       # FastAPI web application
│   ├── services/                  # Business logic services
│   ├── database/                  # Neo4j database layer
│   ├── client/                    # XDR API clients
│   └── servers/                   # MCP servers
├── deployment/                    # 🚀 Deployment Scripts & Docker
│   ├── Dockerfile
│   ├── docker-compose.yml
│   └── scripts/
└── scripts/                       # 🛠️ Utility Scripts
    ├── archive/
    └── dev-setup.sh
```

## 🚀 Quick Start

### Prerequisites

- Python 3.12+
- Neo4j Database (local or AuraDB)
- Google Cloud Project (for Vertex AI)
- Docker (for containerized deployment)

### Development Setup

1. **Clone and Setup Environment**
   ```bash
   git clone <repository-url>
   cd secure-server
   python -m venv venv
   source venv/bin/activate  # On Windows: venv\Scripts\activate
   pip install -r requirements.txt
   ```

2. **Configure Environment**
   ```bash
   # Copy environment template
   cp config/deployment/.env.template .env

   # Edit with your credentials
   nano .env
   ```

3. **Initialize Database**
   ```bash
   cd src
   python -m database.neo4j_setup
   ```

4. **Run the Application**
   ```bash
   # Start web interface
   python -m uvicorn web.app:app --host 0.0.0.0 --port 8080 --reload

   # Start XDR poller (in another terminal)
   python xdr_poller.py
   ```

5. **Access the Platform**
   - Web Interface: http://localhost:8080
   - API Documentation: http://localhost:8080/docs

## 📖 Documentation

### Quick Links

- **[📋 Main Documentation](docs/CLAUDE.md)** - Complete project overview and architecture
- **[🏗️ Architecture Guide](docs/architecture/REFACTORING_GUIDE.md)** - System design and patterns
- **[🚀 Deployment Guide](docs/deployment/DEPLOYMENT_GUIDE.md)** - Production deployment instructions
- **[🌐 Frontend Guide](docs/frontend/LICENSING_COMPLIANCE.md)** - UI/UX development and compliance
- **[🔧 API Reference](docs/api/SERVICE_URLS_REFERENCE.md)** - Complete API documentation

### Key Features Documentation

- **[📊 Neo4j Graph Database](docs/backend/NEO4J_SCHEMA_ENHANCED.md)** - Enhanced security schema
- **[🔍 XDR Integration](docs/backend/ENHANCED_XDR_POLLER_SUMMARY.md)** - Alert polling and processing
- **[⚡ Frontend Components](docs/frontend/DEPLOYMENT_FRONTEND_INTEGRATION.md)** - UI architecture

## 🌟 Key Features

### 🛡️ Security Operations
- **Real-time XDR Alert Polling** - Continuous monitoring of security alerts
- **MITRE ATT&CK Integration** - Technique mapping and threat classification
- **Graph-based Threat Intelligence** - Relationship analysis and correlation
- **Automated Incident Response** - AI-powered response recommendations

### 🤖 AI Integration
- **Vertex AI Integration** - Google Cloud AI for alert analysis
- **MCP Server Architecture** - Modular threat intelligence processing
- **Multi-source Intelligence** - VirusTotal, ServiceNow, CyberReason integration

### 🎨 Modern UI/UX
- **Security-focused Dashboard** - Real-time SOC operations interface
- **WCAG 2.1 AA Compliant** - Full accessibility support
- **Mobile Responsive** - Optimized for security analysts on mobile
- **Interactive Visualizations** - Network graphs and threat timelines

### 🏗️ Architecture
- **Decomposed Services** - Microservice-style architecture
- **Neo4j Graph Database** - Enhanced security relationship modeling
- **Google Cloud Native** - Optimized for GCP deployment
- **Docker Containerized** - Production-ready deployment

## 🔧 Development

### Service Architecture

The platform uses a decomposed service architecture:

```python
# Recommended pattern for new development
from services.service_coordinator import get_service_coordinator

coordinator = await get_service_coordinator()
xdr_service = await coordinator.xdr_config
alert_service = await coordinator.alert_processing
```

### Testing

```bash
# Run tests
python -m pytest

# Code formatting
black src/
isort src/
flake8 src/
```

### Contributing

1. Follow the [Architecture Guide](docs/architecture/REFACTORING_GUIDE.md)
2. Use the decomposed service patterns
3. Ensure accessibility compliance (WCAG 2.1 AA)
4. Add comprehensive documentation

## 🚀 Deployment

### Development
```bash
# Quick development setup
./scripts/dev-setup.sh
python -m uvicorn web.app:app --reload
```

### Production
```bash
# Docker deployment
cd deployment/
docker-compose up -d

# Manual deployment
./docker-run.sh --production
```

See [Deployment Guide](docs/deployment/DEPLOYMENT_GUIDE.md) for detailed instructions.

## 📊 Monitoring

- **System Health**: `/api/health/detailed`
- **Performance Metrics**: `/api/dashboard/system-performance`
- **Neo4j Browser**: http://localhost:7474 (local)
- **Application Logs**: Check deployment/logs/

## 🔒 Security

- **No hardcoded secrets** - All credentials via environment variables
- **Input validation** - Pydantic models prevent injection attacks
- **Encrypted connections** - TLS for all external communications
- **Audit trails** - Complete graph-based activity tracking

## 📝 License

See individual component licenses in [Frontend Licensing Compliance](docs/frontend/LICENSING_COMPLIANCE.md).

## 🆘 Support

- **Documentation**: See [docs/](docs/) directory
- **Issues**: Check logs in `/api/health/detailed`
- **Architecture Questions**: Refer to [CLAUDE.md](docs/CLAUDE.md)

---

**Note**: This is a sophisticated cybersecurity platform. Ensure proper security practices and credential management in production deployments.
