# AI-SOAR Platform - Service URLs and Access Guide

## 🌐 Main Access URLs

### Primary Web Application
- **Main Web Interface**: http://localhost:8080
- **Health Check**: http://localhost:8080/health
- **API Documentation**: http://localhost:8080/docs (FastAPI auto-generated)
- **Alternative Docs**: http://localhost:8080/redoc

### MCP (Model Context Protocol) Servers

#### 🔍 Threat Intelligence Services
- **VirusTotal Server**: http://localhost:8001
  - **Health Check**: http://localhost:8001/health
  - **API Docs**: http://localhost:8001/docs
  - **Purpose**: IP/domain reputation lookups and malware analysis

- **CyberReason Server**: http://localhost:8003
  - **Health Check**: http://localhost:8003/health
  - **API Docs**: http://localhost:8003/docs
  - **Purpose**: Endpoint status and threat detection

- **Cloud IVX Server**: http://localhost:8005
  - **Health Check**: http://localhost:8005/health
  - **API Docs**: http://localhost:8005/docs
  - **Purpose**: Trellix threat intelligence integration

#### 🎫 IT Service Management
- **ServiceNow Server**: http://localhost:8002
  - **Health Check**: http://localhost:8002/health
  - **API Docs**: http://localhost:8002/docs
  - **Purpose**: Incident management and task automation

#### 🔧 Custom Integration
- **Custom REST Server**: http://localhost:8004
  - **Health Check**: http://localhost:8004/health
  - **API Docs**: http://localhost:8004/docs
  - **Purpose**: Generic REST API wrapper for custom integrations

### 📊 Monitoring and Metrics
- **Prometheus Metrics**: http://localhost:9090
  - **Purpose**: System and application metrics collection
  - **Note**: Optional service, may not be running in all deployments

### 🌐 Nginx Reverse Proxy (Production)
- **Main Proxy**: http://localhost (port 80)
- **SSL Proxy**: https://localhost (port 443, if configured)
- **Health Check**: http://localhost/health

## 🔄 XDR Poller Service

### Overview
The XDR (Extended Detection and Response) Poller is a background service that continuously monitors and collects security events from various sources.

### Key Features
- **Continuous Monitoring**: Runs 24/7 to collect security alerts and events
- **Multi-Source Integration**: Pulls data from XDR platforms, SIEM systems, and threat intelligence feeds
- **Automated Processing**: Processes and enriches security events automatically
- **Configurable Intervals**: Adjustable polling frequency (default: 30 seconds)
- **Batch Processing**: Handles large volumes of alerts efficiently

### Configuration
- **Default Poll Interval**: 30 seconds
- **Maximum Alerts per Poll**: 100
- **Processing Batch Size**: 50
- **Retention Period**: 90 days
- **Retry Logic**: Up to 3 attempts per failed operation

### Access Points
- **Service Status**: Check via main web application health endpoint
- **Logs**: Available in `/app/logs/xdr_poller.log`
- **Configuration**: Managed through web interface settings

### Data Flow
1. **Polling**: Connects to configured XDR sources
2. **Collection**: Retrieves new alerts and events
3. **Enrichment**: Adds context and threat intelligence
4. **Storage**: Saves to Neo4j graph database
5. **Notification**: Triggers automated responses if configured

## 🗄️ Database Access

### Neo4j Graph Database
- **HTTP Interface**: http://localhost:7474
- **Bolt Protocol**: localhost:7687 (internal container access)
- **Authentication**: neo4j / devpassword123 (development)
- **Browser Access**: http://localhost:7474/browser

### Redis Cache
- **Connection**: localhost:6379
- **Purpose**: Session storage and temporary data caching

## 🔧 Development vs Production

### Development Environment
- All services run on `localhost` with individual ports
- Full debugging and logging enabled
- Hot reload for code changes
- Direct database access for development

### Production Environment
- Services behind Nginx reverse proxy
- SSL/TLS encryption enabled
- Optimized performance settings
- Restricted database access

## 📋 Service Health Checks

All services provide health check endpoints:
- Format: `http://localhost:{PORT}/health`
- Response: `{"status": "healthy", "service": "service-name", "version": "1.0.0"}`

### Quick Health Check Commands
```bash
# Check all services
curl -s http://localhost:8080/health
curl -s http://localhost:8001/health
curl -s http://localhost:8002/health
curl -s http://localhost:8003/health
curl -s http://localhost:8004/health
curl -s http://localhost:8005/health
```

## 🚀 Quick Start Commands

### Start Development Environment
```bash
cd deployment
docker-compose -f docker-compose.dev.yml up -d
```

### Check Service Status
```bash
docker-compose -f docker-compose.dev.yml ps
```

### View Logs
```bash
# All services
docker-compose -f docker-compose.dev.yml logs -f

# Specific service
docker-compose -f docker-compose.dev.yml logs -f web-app
```

### Stop Services
```bash
docker-compose -f docker-compose.dev.yml down
```

## 📞 Support and Troubleshooting

### Common Issues
1. **Port Conflicts**: Ensure ports 8001-8005, 8080, 7474, 7687 are available
2. **Database Connection**: Check Neo4j container is healthy
3. **Environment Variables**: Verify `.env.development` file is properly configured
4. **Google Cloud**: Ensure Vertex AI is enabled and credentials are valid

### Log Locations
- **Web Application**: `/app/logs/web_app.log`
- **MCP Servers**: `/app/logs/mcp_servers.log`
- **XDR Poller**: `/app/logs/xdr_poller.log`
- **Neo4j**: Container logs via `docker logs aisoar-neo4j-dev`

---

**Last Updated**: September 17, 2025
**Platform Version**: 1.0.0
**Environment**: Development</content>
<parameter name="filePath">/Users/raman.garg/official/projects/ai/AI-Driven-Cybersecurity-Automation-Platform/secure-server/SERVICE_URLS_REFERENCE.md
