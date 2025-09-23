# AI-SOAR Platform Frontend-Backend Integration Deployment Guide

## Overview

This document provides comprehensive deployment instructions ensuring proper frontend-backend integration for the AI-SOAR Cybersecurity Automation Platform across local development and Google Cloud production environments.

## 🛠 Recent Fixes Applied

### Critical Issues Resolved:

1. **Fixed Static File Serving Paths**
   - Updated FastAPI app to use absolute paths for Docker compatibility
   - Fixed Docker volume mounts in `docker-compose.yml`
   - Updated Nginx static file serving configuration

2. **Added Missing Frontend Routes**
   - Added route handlers for `/alerts`, `/incidents`, `/threats`, `/investigations`, `/graph`
   - Implemented proper template rendering for all navigation menu items

3. **Implemented WebSocket Support**
   - Added WebSocketManager class for real-time updates
   - Configured WebSocket endpoint at `/ws`
   - Updated Nginx for WebSocket proxy support

4. **Enhanced Production Deployment**
   - Updated Cloud Build configuration with proper environment variables
   - Created Cloud Run configuration with WebSocket support
   - Added comprehensive deployment testing script

## 📁 Project Structure

```
secure-server/
├── src/web/
│   ├── app.py              # FastAPI application with WebSocket support
│   ├── static/             # CSS, JS, and assets
│   │   ├── css/
│   │   │   ├── dashboard.css
│   │   │   ├── security-theme.css
│   │   │   └── graph-visualization.css
│   │   └── js/
│   │       ├── common.js
│   │       ├── dashboard.js
│   │       ├── alerts-management.js
│   │       ├── incidents-management.js
│   │       ├── graph-visualization.js
│   │       └── security-operations.js
│   └── templates/          # Jinja2 templates
│       ├── base.html       # Enhanced with CDN libraries
│       ├── dashboard.html
│       ├── alerts.html
│       ├── incidents.html
│       └── config.html
├── deployment/
│   ├── docker-compose.yml         # Production deployment
│   ├── docker-compose.dev.yml     # Development with Neo4j/Redis
│   ├── Dockerfile                 # Multi-stage build
│   ├── nginx/
│   │   ├── nginx.conf             # Enhanced with WebSocket support
│   │   └── proxy_params
│   ├── gcp/
│   │   └── cloud-run-config.yaml  # Google Cloud Run configuration
│   └── scripts/
│       └── test-deployment.sh     # Comprehensive deployment testing
└── cloudbuild.yaml               # Google Cloud Build configuration
```

## 🚀 Local Development Deployment

### Prerequisites

- Docker and Docker Compose installed
- Python 3.11+
- Node.js (for frontend dependencies, optional)

### Quick Start

```bash
# Clone and navigate to project
cd /path/to/AI-Driven-Cybersecurity-Automation-Platform/secure-server

# Start development environment with all services
cd deployment
docker-compose -f docker-compose.dev.yml up -d

# Wait for services to start (about 60 seconds)
# Access the application at http://localhost:8080
```

### Development Services

| Service | URL | Description |
|---------|-----|-------------|
| Web App | http://localhost:8080 | Main application with enhanced UI |
| API Docs | http://localhost:8080/docs | Interactive API documentation |
| Neo4j Browser | http://localhost:7474 | Graph database interface |
| Redis | localhost:6379 | Cache service |
| MCP Servers | localhost:8001-8005 | Security service integrations |

### Frontend Development Features

- **Real-time Dashboard**: WebSocket-powered live updates
- **Enhanced UI**: Professional security-focused design
- **Graph Visualization**: Cytoscape.js integration for threat correlation
- **Mobile Responsive**: Bootstrap 5 with accessibility support
- **CDN Integration**: Chart.js, D3.js, DataTables for rich data presentation

### Test Local Deployment

```bash
# Run comprehensive deployment tests
cd deployment
./scripts/test-deployment.sh --mode local --verbose

# Test specific components
curl http://localhost:8080/health          # Health check
curl http://localhost:8080/meta            # Service metadata
curl http://localhost:8080/static/css/dashboard.css  # Static files
```

## 🌐 Production Deployment

### Docker Compose Production

```bash
# Production deployment with Nginx proxy
cd deployment
docker-compose up -d

# Access through Nginx proxy
# Web App: http://localhost (port 80)
# HTTPS: http://localhost (port 443, with SSL certificates)
```

### Production Services Architecture

```
Internet → Nginx (Port 80/443) → Web App (Port 8080)
                               → MCP Servers (Ports 8001-8005)
```

### Nginx Configuration Features

- **Static File Caching**: 1-year cache for immutable assets
- **CORS Support**: Proper cross-origin headers for CDN resources
- **WebSocket Proxy**: Persistent connection support for real-time features
- **Rate Limiting**: API protection with zone-based limits
- **Security Headers**: XSS, clickjacking, and content-type protection
- **Health Check Optimization**: Separate high-frequency health endpoints

### Test Production Deployment

```bash
# Test production deployment
./scripts/test-deployment.sh --mode production --timeout 180

# Verify services are running
docker-compose ps
curl http://localhost/health
curl http://localhost/static/css/dashboard.css
```

## ☁️ Google Cloud Deployment

### Cloud Run Deployment

The platform is optimized for Google Cloud Run with full frontend-backend integration:

#### Prerequisites

1. **Google Cloud Project Setup**:
   ```bash
   gcloud config set project YOUR_PROJECT_ID
   gcloud services enable cloudbuild.googleapis.com
   gcloud services enable run.googleapis.com
   gcloud services enable containerregistry.googleapis.com
   ```

2. **Service Account Configuration**:
   ```bash
   # Create service account
   gcloud iam service-accounts create aisoar-service-account

   # Grant required permissions
   gcloud projects add-iam-policy-binding YOUR_PROJECT_ID \
       --member="serviceAccount:aisoar-service-account@YOUR_PROJECT_ID.iam.gserviceaccount.com" \
       --role="roles/cloudsql.client"
   ```

#### Deployment Process

```bash
# Deploy using Cloud Build
gcloud builds submit --config cloudbuild.yaml .

# Manual Cloud Run deployment (alternative)
cd deployment
docker build --target production -t gcr.io/YOUR_PROJECT_ID/ai-soar-platform:latest -f Dockerfile ..
docker push gcr.io/YOUR_PROJECT_ID/ai-soar-platform:latest

gcloud run deploy ai-soar-platform \
    --image gcr.io/YOUR_PROJECT_ID/ai-soar-platform:latest \
    --region us-central1 \
    --allow-unauthenticated \
    --memory 4Gi \
    --cpu 2 \
    --max-instances 10 \
    --port 8080
```

#### Cloud Run Configuration Features

- **WebSocket Support**: Session affinity enabled for persistent connections
- **Static File Serving**: Direct serving from container with proper caching
- **Health Checks**: Startup, liveness, and readiness probes configured
- **Auto-scaling**: 1-10 instances based on traffic
- **VPC Integration**: Private network access for security services
- **Secret Management**: Neo4j credentials and API keys via Secret Manager

#### Environment Variables

```bash
ENVIRONMENT=production
GOOGLE_CLOUD_PROJECT=your-project-id
VERTEX_AI_LOCATION=us-central1
VERTEX_AI_ENABLED=true
SECRET_MANAGER_ENABLED=true
WEBSOCKET_ENABLED=true
STATIC_FILES_ENABLED=true
NEO4J_URI=neo4j+s://your-auradb-instance.databases.neo4j.io
```

### Test Cloud Deployment

```bash
# Test cloud deployment configuration
./scripts/test-deployment.sh --mode cloud --verbose

# Test actual Cloud Run service
curl https://ai-soar-platform-YOUR_PROJECT_ID.a.run.app/health
curl https://ai-soar-platform-YOUR_PROJECT_ID.a.run.app/meta
curl https://ai-soar-platform-YOUR_PROJECT_ID.a.run.app/static/css/dashboard.css
```

## 🧪 Integration Testing

### Automated Testing

The deployment includes a comprehensive testing script that validates:

- **Service Health**: All endpoints respond correctly
- **Static File Serving**: CSS, JavaScript, and assets accessible
- **WebSocket Connectivity**: Real-time communication works
- **API Endpoints**: All REST API routes functional
- **Security**: Proper HTTPS, CORS, and security headers

### Manual Testing Checklist

#### Frontend Integration:
- [ ] Dashboard loads with all charts and visualizations
- [ ] Navigation menu works for all pages
- [ ] Static files (CSS, JS) load without errors
- [ ] WebSocket connection establishes successfully
- [ ] Real-time updates appear in dashboard
- [ ] Mobile responsive design works on different screen sizes
- [ ] Browser console shows no JavaScript errors

#### Backend Integration:
- [ ] All API endpoints return expected data structures
- [ ] Database connections established successfully
- [ ] MCP server integrations respond properly
- [ ] Error handling displays user-friendly messages
- [ ] Logging captures important events
- [ ] Performance metrics are within acceptable ranges

#### Security Integration:
- [ ] HTTPS enforced in production
- [ ] CORS headers properly configured
- [ ] XSS protection headers present
- [ ] Authentication/authorization works (when implemented)
- [ ] Rate limiting prevents abuse
- [ ] Input validation prevents injection attacks

## 🚨 Troubleshooting

### Common Issues and Solutions

#### 1. Static Files Not Loading

**Symptoms**: CSS/JS files return 404 or connection refused
**Solution**:
```bash
# Check FastAPI static file mount path
docker exec -it web-app ls -la /app/src/web/static/

# Verify Nginx volume mount
docker exec -it nginx-proxy ls -la /var/www/html/static/

# Check Nginx error logs
docker logs nginx-proxy
```

#### 2. WebSocket Connection Fails

**Symptoms**: Real-time updates don't work, console shows WebSocket errors
**Solution**:
```bash
# Test WebSocket endpoint directly
curl --include \
     --no-buffer \
     --header "Connection: Upgrade" \
     --header "Upgrade: websocket" \
     --header "Sec-WebSocket-Key: SGVsbG8sIHdvcmxkIQ==" \
     --header "Sec-WebSocket-Version: 13" \
     http://localhost:8080/ws

# Check WebSocket configuration in Nginx
docker exec -it nginx-proxy nginx -t
```

#### 3. Template Rendering Issues

**Symptoms**: Pages show raw template syntax or 500 errors
**Solution**:
```bash
# Check template directory mount
docker exec -it web-app ls -la /app/src/web/templates/

# Verify template syntax
python -m py_compile src/web/templates/base.html

# Check FastAPI logs
docker logs web-app
```

#### 4. Cloud Run Deployment Issues

**Symptoms**: Service fails to start or responds with errors
**Solution**:
```bash
# Check Cloud Run logs
gcloud run services logs read ai-soar-platform --region us-central1

# Verify service configuration
gcloud run services describe ai-soar-platform --region us-central1

# Test container locally
docker run -p 8080:8080 gcr.io/YOUR_PROJECT_ID/ai-soar-platform:latest
```

### Performance Optimization

#### Frontend Performance:
- **CDN Usage**: All major JavaScript libraries loaded from CDN
- **Static File Caching**: Long-term caching for immutable assets
- **Gzip Compression**: Enabled for all text-based resources
- **Lazy Loading**: Implemented for heavy graph visualizations
- **Bundle Optimization**: Minified CSS and JavaScript in production

#### Backend Performance:
- **Connection Pooling**: Neo4j connections reused efficiently
- **Query Optimization**: Cypher queries use proper indexes
- **Async Operations**: All I/O operations use async/await
- **Caching Strategy**: Redis integration for session and data caching
- **Auto-scaling**: Cloud Run scales based on actual demand

## 📊 Monitoring and Observability

### Health Monitoring

| Endpoint | Purpose | Expected Response |
|----------|---------|-------------------|
| `/health` | Basic service health | `{"status": "healthy"}` |
| `/readiness` | K8s readiness probe | Service dependencies ready |
| `/liveness` | K8s liveness probe | Service is responding |
| `/meta` | Service metadata | Configuration and version info |

### Logging Configuration

- **Local Development**: Console logging with DEBUG level
- **Production**: Google Cloud Logging with structured JSON
- **Error Tracking**: Automatic error aggregation and alerting
- **Performance Metrics**: Response time, throughput, and resource usage

### Real-time Monitoring

The enhanced dashboard provides:
- **System Health**: Live service status indicators
- **Alert Statistics**: Real-time threat detection metrics
- **Processing Metrics**: Alert processing performance
- **Connection Status**: Database and service connectivity
- **WebSocket Activity**: Real-time connection monitoring

## 🔄 Continuous Deployment

### CI/CD Pipeline

1. **Code Push**: Triggers Cloud Build automatically
2. **Security Scan**: Container vulnerability scanning
3. **Build**: Multi-stage Docker build with optimization
4. **Test**: Automated deployment testing
5. **Deploy**: Blue-green deployment to Cloud Run
6. **Verify**: Health checks and smoke tests
7. **Monitor**: Performance and error rate monitoring

### Rollback Strategy

```bash
# List previous revisions
gcloud run revisions list --service ai-soar-platform --region us-central1

# Rollback to previous revision
gcloud run services update-traffic ai-soar-platform \
    --to-revisions REVISION_NAME=100 \
    --region us-central1
```

## 📚 Additional Resources

### Documentation Links
- [FastAPI Documentation](https://fastapi.tiangolo.com/)
- [Google Cloud Run Documentation](https://cloud.google.com/run/docs)
- [Neo4j AuraDB Documentation](https://neo4j.com/docs/aura/)
- [Docker Compose Documentation](https://docs.docker.com/compose/)

### Code Examples
- WebSocket client implementation in `/static/js/common.js`
- API integration patterns in `/static/js/security-operations.js`
- Graph visualization setup in `/static/js/graph-visualization.js`

### Support Contacts
- Platform Architecture: See `../CLAUDE.md` for detailed technical specifications
- Deployment Issues: Check `deployment/scripts/test-deployment.sh` output
- Security Concerns: Review `DEPLOYMENT_SUMMARY.md` for security configurations

---

**Last Updated**: September 11, 2025
**Version**: 1.0.0
**Deployment Status**: ✅ Ready for Production
