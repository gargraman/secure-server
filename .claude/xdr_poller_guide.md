# XDR Poller Implementation Guide

## Overview
The XDR Alert Poller is a standalone service that continuously polls the XDR Alert Management API for new security alerts. It's designed for production deployment with proper signal handling and graceful shutdown capabilities.

## Key Components

### 1. Main Poller Service (`xdr_poller.py`)
- **Standalone executable**: Can run independently of the web application
- **Signal handling**: Responds to SIGINT/SIGTERM for graceful shutdown
- **Development mode**: Handles dummy credentials gracefully for testing
- **Alert persistence**: Saves alerts as JSON files in `alerts/` directory
- **Duplicate prevention**: Tracks processed alert IDs to avoid reprocessing

### 2. XDR Alert Client (`src/client/xdr_alert_client.py`)
- **Async HTTP client**: Built with httpx for efficient API communication
- **Polling capabilities**: Real-time alert monitoring with configurable intervals
- **Callback system**: Supports multiple callbacks for new alert processing
- **Error handling**: Comprehensive error handling for API failures
- **Configuration**: Environment-based configuration with override options

### 3. XDR Client Implementation (`src/client/xdr/alerts/client.py`)
- **Full API coverage**: Supports all XDR Alert Management API endpoints
- **Pagination support**: Handles large alert datasets efficiently
- **Field selection**: Configurable field selection for optimized responses
- **Filtering**: Advanced filtering capabilities for targeted queries

## Configuration

### Environment Variables
```bash
# XDR API Configuration
XDR_BASE_URL="https://api.xdr.example.com"
XDR_AUTH_TOKEN="your-auth-token"

# Polling Configuration
XDR_POLL_INTERVAL=30
XDR_POLL_ENABLED=true
XDR_MAX_ALERTS_PER_POLL=100

# Development Mode
XDR_AUTH_TOKEN="dev-dummy-token"  # For development/testing
```

### Command Line Usage
```bash
# Basic polling with default settings
python xdr_poller.py

# Custom polling interval
python xdr_poller.py --interval 60

# Debug mode
python xdr_poller.py --debug

# Custom API endpoint
python xdr_poller.py --base-url "https://custom.xdr.api" --auth-token "token"
```

## Key Implementation Details

### 1. Alert Processing Flow
1. **Polling**: Service polls XDR API at configured intervals
2. **Deduplication**: Checks against `processed_alert_ids` set
3. **Callback execution**: Runs `handle_new_alerts()` for new alerts
4. **Persistence**: Saves alerts to `alerts/alert_{id}_{timestamp}.json`
5. **Logging**: Comprehensive logging of alert details and processing status

### 2. Development Mode Features
- **Graceful degradation**: Continues running with dummy credentials
- **API failure handling**: Expects 401 errors in development mode
- **No actual polling**: Runs service loop without making API calls

### 3. Production Considerations
- **Signal handling**: SIGINT/SIGTERM trigger graceful shutdown
- **Connection management**: Async context managers for proper cleanup
- **Error resilience**: Continues operation despite API errors
- **Resource management**: Bounded memory usage with processed ID tracking

### 4. Integration Points
- **MCP Client**: Can trigger MCP server processing for new alerts
- **Neo4j Storage**: Alerts can be stored in graph database for correlation
- **Web Dashboard**: Real-time display of polling status and alerts
- **File System**: JSON persistence for audit trails and debugging

## Troubleshooting

### Common Issues
1. **Authentication Failures**: Check XDR_AUTH_TOKEN in environment
2. **Network Connectivity**: Verify XDR_BASE_URL accessibility
3. **Rate Limiting**: Increase polling interval if hitting API limits
4. **Memory Usage**: Monitor processed_alert_ids set growth over time

### Debug Mode
```bash
python xdr_poller.py --debug
```
Enables detailed logging for:
- HTTP request/response details
- Alert processing steps
- Configuration validation
- Connection status
