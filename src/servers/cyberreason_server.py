from typing import Any, Dict, Optional

import uvicorn
from fastapi import FastAPI, Header, HTTPException
from pydantic import BaseModel

app = FastAPI(title="CyberReason MCP Server", version="1.0.0")


class GetPylumIdRequest(BaseModel):
    hostname: Optional[str] = None
    sensor_id: Optional[str] = None


class CheckTerminalStatusRequest(BaseModel):
    hostname: Optional[str] = None
    pylum_id: Optional[str] = None


class MCPResponse(BaseModel):
    success: bool
    data: Optional[Dict[str, Any]] = None
    error: Optional[str] = None


# Mock CyberReason data
MOCK_ENDPOINTS = {
    "workstation-01": {
        "hostname": "workstation-01",
        "pylum_id": "PYL_12345678",
        "sensor_id": "SEN_87654321",
        "status": "compromised",
        "threat_level": "high",
        "last_seen": "2024-01-20T10:30:00Z",
        "os": "Windows 10",
        "ip_address": "192.168.1.100",
        "malops": [
            {
                "malop_id": "MALOP_001",
                "type": "malware",
                "severity": "high",
                "detected_at": "2024-01-20T10:25:00Z",
            }
        ],
    },
    "server-02": {
        "hostname": "server-02",
        "pylum_id": "PYL_87654321",
        "sensor_id": "SEN_12345678",
        "status": "clean",
        "threat_level": "low",
        "last_seen": "2024-01-20T10:35:00Z",
        "os": "Ubuntu 20.04",
        "ip_address": "192.168.1.50",
        "malops": [],
    },
}


@app.get("/meta")
async def get_metadata():
    """Get server metadata and capabilities"""
    return {
        "server_name": "cyberreason",
        "version": "1.0.0",
        "capabilities": ["get_pylum_id", "check_terminal_status"],
        "description": "CyberReason endpoint detection and response platform",
        "authentication_required": True,
        "endpoints": {
            "get_pylum_id": {
                "method": "POST",
                "parameters": {
                    "hostname": "string (optional)",
                    "sensor_id": "string (optional)",
                },
                "description": "Get Pylum ID for a hostname or sensor",
            },
            "check_terminal_status": {
                "method": "POST",
                "parameters": {
                    "hostname": "string (optional)",
                    "pylum_id": "string (optional)",
                },
                "description": "Check if terminal/endpoint is compromised",
            },
        },
    }


@app.post("/get_pylum_id", response_model=MCPResponse)
async def get_pylum_id(
    request: GetPylumIdRequest, authorization: Optional[str] = Header(None)
):
    """Get Pylum ID based on hostname or sensor ID"""

    if not authorization:
        raise HTTPException(status_code=401, detail="Authorization token required")

    try:
        hostname = request.hostname
        sensor_id = request.sensor_id

        # Search by hostname first
        if hostname:
            for endpoint_data in MOCK_ENDPOINTS.values():
                if endpoint_data["hostname"] == hostname:
                    return MCPResponse(
                        success=True,
                        data={
                            "hostname": hostname,
                            "pylum_id": endpoint_data["pylum_id"],
                            "sensor_id": endpoint_data["sensor_id"],
                        },
                    )

        # Search by sensor_id
        if sensor_id:
            for endpoint_data in MOCK_ENDPOINTS.values():
                if endpoint_data["sensor_id"] == sensor_id:
                    return MCPResponse(
                        success=True,
                        data={
                            "hostname": endpoint_data["hostname"],
                            "pylum_id": endpoint_data["pylum_id"],
                            "sensor_id": sensor_id,
                        },
                    )

        return MCPResponse(success=False, error="Endpoint not found")

    except Exception as e:
        return MCPResponse(success=False, error=str(e))


@app.post("/check_terminal_status", response_model=MCPResponse)
async def check_terminal_status(
    request: CheckTerminalStatusRequest, authorization: Optional[str] = Header(None)
):
    """Check terminal/endpoint status for compromise indicators"""

    if not authorization:
        raise HTTPException(status_code=401, detail="Authorization token required")

    try:
        hostname = request.hostname
        pylum_id = request.pylum_id

        endpoint_data = None

        # Search by hostname
        if hostname and hostname in MOCK_ENDPOINTS:
            endpoint_data = MOCK_ENDPOINTS[hostname]

        # Search by pylum_id
        elif pylum_id:
            for data in MOCK_ENDPOINTS.values():
                if data["pylum_id"] == pylum_id:
                    endpoint_data = data
                    break

        if not endpoint_data:
            return MCPResponse(success=False, error="Endpoint not found")

        # Return comprehensive status
        status_report = {
            "hostname": endpoint_data["hostname"],
            "pylum_id": endpoint_data["pylum_id"],
            "status": endpoint_data["status"],
            "threat_level": endpoint_data["threat_level"],
            "last_seen": endpoint_data["last_seen"],
            "os": endpoint_data["os"],
            "ip_address": endpoint_data["ip_address"],
            "malops_count": len(endpoint_data["malops"]),
            "malops": endpoint_data["malops"],
            "is_compromised": endpoint_data["status"] == "compromised",
        }

        return MCPResponse(success=True, data=status_report)

    except Exception as e:
        return MCPResponse(success=False, error=str(e))


if __name__ == "__main__":
    uvicorn.run(app, host="0.0.0.0", port=8003)
