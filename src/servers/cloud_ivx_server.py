import json
import uuid
from datetime import datetime
from typing import Any, Dict, List, Optional

import uvicorn
from fastapi import FastAPI, Header, HTTPException
from pydantic import BaseModel, field_validator

app = FastAPI(title="Trellix Cloud IVX MCP Server", version="1.1.0")


class LookupHashesRequest(BaseModel):
    hashes: List[str]
    enable_raw_json: Optional[bool] = False


class GetReportRequest(BaseModel):
    report_id: str
    include_all: Optional[bool] = False

    @field_validator("report_id")
    @classmethod
    def validate_report_id(cls, v):
        try:
            uuid.UUID(v)
            return v
        except ValueError:
            raise ValueError("Report ID must be a valid UUID")


class AnalyseUrlRequest(BaseModel):
    urls: List[str]

    @field_validator("urls")
    @classmethod
    def validate_urls(cls, v):
        if len(v) > 5:
            raise ValueError("Maximum of 5 URLs allowed")
        return v


class AnalyseFileRequest(BaseModel):
    file_ref: str


class MCPResponse(BaseModel):
    success: bool
    data: Optional[Dict[str, Any]] = None
    error: Optional[str] = None


# Mock data for demonstration
MOCK_HASH_DATABASE = {
    "5d41402abc4b2a76b9719d911017c592": {
        "hash": "5d41402abc4b2a76b9719d911017c592",
        "file_type": "executable",
        "verdict": "malicious",
        "confidence": "high",
        "threat_name": "Trojan.GenKD.12345",
        "analysis_date": "2024-01-20T09:15:00Z",
        "report_id": "550e8400-e29b-41d4-a716-446655440001",
    },
    "098f6bcd4621d373cade4e832627b4f6": {
        "hash": "098f6bcd4621d373cade4e832627b4f6",
        "file_type": "document",
        "verdict": "clean",
        "confidence": "high",
        "threat_name": None,
        "analysis_date": "2024-01-20T08:30:00Z",
        "report_id": "550e8400-e29b-41d4-a716-446655440002",
    },
}

MOCK_REPORTS = {
    "550e8400-e29b-41d4-a716-446655440001": {
        "report_id": "550e8400-e29b-41d4-a716-446655440001",
        "file_hash": "5d41402abc4b2a76b9719d911017c592",
        "file_name": "suspicious.exe",
        "file_size": 1024000,
        "verdict": "malicious",
        "confidence": "high",
        "threat_name": "Trojan.GenKD.12345",
        "analysis_start": "2024-01-20T09:10:00Z",
        "analysis_end": "2024-01-20T09:15:00Z",
        "sandbox_details": {
            "environment": "Windows 10 x64",
            "execution_time": 300,
            "network_connections": 5,
            "file_modifications": 12,
            "registry_changes": 8,
        },
        "iocs": [
            {"type": "ip", "value": "192.168.1.100", "category": "c2"},
            {"type": "domain", "value": "malicious-domain.com", "category": "c2"},
            {
                "type": "file",
                "value": "C:\\temp\\dropped.dll",
                "category": "dropped_file",
            },
        ],
    },
    "550e8400-e29b-41d4-a716-446655440002": {
        "report_id": "550e8400-e29b-41d4-a716-446655440002",
        "file_hash": "098f6bcd4621d373cade4e832627b4f6",
        "file_name": "document.pdf",
        "file_size": 256000,
        "verdict": "clean",
        "confidence": "high",
        "threat_name": None,
        "analysis_start": "2024-01-20T08:25:00Z",
        "analysis_end": "2024-01-20T08:30:00Z",
        "sandbox_details": {
            "environment": "Windows 10 x64",
            "execution_time": 30,
            "network_connections": 0,
            "file_modifications": 0,
            "registry_changes": 0,
        },
        "iocs": [],
    },
}


@app.get("/meta")
async def get_metadata():
    """Get server metadata and capabilities"""
    return {
        "server_name": "cloud_ivx",
        "version": "1.1.0",
        "capabilities": ["lookup_hashes", "get_report", "analyse_url", "analyse_file"],
        "description": "Trellix Cloud IVX malware analysis and threat intelligence platform",
        "authentication_required": True,
        "endpoints": {
            "lookup_hashes": {
                "method": "POST",
                "parameters": {
                    "hashes": "array of strings (required)",
                    "enable_raw_json": "boolean (optional, default: false)",
                },
                "description": "Retrieve malware analysis results based on provided hashes",
            },
            "get_report": {
                "method": "POST",
                "parameters": {
                    "report_id": "string UUID (required)",
                    "include_all": "boolean (optional, default: false)",
                },
                "description": "Retrieve detailed malware reports using specific report ID",
            },
            "analyse_url": {
                "method": "POST",
                "parameters": {"urls": "array of strings (required, max 5 URLs)"},
                "description": "Submit URLs for malware analysis",
            },
            "analyse_file": {
                "method": "POST",
                "parameters": {"file_ref": "string (required, file URL or UUID)"},
                "description": "Submit files for malware analysis",
            },
        },
    }


@app.post("/lookup_hashes", response_model=MCPResponse)
async def lookup_hashes(
    request: LookupHashesRequest, x_api_key: Optional[str] = Header(None)
):
    """Retrieve malware analysis results based on provided hashes"""

    if not x_api_key:
        raise HTTPException(status_code=401, detail="X-API-Key header required")

    try:
        hash_info = []
        raw_json = []

        for hash_value in request.hashes:
            # Validate hash format (simple check for common hash lengths)
            if len(hash_value) not in [32, 40, 64]:  # MD5, SHA1, SHA256
                continue

            if hash_value in MOCK_HASH_DATABASE:
                info = MOCK_HASH_DATABASE[hash_value].copy()
                hash_info.append(info)

                if request.enable_raw_json:
                    raw_json.append(info)
            else:
                # Unknown hash
                unknown_info = {
                    "hash": hash_value,
                    "verdict": "unknown",
                    "confidence": "low",
                    "threat_name": None,
                    "analysis_date": None,
                    "report_id": None,
                }
                hash_info.append(unknown_info)

                if request.enable_raw_json:
                    raw_json.append(unknown_info)

        response_data = {
            "hash_info": hash_info,
            "task_success": True,
            "status_msg": f"Successfully processed {len(request.hashes)} hashes",
            "response_code": 200,
        }

        if request.enable_raw_json:
            response_data["raw_json"] = raw_json

        return MCPResponse(success=True, data=response_data)

    except Exception as e:
        return MCPResponse(success=False, error=str(e))


@app.post("/get_report", response_model=MCPResponse)
async def get_report(
    request: GetReportRequest, x_api_key: Optional[str] = Header(None)
):
    """Retrieve detailed malware reports using specific report ID"""

    if not x_api_key:
        raise HTTPException(status_code=401, detail="X-API-Key header required")

    try:
        if request.report_id in MOCK_REPORTS:
            report = MOCK_REPORTS[request.report_id].copy()

            if not request.include_all:
                # Remove some detailed fields for basic report
                report.pop("sandbox_details", None)
                report.pop("iocs", None)

            response_data = {
                "report": report,
                "task_success": True,
                "status_msg": "Report retrieved successfully",
                "response_code": 200,
            }

            return MCPResponse(success=True, data=response_data)
        else:
            response_data = {
                "report": None,
                "task_success": False,
                "status_msg": "Report not found",
                "response_code": 404,
            }

            return MCPResponse(success=False, data=response_data)

    except Exception as e:
        return MCPResponse(success=False, error=str(e))


@app.post("/analyse_url", response_model=MCPResponse)
async def analyse_url(
    request: AnalyseUrlRequest, x_api_key: Optional[str] = Header(None)
):
    """Submit URLs for malware analysis"""

    if not x_api_key:
        raise HTTPException(status_code=401, detail="X-API-Key header required")

    try:
        # Generate mock report ID for the analysis
        report_id = str(uuid.uuid4())

        # Mock analysis response
        analysis_response = {
            "urls": request.urls,
            "report_id": report_id,
            "submission_time": datetime.now().isoformat() + "Z",
            "status": "submitted",
            "estimated_completion": "5-10 minutes",
            "analysis_environment": "Cloud Sandbox",
            "urls_submitted": len(request.urls),
        }

        response_data = {
            "response_json": analysis_response,
            "report_id": report_id,
            "task_success": True,
            "status_msg": f"Successfully submitted {len(request.urls)} URLs for analysis",
            "response_code": 200,
        }

        return MCPResponse(success=True, data=response_data)

    except Exception as e:
        return MCPResponse(success=False, error=str(e))


@app.post("/analyse_file", response_model=MCPResponse)
async def analyse_file(
    request: AnalyseFileRequest, x_api_key: Optional[str] = Header(None)
):
    """Submit files for malware analysis"""

    if not x_api_key:
        raise HTTPException(status_code=401, detail="X-API-Key header required")

    try:
        # Generate mock report ID for the analysis
        report_id = str(uuid.uuid4())

        # Determine if file_ref is URL or UUID
        is_uuid = False
        try:
            uuid.UUID(request.file_ref)
            is_uuid = True
        except ValueError:
            pass

        # Mock analysis response
        analysis_response = {
            "file_ref": request.file_ref,
            "file_type": "uuid" if is_uuid else "url",
            "report_id": report_id,
            "submission_time": datetime.now().isoformat() + "Z",
            "status": "submitted",
            "estimated_completion": "10-15 minutes",
            "analysis_environment": "Cloud Sandbox",
        }

        response_data = {
            "response_json": json.dumps(analysis_response),
            "report_id": report_id,
            "task_success": True,
            "status_msg": "File successfully submitted for analysis",
            "response_code": 200,
        }

        return MCPResponse(success=True, data=response_data)

    except Exception as e:
        return MCPResponse(success=False, error=str(e))


if __name__ == "__main__":
    uvicorn.run(app, host="0.0.0.0", port=8005)
