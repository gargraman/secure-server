import ast
import datetime
import json
import logging
import os
import uuid
from typing import Any, Dict, Optional

import requests
import uvicorn
from fastapi import FastAPI, Header, HTTPException
from pydantic import BaseModel
from requests.auth import HTTPBasicAuth
from requests.exceptions import RequestException

# Configure logging
logging.basicConfig(
    level=logging.INFO, format="%(asctime)s - %(name)s - %(levelname)s - %(message)s"
)
logger = logging.getLogger(__name__)

app = FastAPI(title="ServiceNow MCP Server", version="1.0.0")


class CreateRecordRequest(BaseModel):
    table_name: str = "incident"
    short_description: str
    description: Optional[str] = None
    severity: Optional[str] = None
    priority: Optional[str] = None
    assigned_to: Optional[str] = None
    comments: Optional[str] = None
    active: Optional[bool] = True
    additional_assignee_list: Optional[str] = None
    fields: Optional[str] = None  # JSON string for additional fields
    custom_fields: Optional[str] = None  # JSON string for custom fields
    enable_raw_json: Optional[bool] = False


class UpdateRecordRequest(BaseModel):
    table_name: str
    sys_id: str
    short_description: Optional[str] = None
    description: Optional[str] = None
    severity: Optional[str] = None
    priority: Optional[str] = None
    assigned_to: Optional[str] = None
    state: Optional[str] = None
    comments: Optional[str] = None
    active: Optional[bool] = None
    additional_assignee_list: Optional[str] = None
    fields: Optional[str] = None  # JSON string for additional fields
    custom_fields: Optional[str] = None  # JSON string for custom fields
    enable_raw_json: Optional[bool] = False


class DeleteRecordRequest(BaseModel):
    table_name: str
    sys_id: str


class RetrieveRecordRequest(BaseModel):
    table_name: str
    sys_id: str
    display_value: Optional[bool] = False
    fields: Optional[str] = None
    enable_raw_json: Optional[bool] = False


class GetRecordRequest(BaseModel):
    record_id: str


class MCPResponse(BaseModel):
    success: bool
    data: Optional[Dict[str, Any]] = None
    error: Optional[str] = None
    response_code: Optional[int] = None
    task_success: Optional[bool] = None
    status_msg: Optional[str] = None
    raw_json: Optional[str] = None
    query_results: Optional[Dict[str, Any]] = None


# ServiceNow configuration from environment variables
SERVICENOW_INSTANCE = os.getenv(
    "SERVICENOW_INSTANCE", "https://dev123456.service-now.com"
)
SERVICENOW_USERNAME = os.getenv("SERVICENOW_USERNAME", "admin")
SERVICENOW_PASSWORD = os.getenv("SERVICENOW_PASSWORD", "admin")


# ServiceNow API configuration
class ServiceNowClient:
    def __init__(self, instance_url: str, username: str, password: str):
        self.instance_url = instance_url.rstrip("/")
        self.auth = HTTPBasicAuth(username, password)
        self.headers = {
            "Content-Type": "application/json",
            "Accept": "application/json",
        }
        self.session = requests.Session()
        self.session.auth = self.auth
        self.session.headers.update(self.headers)

    def _make_table_url(self, table_name: str, sys_id: str = "") -> str:
        """Build ServiceNow table API URL"""
        table_api = "/api/now/table/"
        if sys_id:
            return f"{self.instance_url}{table_api}{table_name}/{sys_id}"
        return f"{self.instance_url}{table_api}{table_name}"

    def _validate_table_name(self, table_name: str) -> str:
        """Validate table name doesn't contain spaces"""
        if " " in table_name.strip():
            raise ValueError(
                "Invalid table name. Table name should not have spaces. "
                "Use actual table names (e.g., 'incident', 'cmdb_ci_web_service')"
            )
        return table_name.strip()

    def _parse_custom_fields(self, custom_fields_str: str) -> dict:
        """Parse custom fields JSON string"""
        if not custom_fields_str:
            return {}
        try:
            return json.loads(custom_fields_str)
        except json.JSONDecodeError as e:
            raise ValueError(f"Invalid custom fields JSON: {e}")

    def _get_fields(self, fields_str: str) -> tuple:
        """Parse fields JSON string"""
        fields_dict = {}
        valid_json = True
        if fields_str:
            try:
                fields_dict = ast.literal_eval(str(fields_str))
            except Exception:
                fields_dict = {}
                valid_json = False
        return (fields_dict, valid_json)

    def _get_custom_fields(self, custom_fields_str: str) -> tuple:
        """Parse custom fields JSON string"""
        custom_fields_dict = {}
        valid_json = True
        if custom_fields_str:
            try:
                custom_fields_dict = ast.literal_eval(str(custom_fields_str))
            except Exception:
                custom_fields_dict = {}
                valid_json = False
        return (custom_fields_dict, valid_json)


# Initialize ServiceNow client
servicenow_client = ServiceNowClient(
    SERVICENOW_INSTANCE, SERVICENOW_USERNAME, SERVICENOW_PASSWORD
)


@app.get("/meta")
async def get_metadata():
    """Get server metadata and capabilities"""
    logger.info("Fetching ServiceNow server metadata and capabilities")
    metadata = {
        "server_name": "servicenow",
        "version": "1.0.0",
        "capabilities": [
            "create_record",
            "get_record",
            "update_record",
            "delete_record",
            "retrieve_record",
        ],
        "description": "ServiceNow ITSM integration for incident and task management",
        "authentication_required": True,
        "endpoints": {
            "create_record": {
                "method": "POST",
                "parameters": {
                    "table_name": "string (default: incident)",
                    "short_description": "string",
                    "description": "string (optional)",
                    "severity": "string (1-4, optional)",
                    "priority": "string (1-5, optional)",
                    "assigned_to": "string (optional)",
                    "comments": "string (optional)",
                    "active": "boolean (optional)",
                    "additional_assignee_list": "string (optional)",
                    "fields": "JSON string (optional)",
                    "custom_fields": "JSON string (optional)",
                    "enable_raw_json": "boolean (optional)",
                },
                "description": "Create a new record in ServiceNow table",
            },
            "get_record": {
                "method": "POST",
                "parameters": {"record_id": "string"},
                "description": "Retrieve a record by ID",
            },
            "update_record": {
                "method": "POST",
                "parameters": {
                    "table_name": "string",
                    "sys_id": "string",
                    "short_description": "string (optional)",
                    "description": "string (optional)",
                    "severity": "string (1-4, optional)",
                    "priority": "string (1-5, optional)",
                    "assigned_to": "string (optional)",
                    "state": "string (optional)",
                    "comments": "string (optional)",
                    "active": "boolean (optional)",
                    "additional_assignee_list": "string (optional)",
                    "fields": "JSON string (optional)",
                    "custom_fields": "JSON string (optional)",
                    "enable_raw_json": "boolean (optional)",
                },
                "description": "Update an existing record",
            },
            "delete_record": {
                "method": "POST",
                "parameters": {"table_name": "string", "sys_id": "string"},
                "description": "Delete a record by sys_id",
            },
            "retrieve_record": {
                "method": "POST",
                "parameters": {
                    "table_name": "string",
                    "sys_id": "string",
                    "display_value": "boolean (optional)",
                    "fields": "string (optional)",
                    "enable_raw_json": "boolean (optional)",
                },
                "description": "Retrieve a record with specific fields",
            },
        },
    }
    logger.debug("ServiceNow metadata: %s", metadata)
    return metadata


@app.post("/create_record", response_model=MCPResponse)
async def create_record(
    request: CreateRecordRequest, authorization: Optional[str] = Header(None)
):
    """Create a new ServiceNow record"""
    logger.info("Creating new ServiceNow record of type: %s", request.table_name)
    logger.debug("Create record request: %s", request)

    if not authorization:
        logger.warning("Authorization required but not provided")
        raise HTTPException(status_code=401, detail="Authorization required")

    try:
        # Validate table name
        table_name = servicenow_client._validate_table_name(request.table_name)

        # Build request data
        query_dict = {
            "short_description": request.short_description,
            "description": request.description,
            "severity": request.severity,
            "priority": request.priority,
            "assigned_to": request.assigned_to,
            "comments": request.comments,
            "active": request.active,
            "additional_assignee_list": request.additional_assignee_list,
        }

        # Remove None values
        query_dict = {k: v for k, v in query_dict.items() if v is not None}

        # Parse fields and custom fields
        fields_dict, valid_fields_dict = servicenow_client._get_fields(request.fields)
        (
            custom_fields_dict,
            valid_custom_fields_dict,
        ) = servicenow_client._get_custom_fields(request.custom_fields)

        if not valid_fields_dict or not valid_custom_fields_dict:
            error_msg = ""
            if not valid_fields_dict and not valid_custom_fields_dict:
                error_msg = "fields and custom_fields are not valid JSON strings"
            elif not valid_fields_dict:
                error_msg = "fields is not a valid JSON string"
            else:
                error_msg = "custom_fields is not a valid JSON string"

            return MCPResponse(
                success=False, error=error_msg, task_success=False, status_msg=error_msg
            )

        # Combine all data
        data_dict = {}
        data_dict.update(query_dict)
        data_dict.update(fields_dict)
        data_dict.update(custom_fields_dict)
        data = json.dumps(data_dict)

        # Make API call
        req_url = servicenow_client._make_table_url(table_name)

        response = servicenow_client.session.post(url=req_url, data=data)

        # Process response
        try:
            raw_json = response.json()
            raw_json_str = json.dumps(raw_json)
        except Exception:
            failure_msg = (
                f"Invalid response content: [{response.status_code}] {response.reason}"
            )
            return MCPResponse(
                success=False,
                error=failure_msg,
                task_success=False,
                status_msg=failure_msg,
                response_code=response.status_code,
            )

        # Transform response for query_results
        query_results = {}
        if "result" in raw_json:
            query_results = raw_json["result"]

        response_data = {
            "message": "Successfully created new record in the specified table",
            "sys_id": query_results.get("sys_id")
            if isinstance(query_results, dict)
            else None,
        }

        return MCPResponse(
            success=True,
            data=response_data,
            task_success=True,
            status_msg="Successfully created new record in the specified table",
            response_code=response.status_code,
            raw_json=raw_json_str if request.enable_raw_json else None,
            query_results=query_results if isinstance(query_results, dict) else {},
        )

    except Exception as e:
        error_msg = f"Failed to create ServiceNow record: {str(e)}"
        return MCPResponse(
            success=False, error=error_msg, task_success=False, status_msg=error_msg
        )


@app.post("/get_record", response_model=MCPResponse)
async def get_record(
    request: GetRecordRequest, authorization: Optional[str] = Header(None)
):
    """Get a ServiceNow record by ID"""

    if not authorization:
        raise HTTPException(status_code=401, detail="Authorization required")

    # For now, we'll treat record_id as sys_id and use the retrieve_record functionality
    # In a more complete implementation, we might need to search for records by different IDs
    try:
        # This is a simplified implementation - in a real scenario, you might need to
        # search across different tables or use a different identifier mapping
        return MCPResponse(
            success=False,
            error="Get record by ID not fully implemented. Use retrieve_record with sys_id and table_name instead.",
            task_success=False,
            status_msg="Get record by ID not fully implemented. Use retrieve_record with sys_id and table_name instead.",
        )

    except Exception as e:
        error_msg = f"Failed to get ServiceNow record: {str(e)}"
        return MCPResponse(
            success=False, error=error_msg, task_success=False, status_msg=error_msg
        )


@app.post("/update_record", response_model=MCPResponse)
async def update_record(
    request: UpdateRecordRequest, authorization: Optional[str] = Header(None)
):
    """Update an existing ServiceNow record"""

    if not authorization:
        raise HTTPException(status_code=401, detail="Authorization required")

    try:
        # Validate table name
        table_name = servicenow_client._validate_table_name(request.table_name)
        sys_id = request.sys_id

        # Build request data
        query_dict = {
            "short_description": request.short_description,
            "description": request.description,
            "severity": request.severity,
            "priority": request.priority,
            "assigned_to": request.assigned_to,
            "state": request.state,
            "comments": request.comments,
            "active": request.active,
            "additional_assignee_list": request.additional_assignee_list,
        }

        # Remove None values
        query_dict = {k: v for k, v in query_dict.items() if v is not None}

        # Parse fields and custom fields
        fields_dict, valid_fields_dict = servicenow_client._get_fields(request.fields)
        (
            custom_fields_dict,
            valid_custom_fields_dict,
        ) = servicenow_client._get_custom_fields(request.custom_fields)

        if not valid_fields_dict or not valid_custom_fields_dict:
            error_msg = ""
            if not valid_fields_dict and not valid_custom_fields_dict:
                error_msg = "fields and custom_fields are not valid JSON strings"
            elif not valid_fields_dict:
                error_msg = "fields is not a valid JSON string"
            else:
                error_msg = "custom_fields is not a valid JSON string"

            return MCPResponse(
                success=False, error=error_msg, task_success=False, status_msg=error_msg
            )

        # Combine all data
        data_dict = {}
        data_dict.update(query_dict)
        data_dict.update(fields_dict)
        data_dict.update(custom_fields_dict)
        data = json.dumps(data_dict)

        # Make API call (PATCH request)
        req_url = servicenow_client._make_table_url(table_name, sys_id)

        response = servicenow_client.session.patch(url=req_url, data=data)

        # Process response
        try:
            raw_json = response.json()
            raw_json_str = json.dumps(raw_json)
        except Exception:
            failure_msg = (
                f"Invalid response content: [{response.status_code}] {response.reason}"
            )
            return MCPResponse(
                success=False,
                error=failure_msg,
                task_success=False,
                status_msg=failure_msg,
                response_code=response.status_code,
            )

        # Transform response for query_results
        query_results = {}
        if "result" in raw_json:
            query_results = raw_json["result"]

        response_data = {
            "message": f"Successfully updated {sys_id} record in the specified table",
            "sys_id": sys_id,
        }

        return MCPResponse(
            success=True,
            data=response_data,
            task_success=True,
            status_msg=f"Successfully updated {sys_id} record in the specified table",
            response_code=response.status_code,
            raw_json=raw_json_str if request.enable_raw_json else None,
            query_results=query_results if isinstance(query_results, dict) else {},
        )

    except Exception as e:
        error_msg = f"Failed to update ServiceNow record: {str(e)}"
        return MCPResponse(
            success=False, error=error_msg, task_success=False, status_msg=error_msg
        )


@app.post("/delete_record", response_model=MCPResponse)
async def delete_record(
    request: DeleteRecordRequest, authorization: Optional[str] = Header(None)
):
    """Delete a ServiceNow record"""

    if not authorization:
        raise HTTPException(status_code=401, detail="Authorization required")

    try:
        # Validate table name
        table_name = servicenow_client._validate_table_name(request.table_name)
        sys_id = request.sys_id

        # Make API call (DELETE request)
        req_url = servicenow_client._make_table_url(table_name, sys_id)

        response = servicenow_client.session.delete(url=req_url)

        response_data = {
            "message": f"Successfully deleted {sys_id} record in the specified table"
        }

        return MCPResponse(
            success=True,
            data=response_data,
            task_success=True,
            status_msg=f"Successfully deleted {sys_id} record in the specified table",
            response_code=response.status_code,
        )

    except Exception as e:
        error_msg = f"Failed to delete ServiceNow record: {str(e)}"
        return MCPResponse(
            success=False, error=error_msg, task_success=False, status_msg=error_msg
        )


@app.post("/retrieve_record", response_model=MCPResponse)
async def retrieve_record(
    request: RetrieveRecordRequest, authorization: Optional[str] = Header(None)
):
    """Retrieve a specific ServiceNow record with optional field filtering"""

    if not authorization:
        raise HTTPException(status_code=401, detail="Authorization required")

    try:
        # Validate table name
        table_name = servicenow_client._validate_table_name(request.table_name)
        sys_id = request.sys_id

        # Build query parameters
        query_dict = {
            "sysparm_display_value": str(request.display_value).lower()
            if request.display_value is not None
            else None,
            "sysparm_fields": request.fields,
        }

        # Remove None values
        query_dict = {k: v for k, v in query_dict.items() if v is not None}

        # Make API call (GET request)
        req_url = servicenow_client._make_table_url(table_name, sys_id)

        response = servicenow_client.session.get(url=req_url, params=query_dict)

        # Process response
        try:
            raw_json = response.json()
            raw_json_str = json.dumps(raw_json)
        except Exception:
            failure_msg = (
                f"Invalid response content: [{response.status_code}] {response.reason}"
            )
            return MCPResponse(
                success=False,
                error=failure_msg,
                task_success=False,
                status_msg=failure_msg,
                response_code=response.status_code,
            )

        # Transform response for query_results
        query_results = {}
        if "result" in raw_json:
            query_results = raw_json["result"]

        return MCPResponse(
            success=True,
            data=query_results if isinstance(query_results, dict) else {},
            task_success=True,
            status_msg=f"Successfully retrieved {sys_id} record in the specified table",
            response_code=response.status_code,
            raw_json=raw_json_str if request.enable_raw_json else None,
            query_results=query_results if isinstance(query_results, dict) else {},
        )

    except Exception as e:
        error_msg = f"Failed to retrieve ServiceNow record: {str(e)}"
        return MCPResponse(
            success=False, error=error_msg, task_success=False, status_msg=error_msg
        )


# This endpoint has been removed as we're now using the actual ServiceNow API
# instead of local storage

if __name__ == "__main__":
    uvicorn.run(app, host="0.0.0.0", port=8002)
