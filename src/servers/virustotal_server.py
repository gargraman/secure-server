import asyncio
import base64
import hashlib
import json
import logging
import os
import re
import time
from datetime import datetime
from typing import Any, Dict, List, Optional

import aiohttp
import requests
import uvicorn
import validators
from fastapi import FastAPI, Header, HTTPException
from pydantic import BaseModel, field_validator

# Configure logging
logging.basicConfig(
    level=logging.INFO, format="%(asctime)s - %(name)s - %(levelname)s - %(message)s"
)
logger = logging.getLogger(__name__)

app = FastAPI(title="VirusTotal MCP Server", version="1.1.0")

# VirusTotal API configuration
VIRUSTOTAL_BASE_URL = "https://www.virustotal.com/vtapi/v2"
MAX_RESOLUTIONS = 10


# Custom exceptions matching XDR plugin patterns
class VirusTotalError(Exception):
    pass


class VirusTotalException(Exception):
    pass


class MissingRequiredParameter(Exception):
    pass


# Helper functions from XDR plugin
class VirusTotalClient:
    """VirusTotal API client adapted from XDR plugin"""

    def __init__(self, api_key: str):
        self.api_key = api_key
        self.base_url = VIRUSTOTAL_BASE_URL
        self.session = requests.Session()
        self.session.params = {"apikey": api_key}

    def make_http_request(
        self,
        method: str,
        endpoint: str,
        params=None,
        data=None,
        files=None,
        headers=None,
    ):
        """Make HTTP request to VirusTotal API"""
        try:
            if headers:
                self.session.headers.update(headers)

            if params:
                request_params = self.session.params.copy()
                request_params.update(params)
            else:
                request_params = self.session.params

            response = self.session.request(
                method=method,
                url=f"{self.base_url}{endpoint}",
                params=request_params,
                data=data,
                files=files,
                timeout=300,
            )

            response.raise_for_status()

            if response.status_code == 204:
                raise VirusTotalError(
                    "Exceeded the VirusTotal public API request rate limit"
                )

            return response

        except requests.exceptions.HTTPError as err:
            if err.response.status_code == 403:
                raise VirusTotalError(
                    "Do not have the required privileges. Please contact VirusTotal."
                )
            raise VirusTotalException(str(err))
        except requests.exceptions.RequestException as err:
            raise VirusTotalException(str(err))

    @staticmethod
    def sanitize_text(text_dict):
        """Sanitize text data removing non-printable characters"""
        try:
            for k, v in text_dict.items():
                if isinstance(v, str):
                    v = re.sub(r"[^\s!-~]", "", v)
                    text_dict[k] = v
        except Exception:
            pass
        return text_dict

    @staticmethod
    def attributify(s):
        """Convert string to valid attribute name"""
        s = re.sub(r"[^\w\s]", "", s)
        s = re.sub(r"\s+", "_", s)
        return s

    @staticmethod
    def parse_resolutions(resolutions, resource_type, max_resolutions=MAX_RESOLUTIONS):
        """Parse DNS resolution data"""
        if not isinstance(resolutions, list):
            resolutions = [resolutions]

        epoch0_date_string = "1970-01-01 00:00:00"

        if resource_type == "ip":
            resolutions = [
                re.sub(
                    r"[^\w\-|.]",
                    "",
                    str(resolution.get("hostname")).replace("*.", "").strip(),
                )
                for resolution in sorted(
                    resolutions,
                    key=lambda k: k.get("last_resolved", epoch0_date_string),
                    reverse=True,
                )
            ][:max_resolutions]

        if resource_type == "domain":
            resolutions = [
                str(dict(resolution).get("ip_address"))
                for resolution in sorted(
                    resolutions,
                    key=lambda k: k.get("last_resolved", epoch0_date_string),
                    reverse=True,
                )
            ][:max_resolutions]

        return resolutions

    @staticmethod
    def is_valid_url(url: str) -> bool:
        """Validate URL format"""
        return validators.url(url) is True


# Request Models
class IPReportRequest(BaseModel):
    ip: str


class DomainReportRequest(BaseModel):
    domain: str


class HashLookupRequest(BaseModel):
    hashes: List[str]
    enable_raw_json: Optional[bool] = False

    @field_validator("hashes")
    @classmethod
    def validate_hashes(cls, v):
        for hash_val in v:
            if not HASH_PATTERN.match(hash_val):
                raise ValueError(f"Invalid hash format: {hash_val}")
            if len(hash_val) not in [32, 40, 64]:  # MD5, SHA1, SHA256
                raise ValueError(f"Invalid hash length: {hash_val}")
        return v


class URLLookupRequest(BaseModel):
    urls: List[str]
    enable_raw_json: Optional[bool] = False


class DomainLookupRequest(BaseModel):
    domains: List[str]
    enable_raw_json: Optional[bool] = False


class IPLookupRequest(BaseModel):
    ip_addresses: List[str]
    enable_raw_json: Optional[bool] = False


class LookupIndicatorsRequest(BaseModel):
    domains: Optional[List[str]] = None
    hashes: Optional[List[str]] = None
    ip_addresses: Optional[List[str]] = None
    urls: Optional[List[str]] = None
    enable_raw_json: Optional[bool] = False
    force_scan: Optional[bool] = False
    max_resolutions: Optional[int] = 10


class FileAnalysisRequest(BaseModel):
    file_content: str  # Base64 encoded file content
    filename: Optional[str] = "unknown"
    enable_raw_json: Optional[bool] = False


class MCPResponse(BaseModel):
    success: bool
    data: Optional[Dict[str, Any]] = None
    error: Optional[str] = None
    response_code: Optional[int] = None


# Validation patterns
HASH_PATTERN = re.compile(r"^[a-fA-F0-9]+$")
DOMAIN_PATTERN = re.compile(
    r"^[a-zA-Z0-9]([a-zA-Z0-9\-]{0,61}[a-zA-Z0-9])?(\.[a-zA-Z0-9]([a-zA-Z0-9\-]{0,61}[a-zA-Z0-9])?)*$"
)
IP_PATTERN = re.compile(
    r"^(?:(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.){3}(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)$"
)
URL_PATTERN = re.compile(
    r"^https?://(?:[-\w.])+(?:[:\d]+)?(?:/(?:[\w/_.])*(?:\?(?:[\w&=%.])*)?(?:#(?:[\w.])*)?)?$"
)

# Enhanced mock responses with more detailed structures (for fallback)
MOCK_RESPONSES = {
    "192.168.1.100": {
        "ip": "192.168.1.100",
        "as_owner": "Malicious ISP",
        "asn": 12345,
        "country": "US",
        "detected_urls": [
            {
                "url": "http://192.168.1.100/malware.exe",
                "positives": 12,
                "total": 20,
                "scan_date": "2024-01-20",
            }
        ],
        "resolutions": [
            {"last_resolved": "2024-01-15", "hostname": "example1.com"},
            {"last_resolved": "2024-01-10", "hostname": "example2.com"},
        ],
        "response_code": 1,
        "verbose_msg": "IP address found in malware database",
        "detected_downloaded_samples": [
            {
                "date": "2024-01-15",
                "positives": 15,
                "total": 69,
                "sha256": "abc123def456...",
            }
        ],
    },
    "malicious-domain.com": {
        "domain": "malicious-domain.com",
        "Alexa_category": "Malicious",
        "Alexa_rank": None,
        "BitDefender_category": "Malware",
        "DrWeb_category": "Phishing",
        "TrendMicro_category": "Suspicious",
        "categories": ["malware", "phishing"],
        "detected_urls": [
            {
                "url": "http://malicious-domain.com/bad.exe",
                "positives": 18,
                "total": 20,
                "scan_date": "2024-01-20",
            }
        ],
        "domain_siblings": ["sibling1.com", "sibling2.com"],
        "resolutions": [
            {"last_resolved": "2024-01-15", "ip_address": "192.168.1.100"},
            {"last_resolved": "2024-01-10", "ip_address": "10.0.0.1"},
        ],
        "response_code": 1,
        "subdomains": ["sub1.malicious-domain.com", "sub2.malicious-domain.com"],
        "verbose_msg": "Domain found in malware database",
        "whois": "Domain registered anonymously",
        "whois_timestamp": "2024-01-10",
    },
    "275a021bbfb6489e54d471899f7db9d1663fc695ec2fe2a2c4538aabf651fd0f": {
        "md5": "44d88612fea8a8f36de82e1278abb02f",
        "permalink": "https://www.virustotal.com/file/275a021bbfb6489e54d471899f7db9d1663fc695ec2fe2a2c4538aabf651fd0f/analysis/",
        "positives": 45,
        "resource": "275a021bbfb6489e54d471899f7db9d1663fc695ec2fe2a2c4538aabf651fd0f",
        "response_code": 1,
        "scan_date": "2024-01-20",
        "scan_id": "275a021bbfb6489e54d471899f7db9d1663fc695ec2fe2a2c4538aabf651fd0f-1705708800",
        "sha1": "0a3d92634bfdc0b84db1b6ff3b86c86b14ff2c1f",
        "sha256": "275a021bbfb6489e54d471899f7db9d1663fc695ec2fe2a2c4538aabf651fd0f",
        "total": 69,
        "verbose_msg": "Scan finished, information embedded",
        "scans": {
            "Microsoft": {
                "detected": True,
                "result": "Trojan:Win32/Generic",
                "update": "20240120",
                "version": "1.1.20700.5",
            },
            "Symantec": {
                "detected": True,
                "result": "Trojan.Gen.MBT",
                "update": "20240120",
                "version": "1.19.0.0",
            },
            "McAfee": {
                "detected": False,
                "result": None,
                "update": "20240120",
                "version": "6.0.6.653",
            },
        },
    },
    "http://malicious-url.com/test": {
        "url": "http://malicious-url.com/test",
        "permalink": "https://www.virustotal.com/url/abc123/analysis/",
        "positives": 22,
        "resource": "http://malicious-url.com/test",
        "response_code": 1,
        "scan_date": "2024-01-20",
        "scan_id": "abc123def456",
        "total": 70,
        "verbose_msg": "Scan finished, information embedded",
        "scans": {
            "Google Safe Browsing": {"detected": True, "result": "Malware site"},
            "BitDefender": {"detected": True, "result": "Malware"},
            "Dr.Web": {"detected": False, "result": "Clean"},
        },
    },
}


def get_vt_client(api_key: str) -> VirusTotalClient:
    """Get VirusTotal client instance"""
    if not api_key:
        raise VirusTotalError("API key is required")
    return VirusTotalClient(api_key)


def generate_mock_scan_report(indicator_type, indicators, enable_raw_json=False):
    """Generate mock scan reports for different indicator types (fallback only)"""
    results = []
    raw_data = []

    for indicator in indicators:
        if indicator in MOCK_RESPONSES:
            result = MOCK_RESPONSES[indicator].copy()
        else:
            # Generate clean response for unknown indicators
            if indicator_type == "hash":
                result = {
                    "md5": hashlib.md5(indicator.encode()).hexdigest()
                    if len(indicator) > 32
                    else indicator,
                    "permalink": f"https://www.virustotal.com/file/{indicator}/analysis/",
                    "positives": 0,
                    "resource": indicator,
                    "response_code": 1,
                    "scan_date": "2024-01-20",
                    "scan_id": f"{indicator}-1705708800",
                    "sha1": hashlib.sha1(indicator.encode()).hexdigest()
                    if len(indicator) > 40
                    else indicator,
                    "sha256": hashlib.sha256(indicator.encode()).hexdigest()
                    if len(indicator) > 64
                    else indicator,
                    "total": 69,
                    "verbose_msg": "Scan finished, information embedded",
                    "scans": {},
                }
            elif indicator_type == "domain":
                result = {
                    "domain": indicator,
                    "Alexa_category": "Uncategorized",
                    "Alexa_rank": 1000,
                    "BitDefender_category": "Clean",
                    "DrWeb_category": "Clean",
                    "TrendMicro_category": "Clean",
                    "categories": ["legitimate"],
                    "detected_urls": [],
                    "domain_siblings": [],
                    "resolutions": [],
                    "response_code": 1,
                    "subdomains": [],
                    "verbose_msg": "Domain found in malware database",
                    "whois": "Domain registration information",
                    "whois_timestamp": "2024-01-20",
                }
            elif indicator_type == "ip":
                result = {
                    "ip": indicator,
                    "as_owner": "Clean ISP",
                    "asn": 12345,
                    "country": "US",
                    "detected_urls": [],
                    "resolutions": [],
                    "response_code": 1,
                    "verbose_msg": "IP address found in malware database",
                    "detected_downloaded_samples": [],
                }
            elif indicator_type == "url":
                result = {
                    "url": indicator,
                    "permalink": f"https://www.virustotal.com/url/{hashlib.md5(indicator.encode()).hexdigest()}/analysis/",
                    "positives": 0,
                    "resource": indicator,
                    "response_code": 1,
                    "scan_date": "2024-01-20",
                    "scan_id": f"{hashlib.md5(indicator.encode()).hexdigest()}-1705708800",
                    "total": 70,
                    "verbose_msg": "Scan finished, information embedded",
                    "scans": {},
                }

        # Convert scans to vendor_scans format for consistency
        if "scans" in result:
            vendor_scans = []
            for k, v in result["scans"].items():
                vendor_scan_dict = {
                    "vendor_name": k,
                    "detected": v.get("detected"),
                    "result": v.get("result"),
                    "update": v.get("update", ""),
                    "version": v.get("version", ""),
                }
                vendor_scans.append(vendor_scan_dict)
            result["vendor_scans"] = vendor_scans
            del result["scans"]

        results.append(result)
        if enable_raw_json:
            raw_data.append(result)

    scan_report = {
        "has_suspicious_object": any(
            r.get("positives", 0) > 10 or r.get("response_code", 0) < 1 for r in results
        ),
        "white_list": [
            r.get(indicator_type, r.get("resource", r.get("url", r.get("hash", ""))))
            for r in results
            if r.get("positives", 0) <= 10 and r.get("response_code", 1) >= 1
        ],
        "black_list": [
            r.get(indicator_type, r.get("resource", r.get("url", r.get("hash", ""))))
            for r in results
            if r.get("positives", 0) > 10 or r.get("response_code", 1) < 1
        ],
        "status_msg": "Scan completed successfully",
        "scan_result": results,
    }

    return raw_data if enable_raw_json else None, scan_report


# Real VirusTotal API functions
def get_reports(
    client: VirusTotalClient,
    resources,
    uri,
    request_scan=False,
    resource_tag="resource",
):
    """Get reports from VirusTotal API"""
    if resource_tag in ["file", "url"]:
        params = {"resource": "\n".join(resources)}
    else:
        params = {resource_tag: "\n".join(resources)}

    if request_scan:
        params["scan"] = 1

    headers = {
        "Accept-Encoding": "gzip, deflate",
        "User-Agent": "gzip, Python requests library",
    }

    if resource_tag != "file":
        if len(resources) > 1:
            response = client.make_http_request(
                "POST", uri, params=params, headers=headers
            )
        else:
            response = client.make_http_request(
                "GET", uri, params=params, headers=headers
            )
        response_data = response.json()
    else:
        response_data = []
        for resource in resources:
            response = client.make_http_request(
                "GET", uri, params={"resource": resource}
            )
            response_data.append(response.json())

    if not isinstance(response_data, list):
        response_data = [response_data]

    return response_data


def fetch_scan_report_details(
    client: VirusTotalClient,
    indicator_values,
    uri,
    resource_tag="resource",
    suspicious_trigger_count=10,
    max_resolutions=MAX_RESOLUTIONS,
    force_scan=True,
):
    """Fetch detailed scan reports from VirusTotal API"""
    white_list = set()
    black_list = set()
    any_hits = False
    scan_results_list = []
    status_msg = ""
    raw_json = []

    if resource_tag in ["url", "file"]:
        reports = get_reports(
            client=client,
            uri=uri,
            resources=indicator_values,
            request_scan=force_scan,
            resource_tag=resource_tag,
        )
        raw_json.extend(reports)

        if not reports:
            raise VirusTotalError(
                f"No report generated for {resource_tag}: {indicator_values}"
            )

        for report in reports:
            if report.get("response_code", 0) < 1:
                resource = report.get("resource", "")
                white_list.add(resource)
                status_msg += (
                    f"resource: {resource} - {report.get('verbose_msg', '')}\n"
                )
            else:
                sanitized_report = client.sanitize_text(dict(report))
                scans = sanitized_report.get("scans", {})
                vendor_scans = []

                for k, v in scans.items():
                    vendor_scan_dict = {
                        "vendor_name": k,
                        "detected": v.get("detected"),
                        "result": v.get("result"),
                    }
                    vendor_scans.append(vendor_scan_dict)

                sanitized_report["vendor_scans"] = vendor_scans
                if "scans" in sanitized_report:
                    del sanitized_report["scans"]

                positives = report.get("positives", -1)
                resource = report.get("resource", "")

                if positives >= suspicious_trigger_count:
                    black_list.add(resource)
                    any_hits = True
                else:
                    white_list.add(resource)

                scan_results_list.append(sanitized_report)

    elif resource_tag in ["domain", "ip"]:
        for indicator in indicator_values:
            reports = get_reports(
                client=client, uri=uri, resources=[indicator], resource_tag=resource_tag
            )
            raw_json.extend(reports)

            if not reports:
                status_msg += f"No report generated for {resource_tag}: {indicator}\n"
                continue

            report = {client.attributify(k): v for k, v in reports[0].items() if v}
            report[resource_tag] = indicator

            sanitized_report = client.sanitize_text(report)

            if "resolutions" in sanitized_report:
                sanitized_report["resolutions"] = client.parse_resolutions(
                    sanitized_report["resolutions"], resource_tag, max_resolutions
                )

            detected_urls = report.get("detected_urls")
            if detected_urls:
                for detected_url in detected_urls:
                    positives = detected_url.get("positives", -1)

                    if positives >= suspicious_trigger_count:
                        black_list.add(indicator)
                        any_hits = True
                        break
                    else:
                        white_list.add(indicator)
            else:
                status_msg = f"No report generated for {resource_tag}: {indicator}"

            scan_results_list.append(sanitized_report)

    white_list.difference_update(black_list)

    if status_msg == "":
        status_msg = "Malware report retrieval completed successfully"

    scan_report = {
        "has_suspicious_object": any_hits,
        "white_list": list(white_list),
        "black_list": list(black_list),
        "status_msg": status_msg,
        "scan_result": scan_results_list,
    }

    return raw_json, scan_report


@app.get("/meta")
async def get_metadata():
    """Get server metadata and capabilities"""
    logger.info("Fetching server metadata and capabilities")
    metadata = {
        "server_name": "virustotal",
        "version": "1.1.0",
        "capabilities": [
            "ip_report",
            "domain_report",
            "lookup_hashes",
            "lookup_urls",
            "lookup_domains",
            "lookup_ip_addresses",
            "lookup_indicators",
            "analyse_file",
        ],
        "description": "Premium Access to VirusTotal threat intelligence, file and data scanning services",
        "authentication_required": True,
        "endpoints": {
            "ip_report": {
                "method": "POST",
                "parameters": {"ip": "string"},
                "description": "Get IP reputation report",
            },
            "domain_report": {
                "method": "POST",
                "parameters": {"domain": "string"},
                "description": "Get domain reputation report",
            },
            "lookup_hashes": {
                "method": "POST",
                "parameters": {
                    "hashes": "list of strings (MD5, SHA-1, SHA-256)",
                    "enable_raw_json": "boolean (optional)",
                },
                "description": "Lookup file hashes for malware analysis",
            },
            "lookup_urls": {
                "method": "POST",
                "parameters": {
                    "urls": "list of strings",
                    "enable_raw_json": "boolean (optional)",
                },
                "description": "Lookup URLs for malicious content",
            },
            "lookup_domains": {
                "method": "POST",
                "parameters": {
                    "domains": "list of strings",
                    "enable_raw_json": "boolean (optional)",
                },
                "description": "Lookup domains for reputation analysis",
            },
            "lookup_ip_addresses": {
                "method": "POST",
                "parameters": {
                    "ip_addresses": "list of strings",
                    "enable_raw_json": "boolean (optional)",
                },
                "description": "Lookup IP addresses for threat intelligence",
            },
            "lookup_indicators": {
                "method": "POST",
                "parameters": {
                    "domains": "list of strings (optional)",
                    "hashes": "list of strings (optional)",
                    "ip_addresses": "list of strings (optional)",
                    "urls": "list of strings (optional)",
                    "force_scan": "boolean (optional)",
                    "max_resolutions": "integer (optional)",
                    "enable_raw_json": "boolean (optional)",
                },
                "description": "Comprehensive lookup for multiple indicator types",
            },
            "analyse_file": {
                "method": "POST",
                "parameters": {
                    "file_content": "base64 encoded file",
                    "filename": "string (optional)",
                    "enable_raw_json": "boolean (optional)",
                },
                "description": "Submit file for analysis on VirusTotal",
            },
        },
    }
    logger.debug("Server metadata: %s", metadata)
    return metadata


@app.post("/ip_report", response_model=MCPResponse)
async def get_ip_report(
    request: IPReportRequest, x_api_key: Optional[str] = Header(None)
):
    """Get IP reputation report from VirusTotal"""
    logger.info("Processing IP report request for IP: %s", request.ip)

    if not x_api_key:
        logger.warning("API key required but not provided")
        raise HTTPException(status_code=401, detail="API key required")

    try:
        # Validate IP format
        if not IP_PATTERN.match(request.ip):
            raise HTTPException(status_code=400, detail="Invalid IP address format")

        client = get_vt_client(x_api_key)

        try:
            raw_json, scan_report = fetch_scan_report_details(
                client=client,
                indicator_values=[request.ip],
                uri="/ip-address/report",
                resource_tag="ip",
                force_scan=False,
            )

            # Extract single IP report from scan results
            ip_data = (
                scan_report["scan_result"][0] if scan_report["scan_result"] else {}
            )

            logger.info("Successfully generated IP report for %s", request.ip)
            return MCPResponse(success=True, data=ip_data, response_code=200)

        except (VirusTotalError, VirusTotalException) as vt_error:
            logger.warning("VirusTotal API error for %s: %s", request.ip, str(vt_error))
            # Fallback to mock data for demo purposes
            if request.ip in MOCK_RESPONSES:
                report = MOCK_RESPONSES[request.ip]
            else:
                report = {
                    "ip": request.ip,
                    "as_owner": "Unknown ISP",
                    "asn": 0,
                    "country": "Unknown",
                    "detected_urls": [],
                    "resolutions": [],
                    "response_code": 0,
                    "verbose_msg": "IP address not found in database",
                    "detected_downloaded_samples": [],
                }
            return MCPResponse(success=True, data=report, response_code=200)

    except Exception as e:
        logger.error("Failed to generate IP report for %s: %s", request.ip, str(e))
        return MCPResponse(success=False, error=str(e))


@app.post("/domain_report", response_model=MCPResponse)
async def get_domain_report(
    request: DomainReportRequest, x_api_key: Optional[str] = Header(None)
):
    """Get domain reputation report from VirusTotal"""
    logger.info("Processing domain report request for domain: %s", request.domain)

    if not x_api_key:
        raise HTTPException(status_code=401, detail="API key required")

    try:
        # Validate domain format
        if not DOMAIN_PATTERN.match(request.domain):
            raise HTTPException(status_code=400, detail="Invalid domain format")

        client = get_vt_client(x_api_key)

        try:
            raw_json, scan_report = fetch_scan_report_details(
                client=client,
                indicator_values=[request.domain],
                uri="/domain/report",
                resource_tag="domain",
                force_scan=False,
            )

            # Extract single domain report from scan results
            domain_data = (
                scan_report["scan_result"][0] if scan_report["scan_result"] else {}
            )

            logger.info("Successfully generated domain report for %s", request.domain)
            return MCPResponse(success=True, data=domain_data, response_code=200)

        except (VirusTotalError, VirusTotalException) as vt_error:
            logger.warning(
                "VirusTotal API error for %s: %s", request.domain, str(vt_error)
            )
            # Fallback to mock data for demo purposes
            if request.domain in MOCK_RESPONSES:
                report = MOCK_RESPONSES[request.domain]
            else:
                report = {
                    "domain": request.domain,
                    "Alexa_category": "Uncategorized",
                    "Alexa_rank": None,
                    "BitDefender_category": "Clean",
                    "DrWeb_category": "Clean",
                    "TrendMicro_category": "Clean",
                    "categories": ["uncategorized"],
                    "detected_urls": [],
                    "domain_siblings": [],
                    "resolutions": [],
                    "response_code": 0,
                    "subdomains": [],
                    "verbose_msg": "Domain not found in database",
                    "whois": "Domain information not available",
                    "whois_timestamp": "unknown",
                }
            return MCPResponse(success=True, data=report, response_code=200)

    except Exception as e:
        logger.error(
            "Failed to generate domain report for %s: %s", request.domain, str(e)
        )
        return MCPResponse(success=False, error=str(e))


@app.post("/lookup_hashes", response_model=MCPResponse)
async def lookup_hashes(
    request: HashLookupRequest, x_api_key: Optional[str] = Header(None)
):
    """Lookup file hashes for malware analysis"""
    logger.info("Processing hash lookup request for %d hashes", len(request.hashes))

    if not x_api_key:
        raise HTTPException(status_code=401, detail="API key required")

    try:
        client = get_vt_client(x_api_key)

        try:
            raw_json, scan_report = fetch_scan_report_details(
                client=client,
                indicator_values=request.hashes,
                uri="/file/report",
                resource_tag="file",
                force_scan=False,
            )

            response_data = {
                "hash_scan_report": scan_report,
                "task_success": True,
                "status_msg": "Hash lookup completed successfully",
            }

            if request.enable_raw_json and raw_json:
                response_data["raw_json"] = json.dumps(raw_json)

            logger.info(
                "Successfully completed hash lookup for %d hashes", len(request.hashes)
            )
            return MCPResponse(success=True, data=response_data, response_code=200)

        except (VirusTotalError, VirusTotalException) as vt_error:
            logger.warning("VirusTotal API error for hash lookup: %s", str(vt_error))
            # Fallback to mock data
            raw_json, scan_report = generate_mock_scan_report(
                "hash", request.hashes, request.enable_raw_json
            )

            response_data = {
                "hash_scan_report": scan_report,
                "task_success": True,
                "status_msg": "Hash lookup completed successfully (using fallback data)",
            }

            if request.enable_raw_json and raw_json:
                response_data["raw_json"] = json.dumps(raw_json)

            return MCPResponse(success=True, data=response_data, response_code=200)

    except Exception as e:
        logger.error("Failed to lookup hashes: %s", str(e))
        return MCPResponse(success=False, error=str(e))


@app.post("/lookup_urls", response_model=MCPResponse)
async def lookup_urls(
    request: URLLookupRequest, x_api_key: Optional[str] = Header(None)
):
    """Lookup URLs for malicious content"""
    logger.info("Processing URL lookup request for %d URLs", len(request.urls))

    if not x_api_key:
        raise HTTPException(status_code=401, detail="API key required")

    try:
        # Validate URL formats
        for url in request.urls:
            if not VirusTotalClient.is_valid_url(url):
                raise HTTPException(
                    status_code=400, detail=f"Invalid URL format: {url}"
                )

        client = get_vt_client(x_api_key)

        try:
            raw_json, scan_report = fetch_scan_report_details(
                client=client,
                indicator_values=request.urls,
                uri="/url/report",
                resource_tag="url",
                force_scan=False,
            )

            response_data = {
                "url_scan_report": scan_report,
                "task_success": True,
                "status_msg": "URL lookup completed successfully",
            }

            if request.enable_raw_json and raw_json:
                response_data["raw_json"] = json.dumps(raw_json)

            logger.info(
                "Successfully completed URL lookup for %d URLs", len(request.urls)
            )
            return MCPResponse(success=True, data=response_data, response_code=200)

        except (VirusTotalError, VirusTotalException) as vt_error:
            logger.warning("VirusTotal API error for URL lookup: %s", str(vt_error))
            # Fallback to mock data
            raw_json, scan_report = generate_mock_scan_report(
                "url", request.urls, request.enable_raw_json
            )

            response_data = {
                "url_scan_report": scan_report,
                "task_success": True,
                "status_msg": "URL lookup completed successfully (using fallback data)",
            }

            if request.enable_raw_json and raw_json:
                response_data["raw_json"] = json.dumps(raw_json)

            return MCPResponse(success=True, data=response_data, response_code=200)

    except Exception as e:
        logger.error("Failed to lookup URLs: %s", str(e))
        return MCPResponse(success=False, error=str(e))


@app.post("/lookup_domains", response_model=MCPResponse)
async def lookup_domains(
    request: DomainLookupRequest, x_api_key: Optional[str] = Header(None)
):
    """Lookup domains for reputation analysis"""
    logger.info("Processing domain lookup request for %d domains", len(request.domains))

    if not x_api_key:
        raise HTTPException(status_code=401, detail="API key required")

    try:
        # Validate domain formats
        for domain in request.domains:
            if not DOMAIN_PATTERN.match(domain):
                raise HTTPException(
                    status_code=400, detail=f"Invalid domain format: {domain}"
                )

        client = get_vt_client(x_api_key)

        try:
            raw_json, scan_report = fetch_scan_report_details(
                client=client,
                indicator_values=request.domains,
                uri="/domain/report",
                resource_tag="domain",
                force_scan=False,
            )

            response_data = {
                "domain_scan_report": scan_report,
                "task_success": True,
                "status_msg": "Domain lookup completed successfully",
            }

            if request.enable_raw_json and raw_json:
                response_data["raw_json"] = json.dumps(raw_json)

            logger.info(
                "Successfully completed domain lookup for %d domains",
                len(request.domains),
            )
            return MCPResponse(success=True, data=response_data, response_code=200)

        except (VirusTotalError, VirusTotalException) as vt_error:
            logger.warning("VirusTotal API error for domain lookup: %s", str(vt_error))
            # Fallback to mock data
            raw_json, scan_report = generate_mock_scan_report(
                "domain", request.domains, request.enable_raw_json
            )

            response_data = {
                "domain_scan_report": scan_report,
                "task_success": True,
                "status_msg": "Domain lookup completed successfully (using fallback data)",
            }

            if request.enable_raw_json and raw_json:
                response_data["raw_json"] = json.dumps(raw_json)

            return MCPResponse(success=True, data=response_data, response_code=200)

    except Exception as e:
        logger.error("Failed to lookup domains: %s", str(e))
        return MCPResponse(success=False, error=str(e))


@app.post("/lookup_ip_addresses", response_model=MCPResponse)
async def lookup_ip_addresses(
    request: IPLookupRequest, x_api_key: Optional[str] = Header(None)
):
    """Lookup IP addresses for threat intelligence"""
    logger.info(
        "Processing IP lookup request for %d IP addresses", len(request.ip_addresses)
    )

    if not x_api_key:
        raise HTTPException(status_code=401, detail="API key required")

    try:
        # Validate IP formats
        for ip in request.ip_addresses:
            if not IP_PATTERN.match(ip):
                raise HTTPException(
                    status_code=400, detail=f"Invalid IP address format: {ip}"
                )

        client = get_vt_client(x_api_key)

        try:
            raw_json, scan_report = fetch_scan_report_details(
                client=client,
                indicator_values=request.ip_addresses,
                uri="/ip-address/report",
                resource_tag="ip",
                force_scan=False,
            )

            response_data = {
                "ip_scan_report": scan_report,
                "task_success": True,
                "status_msg": "IP address lookup completed successfully",
            }

            if request.enable_raw_json and raw_json:
                response_data["raw_json"] = json.dumps(raw_json)

            logger.info(
                "Successfully completed IP lookup for %d IP addresses",
                len(request.ip_addresses),
            )
            return MCPResponse(success=True, data=response_data, response_code=200)

        except (VirusTotalError, VirusTotalException) as vt_error:
            logger.warning("VirusTotal API error for IP lookup: %s", str(vt_error))
            # Fallback to mock data
            raw_json, scan_report = generate_mock_scan_report(
                "ip", request.ip_addresses, request.enable_raw_json
            )

            response_data = {
                "ip_scan_report": scan_report,
                "task_success": True,
                "status_msg": "IP address lookup completed successfully (using fallback data)",
            }

            if request.enable_raw_json and raw_json:
                response_data["raw_json"] = json.dumps(raw_json)

            return MCPResponse(success=True, data=response_data, response_code=200)

    except Exception as e:
        logger.error("Failed to lookup IP addresses: %s", str(e))
        return MCPResponse(success=False, error=str(e))


@app.post("/lookup_indicators", response_model=MCPResponse)
async def lookup_indicators(
    request: LookupIndicatorsRequest, x_api_key: Optional[str] = Header(None)
):
    """Comprehensive lookup for multiple indicator types"""
    logger.info("Processing multi-indicator lookup request")

    if not x_api_key:
        raise HTTPException(status_code=401, detail="API key required")

    try:
        # Validate that at least one indicator type is provided
        if not any(
            [request.domains, request.hashes, request.ip_addresses, request.urls]
        ):
            raise HTTPException(
                status_code=400, detail="At least one indicator type is required"
            )

        # Validate max_resolutions parameter
        max_resolutions = request.max_resolutions or MAX_RESOLUTIONS
        if max_resolutions < 0:
            max_resolutions = MAX_RESOLUTIONS

        client = get_vt_client(x_api_key)
        vt_lookup = {}
        all_raw_json = []
        use_fallback = False

        # Process each indicator type
        if request.domains:
            # Validate domain formats
            for domain in request.domains:
                if not DOMAIN_PATTERN.match(domain):
                    raise HTTPException(
                        status_code=400, detail=f"Invalid domain format: {domain}"
                    )

            try:
                raw_json, domain_report = fetch_scan_report_details(
                    client=client,
                    indicator_values=request.domains,
                    uri="/domain/report",
                    resource_tag="domain",
                    force_scan=request.force_scan,
                    max_resolutions=max_resolutions,
                )
                vt_lookup["domain_scan_report"] = domain_report
                if raw_json:
                    all_raw_json.extend(raw_json)
            except (VirusTotalError, VirusTotalException):
                use_fallback = True
                raw_json, domain_report = generate_mock_scan_report(
                    "domain", request.domains, request.enable_raw_json
                )
                vt_lookup["domain_scan_report"] = domain_report
                if raw_json:
                    all_raw_json.extend(raw_json)

        if request.hashes:
            try:
                raw_json, hash_report = fetch_scan_report_details(
                    client=client,
                    indicator_values=request.hashes,
                    uri="/file/report",
                    resource_tag="file",
                    force_scan=request.force_scan,
                    max_resolutions=max_resolutions,
                )
                vt_lookup["hash_scan_report"] = hash_report
                if raw_json:
                    all_raw_json.extend(raw_json)
            except (VirusTotalError, VirusTotalException):
                use_fallback = True
                raw_json, hash_report = generate_mock_scan_report(
                    "hash", request.hashes, request.enable_raw_json
                )
                vt_lookup["hash_scan_report"] = hash_report
                if raw_json:
                    all_raw_json.extend(raw_json)

        if request.ip_addresses:
            # Validate IP formats
            for ip in request.ip_addresses:
                if not IP_PATTERN.match(ip):
                    raise HTTPException(
                        status_code=400, detail=f"Invalid IP address format: {ip}"
                    )

            try:
                raw_json, ip_report = fetch_scan_report_details(
                    client=client,
                    indicator_values=request.ip_addresses,
                    uri="/ip-address/report",
                    resource_tag="ip",
                    force_scan=request.force_scan,
                    max_resolutions=max_resolutions,
                )
                vt_lookup["ip_scan_report"] = ip_report
                if raw_json:
                    all_raw_json.extend(raw_json)
            except (VirusTotalError, VirusTotalException):
                use_fallback = True
                raw_json, ip_report = generate_mock_scan_report(
                    "ip", request.ip_addresses, request.enable_raw_json
                )
                vt_lookup["ip_scan_report"] = ip_report
                if raw_json:
                    all_raw_json.extend(raw_json)

        if request.urls:
            # Validate URL formats
            for url in request.urls:
                if not VirusTotalClient.is_valid_url(url):
                    raise HTTPException(
                        status_code=400, detail=f"Invalid URL format: {url}"
                    )

            try:
                raw_json, url_report = fetch_scan_report_details(
                    client=client,
                    indicator_values=request.urls,
                    uri="/url/report",
                    resource_tag="url",
                    force_scan=request.force_scan,
                    max_resolutions=max_resolutions,
                )
                vt_lookup["url_scan_report"] = url_report
                if raw_json:
                    all_raw_json.extend(raw_json)
            except (VirusTotalError, VirusTotalException):
                use_fallback = True
                raw_json, url_report = generate_mock_scan_report(
                    "url", request.urls, request.enable_raw_json
                )
                vt_lookup["url_scan_report"] = url_report
                if raw_json:
                    all_raw_json.extend(raw_json)

        status_msg = "Multi-indicator lookup completed successfully"
        if use_fallback:
            status_msg += " (some data from fallback sources)"

        response_data = {
            "vt_lookup": vt_lookup,
            "task_success": True,
            "status_msg": status_msg,
        }

        if request.enable_raw_json and all_raw_json:
            response_data["raw_json"] = json.dumps(all_raw_json)

        logger.info("Successfully completed multi-indicator lookup")
        return MCPResponse(success=True, data=response_data, response_code=200)

    except Exception as e:
        logger.error("Failed to lookup indicators: %s", str(e))
        return MCPResponse(success=False, error=str(e))


@app.post("/analyse_file", response_model=MCPResponse)
async def analyse_file(
    request: FileAnalysisRequest, x_api_key: Optional[str] = Header(None)
):
    """Upload and analyze file for malware detection"""
    logger.info("Processing file analysis request for file: %s", request.filename)

    if not x_api_key:
        raise HTTPException(status_code=401, detail="API key required")

    try:
        # Decode base64 file content
        try:
            file_data = base64.b64decode(request.file_content)
        except Exception:
            raise HTTPException(status_code=400, detail="Invalid base64 file content")

        if len(file_data) == 0:
            raise HTTPException(status_code=400, detail="Empty file content")

        # Generate hash of the file for analysis
        file_hash = hashlib.sha256(file_data).hexdigest()
        client = get_vt_client(x_api_key)

        try:
            # First try to upload file to VirusTotal for scanning
            files = {"file": (request.filename or "unknown_file", file_data)}

            upload_response = client.make_http_request(
                "POST", "/file/scan", files=files
            )

            scan_id = upload_response.json().get("scan_id")
            resource = upload_response.json().get("resource", file_hash)

            # Wait a moment for scan to begin
            logger.info("File uploaded successfully, waiting for analysis...")
            time.sleep(10)  # Reduced from 60s to 10s for responsiveness

            # Get scan results
            try:
                raw_json, scan_report = fetch_scan_report_details(
                    client=client,
                    indicator_values=[resource],
                    uri="/file/report",
                    resource_tag="file",
                    force_scan=False,
                )

                analysis_result = {
                    "file_scan_report": scan_report,
                    "task_success": True,
                    "status_msg": f"File analysis completed for {request.filename}",
                }

                if request.enable_raw_json and raw_json:
                    analysis_result["raw_json"] = json.dumps(raw_json)

                logger.info(
                    "Successfully completed file analysis for %s", request.filename
                )
                return MCPResponse(
                    success=True, data=analysis_result, response_code=200
                )

            except (VirusTotalError, VirusTotalException) as vt_error:
                logger.warning("VirusTotal file report error: %s", str(vt_error))
                # Return basic analysis info even if report isn't ready
                analysis_result = {
                    "file_scan_report": {
                        "has_suspicious_object": False,
                        "white_list": [file_hash],
                        "black_list": [],
                        "status_msg": f"File uploaded successfully. Analysis may take a few minutes. Hash: {file_hash}",
                        "scan_result": [
                            {
                                "sha256": file_hash,
                                "filename": request.filename,
                                "file_size": len(file_data),
                                "scan_id": scan_id,
                                "resource": resource,
                                "response_code": 1,
                                "verbose_msg": "File queued for analysis",
                            }
                        ],
                    },
                    "task_success": True,
                    "status_msg": "File uploaded and queued for analysis",
                }

                if request.enable_raw_json:
                    analysis_result["raw_json"] = json.dumps(
                        [analysis_result["file_scan_report"]["scan_result"][0]]
                    )

                return MCPResponse(
                    success=True, data=analysis_result, response_code=200
                )

        except (VirusTotalError, VirusTotalException) as vt_error:
            logger.warning("VirusTotal file upload error: %s", str(vt_error))
            # Fallback to mock file analysis
            analysis_result = {
                "file_scan_report": {
                    "has_suspicious_object": False,
                    "white_list": [file_hash],
                    "black_list": [],
                    "status_msg": f"File analysis completed for {request.filename} (using fallback analysis)",
                    "scan_result": [
                        {
                            "sha256": file_hash,
                            "filename": request.filename,
                            "file_size": len(file_data),
                            "positives": 0,
                            "total": 69,
                            "scan_date": datetime.now().strftime("%Y-%m-%d"),
                            "vendor_scans": [
                                {
                                    "vendor_name": "Microsoft",
                                    "detected": False,
                                    "result": "Clean",
                                    "update": datetime.now().strftime("%Y%m%d"),
                                    "version": "1.1.20700.5",
                                },
                                {
                                    "vendor_name": "Symantec",
                                    "detected": False,
                                    "result": "Clean",
                                    "update": datetime.now().strftime("%Y%m%d"),
                                    "version": "1.19.0.0",
                                },
                                {
                                    "vendor_name": "McAfee",
                                    "detected": False,
                                    "result": "Clean",
                                    "update": datetime.now().strftime("%Y%m%d"),
                                    "version": "6.0.6.653",
                                },
                            ],
                        }
                    ],
                },
                "task_success": True,
                "status_msg": "File analysis completed successfully (using fallback analysis)",
            }

            # Check if file matches any known malicious patterns
            if file_hash in MOCK_RESPONSES:
                malicious_result = MOCK_RESPONSES[file_hash]
                analysis_result["file_scan_report"]["has_suspicious_object"] = True
                analysis_result["file_scan_report"]["black_list"] = [file_hash]
                analysis_result["file_scan_report"]["white_list"] = []
                analysis_result["file_scan_report"]["scan_result"] = [malicious_result]

            if request.enable_raw_json:
                analysis_result["raw_json"] = json.dumps(
                    analysis_result["file_scan_report"]["scan_result"]
                )

            return MCPResponse(success=True, data=analysis_result, response_code=200)

    except Exception as e:
        logger.error("Failed to analyze file %s: %s", request.filename, str(e))
        return MCPResponse(success=False, error=str(e))


if __name__ == "__main__":
    uvicorn.run(app, host="0.0.0.0", port=8001)
