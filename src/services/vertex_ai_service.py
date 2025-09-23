"""
Google Cloud Vertex AI Integration Service

Service for managing Vertex AI interactions, model configuration,
and AI-powered alert analysis.

Author: AI-SOAR Platform Team
Created: 2025-09-10
"""

import asyncio
import logging
from typing import Any, Dict, List, Optional

try:
    import vertexai
    from google.cloud import aiplatform
    from vertexai.generative_models import ChatSession, GenerativeModel, Part
    from vertexai.preview.generative_models import grounding
except ImportError:
    vertexai = None
    GenerativeModel = None
    aiplatform = None

from ..config.settings import get_settings

logger = logging.getLogger(__name__)


class VertexAIService:
    """Service for Google Cloud Vertex AI integration"""

    def __init__(self):
        self.settings = get_settings()
        self.model = None
        self.chat_session = None

        # Model configuration
        self.default_model = "gemini-1.5-pro"
        self.backup_model = "gemini-1.0-pro"

        if self.settings.google_cloud_project and vertexai:
            self._initialize_vertex_ai()

    def _initialize_vertex_ai(self):
        """Initialize Vertex AI with project configuration"""
        try:
            vertexai.init(
                project=self.settings.google_cloud_project,
                location=self.settings.vertex_ai_location,
            )

            # Initialize the generative model
            self.model = GenerativeModel(
                model_name=self.default_model,
                generation_config={
                    "max_output_tokens": 2048,
                    "temperature": 0.1,
                    "top_p": 0.8,
                    "top_k": 40,
                },
                safety_settings={
                    # Configure safety settings for cybersecurity content
                },
            )

            logger.info(
                f"Vertex AI initialized successfully with model: {self.default_model}"
            )

        except Exception as e:
            logger.error(f"Failed to initialize Vertex AI: {e}")
            self.model = None

    async def analyze_alert(self, alert_data: Dict[str, Any]) -> Dict[str, Any]:
        """Analyze a security alert using Vertex AI"""
        if not self.model:
            return {
                "status": "error",
                "message": "Vertex AI not available",
                "analysis": None,
            }

        try:
            # Prepare alert context for analysis
            alert_context = self._prepare_alert_context(alert_data)

            # Create analysis prompt
            prompt = self._create_analysis_prompt(alert_context)

            # Generate analysis
            response = await asyncio.to_thread(self.model.generate_content, prompt)

            # Parse and structure the response
            analysis = self._parse_analysis_response(response.text)

            return {
                "status": "success",
                "analysis": analysis,
                "model_used": self.default_model,
                "tokens_used": response.usage_metadata.total_token_count
                if hasattr(response, "usage_metadata")
                else None,
            }

        except Exception as e:
            logger.error(f"Alert analysis failed: {e}")
            return {"status": "error", "message": str(e), "analysis": None}

    async def generate_response_recommendations(
        self, alert_data: Dict[str, Any], analysis: Dict[str, Any]
    ) -> Dict[str, Any]:
        """Generate response recommendations for an alert"""
        if not self.model:
            return {"status": "error", "message": "Vertex AI not available"}

        try:
            prompt = self._create_response_prompt(alert_data, analysis)

            response = await asyncio.to_thread(self.model.generate_content, prompt)

            recommendations = self._parse_recommendations_response(response.text)

            return {
                "status": "success",
                "recommendations": recommendations,
                "model_used": self.default_model,
            }

        except Exception as e:
            logger.error(f"Response recommendation generation failed: {e}")
            return {"status": "error", "message": str(e)}

    async def summarize_alerts(self, alerts: List[Dict[str, Any]]) -> Dict[str, Any]:
        """Generate a summary of multiple alerts"""
        if not self.model:
            return {"status": "error", "message": "Vertex AI not available"}

        try:
            prompt = self._create_summary_prompt(alerts)

            response = await asyncio.to_thread(self.model.generate_content, prompt)

            summary = self._parse_summary_response(response.text)

            return {
                "status": "success",
                "summary": summary,
                "alert_count": len(alerts),
                "model_used": self.default_model,
            }

        except Exception as e:
            logger.error(f"Alert summary generation failed: {e}")
            return {"status": "error", "message": str(e)}

    async def list_available_models(self) -> List[str]:
        """List available Vertex AI models"""
        if not aiplatform:
            return []

        try:
            # This is a simplified list - in production you'd query the actual available models
            return [
                "gemini-1.5-pro",
                "gemini-1.0-pro",
                "gemini-1.5-flash",
                "claude-3-5-sonnet@20241022",  # If Anthropic models are available
            ]
        except Exception as e:
            logger.error(f"Failed to list models: {e}")
            return []

    def get_default_model(self) -> str:
        """Get the default model name"""
        return self.default_model

    def get_supported_features(self) -> List[str]:
        """Get list of supported AI features"""
        return [
            "alert_analysis",
            "response_recommendations",
            "alert_summarization",
            "threat_intelligence",
            "incident_correlation",
        ]

    def _prepare_alert_context(self, alert_data: Dict[str, Any]) -> Dict[str, Any]:
        """Prepare alert data for AI analysis"""
        return {
            "alert_id": alert_data.get("id"),
            "alert_name": alert_data.get("alert_name"),
            "severity": alert_data.get("severity"),
            "alert_details": alert_data.get("alert_data", {}),
            "related_entities": alert_data.get("related_entities", {}),
            "timestamp": alert_data.get("alert_created_at"),
        }

    def _create_analysis_prompt(self, alert_context: Dict[str, Any]) -> str:
        """Create analysis prompt for security alert"""
        return f"""
        As a cybersecurity expert, analyze the following security alert and provide a comprehensive assessment:

        Alert Information:
        - Alert ID: {alert_context.get('alert_id')}
        - Alert Name: {alert_context.get('alert_name')}
        - Severity: {alert_context.get('severity')}
        - Timestamp: {alert_context.get('timestamp')}

        Alert Details: {alert_context.get('alert_details')}
        Related Entities: {alert_context.get('related_entities')}

        Please provide analysis in the following JSON format:
        {{
            "threat_assessment": {{
                "risk_level": "low|medium|high|critical",
                "confidence_score": 0.0-1.0,
                "threat_type": "malware|phishing|intrusion|data_breach|other",
                "indicators": ["list of key indicators"]
            }},
            "impact_analysis": {{
                "affected_systems": ["list of affected systems"],
                "potential_damage": "description",
                "business_impact": "low|medium|high|critical"
            }},
            "investigation_notes": {{
                "key_findings": ["list of findings"],
                "suspicious_activities": ["list of activities"],
                "false_positive_likelihood": 0.0-1.0
            }}
        }}
        """

    def _create_response_prompt(
        self, alert_data: Dict[str, Any], analysis: Dict[str, Any]
    ) -> str:
        """Create prompt for response recommendations"""
        return f"""
        Based on the security alert analysis, provide immediate response recommendations:

        Alert: {alert_data.get('alert_name')}
        Severity: {alert_data.get('severity')}
        Analysis Summary: {analysis}

        Provide recommendations in JSON format:
        {{
            "immediate_actions": [
                {{"action": "description", "priority": "high|medium|low", "timeline": "immediate|1h|4h|24h"}}
            ],
            "investigation_steps": [
                {{"step": "description", "tools": ["tool1", "tool2"], "expected_outcome": "description"}}
            ],
            "containment_measures": [
                {{"measure": "description", "impact": "description", "automation_possible": true/false}}
            ],
            "follow_up_tasks": [
                {{"task": "description", "assignee": "role", "deadline": "timeline"}}
            ]
        }}
        """

    def _create_summary_prompt(self, alerts: List[Dict[str, Any]]) -> str:
        """Create prompt for alert summary"""
        alert_summary = []
        for alert in alerts[:10]:  # Limit to first 10 alerts to avoid token limits
            alert_summary.append(
                {
                    "name": alert.get("alert_name"),
                    "severity": alert.get("severity"),
                    "timestamp": alert.get("alert_created_at"),
                }
            )

        return f"""
        Analyze the following security alerts and provide a comprehensive summary:

        Alerts: {alert_summary}

        Provide summary in JSON format:
        {{
            "overview": {{
                "total_alerts": {len(alerts)},
                "severity_distribution": {{"critical": 0, "high": 0, "medium": 0, "low": 0}},
                "time_range": "description",
                "trend_analysis": "increasing|decreasing|stable"
            }},
            "key_patterns": [
                {{"pattern": "description", "frequency": 0, "significance": "high|medium|low"}}
            ],
            "priority_alerts": [
                {{"alert_name": "name", "reason": "why this is priority"}}
            ],
            "recommendations": {{
                "immediate_focus": "description",
                "resource_allocation": "description",
                "escalation_needed": true/false
            }}
        }}
        """

    def _parse_analysis_response(self, response_text: str) -> Dict[str, Any]:
        """Parse AI analysis response"""
        try:
            import json

            # Extract JSON from response (may contain additional text)
            start_idx = response_text.find("{")
            end_idx = response_text.rfind("}") + 1

            if start_idx != -1 and end_idx > start_idx:
                json_text = response_text[start_idx:end_idx]
                return json.loads(json_text)
            else:
                # Fallback: return structured summary of text response
                return {
                    "threat_assessment": {
                        "risk_level": "unknown",
                        "confidence_score": 0.5,
                        "summary": response_text[:500],
                    }
                }
        except Exception as e:
            logger.error(f"Failed to parse analysis response: {e}")
            return {"error": "Failed to parse response", "raw_response": response_text}

    def _parse_recommendations_response(self, response_text: str) -> Dict[str, Any]:
        """Parse AI recommendations response"""
        try:
            import json

            start_idx = response_text.find("{")
            end_idx = response_text.rfind("}") + 1

            if start_idx != -1 and end_idx > start_idx:
                json_text = response_text[start_idx:end_idx]
                return json.loads(json_text)
            else:
                return {
                    "error": "Could not parse recommendations",
                    "raw_response": response_text,
                }
        except Exception as e:
            logger.error(f"Failed to parse recommendations response: {e}")
            return {"error": "Failed to parse response", "raw_response": response_text}

    def _parse_summary_response(self, response_text: str) -> Dict[str, Any]:
        """Parse AI summary response"""
        try:
            import json

            start_idx = response_text.find("{")
            end_idx = response_text.rfind("}") + 1

            if start_idx != -1 and end_idx > start_idx:
                json_text = response_text[start_idx:end_idx]
                return json.loads(json_text)
            else:
                return {
                    "error": "Could not parse summary",
                    "raw_response": response_text,
                }
        except Exception as e:
            logger.error(f"Failed to parse summary response: {e}")
            return {"error": "Failed to parse response", "raw_response": response_text}
