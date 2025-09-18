#!/usr/bin/env python3
"""
AI Planner with Strict JSON Schema Contract
Generates executable test plans based on target fingerprints and knowledge base
"""

import json
import logging
import time
from typing import Dict, List, Optional, Any, Tuple
from dataclasses import dataclass
from datetime import datetime
import re

# Import knowledge base and AI client
try:
    from knowledge_base import get_relevant_docs, KnowledgeDoc
    from modules.ai_client import AIClient
except ImportError as e:
    logging.error(f"Failed to import dependencies: {e}")
    raise

logger = logging.getLogger(__name__)

@dataclass
class PlanAction:
    """Single test action with deterministic execution parameters"""
    id: str
    vuln_class: str  # e.g., "xss.reflected", "sqli.error_based"
    endpoint: str
    method: str  # GET, POST
    param: str
    payloads: List[str]
    mutations: List[str]  # e.g., ["urlencode", "double_urlencode"]
    headers: Dict[str, str]
    evidence_checks: Dict[str, Any]
    priority: float  # 0.0 to 1.0
    source_docs: List[str]  # Knowledge doc IDs that informed this action

@dataclass
class TestPlan:
    """Complete test plan with metadata and execution parameters"""
    plan_version: str = "1.0"
    target: Dict[str, Any] = None
    actions: List[PlanAction] = None
    oob: Dict[str, Any] = None
    reporting: Dict[str, Any] = None
    
    def __post_init__(self):
        if self.target is None:
            self.target = {}
        if self.actions is None:
            self.actions = []
        if self.oob is None:
            self.oob = {}
        if self.reporting is None:
            self.reporting = {}

class AIPlanner:
    """
    AI-powered test planner that generates executable vulnerability test plans.
    Uses schema-first approach with strict JSON validation.
    """
    
    def __init__(self, config: Dict[str, Any]):
        self.config = config
        self.ai_client = AIClient(config)
        
        # Load JSON schema for plan validation
        self.plan_schema = self._load_plan_schema()
    
    def _load_plan_schema(self) -> Dict[str, Any]:
        """Load and return the strict JSON schema for test plans"""
        return {
            "type": "object",
            "required": ["plan_version", "target", "actions"],
            "properties": {
                "plan_version": {"type": "string", "const": "1.0"},
                "target": {
                    "type": "object",
                    "required": ["base_url"],
                    "properties": {
                        "base_url": {"type": "string", "format": "uri"},
                        "stack": {"type": "array", "items": {"type": "string"}},
                        "assumptions": {"type": "array", "items": {"type": "string"}}
                    }
                },
                "actions": {
                    "type": "array",
                    "items": {
                        "type": "object",
                        "required": ["id", "vuln_class", "endpoint", "method", "param", "payloads", "evidence_checks", "priority"],
                        "properties": {
                            "id": {"type": "string", "pattern": "^act-[0-9]{3}$"},
                            "vuln_class": {
                                "type": "string",
                                "enum": ["xss.reflected", "xss.stored", "xss.dom", "sqli.error_based", 
                                        "sqli.boolean_blind", "sqli.time_blind", "sqli.blind", "ssrf", "open_redirect", 
                                        "idor", "csrf", "command_injection", "lfi", "rfi"]
                            },
                            "endpoint": {"type": "string"},
                            "method": {"type": "string", "enum": ["GET", "POST", "PUT", "DELETE"]},
                            "param": {"type": "string"},
                            "payloads": {"type": "array", "items": {"type": "string"}, "minItems": 1},
                            "mutations": {"type": "array", "items": {"type": "string"}},
                            "headers": {"type": "object"},
                            "evidence_checks": {
                                "type": "object",
                                "properties": {
                                    "reflects_marker": {"type": "boolean"},
                                    "regex_any": {"type": "array", "items": {"type": "string"}},
                                    "status_any": {"type": "array", "items": {"type": "integer"}},
                                    "header_contains": {"type": "object"},
                                    "timing_delay": {"type": "number"},
                                    "oob_required": {"type": "boolean"}
                                }
                            },
                            "priority": {"type": "number", "minimum": 0.0, "maximum": 1.0},
                            "source_docs": {"type": "array", "items": {"type": "string"}}
                        }
                    }
                },
                "oob": {
                    "type": "object",
                    "properties": {
                        "enabled": {"type": "boolean"},
                        "collab_url": {"type": "string"},
                        "markers": {"type": "array", "items": {"type": "string"}}
                    }
                },
                "reporting": {
                    "type": "object",
                    "properties": {
                        "artifacts": {"type": "array", "items": {"type": "string"}},
                        "min_evidence_score": {"type": "number"}
                    }
                }
            }
        }
    
    def build_fingerprint(self, url: str, tech_stack: List[str] = None, 
                         params: List[str] = None, headers: Dict[str, str] = None) -> Dict[str, Any]:
        """Build target fingerprint from available information"""
        return {
            "base_url": url,
            "stack": tech_stack or [],
            "params": params or [],
            "headers": headers or {},
            "discovered_at": datetime.now().isoformat()
        }
    
    async def generate_plan(self, fingerprint: Dict[str, Any], 
                          vuln_classes: List[str] = None) -> Optional[TestPlan]:
        """
        Generate a complete test plan based on target fingerprint.
        
        Args:
            fingerprint: Target fingerprint with tech stack, params, etc.
            vuln_classes: Specific vulnerability classes to test (None = all)
            
        Returns:
            TestPlan object or None if generation fails
        """
        try:
            # TODO: Retrieve relevant knowledge documents
            relevant_docs = get_relevant_docs(
                query=" ".join(vuln_classes or ["xss", "sqli", "ssrf", "idor"]),
                fingerprint=fingerprint,
                k=15
            )
            
            # TODO: Call AI planner with context
            plan_json = await self._call_ai_planner(fingerprint, relevant_docs, vuln_classes)
            
            if not plan_json:
                return None
            
            # Validate against schema
            if not self._validate_plan_schema(plan_json):
                logger.error("Generated plan failed schema validation")
                return None
            
            # Convert to TestPlan object
            return self._json_to_plan(plan_json)
            
        except Exception as e:
            logger.error(f"Plan generation failed: {e}")
            return None
    
    async def _call_ai_planner(self, fingerprint: Dict[str, Any], 
                             docs: List[KnowledgeDoc], 
                             vuln_classes: List[str] = None) -> Optional[Dict[str, Any]]:
        """Call AI to generate test plan with strict JSON schema"""
        
        # Build context from knowledge documents
        doc_context = self._build_doc_context(docs)
        
        # Build prompt with schema constraints
        prompt = self._build_planner_prompt(fingerprint, doc_context, vuln_classes)
        
        try:
            # Generate plan with AI
            response = await self.ai_client.generate_text(
                prompt=prompt,
                temperature=0.1,  # Low temperature for deterministic output
                max_tokens=4000
            )
            
            # Extract JSON from response
            plan_json = self._extract_json_from_response(response)
            
            return plan_json
            
        except Exception as e:
            logger.error(f"AI planner call failed: {e}")
            return None
    
    def _build_doc_context(self, docs: List[KnowledgeDoc]) -> str:
        """Build context string from knowledge documents"""
        if not docs:
            return "No relevant knowledge documents found."
        
        context_parts = []
        for doc in docs[:10]:  # Limit to top 10 docs
            payloads_preview = doc.payloads[:3] if doc.payloads else []
            context_parts.append(
                f"Doc {doc.id}: {doc.title}\n"
                f"Category: {doc.category}\n"
                f"Content: {doc.content[:200]}...\n"
                f"Sample Payloads: {payloads_preview}\n"
            )
        
        return "\n".join(context_parts)
    
    def _build_planner_prompt(self, fingerprint: Dict[str, Any], 
                            doc_context: str, vuln_classes: List[str] = None) -> str:
        """Build the AI planner prompt with strict schema requirements"""
        
        vuln_classes_str = ", ".join(vuln_classes) if vuln_classes else "all common vulnerability classes"
        tech_stack = ", ".join(fingerprint.get('stack', []))
        params = ", ".join(fingerprint.get('params', []))
        
        return f"""You are a precision vulnerability testing planner. Generate an executable test plan in STRICT JSON format.

TARGET INFORMATION:
URL: {fingerprint.get('base_url', 'N/A')}
Tech Stack: {tech_stack or 'Unknown'}
Parameters: {params or 'Unknown'}
Focus: {vuln_classes_str}

KNOWLEDGE BASE CONTEXT:
{doc_context}

REQUIREMENTS:
1. Generate ONLY valid JSON matching the exact schema below
2. Use payloads from the knowledge base context above
3. Create 3-8 high-priority test actions
4. Each action must have deterministic evidence checks
5. Prioritize actions based on tech stack and knowledge base relevance

STRICT JSON SCHEMA:
{{
  "plan_version": "1.0",
  "target": {{
    "base_url": "{fingerprint.get('base_url', '')}",
    "stack": {json.dumps(fingerprint.get('stack', []))},
    "assumptions": ["string array of assumptions about the target"]
  }},
  "actions": [
    {{
      "id": "act-001",
      "vuln_class": "xss.reflected|sqli.error_based|ssrf|etc",
      "endpoint": "/path/to/endpoint",
      "method": "GET|POST",
      "param": "parameter_name",
      "payloads": ["payload1", "payload2"],
      "mutations": ["urlencode", "double_urlencode"],
      "headers": {{}},
      "evidence_checks": {{
        "reflects_marker": true|false,
        "regex_any": ["regex1", "regex2"],
        "status_any": [200, 500],
        "header_contains": {{}},
        "oob_required": false
      }},
      "priority": 0.9,
      "source_docs": ["doc_id1", "doc_id2"]
    }}
  ],
  "oob": {{
    "enabled": true,
    "collab_url": "https://callback.oastify.com",
    "markers": ["__MARKER__"]
  }},
  "reporting": {{
    "artifacts": ["html", "headers", "screenshot"],
    "min_evidence_score": 0.75
  }}
}}

CRITICAL: Return ONLY the JSON object. No explanations, no markdown formatting, no additional text.

JSON:"""
    
    def _extract_json_from_response(self, response: str) -> Optional[Dict[str, Any]]:
        """Extract and parse JSON from AI response"""
        try:
            # Clean response
            response = response.strip()
            
            # Try to find JSON in response
            json_match = re.search(r'\{.*\}', response, re.DOTALL)
            if json_match:
                json_str = json_match.group(0)
            else:
                json_str = response
            
            # Parse JSON
            return json.loads(json_str)
            
        except json.JSONDecodeError as e:
            logger.error(f"Failed to parse AI response as JSON: {e}")
            logger.debug(f"Response was: {response[:500]}...")
            return None
    
    def _validate_plan_schema(self, plan_json: Dict[str, Any]) -> bool:
        """Validate plan against strict JSON schema"""
        try:
            # Basic jsonschema validation
            import jsonschema
            jsonschema.validate(plan_json, self.plan_schema)
            
            # Additional validation
            actions = plan_json.get('actions', [])
            if not actions:
                logger.error("Plan has no actions")
                return False
            
            # Validate action IDs are unique
            action_ids = [action.get('id', '') for action in actions]
            if len(action_ids) != len(set(action_ids)):
                logger.error("Plan has duplicate action IDs")
                return False
            
            return True
            
        except ImportError:
            # Fallback validation without jsonschema
            return self._basic_schema_validation(plan_json)
        except Exception as e:
            logger.error(f"Schema validation failed: {e}")
            return False
    
    def _basic_schema_validation(self, plan_json: Dict[str, Any]) -> bool:
        """Basic schema validation fallback"""
        required_fields = ['plan_version', 'target', 'actions']
        
        for field in required_fields:
            if field not in plan_json:
                logger.error(f"Missing required field: {field}")
                return False
        
        # Validate actions
        actions = plan_json.get('actions', [])
        if not isinstance(actions, list) or not actions:
            logger.error("Actions must be non-empty list")
            return False
        
        action_required = ['id', 'vuln_class', 'endpoint', 'method', 'param', 'payloads', 'evidence_checks', 'priority']
        
        for i, action in enumerate(actions):
            if not isinstance(action, dict):
                logger.error(f"Action {i} must be object")
                return False
            
            for field in action_required:
                if field not in action:
                    logger.error(f"Action {i} missing field: {field}")
                    return False
        
        return True
    
    def _json_to_plan(self, plan_json: Dict[str, Any]) -> TestPlan:
        """Convert validated JSON to TestPlan object"""
        actions = []
        
        for action_data in plan_json.get('actions', []):
            action = PlanAction(
                id=action_data['id'],
                vuln_class=action_data['vuln_class'],
                endpoint=action_data['endpoint'],
                method=action_data['method'],
                param=action_data['param'],
                payloads=action_data['payloads'],
                mutations=action_data.get('mutations', []),
                headers=action_data.get('headers', {}),
                evidence_checks=action_data['evidence_checks'],
                priority=float(action_data['priority']),
                source_docs=action_data.get('source_docs', [])
            )
            actions.append(action)
        
        return TestPlan(
            plan_version=plan_json['plan_version'],
            target=plan_json['target'],
            actions=actions,
            oob=plan_json.get('oob', {}),
            reporting=plan_json.get('reporting', {})
        )
    
    async def execute_plan_action(self, action: PlanAction, session) -> Dict[str, Any]:
        """
        Execute a single plan action deterministically.
        Returns execution results with evidence.
        """
        results = {
            'action_id': action.id,
            'success': False,
            'evidence': [],
            'artifacts': [],
            'execution_time': 0
        }
        
        start_time = time.time()
        
        try:
            # Import deterministic verifiers
            from deterministic_verifiers import verify_xss, verify_sqli, verify_ssrf, verify_open_redirect
            
            # Route to appropriate verifier based on vuln_class
            evidence = None
            
            if action.vuln_class.startswith('xss'):
                for payload in action.payloads:
                    evidence = await verify_xss(action.endpoint, action.param, payload, session)
                    if evidence:
                        break
            
            elif action.vuln_class.startswith('sqli'):
                for payload in action.payloads:
                    evidence = await verify_sqli(action.endpoint, action.param, payload, session)
                    if evidence:
                        break
            
            elif action.vuln_class == 'ssrf':
                callback_url = action.headers.get('callback_url')
                for payload in action.payloads:
                    evidence = await verify_ssrf(action.endpoint, action.param, callback_url, session)
                    if evidence:
                        break
            
            elif action.vuln_class == 'open_redirect':
                for payload in action.payloads:
                    evidence = await verify_open_redirect(action.endpoint, action.param, session)
                    if evidence:
                        break
            
            if evidence:
                results['success'] = True
                results['evidence'].append({
                    'type': evidence.type,
                    'confidence': evidence.confidence,
                    'details': evidence.details,
                    'markers': evidence.markers,
                    'context': evidence.context
                })
            
        except Exception as e:
            logger.error(f"Plan action execution failed: {e}")
            results['error'] = str(e)
        
        finally:
            results['execution_time'] = time.time() - start_time
        
        return results

# Global planner instance
planner = None

def get_planner(config: Dict[str, Any] = None) -> AIPlanner:
    """Get global AI planner instance"""
    global planner
    if planner is None:
        planner = AIPlanner(config or {})
    return planner

async def generate_test_plan(fingerprint: Dict[str, Any], 
                           vuln_classes: List[str] = None,
                           config: Dict[str, Any] = None) -> Optional[TestPlan]:
    """
    Main API function to generate test plans.
    
    Args:
        fingerprint: Target fingerprint with tech stack, params, etc.
        vuln_classes: Specific vulnerability classes to test
        config: Configuration for AI client
        
    Returns:
        TestPlan object or None if generation fails
    """
    planner_instance = get_planner(config)
    return await planner_instance.generate_plan(fingerprint, vuln_classes)

if __name__ == "__main__":
    # Test the planner
    import asyncio
    logging.basicConfig(level=logging.INFO)
    
    async def test_planner():
        fingerprint = {
            "base_url": "http://192.168.1.42/dvwa/vulnerabilities/sqli/",
            "stack": ["php", "mysql", "apache"],
            "params": ["id", "Submit"],
            "headers": {"Set-Cookie": "security=low"}
        }
        
        plan = await generate_test_plan(
            fingerprint=fingerprint,
            vuln_classes=["sqli.error_based", "xss.reflected"],
            config={"gemini_api_key": "test"}  # Would need real key
        )
        
        if plan:
            print(f"Generated plan with {len(plan.actions)} actions")
            for action in plan.actions:
                print(f"- {action.id}: {action.vuln_class} on {action.param}")
        else:
            print("Plan generation failed")
    
    # Uncomment to test (requires API key)
    # asyncio.run(test_planner())