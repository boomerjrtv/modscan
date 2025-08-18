#!/usr/bin/env python3
"""
Enhanced Wordlist Generator - Dynamic wordlist expansion with variations
Generates plural/singular/tense variations for better directory discovery
"""

import logging
import re
import aiohttp
import asyncio
from typing import List, Set
from pathlib import Path
from urllib.parse import urljoin, urlparse

logger = logging.getLogger("EnhancedWordlistGenerator")

class EnhancedWordlistGenerator:
    """Generate enhanced wordlists with variations for better discovery coverage"""
    
    def __init__(self):
        # Security-focused base terms
        self.security_base_terms = [
            # Core vulnerability terms
            "vulnerability", "exploit", "security", "pentest", "hack",
            "backdoor", "shell", "payload", "injection", "xss", "csrf",
            "lfi", "rfi", "sqli", "rce", "xxe", "ssrf", "idor",
            
            # Security testing terms  
            "test", "demo", "example", "sample", "proof", "poc",
            "verify", "check", "validate", "audit", "scan",
            
            # Development/staging terms
            "dev", "development", "staging", "test", "testing",
            "debug", "prototype", "beta", "alpha", "experimental",
            
            # Admin/management terms
            "admin", "administrator", "management", "config", "settings",
            "panel", "dashboard", "control", "monitor", "status",
            
            # File/data terms
            "backup", "data", "database", "file", "upload", "download",
            "export", "import", "archive", "temp", "temporary",
            
            # API/service terms
            "api", "service", "endpoint", "webhook", "callback",
            "rest", "soap", "graphql", "json", "xml",
            
            # Documentation terms
            "doc", "docs", "documentation", "help", "readme",
            "manual", "guide", "tutorial", "example", "demo"
        ]
        
        # Common directory patterns
        self.directory_patterns = [
            "www", "web", "site", "portal", "app", "application",
            "public", "private", "internal", "external", "secure",
            "old", "new", "legacy", "current", "latest", "backup"
        ]
        
        # File extensions to try
        self.extensions = ["", ".php", ".asp", ".aspx", ".jsp", ".html", ".htm"]
        
        # JavaScript path extraction patterns
        self.js_path_patterns = [
            # API endpoints
            r'["\'](?:api/|/api/)[^"\']*["\']',
            r'["\'](?:endpoint[s]?["\']?\s*[:=]\s*["\'])[^"\']+["\']',
            
            # Route patterns
            r'["\'](?:route[s]?["\']?\s*[:=]\s*["\'])[^"\']+["\']',
            r'["\'](?:path[s]?["\']?\s*[:=]\s*["\'])[^"\']+["\']',
            r'["\'](?:url[s]?["\']?\s*[:=]\s*["\'])[^"\']+["\']',
            
            # Directory-like strings in JS
            r'["\'][a-zA-Z0-9_-]+/[a-zA-Z0-9_/-]+["\']',
            
            # Function names that might be directories
            r'function\s+([a-zA-Z_][a-zA-Z0-9_]*)',
            r'([a-zA-Z_][a-zA-Z0-9_]*)\s*:\s*function',
            
            # Object keys that might be paths
            r'["\']([a-zA-Z_][a-zA-Z0-9_/-]*)["\']:\s*[{\[]',
            
            # AJAX/fetch URLs
            r'(?:fetch|ajax|get|post)\(["\']([^"\']+)["\']',
            r'(?:url|URL)["\']?\s*[:=]\s*["\']([^"\']+)["\']',
            
            # Configuration objects
            r'baseURL["\']?\s*[:=]\s*["\']([^"\']+)["\']',
            r'apiUrl["\']?\s*[:=]\s*["\']([^"\']+)["\']',
        ]
        
        logger.info("🔤 Enhanced Wordlist Generator initialized with JS path extraction")
    
    def generate_variations(self, base_word: str) -> Set[str]:
        """Generate all variations of a base word"""
        variations = set()
        
        # Add base word
        variations.add(base_word)
        
        # Plural/singular variations
        variations.update(self._generate_plural_singular(base_word))
        
        # Tense variations
        variations.update(self._generate_tense_variations(base_word))
        
        # Common prefixes/suffixes
        variations.update(self._generate_prefix_suffix_variations(base_word))
        
        # Abbreviations and short forms
        variations.update(self._generate_abbreviations(base_word))
        
        return variations
    
    def _generate_plural_singular(self, word: str) -> Set[str]:
        """Generate plural/singular variations"""
        variations = set()
        
        # If word ends in 'y', try 'ies'
        if word.endswith('y') and len(word) > 1:
            variations.add(word[:-1] + "ies")
        
        # If word ends in 's', try without 's' (singular)
        if word.endswith('s') and len(word) > 1:
            variations.add(word[:-1])
        
        # Add 's' for plural
        if not word.endswith('s'):
            variations.add(word + "s")
        
        # Special cases
        if word == "vulnerability":
            variations.update(["vulnerabilities", "vuln", "vulns"])
        elif word == "exploit":
            variations.update(["exploits", "exp", "exps"])
        elif word == "test":
            variations.update(["tests", "testing", "tester"])
        elif word == "admin":
            variations.update(["admins", "administrator", "administrators"])
        
        return variations
    
    def _generate_tense_variations(self, word: str) -> Set[str]:
        """Generate tense variations (past, present, future)"""
        variations = set()
        
        # Present -> past tense (add 'ed')
        if not word.endswith('ed') and not word.endswith('ing'):
            variations.add(word + "ed")
        
        # Present -> continuous (add 'ing')
        if not word.endswith('ing'):
            if word.endswith('e'):
                variations.add(word[:-1] + "ing")
            else:
                variations.add(word + "ing")
        
        # Special cases
        if word in ["test", "scan", "check", "verify"]:
            variations.update([word + "ed", word + "ing", word + "er"])
        
        return variations
    
    def _generate_prefix_suffix_variations(self, word: str) -> Set[str]:
        """Generate prefix/suffix variations"""
        variations = set()
        
        # Common prefixes
        prefixes = ["old", "new", "temp", "backup", "test", "dev", "staging"]
        for prefix in prefixes:
            variations.add(f"{prefix}_{word}")
            variations.add(f"{prefix}-{word}")
            variations.add(f"{prefix}{word}")
        
        # Common suffixes  
        suffixes = ["old", "new", "bak", "backup", "test", "dev", "staging", "prod"]
        for suffix in suffixes:
            variations.add(f"{word}_{suffix}")
            variations.add(f"{word}-{suffix}")
            variations.add(f"{word}{suffix}")
        
        # Version numbers
        for i in range(1, 4):
            variations.add(f"{word}{i}")
            variations.add(f"{word}_{i}")
            variations.add(f"{word}-{i}")
            variations.add(f"{word}v{i}")
        
        return variations
    
    def _generate_abbreviations(self, word: str) -> Set[str]:
        """Generate abbreviations and short forms"""
        variations = set()
        
        # First letters abbreviation
        if len(word) > 3:
            # Take first 3 letters
            variations.add(word[:3])
            # Take first 4 letters
            if len(word) > 4:
                variations.add(word[:4])
        
        # Remove vowels abbreviation
        consonants = ''.join([c for c in word if c.lower() not in 'aeiou'])
        if len(consonants) > 1 and consonants != word:
            variations.add(consonants)
        
        # Common security abbreviations
        abbreviations = {
            "vulnerability": ["vuln", "vul"],
            "exploitation": ["exploit", "exp"],
            "administration": ["admin", "adm"],
            "configuration": ["config", "cfg"],
            "application": ["app"],
            "development": ["dev"],
            "testing": ["test"],
            "security": ["sec"],
            "authentication": ["auth"],
            "authorization": ["authz"],
            "documentation": ["doc", "docs"]
        }
        
        if word in abbreviations:
            variations.update(abbreviations[word])
        
        return variations
    
    async def extract_paths_from_javascript(self, js_content: str) -> Set[str]:
        """Extract potential paths and endpoints from JavaScript content"""
        extracted_paths = set()
        
        # Apply all regex patterns
        for pattern in self.js_path_patterns:
            matches = re.findall(pattern, js_content, re.IGNORECASE)
            for match in matches:
                if isinstance(match, tuple):
                    # If regex has groups, take the first group
                    path = match[0] if match[0] else match[1] if len(match) > 1 else ""
                else:
                    path = match
                
                # Clean up the path
                path = path.strip('\'"/')
                
                # Filter out obvious non-paths
                if self._is_valid_path(path):
                    extracted_paths.add(path)
                    
                    # Also add path components as potential directories
                    path_parts = path.split('/')
                    for part in path_parts:
                        if part and len(part) > 2 and part.isalnum():
                            extracted_paths.add(part)
        
        # Extract quoted strings that look like paths
        quoted_strings = re.findall(r'["\']([a-zA-Z0-9_/-]{3,})["\']', js_content)
        for string in quoted_strings:
            if '/' in string and self._is_valid_path(string):
                extracted_paths.add(string.strip('/'))
        
        logger.info(f"🔍 Extracted {len(extracted_paths)} potential paths from JavaScript")
        return extracted_paths
    
    def _is_valid_path(self, path: str) -> bool:
        """Check if extracted string looks like a valid path"""
        if not path or len(path) < 2:
            return False
        
        # Skip common non-path strings
        skip_patterns = [
            'http', 'https', 'ftp', 'mailto', 'javascript', 'data:',
            'function', 'return', 'var', 'let', 'const', 'if', 'else',
            'true', 'false', 'null', 'undefined', 'NaN', 'window', 'document',
            'console', 'alert', 'confirm', 'prompt'
        ]
        
        path_lower = path.lower()
        if any(skip in path_lower for skip in skip_patterns):
            return False
        
        # Must contain alphanumeric characters
        if not re.search(r'[a-zA-Z0-9]', path):
            return False
        
        # Looks like a path if it has slashes or is a reasonable directory name
        if '/' in path or (len(path) > 2 and path.replace('_', '').replace('-', '').isalnum()):
            return True
        
        return False
    
    async def fetch_and_parse_javascript(self, base_url: str, js_paths: List[str]) -> Set[str]:
        """Fetch JavaScript files and extract paths from them"""
        all_extracted_paths = set()
        
        async with aiohttp.ClientSession() as session:
            for js_path in js_paths:
                try:
                    js_url = urljoin(base_url, js_path)
                    logger.info(f"🔍 Parsing JavaScript: {js_url}")
                    
                    async with session.get(js_url, timeout=10) as response:
                        if response.status == 200:
                            js_content = await response.text()
                            extracted = await self.extract_paths_from_javascript(js_content)
                            all_extracted_paths.update(extracted)
                            
                            logger.info(f"✅ Extracted {len(extracted)} paths from {js_path}")
                        else:
                            logger.debug(f"❌ Could not fetch {js_url}: HTTP {response.status}")
                            
                except Exception as e:
                    logger.debug(f"❌ Error parsing {js_path}: {e}")
        
        return all_extracted_paths
    
    async def generate_wordlist_from_target(self, target_url: str, discovered_js_files: List[str] = None) -> List[str]:
        """Generate comprehensive wordlist for a specific target including JS analysis"""
        
        # Start with domain-specific wordlist
        parsed_url = urlparse(target_url)
        domain = parsed_url.netloc
        base_wordlist = self.generate_domain_specific_wordlist(domain)
        
        # Extract paths from JavaScript if provided
        js_extracted_paths = set()
        if discovered_js_files:
            logger.info(f"🔍 Analyzing {len(discovered_js_files)} JavaScript files for paths...")
            js_extracted_paths = await self.fetch_and_parse_javascript(target_url, discovered_js_files)
        
        # Generate variations for all JS-extracted terms
        js_variations = set()
        for path in js_extracted_paths:
            js_variations.update(self.generate_variations(path))
        
        # Combine all wordlists
        combined_wordlist = set(base_wordlist)
        combined_wordlist.update(js_extracted_paths)
        combined_wordlist.update(js_variations)
        
        final_wordlist = sorted(list(combined_wordlist))
        
        logger.info(f"🎯 Generated target-specific wordlist: {len(final_wordlist)} terms")
        logger.info(f"   Base security terms: {len(base_wordlist)}")
        logger.info(f"   JS extracted paths: {len(js_extracted_paths)}")
        logger.info(f"   JS path variations: {len(js_variations)}")
        
        return final_wordlist
    
    def generate_security_wordlist(self, target_specific_terms: List[str] = None) -> List[str]:
        """Generate comprehensive security-focused wordlist"""
        all_words = set()
        
        # Add base security terms
        for term in self.security_base_terms:
            all_words.update(self.generate_variations(term))
        
        # Add directory patterns
        for pattern in self.directory_patterns:
            all_words.update(self.generate_variations(pattern))
        
        # Add target-specific terms if provided
        if target_specific_terms:
            for term in target_specific_terms:
                all_words.update(self.generate_variations(term))
        
        # Add extensions to some terms
        extended_words = set(all_words)
        for word in list(all_words):
            if not any(word.endswith(ext) for ext in self.extensions):
                for ext in self.extensions:
                    if ext:  # Skip empty extension
                        extended_words.add(word + ext)
        
        # Convert to sorted list
        wordlist = sorted(list(extended_words))
        
        logger.info(f"🔤 Generated enhanced wordlist: {len(wordlist)} terms from {len(self.security_base_terms)} base terms")
        
        return wordlist
    
    def generate_domain_specific_wordlist(self, domain: str) -> List[str]:
        """Generate wordlist specific to a domain/application"""
        target_terms = []
        
        # Extract potential terms from domain
        domain_parts = domain.replace('.', '_').replace('-', '_').split('_')
        target_terms.extend([part for part in domain_parts if len(part) > 2])
        
        # Add common terms based on domain patterns
        if any(term in domain.lower() for term in ['bank', 'finance', 'pay']):
            target_terms.extend(['account', 'transaction', 'payment', 'balance'])
        
        if any(term in domain.lower() for term in ['shop', 'store', 'ecommerce']):
            target_terms.extend(['cart', 'checkout', 'product', 'order'])
        
        if any(term in domain.lower() for term in ['health', 'medical', 'hospital']):
            target_terms.extend(['patient', 'record', 'appointment', 'prescription'])
        
        return self.generate_security_wordlist(target_terms)
    
    def save_wordlist(self, wordlist: List[str], filename: str) -> str:
        """Save wordlist to file"""
        output_path = Path(filename)
        
        with open(output_path, 'w') as f:
            for word in wordlist:
                f.write(word + '\n')
        
        logger.info(f"💾 Saved enhanced wordlist: {len(wordlist)} terms to {output_path}")
        return str(output_path)

# Example usage and testing
if __name__ == "__main__":
    generator = EnhancedWordlistGenerator()
    
    # Generate general security wordlist
    security_wordlist = generator.generate_security_wordlist()
    print(f"Generated {len(security_wordlist)} security terms")
    
    # Show some examples
    print("\nSample variations for 'vulnerability':")
    vuln_variations = generator.generate_variations("vulnerability")
    for var in sorted(vuln_variations)[:20]:  # Show first 20
        print(f"  {var}")
    
    # Save to file
    output_file = generator.save_wordlist(security_wordlist, "enhanced_security_wordlist.txt")
    print(f"\nWordlist saved to: {output_file}")