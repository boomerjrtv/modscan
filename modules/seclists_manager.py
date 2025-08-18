import os
#!/usr/bin/env python3
"""
SecLists Manager Module - Comprehensive wordlist integration like lean_scanner
Provides intelligent wordlist selection based on target analysis and technology detection
"""

import logging
import subprocess
from pathlib import Path
from typing import List, Dict, Optional
import random

logger = logging.getLogger("SecListsManager")

class SecListsManager:
    """Advanced SecLists integration for comprehensive target discovery"""
    
    def __init__(self, asset_manager, config: Dict):
        self.asset_manager = asset_manager
        self.config = config
        self.seclists_path = Path(__file__).parent.parent / "SecLists"
        self.wordlists = {}
        
        logger.info("🔍 SecListsManager initialized for intelligent wordlist management")
    
    async def initialize(self):
        """Initialize SecLists manager"""
        try:
            # Download SecLists if needed
            await self.ensure_seclists_available()
            
            # Load comprehensive wordlists
            self.load_comprehensive_wordlists()
            
            # Log initialization
            self.asset_manager.log_activity(
                'SECLISTS_INIT',
                f'SecLists manager initialized with {len(self.wordlists)} wordlist categories'
            )
            
            logger.info("✅ SecListsManager initialization complete")
            
        except Exception as e:
            logger.error(f"SecListsManager initialization failed: {e}")
    
    async def ensure_seclists_available(self):
        """Ensure SecLists repository is available"""
        if not self.seclists_path.exists():
            logger.info("🔽 Downloading SecLists repository...")
            try:
                subprocess.run([
                    "git", "clone", "--depth", "1",
                    "https://github.com/danielmiessler/SecLists.git",
                    str(self.seclists_path)
                ], check=True, capture_output=True)
                logger.info("✅ SecLists downloaded successfully")
            except subprocess.CalledProcessError as e:
                logger.warning(f"Failed to download SecLists: {e}")
        else:
            logger.info("✅ SecLists already available")
    
    def load_comprehensive_wordlists(self):
        """Load comprehensive wordlists for all discovery types"""
        
        # Comprehensive SecLists wordlist mappings - MUCH more extensive than lean_scanner
        wordlist_configs = {
            'subdomains': [
                'Discovery/DNS/subdomains-top1million-20000.txt',
                'Discovery/DNS/subdomains-top1million-5000.txt', 
                'Discovery/DNS/deepmagic.com-prefixes-top500.txt',
                'Discovery/DNS/fierce-hostlist.txt',
                'Discovery/DNS/namelist.txt'
            ],
            'directories': [
                'Discovery/Web-Content/directory-list-2.3-big.txt',
                'Discovery/Web-Content/directory-list-2.3-medium.txt',
                'Discovery/Web-Content/directory-list-2.3-small.txt',
                'Discovery/Web-Content/raft-large-directories.txt',
                'Discovery/Web-Content/raft-medium-directories.txt',
                'Discovery/Web-Content/quickhits.txt'
            ],
            'files': [
                'Discovery/Web-Content/raft-large-files.txt',
                'Discovery/Web-Content/raft-medium-files.txt', 
                'Discovery/Web-Content/raft-small-files.txt',
                'Discovery/Web-Content/common.txt',
                'Discovery/Web-Content/web-extensions.txt',
                'Discovery/Web-Content/quickhits.txt'
            ],
            'parameters': [
                'Discovery/Web-Content/burp-parameter-names.txt',
                'Discovery/Web-Content/web-mutations.txt',
                'Fuzzing/LFI/LFI-gracefulsecurity-linux.txt'
            ],
            'api_endpoints': [
                'Discovery/Web-Content/common-api-endpoints-mazen160.txt',
                'Discovery/Web-Content/graphql.txt',
                'Discovery/Web-Content/swagger.txt'
            ],
            'admin_paths': [
                'Discovery/Web-Content/Logins.fuzz.txt',
                'Discovery/Web-Content/default-web-root-directory-linux.txt',
                'Discovery/Web-Content/default-web-root-directory-windows.txt',
                'Discovery/Web-Content/CMS/wordpress.fuzz.txt',
                'Discovery/Web-Content/CMS/drupal.txt',
                'Discovery/Web-Content/CMS/joomla.txt'
            ],
            'common': [
                'Discovery/Web-Content/common.txt',
                'Discovery/Web-Content/big.txt',
                'Discovery/Web-Content/quickhits.txt'
            ],
            'web_content': [
                'Discovery/Web-Content/directory-list-lowercase-2.3-medium.txt',
                'Discovery/Web-Content/directory-list-uppercase-2.3-medium.txt', 
                'Discovery/Web-Content/raft-medium-words-lowercase.txt',
                'Discovery/Web-Content/raft-medium-words.txt'
            ]
        }
        
        # Load wordlists - try specific paths first, then scan SecLists dynamically
        for category, file_paths in wordlist_configs.items():
            self.wordlists[category] = []
            
            # Try specific known paths first
            for file_path in file_paths:
                full_path = self.seclists_path / file_path
                
                if full_path.exists():
                    try:
                        with open(full_path, 'r', encoding='utf-8', errors='ignore') as f:
                            words = [line.strip() for line in f if line.strip() and not line.startswith('#')]
                            self.wordlists[category].extend(words[:5000])  # Limit per file for performance
                            logger.info(f"📋 Loaded {len(words)} words from {file_path}")
                    except Exception as e:
                        logger.debug(f"Failed to load {file_path}: {e}")
                else:
                    logger.debug(f"Wordlist not found: {file_path}")
            
            # If we didn't get enough words from specific paths, scan SecLists dynamically  
            if len(self.wordlists[category]) < 100:
                logger.info(f"🔍 Scanning SecLists for more {category} wordlists...")
                fallback_words = self._get_fallback_wordlist(category)
                self.wordlists[category].extend(fallback_words)
            
            # Remove duplicates and limit size
            self.wordlists[category] = list(set(self.wordlists[category]))[:3000]
            logger.info(f"📋 Final loaded: {len(self.wordlists[category])} {category} entries")
    
    def _get_fallback_wordlist(self, category: str) -> List[str]:
        """Get wordlist by scanning SecLists directory structure directly - NO HARDCODING!"""
        
        if not self.seclists_path.exists():
            logger.warning(f"SecLists not available at {self.seclists_path}")
            return []
        
        # Search for relevant wordlists in SecLists based on category
        category_mappings = {
            'subdomains': ['DNS', 'Subdomain'],
            'directories': ['Web-Content', 'directory'],  
            'files': ['Web-Content', 'file'],
            'parameters': ['Web-Content', 'parameter'],
            'api_endpoints': ['Web-Content', 'api'],
            'admin_paths': ['Web-Content', 'admin']
        }
        
        search_terms = category_mappings.get(category, [])
        found_wordlists = []
        
        # Recursively search SecLists for relevant files
        for search_term in search_terms:
            for wordlist_file in self.seclists_path.rglob('*.txt'):
                if search_term.lower() in str(wordlist_file).lower():
                    try:
                        with open(wordlist_file, 'r', encoding='utf-8', errors='ignore') as f:
                            words = [line.strip() for line in f if line.strip() and not line.startswith('#')]
                            found_wordlists.extend(words[:1000])  # Limit per file
                            logger.debug(f"Loaded {len(words)} words from {wordlist_file}")
                            break  # Use first match to avoid duplicates
                    except Exception as e:
                        logger.debug(f"Failed to load {wordlist_file}: {e}")
        
        # If still no results, search more broadly
        if not found_wordlists:
            logger.info(f"Scanning SecLists for {category} wordlists...")
            for wordlist_file in self.seclists_path.rglob('*.txt'):
                filename = wordlist_file.name.lower()
                if any(term in filename for term in [category, category[:-1]]):  # category or singular
                    try:
                        with open(wordlist_file, 'r', encoding='utf-8', errors='ignore') as f:
                            words = [line.strip() for line in f if line.strip() and not line.startswith('#')]
                            found_wordlists.extend(words[:500])
                            logger.info(f"Found {len(words)} {category} from {wordlist_file.name}")
                            if len(found_wordlists) > 1000:  # Stop when we have enough
                                break
                    except Exception as e:
                        logger.debug(f"Failed to load {wordlist_file}: {e}")
        
        return list(set(found_wordlists))[:2000]  # Dedupe and limit
    
    def get_intelligent_wordlist(self, target_info: Dict, wordlist_type: str, limit: int = 500) -> List[str]:
        """Intelligently select and combine SecLists wordlists based on target analysis"""
        
        domain = target_info.get('domain', '')
        technologies = target_info.get('technologies', [])
        tech_keywords = ' '.join(technologies).lower()
        
        # Dynamic wordlist selection based on target intelligence
        selected_wordlists = []
        
        if wordlist_type == 'directories':
            selected_wordlists = self._get_directory_wordlists_for_target(domain, tech_keywords)
        elif wordlist_type == 'files':
            selected_wordlists = self._get_file_wordlists_for_target(domain, tech_keywords)
        elif wordlist_type == 'admin_paths':
            selected_wordlists = self._get_admin_wordlists_for_target(domain, tech_keywords)
        elif wordlist_type == 'api_endpoints':
            selected_wordlists = self._get_api_wordlists_for_target(domain, tech_keywords)
        else:
            # Fallback to standard wordlists
            selected_wordlists = [wordlist_type]
        
        # Combine words from selected SecLists files
        combined_words = []
        for wordlist_category in selected_wordlists:
            category_words = self.wordlists.get(wordlist_category, [])
            combined_words.extend(category_words)
        
        # If no category words found, scan SecLists dynamically
        if not combined_words:
            combined_words = self._scan_seclists_for_target(target_info, wordlist_type)
        
        # Score and filter words based on target relevance
        scored_words = []
        for word in combined_words:
            score = self._score_wordlist_entry(word, domain, technologies, wordlist_type)
            if score > 0.1:  # Only include relevant entries
                scored_words.append((word, score))
        
        # Sort by relevance and return top entries
        scored_words.sort(key=lambda x: x[1], reverse=True)
        selected_words = [word for word, score in scored_words[:limit]]
        
        logger.info(f"🎯 Selected {len(selected_words)} intelligent {wordlist_type} for {domain} (from {len(selected_wordlists)} SecLists)")
        return selected_words
    
    def get_payloads(self, payload_type: str, limit: int = 100) -> List[str]:
        """Get payloads from SecLists for vulnerability testing"""
        payloads = self.wordlists.get(payload_type, [])
        
        if not payloads:
            # Try alternate names or scan dynamically
            alt_names = {
                'sqli_payloads': ['sql_injection', 'sqli', 'sql'],
                'xss_payloads': ['xss', 'cross_site_scripting'],
                'lfi_payloads': ['lfi', 'local_file_inclusion'],
                'parameters': ['parameter_names', 'web_parameters']
            }
            
            for alt_name in alt_names.get(payload_type, []):
                payloads = self.wordlists.get(alt_name, [])
                if payloads:
                    break
        
        # Return limited, shuffled payloads for better coverage
        if payloads:
            import random
            random.shuffle(payloads)
            return payloads[:limit]
        
        return []
    
    def get_context_aware_payloads(self, vuln_type: str, context: str, limit: int = 50) -> List[str]:
        """Get context-aware payloads for specific vulnerability types"""
        base_payloads = self.get_payloads(f'{vuln_type}_payloads', limit * 2)
        
        # Filter payloads based on context
        context_filtered = []
        for payload in base_payloads:
            if context == 'generic' or context.lower() in payload.lower():
                context_filtered.append(payload)
        
        return context_filtered[:limit]
    
    def _get_directory_wordlists_for_target(self, domain: str, tech_keywords: str) -> List[str]:
        """Select directory wordlists based on target technology"""
        wordlists = ['directories', 'common', 'web_content']  # Always include base
        
        # Technology-specific directory lists
        if 'wordpress' in tech_keywords:
            wordlists.extend(['admin_paths'])  # WordPress admin paths
        if 'drupal' in tech_keywords:
            wordlists.extend(['admin_paths'])
        if 'api' in domain.lower() or 'api' in tech_keywords:
            wordlists.extend(['api_endpoints'])
        if any(cms in tech_keywords for cms in ['wordpress', 'drupal', 'joomla']):
            wordlists.extend(['admin_paths'])
            
        return list(set(wordlists))  # Remove duplicates
    
    def _get_file_wordlists_for_target(self, domain: str, tech_keywords: str) -> List[str]:
        """Select file wordlists based on target technology"""
        wordlists = ['files', 'common']  # Always include base
        
        # Technology-specific file lists
        if 'php' in tech_keywords:
            wordlists.extend(['admin_paths'])  # PHP admin files
        if 'asp' in tech_keywords or 'iis' in tech_keywords:
            wordlists.extend(['admin_paths'])  # ASP files
        if 'python' in tech_keywords or 'django' in tech_keywords:
            wordlists.extend(['api_endpoints'])  # Python-specific files
            
        return list(set(wordlists))
    
    def _get_admin_wordlists_for_target(self, domain: str, tech_keywords: str) -> List[str]:
        """Select admin wordlists based on target technology"""
        wordlists = ['admin_paths', 'directories']
        
        # CMS-specific admin paths
        if 'wordpress' in tech_keywords:
            wordlists.extend(['files'])  # WordPress files
        if 'drupal' in tech_keywords:
            wordlists.extend(['files'])
        if 'api' in tech_keywords:
            wordlists.extend(['api_endpoints'])
            
        return list(set(wordlists))
    
    def _get_api_wordlists_for_target(self, domain: str, tech_keywords: str) -> List[str]:
        """Select API wordlists based on target technology"""
        wordlists = ['api_endpoints', 'parameters']
        
        # Framework-specific API paths
        if 'rest' in tech_keywords or 'restful' in tech_keywords:
            wordlists.extend(['directories'])
        if 'graphql' in tech_keywords:
            wordlists.extend(['parameters'])
        if 'swagger' in tech_keywords or 'openapi' in tech_keywords:
            wordlists.extend(['files'])
            
        return list(set(wordlists))
    
    def _scan_seclists_for_target(self, target_info: Dict, wordlist_type: str) -> List[str]:
        """Dynamically scan SecLists for target-specific wordlists using grep-like intelligence"""
        if not self.seclists_path.exists():
            return []
        
        domain = target_info.get('domain', '')
        technologies = target_info.get('technologies', [])
        
        # Technology-specific SecLists search patterns
        search_patterns = {
            'wordpress': ['wp', 'wordpress', 'CMS/wordpress'],
            'drupal': ['drupal', 'CMS/drupal'],
            'joomla': ['joomla', 'CMS/joomla'],
            'php': ['php', 'web-content'],
            'api': ['api', 'rest', 'graphql'],
            'admin': ['admin', 'login', 'management']
        }
        
        found_words = []
        
        # Search for technology-specific wordlists
        for tech in technologies:
            tech_lower = tech.lower()
            patterns = search_patterns.get(tech_lower, [tech_lower])
            
            for pattern in patterns:
                # Search SecLists files containing the pattern
                for wordlist_file in self.seclists_path.rglob('*.txt'):
                    if pattern in str(wordlist_file).lower():
                        try:
                            with open(wordlist_file, 'r', encoding='utf-8', errors='ignore') as f:
                                words = [line.strip() for line in f if line.strip() and not line.startswith('#')]
                                found_words.extend(words[:500])  # Limit per file
                                logger.info(f"🔍 Found {len(words)} words from {wordlist_file.name} for {tech}")
                                break  # Use first match per pattern
                        except Exception as e:
                            logger.debug(f"Failed to load {wordlist_file}: {e}")
        
        return list(set(found_words))[:1000]  # Dedupe and limit
    
    def _score_wordlist_entry(self, word: str, domain: str, technologies: List[str], wordlist_type: str) -> float:
        """Score wordlist entry relevance based on target analysis"""
        score = 0.3  # Base score
        word_lower = word.lower()
        domain_lower = domain.lower()
        tech_keywords = ' '.join(technologies).lower()
        
        # High-value entries
        high_value_words = {
            'subdomains': ['www', 'api', 'admin', 'app', 'mobile', 'dev', 'mail'],
            'directories': ['/admin/', '/api/', '/login/', '/dashboard/', '/app/'],
            'files': ['admin.php', 'login.php', 'config.php', 'index.php', 'robots.txt'],
            'parameters': ['id', 'user', 'password', 'token', 'api_key', 'search'],
            'api_endpoints': ['/api/', '/rest/', '/graphql/', '/api/v1/', '/api/users/'],
            'admin_paths': ['/admin/', '/administrator/', '/dashboard/', '/panel/']
        }
        
        if word_lower in [w.lower() for w in high_value_words.get(wordlist_type, [])]:
            score += 0.5
        
        # Technology-specific scoring
        if 'wordpress' in tech_keywords and 'wp' in word_lower:
            score += 0.6
        if 'drupal' in tech_keywords and 'drupal' in word_lower:
            score += 0.6
        if 'joomla' in tech_keywords and ('joomla' in word_lower or 'administrator' in word_lower):
            score += 0.6
        if 'django' in tech_keywords and ('admin' in word_lower or 'api' in word_lower):
            score += 0.5
        if 'react' in tech_keywords and ('app' in word_lower or 'api' in word_lower):
            score += 0.4
        
        # Domain-based scoring
        if 'shop' in domain_lower and any(kw in word_lower for kw in ['cart', 'checkout', 'payment', 'order']):
            score += 0.4
        if 'api' in domain_lower and wordlist_type == 'api_endpoints':
            score += 0.3
        if 'admin' in domain_lower and 'admin' in word_lower:
            score += 0.3
        
        # Common security-relevant entries
        security_words = ['admin', 'login', 'auth', 'api', 'config', 'backup', 'test', 'debug']
        if any(sec_word in word_lower for sec_word in security_words):
            score += 0.2
        
        return min(score, 1.0)  # Cap at 1.0
SECLISTS_BASE = os.environ.get('SECLISTS_DIR', os.path.expanduser('~/SecLists'))
