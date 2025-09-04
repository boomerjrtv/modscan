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
        # Resolve SecLists path from config/env/common locations
        candidates = []
        try:
            import os as _os
            # Config-provided path
            if config.get('seclists_path'):
                candidates.append(Path(config.get('seclists_path')))
            # Common env vars
            for env_key in ('SECLISTS_PATH', 'SECLISTS_DIR'):
                if _os.environ.get(env_key):
                    candidates.append(Path(_os.environ.get(env_key)))
        except Exception:
            pass
        candidates.extend([
            Path.home() / 'SecLists',
            Path('/usr/share/seclists'),
            Path(__file__).parent.parent / 'SecLists'
        ])
        self.seclists_path = next((p for p in candidates if p.exists()), candidates[-1])
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
            logger.warning(f"SecLists not found at {self.seclists_path}. Set SECLISTS_PATH or config.seclists_path to an existing copy.")
        else:
            logger.info(f"✅ Using SecLists at {self.seclists_path}")
    
    def load_comprehensive_wordlists(self):
        """Load comprehensive wordlists for all discovery types"""
        import os as _os
        # Comprehensive tiered SecLists wordlist configuration with deduplication
        # Tiers: surface -> standard -> deep -> comprehensive
        wordlist_configs = {
            'subdomains': {
                'surface': ['Discovery/DNS/subdomains-top1million-5000.txt', 'Discovery/DNS/FUZZSUBS_CYFARE_1.txt'],  # Universal subdomain discovery
                'standard': ['Discovery/DNS/subdomains-top1million-20000.txt'],  # 20K 
                'deep': ['Discovery/DNS/subdomains-top1million-110000.txt'],  # 110K+
                'comprehensive': ['Discovery/DNS/namelist.txt', 'Discovery/DNS/bitquark-subdomains-top100000.txt', 'Discovery/DNS/dns-Jhaddix.txt']
            },
            'directories': {
                'surface': ['Discovery/Web-Content/quickhits.txt', 'Discovery/Web-Content/raft-small-directories.txt'],  # ~30K
                'standard': ['Discovery/Web-Content/directory-list-2.3-small.txt', 'Discovery/Web-Content/raft-medium-directories.txt'],  # ~120K
                'deep': ['Discovery/Web-Content/directory-list-2.3-medium.txt', 'Discovery/Web-Content/raft-large-directories.txt'],  # ~280K
                'comprehensive': ['Discovery/Web-Content/directory-list-2.3-big.txt', 'Discovery/Web-Content/combined_directories.txt']  # 1.2M+
            },
            'files': {
                'surface': ['Discovery/Web-Content/raft-small-files.txt'],  # 11K
                'standard': ['Discovery/Web-Content/raft-medium-files.txt', 'Discovery/Web-Content/common.txt'],  # ~20K
                'deep': ['Discovery/Web-Content/raft-large-files.txt', 'Discovery/Web-Content/web-extensions.txt'],  # ~40K
                'comprehensive': ['Discovery/Web-Content/versioning_metafiles.txt', 'Discovery/Web-Content/UnixDotfiles.fuzz.txt']
            },
            'admin_paths': {
                'surface': ['Discovery/Web-Content/Logins.fuzz.txt'],
                'standard': ['Discovery/Web-Content/default-web-root-directory-linux.txt', 'Discovery/Web-Content/default-web-root-directory-windows.txt'],
                'deep': ['Discovery/Web-Content/File-Extensions-Universal-SVNDigger-Project/context/admin.txt'],
                'comprehensive': ['Discovery/Web-Content/Service-Specific/confluence-administration.txt']
            },
            'api_endpoints': {
                'surface': ['Discovery/Web-Content/common-api-endpoints-mazen160.txt'],
                'standard': ['Discovery/Web-Content/graphql.txt', 'Discovery/Web-Content/swagger.txt'],
                'deep': ['Discovery/Web-Content/oauth-oidc-scopes.txt'],
                'comprehensive': []
            },
            'parameters': {
                'surface': ['Discovery/Web-Content/burp-parameter-names.txt'],
                'standard': ['Discovery/Web-Content/url-params_from-top-55-most-popular-apps.txt'],
                'deep': ['Discovery/Web-Content/web-mutations.txt'],
                'comprehensive': ['Fuzzing/LFI/LFI-gracefulsecurity-linux.txt']
            },
            'cms_specific': {
                'wordpress': ['Discovery/Web-Content/CMS/wordpress.fuzz.txt'],
                'drupal': ['Discovery/Web-Content/CMS/drupal.txt'],
                'joomla': ['Discovery/Web-Content/CMS/joomla.txt'],
                'django': ['Discovery/Web-Content/Common-WordPress.txt'],
                'umbraco': ['Discovery/Web-Content/Common-CMS.txt']
            },
            'backup_files': {
                'surface': ['Discovery/Web-Content/Common-DB-Backups.txt'],
                'standard': ['Discovery/Web-Content/versioning_metafiles.txt'],
                'deep': ['Discovery/Web-Content/LinuxFileList.txt']
            },
            'technology_specific': {
                'java': ['Discovery/Web-Content/JavaServlets-Common.fuzz.txt'],
                'oracle': ['Discovery/Web-Content/Oracle9i.fuzz.txt', 'Discovery/Web-Content/OracleAppServer.fuzz.txt'],
                'microsoft': ['Discovery/Web-Content/Microsoft-Frontpage.txt'],
                'adobe': ['Discovery/Web-Content/AdobeXML.fuzz.txt']
            }
        }
        
        # Track loaded words per tier for deduplication
        self.tier_tracking = {}
        
        # Helper: determine scan tier based on desired coverage depth  
        def _get_scan_tier(desired_count: int, scan_depth: str = 'auto') -> str:
            if scan_depth != 'auto':
                return scan_depth
            
            if desired_count <= 10000:
                return 'surface'  # Fast, high-value targets
            elif desired_count <= 50000:
                return 'standard'  # Balanced coverage
            elif desired_count <= 200000:
                return 'deep'  # Thorough scanning
            else:
                return 'comprehensive'  # Maximum coverage
                
        # Helper: load wordlist with tier-based deduplication
        def _load_wordlist_tier(category: str, tier: str, previous_tiers: list = None) -> list:
            if previous_tiers is None:
                previous_tiers = []
            
            # Get words from current tier
            tier_words = set()
            tier_configs = wordlist_configs.get(category, {})
            
            if tier not in tier_configs:
                return []
                
            file_paths = tier_configs[tier]
            
            for file_path in file_paths:
                full_path = self.seclists_path / file_path
                if full_path.exists():
                    try:
                        with open(full_path, 'r', encoding='utf-8', errors='ignore') as f:
                            raw_words = [line.strip() for line in f if line.strip() and not line.startswith('#')]
                        
                        # Convert raw words to proper paths for directory categories
                        if category == 'directories':
                            for word in raw_words:
                                if word:
                                    if not word.startswith('/'):
                                        word = '/' + word
                                    word = word.replace('//', '/')
                                    tier_words.add(word)
                        else:
                            tier_words.update(raw_words)
                            
                        logger.info(f"📋 Loaded {len(raw_words)} words from {file_path} [{tier}]")
                    except Exception as e:
                        logger.debug(f"Failed to load {file_path}: {e}")
            
            # Remove words from previous tiers (deduplication)
            for prev_tier in previous_tiers:
                prev_key = f"{category}_{prev_tier}"
                if prev_key in self.tier_tracking:
                    tier_words -= self.tier_tracking[prev_key]
            
            # Store this tier's words for future deduplication
            tier_key = f"{category}_{tier}"
            self.tier_tracking[tier_key] = tier_words.copy()
            
            return list(tier_words)

        # Load wordlists using tiered system with intelligent deduplication
        primary_categories = ['subdomains', 'directories', 'files', 'admin_paths', 'api_endpoints', 'parameters', 'backup_files']
        
        for category in primary_categories:
            self.wordlists[category] = []
            
            # Determine desired coverage based on category and environment
            if category == 'directories':
                desired_count = int(_os.environ.get('MODSCAN_DIR_WORDS_DESIRED', '100000'))
                scan_depth = _os.environ.get('MODSCAN_DIR_SCAN_DEPTH', 'auto')
            elif category == 'files':
                desired_count = int(_os.environ.get('MODSCAN_FILE_WORDS_DESIRED', '30000'))
                scan_depth = _os.environ.get('MODSCAN_FILE_SCAN_DEPTH', 'auto')
            elif category == 'subdomains':
                desired_count = int(_os.environ.get('MODSCAN_SUBDOMAIN_WORDS_DESIRED', '25000'))
                scan_depth = _os.environ.get('MODSCAN_SUBDOMAIN_SCAN_DEPTH', 'auto')
            else:
                desired_count = int(_os.environ.get('MODSCAN_OTHER_WORDS_DESIRED', '10000'))
                scan_depth = _os.environ.get('MODSCAN_OTHER_SCAN_DEPTH', 'auto')
            
            # Determine scan tier
            target_tier = _get_scan_tier(desired_count, scan_depth)
            logger.info(f"📋 Loading {category} wordlists (tier: {target_tier}, target: ~{desired_count} words)")
            
            # Load tiers progressively with deduplication
            tier_order = ['surface', 'standard', 'deep', 'comprehensive']
            stop_at = tier_order.index(target_tier) + 1 if target_tier in tier_order else len(tier_order)
            
            loaded_tiers = []
            for i, tier in enumerate(tier_order[:stop_at]):
                tier_words = _load_wordlist_tier(category, tier, loaded_tiers)
                if tier_words:
                    self.wordlists[category].extend(tier_words)
                    loaded_tiers.append(tier)
                    logger.info(f"🎯 Tier {tier}: added {len(tier_words)} NEW {category} entries (deduplicated)")
                
                # Stop if we've reached target count
                if len(self.wordlists[category]) >= desired_count:
                    break
            
            logger.info(f"✅ Final {category}: {len(self.wordlists[category])} entries from {len(loaded_tiers)} tiers")
        
        # Load specialized categories (CMS, technology-specific)
        specialized_categories = ['cms_specific', 'technology_specific']
        for category in specialized_categories:
            self.wordlists[category] = {}
            category_configs = wordlist_configs.get(category, {})
            
            for subcategory, file_paths in category_configs.items():
                words = []
                for file_path in file_paths:
                    full_path = self.seclists_path / file_path
                    if full_path.exists():
                        try:
                            with open(full_path, 'r', encoding='utf-8', errors='ignore') as f:
                                raw_words = [line.strip() for line in f if line.strip() and not line.startswith('#')]
                            words.extend(raw_words)
                            logger.info(f"📋 Loaded {len(raw_words)} {subcategory} words from {file_path}")
                        except Exception as e:
                            logger.debug(f"Failed to load {file_path}: {e}")
                
                self.wordlists[category][subcategory] = list(set(words))
                logger.info(f"✅ {category}.{subcategory}: {len(self.wordlists[category][subcategory])} entries")

        # Auto-augment with local wordlists if present (universal)
        try:
            local_params = [Path.home() / 'wordlists' / 'parameters' / 'generic.txt',
                            Path.home() / 'wordlists' / 'parameters' / 'web.txt',
                            Path.home() / 'wordlists' / 'parameters' / 'api.txt']
            for p in local_params:
                if p.exists():
                    with open(p, 'r', encoding='utf-8', errors='ignore') as f:
                        words = [line.strip() for line in f if line.strip() and not line.startswith('#')]
                        self.wordlists.setdefault('parameters', []).extend(words)
            self.wordlists['parameters'] = list(set(self.wordlists.get('parameters', [])))[:5000]
            logger.info(f"📋 Augmented parameters list: {len(self.wordlists['parameters'])} entries")
        except Exception:
            pass
    
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
        
        # Dedupe and return a generous slice
        return list(set(found_wordlists))[:50000]
    
    def get_intelligent_wordlist(self, target_info: Dict, wordlist_type: str, limit: int = None) -> List[str]:
        """Intelligently select and combine SecLists wordlists with multi-category and technology-specific support"""
        
        domain = target_info.get('domain', '')
        technologies = target_info.get('technologies', [])
        tech_keywords = ' '.join(technologies).lower()
        
        # Dynamic wordlist selection based on target intelligence
        combined_words = []
        
        if wordlist_type == 'directories':
            wordlist_selection = self._get_directory_wordlists_for_target(domain, tech_keywords)
            
            # Add primary categories
            for category in wordlist_selection['primary']:
                category_words = self.wordlists.get(category, [])
                combined_words.extend(category_words)
                logger.debug(f"Added {len(category_words)} words from {category}")
            
            # Add CMS-specific wordlists
            for cms in wordlist_selection['cms_specific']:
                cms_words = self.wordlists.get('cms_specific', {}).get(cms, [])
                if cms_words:
                    # Convert CMS words to directory paths
                    cms_paths = ['/' + word for word in cms_words if not word.startswith('/')]
                    combined_words.extend(cms_paths)
                    logger.info(f"🎯 Added {len(cms_paths)} {cms} CMS-specific paths")
            
            # Add technology-specific wordlists
            for tech in wordlist_selection['technology_specific']:
                tech_words = self.wordlists.get('technology_specific', {}).get(tech, [])
                if tech_words:
                    tech_paths = ['/' + word for word in tech_words if not word.startswith('/')]
                    combined_words.extend(tech_paths)
                    logger.info(f"🎯 Added {len(tech_paths)} {tech} technology-specific paths")
                    
        elif wordlist_type == 'files':
            selected_wordlists = self._get_file_wordlists_for_target(domain, tech_keywords)
            for wordlist_category in selected_wordlists:
                category_words = self.wordlists.get(wordlist_category, [])
                combined_words.extend(category_words)
                
        elif wordlist_type in ['admin_paths', 'api_endpoints', 'parameters', 'backup_files', 'subdomains']:
            # Direct category access for specialized wordlists
            category_words = self.wordlists.get(wordlist_type, [])
            combined_words.extend(category_words)
            
        else:
            # Fallback to direct category lookup
            category_words = self.wordlists.get(wordlist_type, [])
            combined_words.extend(category_words)
        
        # If no category words found, try fallback
        if not combined_words:
            combined_words = self._get_fallback_wordlist(wordlist_type)
            logger.info(f"🔄 Using fallback wordlist for {wordlist_type}: {len(combined_words)} entries")
        
        # For directory brute-forcing, prefer breadth and randomization
        if wordlist_type == 'directories':
            import random as _random
            _random.shuffle(combined_words)
            # Remove duplicates while preserving randomized order
            seen = set()
            selected = []
            for word in combined_words:
                if word not in seen:
                    seen.add(word)
                    selected.append(word)
            
            # Apply limit if specified
            if limit and limit < len(selected):
                selected = selected[:limit]
            
            logger.info(f"🎯 Selected {len(selected)} comprehensive {wordlist_type} entries for {domain}")
            return selected

        # For other types, apply scoring and filtering
        if limit:
            scored_words = []
            for word in combined_words:
                score = self._score_wordlist_entry(word, domain, technologies, wordlist_type)
                if score >= 0.1:
                    scored_words.append((word, score))
            
            scored_words.sort(key=lambda x: x[1], reverse=True)
            selected_words = [word for word, score in scored_words[:limit]]
            logger.info(f"🎯 Selected {len(selected_words)} intelligent {wordlist_type} for {domain}")
            return selected_words
        else:
            # Return full wordlist without scoring if no limit
            deduped = list(dict.fromkeys(combined_words))
            logger.info(f"🎯 Selected {len(deduped)} full {wordlist_type} entries for {domain}")
            return deduped
    
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
    
    def _get_directory_wordlists_for_target(self, domain: str, tech_keywords: str) -> Dict:
        """Select directory wordlists based on target technology with multi-category support"""
        wordlists = ['directories', 'admin_paths', 'backup_files']  # Always include base categories
        
        # Add specialized categories based on detected technologies
        if 'api' in domain.lower() or 'api' in tech_keywords:
            wordlists.extend(['api_endpoints'])
        
        # CMS-specific augmentation
        cms_detected = []
        if 'wordpress' in tech_keywords:
            cms_detected.append('wordpress')
        if 'drupal' in tech_keywords:
            cms_detected.append('drupal')
        if 'joomla' in tech_keywords:
            cms_detected.append('joomla')
        if 'django' in tech_keywords:
            cms_detected.append('django')
        if 'umbraco' in tech_keywords:
            cms_detected.append('umbraco')
            
        # Technology-specific augmentation
        tech_detected = []
        if 'java' in tech_keywords or 'servlet' in tech_keywords:
            tech_detected.append('java')
        if 'oracle' in tech_keywords:
            tech_detected.append('oracle')
        if 'microsoft' in tech_keywords or 'asp' in tech_keywords:
            tech_detected.append('microsoft')
        if 'adobe' in tech_keywords:
            tech_detected.append('adobe')
            
        return {
            'primary': list(set(wordlists)),
            'cms_specific': cms_detected,
            'technology_specific': tech_detected
        }
    
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
