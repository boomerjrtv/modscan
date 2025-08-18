#!/usr/bin/env python3
"""
🚀 ADVANCED SECLISTS MANAGER - XBOW-CRUSHING WORDLIST INTELLIGENCE
Comprehensive SecLists integration with HTML analysis, tech stack correlation, and dynamic wordlist generation
"""

import logging
import re
import json
from pathlib import Path
from typing import List, Dict, Set, Optional, Tuple
from urllib.parse import urlparse
import asyncio
import aiohttp
from bs4 import BeautifulSoup
import subprocess

logger = logging.getLogger("AdvancedSecListsManager")

class AdvancedSecListsManager:
    """Advanced SecLists manager with AI-powered wordlist selection"""
    
    def __init__(self, asset_manager, config: Dict):
        self.asset_manager = asset_manager
        self.config = config
        self.seclists_path = Path(__file__).parent.parent / "SecLists"
        
        # Comprehensive wordlist categories (100x more than the weak 8)
        self.wordlist_categories = {
            # Discovery categories
            'subdomains': [],
            'directories': [],
            'files': [],
            'parameters': [],
            'endpoints': [],
            'api_paths': [],
            'admin_paths': [],
            'backup_files': [],
            'config_files': [],
            
            # Technology-specific categories
            'apache': [],
            'nginx': [],
            'iis': [],
            'tomcat': [],
            'weblogic': [],
            'jboss': [],
            'wordpress': [],
            'drupal': [],
            'joomla': [],
            'sharepoint': [],
            'confluence': [],
            'jenkins': [],
            'gitlab': [],
            'docker': [],
            'kubernetes': [],
            
            # Language/Framework specific
            'php': [],
            'asp': [],
            'aspx': [],
            'jsp': [],
            'nodejs': [],
            'python': [],
            'ruby': [],
            'golang': [],
            'java': [],
            
            # Database specific
            'mysql': [],
            'postgres': [],
            'mongodb': [],
            'redis': [],
            'elasticsearch': [],
            'oracle': [],
            'mssql': [],
            
            # Cloud specific
            'aws': [],
            'azure': [],
            'gcp': [],
            'cloudflare': [],
            'fastly': [],
            
            # Security specific
            'sqli': [],
            'xss': [],
            'lfi': [],
            'rfi': [],
            'xxe': [],
            'ssrf': [],
            'crlf': [],
            'jwt': [],
            'graphql': [],
            'api_security': [],
            
            # Fuzzing categories
            'fuzzing_general': [],
            'fuzzing_special_chars': [],
            'fuzzing_unicode': [],
            'fuzzing_numbers': [],
            
            # Custom generated
            'html_extracted': [],
            'tech_inferred': [],
            'domain_mutations': [],
            'smart_generated': []
        }
        
        # Technology fingerprint patterns
        self.tech_patterns = {
            'apache': [r'apache', r'httpd', r'server:\s*apache'],
            'nginx': [r'nginx', r'server:\s*nginx'],
            'iis': [r'iis', r'microsoft-iis', r'server:\s*microsoft-iis'],
            'php': [r'\.php', r'x-powered-by:\s*php', r'phpsessid'],
            'wordpress': [r'wp-content', r'wp-includes', r'/wp-admin/', r'wordpress'],
            'nodejs': [r'x-powered-by:\s*express', r'node\.js', r'express'],
            'java': [r'jsessionid', r'\.jsp', r'\.do', r'j2ee'],
            'asp': [r'\.asp', r'aspsessionid', r'x-aspnet-version'],
            'python': [r'django', r'flask', r'\.py', r'python'],
            'ruby': [r'rails', r'\.rb', r'x-powered-by:\s*phusion'],
            'mysql': [r'mysql', r'mariadb'],
            'postgres': [r'postgres', r'postgresql'],
            'mongodb': [r'mongodb', r'mongo'],
            'redis': [r'redis'],
            'aws': [r'amazonaws\.com', r'cloudfront', r's3', r'ec2'],
            'azure': [r'azure', r'microsoft', r'windows\.net'],
            'gcp': [r'google', r'gcp', r'googleapis'],
            'docker': [r'docker', r'container'],
            'kubernetes': [r'k8s', r'kubernetes', r'kube'],
            'jenkins': [r'jenkins', r'/jenkins/', r'hudson'],
            'gitlab': [r'gitlab', r'/gitlab/'],
            'jira': [r'jira', r'atlassian'],
            'confluence': [r'confluence', r'atlassian'],
            'sharepoint': [r'sharepoint', r'_layouts']
        }
        
        logger.info("🚀 Advanced SecLists Manager initialized - XBOW-crushing wordlist intelligence")
    
    async def initialize(self):
        """Initialize with comprehensive wordlist loading"""
        try:
            await self.ensure_seclists_available()
            await self.load_all_wordlists_comprehensive()
            
            categories_loaded = len([cat for cat in self.wordlist_categories.values() if cat])
            
            self.asset_manager.log_activity(
                'ADVANCED_SECLISTS_INIT',
                f'Advanced SecLists manager initialized with {categories_loaded} comprehensive wordlist categories'
            )
            
            logger.info(f"✅ Advanced SecLists initialization complete - {categories_loaded} categories loaded")
            
        except Exception as e:
            logger.error(f"Advanced SecLists initialization failed: {e}")
    
    async def ensure_seclists_available(self):
        """Ensure SecLists repository is available"""
        if not self.seclists_path.exists():
            logger.info("🔽 Downloading comprehensive SecLists repository...")
            try:
                process = await asyncio.create_subprocess_exec(
                    'git', 'clone', 'https://github.com/danielmiessler/SecLists.git',
                    str(self.seclists_path),
                    stdout=asyncio.subprocess.PIPE,
                    stderr=asyncio.subprocess.PIPE
                )
                await process.communicate()
                logger.info("✅ SecLists repository downloaded")
            except Exception as e:
                logger.error(f"Failed to download SecLists: {e}")
                raise
        else:
            logger.info("✅ SecLists already available")
    
    async def load_all_wordlists_comprehensive(self):
        """Load ALL relevant wordlists from SecLists - comprehensive approach"""
        
        # Discovery wordlists
        await self._load_wordlist_category('subdomains', [
            'Discovery/DNS/subdomains-top1million-20000.txt',
            'Discovery/DNS/subdomains-top1million-110000.txt',
            'Discovery/DNS/fierce-hostlist.txt',
            'Discovery/DNS/namelist.txt',
            'Discovery/DNS/deepmagic.com-prefixes-top500.txt',
            'Discovery/DNS/bitquark-subdomains-top100000.txt',
            'Discovery/DNS/combined_subdomains.txt'
        ])
        
        await self._load_wordlist_category('directories', [
            'Discovery/Web-Content/raft-large-directories.txt',
            'Discovery/Web-Content/raft-medium-directories.txt',
            'Discovery/Web-Content/raft-small-directories.txt',
            'Discovery/Web-Content/common.txt',
            'Discovery/Web-Content/big.txt',
            'Discovery/Web-Content/directory-list-2.3-medium.txt',
            'Discovery/Web-Content/directory-list-2.3-big.txt',
            'Discovery/Web-Content/apache.txt',
            'Discovery/Web-Content/nginx.txt'
        ])
        
        await self._load_wordlist_category('files', [
            'Discovery/Web-Content/raft-large-files.txt',
            'Discovery/Web-Content/raft-medium-files.txt',
            'Discovery/Web-Content/raft-small-files.txt',
            'Discovery/Web-Content/raft-large-extensions.txt',
            'Discovery/Web-Content/web-extensions.txt',
            'Discovery/Web-Content/Common-DB-Backups.txt',
            'Discovery/Web-Content/CommonBackdoors-PHP.fuzz.txt'
        ])
        
        await self._load_wordlist_category('parameters', [
            'Discovery/Web-Content/burp-parameter-names.txt',
            'Fuzzing/LFI/LFI-gracefulsecurity-linux.txt',
            'Fuzzing/LFI/LFI-gracefulsecurity-windows.txt',
            'Discovery/Web-Content/web-mutations.txt'
        ])
        
        # API and endpoints
        await self._load_wordlist_category('api_paths', [
            'Discovery/Web-Content/common-api-endpoints-mazen160.txt',
            'Discovery/Web-Content/api/api-endpoints.txt',
            'Discovery/Web-Content/api/api-endpoints-res.txt',
            'Discovery/Web-Content/graphql.txt'
        ])
        
        # Technology-specific wordlists
        await self._load_wordlist_category('apache', [
            'Discovery/Web-Content/apache.txt',
            'Discovery/Web-Content/Apache.fuzz.txt'
        ])
        
        await self._load_wordlist_category('nginx', [
            'Discovery/Web-Content/nginx.txt'
        ])
        
        await self._load_wordlist_category('iis', [
            'Discovery/Web-Content/IIS.fuzz.txt',
            'Discovery/Web-Content/iis-systemweb.txt'
        ])
        
        await self._load_wordlist_category('php', [
            'Discovery/Web-Content/PHP.fuzz.txt',
            'Discovery/Web-Content/CommonBackdoors-PHP.fuzz.txt'
        ])
        
        await self._load_wordlist_category('wordpress', [
            'Discovery/Web-Content/CMS/wordpress.fuzz.txt',
            'Discovery/Web-Content/CMS/wp-plugins.fuzz.txt',
            'Discovery/Web-Content/CMS/wp-themes.fuzz.txt'
        ])
        
        await self._load_wordlist_category('drupal', [
            'Discovery/Web-Content/CMS/drupal.txt',
            'Discovery/Web-Content/CMS/drupal_modules.txt'
        ])
        
        await self._load_wordlist_category('joomla', [
            'Discovery/Web-Content/CMS/joomla.txt'
        ])
        
        # Security testing wordlists
        await self._load_wordlist_category('sqli', [
            'Fuzzing/SQLi/quick-SQLi.txt',
            'Fuzzing/SQLi/Generic-SQLi.txt',
            'Fuzzing/SQLi/MySQL-SQLi-Login-Bypass.fuzz.txt'
        ])
        
        await self._load_wordlist_category('xss', [
            'Fuzzing/XSS/XSS-Bypass-Strings-BruteLogic.txt',
            'Fuzzing/XSS/XSS-RSNAKE.txt',
            'Fuzzing/XSS/XSS-BruteLogic.txt'
        ])
        
        await self._load_wordlist_category('lfi', [
            'Fuzzing/LFI/LFI-gracefulsecurity-linux.txt',
            'Fuzzing/LFI/LFI-gracefulsecurity-windows.txt',
            'Fuzzing/LFI/LFI-etc-files-of-all-linux-packages.txt'
        ])
        
        await self._load_wordlist_category('xxe', [
            'Fuzzing/XXE-Injection/XXE-Injection.txt'
        ])
        
        # Cloud-specific wordlists
        await self._load_wordlist_category('aws', [
            'Discovery/Web-Content/cloud/aws_metadata_security_credentials.txt'
        ])
        
        # Fuzzing wordlists
        await self._load_wordlist_category('fuzzing_special_chars', [
            'Fuzzing/special-chars.txt',
            'Fuzzing/Unicode.txt'
        ])
        
        logger.info(f"✅ Loaded comprehensive wordlists across {len(self.wordlist_categories)} categories")
    
    async def _load_wordlist_category(self, category: str, file_paths: List[str]):
        """Load wordlists for a specific category"""
        words = set()
        
        for file_path in file_paths:
            full_path = self.seclists_path / file_path
            if full_path.exists():
                try:
                    with open(full_path, 'r', encoding='utf-8', errors='ignore') as f:
                        for line in f:
                            word = line.strip()
                            if word and not word.startswith('#') and len(word) < 100:
                                words.add(word)
                except Exception as e:
                    logger.debug(f"Could not load {file_path}: {e}")
        
        # Limit to reasonable size but keep comprehensive
        self.wordlist_categories[category] = list(words)[:10000]  # 10K per category
        
        if self.wordlist_categories[category]:
            logger.info(f"📋 Loaded {len(self.wordlist_categories[category])} words for {category}")
    
    async def generate_intelligent_wordlist(self, target_url: str, tech_stack: str = "", 
                                          html_content: str = "") -> List[str]:
        """Generate intelligent wordlist based on target analysis"""
        wordlist = set()
        
        # Base comprehensive wordlist
        wordlist.update(self.wordlist_categories.get('directories', [])[:2000])
        wordlist.update(self.wordlist_categories.get('files', [])[:2000])
        wordlist.update(self.wordlist_categories.get('parameters', [])[:1000])
        wordlist.update(self.wordlist_categories.get('api_paths', [])[:500])
        
        # Technology-specific wordlists
        detected_techs = self._detect_technologies(target_url, tech_stack, html_content)
        for tech in detected_techs:
            if tech in self.wordlist_categories:
                tech_words = self.wordlist_categories[tech][:1000]  # 1K per detected tech
                wordlist.update(tech_words)
                logger.info(f"🎯 Added {len(tech_words)} {tech}-specific words")
        
        # HTML content analysis
        if html_content:
            html_words = await self._extract_words_from_html(html_content)
            wordlist.update(html_words)
            logger.info(f"🔍 Extracted {len(html_words)} words from HTML analysis")
        
        # Domain-based mutations
        domain_words = self._generate_domain_mutations(target_url)
        wordlist.update(domain_words)
        
        # Smart generated words
        smart_words = self._generate_smart_words(target_url, detected_techs)
        wordlist.update(smart_words)
        
        final_wordlist = list(wordlist)[:15000]  # 15K comprehensive wordlist
        logger.info(f"🚀 Generated intelligent wordlist: {len(final_wordlist)} words")
        
        return final_wordlist
    
    def _detect_technologies(self, target_url: str, tech_stack: str, html_content: str) -> Set[str]:
        """Detect technologies from URL, tech stack, and HTML content"""
        detected = set()
        
        # Check tech_stack parameter
        if tech_stack:
            for tech, patterns in self.tech_patterns.items():
                for pattern in patterns:
                    if re.search(pattern, tech_stack.lower()):
                        detected.add(tech)
        
        # Check HTML content
        if html_content:
            content_lower = html_content.lower()
            for tech, patterns in self.tech_patterns.items():
                for pattern in patterns:
                    if re.search(pattern, content_lower):
                        detected.add(tech)
        
        # Check URL patterns
        url_lower = target_url.lower()
        for tech, patterns in self.tech_patterns.items():
            for pattern in patterns:
                if re.search(pattern, url_lower):
                    detected.add(tech)
        
        return detected
    
    async def _extract_words_from_html(self, html_content: str) -> Set[str]:
        """Extract relevant words from HTML content for wordlist generation"""
        words = set()
        
        try:
            soup = BeautifulSoup(html_content, 'html.parser')
            
            # Extract from various HTML elements
            for element in soup.find_all(['a', 'form', 'input', 'script', 'link']):
                # Extract from href attributes
                if element.get('href'):
                    words.update(self._extract_path_components(element['href']))
                
                # Extract from action attributes
                if element.get('action'):
                    words.update(self._extract_path_components(element['action']))
                
                # Extract from src attributes
                if element.get('src'):
                    words.update(self._extract_path_components(element['src']))
                
                # Extract from name attributes
                if element.get('name'):
                    words.add(element['name'])
                
                # Extract from id attributes
                if element.get('id'):
                    words.add(element['id'])
                
                # Extract from class attributes
                if element.get('class'):
                    words.update(element['class'])
            
            # Extract comments
            for comment in soup.find_all(string=lambda text: isinstance(text, str) and text.strip().startswith('<!--')):
                comment_words = re.findall(r'\\b\\w+\\b', comment)
                words.update(comment_words)
            
            # Extract JavaScript variable names
            scripts = soup.find_all('script')
            for script in scripts:
                if script.string:
                    js_vars = re.findall(r'\\b(?:var|let|const)\\s+(\\w+)', script.string)
                    words.update(js_vars)
                    
                    # Extract function names
                    js_funcs = re.findall(r'function\\s+(\\w+)', script.string)
                    words.update(js_funcs)
        
        except Exception as e:
            logger.debug(f"HTML analysis error: {e}")
        
        # Filter and clean words
        cleaned_words = set()
        for word in words:
            if isinstance(word, str) and 3 <= len(word) <= 50:
                # Remove common noise words
                if word.lower() not in ['the', 'and', 'for', 'are', 'but', 'not', 'you', 'all', 'can', 'her', 'was', 'one', 'our', 'had', 'use']:
                    cleaned_words.add(word)
        
        return cleaned_words
    
    def _extract_path_components(self, url: str) -> Set[str]:
        """Extract useful components from URL paths"""
        words = set()
        
        try:
            parsed = urlparse(url)
            path = parsed.path
            
            # Split by common separators
            components = re.split(r'[/\\\\._-]', path)
            for component in components:
                if component and len(component) >= 3:
                    words.add(component)
            
            # Extract file extensions as potential directories
            if '.' in path:
                ext = path.split('.')[-1]
                if len(ext) <= 5:
                    words.add(ext)
        
        except Exception:
            pass
        
        return words
    
    def _generate_domain_mutations(self, target_url: str) -> Set[str]:
        """Generate mutations based on domain name"""
        words = set()
        
        try:
            parsed = urlparse(target_url)
            domain = parsed.netloc.lower()
            
            # Remove common prefixes/suffixes
            domain_clean = domain.replace('www.', '').replace('.com', '').replace('.org', '').replace('.net', '')
            
            # Split by dots and dashes
            parts = re.split(r'[.-]', domain_clean)
            
            for part in parts:
                if len(part) >= 3:
                    words.add(part)
                    words.add(f"{part}-api")
                    words.add(f"{part}-admin")
                    words.add(f"{part}-test")
                    words.add(f"{part}-dev")
                    words.add(f"{part}-staging")
                    words.add(f"api-{part}")
                    words.add(f"admin-{part}")
        
        except Exception:
            pass
        
        return words
    
    def _generate_smart_words(self, target_url: str, detected_techs: Set[str]) -> Set[str]:
        """Generate smart words based on detected technologies and patterns"""
        words = set()
        
        # Technology-specific common paths
        tech_paths = {
            'wordpress': ['wp-admin', 'wp-content', 'wp-includes', 'wp-json', 'xmlrpc.php'],
            'drupal': ['admin', 'user', 'node', 'sites/default', 'modules', 'themes'],
            'joomla': ['administrator', 'components', 'modules', 'plugins', 'templates'],
            'php': ['admin.php', 'config.php', 'index.php', 'login.php', 'phpinfo.php'],
            'nodejs': ['admin', 'api', 'auth', 'users', 'dashboard'],
            'java': ['admin', 'manager', 'console', 'api', 'rest'],
            'python': ['admin', 'api', 'auth', 'dashboard', 'static'],
            'jenkins': ['job', 'build', 'configure', 'script', 'manage'],
            'gitlab': ['admin', 'projects', 'groups', 'users', 'api/v4'],
            'aws': ['health', 'status', 'metrics', 'logs', 'api'],
            'docker': ['containers', 'images', 'volumes', 'networks', 'api']
        }
        
        for tech in detected_techs:
            if tech in tech_paths:
                words.update(tech_paths[tech])
        
        # Add common security testing paths
        security_paths = [
            'admin', 'administrator', 'login', 'auth', 'api', 'v1', 'v2', 'graphql',
            'config', 'backup', 'test', 'dev', 'staging', 'debug', 'console',
            'dashboard', 'panel', 'manager', 'status', 'health', 'metrics'
        ]
        words.update(security_paths)
        
        return words
    
    async def get_technology_specific_wordlist(self, technology: str) -> List[str]:
        """Get wordlist specific to a detected technology"""
        if technology in self.wordlist_categories:
            return self.wordlist_categories[technology][:5000]  # 5K words per tech
        return []
    
    async def get_comprehensive_subdomain_list(self) -> List[str]:
        """Get comprehensive subdomain wordlist"""
        return self.wordlist_categories.get('subdomains', [])[:20000]  # 20K subdomains
    
    async def get_api_endpoint_wordlist(self) -> List[str]:
        """Get API endpoint specific wordlist"""
        api_words = set()
        api_words.update(self.wordlist_categories.get('api_paths', []))
        api_words.update(self.wordlist_categories.get('endpoints', []))
        api_words.update(self.wordlist_categories.get('parameters', []))
        return list(api_words)[:5000]  # 5K API words