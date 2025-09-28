#!/usr/bin/env python3
"""
Intelligent Directory Discovery - WAF-Aware Content Discovery

Instead of brute force directory enumeration with ffuf/wordlists, this module:
1. Analyzes the target application architecture
2. Uses context-aware path prediction
3. Leverages robots.txt, sitemaps, and existing content analysis
4. Avoids high-speed requests that trigger WAF blocks
"""

import asyncio
import logging
import time
import random
from typing import Set, List, Optional, Dict, Any
from urllib.parse import urlparse, urljoin, urlsplit
import aiohttp
import re

from .stealth_headers import get_stealth_headers

logger = logging.getLogger(__name__)

class IntelligentDiscovery:
    """Smart, context-aware directory discovery that avoids WAF detection"""
    
    def __init__(self):
        self.discovered_paths = set()
        self.analyzed_domains = set()
        self.app_patterns = {}
        
    async def discover_intelligently(self, base_url: str, session: aiohttp.ClientSession) -> Set[str]:
        """
        Main intelligent discovery method
        
        Steps:
        1. Analyze robots.txt and sitemap.xml
        2. Detect application patterns from existing content
        3. Use smart path prediction based on technology stack
        4. Test paths with human-like timing and behavior
        """
        discovered = set()
        
        logger.info(f"🧠 Starting intelligent discovery for: {base_url}")
        
        # Step 1: Safe reconnaissance - robots.txt, sitemap
        recon_paths = await self._safe_reconnaissance(base_url, session)
        discovered.update(recon_paths)
        logger.info(f"📋 Safe recon found {len(recon_paths)} paths")
        
        # Step 2: Analyze existing content for patterns
        app_context = await self._analyze_application_patterns(base_url, session)
        
        # Step 3: Smart path prediction based on context
        predicted_paths = self._predict_paths_from_context(base_url, app_context)
        logger.info(f"🎯 Predicted {len(predicted_paths)} likely paths")
        
        # Step 4: Test predicted paths with stealth
        validated_paths = await self._test_paths_stealthily(predicted_paths, session)
        discovered.update(validated_paths)
        
        logger.info(f"✅ Intelligent discovery complete: {len(discovered)} paths found")
        return discovered
    
    async def _safe_reconnaissance(self, base_url: str, session: aiohttp.ClientSession) -> Set[str]:
        """Safe reconnaissance using robots.txt, sitemap.xml, etc."""
        discovered = set()
        headers = get_stealth_headers(base_url)
        
        # Standard discovery files (safe, expected requests)
        safe_files = [
            '/robots.txt',
            '/sitemap.xml',
            '/sitemap_index.xml',
            '/.well-known/security.txt',
            '/humans.txt',
            '/manifest.json'
        ]
        
        for file_path in safe_files:
            try:
                url = urljoin(base_url, file_path)
                async with session.get(url, headers=headers) as response:
                    if response.status == 200:
                        text = await response.text()
                        discovered.add(url)
                        
                        # Parse discovered paths from content
                        if file_path == '/robots.txt':
                            paths = self._parse_robots_txt(text, base_url)
                            discovered.update(paths)
                        elif 'sitemap' in file_path:
                            paths = self._parse_sitemap(text, base_url)
                            discovered.update(paths)
                
                # Human-like delay between requests
                await asyncio.sleep(random.uniform(1.0, 2.5))
                
            except Exception as e:
                logger.debug(f"Safe recon failed for {file_path}: {e}")
        
        return discovered
    
    def _parse_robots_txt(self, content: str, base_url: str) -> Set[str]:
        """Extract paths from robots.txt"""
        paths = set()
        
        for line in content.split('\n'):
            line = line.strip()
            if line.startswith(('Disallow:', 'Allow:')):
                path = line.split(':', 1)[1].strip()
                if path and path != '/':
                    full_url = urljoin(base_url, path)
                    paths.add(full_url)
        
        return paths
    
    def _parse_sitemap(self, content: str, base_url: str) -> Set[str]:
        """Extract URLs from sitemap.xml"""
        paths = set()
        
        # Simple regex to find URLs in sitemap
        url_pattern = r'<loc>(.*?)</loc>'
        matches = re.findall(url_pattern, content)
        
        for match in matches:
            if match.startswith('http'):
                # Only include URLs from same domain
                if urlparse(match).netloc == urlparse(base_url).netloc:
                    paths.add(match)
        
        return paths
    
    async def _analyze_application_patterns(self, base_url: str, session: aiohttp.ClientSession) -> Dict[str, Any]:
        """Analyze the application to determine likely paths"""
        context = {
            'technology': 'unknown',
            'cms': None,
            'api_patterns': [],
            'language_hints': [],
            'directory_patterns': []
        }
        
        headers = get_stealth_headers(base_url)
        
        try:
            # Analyze homepage for technology clues
            async with session.get(base_url, headers=headers) as response:
                if response.status == 200:
                    text = await response.text()
                    response_headers = dict(response.headers)
                    
                    # Detect technology stack
                    context['technology'] = self._detect_technology_from_content(text, response_headers)
                    
                    # Detect CMS
                    context['cms'] = self._detect_cms(text, response_headers)
                    
                    # Find API patterns in JavaScript
                    context['api_patterns'] = self._extract_api_patterns(text)
                    
                    logger.info(f"🔍 Detected technology: {context['technology']}")
                    if context['cms']:
                        logger.info(f"🔍 Detected CMS: {context['cms']}")
            
            await asyncio.sleep(random.uniform(1.5, 3.0))
            
        except Exception as e:
            logger.debug(f"Application analysis failed: {e}")
        
        return context
    
    def _detect_technology_from_content(self, content: str, headers: Dict) -> str:
        """Detect technology stack from content and headers"""
        
        # Check headers first
        headers_str = str(headers).lower()
        if 'x-powered-by: php' in headers_str:
            return 'php'
        elif 'x-aspnet-version' in headers_str:
            return 'aspnet'
        elif 'server: nginx' in headers_str and 'node' in content.lower():
            return 'nodejs'
        
        # Check content patterns
        content_lower = content.lower()
        if 'wp-content' in content_lower or 'wordpress' in content_lower:
            return 'wordpress'
        elif 'drupal' in content_lower:
            return 'drupal'
        elif 'joomla' in content_lower:
            return 'joomla'
        elif 'react' in content_lower and 'app.js' in content_lower:
            return 'react'
        elif 'angular' in content_lower:
            return 'angular'
        elif 'vue' in content_lower:
            return 'vue'
        
        return 'unknown'
    
    def _detect_cms(self, content: str, headers: Dict) -> Optional[str]:
        """Detect Content Management System"""
        content_lower = content.lower()
        
        cms_indicators = {
            'wordpress': ['wp-content', 'wp-includes', 'wp-admin'],
            'drupal': ['drupal', '/sites/default/', 'drupal.js'],
            'joomla': ['joomla', '/components/', '/modules/'],
            'magento': ['magento', 'skin/frontend', 'mage/cookies'],
            'shopify': ['shopify', 'shop.js', 'shopify-analytics']
        }
        
        for cms, indicators in cms_indicators.items():
            if any(indicator in content_lower for indicator in indicators):
                return cms
        
        return None
    
    def _extract_api_patterns(self, content: str) -> List[str]:
        """Extract API endpoint patterns from JavaScript"""
        patterns = []
        
        # Look for common API patterns in JavaScript
        api_patterns = [
            r'["\']\/api\/[^"\']*["\']',
            r'["\']\/v\d+\/[^"\']*["\']',
            r'["\']\/graphql[^"\']*["\']',
            r'["\']\/rest\/[^"\']*["\']'
        ]
        
        for pattern in api_patterns:
            matches = re.findall(pattern, content)
            for match in matches:
                clean_path = match.strip('"\'')
                if clean_path not in patterns:
                    patterns.append(clean_path)
        
        return patterns[:10]  # Limit to 10 patterns
    
    def _predict_paths_from_context(self, base_url: str, context: Dict) -> List[str]:
        """Predict likely paths based on application context"""
        predicted = []
        
        # Technology-specific predictions
        tech = context.get('technology', 'unknown')
        
        if tech == 'wordpress':
            predicted.extend([
                '/wp-admin/',
                '/wp-content/',
                '/wp-includes/',
                '/wp-login.php',
                '/xmlrpc.php'
            ])
        elif tech == 'drupal':
            predicted.extend([
                '/admin/',
                '/user/login',
                '/node/',
                '/sites/default/'
            ])
        elif tech == 'joomla':
            predicted.extend([
                '/administrator/',
                '/components/',
                '/modules/',
                '/templates/'
            ])
        elif tech in ['react', 'angular', 'vue']:
            predicted.extend([
                '/api/',
                '/assets/',
                '/static/',
                '/build/'
            ])
        elif tech == 'nodejs':
            predicted.extend([
                '/api/',
                '/public/',
                '/assets/',
                '/auth/'
            ])
        elif tech == 'php':
            predicted.extend([
                '/admin/',
                '/includes/',
                '/config/',
                '/assets/'
            ])
        
        # Add API patterns found in content
        for api_pattern in context.get('api_patterns', []):
            predicted.append(api_pattern)
        
        # Common paths for all applications (but limited)
        common_paths = [
            '/admin/',
            '/api/',
            '/login/',
            '/auth/',
            '/dashboard/',
            '/assets/',
            '/static/',
            '/public/'
        ]
        predicted.extend(common_paths)
        
        # Convert to full URLs and deduplicate
        full_urls = []
        seen = set()
        for path in predicted:
            full_url = urljoin(base_url, path)
            if full_url not in seen:
                full_urls.append(full_url)
                seen.add(full_url)
        
        return full_urls[:20]  # Limit to 20 predictions
    
    async def _test_paths_stealthily(self, paths: List[str], session: aiohttp.ClientSession) -> Set[str]:
        """Test predicted paths with stealth timing and behavior"""
        discovered = set()
        
        logger.info(f"🕵️ Testing {len(paths)} predicted paths with stealth timing...")
        
        for i, path in enumerate(paths):
            try:
                headers = get_stealth_headers(path)
                
                async with session.get(path, headers=headers) as response:
                    # Accept any status that indicates the path exists
                    if response.status in [200, 201, 301, 302, 401, 403]:
                        discovered.add(path)
                        logger.info(f"✅ Found: {path} [{response.status}]")
                    else:
                        logger.debug(f"❌ Not found: {path} [{response.status}]")
                
                # Human-like delays (2-5 seconds between requests)
                delay = random.uniform(2.0, 5.0)
                logger.debug(f"⏱️ Waiting {delay:.1f}s before next request ({i+1}/{len(paths)})")
                await asyncio.sleep(delay)
                
            except Exception as e:
                logger.debug(f"Path test failed for {path}: {e}")
                # Even longer delay on errors to avoid suspicion
                await asyncio.sleep(random.uniform(3.0, 6.0))
        
        return discovered


# Global instance
intelligent_discovery = IntelligentDiscovery()

async def discover_paths_intelligently(base_url: str, session: aiohttp.ClientSession) -> Set[str]:
    """Convenience function for intelligent discovery"""
    return await intelligent_discovery.discover_intelligently(base_url, session)


    # Engine compatibility methods
    async def comprehensive_discovery(self, domain: str) -> Set[str]:
        """Engine compatibility method for comprehensive discovery"""
        from modules.stealth_headers import StealthHeaders
        stealth = StealthHeaders()
        
        async with aiohttp.ClientSession(
            headers=stealth.get_stealth_headers(),
            timeout=aiohttp.ClientTimeout(total=30)
        ) as session:
            return await self.discover_intelligently(domain, session)
    
    async def _fast_streamlined_discovery(self, domain: str) -> Set[str]:
        """Engine compatibility method for fast discovery"""
        return await self.comprehensive_discovery(domain)
    
    def _is_internal_ip(self, domain: str) -> bool:
        """Check if domain is internal IP"""
        import ipaddress
        try:
            # Extract hostname from URL if needed
            if '://' in domain:
                from urllib.parse import urlparse
                domain = urlparse(domain).hostname or domain
            
            ip = ipaddress.ip_address(domain)
            return ip.is_private or ip.is_loopback
        except (ipaddress.AddressValueError, ValueError):
            return False
    
    async def _run_gau(self, domain: str) -> Set[str]:
        """GAU compatibility method"""
        return set()  # GAU not needed with intelligent discovery
    
    async def _tier7_universal_port_discovery(self, base_url: str) -> Set[str]:
        """Port discovery compatibility method"""
        return set()  # Not needed with intelligent approach


async def discover_paths_intelligently(base_url: str, session: aiohttp.ClientSession) -> Set[str]:
    """
    Standalone function for intelligent path discovery
    """
    discovery = IntelligentDiscovery()
    return await discovery.discover_intelligently(base_url, session)
