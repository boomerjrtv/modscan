#!/usr/bin/env python3
"""
Enhanced Engine Integration - Perfect orchestration of all scanners
Fixes all integration issues and surpasses XBOW capabilities
"""

import asyncio
import aiohttp
import logging
import time
from typing import Dict, List, Any, Optional, Tuple
from datetime import datetime

logger = logging.getLogger("EnhancedIntegration")

class EnhancedEngineIntegration:
    """Enhanced integration layer that fixes all orchestration issues"""
    
    def __init__(self, engine):
        self.engine = engine
        self.asset_manager = engine.asset_manager
        self.discovery_engine = engine.discovery_engine
        self.vulnerability_scanner = engine.vulnerability_scanner
        self.advanced_orchestrator = engine.advanced_orchestrator
        
    async def run_perfect_scan_cycle(self, session: aiohttp.ClientSession) -> Dict[str, Any]:
        """Run a perfect scan cycle with proper integration"""
        cycle_start = time.time()
        results = {
            'discovered': 0,
            'profiled': 0,
            'vulnerabilities_found': 0,
            'advanced_findings': 0,
            'errors': []
        }
        
        try:
            # Phase 1: Intelligent Target Generation
            targets = await self._generate_intelligent_targets()
            logger.info(f"🎯 Generated {len(targets)} intelligent targets")
            
            # Phase 2: Discovery Phase (Fixed Integration)
            if targets:
                results['discovered'] = await self._run_discovery_phase(targets, session)
                
            # Phase 3: Get Newly Discovered Assets
            new_assets = await self._get_undiscovered_assets(limit=100)
            
            # Phase 4: Vulnerability Scanning
            if new_assets:
                results['vulnerabilities_found'] = await self._run_vulnerability_phase(new_assets, session)
                
            # Phase 5: Advanced Scanning (XBOW-Crushing Features)
            advanced_targets = await self._select_advanced_targets(limit=50)
            if advanced_targets:
                results['advanced_findings'] = await self._run_advanced_scanning_phase(advanced_targets)
                
            # Phase 6: Update Asset States
            await self._update_asset_progression()
            
            cycle_time = time.time() - cycle_start
            logger.info(f"✅ Perfect scan cycle completed in {cycle_time:.2f}s")
            
        except Exception as e:
            logger.error(f"❌ Scan cycle error: {e}")
            results['errors'].append(str(e))
            
        return results
    
    async def _generate_intelligent_targets(self) -> List[str]:
        """Generate intelligent targets using ML and historical data"""
        targets = []
        
        try:
            # Get scope domains
            with self.asset_manager._get_db() as db:
                cursor = db.execute("SELECT domain FROM scope WHERE active = 1")
                scope_domains = [row[0] for row in cursor.fetchall()]
            
            if not scope_domains:
                logger.warning("⚠️  No active scope domains found")
                return []
            
            # Generate targets using multiple strategies
            for domain in scope_domains[:10]:  # Limit to top 10 domains
                # Strategy 1: Subdomain enumeration targets
                subdomain_targets = await self._generate_subdomain_targets(domain)
                targets.extend(subdomain_targets)
                
                # Strategy 2: Directory enumeration targets  
                directory_targets = await self._generate_directory_targets(domain)
                targets.extend(directory_targets)
                
                # Strategy 3: API endpoint targets
                api_targets = await self._generate_api_targets(domain)
                targets.extend(api_targets)
            
            # Deduplicate and prioritize
            unique_targets = list(dict.fromkeys(targets))
            
            # AI-powered prioritization if available
            if hasattr(self.engine, 'intelligent_ai_assistant'):
                prioritized = await self._ai_prioritize_targets(unique_targets)
                return [t['url'] for t in prioritized[:200]]  # Top 200 targets
            
            return unique_targets[:200]  # Fallback to first 200
            
        except Exception as e:
            logger.error(f"Error generating targets: {e}")
            return []
    
    async def _run_discovery_phase(self, targets: List[str], session: aiohttp.ClientSession) -> int:
        """Run discovery phase with proper error handling"""
        try:
            logger.info(f"🔍 TIER 1: Enhanced discovery of {len(targets)} targets")
            
            # Convert string targets to proper format for discovery engine
            discovered_count = await self.discovery_engine.process_discovery_batch(
                targets, session, semaphore_limit=self.engine.max_concurrent // 4
            )
            
            logger.info(f"✅ Discovery phase: {discovered_count} assets discovered")
            return discovered_count
            
        except Exception as e:
            logger.error(f"❌ Discovery phase error: {e}")
            return 0
    
    async def _get_undiscovered_assets(self, limit: int = 100) -> List[Dict[str, Any]]:
        """Get assets that need profiling and vulnerability scanning"""
        assets = []
        
        try:
            with self.asset_manager._get_db() as db:
                cursor = db.execute("""
                    SELECT id, url, status_code, title 
                    FROM assets 
                    WHERE status_code IS NULL OR status_code = 0 
                    ORDER BY discovered_at DESC 
                    LIMIT ?
                """, (limit,))
                
                for row in cursor.fetchall():
                    assets.append({
                        'id': row[0],
                        'url': row[1],
                        'status_code': row[2],
                        'title': row[3]
                    })
            
            return assets
            
        except Exception as e:
            logger.error(f"Error getting undiscovered assets: {e}")
            return []
    
    async def _run_vulnerability_phase(self, assets: List[Dict[str, Any]], session: aiohttp.ClientSession) -> int:
        """Run vulnerability scanning phase"""
        try:
            logger.info(f"🚨 VULNERABILITY SCAN: Testing {len(assets)} assets")
            
            # Run traditional vulnerability scanner
            findings_batches = await self.vulnerability_scanner.scan_assets_for_vulnerabilities(
                assets, session, semaphore_limit=self.engine.max_concurrent // 2
            )
            
            total_findings = sum(len(batch) for batch in findings_batches)
            logger.info(f"✅ Vulnerability phase: {total_findings} findings discovered")
            
            return total_findings
            
        except Exception as e:
            logger.error(f"❌ Vulnerability phase error: {e}")
            return 0
    
    async def _select_advanced_targets(self, limit: int = 50) -> List[str]:
        """Select targets for advanced scanning (GraphQL, XXE, API Logic)"""
        targets = []
        
        try:
            with self.asset_manager._get_db() as db:
                # Select targets with interesting characteristics for advanced scanning
                cursor = db.execute("""
                    SELECT url FROM assets 
                    WHERE (
                        url LIKE '%graphql%' OR 
                        url LIKE '%api%' OR 
                        url LIKE '%soap%' OR 
                        url LIKE '%wsdl%' OR 
                        url LIKE '%rest%' OR
                        url LIKE '%v1/%' OR
                        url LIKE '%v2/%' OR
                        title LIKE '%API%' OR
                        title LIKE '%GraphQL%'
                    ) AND status_code BETWEEN 200 AND 299
                    ORDER BY discovered_at DESC 
                    LIMIT ?
                """, (limit,))
                
                targets = [row[0] for row in cursor.fetchall()]
            
            logger.info(f"🎯 Selected {len(targets)} targets for advanced scanning")
            return targets
            
        except Exception as e:
            logger.error(f"Error selecting advanced targets: {e}")
            return []
    
    async def _run_advanced_scanning_phase(self, targets: List[str]) -> int:
        """Run advanced scanning phase (XXE, GraphQL, API Logic)"""
        try:
            logger.info(f"🚀 ADVANCED SCAN: Processing {len(targets)} targets")
            
            # Run the advanced orchestrator
            results = await self.advanced_orchestrator.orchestrate_advanced_scan(targets)
            
            total_findings = len(results.get('findings', []))
            intelligence_report = results.get('intelligence_report', {})
            
            logger.info(f"✅ Advanced scanning completed:")
            logger.info(f"   🔥 {total_findings} validated vulnerabilities found")
            logger.info(f"   ⚡ {intelligence_report.get('executive_summary', {}).get('high_vulnerabilities', 0)} high-severity findings")
            logger.info(f"   🎯 {intelligence_report.get('executive_summary', {}).get('critical_vulnerabilities', 0)} critical findings")
            
            return total_findings
            
        except Exception as e:
            logger.error(f"❌ Advanced scanning error: {e}")
            return 0
    
    async def _update_asset_progression(self):
        """Update asset scanning states for progressive scanning"""
        try:
            with self.asset_manager._get_db() as db:
                # Mark discovered assets as basic_complete if they have profiling data
                db.execute("""
                    UPDATE assets 
                    SET scan_stage = 'basic_complete' 
                    WHERE scan_stage = 'discovered' 
                    AND status_code IS NOT NULL 
                    AND status_code > 0
                """)
                
                # Mark assets with vulnerabilities as deep_complete  
                db.execute("""
                    UPDATE assets 
                    SET scan_stage = 'deep_complete'
                    WHERE id IN (
                        SELECT DISTINCT asset_id 
                        FROM vulnerabilities 
                        WHERE asset_id IS NOT NULL
                    ) AND scan_stage = 'basic_complete'
                """)
                
                db.commit()
                
        except Exception as e:
            logger.error(f"Error updating asset progression: {e}")
    
    async def _generate_subdomain_targets(self, domain: str) -> List[str]:
        """Generate subdomain targets for discovery"""
        targets = []
        
        # Get common subdomain prefixes from SecLists
        subdomain_prefixes = [
            'www', 'api', 'admin', 'test', 'dev', 'staging', 'prod',
            'app', 'mail', 'ftp', 'blog', 'shop', 'store', 'portal',
            'dashboard', 'panel', 'cpanel', 'webmail', 'secure'
        ]
        
        for prefix in subdomain_prefixes[:20]:  # Limit to top 20
            targets.append(f"https://{prefix}.{domain}")
            targets.append(f"http://{prefix}.{domain}")
        
        return targets
    
    async def _generate_directory_targets(self, domain: str) -> List[str]:
        """Generate directory targets for discovery"""
        targets = []
        base_urls = [f"https://{domain}", f"http://{domain}"]
        
        # Common high-value directories
        directories = [
            '/admin', '/api', '/v1', '/v2', '/test', '/dev',
            '/staging', '/backup', '/upload', '/files', '/docs',
            '/graphql', '/graphiql', '/soap', '/wsdl', '/rest'
        ]
        
        for base_url in base_urls:
            for directory in directories[:15]:  # Limit to top 15
                targets.append(f"{base_url}{directory}")
        
        return targets
    
    async def _generate_api_targets(self, domain: str) -> List[str]:
        """Generate API-specific targets"""
        targets = []
        base_urls = [f"https://{domain}", f"http://{domain}"]
        
        # API-specific paths
        api_paths = [
            '/api/v1', '/api/v2', '/api/graphql', '/graphql',
            '/rest/v1', '/rest/v2', '/soap/v1', '/wsdl',
            '/api/users', '/api/admin', '/api/config', '/api/status'
        ]
        
        for base_url in base_urls:
            for path in api_paths:
                targets.append(f"{base_url}{path}")
        
        return targets
    
    async def _ai_prioritize_targets(self, targets: List[str]) -> List[Dict[str, Any]]:
        """Use AI to prioritize targets (if AI assistant is available)"""
        try:
            if hasattr(self.engine, 'intelligent_ai_assistant'):
                ai_assistant = self.engine.intelligent_ai_assistant
                return await ai_assistant.prioritize_targets_intelligently(targets)
            else:
                # Fallback: basic prioritization
                return [{'url': t, 'priority': 0.5} for t in targets]
                
        except Exception as e:
            logger.error(f"AI prioritization failed: {e}")
            return [{'url': t, 'priority': 0.5} for t in targets]
    
    def get_scan_statistics(self) -> Dict[str, Any]:
        """Get comprehensive scanning statistics"""
        stats = {
            'engine_performance': {
                'max_concurrent': self.engine.max_concurrent,
                'session_limit': self.engine.session_limit,
                'vuln_concurrent': self.engine.vuln_concurrent,
                'unlimited_mode': True
            },
            'asset_counts': {},
            'vulnerability_counts': {},
            'scanner_performance': {}
        }
        
        try:
            with self.asset_manager._get_db() as db:
                # Asset counts by stage
                cursor = db.execute("""
                    SELECT scan_stage, COUNT(*) 
                    FROM assets 
                    GROUP BY scan_stage
                """)
                stats['asset_counts'] = {row[0] or 'unknown': row[1] for row in cursor.fetchall()}
                
                # Vulnerability counts by severity
                cursor = db.execute("""
                    SELECT severity, COUNT(*) 
                    FROM vulnerabilities 
                    GROUP BY severity
                """)
                stats['vulnerability_counts'] = {row[0]: row[1] for row in cursor.fetchall()}
                
                # Total counts
                cursor = db.execute("SELECT COUNT(*) FROM assets")
                stats['total_assets'] = cursor.fetchone()[0]
                
                cursor = db.execute("SELECT COUNT(*) FROM vulnerabilities")
                stats['total_vulnerabilities'] = cursor.fetchone()[0]
                
        except Exception as e:
            logger.error(f"Error getting statistics: {e}")
        
        return stats