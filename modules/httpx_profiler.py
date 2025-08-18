#!/usr/bin/env python3
"""
HTTPx Profiler Module - Fast and reliable HTTP profiling
Replaces the broken asset profiling with HTTPx for real status codes, titles, and tech detection
"""

import asyncio
import subprocess
import json
import logging
import tempfile
from pathlib import Path
from typing import List, Dict, Optional
from datetime import datetime

logger = logging.getLogger("HTTPxProfiler")

class HTTPxProfiler:
    def __init__(self, asset_manager, config):
        self.asset_manager = asset_manager
        self.config = config
        self.httpx_path = config.get("httpx", {}).get("path", "httpx")
        self.max_concurrent = config.get("httpx", {}).get("max_concurrent", 50)
        
    async def profile_assets_batch(self, assets: List[Dict]) -> int:
        """Profile a batch of assets using HTTPx for fast and reliable results"""
        if not assets:
            return 0
            
        logger.info(f"🔍 HTTPX PROFILING: {len(assets)} assets")
        
        # Extract URLs from assets
        urls = [asset['url'] for asset in assets if asset.get('url')]
        if not urls:
            return 0
            
        try:
            # Create temporary file with URLs
            with tempfile.NamedTemporaryFile(mode='w', delete=False, suffix='.txt') as f:
                for url in urls:
                    f.write(f"{url}\n")
                url_file = f.name
            
            # Run HTTPx with comprehensive options
            httpx_cmd = [
                self.httpx_path,
                "-l", url_file,
                "-json",                    # JSON output
                "-status-code",             # Include status codes
                "-title",                   # Extract page titles
                "-tech-detect",             # Technology detection
                "-content-length",          # Response size
                "-response-time",           # Response timing
                "-follow-redirects",        # Follow redirects
                "-include-response",        # Include response body
                "-no-color",               # Clean output
                "-silent",                 # Reduce noise
                "-timeout", "30",          # 30 second timeout
                "-threads", str(min(self.max_concurrent, 50)),  # Concurrent threads
                "-retries", "2",           # Retry failed requests
                "-rate-limit", "100"       # Rate limiting
            ]
            
            # Add proxy if configured
            if self.config.get("proxy_list"):
                proxy = self.config["proxy_list"][0]  # Use first proxy
                httpx_cmd.extend(["-http-proxy", proxy])
                
            logger.info(f"🚀 Running HTTPx: {' '.join(httpx_cmd[:10])}...")
            
            # Execute HTTPx
            process = await asyncio.create_subprocess_exec(
                *httpx_cmd,
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE
            )
            
            stdout, stderr = await process.communicate()
            
            if process.returncode != 0:
                logger.error(f"HTTPx failed: {stderr.decode()}")
                return 0
                
            # Parse HTTPx JSON output
            profiles_updated = 0
            for line in stdout.decode().strip().split('\n'):
                if not line.strip():
                    continue
                    
                try:
                    result = json.loads(line)
                    url = result.get('url', '')
                    
                    if not url:
                        continue
                        
                    # Extract HTTPx data
                    body_raw = result.get('body')
                    logger.debug(f"Raw body from HTTPx: {body_raw[:100] if body_raw else 'None'}")
                    
                    profile_data = {
                        'url': url,
                        'status_code': result.get('status_code'),
                        'title': result.get('title', '').strip()[:200] if result.get('title') else None,
                        'content_length': result.get('content_length'),
                        'response_time': self._parse_response_time(result.get('time')),
                        'tech_stack': self._parse_technologies(result.get('tech', [])),
                        'final_url': result.get('final_url', url),
                        'response_body': self._parse_response_body(body_raw),
                        'last_scanned': datetime.now().isoformat()
                    }
                    
                    logger.debug(f"Parsed response body: {profile_data['response_body'][:100] if profile_data['response_body'] else 'None'}")
                    
                    # Update asset in database with corrected workflow
                    await self._update_asset_profile_fixed(url, profile_data)
                    profiles_updated += 1
                    
                    if profiles_updated % 10 == 0:
                        logger.info(f"✅ Profiled {profiles_updated} assets...")
                        
                except json.JSONDecodeError as e:
                    logger.debug(f"Failed to parse HTTPx JSON: {line[:100]}")
                    continue
                except Exception as e:
                    logger.error(f"Error processing HTTPx result: {e}")
                    continue
            
            # Cleanup
            Path(url_file).unlink(missing_ok=True)
            
            logger.info(f"🎯 HTTPX COMPLETE: Profiled {profiles_updated}/{len(urls)} assets")
            return profiles_updated
            
        except Exception as e:
            logger.error(f"HTTPx profiling failed: {e}")
            return 0
    
    def _parse_response_time(self, time_str: str) -> Optional[int]:
        """Parse HTTPx response time to milliseconds"""
        if not time_str:
            return None
            
        try:
            # HTTPx returns time like "123ms" or "1.2s"
            if time_str.endswith('ms'):
                return int(float(time_str[:-2]))
            elif time_str.endswith('s'):
                return int(float(time_str[:-1]) * 1000)
            else:
                return int(float(time_str) * 1000)
        except:
            return None
    
    def _parse_technologies(self, tech_list: List[str]) -> Optional[str]:
        """Parse HTTPx technology detection results"""
        if not tech_list:
            return None
            
        # Clean and format technologies
        clean_tech = []
        for tech in tech_list:
            if isinstance(tech, str) and tech.strip():
                clean_tech.append(tech.strip())
                
        return ', '.join(clean_tech[:5]) if clean_tech else None  # Limit to 5 technologies
    
    def _parse_response_body(self, body: str) -> Optional[str]:
        """Parse and sanitize response body data"""
        if body is None:
            return None
        if not isinstance(body, str):
            body = str(body)
        if not body:
            return None
            
        # Truncate to reasonable size (10KB) and clean
        cleaned_body = body.strip()[:10240]
        
        # Remove null bytes and control characters
        cleaned_body = ''.join(char for char in cleaned_body if ord(char) >= 32 or char in '\t\n\r')
        
        return cleaned_body if cleaned_body else None
    
    async def _update_asset_profile_fixed(self, url: str, profile_data: Dict):
        """Update asset with HTTPx profile data using corrected workflow"""
        try:
            # Find asset by URL
            asset = self.asset_manager.get_asset_by_url(url)
            if not asset or not asset.get('id'):
                logger.debug(f"Asset not found for URL: {url}")
                return
            
            # Build update fields dict
            update_fields = {}
            
            if profile_data.get('status_code'):
                update_fields['status_code'] = profile_data['status_code']
                
            if profile_data.get('title'):
                update_fields['title'] = profile_data['title']
                
            if profile_data.get('content_length'):
                update_fields['content_length'] = profile_data['content_length']
                
            if profile_data.get('response_time'):
                update_fields['response_time'] = profile_data['response_time']
                
            if profile_data.get('tech_stack'):
                update_fields['tech_stack'] = profile_data['tech_stack']
                
            if profile_data.get('last_scanned'):
                update_fields['discovered_at'] = profile_data['last_scanned']
                
            if profile_data.get('response_body'):
                update_fields['response_body'] = profile_data['response_body']
            
            # Update in database using correct method
            if update_fields:
                self.asset_manager.update_asset_fields(asset['id'], update_fields)
                logger.debug(f"✅ Updated asset: {url} -> {profile_data.get('status_code', 'N/A')}")
                
        except Exception as e:
            logger.error(f"Failed to update asset profile: {e}")

    async def _update_asset_profile(self, url: str, profile_data: Dict):
        """Update asset with HTTPx profile data"""
        try:
            # Find asset by URL
            asset_data = self.asset_manager.get_asset_by_url(url)
            if not asset_data:
                logger.debug(f"Asset not found for URL: {url}")
                return
                
            # Update asset with profile data
            update_fields = {}
            
            if profile_data.get('status_code'):
                update_fields['status_code'] = profile_data['status_code']
                
            if profile_data.get('title'):
                update_fields['title'] = profile_data['title']
                
            if profile_data.get('content_length'):
                update_fields['content_length'] = profile_data['content_length']
                
            if profile_data.get('response_time'):
                update_fields['response_time'] = profile_data['response_time']
                
            if profile_data.get('tech_stack'):
                update_fields['tech_stack'] = profile_data['tech_stack']
                
            if profile_data.get('last_scanned'):
                update_fields['last_scanned'] = profile_data['last_scanned']
            
            # Update in database
            if update_fields:
                self.asset_manager.update_asset_fields(asset_data['id'], update_fields)
                logger.debug(f"✅ Updated asset: {url} -> {profile_data.get('status_code', 'N/A')}")
                
        except Exception as e:
            logger.error(f"Failed to update asset profile: {e}")
    
    async def profile_unscanned_assets(self, limit: int = 100) -> int:
        """Profile assets that haven't been scanned yet"""
        try:
            # Get unscanned assets (no status code)
            unscanned = self.asset_manager.get_assets_without_status_codes(limit=limit)
            
            if not unscanned:
                logger.info("No unscanned assets found")
                return 0
                
            logger.info(f"🎯 Found {len(unscanned)} unscanned assets")
            return await self.profile_assets_batch(unscanned)
            
        except Exception as e:
            logger.error(f"Failed to profile unscanned assets: {e}")
            return 0