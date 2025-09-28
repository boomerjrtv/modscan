#!/usr/bin/env python3
"""
Stealth Headers Module - Advanced Anti-Detection for ModScan

Provides realistic browser headers and stealth techniques to avoid 403 blocks
from enterprise security systems like Cloudflare, Akamai, AWS WAF, etc.
"""

import random
import time
from typing import Dict, List, Optional

class StealthHeaders:
    """Generate realistic browser headers to avoid detection"""
    
    # Real Chrome User-Agents (updated Sept 2025)
    CHROME_USER_AGENTS = [
        "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/128.0.6613.113 Safari/537.36",
        "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/128.0.6613.113 Safari/537.36",
        "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/128.0.6613.113 Safari/537.36",
        "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/127.0.0.0 Safari/537.36",
        "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/127.0.0.0 Safari/537.36",
    ]
    
    # Real Firefox User-Agents
    FIREFOX_USER_AGENTS = [
        "Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:109.0) Gecko/20100101 Firefox/118.0",
        "Mozilla/5.0 (Macintosh; Intel Mac OS X 10.15; rv:109.0) Gecko/20100101 Firefox/118.0",
        "Mozilla/5.0 (X11; Linux x86_64; rv:109.0) Gecko/20100101 Firefox/118.0",
    ]
    
    # Common Accept headers by browser type
    ACCEPT_HEADERS = {
        'chrome': "text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,image/apng,*/*;q=0.8,application/signed-exchange;v=b3;q=0.7",
        'firefox': "text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,*/*;q=0.8"
    }
    
    ACCEPT_LANGUAGE_OPTIONS = [
        "en-US,en;q=0.9",
        "en-US,en;q=0.5", 
        "en-GB,en-US;q=0.9,en;q=0.8",
    ]
    
    ACCEPT_ENCODING = "gzip, deflate, br"
    
    def __init__(self):
        self.current_user_agent = None
        self.browser_type = None
        self._initialize_session()
    
    def _initialize_session(self):
        """Initialize a consistent browser session"""
        # Choose browser type (80% Chrome, 20% Firefox like real usage)
        self.browser_type = 'chrome' if random.random() < 0.8 else 'firefox'
        
        if self.browser_type == 'chrome':
            self.current_user_agent = random.choice(self.CHROME_USER_AGENTS)
        else:
            self.current_user_agent = random.choice(self.FIREFOX_USER_AGENTS)
    
    def get_stealth_headers(self, url: str = "", additional_headers: Optional[Dict[str, str]] = None) -> Dict[str, str]:
        """
        Generate realistic browser headers that avoid detection
        
        Args:
            url: Target URL (for Referer header if needed)
            additional_headers: Any additional headers to include
            
        Returns:
            Dictionary of HTTP headers that mimic a real browser
        """
        headers = {
            "User-Agent": self.current_user_agent,
            "Accept": self.ACCEPT_HEADERS[self.browser_type],
            "Accept-Language": random.choice(self.ACCEPT_LANGUAGE_OPTIONS),
            "Accept-Encoding": self.ACCEPT_ENCODING,
            "DNT": "1",
            "Connection": "keep-alive",
            "Upgrade-Insecure-Requests": "1",
        }
        
        # Add Chrome-specific headers
        if self.browser_type == 'chrome':
            headers.update({
                "sec-ch-ua": '"Chromium";v="128", "Not;A=Brand";v="24", "Google Chrome";v="128"',
                "sec-ch-ua-mobile": "?0",
                "sec-ch-ua-platform": '"Windows"',
                "Sec-Fetch-Site": "none",
                "Sec-Fetch-Mode": "navigate",
                "Sec-Fetch-User": "?1",
                "Sec-Fetch-Dest": "document",
            })
        
        # Add any additional headers
        if additional_headers:
            headers.update(additional_headers)
        
        return headers
    
    def get_api_headers(self, referer: str = "") -> Dict[str, str]:
        """Get headers suitable for API requests"""
        headers = {
            "User-Agent": self.current_user_agent,
            "Accept": "application/json, text/plain, */*",
            "Accept-Language": random.choice(self.ACCEPT_LANGUAGE_OPTIONS),
            "Accept-Encoding": self.ACCEPT_ENCODING,
            "Connection": "keep-alive",
        }
        
        if referer:
            headers["Referer"] = referer
        
        if self.browser_type == 'chrome':
            headers.update({
                "sec-ch-ua": '"Chromium";v="128", "Not;A=Brand";v="24", "Google Chrome";v="128"',
                "sec-ch-ua-mobile": "?0",
                "sec-ch-ua-platform": '"Windows"',
                "Sec-Fetch-Site": "same-origin",
                "Sec-Fetch-Mode": "cors",
                "Sec-Fetch-Dest": "empty",
            })
        
        return headers


# Global instance for easy access
stealth_headers = StealthHeaders()

def get_stealth_headers(url: str = "", additional_headers: Optional[Dict[str, str]] = None) -> Dict[str, str]:
    """Convenience function to get stealth headers"""
    return stealth_headers.get_stealth_headers(url, additional_headers)

def get_api_headers(referer: str = "") -> Dict[str, str]:
    """Convenience function to get API headers"""
    return stealth_headers.get_api_headers(referer)
