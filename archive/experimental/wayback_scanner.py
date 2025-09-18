#!/usr/bin/env python3
"""
Wayback Machine Historical Vulnerability Scanner
Integrates with ModScan to test against archived versions of targets
"""

import requests
import json
import time
from datetime import datetime, timedelta
from urllib.parse import urljoin, urlparse
import sqlite3

class WaybackScanner:
    def __init__(self, database_path="lean_recon.db"):
        self.db_path = database_path
        self.wayback_api = "https://web.archive.org/cdx/search/cdx"
        
    def get_historical_snapshots(self, url, years_back=5, limit=100):
        """Get archived snapshots of a URL from Wayback Machine"""
        
        # Calculate date range
        end_date = datetime.now()
        start_date = end_date - timedelta(days=years_back * 365)
        
        params = {
            'url': url + "/*",
            'output': 'json',
            'from': start_date.strftime('%Y%m%d'),
            'to': end_date.strftime('%Y%m%d'),
            'collapse': 'urlkey',
            'limit': limit
        }
        
        try:
            response = requests.get(self.wayback_api, params=params, timeout=30)
            if response.status_code == 200:
                data = response.json()
                if data:
                    # Skip header row
                    snapshots = []
                    for row in data[1:]:
                        snapshots.append({
                            'urlkey': row[0],
                            'timestamp': row[1],
                            'original_url': row[2],
                            'mimetype': row[3] if len(row) > 3 else '',
                            'statuscode': row[4] if len(row) > 4 else '',
                            'wayback_url': f"https://web.archive.org/web/{row[1]}/{row[2]}"
                        })
                    return snapshots
        except Exception as e:
            print(f"Error fetching Wayback data: {e}")
        
        return []
    
    def extract_historical_endpoints(self, snapshots):
        """Extract unique endpoints and parameters from historical snapshots"""
        
        endpoints = set()
        parameters = set()
        
        for snapshot in snapshots:
            url = snapshot['original_url']
            parsed = urlparse(url)
            
            # Extract endpoint paths
            if parsed.path and parsed.path != '/':
                endpoints.add(parsed.path)
            
            # Extract parameters
            if parsed.query:
                params = parsed.query.split('&')
                for param in params:
                    if '=' in param:
                        param_name = param.split('=')[0]
                        parameters.add(param_name)
        
        return list(endpoints), list(parameters)
    
    def find_sensitive_exposures(self, snapshots):
        """Look for potentially sensitive files in historical snapshots"""
        
        sensitive_patterns = [
            '.git/',
            'config.php',
            'wp-config.php',
            'database.yml',
            '.env',
            'phpinfo.php',
            'admin/',
            'backup/',
            'test/',
            'debug/',
            'api/',
            '.sql',
            '.bak',
            '.old'
        ]
        
        exposures = []
        for snapshot in snapshots:
            url = snapshot['original_url'].lower()
            for pattern in sensitive_patterns:
                if pattern in url:
                    exposures.append({
                        'pattern': pattern,
                        'url': snapshot['original_url'],
                        'wayback_url': snapshot['wayback_url'],
                        'timestamp': snapshot['timestamp'],
                        'status_code': snapshot.get('statuscode', 'unknown')
                    })
        
        return exposures
    
    def enhance_target_with_history(self, target_url):
        """Enhance a target with historical reconnaissance data"""
        
        print(f"🕰️ Analyzing historical data for: {target_url}")
        
        # Get snapshots
        snapshots = self.get_historical_snapshots(target_url)
        if not snapshots:
            print("No historical snapshots found")
            return
        
        print(f"Found {len(snapshots)} historical snapshots")
        
        # Extract endpoints and parameters
        endpoints, parameters = self.extract_historical_endpoints(snapshots)
        print(f"Discovered {len(endpoints)} historical endpoints")
        print(f"Discovered {len(parameters)} historical parameters")
        
        # Find sensitive exposures
        exposures = self.find_sensitive_exposures(snapshots)
        if exposures:
            print(f"⚠️ Found {len(exposures)} potentially sensitive exposures:")
            for exp in exposures[:10]:  # Show first 10
                print(f"  - {exp['pattern']}: {exp['url']}")
        
        # Store in database for ModScan to use
        self.store_historical_intelligence(target_url, endpoints, parameters, exposures)
        
        return {
            'snapshots': len(snapshots),
            'endpoints': endpoints,
            'parameters': parameters,
            'exposures': exposures
        }
    
    def store_historical_intelligence(self, target_url, endpoints, parameters, exposures):
        """Store historical intelligence in ModScan database"""
        
        try:
            conn = sqlite3.connect(self.db_path)
            cursor = conn.cursor()
            
            # Create wayback intelligence table if not exists
            cursor.execute('''
                CREATE TABLE IF NOT EXISTS wayback_intelligence (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    target_url TEXT,
                    intelligence_type TEXT,
                    data TEXT,
                    discovered_at TEXT,
                    UNIQUE(target_url, intelligence_type, data)
                )
            ''')
            
            timestamp = datetime.now().isoformat()
            
            # Store endpoints
            for endpoint in endpoints:
                cursor.execute('''
                    INSERT OR IGNORE INTO wayback_intelligence 
                    (target_url, intelligence_type, data, discovered_at)
                    VALUES (?, ?, ?, ?)
                ''', (target_url, 'historical_endpoint', endpoint, timestamp))
            
            # Store parameters
            for param in parameters:
                cursor.execute('''
                    INSERT OR IGNORE INTO wayback_intelligence 
                    (target_url, intelligence_type, data, discovered_at)
                    VALUES (?, ?, ?, ?)
                ''', (target_url, 'historical_parameter', param, timestamp))
            
            # Store exposures
            for exposure in exposures:
                cursor.execute('''
                    INSERT OR IGNORE INTO wayback_intelligence 
                    (target_url, intelligence_type, data, discovered_at)
                    VALUES (?, ?, ?, ?)
                ''', (target_url, 'sensitive_exposure', json.dumps(exposure), timestamp))
            
            conn.commit()
            conn.close()
            
            print(f"✅ Stored historical intelligence in database")
            
        except Exception as e:
            print(f"Error storing historical intelligence: {e}")

def main():
    """Test the Wayback Scanner"""
    
    scanner = WaybackScanner()
    
    # Test targets from your previous scans
    test_targets = [
        "https://testhtml5.vulnweb.com",
        "https://testphp.vulnweb.com", 
        "https://testasp.vulnweb.com"
    ]
    
    for target in test_targets:
        print(f"\n{'='*60}")
        results = scanner.enhance_target_with_history(target)
        if results:
            print(f"Historical analysis complete for {target}")
            time.sleep(2)  # Be respectful to Wayback Machine API

if __name__ == "__main__":
    main()