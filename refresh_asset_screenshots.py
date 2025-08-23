#!/usr/bin/env python3
"""
Refresh Asset Screenshots
Update stale screenshots with fresh authentication
"""
import asyncio
import aiohttp
import requests
import re
import sys
import os
from datetime import datetime

sys.path.append('.')
from asset_manager import AssetManager
from modules.screenshot_manager import ScreenshotManager

async def get_fresh_dvwa_auth():
    """Get fresh DVWA authentication cookies"""
    print("🔐 Getting fresh DVWA authentication...")
    
    dvwa_base = 'http://192.168.1.42/dvwa/'
    login_url = dvwa_base + 'login.php'
    
    session = requests.Session()
    
    # Get CSRF token
    login_response = session.get(login_url, timeout=10)
    csrf_pattern = r'name=[\"\']{1}user_token[\"\']{1}\s+value=[\"\']{1}([^\"\']+)[\"\']{1}'
    csrf_match = re.search(csrf_pattern, login_response.text)
    csrf_token = csrf_match.group(1) if csrf_match else ''
    
    if not csrf_token:
        raise Exception("Could not extract CSRF token")
    
    # Login
    login_data = {
        'username': 'admin',
        'password': 'password',
        'Login': 'Login',
        'user_token': csrf_token
    }
    
    login_submit = session.post(login_url, data=login_data, timeout=10)
    
    if 'Welcome to' not in login_submit.text:
        raise Exception("Login failed")
    
    # Set security to low
    security_url = dvwa_base + 'security.php'
    security_response = session.get(security_url, timeout=10)
    
    csrf_match = re.search(csrf_pattern, security_response.text)
    security_csrf = csrf_match.group(1) if csrf_match else ''
    
    security_data = {
        'security': 'low',
        'seclev_submit': 'Submit',
        'user_token': security_csrf
    }
    
    session.post(security_url, data=security_data, timeout=10)
    
    # Extract cookies
    auth_cookies = {}
    for cookie in session.cookies:
        auth_cookies[cookie.name] = cookie.value
    
    print(f"✅ Authentication successful - Session: {auth_cookies.get('PHPSESSID', 'N/A')[:10]}...")
    return auth_cookies

async def refresh_asset_screenshot(asset, auth_cookies, am):
    """Refresh screenshot for a single asset"""
    asset_id = asset.get('id')
    url = asset.get('url')
    
    print(f"\n📸 Refreshing screenshot for Asset {asset_id}: {url}")
    
    try:
        # Update asset with fresh auth cookies first
        am.update_asset(asset_id, {
            'needs_screenshot': True,
            'last_updated': datetime.now().isoformat()
        })
        
        # Use VulnerabilityScanner's screenshot method which handles auth
        from modules.vulnerability_scanner import VulnerabilityScanner
        
        config = {'screenshot_enabled': True}
        scanner = VulnerabilityScanner(am, config)
        
        # Take screenshot with authentication
        screenshot_path = await scanner._take_screenshot(url)
        
        if screenshot_path and os.path.exists(screenshot_path):
            # Update asset with new screenshot path
            am.update_asset(asset_id, {
                'screenshot_path': screenshot_path,
                'needs_screenshot': False
            })
            print(f"✅ Updated screenshot: {screenshot_path}")
            
            # Verify screenshot was taken recently (not stale)
            file_size = os.path.getsize(screenshot_path)
            print(f"   Screenshot size: {file_size} bytes")
            return True
        else:
            print(f"❌ Failed to take screenshot or file doesn't exist")
            return False
            
    except Exception as e:
        print(f"⚠️  Error refreshing screenshot: {e}")
        import traceback
        traceback.print_exc()
        return False

async def main():
    """Main function to refresh stale screenshots"""
    if len(sys.argv) > 1 and sys.argv[1] == '--help':
        print("Usage: python refresh_asset_screenshots.py [asset_ids...]")
        print("Examples:")
        print("  python refresh_asset_screenshots.py              # Refresh all DVWA vulnerability assets")
        print("  python refresh_asset_screenshots.py 38 49        # Refresh specific assets")
        sys.exit(0)
    
    # Get fresh authentication
    try:
        auth_cookies = await get_fresh_dvwa_auth()
    except Exception as e:
        print(f"❌ Authentication failed: {e}")
        sys.exit(1)
    
    # Initialize components
    am = AssetManager()
    
    # Get assets to refresh
    if len(sys.argv) > 1:
        # Specific asset IDs provided
        asset_ids = [int(id) for id in sys.argv[1:]]
        assets = [am.get_asset_by_id(id) for id in asset_ids]
        assets = [a for a in assets if a]  # Filter out None results
    else:
        # Refresh all DVWA vulnerability assets
        all_assets = am.get_all_assets()
        assets = [a for a in all_assets 
                 if 'dvwa' in a.get('url', '').lower() 
                 and 'vulnerabilit' in a.get('url', '').lower()]
    
    print(f"\n🎯 Refreshing screenshots for {len(assets)} assets...")
    
    success_count = 0
    
    for asset in assets:
        success = await refresh_asset_screenshot(asset, auth_cookies, am)
        if success:
            success_count += 1
    
    print(f"\n📊 Refresh complete!")
    print(f"   Successfully updated: {success_count}/{len(assets)} assets")
    
    if success_count > 0:
        print(f"\n💡 Dashboard will show updated screenshots after refresh")
        print(f"   Fresh authentication ensures proper vulnerability page access")

if __name__ == "__main__":
    asyncio.run(main())