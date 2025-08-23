#!/usr/bin/env python3
"""
Manual Screenshot Update for Key Assets
Simple script to retake screenshots with fresh authentication
"""
import requests
import re
import sys
import os
import time
from pathlib import Path

sys.path.append('.')
from asset_manager import AssetManager

def get_fresh_dvwa_auth():
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
    return auth_cookies, session

def take_authenticated_screenshot(url, session, filename):
    """Take a screenshot using browser automation with authentication"""
    print(f"📸 Taking screenshot of {url}...")
    
    try:
        # First, verify we can access the page
        response = session.get(url, timeout=10)
        print(f"   Status: {response.status_code}, Length: {len(response.text)}")
        
        if response.status_code != 200:
            print(f"   ❌ HTTP error {response.status_code}")
            return False
        
        if 'login' in response.text.lower() and len(response.text) < 2000:
            print(f"   ❌ Got login page - authentication failed")
            return False
        
        # Use Playwright for screenshot with session cookies
        import subprocess
        
        # Build cookie string for browser
        cookie_header = '; '.join([f'{c.name}={c.value}' for c in session.cookies])
        
        # Create a simple Playwright script
        playwright_script = f'''
const {{ chromium }} = require('playwright');

(async () => {{
  const browser = await chromium.launch({{ headless: true }});
  const context = await browser.newContext();
  
  // Set cookies
  await context.addCookies([
    {{
      name: 'PHPSESSID',
      value: '{session.cookies.get('PHPSESSID')}',
      domain: '192.168.1.42',
      path: '/'
    }},
    {{
      name: 'security',
      value: '{session.cookies.get('security', 'low')}',
      domain: '192.168.1.42',
      path: '/'
    }}
  ]);
  
  const page = await context.newPage();
  await page.goto('{url}');
  await page.waitForTimeout(2000);
  await page.screenshot({{ path: '{filename}', fullPage: true }});
  await browser.close();
}})();
'''
        
        # Write script to temp file
        script_path = f'/tmp/screenshot_{int(time.time())}.js'
        with open(script_path, 'w') as f:
            f.write(playwright_script)
        
        # Run Playwright
        result = subprocess.run(['node', script_path], 
                              capture_output=True, text=True, timeout=30)
        
        # Clean up
        os.unlink(script_path)
        
        if result.returncode == 0 and os.path.exists(filename):
            file_size = os.path.getsize(filename)
            print(f"   ✅ Screenshot saved: {filename} ({file_size} bytes)")
            return True
        else:
            print(f"   ❌ Playwright failed: {result.stderr}")
            return False
            
    except Exception as e:
        print(f"   ⚠️  Screenshot error: {e}")
        return False

def main():
    """Main function"""
    try:
        # Get fresh authentication
        auth_cookies, session = get_fresh_dvwa_auth()
        
        # Initialize asset manager
        am = AssetManager()
        
        # Key SQLi assets to update
        sqli_assets = [
            {'id': 38, 'url': 'http://192.168.1.42/dvwa/vulnerabilities/sqli/'},
            {'id': 49, 'url': 'http://192.168.1.42/dvwa/vulnerabilities/sqli_blind/'}
        ]
        
        print(f"\n🎯 Updating screenshots for {len(sqli_assets)} key assets...")
        
        success_count = 0
        screenshots_dir = Path('screenshots')
        screenshots_dir.mkdir(exist_ok=True)
        
        for asset in sqli_assets:
            asset_id = asset['id']
            url = asset['url']
            
            print(f"\n📍 Asset {asset_id}: {url}")
            
            # Generate new filename
            import hashlib
            url_hash = hashlib.md5(url.encode()).hexdigest()[:8]
            timestamp = int(time.time())
            filename = screenshots_dir / f"dvwa_sqli_{asset_id}_{timestamp}_{url_hash}.png"
            
            # Take screenshot
            if take_authenticated_screenshot(url, session, str(filename)):
                # Update asset in database
                am.update_screenshot_path(asset_id, str(filename))
                print(f"   💾 Database updated with new screenshot path")
                success_count += 1
            else:
                print(f"   ❌ Failed to update asset {asset_id}")
        
        print(f"\n📊 Update complete!")
        print(f"   Successfully updated: {success_count}/{len(sqli_assets)} assets")
        
        if success_count > 0:
            print(f"\n💡 Dashboard will show updated screenshots")
            print(f"   Fresh screenshots show actual vulnerability pages, not login")
            
    except Exception as e:
        print(f"❌ Error: {e}")
        import traceback
        traceback.print_exc()

if __name__ == "__main__":
    main()