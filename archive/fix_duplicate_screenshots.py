#!/usr/bin/env python3
"""
Fix Duplicate Screenshot Links

Copy screenshot paths from working entries (200 status) to their redirect counterparts
(301/302 status) so all variations of the same domain have screenshots.
"""

import sqlite3
from urllib.parse import urlparse

def fix_duplicate_screenshots():
    print("🔧 Fixing duplicate screenshot links...")
    
    conn = sqlite3.connect('lean_recon.db')
    cursor = conn.cursor()
    
    # Find assets with screenshots (200 status, trailing slash)
    cursor.execute("""
        SELECT url, screenshot_path, host 
        FROM assets 
        WHERE screenshot_path IS NOT NULL 
        AND screenshot_path != ''
        AND status_code = 200
        AND url LIKE '%/'
    """)
    
    assets_with_screenshots = cursor.fetchall()
    print(f"📸 Found {len(assets_with_screenshots)} assets with screenshots")
    
    fixed_count = 0
    
    for url, screenshot_path, host in assets_with_screenshots:
        # Find related entries for the same domain
        domain = host  # Use the host field which should be consistent
        
        # Find all other entries for this domain without screenshots
        cursor.execute("""
            SELECT id, url FROM assets 
            WHERE host = ? 
            AND (screenshot_path IS NULL OR screenshot_path = '')
            AND id != (SELECT id FROM assets WHERE url = ?)
        """, (domain, url))
        
        related_entries = cursor.fetchall()
        
        for asset_id, related_url in related_entries:
            # Update the related entry with the same screenshot
            cursor.execute("""
                UPDATE assets SET 
                    screenshot_path = ?,
                    screenshot_complete = 1
                WHERE id = ?
            """, (screenshot_path, asset_id))
            
            print(f"✅ Copied screenshot: {related_url} -> {screenshot_path}")
            fixed_count += 1
    
    conn.commit()
    conn.close()
    
    print(f"🎯 Fixed {fixed_count} duplicate screenshot links!")
    return fixed_count

if __name__ == "__main__":
    fix_duplicate_screenshots()