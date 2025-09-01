#!/usr/bin/env python3
"""
Fix Screenshot Database Links

This script finds screenshot files that exist but aren't linked in the database
and updates the database records accordingly.
"""

import sqlite3
import os
import glob
import re

def fix_screenshot_links():
    print("🔧 Fixing screenshot database links...")
    
    # Connect to database
    conn = sqlite3.connect('lean_recon.db')
    cursor = conn.cursor()
    
    # Get all screenshot files
    screenshot_files = glob.glob('screenshots/*.png')
    print(f"📁 Found {len(screenshot_files)} screenshot files")
    
    # Get all assets missing screenshot links
    cursor.execute("""
        SELECT url, id FROM assets 
        WHERE (screenshot_path IS NULL OR screenshot_path = '') 
        AND status_code IN (200, 403, 430)
    """)
    assets_missing_screenshots = cursor.fetchall()
    print(f"🔍 Found {len(assets_missing_screenshots)} assets missing screenshot links")
    
    fixed_count = 0
    
    for url, asset_id in assets_missing_screenshots:
        # Extract domain from URL for matching
        # Remove protocol and trailing slash
        domain = url.replace('https://', '').replace('http://', '').rstrip('/')
        
        # Look for matching screenshot files
        matches = []
        for screenshot_file in screenshot_files:
            filename = os.path.basename(screenshot_file)
            # Remove .png extension for comparison
            base_name = filename.replace('.png', '')
            
            # Check if domain matches the screenshot filename
            if domain in base_name or base_name.startswith(domain.replace('.', '_')):
                matches.append(screenshot_file)
        
        if matches:
            # Use the most recent screenshot (longest filename usually has hash)
            best_match = max(matches, key=len)
            
            # Update database
            cursor.execute("""
                UPDATE assets SET 
                    screenshot_path = ?,
                    screenshot_complete = 1
                WHERE id = ?
            """, (best_match, asset_id))
            
            print(f"✅ Linked {url} -> {best_match}")
            fixed_count += 1
    
    # Commit changes
    conn.commit()
    conn.close()
    
    print(f"🎯 Fixed {fixed_count} screenshot links!")
    return fixed_count

if __name__ == "__main__":
    fix_screenshot_links()