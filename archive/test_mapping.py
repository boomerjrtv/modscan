#!/usr/bin/env python3
import urllib.request
import json

# Test the API directly
mapping_response = urllib.request.urlopen('http://localhost:8000/api/asset_mapping')
mapping_data = json.loads(mapping_response.read())

assets_response = urllib.request.urlopen('http://localhost:8000/api/assets?limit=3')
assets_data = json.loads(assets_response.read())

print("=== ASSET MAPPING TEST ===")
print("Screenshot field mapping:", mapping_data['field_mappings']['screenshot'])
print("Response field mapping:", mapping_data['field_mappings']['response'])
print()

for i, asset in enumerate(assets_data['assets'][:3]):
    print(f"Asset {i+1}: {asset['url']}")
    
    # Test screenshot
    screenshot_path = asset.get('screenshot_path', '')
    print(f"  Screenshot path: '{screenshot_path}'")
    
    has_screenshot = (screenshot_path and 
                     screenshot_path != 'NONE' and 
                     screenshot_path != '' and
                     'placeholder' not in str(screenshot_path) and
                     str(screenshot_path).endswith('.png'))
    
    print(f"  Has screenshot: {has_screenshot}")
    
    # Test response
    response_body = asset.get('response_body', '')
    print(f"  Response body length: {len(response_body or '')} chars")
    if response_body:
        print(f"  Response preview: {response_body[:50]}...")
    
    print()