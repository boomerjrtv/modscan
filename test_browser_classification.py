#!/usr/bin/env python3
"""
Test script for browser-based endpoint classification
"""
import asyncio
import sys
import os

# Add the current directory to Python path
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

from modules.vulnerability_scanner import EndpointClassifier

async def test_browser_classification():
    """Test the enhanced browser-based classification"""

    test_urls = [
        "http://testphp.vulnweb.com/userinfo.php",
        "http://testphp.vulnweb.com/secured/newuser.php",
        "http://testphp.vulnweb.com/login.php",
        "http://testhtml5.vulnweb.com/",
        "http://testaspnet.vulnweb.com/"
    ]

    print("🧠 Testing Enhanced Browser-Based Endpoint Classification")
    print("=" * 60)

    for url in test_urls:
        print(f"\n🔍 Testing: {url}")

        # Test static classification
        print("📄 Static classification:")
        static_types = EndpointClassifier.classify_endpoint(url)
        print(f"   Types: {static_types}")

        # Test browser-based classification
        print("🌐 Browser-based classification:")
        try:
            browser_types = await EndpointClassifier.classify_endpoint_with_browser(url)
            print(f"   Types: {browser_types}")

            # Compare results
            if set(browser_types) != set(static_types):
                print(f"✨ Enhanced detection found: {set(browser_types) - set(static_types)}")
            else:
                print("📋 Same as static classification")

        except Exception as e:
            print(f"❌ Browser classification failed: {e}")

if __name__ == "__main__":
    asyncio.run(test_browser_classification())