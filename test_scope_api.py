#!/usr/bin/env python3
import requests
import json

# Test the scope API to see what's working
url = "http://127.0.0.1:8000"

# Test GET scope
print("=== Testing GET /api/scope ===")
try:
    r = requests.get(f"{url}/api/scope")
    print(f"Status: {r.status_code}")
    print(f"Response: {r.json()}")
except Exception as e:
    print(f"Error: {e}")

# Test POST scope with target field
print("\n=== Testing POST /api/scope with target ===")
try:
    data = {"target": "192.168.1.42"}
    r = requests.post(f"{url}/api/scope", json=data)
    print(f"Status: {r.status_code}")
    print(f"Response: {r.json()}")
except Exception as e:
    print(f"Error: {e}")

# Test GET scope again
print("\n=== Testing GET /api/scope again ===")
try:
    r = requests.get(f"{url}/api/scope")
    print(f"Status: {r.status_code}")
    print(f"Response: {r.json()}")
except Exception as e:
    print(f"Error: {e}")