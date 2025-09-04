#!/usr/bin/env python3
"""Test the old Google AI SDK that MLVulnerabilityEngine uses"""

import json
import google.generativeai as genai

# Load config
with open('config.json', 'r') as f:
    config = json.load(f)

api_key = config.get('gemini_api_key')
print(f"Testing old SDK with API key: {'***' if api_key else 'MISSING'}")

try:
    # Configure the old SDK
    genai.configure(api_key=api_key)
    
    # Create model like MLVulnerabilityEngine does
    model = genai.GenerativeModel('gemini-1.5-flash')
    print("✅ Model created successfully")
    
    # Test generation
    response = model.generate_content("What is 2+2? Just the number.")
    result = getattr(response, 'text', str(response))
    print(f"✅ Old SDK Response: {result}")
    
except Exception as e:
    print(f"❌ Old SDK Error: {e}")