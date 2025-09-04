#!/usr/bin/env python3
"""Test AI client functionality"""

import asyncio
import sys
import json

sys.path.append('.')
from modules.ai_client import AIClient

async def test_ai():
    """Test AI client with simple prompt"""
    
    # Load config
    with open('config.json', 'r') as f:
        config = json.load(f)
    
    print(f"Gemini API key present: {'Yes' if config.get('gemini_api_key') else 'No'}")
    
    # Create AI client
    ai_client = AIClient(config)
    print(f"AI Client initialized: model={ai_client.model}, api_key={'***' if ai_client.api_key else 'MISSING'}")
    
    # Test simple prompt
    try:
        print("Testing AI with simple prompt...")
        result = await ai_client.generate_text("What is 2+2? Answer with just the number.", temperature=0.1, max_tokens=10)
        print(f"✅ AI Response: {result}")
    except Exception as e:
        print(f"❌ AI Error: {e}")

if __name__ == "__main__":
    asyncio.run(test_ai())