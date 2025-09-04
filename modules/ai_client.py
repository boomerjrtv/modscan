#!/usr/bin/env python3
"""
Pure Gemini AI Client - No Vertex AI
Uses Google's Generative Language API with API key authentication
"""

import json
import os
from typing import Optional, Dict, Any

import aiohttp


class AIClient:
    def __init__(self, config: Dict[str, Any]):
        self.config = config or {}
        self.model = (self.config.get('ai_model') or 'gemini-2.0-flash-exp')
        # Get Gemini API key from config or environment
        self.api_key = (self.config.get('gemini_api_key') or os.environ.get('GEMINI_API_KEY') or '').strip()
        
        if not self.api_key:
            raise RuntimeError("Gemini API key required - set gemini_api_key in config.json or GEMINI_API_KEY env var")

    async def generate_text(self, prompt: str, temperature: float = 0.2, max_tokens: int = 1024) -> str:
        """Generate text using Gemini API"""
        url = f"https://generativelanguage.googleapis.com/v1beta/models/{self.model}:generateContent"
        headers = {
            'Content-Type': 'application/json',
            'X-goog-api-key': self.api_key,
        }
        payload = {
            'contents': [{
                'parts': [{'text': prompt}]
            }],
            'generationConfig': {
                'temperature': temperature,
                'maxOutputTokens': max_tokens
            }
        }
        
        async with aiohttp.ClientSession() as session:
            async with session.post(url, headers=headers, json=payload, 
                                  timeout=aiohttp.ClientTimeout(total=20)) as resp:
                data = await resp.json(content_type=None)
                if resp.status != 200:
                    raise RuntimeError(f"Gemini API error {resp.status}: {json.dumps(data)[:300]}")
                return self._extract_text(data)

    def _extract_text(self, data: Dict[str, Any]) -> str:
        """Extract text from Gemini API response"""
        try:
            candidates = data.get('candidates', [])
            if candidates:
                content = candidates[0].get('content', {})
                parts = content.get('parts', [])
                if parts and isinstance(parts[0], dict):
                    text = parts[0].get('text')
                    if isinstance(text, str):
                        return text.strip()
        except Exception:
            pass
        
        # Fallback for debugging
        return json.dumps(data)[:500]