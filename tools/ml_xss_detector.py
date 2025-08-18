#!/usr/bin/env python3
"""
ML-Based XSS Detection Engine
Learns from Google XSS Game walkthrough patterns to detect XSS vulnerabilities
"""
import asyncio
import aiohttp
import json
import re
import hashlib
import time
import urllib.parse
from pathlib import Path
from dataclasses import dataclass
from typing import List, Dict, Optional, Tuple
import numpy as np
from sklearn.ensemble import RandomForestClassifier
from sklearn.feature_extraction.text import TfidfVectorizer
from sklearn.model_selection import train_test_split

@dataclass
class XSSPattern:
    """Represents a learned XSS attack pattern"""
    attack_type: str
    context: str
    payload_template: str
    indicators: List[str]
    bypass_techniques: List[str]
    confidence_score: float

class MLXSSDetector:
    """Machine Learning XSS Detection Engine"""
    
    def __init__(self):
        self.patterns = self._initialize_learned_patterns()
        self.vectorizer = TfidfVectorizer(max_features=1000, ngram_range=(1,3))
        self.classifier = RandomForestClassifier(n_estimators=100, random_state=42)
        self.is_trained = False
        self._train_model()
    
    def _initialize_learned_patterns(self) -> List[XSSPattern]:
        """Initialize patterns learned from XSS Game walkthrough"""
        return [
            # Level 1: Basic Reflected XSS
            XSSPattern(
                attack_type="reflected",
                context="search_query", 
                payload_template="<script>alert('XSS')</script>",
                indicators=["Sorry, no results", "Try again", "search"],
                bypass_techniques=["basic_injection"],
                confidence_score=0.95
            ),
            
            # Level 2: Stored XSS with Filter Bypass
            XSSPattern(
                attack_type="stored",
                context="chat_message",
                payload_template="<img src/onerror=alert(1)>",
                indicators=["post", "chat", "message", "persistence"],
                bypass_techniques=["tag_filter_bypass", "event_handler"],
                confidence_score=0.90
            ),
            
            # Level 3: DOM-based XSS via Fragment
            XSSPattern(
                attack_type="dom", 
                context="url_fragment",
                payload_template="1' onerror='alert(1)';//",
                indicators=["chooseTab", "location.hash", "parseInt"],
                bypass_techniques=["attribute_breaking", "comment_injection"],
                confidence_score=0.85
            ),
            
            # Level 4: JavaScript Context Injection
            XSSPattern(
                attack_type="js_context",
                context="timer_function",
                payload_template="3'*alert(1);//",
                indicators=["startTimer", "setTimeout", "onload"],
                bypass_techniques=["expression_injection", "operator_abuse"],
                confidence_score=0.88
            ),
            
            # Level 5: JavaScript Protocol Injection
            XSSPattern(
                attack_type="protocol_injection",
                context="url_redirect",
                payload_template="javascript:alert('XSS')",
                indicators=["next", "signup", "redirect", "protocol"],
                bypass_techniques=["case_bypass", "protocol_switching"],
                confidence_score=0.92
            ),
            
            # Level 6: External Script Gadget
            XSSPattern(
                attack_type="gadget",
                context="script_loading",
                payload_template="data:text/javascript,alert(1)",
                indicators=["includeGadget", "external", "//", "case sensitive"],
                bypass_techniques=["case_bypass", "protocol_substitution"],
                confidence_score=0.87
            )
        ]
    
    def _train_model(self):
        """Train ML model on XSS patterns and common web responses"""
        # Generate training data from patterns
        training_data = []
        labels = []
        
        # Positive samples (XSS vulnerable)
        for pattern in self.patterns:
            for indicator in pattern.indicators:
                for bypass in pattern.bypass_techniques:
                    sample = f"{indicator} {bypass} {pattern.context} {pattern.payload_template}"
                    training_data.append(sample)
                    labels.append(1)  # Vulnerable
        
        # Negative samples (Not vulnerable)
        safe_responses = [
            "404 not found error page",
            "403 forbidden access denied", 
            "input validation failed",
            "csrf token mismatch",
            "rate limit exceeded",
            "maintenance mode active",
            "user authentication required",
            "sanitized output clean"
        ]
        
        for response in safe_responses:
            for _ in range(10):  # Balance dataset
                training_data.append(f"{response} normal behavior")
                labels.append(0)  # Not vulnerable
        
        # Train the model
        if len(training_data) > 0:
            X = self.vectorizer.fit_transform(training_data)
            self.classifier.fit(X, labels)
            self.is_trained = True
    
    def analyze_response(self, url: str, payload: str, response_text: str, 
                        response_headers: Dict[str, str]) -> Dict:
        """Analyze response for XSS vulnerability using ML"""
        
        # Extract features for ML analysis
        features = self._extract_features(url, payload, response_text, response_headers)
        
        # Get ML prediction
        ml_prediction = self._get_ml_prediction(response_text, payload)
        
        # Pattern-based analysis
        pattern_matches = self._match_patterns(url, payload, response_text)
        
        # Context analysis
        context = self._analyze_context(url, response_text)
        
        # Combine results
        vulnerability_score = self._calculate_confidence(
            ml_prediction, pattern_matches, features, context
        )
        
        return {
            "is_vulnerable": vulnerability_score > 0.7,
            "vulnerability_score": vulnerability_score,
            "attack_type": self._classify_attack_type(pattern_matches, context),
            "ml_prediction": ml_prediction,
            "pattern_matches": pattern_matches,
            "context": context,
            "features": features,
            "confidence": "high" if vulnerability_score > 0.8 else "medium" if vulnerability_score > 0.6 else "low"
        }
    
    def _extract_features(self, url: str, payload: str, response_text: str, 
                         headers: Dict[str, str]) -> Dict:
        """Extract features for ML analysis"""
        return {
            "payload_reflected": payload in response_text,
            "html_tags_present": bool(re.search(r'<[^>]+>', response_text)),
            "script_tags": len(re.findall(r'<script[^>]*>', response_text, re.I)),
            "error_indicators": any(error in response_text.lower() for error in [
                "error", "exception", "failed", "invalid", "forbidden"
            ]),
            "interactive_elements": len(re.findall(r'<(input|form|button)', response_text, re.I)),
            "javascript_present": 'javascript:' in response_text.lower(),
            "payload_in_js_context": self._payload_in_js_context(payload, response_text),
            "payload_in_attribute": self._payload_in_attribute(payload, response_text),
            "url_has_params": '?' in url,
            "response_size": len(response_text),
            "content_type_html": headers.get('content-type', '').startswith('text/html')
        }
    
    def _payload_in_js_context(self, payload: str, text: str) -> bool:
        """Check if payload appears in JavaScript context"""
        js_patterns = [
            r'<script[^>]*>.*?' + re.escape(payload) + r'.*?</script>',
            r'javascript:.*?' + re.escape(payload),
            r'on\w+\s*=\s*[\'"].*?' + re.escape(payload)
        ]
        return any(re.search(pattern, text, re.DOTALL | re.I) for pattern in js_patterns)
    
    def _payload_in_attribute(self, payload: str, text: str) -> bool:
        """Check if payload appears in HTML attribute"""
        attr_pattern = r'<[^>]*\s+[^=]*=[\'"]*[^\'">]*' + re.escape(payload)
        return bool(re.search(attr_pattern, text, re.I))
    
    def _get_ml_prediction(self, response_text: str, payload: str) -> float:
        """Get ML model prediction"""
        if not self.is_trained:
            return 0.5
        
        sample = f"{response_text} {payload}"
        X = self.vectorizer.transform([sample])
        prediction_proba = self.classifier.predict_proba(X)
        return prediction_proba[0][1] if len(prediction_proba[0]) > 1 else 0.5
    
    def _match_patterns(self, url: str, payload: str, response_text: str) -> List[XSSPattern]:
        """Find matching XSS patterns"""
        matches = []
        text_lower = response_text.lower()
        url_lower = url.lower()
        
        for pattern in self.patterns:
            match_score = 0
            
            # Check URL context
            if any(indicator in url_lower for indicator in pattern.indicators):
                match_score += 0.3
            
            # Check response content  
            if any(indicator in text_lower for indicator in pattern.indicators):
                match_score += 0.4
            
            # Check payload compatibility
            if pattern.attack_type in ["reflected", "stored"] and payload in response_text:
                match_score += 0.5
            elif pattern.attack_type == "dom" and '#' in url:
                match_score += 0.4
            elif pattern.attack_type == "protocol_injection" and 'javascript:' in payload.lower():
                match_score += 0.5
            
            if match_score > 0.4:
                matches.append(pattern)
        
        return matches
    
    def _analyze_context(self, url: str, response_text: str) -> Dict:
        """Analyze the context of the potential vulnerability"""
        context = {
            "page_type": "unknown",
            "input_methods": [],
            "js_functions": [],
            "risk_factors": []
        }
        
        # Determine page type
        if any(keyword in response_text.lower() for keyword in ["search", "query"]):
            context["page_type"] = "search"
        elif any(keyword in response_text.lower() for keyword in ["chat", "message", "post"]):
            context["page_type"] = "social"
        elif any(keyword in response_text.lower() for keyword in ["signup", "register", "login"]):
            context["page_type"] = "authentication"
        elif "#" in url:
            context["page_type"] = "spa_fragment"
        
        # Find input methods
        if re.search(r'<form[^>]*>', response_text, re.I):
            context["input_methods"].append("form")
        if '?' in url:
            context["input_methods"].append("url_params")
        if '#' in url:
            context["input_methods"].append("fragment")
        
        # Find JavaScript functions
        js_functions = re.findall(r'function\s+(\w+)', response_text, re.I)
        context["js_functions"] = js_functions[:5]  # Limit to first 5
        
        # Risk factors
        if "eval(" in response_text:
            context["risk_factors"].append("eval_usage")
        if "innerHTML" in response_text:
            context["risk_factors"].append("innerHTML_usage")
        if "document.write" in response_text:
            context["risk_factors"].append("document_write_usage")
        
        return context
    
    def _calculate_confidence(self, ml_prediction: float, pattern_matches: List[XSSPattern],
                            features: Dict, context: Dict) -> float:
        """Calculate overall confidence score"""
        confidence = 0.0
        
        # ML prediction weight
        confidence += ml_prediction * 0.4
        
        # Pattern matching weight
        if pattern_matches:
            pattern_confidence = max(p.confidence_score for p in pattern_matches)
            confidence += pattern_confidence * 0.3
        
        # Feature-based confidence
        if features["payload_reflected"]:
            confidence += 0.2
        if features["payload_in_js_context"]:
            confidence += 0.15
        if features["javascript_present"]:
            confidence += 0.1
        
        # Context-based confidence
        if context["page_type"] != "unknown":
            confidence += 0.1
        if context["risk_factors"]:
            confidence += len(context["risk_factors"]) * 0.05
        
        return min(confidence, 1.0)
    
    def _classify_attack_type(self, pattern_matches: List[XSSPattern], context: Dict) -> str:
        """Classify the type of XSS attack"""
        if pattern_matches:
            # Return the highest confidence pattern type
            best_pattern = max(pattern_matches, key=lambda p: p.confidence_score)
            return best_pattern.attack_type
        
        # Fallback classification based on context
        if context["page_type"] == "spa_fragment":
            return "dom"
        elif context["page_type"] == "social":
            return "stored"
        else:
            return "reflected"

async def test_ml_xss_detector():
    """Test the ML XSS detector"""
    detector = MLXSSDetector()
    
    # Test cases from XSS Game walkthrough
    test_cases = [
        {
            "url": "https://xss-game.appspot.com/level1/frame?query=<script>alert('XSS')</script>",
            "payload": "<script>alert('XSS')</script>",
            "response": "Sorry, no results were found for <b><script>alert('XSS')</script></b>. <a href='?'>Try again</a>.",
            "expected": "reflected"
        },
        {
            "url": "https://xss-game.appspot.com/level2/frame",
            "payload": "<img src/onerror=alert(1)>",
            "response": "Posted message: <img src/onerror=alert(1)>",
            "expected": "stored"
        },
        {
            "url": "https://xss-game.appspot.com/level3/frame#1' onerror='alert(1)';//",
            "payload": "1' onerror='alert(1)';//",
            "response": "function chooseTab(num) { var html = 'Image ' + parseInt(num) + '<br>'; }",
            "expected": "dom"
        },
        {
            "url": "https://xss-game.appspot.com/level5/frame/signup?next=javascript:alert('XSS')",
            "payload": "javascript:alert('XSS')",
            "response": "Sign up for beta program. <a href='javascript:alert('XSS')'>Next >></a>",
            "expected": "protocol_injection"
        }
    ]
    
    print("🧠 Testing ML XSS Detector")
    print("=" * 50)
    
    for i, test in enumerate(test_cases, 1):
        result = detector.analyze_response(
            url=test["url"],
            payload=test["payload"], 
            response_text=test["response"],
            response_headers={"content-type": "text/html"}
        )
        
        print(f"\n📍 Test {i}: {test['expected'].upper()}")
        print(f"  Vulnerable: {result['is_vulnerable']}")
        print(f"  Score: {result['vulnerability_score']:.3f}")
        print(f"  Type: {result['attack_type']}")
        print(f"  Confidence: {result['confidence']}")
        print(f"  ML Prediction: {result['ml_prediction']:.3f}")
        print(f"  Patterns: {len(result['pattern_matches'])} matched")
        
        # Verify classification
        if result['attack_type'] == test['expected']:
            print(f"  ✅ Classification correct")
        else:
            print(f"  ❌ Expected {test['expected']}, got {result['attack_type']}")

if __name__ == "__main__":
    asyncio.run(test_ml_xss_detector())