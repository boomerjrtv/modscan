#!/usr/bin/env python3

"""
ML Engine Module - Machine Learning vulnerability prediction with AssetManager
"""

import logging
import numpy as np
from typing import Dict, List, Optional
from sklearn.ensemble import RandomForestClassifier, IsolationForest
from sklearn.feature_extraction.text import TfidfVectorizer
import joblib
from pathlib import Path

logger = logging.getLogger("MLEngine")

class MLEngine:
    """Advanced machine learning engine using AssetManager field mappings"""
    
    def __init__(self, asset_manager, config: Dict):
        self.asset_manager = asset_manager  # Use YOUR AssetManager
        self.config = config
        
        # ML models
        self.xss_model = None
        self.sqli_model = None
        self.vulnerability_classifier = None
        self.anomaly_detector = None
        self.vulnerability_vectorizer = TfidfVectorizer(max_features=1000)
        
        # Model paths
        self.model_dir = Path(__file__).parent.parent / "models"
        self.model_dir.mkdir(exist_ok=True)
        
        # Statistics
        self.ml_stats = {
            "predictions_made": 0,
            "accuracy": 0.0,
            "models_trained": 0
        }
        
        logger.info("🤖 MLEngine initialized with AssetManager integration")
    
    async def initialize(self):
        """Initialize ML engine with model training"""
        try:
            # Try to load existing models
            await self._load_trained_models()
            
            # If no models exist, train new ones
            if not self._models_exist():
                await self._train_initial_models()
            
            # Log initialization using AssetManager
            self.asset_manager.log_activity(
                'ML_ENGINE_INIT',
                f'MLEngine initialized - {self.ml_stats["models_trained"]} models loaded/trained'
            )
            
            logger.info("✅ MLEngine initialization complete")
            
        except Exception as e:
            logger.error(f"MLEngine initialization failed: {e}")
    
    def _models_exist(self) -> bool:
        """Check if trained models exist"""
        model_files = [
            self.model_dir / "xss_model.joblib",
            self.model_dir / "vulnerability_classifier.joblib"
        ]
        return all(model_file.exists() for model_file in model_files)
    
    async def _load_trained_models(self):
        """Load previously trained models"""
        try:
            xss_model_path = self.model_dir / "xss_model.joblib"
            vuln_model_path = self.model_dir / "vulnerability_classifier.joblib"
            vectorizer_path = self.model_dir / "vectorizer.joblib"
            
            if xss_model_path.exists():
                self.xss_model = joblib.load(xss_model_path)
                self.ml_stats["models_trained"] += 1
                logger.info("📚 Loaded XSS prediction model")
            
            if vuln_model_path.exists():
                self.vulnerability_classifier = joblib.load(vuln_model_path)
                self.ml_stats["models_trained"] += 1
                logger.info("📚 Loaded vulnerability classification model")
            
            if vectorizer_path.exists():
                self.vulnerability_vectorizer = joblib.load(vectorizer_path)
                logger.info("📚 Loaded text vectorizer")
                
        except Exception as e:
            logger.warning(f"Failed to load existing models: {e}")
    
    async def _train_initial_models(self):
        """Train initial ML models using existing data"""
        try:
            # Get training data from AssetManager
            training_data = await self._collect_training_data()
            
            if len(training_data) < 10:
                # Create synthetic training data for initial model
                training_data = self._create_synthetic_training_data()
            
            # Train XSS detection model
            await self._train_xss_model(training_data)
            
            # Train vulnerability classification model
            await self._train_vulnerability_classifier(training_data)
            
            # Save trained models
            await self._save_models()
            
            logger.info("🎓 Initial ML models training complete")
            
        except Exception as e:
            logger.error(f"Initial model training failed: {e}")
    
    async def _collect_training_data(self) -> List[Dict]:
        """Collect training data from AssetManager database"""
        training_data = []
        
        try:
            import sqlite3
            db_path = self.config.get('database_path', 'lean_recon.db')
            
            with sqlite3.connect(db_path) as db:
                # Get assets with vulnerability information
                cursor = db.execute('''
                    SELECT a.*, v.type, v.severity, v.payload, v.evidence
                    FROM assets a
                    LEFT JOIN vulnerabilities v ON a.id = v.asset_id
                    WHERE a.basic_scan_complete = 1
                    LIMIT 1000
                ''')
                
                rows = cursor.fetchall()
                
                for row in rows:
                    training_data.append({
                        'url': row[1] if len(row) > 1 else '',
                        'status_code': row[3] if len(row) > 3 else 200,
                        'title': row[4] if len(row) > 4 else '',
                        'content_length': row[6] if len(row) > 6 else 0,
                        'technologies': row[17] if len(row) > 17 else '',
                        'vuln_type': row[-4] if len(row) > 20 and row[-4] else None,
                        'severity': row[-3] if len(row) > 20 and row[-3] else None,
                        'payload': row[-2] if len(row) > 20 and row[-2] else '',
                        'evidence': row[-1] if len(row) > 20 and row[-1] else ''
                    })
                
        except Exception as e:
            logger.debug(f"Training data collection failed: {e}")
        
        return training_data
    
    def _create_synthetic_training_data(self) -> List[Dict]:
        """Create synthetic training data for initial model training"""
        synthetic_data = []
        
        # XSS patterns
        xss_patterns = [
            ("<script>alert('XSS')</script>", "xss", "HIGH"),
            ("<img src=x onerror=alert(1)>", "xss", "HIGH"),
            ("javascript:alert(1)", "xss", "MEDIUM"),
            ("'><script>alert(1)</script>", "xss", "HIGH"),
        ]
        
        # SQLi patterns
        sqli_patterns = [
            ("' OR '1'='1", "sqli", "CRITICAL"),
            ("' UNION SELECT NULL--", "sqli", "CRITICAL"),
            ("'; DROP TABLE users--", "sqli", "CRITICAL"),
            ("' AND 1=1--", "sqli", "HIGH"),
        ]
        
        # Benign patterns
        benign_patterns = [
            ("normal search query", None, None),
            ("user@example.com", None, None),
            ("12345", None, None),
            ("test", None, None),
        ]
        
        # Combine all patterns
        all_patterns = xss_patterns + sqli_patterns + benign_patterns
        
        for i, (payload, vuln_type, severity) in enumerate(all_patterns):
            synthetic_data.append({
                'url': f'https://example{i}.com/test',
                'status_code': 200,
                'title': f'Test Page {i}',
                'content_length': len(payload) * 100,
                'technologies': 'PHP' if vuln_type else 'Static',
                'vuln_type': vuln_type,
                'severity': severity,
                'payload': payload,
                'evidence': f'Response contains: {payload}' if vuln_type else 'Normal response'
            })
        
        return synthetic_data * 5  # Replicate for more training samples
    
    async def _train_xss_model(self, training_data: List[Dict]):
        """Train XSS detection model"""
        try:
            # Prepare training data
            X_features = []
            y_labels = []
            
            for data in training_data:
                # Create feature vector
                features = [
                    len(data.get('payload', '')),
                    1 if '<script' in data.get('payload', '').lower() else 0,
                    1 if 'alert' in data.get('payload', '').lower() else 0,
                    1 if 'onerror' in data.get('payload', '').lower() else 0,
                    1 if 'javascript:' in data.get('payload', '').lower() else 0,
                    len(data.get('url', '')),
                    data.get('status_code', 200),
                    len(data.get('title', '')),
                ]
                
                X_features.append(features)
                y_labels.append(1 if data.get('vuln_type') == 'xss' else 0)
            
            # Train model
            if len(X_features) >= 5:
                self.xss_model = RandomForestClassifier(n_estimators=50, random_state=42)
                self.xss_model.fit(X_features, y_labels)
                self.ml_stats["models_trained"] += 1
                logger.info("🎯 XSS detection model trained")
            
        except Exception as e:
            logger.error(f"XSS model training failed: {e}")
    
    async def _train_vulnerability_classifier(self, training_data: List[Dict]) -> None:
        """Train general vulnerability classification model"""
        try:
            # Extract text features for vectorization
            text_features = []
            labels = []
            
            for data in training_data:
                # Combine relevant text features
                combined_text = f"{data.get('payload', '')} {data.get('evidence', '')} {data.get('technologies', '')}"
                text_features.append(combined_text)
                
                # Multi-class labels
                vuln_type = data.get('vuln_type')
                if vuln_type == 'xss':
                    labels.append(1)
                elif vuln_type == 'sqli':
                    labels.append(2)
                else:
                    labels.append(0)  # No vulnerability
            
            # Vectorize text features
            if text_features:
                X_vectorized = self.vulnerability_vectorizer.fit_transform(text_features)
                
                # Train classifier
                self.vulnerability_classifier = RandomForestClassifier(n_estimators=50, random_state=42)
                self.vulnerability_classifier.fit(X_vectorized, labels)
                self.ml_stats["models_trained"] += 1
                logger.info("🎯 Vulnerability classifier trained")
            
        except Exception as e:
            logger.error(f"Vulnerability classifier training failed: {e}")
    
    async def _save_models(self):
        """Save trained models to disk"""
        try:
            if self.xss_model:
                joblib.dump(self.xss_model, self.model_dir / "xss_model.joblib")
            
            if self.vulnerability_classifier:
                joblib.dump(self.vulnerability_classifier, self.model_dir / "vulnerability_classifier.joblib")
            
            if self.vulnerability_vectorizer:
                joblib.dump(self.vulnerability_vectorizer, self.model_dir / "vectorizer.joblib")
            
            logger.info("💾 ML models saved to disk")
            
        except Exception as e:
            logger.error(f"Model saving failed: {e}")
    
    async def predict_xss_vulnerability(self, response_content: str, payload: str) -> float:
        """Predict XSS vulnerability likelihood using ML"""
        try:
            if not self.xss_model:
                return self._heuristic_xss_detection(response_content, payload)
            
            # Create feature vector
            features = [
                len(payload),
                1 if '<script' in payload.lower() else 0,
                1 if 'alert' in payload.lower() else 0,
                1 if 'onerror' in payload.lower() else 0,
                1 if 'javascript:' in payload.lower() else 0,
                len(response_content),
                1 if payload in response_content else 0,
                len(response_content.split())
            ]
            
            # Get prediction probability
            probability = self.xss_model.predict_proba([features])[0][1]
            
            self.ml_stats["predictions_made"] += 1
            return probability
            
        except Exception as e:
            logger.debug(f"XSS ML prediction failed: {e}")
            return self._heuristic_xss_detection(response_content, payload)
    
    def _heuristic_xss_detection(self, response_content: str, payload: str) -> float:
        """Fallback heuristic XSS detection"""
        score = 0.0
        
        if payload in response_content:
            score += 0.4
        
        if any(pattern in response_content.lower() for pattern in ['<script', 'javascript:', 'onerror=', 'onclick=']):
            score += 0.3
        
        if any(context in response_content.lower() for context in ['value="', "value='", '<input', '<textarea']):
            score += 0.2
        
        if '>' in response_content or '<' in response_content:
            score += 0.1
        
        return min(score, 1.0)
    
    async def predict_vulnerability_type(self, payload: str, response_content: str, evidence: str) -> Dict:
        """Predict vulnerability type and confidence"""
        try:
            if not self.vulnerability_classifier:
                return {"type": "unknown", "confidence": 0.5}
            
            # Combine text features
            combined_text = f"{payload} {evidence} {response_content[:500]}"
            
            # Vectorize
            X_vectorized = self.vulnerability_vectorizer.transform([combined_text])
            
            # Get prediction and probability
            prediction = self.vulnerability_classifier.predict(X_vectorized)[0]
            probabilities = self.vulnerability_classifier.predict_proba(X_vectorized)[0]
            
            # Map prediction to vulnerability type
            type_mapping = {0: "none", 1: "xss", 2: "sqli"}
            predicted_type = type_mapping.get(prediction, "unknown")
            confidence = max(probabilities)
            
            self.ml_stats["predictions_made"] += 1
            
            return {
                "type": predicted_type,
                "confidence": confidence,
                "all_probabilities": {
                    "none": probabilities[0],
                    "xss": probabilities[1] if len(probabilities) > 1 else 0,
                    "sqli": probabilities[2] if len(probabilities) > 2 else 0
                }
            }
            
        except Exception as e:
            logger.debug(f"Vulnerability type prediction failed: {e}")
            return {"type": "unknown", "confidence": 0.5}
    
    def get_ml_statistics(self) -> Dict:
        """Get ML engine statistics"""
        return {
            "predictions_made": self.ml_stats["predictions_made"],
            "accuracy": self.ml_stats["accuracy"],
            "models_loaded": self.ml_stats["models_trained"],
            "models_available": {
                "xss_model": self.xss_model is not None,
                "vulnerability_classifier": self.vulnerability_classifier is not None,
                "anomaly_detector": self.anomaly_detector is not None
            }
        }
    
    async def retrain_models_with_new_data(self):
        """Retrain models with latest vulnerability data"""
        try:
            logger.info("🔄 Retraining ML models with latest data...")
            
            # Collect latest training data
            latest_data = await self._collect_training_data()
            
            if len(latest_data) >= 20:  # Need sufficient data for retraining
                await self._train_xss_model(latest_data)
                await self._train_vulnerability_classifier(latest_data)
                await self._save_models()
                
                logger.info("🎓 Model retraining complete")
                
                # Log retraining using AssetManager
                self.asset_manager.log_activity(
                    'ML_RETRAIN',
                    f'ML models retrained with {len(latest_data)} data points'
                )
            else:
                logger.info("📊 Insufficient data for model retraining")
                
        except Exception as e:
            logger.error(f"Model retraining failed: {e}")
