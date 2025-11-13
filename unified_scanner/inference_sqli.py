"""
SQL Injection Detection Inference Module
"""

import pickle
import logging
import numpy as np
from typing import Dict, Any
import os
import sys

# Add current directory to path for local imports
current_dir = os.path.dirname(os.path.abspath(__file__))
if current_dir not in sys.path:
    sys.path.insert(0, current_dir)

from config import MODEL_PATHS, THRESHOLDS

logger = logging.getLogger("inference.sqli")

class SQLiInference:
    def __init__(self):
        self.model = None
        self.vectorizer = None
        self.threshold = THRESHOLDS["sqli"]
        self.is_mock = False
        self.load_model()
    
    def load_model(self):
        """Load the trained SQLi model and vectorizer"""
        try:
            model_path = MODEL_PATHS["sqli"]["model"]
            vectorizer_path = MODEL_PATHS["sqli"]["vectorizer"]
            
            # Check if model files exist
            if not os.path.exists(model_path) or not os.path.exists(vectorizer_path):
                logger.warning(f"SQLi model files not found at {model_path}")
                logger.info("Using rule-based SQLi detection as fallback")
                self.is_mock = True
                return
            
            # Load model
            with open(model_path, 'rb') as f:
                self.model = pickle.load(f)
            
            # Load vectorizer
            with open(vectorizer_path, 'rb') as f:
                self.vectorizer = pickle.load(f)
            
            logger.info("SQLi model and vectorizer loaded successfully")
            
        except Exception as e:
            logger.error(f"Error loading SQLi model: {str(e)}")
            logger.info("Using rule-based SQLi detection as fallback")
            self.is_mock = True
    
    def preprocess_text(self, text: str) -> str:
        """Preprocess text for SQLi detection"""
        if not text:
            return ""
        # Basic preprocessing - can be enhanced based on training preprocessing
        return text.lower().strip()
    
    def predict_sqli(self, request_data: str, response_text: str) -> Dict[str, Any]:
        """
        Predict if the request/response contains SQL injection
        
        Args:
            request_data: The request payload or parameters
            response_text: The HTTP response content
            
        Returns:
            Dictionary with prediction results
        """
        try:
            # Use mock detection if model not loaded
            if self.is_mock or self.model is None or self.vectorizer is None:
                return self._mock_sqli_detection(request_data, response_text)
            
            # Combine request and response for analysis
            combined_text = f"{request_data} {response_text}"
            processed_text = self.preprocess_text(combined_text)
            
            if not processed_text:
                return {
                    "prob": 0.0,
                    "label": "benign",
                    "is_malicious": False,
                    "method": "ml",
                    "threshold": self.threshold
                }
            
            # Vectorize the input
            X = self.vectorizer.transform([processed_text])
            
            # Make prediction
            if hasattr(self.model, 'predict_proba'):
                probability = self.model.predict_proba(X)[0][1]  # Probability of class 1 (malicious)
            else:
                prediction = self.model.predict(X)[0]
                probability = float(prediction)
            
            # Determine label based on threshold
            is_malicious = probability >= self.threshold
            label = "malicious" if is_malicious else "benign"
            
            result = {
                "prob": float(probability),
                "label": label,
                "is_malicious": is_malicious,
                "method": "ml",
                "threshold": self.threshold
            }
            
            logger.debug(f"SQLi prediction: {result}")
            return result
            
        except Exception as e:
            logger.error(f"Error in SQLi prediction: {str(e)}")
            # Fallback to mock detection
            return self._mock_sqli_detection(request_data, response_text)
    
    def _mock_sqli_detection(self, request_data: str, response_text: str) -> Dict[str, Any]:
        """Rule-based SQLi detection as fallback"""
        # SQLi patterns in request
        sqli_patterns = [
            "' OR '1'='1", "UNION SELECT", "'; DROP TABLE", 
            "' OR 1=1--", "WAITFOR DELAY", "BENCHMARK", 
            "sleep(", "pg_sleep", "dbms_pipe"
        ]
        
        # Error patterns in response
        error_patterns = [
            "sql syntax", "mysql_fetch", "ora-", "postgresql", 
            "microsoft odbc", "odbc driver", "pdoexception"
        ]
        
        request_score = 0
        response_score = 0
        
        # Check request for SQLi patterns
        request_lower = request_data.lower()
        for pattern in sqli_patterns:
            if pattern.lower() in request_lower:
                request_score += 0.3
        
        # Check response for SQL errors
        response_lower = response_text.lower()
        for pattern in error_patterns:
            if pattern in response_lower:
                response_score += 0.4
        
        # Calculate combined probability
        probability = min(0.95, request_score + response_score)
        is_malicious = probability >= self.threshold
        label = "malicious" if is_malicious else "benign"
        
        return {
            "prob": probability,
            "label": label,
            "is_malicious": is_malicious,
            "method": "rule_based",
            "threshold": self.threshold
        }

# Singleton instance
_sqli_detector = None

def get_sqli_detector():
    """Get SQLi detector instance"""
    global _sqli_detector
    if _sqli_detector is None:
        _sqli_detector = SQLiInference()
    return _sqli_detector

def predict_sqli(request_data: str, response_text: str) -> Dict[str, Any]:
    """Convenience function for SQLi prediction"""
    detector = get_sqli_detector()
    return detector.predict_sqli(request_data, response_text)