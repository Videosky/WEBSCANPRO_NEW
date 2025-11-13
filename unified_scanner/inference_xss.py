"""
XSS Detection Inference Module
"""

import logging
from typing import Dict, Any
import os
import sys

# Add current directory to path for local imports
current_dir = os.path.dirname(os.path.abspath(__file__))
if current_dir not in sys.path:
    sys.path.insert(0, current_dir)

from config import MODEL_PATHS, THRESHOLDS

logger = logging.getLogger("inference.xss")

class XSSInference:
    def __init__(self):
        self.model = None
        self.tokenizer = None
        self.threshold = THRESHOLDS["xss"]
        self.is_mock = False
        self.load_model()
    
    def load_model(self):
        """Load the trained XSS model and tokenizer"""
        try:
            model_path = MODEL_PATHS["xss"]["model"]
            tokenizer_path = MODEL_PATHS["xss"]["tokenizer"]
            
            # Check if model files exist
            if not os.path.exists(model_path) or not os.path.exists(tokenizer_path):
                logger.warning(f"XSS model files not found at {model_path}")
                logger.info("Using rule-based XSS detection as fallback")
                self.is_mock = True
                return
            
            # Try to load PyTorch model
            try:
                import torch
                from transformers import AutoTokenizer
                
                model_data = torch.load(model_path, map_location='cpu')
                self.model = model_data
                self.tokenizer = AutoTokenizer.from_pretrained(tokenizer_path)
                logger.info("XSS model and tokenizer loaded successfully")
                
            except ImportError:
                logger.warning("PyTorch not available, using rule-based detection")
                self.is_mock = True
                
        except Exception as e:
            logger.error(f"Error loading XSS model: {str(e)}")
            logger.info("Using rule-based XSS detection as fallback")
            self.is_mock = True
    
    def predict_xss(self, response_text: str) -> Dict[str, Any]:
        """
        Predict if the response contains XSS payload
        
        Args:
            response_text: The HTTP response content
            
        Returns:
            Dictionary with prediction results
        """
        try:
            # Use mock detection if model not loaded
            if self.is_mock or self.model is None or self.tokenizer is None:
                return self._mock_xss_detection(response_text)
            
            # ML-based detection would go here
            # This is a placeholder for actual model inference
            probability = self._ml_xss_detection(response_text)
            
            is_malicious = probability >= self.threshold
            label = "malicious" if is_malicious else "benign"
            
            result = {
                "prob": probability,
                "label": label,
                "is_malicious": is_malicious,
                "method": "ml",
                "threshold": self.threshold
            }
            
            logger.debug(f"XSS prediction: {result}")
            return result
            
        except Exception as e:
            logger.error(f"Error in XSS prediction: {str(e)}")
            # Fallback to mock detection
            return self._mock_xss_detection(response_text)
    
    def _ml_xss_detection(self, response_text: str) -> float:
        """Placeholder for ML-based XSS detection"""
        # In a real implementation, this would use the loaded model
        # For now, we'll use rule-based as fallback within ML method
        return self._mock_xss_detection(response_text)["prob"]
    
    def _mock_xss_detection(self, response_text: str) -> Dict[str, Any]:
        """Rule-based XSS detection as fallback"""
        xss_patterns = [
            "<script", "javascript:", "onerror=", "onload=", "onclick=",
            "alert(", "prompt(", "confirm(", "eval(", "setTimeout(",
            "<iframe", "<embed", "<object", "<applet", "<svg onload",
            "vbscript:", "mocha:", "livescript:", "base64,"
        ]
        
        score = 0
        response_lower = response_text.lower()
        
        # Check for XSS patterns
        for pattern in xss_patterns:
            if pattern in response_lower:
                score += 0.2
        
        # Additional scoring for suspicious contexts
        if "document.cookie" in response_lower:
            score += 0.3
        if "window.location" in response_lower:
            score += 0.2
        if "innerhtml" in response_lower:
            score += 0.1
        
        probability = min(0.95, score)
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
_xss_detector = None

def get_xss_detector():
    """Get XSS detector instance"""
    global _xss_detector
    if _xss_detector is None:
        _xss_detector = XSSInference()
    return _xss_detector

def predict_xss(response_text: str) -> Dict[str, Any]:
    """Convenience function for XSS prediction"""
    detector = get_xss_detector()
    return detector.predict_xss(response_text)