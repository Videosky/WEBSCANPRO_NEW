# projects/auth_session/scanner_ml_integration.py

import pandas as pd
import numpy as np
import joblib
import logging
from datetime import datetime
from pathlib import Path
import time
from typing import Dict, Any, Optional
import json
import sys

# TensorFlow with error handling
try:
    from tensorflow.keras.models import load_model
    from tensorflow.keras.metrics import MeanSquaredError, MeanAbsoluteError
    TENSORFLOW_AVAILABLE = True
except ImportError:
    TENSORFLOW_AVAILABLE = False
    print("Warning: TensorFlow not available. Autoencoder will be disabled.")

class AuthMLIntegration:
    """
    ML Integration for Authentication Scanner
    Loads trained models and provides real-time anomaly detection
    """
    
    def __init__(self, model_dir: str = "projects/auth_session/ml"):
        self.model_dir = Path(model_dir)
        self.models_loaded = False
        self.inference_times = []
        
        # Initialize components
        self.isolation_forest = None
        self.autoencoder = None
        self.preprocessor = None
        self.autoencoder_threshold = None
        
        # Setup logging
        self._setup_logging()
        
        # Load models
        self.load_models()
    
    def _setup_logging(self):
        """Setup inference logging without emojis for Windows compatibility"""
        logs_dir = Path("projects/auth_session/logs")
        logs_dir.mkdir(parents=True, exist_ok=True)
        
        timestamp = datetime.now().strftime("%Y-%m-%d_%H-%M-%S")
        log_file = logs_dir / f"scanner_inference_{timestamp}.log"
        
        logging.basicConfig(
            level=logging.INFO,
            format='%(asctime)s - %(name)s - %(levelname)s - %(message)s',
            handlers=[
                logging.FileHandler(log_file, encoding='utf-8'),
                logging.StreamHandler()
            ]
        )
        self.logger = logging.getLogger('auth_ml_integration')
        self.logger.info(f"ML Integration initialized - Logging to: {log_file}")
    
    def load_models(self):
        """Load trained models and preprocessing artifacts"""
        self.logger.info("Loading ML models...")
        
        try:
            # Load Isolation Forest
            iforest_path = self.model_dir / "isolation_forest_model.pkl"
            if iforest_path.exists():
                self.isolation_forest = joblib.load(iforest_path)
                self.logger.info("[SUCCESS] Isolation Forest loaded successfully")
            else:
                self.logger.error("[ERROR] Isolation Forest model file not found")
                return False
            
            # Load Autoencoder with TensorFlow availability check
            if TENSORFLOW_AVAILABLE:
                autoencoder_path = self.model_dir / "autoencoder_model.h5"
                if autoencoder_path.exists():
                    try:
                        # Use correct metric names for TensorFlow 2.x
                        custom_objects = {
                            'mse': MeanSquaredError(),
                            'mae': MeanAbsoluteError()
                        }
                        self.autoencoder = load_model(autoencoder_path, custom_objects=custom_objects, compile=False)
                        self.logger.info("[SUCCESS] Autoencoder loaded successfully")
                    except Exception as e:
                        self.logger.warning(f"[WARNING] Autoencoder loading failed: {e}. Continuing without Autoencoder.")
                        self.autoencoder = None
                else:
                    self.logger.warning("[WARNING] Autoencoder model file not found. Continuing without Autoencoder.")
            else:
                self.logger.warning("[WARNING] TensorFlow not available. Autoencoder disabled.")
            
            # Load preprocessing artifacts
            artifacts_path = self.model_dir / "preprocessing_artifacts.pkl"
            if artifacts_path.exists():
                artifacts = joblib.load(artifacts_path)
                self.preprocessor = artifacts.get('scaler')
                self.autoencoder_threshold = artifacts.get('autoencoder_threshold', 0.236)
                self.feature_names = artifacts.get('feature_names', [])
                self.logger.info("[SUCCESS] Preprocessing artifacts loaded successfully")
                self.logger.info(f"   Autoencoder threshold: {self.autoencoder_threshold:.6f}")
                self.logger.info(f"   Feature count: {len(self.feature_names)}")
            else:
                self.logger.error("[ERROR] Preprocessing artifacts not found")
                return False
            
            self.models_loaded = True
            self.logger.info("[SUCCESS] All ML models loaded and ready for inference")
            return True
            
        except Exception as e:
            self.logger.error(f"[ERROR] Failed to load models: {e}")
            self.models_loaded = False
            return False
    
    def preprocess_features(self, session_data: Dict[str, Any]) -> Optional[np.ndarray]:
        """Preprocess session features for model inference"""
        try:
            # Define expected features (adjust based on your dataset)
            expected_features = [
                'is_bruteforce_candidate', 'total_attempts', 'success_rate', 
                'failure_rate', 'distinct_ips', 'ip_entropy', 'avg_time_between_attempts',
                'total_attempts_ip', 'distinct_usernames', 'success_rate_ip',
                'attempts_per_minute', 'session_duration', 'ip_changes', 
                'user_agent_changes', 'login_hour', 'weekday', 'is_weekend', 
                'is_night', 'velocity_score', 'suspicious_ip_flag'
            ]
            
            # Extract features in correct order
            features = []
            for feature in expected_features:
                if feature in session_data:
                    features.append(session_data[feature])
                else:
                    # Use default value for missing features
                    if feature in ['success_rate', 'failure_rate', 'ip_entropy']:
                        features.append(0.0)  # Default for rates
                    else:
                        features.append(0)    # Default for counts
            
            # Convert to numpy array and reshape
            feature_array = np.array(features).reshape(1, -1)
            
            # Apply preprocessing
            if self.preprocessor:
                feature_array = self.preprocessor.transform(feature_array)
            
            return feature_array
            
        except Exception as e:
            self.logger.error(f"[ERROR] Feature preprocessing failed: {e}")
            return None
    
    def predict_anomaly(self, session_data: Dict[str, Any]) -> Dict[str, Any]:
        """
        Perform anomaly detection on session data
        Returns comprehensive prediction results
        """
        start_time = time.time()
        
        if not self.models_loaded:
            return {
                "error": "Models not loaded",
                "session_id": session_data.get('session_id', 'unknown'),
                "timestamp": datetime.now().isoformat()
            }
        
        try:
            # Preprocess features
            features = self.preprocess_features(session_data)
            if features is None:
                return {
                    "error": "Feature preprocessing failed",
                    "session_id": session_data.get('session_id', 'unknown'),
                    "timestamp": datetime.now().isoformat()
                }
            
            results = {
                "session_id": session_data.get('session_id', 'unknown'),
                "timestamp": datetime.now().isoformat(),
                "features_used": len(features[0]),
                "model_predictions": {}
            }
            
            # Isolation Forest prediction
            if self.isolation_forest:
                if_scores = self.isolation_forest.decision_function(features)
                if_predictions = self.isolation_forest.predict(features)
                
                # Convert to anomaly score (higher = more anomalous)
                if_anomaly_score = -if_scores[0]  # Negative because IF returns -1 for anomalies
                if_label = "anomalous" if if_predictions[0] == -1 else "normal"
                
                results["model_predictions"]["isolation_forest"] = {
                    "anomaly_score": float(if_anomaly_score),
                    "prediction": if_label,
                    "raw_score": float(if_scores[0])
                }
            
            # Autoencoder prediction
            if self.autoencoder and TENSORFLOW_AVAILABLE:
                try:
                    reconstructions = self.autoencoder.predict(features, verbose=0)
                    reconstruction_error = np.mean(np.square(features - reconstructions))
                    
                    ae_label = "anomalous" if reconstruction_error > self.autoencoder_threshold else "normal"
                    
                    results["model_predictions"]["autoencoder"] = {
                        "reconstruction_error": float(reconstruction_error),
                        "prediction": ae_label,
                        "threshold": float(self.autoencoder_threshold)
                    }
                except Exception as e:
                    self.logger.warning(f"[WARNING] Autoencoder prediction failed: {e}")
                    results["model_predictions"]["autoencoder"] = {
                        "error": str(e),
                        "prediction": "error"
                    }
            
            # Combined decision logic
            predictions = []
            if "isolation_forest" in results["model_predictions"]:
                predictions.append(results["model_predictions"]["isolation_forest"]["prediction"])
            if "autoencoder" in results["model_predictions"]:
                predictions.append(results["model_predictions"]["autoencoder"]["prediction"])
            
            # Final decision: flag as anomalous if ANY model detects anomaly
            final_label = "anomalous" if "anomalous" in predictions else "normal"
            
            # Calculate confidence score
            anomaly_models = sum(1 for pred in predictions if pred == "anomalous")
            total_models = len(predictions)
            confidence = anomaly_models / total_models if total_models > 0 else 0.0
            
            results["final_prediction"] = {
                "label": final_label,
                "confidence": confidence,
                "models_agreed": total_models - anomaly_models if final_label == "normal" else anomaly_models,
                "total_models": total_models
            }
            
            # Calculate inference time
            inference_time = (time.time() - start_time) * 1000  # Convert to milliseconds
            results["inference_time_ms"] = inference_time
            self.inference_times.append(inference_time)
            
            # Log the prediction
            self.logger.info(
                f"Session {session_data.get('session_id', 'unknown')}: "
                f"Final={final_label}, Confidence={confidence:.2f}, "
                f"Time={inference_time:.2f}ms"
            )
            
            return results
            
        except Exception as e:
            self.logger.error(f"[ERROR] Prediction failed for session {session_data.get('session_id', 'unknown')}: {e}")
            return {
                "error": str(e),
                "session_id": session_data.get('session_id', 'unknown'),
                "timestamp": datetime.now().isoformat()
            }
    
    def get_performance_stats(self) -> Dict[str, Any]:
        """Get performance statistics"""
        if not self.inference_times:
            return {"message": "No inferences performed yet"}
        
        times = np.array(self.inference_times)
        return {
            "total_inferences": len(self.inference_times),
            "avg_inference_time_ms": float(np.mean(times)),
            "min_inference_time_ms": float(np.min(times)),
            "max_inference_time_ms": float(np.max(times)),
            "p95_inference_time_ms": float(np.percentile(times, 95))
        }
    
    def health_check(self) -> Dict[str, Any]:
        """Check model health and status"""
        return {
            "models_loaded": self.models_loaded,
            "isolation_forest_available": self.isolation_forest is not None,
            "autoencoder_available": self.autoencoder is not None and TENSORFLOW_AVAILABLE,
            "preprocessor_available": self.preprocessor is not None,
            "tensorflow_available": TENSORFLOW_AVAILABLE,
            "autoencoder_threshold": self.autoencoder_threshold,
            "feature_count": len(self.feature_names) if hasattr(self, 'feature_names') else 0
        }


# FastAPI Integration for Microservice
try:
    from fastapi import FastAPI, HTTPException
    from pydantic import BaseModel
    import uvicorn
    
    class SessionData(BaseModel):
        session_id: str
        is_bruteforce_candidate: int = 0
        total_attempts: int = 0
        success_rate: float = 0.0
        failure_rate: float = 0.0
        distinct_ips: int = 0
        ip_entropy: float = 0.0
        avg_time_between_attempts: float = 0.0
        total_attempts_ip: int = 0
        distinct_usernames: int = 0
        success_rate_ip: float = 0.0
        attempts_per_minute: float = 0.0
        session_duration: float = 0.0
        ip_changes: int = 0
        user_agent_changes: int = 0
        login_hour: int = 0
        weekday: int = 0
        is_weekend: int = 0
        is_night: int = 0
        velocity_score: int = 0
        suspicious_ip_flag: int = 0
    
    # Create FastAPI app
    app = FastAPI(title="Auth Anomaly Detection API", version="1.0.0")
    ml_integration = AuthMLIntegration()
    
    @app.get("/")
    async def root():
        return {"message": "Authentication Anomaly Detection API", "status": "active"}
    
    @app.get("/health")
    async def health():
        return ml_integration.health_check()
    
    @app.post("/predict")
    async def predict(session_data: SessionData):
        """Predict anomaly for session data"""
        try:
            result = ml_integration.predict_anomaly(session_data.dict())
            return result
        except Exception as e:
            raise HTTPException(status_code=500, detail=str(e))
    
    @app.get("/stats")
    async def stats():
        """Get performance statistics"""
        return ml_integration.get_performance_stats()
    
    def start_api_server(host: str = "0.0.0.0", port: int = 8000):
        """Start the FastAPI server"""
        print(f"Starting ML Integration API at http://{host}:{port}")
        uvicorn.run(app, host=host, port=port)
    
    FASTAPI_AVAILABLE = True

except ImportError:
    FASTAPI_AVAILABLE = False
    print("FastAPI not available - API server disabled")


# Standalone usage example
def main():
    """Example usage of the ML integration"""
    print("Authentication ML Integration - Standalone Test")
    
    # Initialize integration
    ml_integration = AuthMLIntegration()
    
    if not ml_integration.models_loaded:
        print("Failed to load models. Exiting.")
        return
    
    # Test with sample session data
    sample_session = {
        "session_id": "test_session_001",
        "is_bruteforce_candidate": 1,
        "total_attempts": 15,
        "success_rate": 0.1,
        "failure_rate": 0.9,
        "distinct_ips": 3,
        "ip_entropy": 1.2,
        "avg_time_between_attempts": 2.5,
        "total_attempts_ip": 8,
        "distinct_usernames": 2,
        "success_rate_ip": 0.15,
        "attempts_per_minute": 6.0,
        "session_duration": 150.0,
        "ip_changes": 1,
        "user_agent_changes": 0,
        "login_hour": 2,
        "weekday": 1,
        "is_weekend": 0,
        "is_night": 1,
        "velocity_score": 8,
        "suspicious_ip_flag": 1
    }
    
    print("\nTesting with sample session...")
    result = ml_integration.predict_anomaly(sample_session)
    print("Prediction Result:")
    print(json.dumps(result, indent=2))
    
    # Performance stats
    stats = ml_integration.get_performance_stats()
    print(f"\nPerformance: {stats}")


if __name__ == "__main__":
    if FASTAPI_AVAILABLE and len(sys.argv) > 1 and sys.argv[1] == "api":
        start_api_server()
    else:
        main()