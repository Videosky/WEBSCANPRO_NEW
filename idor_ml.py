import pandas as pd
import numpy as np
import joblib
import os
from urllib.parse import urlparse, parse_qs
import re

class IDORMLDetector:
    def __init__(self, model_path=None, preprocessor_path=None):
        self.model = None
        self.feature_columns = None
        self.is_loaded = False
        
        if model_path is None:
            model_path = r"C:\Users\vishal\Desktop\WEBSCAN_PRO\projects\auth_session\models\idor_model.joblib"
        if preprocessor_path is None:
            preprocessor_path = r"C:\Users\vishal\Desktop\WEBSCAN_PRO\projects\auth_session\models\preprocessor.joblib"
        
        self.model_path = model_path
        self.preprocessor_path = preprocessor_path
        
        self.load_model()
    
    def load_model(self):
        try:
            if not os.path.exists(self.model_path):
                print(f"Model file not found: {self.model_path}")
                return False
            
            if not os.path.exists(self.preprocessor_path):
                print(f"Preprocessor file not found: {self.preprocessor_path}")
                return False
            
            self.model = joblib.load(self.model_path)
            self.feature_columns = joblib.load(self.preprocessor_path)
            
            self.is_loaded = True
            print(f"IDOR ML model loaded successfully")
            print(f"Model type: {type(self.model).__name__}")
            print(f"Features: {len(self.feature_columns)}")
            
            return True
            
        except Exception as e:
            print(f"Error loading model: {e}")
            self.is_loaded = False
            return False
    
    def extract_features_from_request(self, request_data):
        features = {}
        
        try:
            url = request_data.get('url', '')
            features.update(self._extract_url_features(url))
            
            status_code = request_data.get('status_code', 200)
            features.update(self._extract_response_features(status_code))
            
            features.update(self._extract_parameter_features(url))
            
            user_id = request_data.get('user_id')
            features.update(self._extract_user_features(user_id, url))
            
            features = self._ensure_feature_completeness(features)
            
            return features
            
        except Exception as e:
            print(f"Error extracting features: {e}")
            return self._get_default_features()
    
    def _extract_url_features(self, url):
        features = {}
        
        try:
            parsed = urlparse(url)
            path = parsed.path
            
            endpoint_path = re.sub(r'/\d+', '/{id}', path)
            endpoint_path = re.sub(r'/[a-fA-F0-9-]{36}', '/{uuid}', endpoint_path)
            
            features['endpoint_encoded'] = hash(endpoint_path) % 1000
            
            query_params = parse_qs(parsed.query)
            features['param_key_count'] = len(query_params)
            features['has_parameters'] = 1 if features['param_key_count'] > 0 else 0
            
            param_types = []
            for values in query_params.values():
                if values:
                    value = str(values[0])
                    if re.match(r'^\d+$', value):
                        param_types.append('numeric')
                    elif re.match(r'^[a-fA-F0-9-]{36}$', value):
                        param_types.append('uuid')
                    else:
                        param_types.append('other')
            
            features['param_type_pattern'] = hash('_'.join(sorted(set(param_types)))) % 100 if param_types else 0
            
        except Exception as e:
            print(f"Error in URL feature extraction: {e}")
            features.update({
                'endpoint_encoded': 0,
                'param_key_count': 0,
                'has_parameters': 0,
                'param_type_pattern': 0
            })
        
        return features
    
    def _extract_response_features(self, status_code):
        features = {}
        
        try:
            if 200 <= status_code < 300:
                features['status_encoded'] = 0
            elif 300 <= status_code < 400:
                features['status_encoded'] = 1
            elif 400 <= status_code < 500:
                features['status_encoded'] = 2
            else:
                features['status_encoded'] = 3
            
            features['response_length'] = np.random.randint(100, 5000)
            features['sensitive_data_found'] = 0
            
        except Exception as e:
            print(f"Error in response feature extraction: {e}")
            features.update({
                'status_encoded': 0,
                'response_length': 1000,
                'sensitive_data_found': 0
            })
        
        return features
    
    def _extract_parameter_features(self, url):
        features = {}
        
        try:
            parsed = urlparse(url)
            query_params = parse_qs(parsed.query)
            
            features['self_access'] = 0
            features['has_user_id'] = 1 if any('user' in key.lower() for key in query_params) else 0
            features['has_target_id'] = 1 if any('id' in key.lower() for key in query_params) else 0
            
            features['user_request_count'] = 1
            features['user_unauthorized_count'] = 0
            features['user_success_rate'] = 1.0
            
        except Exception as e:
            print(f"Error in parameter feature extraction: {e}")
            features.update({
                'self_access': 0,
                'has_user_id': 0,
                'has_target_id': 0,
                'user_request_count': 1,
                'user_unauthorized_count': 0,
                'user_success_rate': 1.0
            })
        
        return features
    
    def _extract_user_features(self, user_id, url):
        features = {}
        
        try:
            if user_id is not None:
                features['user_request_count'] = np.random.randint(1, 100)
                features['user_unauthorized_count'] = 0
                features['user_success_rate'] = 0.95
            else:
                features['user_request_count'] = 1
                features['user_unauthorized_count'] = 0
                features['user_success_rate'] = 1.0
                
        except Exception as e:
            print(f"Error in user feature extraction: {e}")
            features.update({
                'user_request_count': 1,
                'user_unauthorized_count': 0,
                'user_success_rate': 1.0
            })
        
        return features
    
    def _ensure_feature_completeness(self, features):
        default_features = self._get_default_features()
        
        for feature in self.feature_columns:
            if feature not in features:
                features[feature] = default_features.get(feature, 0)
        
        return features
    
    def _get_default_features(self):
        return {
            'endpoint_encoded': 0,
            'param_key_count': 0,
            'param_type_pattern': 0,
            'status_encoded': 0,
            'response_length': 1000,
            'sensitive_data_found': 0,
            'self_access': 0,
            'has_user_id': 0,
            'has_target_id': 0,
            'has_parameters': 0,
            'user_request_count': 1,
            'user_unauthorized_count': 0,
            'user_success_rate': 1.0
        }
    
    def predict(self, request_data, threshold=0.5):
        if not self.is_loaded:
            return {
                'error': 'Model not loaded',
                'probability': 0.0,
                'prediction': 0,
                'features': {}
            }
        
        try:
            features = self.extract_features_from_request(request_data)
            
            feature_vector = []
            for feature_name in self.feature_columns:
                feature_vector.append(features.get(feature_name, 0))
            
            X = np.array(feature_vector).reshape(1, -1)
            
            probability = self.model.predict_proba(X)[0, 1]
            prediction = 1 if probability >= threshold else 0
            
            return {
                'probability': float(probability),
                'prediction': int(prediction),
                'features': features,
                'threshold': threshold,
                'model_loaded': True
            }
            
        except Exception as e:
            print(f"Prediction error: {e}")
            return {
                'error': str(e),
                'probability': 0.0,
                'prediction': 0,
                'features': {},
                'model_loaded': False
            }
    
    def batch_predict(self, requests_data, threshold=0.5):
        results = []
        
        for i, request_data in enumerate(requests_data):
            result = self.predict(request_data, threshold)
            result['request_id'] = i
            results.append(result)
        
        return results

_idor_detector = None

def get_idor_detector(model_path=None, preprocessor_path=None):
    global _idor_detector
    
    if _idor_detector is None:
        _idor_detector = IDORMLDetector(model_path, preprocessor_path)
    
    return _idor_detector

def predict_idor(request_data, threshold=0.5):
    detector = get_idor_detector()
    return detector.predict(request_data, threshold)

if __name__ == "__main__":
    test_request = {
        'url': 'https://api.example.com/user/123/profile?user_id=456&token=abc123',
        'status_code': 200,
        'user_id': 'user123'
    }
    
    detector = IDORMLDetector()
    result = detector.predict(test_request)
    
    print("IDOR Detection Result:")
    print(f"  Probability: {result['probability']:.4f}")
    print(f"  Prediction: {result['prediction']}")