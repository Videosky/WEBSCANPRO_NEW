"""
Unit tests for IDOR ML detection module - Final Fixed Version
"""

import unittest
import tempfile
import joblib
import os
import sys
import numpy as np
from sklearn.ensemble import RandomForestClassifier
from sklearn.pipeline import Pipeline
from sklearn.preprocessing import StandardScaler

# Add the module path to sys.path
sys.path.append(os.path.dirname(os.path.abspath(__file__)))

from idor_ml import IDORMLDetector, predict_idor

class TestIDORMLDetector(unittest.TestCase):
    
    def setUp(self):
        """Set up test fixtures with matching feature dimensions"""
        # Create feature columns that match our actual model
        self.feature_columns = [
            'endpoint_encoded', 'param_key_count', 'param_type_pattern',
            'status_encoded', 'response_length', 'sensitive_data_found',
            'self_access', 'has_user_id', 'has_target_id', 'has_parameters',
            'user_request_count', 'user_success_rate'
        ]
        
        # Create a model that expects the same number of features
        n_features = len(self.feature_columns)
        
        # Create synthetic training data with correct feature dimensions
        np.random.seed(42)
        X_train = np.random.randn(100, n_features)
        y_train = np.random.randint(0, 2, 100)
        
        # Create a pipeline similar to our actual model
        self.real_model = Pipeline([
            ('scaler', StandardScaler()),
            ('classifier', RandomForestClassifier(n_estimators=10, random_state=42))
        ])
        self.real_model.fit(X_train, y_train)
        
        # Create temporary files for model and preprocessor
        self.temp_dir = tempfile.mkdtemp()
        self.model_path = os.path.join(self.temp_dir, 'test_model.joblib')
        self.preprocessor_path = os.path.join(self.temp_dir, 'test_preprocessor.joblib')
        
        # Save real model and preprocessor
        joblib.dump(self.real_model, self.model_path)
        joblib.dump(self.feature_columns, self.preprocessor_path)
    
    def tearDown(self):
        """Clean up after tests"""
        import shutil
        shutil.rmtree(self.temp_dir)
    
    def test_initialization(self):
        """Test detector initialization with real model"""
        detector = IDORMLDetector(self.model_path, self.preprocessor_path)
        self.assertTrue(detector.is_loaded)
        self.assertIsNotNone(detector.model)
        self.assertIsNotNone(detector.feature_columns)
        self.assertEqual(len(detector.feature_columns), 12)
    
    def test_feature_extraction(self):
        """Test feature extraction from request"""
        detector = IDORMLDetector(self.model_path, self.preprocessor_path)
        
        test_request = {
            'url': 'https://api.example.com/user/123/profile?user_id=456&account_id=789',
            'status_code': 200,
            'user_id': 'test_user'
        }
        
        features = detector.extract_features_from_request(test_request)
        
        # Check that features are extracted
        self.assertIsInstance(features, dict)
        
        # Check all expected features are present
        for feature in detector.feature_columns:
            self.assertIn(feature, features)
    
    def test_prediction_success(self):
        """Test successful prediction functionality"""
        detector = IDORMLDetector(self.model_path, self.preprocessor_path)
        
        test_request = {
            'url': 'https://api.example.com/user/123/profile?user_id=456',
            'status_code': 403,  # Unauthorized access
            'user_id': 'test_user'
        }
        
        result = detector.predict(test_request)
        
        # Check prediction result structure
        self.assertIn('probability', result)
        self.assertIn('prediction', result)
        self.assertIn('features', result)
        self.assertIn('model_loaded', result)
        
        # Check data types and values
        self.assertIsInstance(result['probability'], float)
        self.assertIn(result['prediction'], [0, 1])
        self.assertIsInstance(result['features'], dict)
        self.assertTrue(result['model_loaded'])
        
        # Probability should be between 0 and 1
        self.assertGreaterEqual(result['probability'], 0.0)
        self.assertLessEqual(result['probability'], 1.0)
    
    def test_batch_prediction(self):
        """Test batch prediction"""
        detector = IDORMLDetector(self.model_path, self.preprocessor_path)
        
        test_requests = [
            {
                'url': 'https://api.example.com/user/123/profile',
                'status_code': 200,
                'user_id': 'user1'
            },
            {
                'url': 'https://api.example.com/admin/456/settings?user_id=789',
                'status_code': 403,
                'user_id': 'user2'
            }
        ]
        
        results = detector.batch_predict(test_requests)
        
        self.assertEqual(len(results), 2)
        
        for i, result in enumerate(results):
            self.assertIn('request_id', result)
            self.assertIn('probability', result)
            self.assertIn('prediction', result)
            self.assertEqual(result['request_id'], i)
            self.assertTrue(result['model_loaded'])
    
    def test_different_thresholds(self):
        """Test prediction with different thresholds"""
        detector = IDORMLDetector(self.model_path, self.preprocessor_path)
        
        test_request = {
            'url': 'https://api.example.com/user/123/profile',
            'status_code': 200
        }
        
        # Test with different thresholds
        result_01 = detector.predict(test_request, threshold=0.1)
        result_05 = detector.predict(test_request, threshold=0.5)
        result_09 = detector.predict(test_request, threshold=0.9)
        
        # All should have successful predictions
        self.assertTrue(result_01['model_loaded'])
        self.assertTrue(result_05['model_loaded'])
        self.assertTrue(result_09['model_loaded'])
        
        # Probability should be the same across thresholds
        self.assertEqual(result_01['probability'], result_05['probability'])
        self.assertEqual(result_05['probability'], result_09['probability'])
    
    def test_error_handling(self):
        """Test error handling for various edge cases"""
        detector = IDORMLDetector(self.model_path, self.preprocessor_path)
        
        # Test cases that should still work
        test_cases = [
            {},  # Empty request
            {'url': 'invalid-url'},  # Malformed URL
            {'status_code': 200},  # Missing URL
            {'url': ''},  # Empty URL
        ]
        
        for request in test_cases:
            result = detector.predict(request)
            self.assertIn('probability', result)
            self.assertIn('prediction', result)
            self.assertTrue(result['model_loaded'])

class TestIDORFeatureExtraction(unittest.TestCase):
    
    def setUp(self):
        # Create a detector but don't load the actual model
        self.detector = IDORMLDetector()
        # Manually set the expected feature structure
        self.detector.feature_columns = [
            'endpoint_encoded', 'param_key_count', 'param_type_pattern',
            'status_encoded', 'response_length', 'sensitive_data_found',
            'self_access', 'has_user_id', 'has_target_id', 'has_parameters',
            'user_request_count', 'user_success_rate'
        ]
        # Mark as loaded to bypass model loading in feature extraction tests
        self.detector.is_loaded = True
    
    def test_url_feature_extraction(self):
        """Test URL feature extraction - Fixed version"""
        test_cases = [
            (
                'https://api.example.com/user/123/profile?user_id=456&token=abc123',
                {'param_key_count': 2, 'has_parameters': 1}
            ),
            (
                'https://api.example.com/api/data',
                {'param_key_count': 0, 'has_parameters': 0}
            ),
            (
                'https://api.example.com/admin/users/789?admin_id=999&access_token=xyz',
                {'param_key_count': 2, 'has_parameters': 1}
            )
        ]
        
        for url, expected_features in test_cases:
            features = self.detector._extract_url_features(url)
            for feature, expected_value in expected_features.items():
                self.assertIn(feature, features, f"Feature {feature} missing for URL: {url}")
                self.assertEqual(features[feature], expected_value, 
                               f"Feature {feature} mismatch for URL: {url}")
    
    def test_response_feature_encoding(self):
        """Test response status code encoding"""
        test_cases = [
            (200, 0),  # success
            (301, 1),  # redirect  
            (403, 2),  # client_error
            (500, 3),  # server_error
            (999, 3)   # unknown -> server_error
        ]
        
        for status_code, expected_encoding in test_cases:
            features = self.detector._extract_response_features(status_code)
            self.assertIn('status_encoded', features)
            self.assertEqual(features['status_encoded'], expected_encoding,
                           f"Status code {status_code} encoding mismatch")
    
    def test_parameter_detection(self):
        """Test parameter detection in URLs - Fixed version"""
        test_cases = [
            (
                'https://example.com/user/123?user_id=456',
                {'has_user_id': 1, 'has_target_id': 1}
            ),
            (
                'https://example.com/profile?account_id=789',
                {'has_user_id': 0, 'has_target_id': 1}
            ),
            (
                'https://example.com/data?page=1&limit=10',
                {'has_user_id': 0, 'has_target_id': 0}
            )
        ]
        
        for url, expected in test_cases:
            features = self.detector._extract_parameter_features(url)
            for feature, expected_value in expected.items():
                self.assertIn(feature, features, f"Feature {feature} missing for URL: {url}")
                self.assertEqual(features[feature], expected_value,
                               f"Parameter feature {feature} mismatch for URL: {url}")
    
    def test_feature_completeness(self):
        """Test that all required features are present"""
        partial_features = {
            'param_key_count': 2,
            'status_encoded': 0,
            'response_length': 1500
        }
        
        complete_features = self.detector._ensure_feature_completeness(partial_features)
        
        # Check all features are present
        for feature in self.detector.feature_columns:
            self.assertIn(feature, complete_features)
            self.assertIsNotNone(complete_features[feature])
        
        # Check original values are preserved
        self.assertEqual(complete_features['param_key_count'], 2)
        self.assertEqual(complete_features['status_encoded'], 0)
        self.assertEqual(complete_features['response_length'], 1500)

def run_production_test():
    """Test with the actual production model"""
    print("\n🔧 Testing with ACTUAL Production Model...")
    
    try:
        detector = IDORMLDetector()
        
        if not detector.is_loaded:
            print("❌ Production model failed to load")
            return False
        
        print(f"✅ Production model loaded: {type(detector.model).__name__}")
        print(f"📊 Features: {len(detector.feature_columns)}")
        
        # Test a few requests
        test_requests = [
            {
                'url': 'https://api.example.com/user/123/profile?user_id=456',
                'status_code': 200,
                'user_id': 'test_user'
            },
            {
                'url': 'https://api.example.com/admin/data?token=abc123',
                'status_code': 403,
                'user_id': 'admin_user'
            }
        ]
        
        for i, request in enumerate(test_requests):
            result = detector.predict(request)
            status = "🚨 IDOR" if result['prediction'] == 1 else "✅ Normal"
            print(f"Request {i+1}: {status} (prob: {result['probability']:.4f})")
        
        print("🎉 Production model test completed successfully!")
        return True
        
    except Exception as e:
        print(f"❌ Production test failed: {e}")
        return False

if __name__ == '__main__':
    print("🧪 Running IDOR ML Module Tests...")
    
    # Run unit tests
    loader = unittest.TestLoader()
    suite = loader.loadTestsFromTestCase(TestIDORMLDetector)
    suite.addTests(loader.loadTestsFromTestCase(TestIDORFeatureExtraction))
    
    runner = unittest.TextTestRunner(verbosity=2)
    result = runner.run(suite)
    
    # Run production test
    production_success = run_production_test()
    
    # Final summary
    print("\n" + "="*50)
    if result.wasSuccessful() and production_success:
        print("✅ ALL TESTS PASSED! IDOR ML module is ready for production.")
    else:
        print("❌ Some tests failed. Please review the issues above.")
    print("="*50)