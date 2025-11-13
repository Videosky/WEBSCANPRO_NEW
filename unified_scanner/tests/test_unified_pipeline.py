"""
Test suite for Unified Vulnerability Scanner - FIXED VERSION
"""

import unittest
import os
import sys
import tempfile
import json
from unittest import mock

# Add project root to path
project_root = os.path.abspath(os.path.join(os.path.dirname(__file__), '..', '..'))
sys.path.insert(0, project_root)

# Add unified_scanner directory directly to path
unified_scanner_dir = os.path.join(project_root, 'projects', 'unified_scanner')
sys.path.insert(0, unified_scanner_dir)

class TestUnifiedScanner(unittest.TestCase):
    
    def setUp(self):
        """Set up test environment"""
        self.test_url = "http://example.com/test"
        
    @mock.patch('utils.HTTPClient')
    @mock.patch('inference_xss.get_xss_detector')
    @mock.patch('inference_sqli.get_sqli_detector')
    def test_scanner_initialization(self, mock_sqli, mock_xss, mock_http):
        """Test scanner initialization"""
        # Import after setting up paths
        from unified_scanner import UnifiedScanner
        
        # Mock dependencies
        mock_xss.return_value.predict_xss.return_value = {"prob": 0.1, "is_malicious": False, "method": "mock"}
        mock_sqli.return_value.predict_sqli.return_value = {"prob": 0.1, "is_malicious": False, "method": "mock"}
        
        scanner = UnifiedScanner()
        self.assertIsNotNone(scanner)
        self.assertIsNotNone(scanner.xss_detector)
        self.assertIsNotNone(scanner.sqli_detector)
    
    def test_payload_generation(self):
        """Test payload generation"""
        from utils import PayloadGenerator
        
        generator = PayloadGenerator()
        
        xss_payloads = generator.get_xss_payloads()
        sqli_payloads = generator.get_sqli_payloads()
        
        self.assertGreater(len(xss_payloads), 0)
        self.assertGreater(len(sqli_payloads), 0)
        
        # Check that payloads are strings
        for payload in xss_payloads + sqli_payloads:
            self.assertIsInstance(payload, str)
    
    def test_report_generation(self):
        """Test report generation"""
        from reporting import ReportGenerator
        
        with tempfile.TemporaryDirectory() as temp_dir:
            # Mock SCAN_REPORTS_DIR
            with mock.patch('reporting.SCAN_REPORTS_DIR', temp_dir):
                reporter = ReportGenerator()
                
                # Add mock results
                mock_results = [
                    {
                        "url": "http://example.com",
                        "xss": {"is_malicious": True, "prob": 0.9, "method": "test"},
                        "sqli": {"is_malicious": False, "prob": 0.2, "method": "test"},
                        "success": True
                    }
                ]
                
                for result in mock_results:
                    reporter.add_result(result)
                
                # Generate reports
                json_file = reporter.generate_json_report()
                csv_file = reporter.generate_csv_report()
                
                self.assertTrue(os.path.exists(json_file))
                self.assertTrue(os.path.exists(csv_file))
                
                # Verify JSON content
                with open(json_file, 'r') as f:
                    report_data = json.load(f)
                    self.assertEqual(report_data["metadata"]["total_urls_scanned"], 1)
                    self.assertEqual(report_data["metadata"]["total_xss_detected"], 1)


class TestInferenceModules(unittest.TestCase):
    
    def test_xss_detection(self):
        """Test XSS detection"""
        from inference_xss import predict_xss
        
        # Test benign content
        result = predict_xss("Normal HTML content")
        self.assertIn("prob", result)
        self.assertIn("is_malicious", result)
        self.assertIn("method", result)
        
        # Test malicious content
        result = predict_xss("<script>alert('XSS')</script>")
        self.assertIn("prob", result)
        self.assertIn("is_malicious", result)
    
    def test_sqli_detection(self):
        """Test SQLi detection"""
        from inference_sqli import predict_sqli
        
        # Test benign content
        result = predict_sqli("normal input", "normal response")
        self.assertIn("prob", result)
        self.assertIn("is_malicious", result)
        self.assertIn("method", result)
        
        # Test malicious content
        result = predict_sqli("' OR 1=1--", "SQL syntax error")
        self.assertIn("prob", result)
        self.assertIn("is_malicious", result)


if __name__ == '__main__':
    # Create test directories
    os.makedirs('outputs/scan_reports', exist_ok=True)
    os.makedirs('outputs/logs', exist_ok=True)
    
    # Run tests
    unittest.main(verbosity=2)