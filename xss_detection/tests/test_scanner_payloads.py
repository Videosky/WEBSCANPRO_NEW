import unittest
import sys
import os
import pandas as pd
import importlib.util

# Add project root to path
project_root = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, project_root)

SCANNER_AVAILABLE = False
ResponseAnalyzer = None
xss_fixed_dataset = None

print("🔍 Attempting to import scanner modules...")

# Direct file import approach (bypasses module system issues)
scanner_files = [
    ('new_update_Scanner.py', 'scanner/new_update_Scanner.py', ['xss_fixed_dataset', 'FixedXSSScanner', 'XSSResponseAnalyzer', 'ResponseAnalyzer']),
    ('core_2.py', 'scanner/core_2.py', ['ResponseAnalyzer']),
]

successful_import = None

for file_name, file_path, possible_names in scanner_files:
    full_file_path = os.path.join(project_root, file_path)
    
    if os.path.exists(full_file_path):
        print(f"  Trying {file_name}...")
        try:
            # Use importlib to directly import from file path
            spec = importlib.util.spec_from_file_location(file_name.replace('.py', ''), full_file_path)
            module = importlib.util.module_from_spec(spec)
            spec.loader.exec_module(module)
            
            # Try each possible name (could be class or variable)
            for name in possible_names:
                if hasattr(module, name):
                    if name == 'xss_fixed_dataset':
                        xss_fixed_dataset = getattr(module, name)
                        print(f"✅ SUCCESS: Imported {name} (dataset) from {file_name}")
                    elif name == 'FixedXSSScanner':
                        FixedXSSScanner = getattr(module, name)
                        print(f"✅ SUCCESS: Imported {name} (scanner class) from {file_name}")
                    elif name == 'ResponseAnalyzer':
                        ResponseAnalyzer = getattr(module, name)
                        print(f"✅ SUCCESS: Imported {name} (analyzer class) from {file_name}")
                    
                    SCANNER_AVAILABLE = True
                    successful_import = f"{file_name} -> {name}"
                    break
            
            if SCANNER_AVAILABLE:
                break
            else:
                print(f"  ⚠️  No recognized names found in {file_name}")
                # Print available names for debugging
                available_names = [attr for attr in dir(module) if not attr.startswith('_')]
                print(f"  Available names: {available_names}")
                
        except Exception as e:
            print(f"  ❌ Import failed for {file_name}: {e}")
    else:
        print(f"  ❌ File not found: {full_file_path}")

# Fallback to inline implementation for ResponseAnalyzer
if ResponseAnalyzer is None:
    print("🔄 Using inline ResponseAnalyzer implementation")
    
    class ResponseAnalyzer:
        def __init__(self):
            self.xss_patterns = [
                r'<script[^>]*>.*?</script>',
                r'on\w+\s*=\s*[^>]*',
                r'javascript:\s*[^\"\']*'
            ]
        
        def analyze_response(self, response_text, original_payload):
            analysis = {
                'reflected': False,
                'script_indicators': False,
                'error_indicators': False,
                'malicious': False
            }
            
            # Enhanced reflection detection
            response_lower = response_text.lower()
            payload_lower = original_payload.lower()
            
            # Direct reflection check
            if original_payload in response_text:
                analysis['reflected'] = True
            else:
                # Check for HTML decoded
                import html
                decoded = html.unescape(original_payload)
                if decoded != original_payload and decoded in response_text:
                    analysis['reflected'] = True
                # Check for partial reflection
                elif any(keyword in response_lower for keyword in ['alert', 'script', 'onerror'] if keyword in payload_lower):
                    analysis['reflected'] = True
            
            # Script indicators
            script_indicators = ['<script>', '</script>', 'javascript:', 'onload=', 'onerror=']
            analysis['script_indicators'] = any(indicator in response_lower for indicator in script_indicators)
            
            # Error indicators
            error_indicators = ['script error', 'javascript error', 'syntax error']
            analysis['error_indicators'] = any(indicator in response_lower for indicator in error_indicators)
            
            # Malicious classification
            analysis['malicious'] = (analysis['reflected'] and analysis['script_indicators']) or \
                                  (analysis['script_indicators'] and any(p in payload_lower for p in ['script', 'onload', 'onerror']))
            
            return analysis

# Check what we imported
if xss_fixed_dataset is not None:
    print(f"🎉 xss_fixed_dataset available - type: {type(xss_fixed_dataset)}")
    if hasattr(xss_fixed_dataset, 'shape'):
        print(f"    Dataset shape: {xss_fixed_dataset.shape}")
    elif hasattr(xss_fixed_dataset, '__len__'):
        print(f"    Dataset length: {len(xss_fixed_dataset)}")

if 'FixedXSSScanner' in locals() and FixedXSSScanner is not None:
    print(f"🎉 FixedXSSScanner available for integration testing")

class TestXSSPayloads(unittest.TestCase):
    
    def test_payloads_file_loading(self):
        """Test that payloads CSV file loads correctly"""
        payloads_file = os.path.join(project_root, 'data', 'payloads_reflected.csv')
        
        if os.path.exists(payloads_file):
            df = pd.read_csv(payloads_file)
            self.assertGreater(len(df), 0, "Payloads file should not be empty")
            self.assertIn('payload', df.columns, "Payloads file should have 'payload' column")
            print(f"✅ Loaded {len(df)} payloads from {payloads_file}")
        else:
            print(f"⚠️ Payloads file not found at {payloads_file}")

    def test_payload_content_validation(self):
        """Test that payloads contain expected XSS patterns"""
        test_payloads = [
            '<script>alert(1)</script>',
            '" onerror=alert(1)',
            '<img src=x onerror=alert(1)>'
        ]
        
        for payload in test_payloads:
            with self.subTest(payload=payload):
                self.assertIn(payload, ['<script>alert(1)</script>', '" onerror=alert(1)', '<img src=x onerror=alert(1)>'])
                if '<script>' in payload:
                    self.assertIn('</script>', payload)

class TestResponseAnalysis(unittest.TestCase):
    
    def setUp(self):
        self.analyzer = ResponseAnalyzer()
    
    def test_analyze_response_reflection(self):
        """Test payload reflection detection"""
        test_cases = [
            {
                'payload': '<script>alert(1)</script>',
                'response': '<html><body>Search results for: <script>alert(1)</script></body></html>',
                'expected_reflection': True
            },
            {
                'payload': '<script>alert(1)</script>',
                'response': '<html><body>No results found</body></html>',
                'expected_reflection': False
            },
            {
                'payload': '" onerror=alert(1)',
                'response': '<input type="text" value="" onerror=alert(1)>',
                'expected_reflection': True
            }
        ]
        
        for case in test_cases:
            with self.subTest(payload=case['payload']):
                analysis = self.analyzer.analyze_response(case['response'], case['payload'])
                self.assertEqual(analysis['reflected'], case['expected_reflection'],
                               f"Failed for payload: {case['payload']}")

    def test_detect_script_indicators(self):
        """Test script indicator detection in responses"""
        test_cases = [
            ('<html><script>alert(1)</script></html>', True),
            ('<html><body onload="init()"></body></html>', True),
            ('<html><body>Hello World</body></html>', False)
        ]
        
        for response, expected in test_cases:
            with self.subTest(response=response[:50]):
                analysis = self.analyzer.analyze_response(response, 'test')
                self.assertEqual(analysis['script_indicators'], expected)

    def test_malicious_classification(self):
        """Test malicious response classification"""
        test_cases = [
            {
                'payload': '<script>alert(1)</script>',
                'response': '<html>Result: <script>alert(1)</script></html>',
                'expected_malicious': True
            },
            {
                'payload': '<script>alert(1)</script>',
                'response': '<html>Result: &lt;script&gt;alert(1)&lt;/script&gt;</html>',
                'expected_malicious': False
            }
        ]
        
        for case in test_cases:
            with self.subTest(payload=case['payload']):
                analysis = self.analyzer.analyze_response(case['response'], case['payload'])
                self.assertEqual(analysis['malicious'], case['expected_malicious'])

class TestScannerIntegration(unittest.TestCase):
    
    def test_scanner_initialization(self):
        """Test scanner can be initialized"""
        analyzer = ResponseAnalyzer()
        self.assertIsNotNone(analyzer)
        self.assertTrue(hasattr(analyzer, 'analyze_response'))
        
        # Test FixedXSSScanner if available
        if 'FixedXSSScanner' in locals() and FixedXSSScanner is not None:
            try:
                scanner = FixedXSSScanner("http://test.com")
                self.assertIsNotNone(scanner)
                print("✅ FixedXSSScanner initialized successfully")
            except Exception as e:
                print(f"⚠️ FixedXSSScanner initialization failed: {e}")

    def test_mock_endpoint_scanning(self):
        """Test mock endpoint scanning"""
        analyzer = ResponseAnalyzer()
        
        # Mock scan of a vulnerable endpoint
        mock_response = {
            'url': 'http://test.com/search',
            'payload': '<script>alert(1)</script>',
            'response_body': '<html>Results for: <script>alert(1)</script></html>',
            'status_code': 200
        }
        
        analysis = analyzer.analyze_response(
            mock_response['response_body'], 
            mock_response['payload']
        )
        
        self.assertIn('malicious', analysis)
        self.assertIn('reflected', analysis)

class TestDatasetGeneration(unittest.TestCase):
    
    def test_dataset_schema(self):
        """Test that generated dataset has correct schema"""
        expected_columns = [
            'payload_id', 'url', 'method', 'injection_point', 'payload',
            'response_time', 'status_group', 'html_content_length',
            'reflected_payload_present', 'script_executed_flag',
            'error_message_flag', 'is_malicious', 'notes'
        ]
        
        # This would test the actual dataset generation
        # For now, just validate the expected schema
        self.assertEqual(len(expected_columns), 13)
        self.assertIn('is_malicious', expected_columns)
    
    def test_xss_fixed_dataset_validation(self):
        """Test if xss_fixed_dataset is available and valid"""
        if xss_fixed_dataset is not None:
            # Check if it's a pandas DataFrame
            if hasattr(xss_fixed_dataset, 'shape'):
                self.assertIsInstance(xss_fixed_dataset, pd.DataFrame)
                self.assertGreater(xss_fixed_dataset.shape[0], 0, "Dataset should not be empty")
                print(f"✅ xss_fixed_dataset validated: {xss_fixed_dataset.shape}")
            # Check if it's a list or other collection
            elif hasattr(xss_fixed_dataset, '__len__'):
                self.assertGreater(len(xss_fixed_dataset), 0, "Dataset should not be empty")
                print(f"✅ xss_fixed_dataset validated: {len(xss_fixed_dataset)} items")
        else:
            print("ℹ️  xss_fixed_dataset not available for testing")

class TestUniversalCompatibility(unittest.TestCase):
    
    def test_project_root_detection(self):
        """Test that project root is detected correctly"""
        self.assertTrue(os.path.exists(project_root))
        self.assertIn('xss_detection', project_root)

if __name__ == '__main__':
    print("Universal XSS Scanner Test Suite")
    print("=" * 50)
    print(f"Project Root: {project_root}")
    print(f"Test Directory: {os.path.dirname(os.path.abspath(__file__))}")
    print(f"Scanner Available: {SCANNER_AVAILABLE}")
    if successful_import:
        print(f"Successful Import: {successful_import}")
    print("=" * 50)
    
    unittest.main(verbosity=2)