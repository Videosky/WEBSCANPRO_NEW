"""
Fixed XSS Scanner without emojis for Windows compatibility
"""

import pandas as pd
import requests
import time
import logging
import os
import re
from datetime import datetime
from typing import List, Dict
from urllib.parse import urljoin, urlencode, parse_qs

class FixedXSSScanner:
    def __init__(self, base_url: str):
        self.base_url = base_url.rstrip('/')
        self.session = requests.Session()
        self.session.headers.update({
            'User-Agent': 'XSS-Scanner/1.0'
        })
        
    def test_endpoint(self, endpoint: str, payload: str, param_name: str = "q") -> Dict:
        """Test a single endpoint with XSS payload"""
        start_time = time.time()
        
        try:
            # Build URL with payload and identify injection point
            if '?' in endpoint:
                test_url = f"{self.base_url}{endpoint}&{param_name}={payload}"
                injection_point = f"query_param:{param_name}"
            else:
                test_url = f"{self.base_url}{endpoint}?{param_name}={payload}"
                injection_point = f"query_param:{param_name}"
            
            response = self.session.get(test_url, timeout=10, allow_redirects=True)
            response_time = time.time() - start_time
            
            # Analyze response
            analysis = self.analyze_response(response.text, payload)
            
            # Determine status group
            status_group = self._get_status_group(response.status_code)
            
            return {
                'success': True,
                'endpoint': endpoint,
                'url': response.url,
                'method': 'GET',
                'injection_point': injection_point,
                'payload': payload,
                'status_code': response.status_code,
                'status_group': status_group,
                'response_time': response_time,
                'html_content_length': len(response.text),
                'reflected_payload_present': analysis['reflected'],
                'script_indicators': analysis['script_indicators'],
                'is_malicious': analysis['is_malicious'],
                'notes': analysis['notes']
            }
            
        except Exception as e:
            return {
                'success': False,
                'endpoint': endpoint,
                'error': str(e),
                'response_time': time.time() - start_time
            }
    
    def _get_status_group(self, status_code: int) -> str:
        """Convert status code to status group"""
        if 200 <= status_code < 300:
            return "success"
        elif 300 <= status_code < 400:
            return "redirect"
        elif 400 <= status_code < 500:
            return "client_error"
        elif 500 <= status_code < 600:
            return "server_error"
        else:
            return "unknown"
    
    def analyze_response(self, content: str, payload: str) -> Dict:
        """Analyze response for XSS indicators"""
        # Check if payload is reflected
        payload_reflected = payload in content
        
        # Check for encoded payload reflection
        encoded_reflected = False
        try:
            from urllib.parse import unquote
            encoded_reflected = unquote(payload) in content
        except:
            pass
        
        # Look for script indicators
        script_indicators = []
        
        patterns = {
            'script_tag': r'<script[^>]*>',
            'onerror_event': r'onerror\s*=',
            'onload_event': r'onload\s*=',
            'onclick_event': r'onclick\s*=',
            'javascript_url': r'javascript:',
            'alert_function': r'alert\s*\(',
            'img_tag_with_event': r'<img[^>]*onerror',
            'svg_tag_with_event': r'<svg[^>]*onload'
        }
        
        for name, pattern in patterns.items():
            if re.search(pattern, content, re.IGNORECASE):
                script_indicators.append(name)
        
        # Determine if malicious
        is_malicious = (payload_reflected or encoded_reflected) and len(script_indicators) > 0
        
        notes = []
        if payload_reflected:
            notes.append("Payload directly reflected")
        if encoded_reflected:
            notes.append("URL-encoded payload reflected")
        if script_indicators:
            notes.append(f"Script indicators: {', '.join(script_indicators)}")
        if not notes:
            notes.append("No XSS indicators found")
        
        return {
            'reflected': payload_reflected or encoded_reflected,
            'script_indicators': script_indicators,
            'is_malicious': is_malicious,
            'notes': '; '.join(notes)
        }

class FixedDatasetCollector:
    def __init__(self, base_url: str = "http://localhost:8080"):
        self.base_url = base_url
        self.scanner = FixedXSSScanner(base_url)
        self.dataset = []
        
        self._setup_logging()
        
    def _setup_logging(self):
        """Setup logging without emojis"""
        log_dir = os.path.join(os.path.dirname(os.path.dirname(__file__)), 'logs')
        os.makedirs(log_dir, exist_ok=True)
        
        timestamp = datetime.now().strftime('%Y%m%d_%H%M%S')
        log_file = os.path.join(log_dir, f'fixed_scan_{timestamp}.log')
        
        logging.basicConfig(
            level=logging.INFO,
            format='%(asctime)s - %(levelname)s - %(message)s',
            handlers=[logging.FileHandler(log_file), logging.StreamHandler()]
        )
        self.logger = logging.getLogger('fixed_scanner')
    
    def load_payloads(self, filename: str) -> List[Dict]:
        """Load XSS payloads"""
        try:
            data_dir = os.path.join(os.path.dirname(os.path.dirname(__file__)), 'data')
            filepath = os.path.join(data_dir, filename)
            
            if not os.path.exists(filepath):
                self.logger.error(f"Payload file not found: {filepath}")
                return []
                
            df = pd.read_csv(filepath)
            payloads = []
            
            for _, row in df.iterrows():
                payloads.append({
                    'id': row.get('payload_id', 'Unknown'),
                    'payload': row.get('payload', ''),
                    'type': row.get('context_hint', 'reflected')
                })
            
            self.logger.info(f"Loaded {len(payloads)} payloads from {filename}")
            return payloads
            
        except Exception as e:
            self.logger.error(f"Error loading payloads: {e}")
            return []
    
    def scan_with_endpoints(self, endpoints: List[str], payloads_file: str = "payloads_reflected.csv"):
        """Scan specific endpoints with XSS payloads"""
        self.logger.info(f"Starting scan of {len(endpoints)} endpoints")
        
        payloads = self.load_payloads(payloads_file)
        if not payloads:
            self.logger.error("No payloads loaded")
            return
        
        total_tests = len(endpoints) * len(payloads)
        completed_tests = 0
        
        for endpoint in endpoints:
            self.logger.info(f"Testing endpoint: {endpoint}")
            
            for payload_data in payloads:
                result = self.scanner.test_endpoint(endpoint, payload_data['payload'])
                
                if result['success']:
                    self.dataset.append({
                        'payload_id': payload_data['id'],
                        'url': result['url'],
                        'method': result['method'],
                        'injection_point': result['injection_point'],
                        'payload': result['payload'],
                        'response_time': result['response_time'],
                        'status_group': result['status_group'],
                        'html_content_length': result['html_content_length'],
                        'reflected_payload_present': result['reflected_payload_present'],
                        'is_malicious': result['is_malicious'],
                        'notes': result['notes']
                    })
                    
                    if result['is_malicious']:
                        self.logger.info(f"  [XSS] XSS DETECTED: {payload_data['id']}")
                    else:
                        status = "REFLECTED" if result['reflected_payload_present'] else "SAFE"
                        self.logger.info(f"  [TEST] {payload_data['id']} - {status}")
                else:
                    # Log failed tests but don't add to dataset
                    self.logger.error(f"  [ERROR] {payload_data['id']} - {result.get('error', 'Unknown error')}")
                
                completed_tests += 1
                if completed_tests % 5 == 0:  # Log progress every 5 tests
                    self.logger.info(f"Progress: {completed_tests}/{total_tests} tests completed")
                
                time.sleep(0.2)
    
    def save_dataset(self, filename: str = "xss_response_dataset.csv"):
        """Save the collected dataset with required columns"""
        if not self.dataset:
            self.logger.warning("No data to save")
            return
        
        output_dir = os.path.join(os.path.dirname(os.path.dirname(__file__)), 'data')
        os.makedirs(output_dir, exist_ok=True)
        output_file = os.path.join(output_dir, filename)
        
        df = pd.DataFrame(self.dataset)
        
        # Ensure all required columns are present
        required_columns = [
            'payload_id', 'url', 'method', 'injection_point', 'payload', 
            'response_time', 'status_group', 'html_content_length', 
            'reflected_payload_present', 'is_malicious', 'notes'
        ]
        
        # Add missing columns if any
        for col in required_columns:
            if col not in df.columns:
                df[col] = None
        
        # Reorder columns to match required format
        df = df[required_columns]
        
        df.to_csv(output_file, index=False)
        
        malicious_count = df['is_malicious'].sum()
        total_count = len(df)
        reflected_count = df['reflected_payload_present'].sum()
        
        self.logger.info(f"Dataset saved: {output_file}")
        self.logger.info(f"Results: {malicious_count}/{total_count} malicious samples")
        self.logger.info(f"Reflected payloads: {reflected_count}/{total_count}")
        
        # Print dataset summary
        print("\nDataset Summary:")
        print("=" * 50)
        print(f"Total samples: {total_count}")
        print(f"Malicious samples: {malicious_count}")
        print(f"Reflected payloads: {reflected_count}")
        print(f"Status groups distribution:")
        print(df['status_group'].value_counts())
        
        return df

def main():
    """Main function with discovered endpoints"""
    
    # Based on your discovery results, these endpoints exist:
    discovered_endpoints = [
        "/",                    # Home page
        "/login.php",           # Login page  
        "/about.php",           # About page
        "/index.php",           # Index page
        "/?search=test",        # Home with search parameter
        "/?q=test",             # Home with q parameter
        "/?query=test",         # Home with query parameter
        "/?id=1",               # Home with id parameter
        "/?page=1",             # Home with page parameter
    ]
    
    print("Fixed XSS Scanner - Windows Compatible")
    print("=" * 50)
    print("Target: http://localhost:8080")
    print(f"Testing {len(discovered_endpoints)} endpoints")
    print("=" * 50)
    
    collector = FixedDatasetCollector("http://localhost:8080")
    
    if discovered_endpoints:
        collector.scan_with_endpoints(discovered_endpoints)
        df = collector.save_dataset("xss_response_dataset.csv")
        
        print("\n[SUCCESS] Scan completed!")
        print(f"[INFO] Collected {len(collector.dataset)} samples")
        
        if df is not None:
            print(f"[INFO] Dataset saved with {len(df.columns)} columns:")
            for col in df.columns:
                print(f"  - {col}")
    else:
        print("[ERROR] No endpoints to test.")

if __name__ == "__main__":
    main()