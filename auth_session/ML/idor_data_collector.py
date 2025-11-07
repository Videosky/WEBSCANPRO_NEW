# projects/auth_session/ML/idor_data_collector.py

import requests
import pandas as pd
import json
import time
import hashlib
import random
from datetime import datetime
from pathlib import Path
import logging
from typing import Dict, List, Optional, Tuple
import re

class IDORDataCollector:
    """
    IDOR Vulnerability Data Collection System
    Collects and labels parameterized web requests for access control ML training
    """
    
    def __init__(self, base_url: str = "http://localhost:8080"):
        self.base_url = base_url
        self.raw_data_dir = Path("projects/auth_session/data/raw_requests")
        self.processed_data_dir = Path("projects/auth_session/data")
        self.reports_dir = Path("projects/auth_session/docs")
        
        # Setup directories
        self.raw_data_dir.mkdir(parents=True, exist_ok=True)
        self.processed_data_dir.mkdir(parents=True, exist_ok=True)
        self.reports_dir.mkdir(parents=True, exist_ok=True)
        
        # Setup logging
        self._setup_logging()
        
        # Test users configuration
        self.test_users = {
            'user_a': {
                'user_id': '101',
                'auth_token': 'token_user_a_12345',
                'resources': ['101', '103', '105']  # Resources owned by user A
            },
            'user_b': {
                'user_id': '102', 
                'auth_token': 'token_user_b_67890',
                'resources': ['102', '104', '106']  # Resources owned by user B
            }
        }
        
        # Target endpoints to test
        self.target_endpoints = [
            {
                'endpoint': '/user/profile',
                'method': 'GET',
                'parameter': 'id',
                'sensitive_fields': ['email', 'phone', 'address', 'ssn']
            },
            {
                'endpoint': '/api/orders',
                'method': 'GET', 
                'parameter': 'order_id',
                'sensitive_fields': ['total_amount', 'credit_card', 'shipping_address']
            },
            {
                'endpoint': '/documents/view',
                'method': 'GET',
                'parameter': 'doc_id',
                'sensitive_fields': ['content', 'author', 'confidential_notes']
            },
            {
                'endpoint': '/api/invoices',
                'method': 'GET',
                'parameter': 'invoice_id',
                'sensitive_fields': ['amount', 'client_info', 'tax_id']
            }
        ]
    
    def _setup_logging(self):
        """Setup logging configuration"""
        log_file = self.raw_data_dir / "idor_collection.log"
        
        logging.basicConfig(
            level=logging.INFO,
            format='%(asctime)s - %(name)s - %(levelname)s - %(message)s',
            handlers=[
                logging.FileHandler(log_file),
                logging.StreamHandler()
            ]
        )
        self.logger = logging.getLogger('idor_collector')
    
    def make_authenticated_request(self, endpoint: str, method: str, 
                                 params: Dict, auth_token: str) -> Dict:
        """
        Make authenticated HTTP request and capture response details
        """
        url = f"{self.base_url}{endpoint}"
        headers = {
            'Authorization': f'Bearer {auth_token}',
            'User-Agent': 'IDOR-Testing-Scanner/1.0',
            'Content-Type': 'application/json'
        }
        
        request_id = hashlib.md5(f"{url}{params}{datetime.now().isoformat()}".encode()).hexdigest()[:8]
        
        try:
            start_time = time.time()
            
            if method.upper() == 'GET':
                response = requests.get(url, params=params, headers=headers, timeout=10)
            elif method.upper() == 'POST':
                response = requests.post(url, json=params, headers=headers, timeout=10)
            else:
                response = requests.request(method, url, json=params, headers=headers, timeout=10)
            
            response_time = (time.time() - start_time) * 1000  # Convert to ms
            
            # Capture response details
            response_data = {
                'request_id': request_id,
                'timestamp': datetime.now().isoformat(),
                'url': url,
                'method': method,
                'parameters': params,
                'status_code': response.status_code,
                'response_time_ms': response_time,
                'response_length': len(response.text),
                'response_headers': dict(response.headers),
                'response_body': response.text[:5000],  # Limit body size
                'error': None
            }
            
            # Save raw request/response
            self._save_raw_request(response_data)
            
            return response_data
            
        except requests.RequestException as e:
            self.logger.error(f"Request failed: {e}")
            return {
                'request_id': request_id,
                'timestamp': datetime.now().isoformat(),
                'url': url,
                'method': method,
                'parameters': params,
                'status_code': 0,
                'response_time_ms': 0,
                'response_length': 0,
                'response_headers': {},
                'response_body': '',
                'error': str(e)
            }
    
    def _save_raw_request(self, request_data: Dict):
        """Save raw request/response data to JSON file"""
        filename = f"request_{request_data['request_id']}.json"
        filepath = self.raw_data_dir / filename
        
        with open(filepath, 'w', encoding='utf-8') as f:
            json.dump(request_data, f, indent=2, ensure_ascii=False)
    
    def analyze_response(self, response_data: Dict, endpoint_config: Dict, 
                        user_id: str, target_id: str) -> Dict:
        """
        Analyze response to determine if unauthorized access occurred
        """
        # Default analysis
        analysis = {
            'sensitive_data_found': False,
            'unauthorized_indicator': False,
            'access_granted': False,
            'error_occurred': False
        }
        
        # Check for errors
        if response_data['error'] or response_data['status_code'] == 0:
            analysis['error_occurred'] = True
            return analysis
        
        # Status code analysis
        status = response_data['status_code']
        if status == 200:
            analysis['access_granted'] = True
        elif status in [401, 403, 404]:
            analysis['unauthorized_indicator'] = True
            return analysis
        
        # Check for sensitive data in response
        response_text = response_data['response_body'].lower()
        sensitive_fields = endpoint_config.get('sensitive_fields', [])
        
        for field in sensitive_fields:
            if field.lower() in response_text:
                analysis['sensitive_data_found'] = True
                break
        
        # Additional unauthorized access indicators
        unauthorized_indicators = [
            'access denied', 'unauthorized', 'forbidden', 'not authorized',
            'permission denied', 'login required', '403', '401'
        ]
        
        for indicator in unauthorized_indicators:
            if indicator in response_text.lower():
                analysis['unauthorized_indicator'] = True
                break
        
        # Check if user accessed someone else's data
        # This is the core IDOR detection logic
        if user_id != target_id and analysis['access_granted']:
            if analysis['sensitive_data_found'] or response_data['response_length'] > 100:
                analysis['unauthorized_indicator'] = True
        
        return analysis
    
    def test_authorized_access(self):
        """Test authorized access scenarios (user accessing own resources)"""
        self.logger.info("Testing authorized access scenarios...")
        
        authorized_requests = []
        
        for user_key, user_data in self.test_users.items():
            for endpoint_config in self.target_endpoints:
                for resource_id in user_data['resources']:
                    # User accessing their own resource
                    params = {endpoint_config['parameter']: resource_id}
                    
                    response = self.make_authenticated_request(
                        endpoint_config['endpoint'],
                        endpoint_config['method'],
                        params,
                        user_data['auth_token']
                    )
                    
                    analysis = self.analyze_response(
                        response, endpoint_config, 
                        user_data['user_id'], resource_id
                    )
                    
                    # Label as authorized (0)
                    request_record = self._create_dataset_record(
                        response, endpoint_config, user_data['user_id'], 
                        resource_id, analysis, is_unauthorized=0
                    )
                    
                    authorized_requests.append(request_record)
                    
                    self.logger.info(f"Authorized: {user_key} -> {resource_id} | Status: {response['status_code']}")
        
        return authorized_requests
    
    def test_unauthorized_access(self):
        """Test unauthorized access scenarios (user accessing others' resources)"""
        self.logger.info("Testing unauthorized access scenarios...")
        
        unauthorized_requests = []
        
        for user_key, user_data in self.test_users.items():
            other_user_key = 'user_b' if user_key == 'user_a' else 'user_a'
            other_user_resources = self.test_users[other_user_key]['resources']
            
            for endpoint_config in self.target_endpoints:
                for resource_id in other_user_resources[:2]:  # Test 2 resources per endpoint
                    # User accessing someone else's resource
                    params = {endpoint_config['parameter']: resource_id}
                    
                    response = self.make_authenticated_request(
                        endpoint_config['endpoint'],
                        endpoint_config['method'],
                        params,
                        user_data['auth_token']
                    )
                    
                    analysis = self.analyze_response(
                        response, endpoint_config,
                        user_data['user_id'], resource_id
                    )
                    
                    # Determine if this is actually unauthorized access
                    is_unauthorized = 1 if (analysis['access_granted'] and 
                                          analysis['sensitive_data_found']) else 0
                    
                    request_record = self._create_dataset_record(
                        response, endpoint_config, user_data['user_id'],
                        resource_id, analysis, is_unauthorized
                    )
                    
                    unauthorized_requests.append(request_record)
                    
                    status = "UNAUTHORIZED" if is_unauthorized else "BLOCKED"
                    self.logger.info(f"Cross-user: {user_key} -> {resource_id} | Status: {status}")
        
        return unauthorized_requests
    
    def test_edge_cases(self):
        """Test edge cases and invalid parameters"""
        self.logger.info("Testing edge cases...")
        
        edge_cases = []
        
        # Test invalid resource IDs
        invalid_ids = ['0', '-1', '999999', 'null', 'undefined', 'admin', "' OR '1'='1"]
        
        for user_key, user_data in self.test_users.items():
            for endpoint_config in self.target_endpoints[:2]:  # Test first 2 endpoints
                for invalid_id in invalid_ids[:3]:  # Test 3 invalid IDs
                    params = {endpoint_config['parameter']: invalid_id}
                    
                    response = self.make_authenticated_request(
                        endpoint_config['endpoint'],
                        endpoint_config['method'],
                        params,
                        user_data['auth_token']
                    )
                    
                    analysis = self.analyze_response(
                        response, endpoint_config,
                        user_data['user_id'], invalid_id
                    )
                    
                    # Edge cases are typically unauthorized
                    is_unauthorized = 1
                    
                    request_record = self._create_dataset_record(
                        response, endpoint_config, user_data['user_id'],
                        invalid_id, analysis, is_unauthorized
                    )
                    
                    edge_cases.append(request_record)
        
        return edge_cases
    
    def _create_dataset_record(self, response: Dict, endpoint_config: Dict,
                             user_id: str, target_id: str, analysis: Dict,
                             is_unauthorized: int) -> Dict:
        """Create standardized dataset record"""
        return {
            'request_id': response['request_id'],
            'timestamp': response['timestamp'],
            'endpoint': endpoint_config['endpoint'],
            'method': endpoint_config['method'],
            'parameter': endpoint_config['parameter'],
            'parameter_value': target_id,
            'user_id': user_id,
            'target_id': target_id,
            'status_code': response['status_code'],
            'response_time_ms': response['response_time_ms'],
            'response_length': response['response_length'],
            'sensitive_data_found': int(analysis['sensitive_data_found']),
            'access_granted': int(analysis['access_granted']),
            'unauthorized_indicator': int(analysis['unauthorized_indicator']),
            'error_occurred': int(analysis['error_occurred']),
            'is_unauthorized': is_unauthorized,
            'raw_file': f"request_{response['request_id']}.json"
        }
    
    def generate_synthetic_data(self, num_samples: int = 100):
        """Generate synthetic IDOR test data for offline development"""
        self.logger.info(f"Generating {num_samples} synthetic IDOR test records...")
        
        synthetic_data = []
        endpoints = ['/user/profile', '/api/orders', '/documents/view', '/api/invoices']
        methods = ['GET', 'POST']
        status_codes = [200, 401, 403, 404, 500]
        user_ids = ['101', '102', '103', '104']
        
        for i in range(num_samples):
            endpoint = random.choice(endpoints)
            method = random.choice(methods)
            user_id = random.choice(user_ids)
            target_id = random.choice(user_ids)
            
            # Determine if this should be unauthorized
            is_unauthorized = 1 if user_id != target_id and random.random() > 0.3 else 0
            
            # Simulate response patterns
            if is_unauthorized:
                status_code = random.choice([200, 403, 404])  # Sometimes unauthorized access works!
                sensitive_data = 1 if status_code == 200 and random.random() > 0.7 else 0
            else:
                status_code = 200 if random.random() > 0.1 else random.choice([401, 500])
                sensitive_data = 1 if status_code == 200 else 0
            
            record = {
                'request_id': f"synth_{i:06d}",
                'timestamp': datetime.now().isoformat(),
                'endpoint': endpoint,
                'method': method,
                'parameter': 'id',
                'parameter_value': target_id,
                'user_id': user_id,
                'target_id': target_id,
                'status_code': status_code,
                'response_time_ms': random.randint(50, 500),
                'response_length': random.randint(100, 5000),
                'sensitive_data_found': sensitive_data,
                'access_granted': 1 if status_code == 200 else 0,
                'unauthorized_indicator': 1 if status_code in [401, 403] else 0,
                'error_occurred': 1 if status_code >= 500 else 0,
                'is_unauthorized': is_unauthorized,
                'raw_file': 'synthetic'
            }
            
            synthetic_data.append(record)
        
        return synthetic_data
    
    def create_idor_dataset(self, use_synthetic: bool = False):
        """Create the complete IDOR dataset"""
        self.logger.info("Creating IDOR dataset...")
        
        if use_synthetic:
            # Use synthetic data for testing
            authorized_data = self.generate_synthetic_data(50)
            unauthorized_data = self.generate_synthetic_data(50)
            edge_cases = self.generate_synthetic_data(20)
        else:
            # Collect real data
            authorized_data = self.test_authorized_access()
            unauthorized_data = self.test_unauthorized_access()
            edge_cases = self.test_edge_cases()
        
        # Combine all data
        all_data = authorized_data + unauthorized_data + edge_cases
        
        # Create DataFrame
        df = pd.DataFrame(all_data)
        
        # Clean and normalize data
        df_clean = self.clean_dataset(df)
        
        # Save dataset
        dataset_path = self.processed_data_dir / "idor_dataset.csv"
        df_clean.to_csv(dataset_path, index=False)
        
        self.logger.info(f"Dataset saved: {dataset_path}")
        self.logger.info(f"Total records: {len(df_clean)}")
        self.logger.info(f"Authorized: {len(authorized_data)}")
        self.logger.info(f"Unauthorized: {len(unauthorized_data)}")
        self.logger.info(f"Edge cases: {len(edge_cases)}")
        
        # Generate summary report
        self.generate_summary_report(df_clean)
        
        return df_clean
    
    def clean_dataset(self, df: pd.DataFrame) -> pd.DataFrame:
        """Clean and normalize the dataset"""
        # Remove duplicates
        df_clean = df.drop_duplicates(subset=['request_id'])
        
        # Remove incomplete records
        df_clean = df_clean.dropna()
        
        # Standardize endpoint patterns
        df_clean['endpoint_normalized'] = df_clean['endpoint'].apply(
            lambda x: re.sub(r'\d+', '<ID>', x)  # Replace numbers with <ID>
        )
        
        # Encode categorical variables
        df_clean['method_encoded'] = df_clean['method'].astype('category').cat.codes
        df_clean['endpoint_encoded'] = df_clean['endpoint_normalized'].astype('category').cat.codes
        
        # Ensure correct data types
        df_clean['is_unauthorized'] = df_clean['is_unauthorized'].astype(int)
        df_clean['sensitive_data_found'] = df_clean['sensitive_data_found'].astype(int)
        df_clean['access_granted'] = df_clean['access_granted'].astype(int)
        
        return df_clean
    
    def generate_summary_report(self, df: pd.DataFrame):
        """Generate comprehensive dataset summary report"""
        report_path = self.reports_dir / "idor_data_summary.md"
        
        # Calculate statistics
        total_records = len(df)
        authorized_count = len(df[df['is_unauthorized'] == 0])
        unauthorized_count = len(df[df['is_unauthorized'] == 1])
        
        status_distribution = df['status_code'].value_counts()
        endpoint_distribution = df['endpoint'].value_counts()
        method_distribution = df['method'].value_counts()
        
        # Detection accuracy (for synthetic data analysis)
        true_positives = len(df[(df['is_unauthorized'] == 1) & (df['access_granted'] == 1)])
        false_negatives = len(df[(df['is_unauthorized'] == 1) & (df['access_granted'] == 0)])
        
        report_content = f"""
# IDOR Dataset Summary Report

## 📊 Dataset Overview
**Generated**: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}
**Total Records**: {total_records}
**Authorized Access**: {authorized_count} ({authorized_count/total_records*100:.1f}%)
**Unauthorized Access**: {unauthorized_count} ({unauthorized_count/total_records*100:.1f}%)

## 🎯 Data Distribution

### HTTP Status Codes
| Status Code | Count | Percentage |
|-------------|-------|------------|
"""
        for status, count in status_distribution.items():
            percentage = (count / total_records) * 100
            report_content += f"| {status} | {count} | {percentage:.1f}% |\n"

        report_content += """
### Endpoints Tested
| Endpoint | Count | Percentage |
|----------|-------|------------|
"""
        for endpoint, count in endpoint_distribution.items():
            percentage = (count / total_records) * 100
            report_content += f"| {endpoint} | {count} | {percentage:.1f}% |\n"

        report_content += f"""
## 🔍 Security Analysis

### Access Patterns
- **Sensitive Data Exposed**: {df['sensitive_data_found'].sum()} times
- **Unauthorized Indicators**: {df['unauthorized_indicator'].sum()} detected
- **Errors Occurred**: {df['error_occurred'].sum()} requests

### Detection Metrics
- **True Positives**: {true_positives} (Unauthorized access that worked)
- **False Negatives**: {false_negatives} (Unauthorized access that was blocked)

## 📈 Feature Statistics

### Response Characteristics
- **Average Response Time**: {df['response_time_ms'].mean():.2f} ms
- **Average Response Length**: {df['response_length'].mean():.2f} bytes
- **Max Response Length**: {df['response_length'].max()} bytes

### Parameter Analysis
- **Unique Parameters**: {df['parameter'].nunique()}
- **Unique Parameter Values**: {df['parameter_value'].nunique()}

## ✅ Data Quality

### Completeness
- **Missing Values**: {df.isnull().sum().sum()} total
- **Duplicate Records**: {len(df) - len(df.drop_duplicates(subset=['request_id']))} removed

### Normalization
- **Endpoints Normalized**: {df['endpoint_normalized'].nunique()} unique patterns
- **Methods Encoded**: {df['method_encoded'].nunique()} categories

## 🚀 Recommendations for ML Training

1. **Feature Selection**: Use response_length, status_code, sensitive_data_found as key features
2. **Class Balance**: {'' if unauthorized_count/authorized_count > 0.3 else 'Consider oversampling unauthorized cases'}
3. **Validation Split**: Use stratified sampling to maintain class distribution
4. **Model Choice**: Start with Random Forest or Neural Networks for pattern recognition

---
*Report generated automatically by IDOR Data Collector*
"""
        
        with open(report_path, 'w', encoding='utf-8') as f:
            f.write(report_content)
        
        self.logger.info(f"Summary report saved: {report_path}")

def main():
    """Main execution function"""
    print("🚀 IDOR Data Collection System")
    print("=" * 50)
    
    # Initialize collector (use a test URL or synthetic data)
    collector = IDORDataCollector(base_url="http://test-api.example.com")
    
    # Create dataset (use synthetic data for demonstration)
    print("\n📊 Generating IDOR dataset...")
    dataset = collector.create_idor_dataset(use_synthetic=True)
    
    print(f"\n✅ Dataset created with {len(dataset)} records")
    print(f"📍 Saved to: projects/auth_session/data/idor_dataset.csv")
    print(f"📋 Summary: projects/auth_session/docs/idor_data_summary.md")
    print(f"📁 Raw logs: projects/auth_session/data/raw_requests/")
    
    # Show quick stats
    authorized = len(dataset[dataset['is_unauthorized'] == 0])
    unauthorized = len(dataset[dataset['is_unauthorized'] == 1])
    print(f"\n📈 Distribution: {authorized} authorized, {unauthorized} unauthorized")

if __name__ == "__main__":
    main()