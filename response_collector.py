import requests
import time
import os
import pandas as pd
from urllib.parse import urljoin, urlencode
from config import TARGET_CONFIG, REQUEST_CONFIG, ERROR_KEYWORDS, LOG_DIR

class ResponseCollector:
    def __init__(self, session=None):
        self.base_url = TARGET_CONFIG['base_url']
        self.session = session or requests.Session()
        self.session.headers.update(REQUEST_CONFIG['headers'])
        self.timeout = REQUEST_CONFIG['timeout']
        self.request_count = 0
        
    def login(self):
        """Login to DVWA"""
        try:
            login_data = {
                'username': TARGET_CONFIG['credentials']['username'],
                'password': TARGET_CONFIG['credentials']['password'],
                'Login': 'Login'
            }
            
            login_url = urljoin(self.base_url, TARGET_CONFIG['login_url'])
            print(f"Attempting login to {login_url}")
            
            response = self.session.post(login_url, data=login_data, timeout=self.timeout)
            
            # Check if login was successful
            if response.status_code == 200:
                if 'Login failed' in response.text:
                    print("Login failed: Invalid credentials")
                    return False
                else:
                    print("Login successful")
                    return True
            else:
                print(f"Login failed with status code: {response.status_code}")
                return False
                
        except Exception as e:
            print(f"Login error: {e}")
            return False
    
    def send_request(self, url, method='GET', param_name=None, input_value=None):
        """Send HTTP request and collect response metrics"""
        full_url = urljoin(self.base_url, url)
        self.request_count += 1
        
        start_time = time.time()
        try:
            if method.upper() == 'GET':
                params = {param_name: input_value} if param_name else {}
                response = self.session.get(
                    full_url, 
                    params=params,
                    timeout=self.timeout,
                    allow_redirects=True
                )
            else:  # POST
                data = {param_name: input_value} if param_name else {}
                response = self.session.post(
                    full_url, 
                    data=data,
                    timeout=self.timeout,
                    allow_redirects=True
                )
            response_time = (time.time() - start_time) * 1000  # Convert to ms
        except requests.exceptions.RequestException as e:
            response_time = (time.time() - start_time) * 1000
            return self._create_error_response(str(e), response_time)
        
        return self._process_response(response, response_time)
    
    def _process_response(self, response, response_time):
        """Process response and extract features"""
        # Check for error messages in response body
        error_flag = self._check_error_in_response(response.text)
        
        # Get content length
        content_length = len(response.text)
        
        # Save response body if needed
        response_body_path = self._save_response_body(response.text) if content_length > 0 else None
        
        return {
            'response_status': response.status_code,
            'response_time': round(response_time, 2),
            'html_content_length': content_length,
            'error_message_flag': 1 if error_flag else 0,
            'response_body_path': response_body_path,
            'success': True
        }
    
    def _check_error_in_response(self, response_text):
        """Check if response contains error keywords"""
        if not response_text:
            return False
            
        response_lower = response_text.lower()
        return any(keyword in response_lower for keyword in ERROR_KEYWORDS)
    
    def _save_response_body(self, response_text):
        """Save response body to file and return path"""
        if not response_text.strip():
            return None
            
        timestamp = int(time.time())
        filename = f"response_{timestamp}_{self.request_count}.html"
        filepath = os.path.join(LOG_DIR, filename)
        
        try:
            with open(filepath, 'w', encoding='utf-8', errors='ignore') as f:
                f.write(response_text)
            return filepath
        except Exception as e:
            print(f"Error saving response body: {e}")
            return None
    
    def _create_error_response(self, error_message, response_time):
        """Create response data for failed requests"""
        print(f"Request error: {error_message}")
        return {
            'response_status': 0,  # Custom code for request failure
            'response_time': round(response_time, 2),
            'html_content_length': 0,
            'error_message_flag': 1,
            'response_body_path': None,
            'success': False,
            'error_message': error_message
        }