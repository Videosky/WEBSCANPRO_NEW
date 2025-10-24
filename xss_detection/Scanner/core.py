"""
Core scanning functionality for XSS detection
"""

import requests
import time
import re
import urllib.parse
from typing import Dict, List, Optional, Tuple
import logging

class XSSScanner:
    def __init__(self, base_url: str, timeout: int = 10):
        self.base_url = base_url.rstrip('/')
        self.timeout = timeout
        self.session = requests.Session()
        self.session.headers.update({
            'User-Agent': 'XSS-Scanner/1.0',
            'Content-Type': 'application/x-www-form-urlencoded'
        })
        self.logger = logging.getLogger('xss_scanner')
        
    def send_payload(self, url: str, method: str = 'GET', 
                    injection_point: str = 'query',
                    payload: str = '', 
                    params: Dict = None,
                    data: Dict = None) -> Dict:
        """
        Send payload to target and capture response
        """
        start_time = time.time()
        
        try:
            # Prepare request based on injection point
            if injection_point == 'query':
                # For query injection, append payload as parameter
                if '?' in url:
                    full_url = f"{url}&{payload}"
                else:
                    full_url = f"{url}?{payload}"
                self.logger.debug(f"Sending GET to: {full_url}")
                response = self.session.request(method, full_url, timeout=self.timeout)
            elif injection_point == 'body':
                if data is None:
                    data = {}
                # Inject into first available field or use default
                if data:
                    first_key = list(data.keys())[0]
                    data[first_key] = payload
                else:
                    data = {'input': payload}
                self.logger.debug(f"Sending POST to: {url} with data: {data}")
                response = self.session.request(method, url, data=data, timeout=self.timeout)
            else:
                response = self.session.request(method, url, timeout=self.timeout)
            
            response_time = time.time() - start_time
            
            return {
                'success': True,
                'status_code': response.status_code,
                'headers': dict(response.headers),
                'content': response.text,
                'response_time': response_time,
                'url': response.url
            }
            
        except requests.exceptions.ConnectTimeout:
            error_msg = f"Connection timeout to {url}"
            self.logger.error(error_msg)
            return {
                'success': False,
                'error': error_msg,
                'response_time': time.time() - start_time
            }
        except requests.exceptions.ConnectionError:
            error_msg = f"Connection error to {url}. Is the lab app running?"
            self.logger.error(error_msg)
            return {
                'success': False,
                'error': error_msg,
                'response_time': time.time() - start_time
            }
        except requests.RequestException as e:
            error_msg = f"Request failed: {e}"
            self.logger.error(error_msg)
            return {
                'success': False,
                'error': str(e),
                'response_time': time.time() - start_time
            }
    
    def analyze_response(self, response_content: str, original_payload: str) -> Dict:
        """
        Analyze response for XSS indicators
        """
        # Check if payload is reflected
        payload_reflected = original_payload in response_content
        
        # Check for unescaped payload
        unescaped_indicators = self._check_unescaped_payload(response_content, original_payload)
        
        # Check for script execution patterns
        script_indicators = self._check_script_indicators(response_content)
        
        # Check for error messages
        error_detected = self._check_error_messages(response_content)
        
        # Determine if malicious
        is_malicious = self._determine_malicious(
            payload_reflected, unescaped_indicators, script_indicators
        )
        
        return {
            'reflected_payload_present': payload_reflected,
            'unescaped_indicators': unescaped_indicators,
            'script_indicators': script_indicators,
            'error_message_flag': error_detected,
            'is_malicious': is_malicious,
            'html_content_length': len(response_content)
        }
    
    def _check_unescaped_payload(self, content: str, payload: str) -> Dict:
        """Check if payload appears unescaped in response"""
        # Check for HTML entity encoding
        html_encoded = any(
            entity in content for entity in ['&lt;', '&gt;', '&quot;', '&#x']
        )
        
        # Check for URL encoding
        url_decoded = urllib.parse.unquote(payload) in content if '%' in payload else False
        
        # Check for direct reflection
        direct_reflection = payload in content
        
        # Check for partial reflection of dangerous patterns
        dangerous_patterns = ['<script', 'onerror=', 'javascript:', 'onload=']
        dangerous_reflection = any(pattern in content for pattern in dangerous_patterns)
        
        return {
            'direct_reflection': direct_reflection,
            'html_encoded': html_encoded,
            'url_decoded': url_decoded,
            'dangerous_reflection': dangerous_reflection
        }
    
    def _check_script_indicators(self, content: str) -> List[str]:
        """Check for script execution indicators"""
        indicators = []
        
        # Script tags
        if re.search(r'<script[^>]*>', content, re.IGNORECASE):
            indicators.append('script_tag_present')
        
        # Event handlers
        event_patterns = [
            r'onload\s*=', r'onerror\s*=', r'onclick\s*=',
            r'onmouseover\s*=', r'onfocus\s*='
        ]
        for pattern in event_patterns:
            if re.search(pattern, content, re.IGNORECASE):
                handler_name = pattern.split('\\s*=')[0].replace('r\\', '')
                indicators.append(f'event_handler_{handler_name}')
        
        # JavaScript URLs
        if 'javascript:' in content.lower():
            indicators.append('javascript_url')
            
        # SVG elements with events
        if '<svg' in content.lower() and 'onload' in content.lower():
            indicators.append('svg_onload')
            
        return indicators
    
    def _check_error_messages(self, content: str) -> bool:
        """Check for error messages in response"""
        error_indicators = [
            'error', 'exception', 'invalid', 'not found',
            'failed', 'undefined', 'syntax error'
        ]
        content_lower = content.lower()
        return any(indicator in content_lower for indicator in error_indicators)
    
    def _determine_malicious(self, reflected: bool, unescaped: Dict, scripts: List[str]) -> bool:
        """Determine if response indicates XSS vulnerability"""
        # If payload is reflected and has script indicators
        if reflected and scripts:
            return True
        
        # If dangerous patterns are reflected without encoding
        if unescaped.get('dangerous_reflection') and reflected:
            return True
        
        # If payload is directly reflected without encoding and contains script patterns
        if (unescaped.get('direct_reflection') and 
            not unescaped.get('html_encoded') and
            any('script' in script or 'javascript' in script for script in scripts)):
            return True
            
        # Multiple strong indicators
        strong_indicators = len([ind for ind in scripts if 'script' in ind or 'javascript' in ind or 'onload' in ind])
        if strong_indicators >= 2:
            return True
            
        return False