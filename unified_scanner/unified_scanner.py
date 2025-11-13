#!/usr/bin/env python3
"""
Unified Vulnerability Scanner
Integrates XSS and SQLi detection models for comprehensive security scanning
"""

import argparse
import logging
import time
from typing import List, Dict, Any
import sys
import os

# Add current directory to path for local imports
current_dir = os.path.dirname(os.path.abspath(__file__))
if current_dir not in sys.path:
    sys.path.insert(0, current_dir)

# Import local modules
from config import LOG_CONFIG, THRESHOLDS, SCAN_OPTIONS
from inference_xss import get_xss_detector, predict_xss
from inference_sqli import get_sqli_detector, predict_sqli
from reporting import ReportGenerator
from utils import HTTPClient, PayloadGenerator, parallel_scan, setup_logging

class UnifiedScanner:
    def __init__(self, config: Dict[str, Any] = None):
        """
        Initialize the unified scanner
        
        Args:
            config: Optional configuration overrides
        """
        # Setup logging
        setup_logging()
        self.logger = logging.getLogger("unified_scanner")
        
        # Store configuration
        self.config = config or {}
        self.timeout = self.config.get('timeout', SCAN_OPTIONS['timeout'])
        self.max_payloads = self.config.get('max_payloads', SCAN_OPTIONS['max_payloads_per_type'])
        
        # Initialize components
        self.logger.info("Initializing Unified Vulnerability Scanner...")
        
        try:
            self.xss_detector = get_xss_detector()
            self.sqli_detector = get_sqli_detector()
            self.http_client = HTTPClient()
            self.payload_generator = PayloadGenerator()
            
            # Initialize reporter
            output_file = self.config.get('output_file')
            self.reporter = ReportGenerator(output_file)
            
            self.logger.info("All components initialized successfully")
            
        except Exception as e:
            self.logger.error(f"Failed to initialize scanner: {str(e)}")
            raise
    
    def scan_url(self, url: str) -> Dict[str, Any]:
        """
        Scan a single URL for both SQLi and XSS vulnerabilities
        
        Args:
            url: The URL to scan
            
        Returns:
            Dictionary with scan results
        """
        self.logger.info(f"Scanning URL: {url}")
        scan_start = time.time()
        
        result = {
            "url": url,
            "scan_timestamp": time.time(),
            "scan_duration": 0,
            "xss": {
                "is_malicious": False,
                "prob": 0.0,
                "label": "benign",
                "method": "none",
                "tested_payloads": 0,
                "vulnerable_payloads": []
            },
            "sqli": {
                "is_malicious": False,
                "prob": 0.0,
                "label": "benign",
                "method": "none",
                "tested_payloads": 0,
                "vulnerable_payloads": []
            },
            "success": True
        }
        
        try:
            # Test XSS vulnerabilities
            xss_responses = self._test_xss_vulnerabilities(url)
            result["xss"] = self._analyze_xss_responses(xss_responses)
            
            # Test SQLi vulnerabilities
            sqli_responses = self._test_sqli_vulnerabilities(url)
            result["sqli"] = self._analyze_sqli_responses(sqli_responses)
            
            result["scan_duration"] = time.time() - scan_start
            
            self.logger.info(
                f"Scan completed for {url}: "
                f"XSS={result['xss']['is_malicious']}({result['xss']['prob']:.2f}), "
                f"SQLi={result['sqli']['is_malicious']}({result['sqli']['prob']:.2f})"
            )
            
        except Exception as e:
            self.logger.error(f"Error scanning {url}: {str(e)}")
            result["success"] = False
            result["error"] = str(e)
        
        return result
    
    def _test_xss_vulnerabilities(self, url: str) -> List[Dict[str, Any]]:
        """Test URL for XSS vulnerabilities"""
        xss_payloads = self.payload_generator.get_xss_payloads()
        return parallel_scan(self.http_client, url, xss_payloads, "xss")
    
    def _test_sqli_vulnerabilities(self, url: str) -> List[Dict[str, Any]]:
        """Test URL for SQLi vulnerabilities"""
        sqli_payloads = self.payload_generator.get_sqli_payloads()
        return parallel_scan(self.http_client, url, sqli_payloads, "sqli")
    
    def _analyze_xss_responses(self, responses: List[Dict[str, Any]]) -> Dict[str, Any]:
        """Analyze XSS responses and return aggregated results"""
        if not responses:
            return {
                "is_malicious": False,
                "prob": 0.0,
                "label": "benign",
                "method": "none",
                "tested_payloads": 0,
                "vulnerable_payloads": []
            }
        
        successful_responses = [r for r in responses if r.get("success") and r.get("response_text")]
        tested_payloads = len(successful_responses)
        
        max_probability = 0.0
        vulnerable_payloads = []
        
        for response in successful_responses:
            prediction = predict_xss(response["response_text"])
            probability = prediction.get("prob", 0.0)
            
            if probability > max_probability:
                max_probability = probability
            
            if prediction.get("is_malicious", False):
                vulnerable_payloads.append({
                    "payload": response["payload"],
                    "probability": probability,
                    "method": prediction.get("method", "unknown")
                })
        
        is_malicious = max_probability >= THRESHOLDS["xss"]
        label = "malicious" if is_malicious else "benign"
        method = prediction.get("method", "rule_based") if successful_responses else "none"
        
        return {
            "is_malicious": is_malicious,
            "prob": max_probability,
            "label": label,
            "method": method,
            "tested_payloads": tested_payloads,
            "vulnerable_payloads": vulnerable_payloads
        }
    
    def _analyze_sqli_responses(self, responses: List[Dict[str, Any]]) -> Dict[str, Any]:
        """Analyze SQLi responses and return aggregated results"""
        if not responses:
            return {
                "is_malicious": False,
                "prob": 0.0,
                "label": "benign",
                "method": "none",
                "tested_payloads": 0,
                "vulnerable_payloads": []
            }
        
        successful_responses = [r for r in responses if r.get("success") and r.get("response_text")]
        tested_payloads = len(successful_responses)
        
        max_probability = 0.0
        vulnerable_payloads = []
        
        for response in successful_responses:
            prediction = predict_sqli(response["payload"], response["response_text"])
            probability = prediction.get("prob", 0.0)
            
            if probability > max_probability:
                max_probability = probability
            
            if prediction.get("is_malicious", False):
                vulnerable_payloads.append({
                    "payload": response["payload"],
                    "probability": probability,
                    "method": prediction.get("method", "unknown")
                })
        
        is_malicious = max_probability >= THRESHOLDS["sqli"]
        label = "malicious" if is_malicious else "benign"
        method = prediction.get("method", "rule_based") if successful_responses else "none"
        
        return {
            "is_malicious": is_malicious,
            "prob": max_probability,
            "label": label,
            "method": method,
            "tested_payloads": tested_payloads,
            "vulnerable_payloads": vulnerable_payloads
        }
    
    def scan_urls(self, urls: List[str]) -> List[Dict[str, Any]]:
        """
        Scan multiple URLs for vulnerabilities
        
        Args:
            urls: List of URLs to scan
            
        Returns:
            List of scan results
        """
        results = []
        total_urls = len(urls)
        
        self.logger.info(f"Starting scan of {total_urls} URLs")
        start_time = time.time()
        
        for i, url in enumerate(urls, 1):
            self.logger.info(f"Progress: {i}/{total_urls} - Scanning: {url}")
            
            result = self.scan_url(url)
            results.append(result)
            
            # Add result to reporter
            self.reporter.add_result(result)
            
            # Brief pause between URLs to be respectful
            time.sleep(1)
        
        scan_duration = time.time() - start_time
        self.logger.info(f"Scan completed in {scan_duration:.2f} seconds")
        
        return results
    
    def scan_from_file(self, file_path: str) -> List[Dict[str, Any]]:
        """
        Scan URLs from a file
        
        Args:
            file_path: Path to file containing URLs (one per line)
            
        Returns:
            List of scan results
        """
        urls = []
        
        try:
            with open(file_path, 'r') as f:
                for line in f:
                    url = line.strip()
                    if url and not url.startswith('#'):
                        urls.append(url)
            
            self.logger.info(f"Loaded {len(urls)} URLs from {file_path}")
            return self.scan_urls(urls)
            
        except Exception as e:
            self.logger.error(f"Error reading URL file: {str(e)}")
            return []
    
    def generate_report(self, format: str = "both"):
        """
        Generate vulnerability reports
        
        Args:
            format: Output format - "json", "csv", or "both"
        """
        if format in ["json", "both"]:
            json_file = self.reporter.generate_json_report()
            print(f"JSON report: {json_file}")
        
        if format in ["csv", "both"]:
            csv_file = self.reporter.generate_csv_report()
            print(f"CSV report: {csv_file}")
        
        # Always show console summary
        self.reporter.generate_console_summary()


def main():
    """Main entry point for the unified scanner"""
    parser = argparse.ArgumentParser(
        description='Unified Vulnerability Scanner - Detect XSS and SQLi vulnerabilities',
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog='''
Examples:
  python unified_scanner.py --url http://example.com
  python unified_scanner.py --url-list targets.txt --output my_scan
  python unified_scanner.py --url http://test.com --format csv
        '''
    )
    
    # Input options
    input_group = parser.add_mutually_exclusive_group(required=True)
    input_group.add_argument('--url', help='Single URL to scan')
    input_group.add_argument('--url-list', help='File containing list of URLs to scan (one per line)')
    
    # Output options
    parser.add_argument('--output', help='Output file name (without extension) for reports')
    parser.add_argument('--format', choices=['json', 'csv', 'both'], default='both',
                       help='Output format (default: both)')
    
    # Scan options
    parser.add_argument('--timeout', type=int, default=SCAN_OPTIONS['timeout'],
                       help=f'Request timeout in seconds (default: {SCAN_OPTIONS["timeout"]})')
    parser.add_argument('--max-payloads', type=int, default=SCAN_OPTIONS['max_payloads_per_type'],
                       help=f'Max payloads per vulnerability type (default: {SCAN_OPTIONS["max_payloads_per_type"]})')
    
    args = parser.parse_args()
    
    # Prepare configuration
    config = {
        'timeout': args.timeout,
        'max_payloads': args.max_payloads
    }
    
    if args.output:
        config['output_file'] = args.output
    
    try:
        # Initialize scanner
        scanner = UnifiedScanner(config)
        
        # Run scan
        if args.url:
            scanner.scan_urls([args.url])
        elif args.url_list:
            scanner.scan_from_file(args.url_list)
        
        # Generate reports
        scanner.generate_report(args.format)
        
    except KeyboardInterrupt:
        print("\nScan interrupted by user")
        sys.exit(1)
    except Exception as e:
        print(f"Scanner error: {str(e)}")
        sys.exit(1)


if __name__ == "__main__":
    main()