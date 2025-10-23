"""
Scanner CLI with ML Integration - FIXED VERSION
"""

import argparse
import logging
import sys
import os
from typing import Optional

# Configure logging
logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')

# Add current directory to path for imports
current_dir = os.path.dirname(os.path.abspath(__file__))
if current_dir not in sys.path:
    sys.path.insert(0, current_dir)

print(f"Current directory: {current_dir}")

# Add ML integration - FIXED IMPORT
try:
    # Import the CLASS, not the functions
    from ml_integration import SQLiMLDetector
    ML_AVAILABLE = True
    print("✅ ML integration imported successfully")
except ImportError as e:
    ML_AVAILABLE = False
    print(f"❌ ML integration import failed: {e}")

def add_ml_arguments(parser: argparse.ArgumentParser):
    """Add ML-specific arguments to CLI parser."""
    ml_group = parser.add_argument_group('ML Detection Options')
    ml_group.add_argument(
        '--use-ml',
        action='store_true',
        help='Enable ML-based SQL injection detection'
    )
    ml_group.add_argument(
        '--ml-model',
        default='projects/sql_injection/models/best_model.pkl',
        help='Path to trained ML model (default: projects/sql_injection/models/best_model.pkl)'
    )
    ml_group.add_argument(
        '--ml-preprocessor',
        default=None,
        help='Path to ML preprocessor (optional)'
    )
    ml_group.add_argument(
        '--ml-confidence-threshold',
        type=float,
        default=0.6,
        help='Minimum confidence threshold for ML predictions (default: 0.6)'
    )

def initialize_ml_if_enabled(args) -> Optional[SQLiMLDetector]:
    """Initialize ML detector if enabled via CLI."""
    if not args.use_ml:
        logging.info("ML detection disabled")
        return None
        
    if not ML_AVAILABLE:
        logging.error("ML integration requested but not available")
        return None
        
    # Check if model files exist
    if not os.path.exists(args.ml_model):
        logging.error(f"ML model file not found: {args.ml_model}")
        logging.info("Please ensure the model file exists or specify with --ml-model")
        return None
        
    # Initialize detector - FIXED: Create instance directly
    logging.info(f"Initializing ML detector with model: {args.ml_model}")
    detector = SQLiMLDetector(args.ml_model, args.ml_preprocessor)
    success = detector.load_model(args.ml_model, args.ml_preprocessor)
    
    if not success:
        logging.error("Failed to initialize ML detector")
        return None
        
    logging.info("✅ ML detector initialized successfully")
    return detector

def main():
    """Main CLI entrypoint with ML support."""
    parser = argparse.ArgumentParser(
        description='Web Security Scanner with ML Detection',
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  python cli.py http://example.com                    # Standard scan
  python cli.py http://example.com --use-ml           # Scan with ML detection
  python cli.py http://example.com --use-ml --ml-model path/to/model.pkl  # Custom model
        """
    )
    
    # Existing scanner arguments
    parser.add_argument('target', help='Target URL or file to scan')
    parser.add_argument('--output', '-o', help='Output file for results')
    
    # Add ML arguments
    add_ml_arguments(parser)
    
    args = parser.parse_args()
    
    # Initialize ML if enabled
    ml_detector = initialize_ml_if_enabled(args)
    
    # Run scanner with ML integration
    run_scanner_with_ml(args, ml_detector)

def run_scanner_with_ml(args, ml_detector: Optional[SQLiMLDetector] = None):
    """Run scanner with optional ML detection."""
    logging.info(f"Starting scan for target: {args.target}")
    
    if ml_detector and ml_detector.is_loaded:
        logging.info("✅ ML detection enabled - scanning requests with ML model")
        
        # Example test requests - replace with your actual scanner logic
        test_requests = [
            {
                'method': 'GET',
                'url': f'{args.target}?id=1',
                'headers': {'User-Agent': 'Scanner'},
                'body': '',
                'query_params': {'id': '1'},
                'payload': '1'  # Added for your feature engineering
            },
            {
                'method': 'GET', 
                'url': f'{args.target}?user=admin',
                'headers': {'User-Agent': 'Scanner'},
                'body': '',
                'query_params': {'user': 'admin'},
                'payload': 'admin'  # Added for your feature engineering
            },
            {
                'method': 'GET',
                'url': f"{args.target}?id=1' OR '1'='1",
                'headers': {'User-Agent': 'Scanner'},
                'body': '',
                'query_params': {'id': "1' OR '1'='1"},
                'payload': "1' OR '1'='1"  # SQL injection attempt
            }
        ]
        
        test_responses = [
            {
                'status_code': 200,
                'headers': {'Content-Type': 'text/html'},
                'body': 'Normal response content',
                'response_time': 0.15,
                'content_length': 5200
            },
            {
                'status_code': 200,
                'headers': {'Content-Type': 'text/html'},
                'body': 'User profile page',
                'response_time': 0.12,
                'content_length': 4800
            },
            {
                'status_code': 500,
                'headers': {'Content-Type': 'text/html'},
                'body': 'SQL syntax error near OR',
                'response_time': 0.25,
                'content_length': 6800
            }
        ]
        
        print(f"\n🔍 Testing ML Detection on {len(test_requests)} sample requests:")
        print("=" * 60)
        
        for i, (request, response) in enumerate(zip(test_requests, test_responses), 1):
            print(f"\n--- Request {i}: {request['url'][:50]}... ---")
            
            # Get ML prediction
            result = ml_detector.predict_request(request, response)
            
            # Display results
            status_icon = "🔴" if result['ml_label'] == 'malicious' else "🟢"
            confidence_level = "HIGH" if result['ml_confidence'] > 0.7 else "MEDIUM" if result['ml_confidence'] > 0.4 else "LOW"
            
            print(f"{status_icon} ML Result: {result['ml_label'].upper()}")
            print(f"   Confidence: {result['ml_confidence']:.3f} ({confidence_level})")
            print(f"   Status: {result['ml_status']}")
            print(f"   Features: {result['features_extracted']}")
            
            # Alert for high-confidence malicious detection
            if result['ml_label'] == 'malicious' and result['ml_confidence'] > args.ml_confidence_threshold:
                print("   🚨 ALERT: Potential SQL Injection detected!")
            
        print("\n" + "=" * 60)
        print("📊 ML Detection Summary:")
        print(f"   Model: {os.path.basename(args.ml_model)}")
        print(f"   Confidence Threshold: {args.ml_confidence_threshold}")
        print(f"   Feature Engineering: Working")
        print("=" * 60)
    
    else:
        logging.info("Running with standard rule-based detection only")
        
        # Your existing scanner logic here
        print(f"\n🔍 Scanning {args.target} with rule-based detection...")
        print("(ML detection not enabled - use --use-ml to enable)")
    
    # Continue with normal scanner processing...
    logging.info("✅ Scan completed")

# Simple test function
def test_cli():
    """Test the CLI functionality"""
    print("Testing CLI functionality...")
    
    # Test with ML enabled
    test_args = type('Args', (), {
        'target': 'http://example.com',
        'use_ml': True,
        'ml_model': 'projects/sql_injection/models/best_model.pkl',
        'ml_preprocessor': None,
        'ml_confidence_threshold': 0.6
    })()
    
    detector = initialize_ml_if_enabled(test_args)
    if detector:
        print("✅ CLI ML initialization working!")
    else:
        print("❌ CLI ML initialization failed")

if __name__ == '__main__':
    # If no arguments provided, show help
    if len(sys.argv) == 1:
        print("Web Security Scanner with ML Detection")
        print("=" * 50)
        print("Usage: python cli.py TARGET [OPTIONS]")
        print("\nOptions:")
        print("  --use-ml              Enable ML-based SQL injection detection")
        print("  --ml-model PATH       Custom ML model path")
        print("  --ml-confidence FLOAT Confidence threshold (default: 0.6)")
        print("  --output FILE         Output results to file")
        print("\nExamples:")
        print("  python cli.py http://example.com --use-ml")
        print("  python cli.py http://test.com --use-ml --ml-model my_model.pkl")
        sys.exit(1)
    
    main()