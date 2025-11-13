import os
import sys

# Add the parent directory to Python path so we can import our modules
current_dir = os.path.dirname(os.path.abspath(__file__))
parent_dir = os.path.dirname(current_dir)
sys.path.insert(0, parent_dir)

# Now import the modules
from scripts.predict_and_report import MLEnhancedReporter
import logging

def main():
    """Main execution function"""
    logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')
    logger = logging.getLogger(__name__)
    
    logger.info("🚀 Starting WebScanPro ML-Enhanced Reporting...")
    
    try:
        # Configuration
        MODEL_PATH = os.path.join(parent_dir, "models/vuln_classifier.pkl")
        DATA_PATH = os.path.join(parent_dir, "data/processed/findings_with_ml.csv")
        
        # Initialize reporter
        reporter = MLEnhancedReporter(model_path=MODEL_PATH, data_path=DATA_PATH)
        
        # Load data and generate predictions
        reporter.load_data()
        reporter.predict_vulnerabilities()
        
        # Generate summary
        summary = reporter.generate_confidence_summary()
        print("\n" + "="*50)
        print("CONFIDENCE SUMMARY")
        print("="*50)
        print(summary)
        
        # Create visualizations
        reporter.create_visualizations()
        
        # Generate reports
        html_report = reporter.generate_html_report()
        
        # Save enhanced data
        data_output = reporter.save_enhanced_data()
        
        print(f"\n✅ AI-Enhanced Reporting Completed Successfully!")
        print(f"📁 Enhanced Dataset: {data_output}")
        print(f"🌐 HTML Report: {html_report}")
        
    except Exception as e:
        logger.error(f"❌ Error in ML reporting pipeline: {e}")
        raise

if __name__ == "__main__":
    main()