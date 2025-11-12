"""
WebScanProd - Main Execution Script for Windows
Orchestrates the complete vulnerability assessment reporting workflow
"""

import logging
import sys
import os

# Add the scripts directory to the Python path
sys.path.append(os.path.join(os.path.dirname(__file__), 'scripts'))

# Configure logging with proper encoding for Windows
try:
    # Try to use UTF-8 encoding for console output
    if sys.stdout.encoding != 'UTF-8':
        import io
        sys.stdout = io.TextIOWrapper(sys.stdout.buffer, encoding='utf-8', errors='replace')
except:
    pass

logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(levelname)s - %(message)s',
    handlers=[
        logging.FileHandler('webscanprod.log', encoding='utf-8'),
        logging.StreamHandler()
    ]
)
logger = logging.getLogger(__name__)

def main():
    """Main execution workflow"""
    logger.info("Starting WebScanProd Vulnerability Assessment System")
    
    try:
        # Import modules after path setup
        from scan_runner import ScanProcessor
        from report_generator import ReportGenerator
        
        # Step 1: Process raw scan findings
        logger.info("Step 1: Processing raw scan findings...")
        processor = ScanProcessor()
        findings = processor.load_raw_findings()
        
        if not findings:
            logger.error("No findings to process. Please check raw data files in data/raw_findings/")
            return False
        
        df = processor.save_processed_findings(findings)
        summary = processor.generate_severity_summary(df)
        
        logger.info(f"Processed {len(findings)} vulnerabilities")
        logger.info(f"Severity breakdown: {summary}")
        
        # Step 2: Generate reports
        logger.info("Step 2: Generating vulnerability reports...")
        generator = ReportGenerator()
        success = generator.generate_all_reports()
        
        if success:
            # Use ASCII alternatives for Windows compatibility
            print("\n" + "="*60)
            print("SUCCESS: WebScanProd completed successfully!")
            print("REPORTS: Check the 'reports' folder for your vulnerability reports")
            print("="*60)
            
            # List generated reports
            reports_path = os.path.join(os.path.dirname(__file__), 'reports')
            if os.path.exists(reports_path):
                print("\nGenerated Reports:")
                for file in os.listdir(reports_path):
                    if file.endswith(('.md', '.pdf', '.docx')):
                        file_path = os.path.join(reports_path, file)
                        file_size = os.path.getsize(file_path)
                        print(f"  - {file} ({file_size} bytes)")
            
            return True
        else:
            print("\n" + "="*60)
            print("ERROR: WebScanProd completed with errors!")
            print("="*60)
            return False
            
    except ImportError as e:
        logger.error(f"Import error: {e}")
        print("INFO: Run 'python install_dependencies.py' to install required packages")
        return False
    except Exception as e:
        logger.error(f"WebScanProd workflow failed: {str(e)}")
        return False

if __name__ == "__main__":
    success = main()
    
    # Keep console open on Windows
    input("\nPress Enter to exit...")
    exit(0 if success else 1)