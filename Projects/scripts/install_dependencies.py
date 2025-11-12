"""
WebScanProd - Dependency Installer for Windows
Installs all required packages for the vulnerability reporting system
"""

import subprocess
import sys
import logging

# Configure logging
logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')
logger = logging.getLogger(__name__)

def install_package(package):
    """Install a Python package using pip"""
    try:
        logger.info(f"Installing {package}...")
        subprocess.check_call([sys.executable, "-m", "pip", "install", package])
        logger.info(f"Successfully installed {package}")
        return True
    except subprocess.CalledProcessError as e:
        logger.error(f"Failed to install {package}: {e}")
        return False

def main():
    """Install all required dependencies"""
    packages = [
        "pandas>=1.5.0",
        "reportlab>=3.6.0", 
        "python-docx>=0.8.11",
        "openpyxl>=3.0.0",
        "lxml>=4.9.0"
    ]
    
    logger.info("Starting WebScanProd dependency installation...")
    
    success_count = 0
    for package in packages:
        if install_package(package):
            success_count += 1
    
    logger.info(f"Installation complete: {success_count}/{len(packages)} packages installed successfully")
    
    if success_count == len(packages):
        logger.info("🎉 All dependencies installed successfully! WebScanProd is ready to use.")
    else:
        logger.warning("⚠️ Some dependencies failed to install. Basic functionality may still work.")
        logger.info("Markdown reports will work with just pandas installed.")
        logger.info("PDF reports require reportlab.")
        logger.info("DOCX reports require python-docx.")

if __name__ == "__main__":
    main()