"""
Configuration for Unified Vulnerability Scanner
"""

import os
from datetime import datetime

# Base paths
BASE_DIR = os.path.dirname(os.path.abspath(__file__))
PROJECT_ROOT = os.path.dirname(os.path.dirname(BASE_DIR))

# Model paths - using relative paths from unified_scanner directory
MODEL_PATHS = {
    "xss": {
        "model": os.path.join(PROJECT_ROOT, "xss_detection/models/best_model.pt"),
        "tokenizer": os.path.join(PROJECT_ROOT, "xss_detection/models/tokenizer.json")
    },
    "sqli": {
        "model": os.path.join(PROJECT_ROOT, "sql_injection/models/best_model.pkl"),
        "vectorizer": os.path.join(PROJECT_ROOT, "sql_injection/models/vectorizer.pkl")
    }
}

# Detection thresholds
THRESHOLDS = {
    "xss": 0.75,
    "sqli": 0.70
}

# Scan options
SCAN_OPTIONS = {
    "timeout": 10,
    "max_payloads_per_type": 20,
    "max_workers": 3,
    "retries": 2,
    "user_agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36"
}

# Output paths
OUTPUT_DIR = os.path.join(PROJECT_ROOT, "outputs")
SCAN_REPORTS_DIR = os.path.join(OUTPUT_DIR, "scan_reports")
LOGS_DIR = os.path.join(OUTPUT_DIR, "logs")

# Create directories if they don't exist
for directory in [OUTPUT_DIR, SCAN_REPORTS_DIR, LOGS_DIR]:
    os.makedirs(directory, exist_ok=True)

# Logging configuration
LOG_FILE = os.path.join(LOGS_DIR, f"scanner_{datetime.now().strftime('%Y%m%d_%H%M%S')}.log")

LOG_CONFIG = {
    "version": 1,
    "disable_existing_loggers": False,
    "formatters": {
        "standard": {
            "format": "%(asctime)s [%(levelname)s] %(name)s: %(message)s"
        },
        "detailed": {
            "format": "%(asctime)s [%(levelname)s] %(name)s:%(lineno)d: %(message)s"
        }
    },
    "handlers": {
        "file": {
            "level": "INFO",
            "class": "logging.FileHandler",
            "filename": LOG_FILE,
            "formatter": "standard"
        },
        "console": {
            "level": "INFO",
            "class": "logging.StreamHandler",
            "formatter": "standard"
        }
    },
    "loggers": {
        "unified_scanner": {
            "handlers": ["file", "console"],
            "level": "INFO",
            "propagate": False
        },
        "inference": {
            "handlers": ["file", "console"],
            "level": "INFO",
            "propagate": False
        }
    }
}

def get_report_filename():
    """Generate report filename with timestamp"""
    return os.path.join(SCAN_REPORTS_DIR, f"scan_report_{datetime.now().strftime('%Y%m%d_%H%M%S')}.json")