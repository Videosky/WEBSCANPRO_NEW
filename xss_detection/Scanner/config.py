"""
Scanner configuration for XSS detection
"""

# Lab application configuration
LAB_CONFIG = {
    'base_url': 'http://localhost:3000',  # Juice Shop default
    'timeout': 10,
    'max_retries': 3
}

# Test endpoints for different contexts
TEST_ENDPOINTS = {
    'reflected': {
        'search': '/rest/products/search?q={payload}',
        'contact': '/api/Feedbacks',
        'login': '/rest/user/login'
    },
    'stored': {
        'comment': '/api/Comments',
        'feedback': '/api/Feedbacks',
        'product_review': '/api/ProductReviews'
    }
}

# Response analysis patterns
XSS_INDICATORS = {
    'script_tags': ['<script', '</script>'],
    'event_handlers': ['onerror=', 'onload=', 'onclick=', 'onmouseover='],
    'javascript_handlers': ['javascript:', 'javascrip&t:'],
    'alert_patterns': ['alert(', 'alert&#40;', 'alert%28']
}

# Safety patterns to avoid
SAFETY_PATTERNS = {
    'dangerous_domains': ['.com', '.org', '.net'],  # External domains in payloads
    'sensitive_actions': ['document.cookie', 'localStorage', 'fetch(']
}