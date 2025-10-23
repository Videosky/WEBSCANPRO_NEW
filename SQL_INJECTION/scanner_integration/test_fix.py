#!/usr/bin/env python3
"""
Quick test to verify the fix works
"""

import sys
import os

# Add current directory to path
current_dir = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, current_dir)

print("🧪 Testing fixed imports...")

try:
    from ml_integration import SQLiMLDetector
    print("✅ SUCCESS: SQLiMLDetector imported!")
    
    # Test creating instance
    detector = SQLiMLDetector()
    print("✅ SUCCESS: SQLiMLDetector instance created!")
    
    # Test with a simple model path
    test_model = 'compatible_test_model.pkl'
    if os.path.exists(test_model):
        success = detector.load_model(test_model)
        print(f"✅ SUCCESS: Model loading test: {success}")
    else:
        print("ℹ️  No test model found, but imports work!")
        
except ImportError as e:
    print(f"❌ FAILED: {e}")

print("\n🎉 If you see ✅ SUCCESS messages, the fix worked!")