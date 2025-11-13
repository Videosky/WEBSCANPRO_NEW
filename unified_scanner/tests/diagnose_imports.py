#!/usr/bin/env python3
"""
Diagnose import issues
"""

import os
import sys
import inspect

# Add project root to path
project_root = os.path.abspath(os.path.join(os.path.dirname(__file__), '..', '..'))
sys.path.insert(0, project_root)

def check_unified_scanner_file():
    """Check what's actually in the unified_scanner.py file"""
    unified_scanner_path = os.path.join(project_root, 'projects', 'unified_scanner', 'unified_scanner.py')
    
    print(f"Checking file: {unified_scanner_path}")
    print(f"File exists: {os.path.exists(unified_scanner_path)}")
    
    if os.path.exists(unified_scanner_path):
        with open(unified_scanner_path, 'r', encoding='utf-8') as f:
            content = f.read()
            print(f"File size: {len(content)} bytes")
            
            # Look for class definitions
            if 'class UnifiedScanner' in content:
                print("✓ Found 'class UnifiedScanner' in file")
            else:
                print("❌ 'class UnifiedScanner' NOT found in file")
                
            # Look for other classes
            classes_to_check = ['SQLiInference', 'XSSInference', 'HTTPClient', 'PayloadGenerator']
            for class_name in classes_to_check:
                if f'class {class_name}' in content:
                    print(f"✓ Found 'class {class_name}' in file")
                else:
                    print(f"❌ 'class {class_name}' NOT found in file")
            
            # Show first few lines
            print("\nFirst 10 lines of file:")
            lines = content.split('\n')[:10]
            for i, line in enumerate(lines, 1):
                print(f"{i:2}: {line}")

def try_import_unified_scanner():
    """Try to import and see what's available"""
    print("\n" + "="*50)
    print("Trying to import from unified_scanner...")
    
    try:
        # Try to import the module
        from projects.unified_scanner import unified_scanner
        
        print("✓ Successfully imported unified_scanner module")
        print(f"Module location: {unified_scanner.__file__}")
        
        # List available attributes
        print("\nAvailable attributes in unified_scanner:")
        for attr in dir(unified_scanner):
            if not attr.startswith('_'):
                print(f"  - {attr}")
                
        # Try to access UnifiedScanner
        if hasattr(unified_scanner, 'UnifiedScanner'):
            print(f"\n✓ UnifiedScanner class found!")
            print(f"  Type: {type(unified_scanner.UnifiedScanner)}")
        else:
            print(f"\n❌ UnifiedScanner class NOT found in module")
            
    except ImportError as e:
        print(f"❌ Import failed: {e}")

def check_all_components():
    """Check all components"""
    print("\n" + "="*50)
    print("Checking all components...")
    
    components = [
        ('config', ['THRESHOLDS', 'SCAN_OPTIONS']),
        ('utils', ['PayloadGenerator', 'HTTPClient']),
        ('inference_sqli', ['SQLiInference']),
        ('inference_xss', ['XSSInference']),
        ('reporting', ['ReportGenerator']),
    ]
    
    for module_name, expected_attrs in components:
        try:
            module = __import__(f'projects.unified_scanner.{module_name}', fromlist=['*'])
            print(f"✓ {module_name}: imported successfully")
            
            for attr in expected_attrs:
                if hasattr(module, attr):
                    print(f"  ✓ {attr} found")
                else:
                    print(f"  ❌ {attr} NOT found")
                    
        except ImportError as e:
            print(f"❌ {module_name}: import failed - {e}")

if __name__ == '__main__':
    print("Unified Scanner Import Diagnostics")
    print("="*50)
    
    check_unified_scanner_file()
    try_import_unified_scanner()
    check_all_components()