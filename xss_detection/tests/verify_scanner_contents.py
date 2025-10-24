import os
import sys

project_root = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, project_root)

scanner_file = os.path.join(project_root, 'scanner', 'new_update_Scanner.py')

if os.path.exists(scanner_file):
    print(f"✅ File found: {scanner_file}")
    print("Reading first 20 lines...")
    
    with open(scanner_file, 'r', encoding='utf-8') as f:
        for i, line in enumerate(f):
            if i < 20:  # Show first 20 lines
                print(f"{i+1:2}: {line.rstrip()}")
            else:
                break
                
    # Try to import and see what's available
    print("\n🐍 Attempting import...")
    try:
        from Scanner.new_update_Scanner import ResponseAnalyzer
        print("✅ Successfully imported ResponseAnalyzer!")
        
        # Check if XSSScanner also exists
        try:
            from Scanner.new_update_Scanner import XSSScanner
            print("✅ XSSScanner class found!")
        except ImportError:
            print("❌ XSSScanner class not found in file")
            
    except ImportError as e:
        print(f"❌ Import failed: {e}")
        
else:
    print(f"❌ File not found: {scanner_file}")