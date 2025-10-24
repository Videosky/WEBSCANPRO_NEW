import os
import sys

# Add project root to path
project_root = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, project_root)

scanner_dir = os.path.join(project_root, 'scanner')

print("🔍 Scanner Directory Diagnostic")
print("=" * 50)
print(f"Scanner directory: {scanner_dir}")
print(f"Directory exists: {os.path.exists(scanner_dir)}")

if os.path.exists(scanner_dir):
    print("\n📁 Files in scanner directory:")
    for file in os.listdir(scanner_dir):
        file_path = os.path.join(scanner_dir, file)
        file_type = "DIR" if os.path.isdir(file_path) else "FILE"
        print(f"  {file_type}: {file}")
    
    # Check for specific files
    files_to_check = [
        'new_update_Scanner.py',
        'new_update_scanner.py', 
        'core_2.py',
        'scanner.py'
    ]
    
    print("\n🔎 Looking for specific files:")
    for file_name in files_to_check:
        full_path = os.path.join(scanner_dir, file_name)
        exists = os.path.exists(full_path)
        print(f"  {file_name}: {'✅ FOUND' if exists else '❌ NOT FOUND'}")

print("\n🐍 Python path:")
for path in sys.path:
    print(f"  {path}")