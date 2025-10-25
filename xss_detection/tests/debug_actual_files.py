import sys
import os

# Add paths
project_root = os.path.abspath(os.path.join(os.path.dirname(__file__), '..'))
ml_dir = os.path.join(project_root, 'ML')
sys.path.insert(0, ml_dir)

print("🔍 DEBUGGING YOUR ACTUAL FILES")
print("=" * 50)

# Check dataset.py
print("\n📊 dataset.py contents:")
try:
    import dataset
    for item in dir(dataset):
        if not item.startswith('_'):
            obj = getattr(dataset, item)
            print(f"   {item}: {type(obj).__name__}")
except Exception as e:
    print(f"   ERROR: {e}")

# Check utils.py  
print("\n🛠️ utils.py contents:")
try:
    import utils
    for item in dir(utils):
        if not item.startswith('_'):
            obj = getattr(utils, item)
            print(f"   {item}: {type(obj).__name__}")
except Exception as e:
    print(f"   ERROR: {e}")

# Check model parameters
print("\n🤖 Model parameters:")
try:
    from models import LSTMClassifier, BaselineModel
    import inspect
    
    print("   LSTMClassifier.__init__ parameters:")
    sig = inspect.signature(LSTMClassifier.__init__)
    for name, param in sig.parameters.items():
        if name != 'self':
            print(f"      {name}: {param.default if param.default != param.empty else 'REQUIRED'}")
    
    print("\n   BaselineModel.__init__ parameters:")
    sig = inspect.signature(BaselineModel.__init__)
    for name, param in sig.parameters.items():
        if name != 'self':
            print(f"      {name}: {param.default if param.default != param.empty else 'REQUIRED'}")
            
except Exception as e:
    print(f"   ERROR: {e}")