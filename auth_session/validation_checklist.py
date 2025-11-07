# validation_checklist.py
import pandas as pd
import os

def validate_feature_engineering():
    """Validate the feature engineering pipeline"""
    
    print("🔍 Validating IDOR Feature Engineering Pipeline...")
    
    # Check files exist
    required_files = [
        "projects/auth_session/data/idor_features.csv",
        "projects/auth_session/docs/idor_feature_summary.md"
    ]
    
    for file_path in required_files:
        if os.path.exists(file_path):
            print(f"✅ {file_path} exists")
        else:
            print(f"❌ {file_path} missing")
            return False
    
    # Load and validate features
    try:
        features_df = pd.read_csv("projects/auth_session/data/idor_features.csv")
        original_df = pd.read_csv("projects/auth_session/data/idor_dataset.csv")
        
        print("\n📊 Feature Validation:")
        
        # 1. URL components parsed
        url_features_present = all(col in features_df.columns for col in 
                                 ['endpoint_encoded', 'param_key_count'])
        print(f"✅ URL components parsed: {url_features_present}")
        
        # 2. Parameter variation computed
        param_features_present = 'param_change_rate' in features_df.columns
        print(f"✅ Parameter variation computed: {param_features_present}")
        
        # 3. Self-access features computed
        self_access_present = 'self_access' in features_df.columns
        print(f"✅ Self-access features computed: {self_access_present}")
        
        # 4. Response codes encoded
        status_encoded_present = 'status_encoded' in features_df.columns
        print(f"✅ Response codes encoded: {status_encoded_present}")
        
        # 5. Schema consistency
        has_target = 'is_unauthorized' in features_df.columns
        feature_count = len(features_df.columns)
        print(f"✅ Schema consistency: {has_target} ({feature_count} features)")
        
        # 6. No data loss
        no_data_loss = len(features_df) == len(original_df)
        print(f"✅ No data loss: {no_data_loss}")
        
        print(f"\n🎯 Final Feature Matrix: {features_df.shape}")
        print(f"📈 Feature columns: {list(features_df.columns)}")
        
        return all([url_features_present, param_features_present, 
                   self_access_present, status_encoded_present, 
                   has_target, no_data_loss])
        
    except Exception as e:
        print(f"❌ Validation failed: {e}")
        return False

if __name__ == "__main__":
    validate_feature_engineering()