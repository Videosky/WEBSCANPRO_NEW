# scripts/validate_features.py
import pandas as pd
import numpy as np

def validate_feature_dataset():
    """Validate the generated feature dataset meets requirements"""
    print("🔍 Validating Feature Dataset...")
    
    try:
        # Load the feature dataset
        df = pd.read_csv('data/feature_dataset.csv')
        
        print(f"✅ Dataset loaded successfully")
        print(f"   Shape: {df.shape}")
        print(f"   Columns: {list(df.columns)}")
        
        # Check required columns
        required_columns = [
            'response_time', 'html_content_length', 'error_message_flag',
            'status_group', 'is_malicious'
        ]
        
        missing_columns = [col for col in required_columns if col not in df.columns]
        if missing_columns:
            print(f"❌ Missing required columns: {missing_columns}")
            return False
        else:
            print("✅ All required columns present")
        
        # Check data types
        print("\n📊 Data types check:")
        for col in required_columns:
            print(f"   {col}: {df[col].dtype}")
        
        # Check for missing values
        print("\n🔍 Missing values check:")
        missing_values = df[required_columns].isnull().sum()
        if missing_values.sum() > 0:
            print(f"❌ Missing values found:")
            for col, count in missing_values.items():
                if count > 0:
                    print(f"   {col}: {count} missing")
            return False
        else:
            print("✅ No missing values in required columns")
        
        # Check label distribution
        print(f"\n🎯 Label distribution:")
        malicious_count = df['is_malicious'].sum()
        safe_count = len(df) - malicious_count
        print(f"   Malicious (1): {malicious_count} ({malicious_count/len(df)*100:.1f}%)")
        print(f"   Safe (0): {safe_count} ({safe_count/len(df)*100:.1f}%)")
        
        # Check value ranges
        print(f"\n📈 Value ranges:")
        print(f"   response_time: {df['response_time'].min():.2f} to {df['response_time'].max():.2f}")
        print(f"   html_content_length: {df['html_content_length'].min():.2f} to {df['html_content_length'].max():.2f}")
        print(f"   error_message_flag: {df['error_message_flag'].unique()}")
        print(f"   status_group: {df['status_group'].unique()}")
        
        # Check for infinite values
        numeric_cols = ['response_time', 'html_content_length']
        for col in numeric_cols:
            if col in df.columns:
                inf_count = np.isinf(df[col]).sum()
                if inf_count > 0:
                    print(f"❌ Infinite values in {col}: {inf_count}")
                    return False
        
        print("\n🎉 All validation checks passed! Feature dataset is ready for model training.")
        return True
        
    except Exception as e:
        print(f"❌ Validation failed with error: {e}")
        return False

if __name__ == "__main__":
    validate_feature_dataset()