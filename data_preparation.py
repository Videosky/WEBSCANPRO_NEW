"""
Data preparation and splitting for IDOR ML model training
"""

import pandas as pd
import numpy as np
import json
import os
from sklearn.model_selection import train_test_split
from sklearn.preprocessing import StandardScaler
import joblib

class IDORDataPreprocessor:
    def __init__(self):
        self.scaler = StandardScaler()
        self.feature_columns = None
        
    def load_and_validate_data(self, data_path):
        """Load and validate the feature-engineered dataset"""
        print("📊 Loading and validating dataset...")
        
        if not os.path.exists(data_path):
            raise FileNotFoundError(f"Dataset not found: {data_path}")
        
        df = pd.read_csv(data_path)
        print(f"Dataset shape: {df.shape}")
        print(f"Columns: {list(df.columns)}")
        
        # Validate required columns
        required_columns = ['is_unauthorized']
        missing_columns = [col for col in required_columns if col not in df.columns]
        if missing_columns:
            raise ValueError(f"Missing required columns: {missing_columns}")
        
        # Check label distribution
        label_counts = df['is_unauthorized'].value_counts()
        print(f"Label distribution:\n{label_counts}")
        print(f"Unauthorized ratio: {label_counts.get(1, 0) / len(df):.3f}")
        
        return df
    
    def prepare_features(self, df):
        """Prepare features for model training"""
        print("🔧 Preparing features...")
        
        # Select feature columns (exclude target and non-feature columns)
        exclude_columns = ['is_unauthorized']
        feature_columns = [col for col in df.columns if col not in exclude_columns]
        
        # Ensure we have numeric features
        numeric_columns = df[feature_columns].select_dtypes(include=[np.number]).columns
        if len(numeric_columns) == 0:
            raise ValueError("No numeric features found for training")
        
        print(f"Using {len(numeric_columns)} numeric features")
        self.feature_columns = numeric_columns.tolist()
        
        X = df[numeric_columns]
        y = df['is_unauthorized']
        
        return X, y
    
    def create_stratified_splits(self, X, y, test_size=0.2, val_size=0.2, random_state=42):
        """Create stratified train/validation/test splits"""
        print("🎯 Creating stratified splits...")
        
        # First split: train + temp
        X_train, X_temp, y_train, y_temp = train_test_split(
            X, y, test_size=test_size + val_size, 
            stratify=y, random_state=random_state
        )
        
        # Second split: validation + test
        val_ratio = val_size / (test_size + val_size)
        X_val, X_test, y_val, y_test = train_test_split(
            X_temp, y_temp, test_size=1-val_ratio,
            stratify=y_temp, random_state=random_state
        )
        
        print(f"Train set: {X_train.shape[0]} samples ({X_train.shape[0]/len(X):.1%})")
        print(f"Validation set: {X_val.shape[0]} samples ({X_val.shape[0]/len(X):.1%})")
        print(f"Test set: {X_test.shape[0]} samples ({X_test.shape[0]/len(X):.1%})")
        
        return X_train, X_val, X_test, y_train, y_val, y_test
    
    def save_splits(self, X_train, X_val, X_test, y_train, y_val, y_test, output_dir):
        """Save data splits and configuration"""
        print("💾 Saving data splits...")
        
        os.makedirs(output_dir, exist_ok=True)
        
        # Save splits as CSV
        train_df = pd.concat([X_train, y_train], axis=1)
        val_df = pd.concat([X_val, y_val], axis=1)
        test_df = pd.concat([X_test, y_test], axis=1)
        
        train_df.to_csv(os.path.join(output_dir, 'train.csv'), index=False)
        val_df.to_csv(os.path.join(output_dir, 'val.csv'), index=False)
        test_df.to_csv(os.path.join(output_dir, 'test.csv'), index=False)
        
        # Save split configuration
        split_config = {
            'feature_columns': self.feature_columns,
            'split_sizes': {
                'train': len(X_train),
                'validation': len(X_val),
                'test': len(X_test),
                'total': len(X_train) + len(X_val) + len(X_test)
            },
            'label_distribution': {
                'train': y_train.value_counts().to_dict(),
                'validation': y_val.value_counts().to_dict(),
                'test': y_test.value_counts().to_dict()
            },
            'test_size': 0.2,
            'val_size': 0.2,
            'random_state': 42
        }
        
        with open(os.path.join(output_dir, 'split_config.json'), 'w') as f:
            json.dump(split_config, f, indent=2)
        
        print("✅ Data splits saved successfully")
        return split_config

def main():
    """Main data preparation pipeline"""
    data_path = r"C:\Users\vishal\Desktop\WEBSCAN_PRO\projects\auth_session\data\idor_features.csv"
    output_dir = r"C:\Users\vishal\Desktop\WEBSCAN_PRO\projects\auth_session\data\splits"
    
    preprocessor = IDORDataPreprocessor()
    
    try:
        # Load and validate data
        df = preprocessor.load_and_validate_data(data_path)
        
        # Prepare features
        X, y = preprocessor.prepare_features(df)
        
        # Create splits
        X_train, X_val, X_test, y_train, y_val, y_test = preprocessor.create_stratified_splits(X, y)
        
        # Save splits
        config = preprocessor.save_splits(X_train, X_val, X_test, y_train, y_val, y_test, output_dir)
        
        print("\n🎉 Data preparation completed successfully!")
        print(f"📁 Splits saved to: {output_dir}")
        
    except Exception as e:
        print(f"❌ Error in data preparation: {e}")
        raise

if __name__ == "__main__":
    main()