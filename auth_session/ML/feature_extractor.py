import pandas as pd
import numpy as np
from datetime import datetime, timedelta
import hashlib
from typing import List, Dict
import os

class FeatureExtractor:
    def __init__(self, window_minutes: List[int] = None):
        self.window_minutes = window_minutes or [5, 15, 60]
        
    def load_dataset(self, filepath: str) -> pd.DataFrame:
        """Load and prepare the dataset"""
        print(f"Loading dataset from: {filepath}")
        df = pd.read_csv(filepath)
        df['timestamp'] = pd.to_datetime(df['timestamp'])
        return df
    
    def compute_rolling_features(self, df: pd.DataFrame, entity: str, value: str) -> pd.DataFrame:
        """Compute rolling window features for a specific entity"""
        features = {}
        
        for window in self.window_minutes:
            # Count events in window
            window_sec = window * 60
            features[f'{entity}_{value}_count_{window}m'] = (
                df.groupby(entity)['timestamp']
                .transform(lambda x: x.apply(
                    lambda ts: ((x >= ts - timedelta(seconds=window_sec)) & 
                               (x <= ts)).sum()
                ))
            )
        
        return pd.DataFrame(features)
    
    def extract_username_features(self, df: pd.DataFrame) -> pd.DataFrame:
        """Extract features grouped by username"""
        username_features = {}
        
        # Basic counts
        username_group = df.groupby('username')
        username_features['total_attempts'] = username_group.size()
        
        # Success/failure rates
        success_counts = username_group['auth_result'].apply(lambda x: (x == 'success').sum())
        failure_counts = username_group['auth_result'].apply(lambda x: (x == 'failure').sum())
        username_features['success_rate'] = success_counts / username_features['total_attempts']
        username_features['failure_rate'] = failure_counts / username_features['total_attempts']
        
        # IP diversity
        username_features['distinct_ips'] = username_group['ip_address'].nunique()
        username_features['ip_entropy'] = username_group['ip_address'].apply(
            lambda x: self._calculate_entropy(x)
        )
        
        # Temporal features
        username_features['avg_time_between_attempts'] = username_group['timestamp'].apply(
            lambda x: x.sort_values().diff().mean().total_seconds() if len(x) > 1 else 0
        )
        
        return pd.DataFrame(username_features).reset_index()
    
    def extract_ip_features(self, df: pd.DataFrame) -> pd.DataFrame:
        """Extract features grouped by IP address"""
        ip_features = {}
        
        ip_group = df.groupby('ip_address')
        ip_features['total_attempts'] = ip_group.size()
        ip_features['distinct_usernames'] = ip_group['username'].nunique()
        
        # Success rate from this IP
        success_counts = ip_group['auth_result'].apply(lambda x: (x == 'success').sum())
        ip_features['success_rate'] = success_counts / ip_features['total_attempts']
        
        # Attempt rate features
        ip_features['attempts_per_minute'] = ip_group['timestamp'].apply(
            lambda x: len(x) / ((x.max() - x.min()).total_seconds() / 60) 
            if len(x) > 1 and x.max() != x.min() else 0
        )
        
        return pd.DataFrame(ip_features).reset_index()
    
    def extract_session_features(self, df: pd.DataFrame) -> pd.DataFrame:
        """Extract session-level features"""
        session_features = {}
        
        # Filter events with sessions
        session_events = df[df['session_id'].notna() & (df['session_id'] != '')]
        
        if len(session_events) > 0:
            session_group = session_events.groupby('session_id')
            session_features['session_duration'] = session_group['session_duration'].max()
            session_features['ip_changes'] = session_group['ip_address'].nunique()
            session_features['user_agent_changes'] = session_group['user_agent'].nunique()
            
            return pd.DataFrame(session_features).reset_index()
        else:
            return pd.DataFrame(columns=['session_id', 'session_duration', 'ip_changes', 'user_agent_changes'])
    
    def extract_temporal_features(self, df: pd.DataFrame) -> pd.DataFrame:
        """Extract time-based features"""
        temporal_features = {}
        
        df['login_hour'] = df['timestamp'].dt.hour
        df['weekday'] = df['timestamp'].dt.weekday
        
        temporal_features['login_hour'] = df['login_hour']
        temporal_features['weekday'] = df['weekday']
        temporal_features['is_weekend'] = df['weekday'].isin([5, 6]).astype(int)
        temporal_features['is_night'] = ((df['login_hour'] >= 0) & (df['login_hour'] <= 6)).astype(int)
        
        return pd.DataFrame(temporal_features)
    
    def _calculate_entropy(self, series):
        """Calculate entropy of a series"""
        value_counts = series.value_counts()
        probabilities = value_counts / len(series)
        return -np.sum(probabilities * np.log2(probabilities))
    
    def create_feature_dataset(self, input_file: str, output_file: str):
        """Create complete feature dataset"""
        print("Loading dataset...")
        df = self.load_dataset(input_file)
        
        print("Extracting username features...")
        username_features = self.extract_username_features(df)
        
        print("Extracting IP features...")
        ip_features = self.extract_ip_features(df)
        
        print("Extracting session features...")
        session_features = self.extract_session_features(df)
        
        print("Extracting temporal features...")
        temporal_features = self.extract_temporal_features(df)
        
        # Merge features
        print("Merging features...")
        feature_df = df[['event_id', 'username', 'ip_address', 'session_id', 'timestamp', 
                        'is_bruteforce_candidate', 'is_anomalous']].copy()
        
        # Merge username features
        feature_df = feature_df.merge(username_features, on='username', how='left')
        
        # Merge IP features
        feature_df = feature_df.merge(ip_features, on='ip_address', how='left', 
                                    suffixes=('', '_ip'))
        
        # Merge session features
        if not session_features.empty:
            feature_df = feature_df.merge(session_features, on='session_id', how='left')
        
        # Add temporal features
        temporal_features.index = feature_df.index
        feature_df = pd.concat([feature_df, temporal_features], axis=1)
        
        # Engineered features
        feature_df['velocity_score'] = (
            feature_df['total_attempts'] * feature_df['distinct_ips']
        )
        feature_df['suspicious_ip_flag'] = (
            (feature_df['distinct_usernames'] > 10) | 
            (feature_df['attempts_per_minute'] > 20)
        ).astype(int)
        
        # Fill NaN values
        feature_df = feature_df.fillna(0)
        
        print(f"Saving feature dataset to {output_file}")
        feature_df.to_csv(output_file, index=False)
        
        # Print feature summary
        print(f"\n=== FEATURE DATASET SUMMARY ===")
        print(f"Total records: {len(feature_df)}")
        print(f"Total features: {len(feature_df.columns)}")
        print(f"Anomalous records: {feature_df['is_anomalous'].sum()}")
        print(f"Feature columns: {list(feature_df.columns)}")
        
        return feature_df

def main():
    extractor = FeatureExtractor()
    
    # FIXED: Use raw string for Windows path
    input_file = r"C:\Users\vishal\Desktop\WEBSCAN_PRO\projects\auth_session\data\login_session_dataset_type1.csv"
    
    # FIXED: Use absolute path for output
    output_file = r"C:\Users\vishal\Desktop\WEBSCAN_PRO\projects\auth_session\data\feature_dataset.csv"
    
    # Create output directory if it doesn't exist
    os.makedirs(os.path.dirname(output_file), exist_ok=True)
    
    if not os.path.exists(input_file):
        print(f"Input file {input_file} not found. Run auth_scanner.py first.")
        return
    
    feature_df = extractor.create_feature_dataset(input_file, output_file)
    print(f"\nFeature extraction completed successfully!")
    print(f"Output saved to: {output_file}")

if __name__ == "__main__":
    main()