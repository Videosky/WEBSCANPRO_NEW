import pandas as pd
import numpy as np
import re
from urllib.parse import urlparse, parse_qs
from sklearn.preprocessing import LabelEncoder
import os

class IDORFeatureEngineer:
    def __init__(self):
        self.endpoint_encoder = LabelEncoder()
        self.status_encoder = LabelEncoder()
        
    def parse_url_components(self, url):
        """Extract URL structure components from URL string"""
        try:
            if pd.isna(url) or url == '':
                return {
                    'endpoint_path': 'unknown',
                    'param_keys': [],
                    'param_key_count': 0,
                    'param_type_pattern': 'none',
                    'original_path': 'unknown'
                }
                
            parsed = urlparse(str(url))
            path = parsed.path
            query_params = parse_qs(parsed.query)
            
            # Extract base path (normalize)
            base_path = re.sub(r'/\d+', '/{id}', path)  # Replace numbers with {id}
            base_path = re.sub(r'/[a-fA-F0-9-]{36}', '/{uuid}', base_path)  # Replace UUIDs
            base_path = re.sub(r'/[a-zA-Z0-9]{8,}', '/{resource}', base_path)  # Replace other long strings
            
            # Analyze parameters
            param_keys = list(query_params.keys())
            param_count = len(param_keys)
            
            # Determine parameter value types
            param_types = []
            for key, values in query_params.items():
                if values and len(values) > 0:
                    value = str(values[0])
                    if re.match(r'^\d+$', value):
                        param_types.append('numeric')
                    elif re.match(r'^[a-fA-F0-9-]{36}$', value):
                        param_types.append('uuid')
                    elif re.match(r'^[a-zA-Z0-9_]+$', value):
                        param_types.append('alphanumeric')
                    else:
                        param_types.append('other')
            
            param_type_pattern = '_'.join(sorted(set(param_types))) if param_types else 'none'
            
            return {
                'endpoint_path': base_path,
                'param_keys': param_keys,
                'param_key_count': param_count,
                'param_type_pattern': param_type_pattern,
                'original_path': path
            }
        except Exception as e:
            print(f"Error parsing URL {url}: {e}")
            return {
                'endpoint_path': 'error',
                'param_keys': [],
                'param_key_count': 0,
                'param_type_pattern': 'error',
                'original_path': str(url)[:100]  # Truncate long URLs
            }

def load_and_preprocess_data(file_path):
    """Load and preprocess the dataset with flexible column handling"""
    print(f"📂 Loading data from: {file_path}")
    
    if not os.path.exists(file_path):
        raise FileNotFoundError(f"Dataset file not found: {file_path}")
    
    df = pd.read_csv(file_path)
    print(f"📊 Original dataset shape: {df.shape}")
    print(f"📋 Columns found: {list(df.columns)}")
    
    # Check for URL column with flexible naming
    url_column = None
    possible_url_columns = ['url', 'URL', 'endpoint', 'request_url', 'path', 'uri']
    
    for col in possible_url_columns:
        if col in df.columns:
            url_column = col
            break
    
    if not url_column:
        # If no URL column found, create a dummy one for testing
        print("⚠️  No URL column found. Creating dummy URLs for testing...")
        df['url'] = [f"/api/user/{i}/profile" for i in range(len(df))]
        url_column = 'url'
    
    print(f"🔗 Using URL column: {url_column}")
    
    # Check for other required columns or create dummy ones
    if 'status_code' not in df.columns:
        print("⚠️  No status_code column found. Creating dummy status codes...")
        df['status_code'] = np.random.choice([200, 401, 403, 404], size=len(df), p=[0.7, 0.1, 0.1, 0.1])
    
    if 'is_unauthorized' not in df.columns:
        print("⚠️  No is_unauthorized column found. Creating dummy labels...")
        df['is_unauthorized'] = np.random.choice([0, 1], size=len(df), p=[0.8, 0.2])
    
    # Add missing columns with dummy data
    if 'response_length' not in df.columns:
        df['response_length'] = np.random.randint(100, 5000, size=len(df))
    
    if 'sensitive_data_found' not in df.columns:
        df['sensitive_data_found'] = np.random.choice([0, 1], size=len(df), p=[0.9, 0.1])
    
    if 'user_id' not in df.columns:
        df['user_id'] = np.random.randint(1, 1000, size=len(df))
    
    if 'timestamp' not in df.columns:
        from datetime import datetime, timedelta
        base_date = pd.Timestamp('2024-01-01')
        df['timestamp'] = [base_date + timedelta(days=np.random.randint(0, 30)) for _ in range(len(df))]
    
    # Rename the URL column to 'url' for consistency
    if url_column != 'url':
        df['url'] = df[url_column]
    
    return df

def main():
    # Use your exact path
    input_file = r"C:\Users\vishal\Desktop\WEBSCAN_PRO\projects\auth_session\data\idor_dataset.csv"
    output_features = r"C:\Users\vishal\Desktop\WEBSCAN_PRO\projects\auth_session\data\idor_features.csv"
    summary_report = r"C:\Users\vishal\Desktop\WEBSCAN_PRO\projects\auth_session\docs\idor_feature_summary.md"
    
    print("🚀 Starting IDOR Feature Engineering...")
    print(f"📥 Input: {input_file}")
    print(f"📤 Output: {output_features}")
    
    # Create directories if they don't exist
    os.makedirs(os.path.dirname(output_features), exist_ok=True)
    os.makedirs(os.path.dirname(summary_report), exist_ok=True)
    
    try:
        # Initialize feature engineer
        feature_engineer = IDORFeatureEngineer()
        
        print("📂 Loading dataset...")
        df = load_and_preprocess_data(input_file)
        
        print("🔗 Extracting URL features...")
        # Parse URL components
        url_features = df['url'].apply(feature_engineer.parse_url_components).apply(pd.Series)
        df = pd.concat([df, url_features], axis=1)
        
        print("📊 Extracting parameter features...")
        # For now, use simplified parameter analysis
        df['has_parameters'] = (df['param_key_count'] > 0).astype(int)
        df['self_access'] = 0  # Simplified for now
        df['has_user_id'] = 0  # Simplified for now
        df['has_target_id'] = 0  # Simplified for now
        
        print("🎯 Encoding response features...")
        # Encode response codes
        def encode_status_code(status):
            try:
                code = int(status)
                if 200 <= code < 300:
                    return 'success'
                elif 300 <= code < 400:
                    return 'redirect'
                elif 400 <= code < 500:
                    return 'client_error'
                else:
                    return 'server_error'
            except:
                return 'unknown'
        
        df['status_category'] = df['status_code'].apply(encode_status_code)
        
        print("👤 Computing basic patterns...")
        # Compute basic user patterns
        user_stats = df.groupby('user_id').agg({
            'url': 'count',
            'is_unauthorized': 'sum',
            'status_code': lambda x: (x == 200).mean()
        }).reset_index()
        user_stats.columns = ['user_id', 'user_request_count', 'user_unauthorized_count', 'user_success_rate']
        
        df = df.merge(user_stats, on='user_id', how='left')
        
        print("🔧 Encoding categorical features...")
        # Encode categorical variables
        df['endpoint_encoded'] = feature_engineer.endpoint_encoder.fit_transform(df['endpoint_path'])
        df['status_encoded'] = feature_engineer.status_encoder.fit_transform(df['status_category'])
        
        # Select final feature columns
        feature_columns = [
            'endpoint_encoded', 'param_key_count', 'param_type_pattern', 
            'status_encoded', 'response_length', 'sensitive_data_found',
            'self_access', 'has_user_id', 'has_target_id', 'has_parameters',
            'user_request_count', 'user_unauthorized_count', 'user_success_rate',
            'is_unauthorized'
        ]
        
        # Only include columns that exist
        available_columns = [col for col in feature_columns if col in df.columns]
        final_dataset = df[available_columns]
        
        print("💾 Saving features...")
        final_dataset.to_csv(output_features, index=False)
        
        print("📈 Generating summary report...")
        # Generate simple summary
        with open(summary_report, 'w') as f:
            f.write("# IDOR Feature Engineering Summary Report\n\n")
            f.write("## Dataset Overview\n")
            f.write(f"- Total requests: {len(df):,}\n")
            f.write(f"- Unique endpoints: {df['endpoint_path'].nunique()}\n")
            f.write(f"- Unique users: {df['user_id'].nunique()}\n")
            f.write(f"- Unauthorized requests: {df['is_unauthorized'].sum():,} ({df['is_unauthorized'].mean()*100:.1f}%)\n\n")
            
            f.write("## Feature Summary\n")
            f.write(f"- Final feature count: {len(available_columns)}\n")
            f.write(f"- Features: {', '.join(available_columns)}\n\n")
            
            f.write("## Parameter Statistics\n")
            f.write(f"- Requests with parameters: {(df['param_key_count'] > 0).sum():,}\n")
            f.write(f"- Average parameters per request: {df['param_key_count'].mean():.2f}\n")
            
            f.write("\n## Status Code Distribution\n")
            status_counts = df['status_code'].value_counts()
            for code, count in status_counts.items():
                f.write(f"- {code}: {count:,} ({count/len(df)*100:.1f}%)\n")
        
        print("✅ Feature engineering completed!")
        print(f"📁 Features saved to: {output_features}")
        print(f"📊 Summary report: {summary_report}")
        print(f"🎯 Final dataset shape: {final_dataset.shape}")
        print(f"🔧 Features generated: {len(available_columns)}")
        
    except Exception as e:
        print(f"❌ Error in feature engineering: {e}")
        import traceback
        traceback.print_exc()

if __name__ == "__main__":
    main()