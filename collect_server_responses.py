import pandas as pd
import time
import random
import os
from datetime import datetime
from response_collector import ResponseCollector
from payload_generator import PayloadGenerator
from config import DATA_DIR, OUTPUT_DIR

class ServerResponseCollection:
    def __init__(self):
        self.collector = ResponseCollector()
        self.payload_generator = PayloadGenerator()
        self.dataset = None
        self.results = []
        
    def load_metadata(self):
        """Load metadata.csv with URL structures"""
        try:
            # Fixed path - using raw string and proper path
            metadata_path = r"C:\Users\vishal\Desktop\WEBSCAN_PRO\metadata.csv"
            
            if os.path.exists(metadata_path):
                self.dataset = pd.read_csv(metadata_path)
                print(f"✓ Loaded metadata with {len(self.dataset)} records")
                print(f"Columns found: {self.dataset.columns.tolist()}")
                return True
            else:
                print(f"❌ Metadata file not found at: {metadata_path}")
                print("ℹ Creating sample data instead...")
                self.dataset = self.payload_generator.create_sample_dataset()
                return True
        except Exception as e:
            print(f"✗ Error loading metadata: {e}")
            return False
    
    def collect_responses(self, delay=2, max_requests=50):
        """Collect responses for all parameters with normal and injected inputs"""
        if self.dataset is None or self.dataset.empty:
            print("✗ No dataset available!")
            return None
        
        # Login to DVWA
        print("\n🔐 Attempting to login to DVWA...")
        login_success = self.collector.login()
        if not login_success:
            print("⚠ Warning: Login failed or skipped. Some endpoints might not work.")
        
        total_endpoints = len(self.dataset)
        current_endpoint = 0
        request_count = 0
        
        print(f"\n🎯 Starting server response collection for {total_endpoints} endpoints...")
        
        for _, row in self.dataset.iterrows():
            current_endpoint += 1
            print(f"\n--- Testing Endpoint {current_endpoint}/{total_endpoints} ---")
            print(f"URL: {row['url']}")
            print(f"Method: {row['method']}")
            print(f"Parameter: {row['param_name']}")
            
            # Generate test payloads
            test_pairs = self.payload_generator.generate_test_pairs(
                row['input_type'], 
                max_injections=3
            )
            
            for label, payload in test_pairs:
                if request_count >= max_requests:
                    print(f"ℹ Reached maximum request limit ({max_requests})")
                    break
                
                request_count += 1
                print(f"  [{request_count}] {label:8}: {payload[:60]}...")
                
                # Send request
                response_data = self.collector.send_request(
                    url=row['url'],
                    method=row['method'],
                    param_name=row['param_name'],
                    input_value=payload
                )
                
                # Create result record
                record = {
                    'url': row['url'],
                    'method': row['method'],
                    'param_name': row['param_name'],
                    'input_type': row['input_type'],
                    'default_value': row.get('default_value', ''),
                    'form_action': row.get('form_action', ''),
                    'input_value': payload,
                    'label': label,
                    'is_malicious': 1 if label == 'injection' else 0,
                    'response_status': response_data['response_status'],
                    'response_time': response_data['response_time'],
                    'html_content_length': response_data['html_content_length'],
                    'error_message_flag': response_data['error_message_flag'],
                    'response_body_path': response_data['response_body_path'],
                    'timestamp': datetime.now().isoformat()
                }
                
                # Add error message if present
                if 'error_message' in response_data:
                    record['error_message'] = response_data['error_message']
                
                self.results.append(record)
                
                # Delay between requests to avoid overwhelming the server
                if delay > 0:
                    time.sleep(delay)
            
            if request_count >= max_requests:
                break
        
        return pd.DataFrame(self.results)
    
    def save_results(self, results_df, filename='raw_server_responses.csv'):
        """Save collected results to CSV"""
        filepath = os.path.join(DATA_DIR, filename)
        results_df.to_csv(filepath, index=False)
        print(f"✓ Results saved to {filepath}")
        return filepath
    
    def generate_summary(self, results_df):
        """Generate collection summary"""
        print("\n" + "="*50)
        print("📊 COLLECTION SUMMARY")
        print("="*50)
        
        if results_df is None or results_df.empty:
            print("No data collected!")
            return
        
        total_requests = len(results_df)
        safe_requests = len(results_df[results_df['label'] == 'safe'])
        injection_requests = len(results_df[results_df['label'] == 'injection'])
        
        print(f"Total Requests: {total_requests}")
        print(f"Safe Requests: {safe_requests}")
        print(f"Injection Requests: {injection_requests}")
        print(f"Unique Endpoints: {results_df['url'].nunique()}")
        print(f"Unique Parameters: {results_df['param_name'].nunique()}")
        
        print("\n📈 Response Status Distribution:")
        status_counts = results_df['response_status'].value_counts().sort_index()
        for status, count in status_counts.items():
            print(f"  {status}: {count} requests")
        
        print(f"\n⚠ Error Flags: {results_df['error_message_flag'].sum()} / {total_requests}")
        
        # Calculate average response times
        avg_time_safe = results_df[results_df['label'] == 'safe']['response_time'].mean()
        avg_time_injection = results_df[results_df['label'] == 'injection']['response_time'].mean()
        
        print(f"\n⏱ Average Response Times:")
        print(f"  Safe: {avg_time_safe:.2f} ms")
        print(f"  Injection: {avg_time_injection:.2f} ms")
        
        # Save summary to file
        summary_path = os.path.join(OUTPUT_DIR, 'reports', 'collection_summary.txt')
        os.makedirs(os.path.dirname(summary_path), exist_ok=True)
        
        with open(summary_path, 'w') as f:
            f.write("Server Response Collection Summary\n")
            f.write("================================\n\n")
            f.write(f"Collection Date: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}\n")
            f.write(f"Total Requests: {total_requests}\n")
            f.write(f"Safe Requests: {safe_requests}\n")
            f.write(f"Injection Requests: {injection_requests}\n")
            f.write(f"Unique Endpoints: {results_df['url'].nunique()}\n")
            f.write(f"Error Flags: {results_df['error_message_flag'].sum()}\n")
        
        print(f"\n📄 Summary saved to: {summary_path}")

def main():
    print("🚀 WebScanPro ML - Server Response Collection")
    print("===========================================")
    
    # Initialize collection system
    collection = ServerResponseCollection()
    
    # Load metadata - FIXED: Using metadata.csv instead of existing_dataset.csv
    collection.load_metadata()
    
    # Collect responses (with 2-second delay between requests, max 50 requests)
    results = collection.collect_responses(delay=2, max_requests=50)
    
    if results is not None and not results.empty:
        # Save results
        output_file = collection.save_results(results)
        
        # Generate summary
        collection.generate_summary(results)
        
        print(f"\n✅ Collection completed successfully!")
        print(f"📁 Output file: {output_file}")
        print(f"📊 Total records: {len(results)}")
        
        # Show sample of collected data
        print("\n📋 Sample of collected data:")
        print(results[['url', 'param_name', 'label', 'response_status', 'response_time', 'error_message_flag']].head(10).to_string(index=False))
        
    else:
        print("❌ Collection failed or no data collected!")

if __name__ == "__main__":
    main()