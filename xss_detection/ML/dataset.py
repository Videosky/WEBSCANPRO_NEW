import pandas as pd
import numpy as np
import re
from sklearn.model_selection import train_test_split
from sklearn.preprocessing import LabelEncoder, StandardScaler
import torch
from torch.utils.data import Dataset, DataLoader
import pickle
import os
from typing import List, Dict, Tuple, Optional

class XSSDataset(Dataset):
    def __init__(self, texts, features, labels, tokenizer, max_length=1000):
        self.texts = texts
        self.features = features
        self.labels = labels
        self.tokenizer = tokenizer
        self.max_length = max_length
    
    def __len__(self):
        return len(self.texts)
    
    def __getitem__(self, idx):
        text = self.texts[idx]
        features = self.features[idx]
        label = self.labels[idx]
        
        # Tokenize text
        tokens = self.tokenizer.text_to_sequence(text, self.max_length)
        
        return {
            'tokens': torch.tensor(tokens, dtype=torch.long),
            'features': torch.tensor(features, dtype=torch.float),
            'label': torch.tensor(label, dtype=torch.float)
        }

class XSSDataPreprocessor:
    def __init__(self, config):
        self.config = config
        self.tokenizer = CharTokenizer()
        self.feature_engineer = FeatureEngineer(config)
        self.feature_scaler = StandardScaler()
        
        # Define important columns to preserve
        self.important_columns = [
            'payload_id', 'url', 'method', 'injection_point', 'payload',
            'response_time', 'status_group', 'html_content_length',
            'reflected_payload_present', 'is_malicious', 'notes'
        ]
        
        # Define critical columns that must exist
        self.critical_columns = ['payload', 'is_malicious']
    
    def load_and_clean_data(self, csv_path: str) -> Tuple[List[str], np.ndarray, np.ndarray, pd.DataFrame]:
        """Load and clean the dataset while preserving important columns"""
        print(f"Loading data from {csv_path}")
        
        # Load data with error handling
        try:
            df = pd.read_csv(csv_path)
        except Exception as e:
            raise ValueError(f"Failed to load CSV file: {e}")
        
        # Print dataset info
        self._print_dataset_info(df)
        
        # Clean dataset while preserving important columns
        df_clean = self._clean_dataset(df)
        
        # Extract features
        features = self.feature_engineer.extract_features(df_clean)
        
        # Prepare text data
        texts = self._prepare_text_data(df_clean)
        
        # Prepare labels
        labels = self._prepare_labels(df_clean)
        
        # Validate processed data
        self._validate_processed_data(texts, features, labels, df_clean)
        
        return texts, features, labels, df_clean
    
    def _print_dataset_info(self, df: pd.DataFrame):
        """Print detailed dataset information"""
        print(f"Dataset shape: {df.shape}")
        print(f"Columns: {df.columns.tolist()}")
        print(f"Missing values per column:")
        for col in df.columns:
            missing = df[col].isna().sum()
            if missing > 0:
                print(f"  {col}: {missing} missing values")
        
        # Check for critical columns
        missing_critical = [col for col in self.critical_columns if col not in df.columns]
        if missing_critical:
            print(f"WARNING: Missing critical columns: {missing_critical}")
        
        # Print label distribution if available
        if 'is_malicious' in df.columns:
            try:
                label_dist = df['is_malicious'].value_counts()
                print(f"Label distribution: {label_dist.to_dict()}")
            except:
                print("Could not calculate label distribution")
    
    def _clean_dataset(self, df: pd.DataFrame) -> pd.DataFrame:
        """Clean the dataset while preserving all important columns"""
        print("Cleaning dataset...")
        
        # Create a working copy
        df_clean = df.copy()
        
        # 1. Ensure critical columns exist
        missing_critical = [col for col in self.critical_columns if col not in df_clean.columns]
        if missing_critical:
            raise ValueError(f"Missing critical columns: {missing_critical}")
        
        # 2. Handle missing values in critical columns
        initial_count = len(df_clean)
        df_clean = df_clean.dropna(subset=self.critical_columns)
        removed_missing = initial_count - len(df_clean)
        if removed_missing > 0:
            print(f"Removed {removed_missing} rows with missing critical data")
        
        # 3. Clean and standardize important columns
        df_clean = self._clean_important_columns(df_clean)
        
        # 4. Filter by payload length
        df_clean = self._filter_by_payload_length(df_clean)
        
        # 5. Ensure all important columns exist (add missing ones with defaults)
        df_clean = self._ensure_important_columns(df_clean)
        
        print(f"Final cleaned dataset size: {len(df_clean)}")
        return df_clean
    
    def _clean_important_columns(self, df: pd.DataFrame) -> pd.DataFrame:
        """Clean and standardize important columns"""
        df_clean = df.copy()
        
        # Clean payload column
        if 'payload' in df_clean.columns:
            df_clean['payload'] = df_clean['payload'].astype(str)
            # Remove extra whitespace and quotes
            df_clean['payload'] = df_clean['payload'].str.strip().str.strip('"\'')
        
        # Clean is_malicious column
        if 'is_malicious' in df_clean.columns:
            df_clean['is_malicious'] = self._ensure_boolean(df_clean['is_malicious'])
        
        # Clean reflected_payload_present column
        if 'reflected_payload_present' in df_clean.columns:
            df_clean['reflected_payload_present'] = self._ensure_boolean(df_clean['reflected_payload_present'])
        
        # Clean numeric columns
        numeric_columns = ['response_time', 'html_content_length']
        for col in numeric_columns:
            if col in df_clean.columns:
                df_clean[col] = pd.to_numeric(df_clean[col], errors='coerce').fillna(0)
        
        # Clean text columns
        text_columns = ['url', 'method', 'injection_point', 'notes']
        for col in text_columns:
            if col in df_clean.columns:
                df_clean[col] = df_clean[col].astype(str).fillna('')
        
        return df_clean
    
    def _ensure_boolean(self, series: pd.Series) -> pd.Series:
        """Ensure a series contains proper boolean values"""
        if series.dtype == 'bool':
            return series
        
        try:
            # Handle various boolean representations
            if series.dtype == 'object':
                # Handle string representations
                return series.astype(str).str.lower().isin(['true', '1', 'yes', 't', 'y']).astype(bool)
            else:
                # Handle numeric (0/1)
                return series.astype(bool)
        except Exception as e:
            print(f"Warning: Could not convert to boolean, using default False: {e}")
            return pd.Series([False] * len(series), index=series.index)
    
    def _filter_by_payload_length(self, df: pd.DataFrame) -> pd.DataFrame:
        """Filter dataset by payload length constraints"""
        min_len = self.config['data']['min_sequence_length']
        max_len = self.config['data']['max_sequence_length']
        
        if 'payload' not in df.columns:
            return df
        
        payload_lengths = df['payload'].str.len()
        before_filter = len(df)
        
        df_filtered = df[
            (payload_lengths >= min_len) & 
            (payload_lengths <= max_len)
        ]
        
        after_filter = len(df_filtered)
        filtered_count = before_filter - after_filter
        
        if filtered_count > 0:
            print(f"Filtered {filtered_count} rows by payload length ({min_len}-{max_len} chars)")
        
        return df_filtered
    
    def _ensure_important_columns(self, df: pd.DataFrame) -> pd.DataFrame:
        """Ensure all important columns exist in the dataframe"""
        df_clean = df.copy()
        
        for col in self.important_columns:
            if col not in df_clean.columns:
                print(f"Adding missing column: {col}")
                if col in ['is_malicious', 'reflected_payload_present']:
                    df_clean[col] = False
                elif col in ['response_time', 'html_content_length']:
                    df_clean[col] = 0
                elif col == 'status_group':
                    df_clean[col] = 'success'
                elif col == 'method':
                    df_clean[col] = 'GET'
                elif col == 'injection_point':
                    df_clean[col] = 'query_param:q'
                else:
                    df_clean[col] = ''
        
        # Reorder columns to maintain consistency
        existing_columns = [col for col in self.important_columns if col in df_clean.columns]
        extra_columns = [col for col in df_clean.columns if col not in self.important_columns]
        
        return df_clean[existing_columns + extra_columns]
    
    def _prepare_text_data(self, df: pd.DataFrame) -> List[str]:
        """Prepare text data from payload and other relevant columns"""
        texts = []
        
        for _, row in df.iterrows():
            text_parts = []
            
            # Primary text source: payload
            if 'payload' in row:
                text_parts.append(str(row['payload']))
            
            # Secondary text sources for context
            context_columns = ['notes', 'injection_point', 'url']
            for col in context_columns:
                if col in row and pd.notna(row[col]) and row[col] != '':
                    text_parts.append(str(row[col]))
            
            # Combine all text parts
            combined_text = " ".join(text_parts)
            normalized_text = self._normalize_text(combined_text)
            texts.append(normalized_text)
        
        print(f"Prepared {len(texts)} text samples")
        return texts
    
    def _prepare_labels(self, df: pd.DataFrame) -> np.ndarray:
        """Prepare labels with validation"""
        if 'is_malicious' not in df.columns:
            raise ValueError("is_malicious column not found for label preparation")
        
        labels = df['is_malicious'].astype(int).values
        
        # Validate labels
        unique_labels = np.unique(labels)
        if not set(unique_labels).issubset({0, 1}):
            raise ValueError(f"Invalid label values found: {unique_labels}")
        
        malicious_count = np.sum(labels)
        benign_count = len(labels) - malicious_count
        
        print(f"Label distribution: {malicious_count} malicious, {benign_count} benign "
              f"({malicious_count/len(labels)*100:.1f}% malicious)")
        
        return labels
    
    def _normalize_text(self, text: str) -> str:
        """Normalize text for consistent processing"""
        if not isinstance(text, str):
            text = str(text)
        
        # Remove extra whitespace
        text = re.sub(r'\s+', ' ', text)
        
        # Standardize case (optional - can be configurable)
        if self.config['data'].get('lowercase', True):
            text = text.lower()
        
        # Remove excessive special characters (optional)
        if self.config['data'].get('clean_special_chars', False):
            text = re.sub(r'[^\w\s<>=\(\)\.;:\'"-]', '', text)
        
        return text.strip()
    
    def _validate_processed_data(self, texts: List[str], features: np.ndarray, 
                               labels: np.ndarray, df: pd.DataFrame):
        """Validate the processed data"""
        assert len(texts) == len(features) == len(labels) == len(df), \
            f"Data length mismatch: texts={len(texts)}, features={len(features)}, labels={len(labels)}, df={len(df)}"
        
        assert features.shape[0] == len(texts), \
            f"Features shape mismatch: {features.shape[0]} != {len(texts)}"
        
        print(f"Data validation passed: {len(texts)} samples ready for training")
    
    def prepare_splits(self, texts: List[str], features: np.ndarray, labels: np.ndarray, 
                      test_size: float = 0.2, val_size: float = 0.1, 
                      random_state: int = 42) -> Tuple:
        """Prepare stratified train/validation/test splits"""
        
        if len(texts) == 0:
            raise ValueError("No data available for splitting")
        
        print(f"Preparing splits with test_size={test_size}, val_size={val_size}")
        
        # First split: separate test set
        X_temp, X_test, y_temp, y_test, feat_temp, feat_test = train_test_split(
            texts, labels, features, 
            test_size=test_size, 
            stratify=labels,
            random_state=random_state
        )
        
        # Second split: separate validation set from temp
        val_size_adjusted = val_size / (1 - test_size)
        X_train, X_val, y_train, y_val, feat_train, feat_val = train_test_split(
            X_temp, y_temp, feat_temp,
            test_size=val_size_adjusted,
            stratify=y_temp,
            random_state=random_state
        )
        
        print(f"Split sizes - Train: {len(X_train)}, Val: {len(X_val)}, Test: {len(X_test)}")
        
        return (X_train, X_val, X_test, 
                feat_train, feat_val, feat_test,
                y_train, y_val, y_test)
    
    def create_data_loaders(self, X_train, X_val, X_test, feat_train, feat_val, feat_test, 
                          y_train, y_val, y_test, batch_size: int = 32) -> Tuple[DataLoader, DataLoader, DataLoader]:
        """Create PyTorch data loaders with proper feature scaling"""
        
        # Scale features
        if len(feat_train) > 0:
            feat_train_scaled = self.feature_scaler.fit_transform(feat_train)
            feat_val_scaled = self.feature_scaler.transform(feat_val)
            feat_test_scaled = self.feature_scaler.transform(feat_test)
        else:
            # Handle case with no features
            feat_train_scaled = np.zeros((len(X_train), 1))
            feat_val_scaled = np.zeros((len(X_val), 1))
            feat_test_scaled = np.zeros((len(X_test), 1))
        
        # Create datasets
        max_length = self.config['data']['max_sequence_length']
        train_dataset = XSSDataset(X_train, feat_train_scaled, y_train, self.tokenizer, max_length)
        val_dataset = XSSDataset(X_val, feat_val_scaled, y_val, self.tokenizer, max_length)
        test_dataset = XSSDataset(X_test, feat_test_scaled, y_test, self.tokenizer, max_length)
        
        # Create data loaders
        train_loader = DataLoader(train_dataset, batch_size=batch_size, shuffle=True, 
                                num_workers=0, pin_memory=True)
        val_loader = DataLoader(val_dataset, batch_size=batch_size, shuffle=False,
                              num_workers=0, pin_memory=True)
        test_loader = DataLoader(test_dataset, batch_size=batch_size, shuffle=False,
                               num_workers=0, pin_memory=True)
        
        print(f"Created data loaders with batch_size={batch_size}")
        return train_loader, val_loader, test_loader
    
    def save_preprocessor(self, filepath: str):
        """Save preprocessor objects for inference"""
        os.makedirs(os.path.dirname(filepath), exist_ok=True)
        
        save_data = {
            'tokenizer': self.tokenizer,
            'feature_scaler': self.feature_scaler,
            'feature_engineer': self.feature_engineer,
            'config': self.config,
            'important_columns': self.important_columns
        }
        
        with open(filepath, 'wb') as f:
            pickle.dump(save_data, f)
        
        print(f"Preprocessor saved to: {filepath}")
    
    def load_preprocessor(self, filepath: str) -> 'XSSDataPreprocessor':
        """Load preprocessor objects"""
        with open(filepath, 'rb') as f:
            data = pickle.load(f)
            self.tokenizer = data['tokenizer']
            self.feature_scaler = data['feature_scaler']
            self.feature_engineer = data['feature_engineer']
            # Update config if provided
            if 'config' in data:
                self.config.update(data['config'])
        return self


class CharTokenizer:
    """Enhanced character-level tokenizer for XSS payloads"""
    
    def __init__(self, vocab_size: int = 256):
        self.char_to_idx = {}
        self.idx_to_char = {}
        self.vocab_size = 0
        self.vocab_size_limit = vocab_size
        self._build_vocab()
    
    def _build_vocab(self):
        """Build comprehensive character vocabulary for XSS patterns"""
        # Basic ASCII characters (printable)
        chars = []
        for i in range(32, 127):
            chars.append(chr(i))
        
        # Special characters common in XSS payloads
        xss_special_chars = [
            '<', '>', '/', '\\', '"', "'", '=', ' ', '\t', '\n', '\r',
            '(', ')', '[', ']', '{', '}', ';', ':', '.', ',', '&', '%',
            '+', '-', '*', '|', '^', '~', '`', '!', '?', '@', '#', '$'
        ]
        
        # Combine and deduplicate
        all_chars = list(set(chars + xss_special_chars))
        all_chars.sort()
        
        # Limit vocabulary size if needed
        if len(all_chars) > self.vocab_size_limit:
            print(f"Limiting vocabulary from {len(all_chars)} to {self.vocab_size_limit} characters")
            all_chars = all_chars[:self.vocab_size_limit]
        
        # Add special tokens
        self.char_to_idx = {'<PAD>': 0, '<UNK>': 1}
        for char in all_chars:
            self.char_to_idx[char] = len(self.char_to_idx)
        
        self.idx_to_char = {idx: char for char, idx in self.char_to_idx.items()}
        self.vocab_size = len(self.char_to_idx)
        
        print(f"Built vocabulary with {self.vocab_size} characters")
    
    def text_to_sequence(self, text: str, max_length: int) -> List[int]:
        """Convert text to sequence of indices with truncation/padding"""
        if not isinstance(text, str):
            text = str(text)
        
        sequence = []
        for char in text[:max_length]:
            sequence.append(self.char_to_idx.get(char, self.char_to_idx['<UNK>']))
        
        # Padding
        while len(sequence) < max_length:
            sequence.append(self.char_to_idx['<PAD>'])
        
        return sequence
    
    def sequence_to_text(self, sequence: List[int]) -> str:
        """Convert sequence of indices back to text"""
        return ''.join([self.idx_to_char.get(idx, '') for idx in sequence if idx != self.char_to_idx['<PAD>']])
    
    def save(self, filepath: str):
        """Save tokenizer"""
        with open(filepath, 'wb') as f:
            pickle.dump({
                'char_to_idx': self.char_to_idx,
                'idx_to_char': self.idx_to_char,
                'vocab_size': self.vocab_size,
                'vocab_size_limit': self.vocab_size_limit
            }, f)
    
    def load(self, filepath: str) -> 'CharTokenizer':
        """Load tokenizer"""
        with open(filepath, 'rb') as f:
            data = pickle.load(f)
            self.char_to_idx = data['char_to_idx']
            self.idx_to_char = data['idx_to_char']
            self.vocab_size = data['vocab_size']
            self.vocab_size_limit = data.get('vocab_size_limit', 256)
        return self


class FeatureEngineer:
    """Enhanced feature engineering for XSS detection"""
    
    def __init__(self, config):
        self.config = config
        self.regex_patterns = config['features']['regex_patterns']
        
        # Extended regex patterns for XSS detection
        self.extended_patterns = [
            r'&lt;', r'&gt;', r'&quot;', r'&#x', r'&#',  # HTML entities
            r'\\x[0-9a-f]{2}', r'%[0-9a-f]{2}',  # Hex encoding
            r'\\u[0-9a-f]{4}',  # Unicode encoding
            r'document\.', r'window\.', r'location\.',  # DOM access
            r'String\.fromCharCode', r'decodeURI', r'atob',  # Obfuscation
            r'eval\s*\(', r'setTimeout\s*\(', r'setInterval\s*\(',  # JS execution
            r'innerHTML', r'outerHTML', r'write\s*\(',  # DOM manipulation
            r'<iframe', r'<embed', r'<object', r'<base',  # Suspicious tags
            r'on\w+\s*=',  # Event handlers
            r'javascript:', r'vbscript:', r'data:',  # Protocols
        ]
    
    def extract_features(self, df: pd.DataFrame) -> np.ndarray:
        """Extract comprehensive features from dataframe"""
        features = []
        
        print("Extracting features...")
        
        for _, row in df.iterrows():
            feature_vector = []
            
            # Basic features
            if self.config['features']['use_basic_features']:
                feature_vector.extend(self._extract_basic_features(row))
            
            # Regex-based features
            if self.config['features']['use_regex_features']:
                feature_vector.extend(self._extract_regex_features(row))
                feature_vector.extend(self._extract_extended_features(row))
            
            # Statistical features
            if self.config['features'].get('use_statistical_features', True):
                feature_vector.extend(self._extract_statistical_features(row))
            
            features.append(feature_vector)
        
        features_array = np.array(features)
        print(f"Extracted {len(features_array)} feature vectors with {features_array.shape[1]} features each")
        
        return features_array
    
    def _extract_basic_features(self, row) -> List[float]:
        """Extract basic numerical and categorical features"""
        features = []
        
        # HTML content length (normalized)
        html_len = row.get('html_content_length', 0)
        features.append(min(html_len / 10000.0, 1.0))  # Normalize to [0,1]
        
        # Response time (normalized)
        resp_time = row.get('response_time', 0)
        features.append(min(resp_time / 10.0, 1.0))  # Normalize to [0,1]
        
        # Boolean flags
        features.append(1.0 if row.get('reflected_payload_present', False) else 0.0)
        
        # Status group encoding (one-hot like)
        status_group = row.get('status_group', 'success')
        status_features = [0.0] * 5
        status_mapping = {'success': 0, 'redirect': 1, 'client_error': 2, 'server_error': 3, 'unknown': 4}
        status_idx = status_mapping.get(status_group, 4)
        status_features[status_idx] = 1.0
        features.extend(status_features)
        
        # Method encoding
        method = str(row.get('method', 'GET')).upper()
        method_features = [0.0] * 3
        method_mapping = {'GET': 0, 'POST': 1, 'OTHER': 2}
        method_idx = method_mapping.get(method, 2)
        method_features[method_idx] = 1.0
        features.extend(method_features)
        
        return features
    
    def _extract_regex_features(self, row) -> List[float]:
        """Extract regex-based pattern counts"""
        payload = str(row.get('payload', ''))
        notes = str(row.get('notes', '')) if 'notes' in row.index else ''
        text = payload + " " + notes
        
        features = []
        
        for pattern in self.regex_patterns:
            count = len(re.findall(pattern, text, re.IGNORECASE))
            # Normalize count
            normalized_count = min(count / 5.0, 1.0)
            features.append(normalized_count)
        
        return features
    
    def _extract_extended_features(self, row) -> List[float]:
        """Extract extended regex features for XSS detection"""
        payload = str(row.get('payload', ''))
        notes = str(row.get('notes', '')) if 'notes' in row.index else ''
        text = payload + " " + notes
        
        features = []
        
        for pattern in self.extended_patterns:
            count = len(re.findall(pattern, text, re.IGNORECASE))
            normalized_count = min(count / 3.0, 1.0)
            features.append(normalized_count)
        
        return features
    
    def _extract_statistical_features(self, row) -> List[float]:
        """Extract statistical features from payload"""
        payload = str(row.get('payload', ''))
        
        features = []
        
        if len(payload) > 0:
            # Character diversity
            unique_chars = len(set(payload))
            features.append(unique_chars / len(payload))
            
            # Ratio of special characters
            special_chars = len(re.findall(r'[<>/"\'=;()&%]', payload))
            features.append(special_chars / len(payload))
            
            # Ratio of digits
            digits = len(re.findall(r'\d', payload))
            features.append(digits / len(payload))
            
            # Ratio of whitespace
            whitespace = len(re.findall(r'\s', payload))
            features.append(whitespace / len(payload))
        else:
            features.extend([0.0] * 4)
        
        return features