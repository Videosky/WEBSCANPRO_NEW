import torch
import torch.nn as nn
import torch.nn.functional as F
import math
from typing import List, Optional

class Attention(nn.Module):
    """Attention mechanism for better feature extraction"""
    def __init__(self, hidden_size):
        super(Attention, self).__init__()
        self.hidden_size = hidden_size
        self.attention = nn.Linear(hidden_size, 1)
        
    def forward(self, lstm_output):
        # lstm_output: [batch_size, seq_len, hidden_size]
        attention_weights = torch.softmax(self.attention(lstm_output).squeeze(-1), dim=1)
        # attention_weights: [batch_size, seq_len]
        context_vector = torch.bmm(attention_weights.unsqueeze(1), lstm_output).squeeze(1)
        return context_vector, attention_weights

class ResidualBlock(nn.Module):
    """Residual block for better gradient flow"""
    def __init__(self, hidden_size, dropout=0.3):
        super(ResidualBlock, self).__init__()
        self.linear1 = nn.Linear(hidden_size, hidden_size)
        self.linear2 = nn.Linear(hidden_size, hidden_size)
        self.dropout = nn.Dropout(dropout)
        self.layer_norm = nn.LayerNorm(hidden_size)
        
    def forward(self, x):
        residual = x
        x = F.relu(self.linear1(x))
        x = self.dropout(x)
        x = self.linear2(x)
        x = self.layer_norm(x + residual)
        return F.relu(x)

class LSTMClassifier(nn.Module):
    def __init__(self, vocab_size, embedding_dim, hidden_size, num_layers, 
                 dropout, bidirectional, num_features, output_dim=1,
                 use_attention=True, use_residual=True):
        super(LSTMClassifier, self).__init__()
        
        self.use_attention = use_attention
        self.use_residual = use_residual
        
        # Enhanced embedding with better initialization
        self.embedding = nn.Embedding(vocab_size, embedding_dim, padding_idx=0)
        # Initialize embeddings with Xavier uniform
        nn.init.xavier_uniform_(self.embedding.weight)
        
        # Enhanced LSTM with layer normalization
        self.lstm = nn.LSTM(
            embedding_dim, 
            hidden_size, 
            num_layers, 
            batch_first=True,
            dropout=dropout if num_layers > 1 else 0,
            bidirectional=bidirectional
        )
        
        # Attention mechanism
        if use_attention:
            lstm_output_size = hidden_size * 2 if bidirectional else hidden_size
            self.attention = Attention(lstm_output_size)
        
        self.dropout = nn.Dropout(dropout)
        
        # Calculate sizes
        lstm_output_size = hidden_size * 2 if bidirectional else hidden_size
        feature_output_size = lstm_output_size // 2
        
        # Enhanced feature processing
        self.feature_fc = nn.Sequential(
            nn.Linear(num_features, feature_output_size * 2),
            nn.BatchNorm1d(feature_output_size * 2),
            nn.ReLU(),
            nn.Dropout(dropout),
            nn.Linear(feature_output_size * 2, feature_output_size)
        )
        
        # Combined classifier with residual connections
        combined_size = lstm_output_size + feature_output_size
        
        if use_residual:
            self.classifier = nn.Sequential(
                nn.Linear(combined_size, hidden_size),
                nn.BatchNorm1d(hidden_size),
                nn.ReLU(),
                nn.Dropout(dropout),
                ResidualBlock(hidden_size, dropout),
                nn.Linear(hidden_size, hidden_size // 2),
                nn.BatchNorm1d(hidden_size // 2),
                nn.ReLU(),
                nn.Dropout(dropout),
                nn.Linear(hidden_size // 2, output_dim)
            )
        else:
            self.classifier = nn.Sequential(
                nn.Linear(combined_size, hidden_size),
                nn.BatchNorm1d(hidden_size),
                nn.ReLU(),
                nn.Dropout(dropout),
                nn.Linear(hidden_size, hidden_size // 2),
                nn.BatchNorm1d(hidden_size // 2),
                nn.ReLU(),
                nn.Dropout(dropout),
                nn.Linear(hidden_size // 2, output_dim)
            )
        
    def forward(self, tokens, features):
        # Text processing through LSTM
        embedded = self.embedding(tokens)
        
        lstm_out, (hidden, _) = self.lstm(embedded)
        
        # Use attention or last hidden state
        if self.use_attention:
            text_features, attention_weights = self.attention(lstm_out)
        else:
            if self.lstm.bidirectional:
                text_features = torch.cat((hidden[-2], hidden[-1]), dim=1)
            else:
                text_features = hidden[-1]
        
        text_features = self.dropout(text_features)
        
        # Enhanced feature processing
        processed_features = self.feature_fc(features)
        
        # Combine text and feature representations
        combined = torch.cat([text_features, processed_features], dim=1)
        
        # Final classification
        output = self.classifier(combined)
        
        return torch.sigmoid(output)

class MultiScaleCNN(nn.Module):
    """Enhanced CNN with multiple kernel sizes and residual connections"""
    def __init__(self, vocab_size, embedding_dim, num_filters, filter_sizes, 
                 dropout, num_features, output_dim=1, use_batch_norm=True):
        super(MultiScaleCNN, self).__init__()
        
        self.embedding = nn.Embedding(vocab_size, embedding_dim, padding_idx=0)
        nn.init.xavier_uniform_(self.embedding.weight)
        
        # Multi-scale convolutional layers with batch normalization
        self.convs = nn.ModuleList()
        for fs in filter_sizes:
            conv_seq = nn.Sequential(
                nn.Conv1d(embedding_dim, num_filters, kernel_size=fs, padding=fs//2),
                nn.BatchNorm1d(num_filters) if use_batch_norm else nn.Identity(),
                nn.ReLU(),
                nn.Dropout(dropout),
                nn.Conv1d(num_filters, num_filters, kernel_size=fs, padding=fs//2),
                nn.BatchNorm1d(num_filters) if use_batch_norm else nn.Identity(),
                nn.ReLU()
            )
            self.convs.append(conv_seq)
        
        # Global attention pooling
        self.attention_pool = nn.Sequential(
            nn.Linear(num_filters, num_filters),
            nn.Tanh(),
            nn.Linear(num_filters, 1)
        )
        
        self.dropout = nn.Dropout(dropout)
        
        # Enhanced feature processing
        self.feature_fc = nn.Sequential(
            nn.Linear(num_features, num_filters),
            nn.BatchNorm1d(num_filters),
            nn.ReLU(),
            nn.Dropout(dropout)
        )
        
        # Combined classifier
        combined_size = num_filters * len(filter_sizes) + num_filters
        self.classifier = nn.Sequential(
            nn.Linear(combined_size, num_filters * 2),
            nn.BatchNorm1d(num_filters * 2),
            nn.ReLU(),
            nn.Dropout(dropout),
            nn.Linear(num_filters * 2, num_filters),
            nn.BatchNorm1d(num_filters),
            nn.ReLU(),
            nn.Dropout(dropout),
            nn.Linear(num_filters, output_dim)
        )
        
    def forward(self, tokens, features):
        # Text processing through multi-scale CNN
        embedded = self.embedding(tokens)  # [batch_size, seq_len, embedding_dim]
        embedded = embedded.permute(0, 2, 1)  # [batch_size, embedding_dim, seq_len]
        
        # Apply multi-scale convolutions
        conv_outputs = []
        for conv in self.convs:
            conv_out = conv(embedded)  # [batch_size, num_filters, seq_len]
            
            # Attention pooling
            attention_weights = torch.softmax(
                self.attention_pool(conv_out.permute(0, 2, 1)), dim=1
            )  # [batch_size, seq_len, 1]
            
            pooled = torch.bmm(attention_weights.transpose(1, 2), conv_out.permute(0, 2, 1))
            pooled = pooled.squeeze(1)  # [batch_size, num_filters]
            conv_outputs.append(pooled)
        
        text_features = self.dropout(torch.cat(conv_outputs, dim=1))
        
        # Feature processing
        processed_features = self.feature_fc(features)
        
        # Combine representations
        combined = torch.cat([text_features, processed_features], dim=1)
        
        # Final classification
        output = self.classifier(combined)
        
        return torch.sigmoid(output)

class TransformerClassifier(nn.Module):
    """Transformer-based classifier for sequence classification"""
    def __init__(self, vocab_size, embedding_dim, num_heads, num_layers,
                 hidden_size, dropout, num_features, output_dim=1, max_seq_length=1000):
        super(TransformerClassifier, self).__init__()
        
        self.embedding = nn.Embedding(vocab_size, embedding_dim, padding_idx=0)
        nn.init.xavier_uniform_(self.embedding.weight)
        
        # Positional encoding
        self.pos_encoding = PositionalEncoding(embedding_dim, max_seq_length, dropout)
        
        # Transformer encoder
        encoder_layer = nn.TransformerEncoderLayer(
            d_model=embedding_dim,
            nhead=num_heads,
            dim_feedforward=hidden_size,
            dropout=dropout,
            batch_first=True
        )
        self.transformer = nn.TransformerEncoder(encoder_layer, num_layers)
        
        # Feature processing
        self.feature_fc = nn.Sequential(
            nn.Linear(num_features, hidden_size // 2),
            nn.BatchNorm1d(hidden_size // 2),
            nn.ReLU(),
            nn.Dropout(dropout)
        )
        
        # Classifier
        combined_size = embedding_dim + hidden_size // 2
        self.classifier = nn.Sequential(
            nn.Linear(combined_size, hidden_size),
            nn.BatchNorm1d(hidden_size),
            nn.ReLU(),
            nn.Dropout(dropout),
            nn.Linear(hidden_size, hidden_size // 2),
            nn.BatchNorm1d(hidden_size // 2),
            nn.ReLU(),
            nn.Dropout(dropout),
            nn.Linear(hidden_size // 2, output_dim)
        )
        
    def forward(self, tokens, features):
        # Create mask for padding tokens
        mask = (tokens == 0)
        
        # Embedding and positional encoding
        embedded = self.embedding(tokens)
        embedded = self.pos_encoding(embedded)
        
        # Transformer encoding
        transformer_out = self.transformer(embedded, src_key_padding_mask=mask)
        
        # Use [CLS] token equivalent (mean pooling)
        text_features = transformer_out.mean(dim=1)
        
        # Feature processing
        processed_features = self.feature_fc(features)
        
        # Combine representations
        combined = torch.cat([text_features, processed_features], dim=1)
        
        # Final classification
        output = self.classifier(combined)
        
        return torch.sigmoid(output)

class PositionalEncoding(nn.Module):
    """Positional encoding for transformer"""
    def __init__(self, d_model, max_len=5000, dropout=0.1):
        super(PositionalEncoding, self).__init__()
        self.dropout = nn.Dropout(p=dropout)
        
        pe = torch.zeros(max_len, d_model)
        position = torch.arange(0, max_len, dtype=torch.float).unsqueeze(1)
        div_term = torch.exp(torch.arange(0, d_model, 2).float() * 
                           (-math.log(10000.0) / d_model))
        pe[:, 0::2] = torch.sin(position * div_term)
        pe[:, 1::2] = torch.cos(position * div_term)
        pe = pe.unsqueeze(0)
        self.register_buffer('pe', pe)
        
    def forward(self, x):
        x = x + self.pe[:, :x.size(1)]
        return self.dropout(x)

class EnsembleModel(nn.Module):
    """Ensemble of multiple models"""
    def __init__(self, models):
        super(EnsembleModel, self).__init__()
        self.models = nn.ModuleList(models)
        
    def forward(self, tokens, features):
        outputs = []
        for model in self.models:
            output = model(tokens, features)
            outputs.append(output)
        
        # Average the predictions
        ensemble_output = torch.stack(outputs).mean(dim=0)
        return ensemble_output

class FocalLoss(nn.Module):
    """Focal loss for handling class imbalance"""
    def __init__(self, alpha=1, gamma=2, reduction='mean'):
        super(FocalLoss, self).__init__()
        self.alpha = alpha
        self.gamma = gamma
        self.reduction = reduction
        
    def forward(self, inputs, targets):
        BCE_loss = F.binary_cross_entropy(inputs, targets, reduction='none')
        pt = torch.exp(-BCE_loss)
        F_loss = self.alpha * (1-pt)**self.gamma * BCE_loss
        
        if self.reduction == 'mean':
            return F_loss.mean()
        elif self.reduction == 'sum':
            return F_loss.sum()
        else:
            return F_loss

class BaselineModel(nn.Module):
    """Enhanced baseline model with better architecture"""
    def __init__(self, num_features, hidden_size=128, output_dim=1, dropout=0.3):
        super(BaselineModel, self).__init__()
        
        self.classifier = nn.Sequential(
            nn.Linear(num_features, hidden_size),
            nn.BatchNorm1d(hidden_size),
            nn.ReLU(),
            nn.Dropout(dropout),
            nn.Linear(hidden_size, hidden_size // 2),
            nn.BatchNorm1d(hidden_size // 2),
            nn.ReLU(),
            nn.Dropout(dropout),
            nn.Linear(hidden_size // 2, hidden_size // 4),
            nn.BatchNorm1d(hidden_size // 4),
            nn.ReLU(),
            nn.Dropout(dropout),
            nn.Linear(hidden_size // 4, output_dim)
        )
        
    def forward(self, tokens, features):
        output = self.classifier(features)
        return torch.sigmoid(output)

def get_model(model_type, vocab_size, num_features, config):
    """Enhanced factory function with more model options"""
    if model_type == "lstm":
        return LSTMClassifier(
            vocab_size=vocab_size,
            embedding_dim=config['model']['embedding_dim'],
            hidden_size=config['model']['hidden_size'],
            num_layers=config['model']['num_layers'],
            dropout=config['model']['dropout'],
            bidirectional=config['model']['bidirectional'],
            num_features=num_features,
            use_attention=config['model'].get('use_attention', True),
            use_residual=config['model'].get('use_residual', True)
        )
    elif model_type == "cnn":
        return MultiScaleCNN(
            vocab_size=vocab_size,
            embedding_dim=config['model']['embedding_dim'],
            num_filters=config['model']['hidden_size'],
            filter_sizes=config['model'].get('filter_sizes', [2, 3, 4, 5]),
            dropout=config['model']['dropout'],
            num_features=num_features
        )
    elif model_type == "transformer":
        return TransformerClassifier(
            vocab_size=vocab_size,
            embedding_dim=config['model']['embedding_dim'],
            num_heads=config['model'].get('num_heads', 8),
            num_layers=config['model']['num_layers'],
            hidden_size=config['model']['hidden_size'],
            dropout=config['model']['dropout'],
            num_features=num_features
        )
    elif model_type == "baseline":
        return BaselineModel(
            num_features=num_features,
            hidden_size=config['model'].get('hidden_size', 128),
            dropout=config['model']['dropout']
        )
    elif model_type == "ensemble":
        # Create an ensemble of different models
        models = [
            LSTMClassifier(
                vocab_size=vocab_size,
                embedding_dim=config['model']['embedding_dim'],
                hidden_size=config['model']['hidden_size'],
                num_layers=config['model']['num_layers'],
                dropout=config['model']['dropout'],
                bidirectional=True,
                num_features=num_features
            ),
            MultiScaleCNN(
                vocab_size=vocab_size,
                embedding_dim=config['model']['embedding_dim'],
                num_filters=config['model']['hidden_size'],
                filter_sizes=[2, 3, 5],
                dropout=config['model']['dropout'],
                num_features=num_features
            )
        ]
        return EnsembleModel(models)
    else:
        raise ValueError(f"Unknown model type: {model_type}")

def get_loss_function(loss_type='bce', alpha=1, gamma=2):
    """Get loss function with options for handling class imbalance"""
    if loss_type == 'bce':
        return nn.BCELoss()
    elif loss_type == 'focal':
        return FocalLoss(alpha=alpha, gamma=gamma)
    else:
        raise ValueError(f"Unknown loss type: {loss_type}")