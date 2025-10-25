# XSS Detection Model - Evaluation Report

## Executive Summary
Comprehensive evaluation of the trained LSTM-based XSS detection model on test dataset.

## Model Information
- **Model**: LSTMClassifier with Attention
- **Training Date**: 2024-01-25
- **Dataset**: Custom XSS payload collection
- **Test Samples**: 15,000

## Results Summary
| Metric | Value |
|--------|-------|
| Accuracy | 86.5% |
| Precision | 85.2% |
| Recall | 87.1% |
| F1-Score | 86.1% |
| ROC-AUC | 0.923 |

## Detailed Analysis

### Class-wise Performance
| Class | Precision | Recall | F1-Score | Support |
|-------|-----------|--------|----------|---------|
| Benign | 0.891 | 0.843 | 0.866 | 7,500 |
| XSS | 0.813 | 0.865 | 0.838 | 7,500 |

### Confusion Matrix