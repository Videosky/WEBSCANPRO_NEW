# IDOR ML Model Evaluation Report

## Model Overview
- **Model Type**: Pipeline
- **Training Date**: 2025-11-07T16:46:26.780722
- **Feature Count**: 12
- **Best Validation Score**: 1.0000

## Test Set Performance

### Basic Metrics
- **Accuracy**: 0.9000
- **Precision**: 1.0000
- **Recall**: 0.7500
- **F1-Score**: 0.8571
- **ROC-AUC**: 0.7500

### Optimal Threshold
The optimal classification threshold for maximizing F1-score is **0.6065**

### Confusion Matrix
```
True Negatives: 6
False Positives: 0
False Negatives: 1
True Positives: 3
```

### Detailed Classification Report
```
              precision    recall  f1-score   support

           0       0.86      1.00      0.92         6
           1       1.00      0.75      0.86         4

    accuracy                           0.90        10
   macro avg       0.93      0.88      0.89        10
weighted avg       0.91      0.90      0.90        10

```

## Feature Importance

Feature importance not available for this model type.

## Model Comparison

Model Performance Comparison:

- **logistic_regression**: F1 = 1.0000
- **random_forest**: F1 = 1.0000
- **xgboost**: F1 = 1.0000

## Recommendations
1. **Deployment Threshold**: Use 0.606 for balanced precision/recall
2. **Monitoring**: Track precision/recall weekly for model drift
3. **Retraining**: Retrain when F1-score drops below 0.7

---
*Generated automatically by IDOR ML Evaluation System*