# Authentication Dataset Documentation

## Overview
This dataset contains synthetic authentication events generated for ML-based anomaly detection training. The data includes both normal user behavior and various attack patterns.

## Data Collection

### Environment
- **Type**: Synthetic test environment
- **Authentication**: Simulated login endpoints
- **Duration**: Multiple sessions over simulated time periods

### Events Captured
- Login attempts (success/failure)
- Session creation/destruction
- Authentication state changes

## Labeling Heuristics

### Automated Labeling Rules

#### Brute-Force Detection
```python
is_bruteforce_candidate = 1 if:
    attempt_count_for_username >= 10 within 10 minutes OR
    attempt_count_from_ip >= 50 within 10 minutes OR
    distinct_ips_for_username >= 20 within 60 minutes