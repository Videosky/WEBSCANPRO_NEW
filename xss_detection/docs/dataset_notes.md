# XSS Response Dataset Documentation

## Dataset Overview
- **Total Samples**: 90
- **Malicious Samples**: 0
- **Benign Samples**: 90
- **Collection Date**: 2025-10-23
- **Target Application**: http://localhost:8080

## Data Collection Methodology

### Scanning Approach
- **Scanner**: FixedXSSScanner (Windows compatible)
- **Endpoints Tested**: 9 discovered endpoints
- **Payloads Used**: 10 reflected XSS payloads
- **Parameters**: Single parameter 'q' injection
- **Request Method**: GET

### Labeling Logic
A response is classified as `is_malicious = 1` if:
- Payload is reflected in response body AND
- Script indicators are present (script tags, event handlers, etc.)

### Feature Description
| Column | Description | Type | Example |
|--------|-------------|------|---------|
| payload_id | Payload identifier | Categorical | R1, R2 |
| endpoint | Target endpoint | Categorical | /, /login.php |
| url | Full request URL | Text | http://localhost:8080/login.php?q=payload |
| payload | XSS payload used | Text | `<script>alert(1)</script>` |
| status_code | HTTP status code | Numerical | 200 |
| response_time | Request duration (seconds) | Numerical | 0.040 |
| content_length | Response size (bytes) | Numerical | 1523 |
| reflected_payload | Payload reflection flag | Boolean | False |
| script_indicators_count | Number of XSS indicators | Numerical | 0, 1 |
| script_indicators | Types of indicators found | Categorical | script_tag |
| is_malicious | Classification label | Boolean | False |
| analysis_notes | Human-readable analysis | Text | "No XSS indicators found" |
| timestamp | Test timestamp | DateTime | 2025-10-23T19:42:05.887380 |

## Dataset Quality Assessment

### Strengths
- 100% successful requests (all status 200)
- Consistent response timing data
- Clean feature extraction
- Proper labeling based on heuristics

### Limitations
- No malicious samples detected (class imbalance)
- Limited to GET parameter injection
- Single parameter tested per endpoint

### Security Findings
- Application appears well-secured against reflected XSS
- Login page redirects suggest authentication requirements
- About.php contains static script tags (false positives)

## Usage for ML Training

This dataset is ready for:
1. **Feature Engineering**: Extract numerical features from existing columns
2. **Binary Classification**: Distinguish between benign and (future) malicious samples
3. **Anomaly Detection**: Identify unusual response patterns
4. **Model Validation**: Test XSS detection models

### Suggested Features for ML:
- Numerical: response_time, content_length, script_indicators_count
- Categorical: status_code, endpoint
- Boolean: reflected_payload, is_malicious
- Text-based: payload (for embedding), script_indicators