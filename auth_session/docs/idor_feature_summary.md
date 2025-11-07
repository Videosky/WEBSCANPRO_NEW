# IDOR Feature Engineering Summary Report

## Dataset Overview
- Total requests: 50
- Unique endpoints: 4
- Unique users: 4
- Unauthorized requests: 22 (44.0%)

## Feature Summary
- Final feature count: 14
- Features: endpoint_encoded, param_key_count, param_type_pattern, status_encoded, response_length, sensitive_data_found, self_access, has_user_id, has_target_id, has_parameters, user_request_count, user_unauthorized_count, user_success_rate, is_unauthorized

## Parameter Statistics
- Requests with parameters: 0
- Average parameters per request: 0.00

## Status Code Distribution
- 200: 38 (76.0%)
- 403: 10 (20.0%)
- 404: 2 (4.0%)
