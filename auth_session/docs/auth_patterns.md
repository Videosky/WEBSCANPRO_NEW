# Authentication Patterns & Attack Scenarios

## Normal Authentication Flows

### Normal Login Flow
- **Description**: Standard user authentication with valid credentials
- **Flow**: POST /login → 200 OK → Session creation
- **Characteristics**: 
  - Single attempt per session
  - Reasonable time between attempts
  - Consistent geolocation/user-agent

### Session Management
- **Session Creation**: New session token on successful login
- **Session Refresh**: Token renewal before expiry
- **Logout**: Explicit session invalidation
- **Timeout**: Automatic session expiry after inactivity

## Failed Login Scenarios

### Bad Password
- **Description**: Valid username with incorrect password
- **Response**: HTTP 401 Unauthorized
- **Characteristics**: Single or few attempts

### Invalid User
- **Description**: Non-existent username
- **Response**: HTTP 401 Unauthorized or 404 Not Found
- **Characteristics**: May indicate reconnaissance

### Account Lockout
- **Description**: Temporary account suspension after failed attempts
- **Response**: HTTP 423 Locked or 429 Too Many Requests
- **Characteristics**: Follows multiple rapid failures

## Attack Patterns

### Brute-Force Attacks
- **Description**: Rapid password guessing against single account
- **Characteristics**: 
  - High attempt frequency (10+ attempts/minute)
  - Single IP, multiple passwords
  - Consistent username, varying passwords

### Credential Stuffing
- **Description**: Using breached credentials across multiple accounts
- **Characteristics**:
  - Multiple usernames from single IP
  - Moderate attempt rate
  - Diverse username patterns

### Distributed Brute-Force
- **Description**: Coordinated attacks from multiple IPs
- **Characteristics**:
  - Same username from multiple IPs
  - Lower per-IP attempt rate
  - Synchronized timing patterns

### Slow/Low-and-Slow Attacks
- **Description**: Deliberately slow to evade rate limiting
- **Characteristics**:
  - Regular but infrequent attempts (1 attempt/5 minutes)
  - Persistence over long periods
  - Multiple IP rotation

### Account Takeover Indicators
- **Description**: Suspicious successful authentication
- **Characteristics**:
  - Login after multiple failures
  - Geolocation changes within short timeframe
  - Unusual user-agent or time patterns

### Session Attacks
- **Session Hijacking**: Token reuse across different IPs
- **Session Fixation**: Forcing known session tokens
- **Long-lived Sessions**: Extended session durations

## Defense Mechanisms

### Rate Limiting
- IP-based throttling
- Account-based throttling
- Progressive delays

### Anomaly Detection
- Geolocation changes
- Device fingerprinting
- Behavioral biometrics

### Multi-Factor Authentication
- Time-based one-time passwords
- Push notifications
- Hardware tokens