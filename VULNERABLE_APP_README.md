# Intentionally Vulnerable Web Application

## ⚠️ WARNING
**This application contains INTENTIONAL SECURITY VULNERABILITIES for testing purposes only.**
- **DO NOT deploy to production**
- **DO NOT expose to the internet**
- **Use only in isolated testing environments**

## Purpose

This application is designed for testing the **AI Recruiter 2.0** M.Tech project that aims to:
- Automate security vulnerability detection using AI
- Build knowledge graphs from source code
- Use Adjacency, Incidence, and Laplacian matrices for vulnerability analysis

This consolidated vulnerable application provides a single target for both:
- **SAST (Static Application Security Testing)** - Code pattern analysis
- **DAST (Dynamic Application Security Testing)** - Runtime behavior testing

## Vulnerabilities Included

All **27 vulnerabilities** from the OWASP Top 20 and additional security issues are present:

### Detectable by Both SAST and DAST (19)
1. **SQL Injection** - Direct string concatenation in queries
2. **Cross-Site Scripting (XSS)** - Unsanitized HTML output
4. **Frame Injection** - Unvalidated iframe sources
5. **Open URL Redirection** - Unvalidated redirect targets
7. **GET vs POST** - Sensitive data via GET parameters
10. **Password in Cleartext** - Displaying sensitive information
12. **Weak Encryption** - Using deprecated DES algorithm
13. **CRLF Injection** - Unsanitized HTTP headers
14. **Trust Boundary Violation** - Mixing trusted/untrusted data
15. **Directory Traversal** - Unvalidated file paths
17. **Risky Crypto Algorithm** - MD5 password hashing
18. **Credential Management** - Hardcoded credentials
19. **SQL Injection via ORM** - Raw SQL in ORM queries
20. **Resource Shutdown** - File handles not closed
22. **SSRF** - Fetching arbitrary URLs
24. **Insecure Deserialization** - Using pickle on untrusted data
25. **Command Injection** - Unsanitized shell commands
26. **XXE** - XML External Entity processing

### Detectable Primarily by DAST (8)
3. **Information Leakage** - Detailed error messages
6. **Missing Session Timeout** - No session expiration
8. **Session Cookie Flags** - Missing Secure/HttpOnly
9. **Clickjacking** - Missing X-Frame-Options header
11. **Cache Information** - Missing Cache-Control headers
16. **Session Fixation** - Accepting external session IDs
21. **CSRF** - No CSRF token validation
23. **Broken Access Control** - IDOR vulnerabilities

## Installation

### Prerequisites
- Python 3.7+
- pip

### Setup
```bash
# Install dependencies
pip install -r requirements.txt

# Run the application
python vulnerable_app.py
```

The application will start on `http://127.0.0.1:5000`

## Application Structure

```
vulnerable_app.py           # Main Flask application with all vulnerabilities
requirements.txt            # Python dependencies
test_payloads.md           # DAST testing payloads and examples
VULNERABLE_APP_README.md   # This file
```

## Testing the Application

### Manual Testing
1. Start the application: `python vulnerable_app.py`
2. Visit `http://127.0.0.1:5000` for a list of all vulnerable endpoints
3. Follow links or use the payloads from `test_payloads.md`

### SAST Testing
Use static analysis tools on the source code:

**Python SAST Tools:**
- **Bandit**: `bandit -r vulnerable_app.py`
- **Semgrep**: `semgrep --config=auto vulnerable_app.py`
- **PyLint Security**: `pylint vulnerable_app.py`
- **SonarQube**: Import project and run analysis

Expected findings:
- Hardcoded credentials
- SQL injection patterns
- Command injection risks
- Weak cryptography
- Insecure deserialization
- XSS vulnerabilities

### DAST Testing
Use dynamic testing tools on the running application:

**DAST Tools:**
- **OWASP ZAP**
  ```bash
  zap-cli quick-scan http://127.0.0.1:5000
  ```

- **Burp Suite**
  - Configure browser proxy
  - Spider the application
  - Run active scanner

- **Nikto**
  ```bash
  nikto -h http://127.0.0.1:5000
  ```

- **SQLMap**
  ```bash
  sqlmap -u "http://127.0.0.1:5000/login?username=test&password=test" --batch
  ```

Expected findings:
- Active exploitation of SQL injection
- XSS execution
- CSRF token absence
- Missing security headers
- Session management issues
- Access control bypasses

## Endpoint Reference

| Endpoint | Method | Vulnerabilities |
|----------|--------|-----------------|
| `/` | GET | Index page with links |
| `/login` | GET/POST | #1, #3, #7 - SQL Injection, Info Leakage, GET vs POST |
| `/profile` | GET | #2, #10 - XSS, Password Cleartext |
| `/frame_content` | GET | #4 - Frame Injection |
| `/redirect` | GET | #5 - Open URL Redirection |
| `/encrypt` | GET | #12, #18 - Weak Encryption, Hardcoded Key |
| `/set_header` | GET | #13 - CRLF Injection |
| `/process_data` | GET | #14 - Trust Boundary Violation |
| `/download` | GET | #15 - Directory Traversal |
| `/login_with_session` | GET | #16 - Session Fixation |
| `/search` | GET | #19 - SQL Injection via ORM |
| `/read_log` | GET | #20 - Resource Leak |
| `/transfer_funds` | GET/POST | #21 - CSRF |
| `/fetch_url` | GET | #22 - SSRF |
| `/account/<id>` | GET | #23 - IDOR/Access Control |
| `/load_object` | POST | #24 - Insecure Deserialization |
| `/ping` | GET | #25 - Command Injection |
| `/parse_xml` | POST | #26 - XXE |

## Configuration Vulnerabilities

The application has several insecure configurations (see source code comments):

- **Session timeout not configured** - Sessions never expire
- **Cookie flags not set** - Secure, HttpOnly, SameSite missing
- **X-Frame-Options missing** - Clickjacking possible
- **Cache-Control missing** - Sensitive data cached
- **Debug mode enabled** - Detailed error traces
- **Hardcoded secrets** - API keys, passwords in code
- **MD5 password hashing** - Cryptographically broken

## Integration with AI Recruiter 2.0

This application serves as:

1. **Training Data** - For machine learning models to learn vulnerability patterns
2. **Test Target** - For validating Knowledge Graph construction from code
3. **Benchmark** - Measuring detection accuracy (all 27 vulnerabilities known)
4. **Graph Analysis** - Testing Adjacency/Incidence/Laplacian matrix analysis

### Expected Graph Features
- **Nodes**: Functions, variables, database operations, user inputs, outputs
- **Edges**: Data flow, control flow, function calls
- **Patterns**: Untrusted input → dangerous function (no sanitization)

## Sample Attack Scenarios

### Scenario 1: SQL Injection
```bash
curl "http://127.0.0.1:5000/login?username=admin'--&password=x"
```
Bypasses authentication by commenting out password check.

### Scenario 2: XSS Attack
```bash
curl "http://127.0.0.1:5000/profile?name=<script>alert(document.cookie)</script>"
```
Executes JavaScript to steal session cookies.

### Scenario 3: Command Injection
```bash
curl "http://127.0.0.1:5000/ping?host=127.0.0.1;whoami"
```
Executes arbitrary system commands.

### Scenario 4: Directory Traversal
```bash
curl "http://127.0.0.1:5000/download?file=../../../../etc/passwd"
```
Reads arbitrary files from the system.

### Scenario 5: CSRF Attack
Create HTML page:
```html
<form action="http://127.0.0.1:5000/transfer_funds" method="POST">
    <input type="hidden" name="from" value="alice">
    <input type="hidden" name="to" value="attacker">
    <input type="hidden" name="amount" value="1000">
</form>
<script>document.forms[0].submit();</script>
```

## Comparison with Original Files

This consolidated application differs from the original 27 files (00-26):

**Original Files:**
- Individual demonstrations
- Mix of Flask and standalone Python
- Some with safe alternatives shown
- Educational focus with detailed explanations

**This Application:**
- Single unified web application
- All vulnerabilities active simultaneously
- No safe alternatives (purely vulnerable)
- Testing/detection focus
- Realistic web application structure

## Educational Value

This application demonstrates:

1. **How vulnerabilities exist in real code** - Not just theoretical examples
2. **Compound risks** - Multiple vulnerabilities in one application
3. **Detection challenges** - Some obvious (SAST), some subtle (DAST only)
4. **Real-world patterns** - Common coding mistakes that introduce vulnerabilities

## Database Schema

The application creates `vulnerable_app.db` with:

**Users Table:**
```sql
CREATE TABLE users (
    id INTEGER PRIMARY KEY,
    username TEXT,
    password TEXT,  -- Hashed with MD5 (weak!)
    email TEXT,
    role TEXT
)
```

**Accounts Table:**
```sql
CREATE TABLE accounts (
    id INTEGER PRIMARY KEY,
    username TEXT,
    balance REAL,
    account_number TEXT
)
```

## Security Testing Checklist

- [ ] All 27 vulnerabilities detected by SAST/DAST?
- [ ] Knowledge graph correctly identifies data flows?
- [ ] Matrix analysis detects vulnerability patterns?
- [ ] False positive rate acceptable?
- [ ] Detection time reasonable?
- [ ] Severity scoring accurate?

## References

- OWASP Top 10: https://owasp.org/www-project-top-ten/
- UpGuard Top 20: https://www.upguard.com/blog/top-20-owasp-vulnerabilities-and-how-to-fix-them
- OWASP Testing Guide: https://owasp.org/www-project-web-security-testing-guide/

## License

This code is for educational and testing purposes only. Use at your own risk.

## Author

Created for M.Tech Project: AI Recruiter 2.0
Testing framework for automated security vulnerability detection using AI and Knowledge Graphs.
