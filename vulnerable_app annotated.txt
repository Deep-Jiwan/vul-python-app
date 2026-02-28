"""
INTENTIONALLY VULNERABLE WEB APPLICATION
=========================================
WARNING: This application contains MULTIPLE SECURITY VULNERABILITIES by design.
DO NOT deploy this to production or expose to the internet.

Purpose: Testing SAST and DAST security scanning tools for AI Recruiter 2.0 M.Tech Project
Contains: All 27 vulnerability types from OWASP Top 20 and additional security issues

Each vulnerability is clearly marked with comments for educational purposes.
"""

from flask import Flask, request, Response, redirect, session, make_response, render_template_string
import sqlite3
import os
import pickle
import hashlib
import time
import secrets
import subprocess
import urllib.request
import xml.etree.ElementTree as ET
from Crypto.Cipher import DES
import html

# VULNERABILITY #18: Credential Management - Hardcoded Credentials
ADMIN_USERNAME = "admin"  # Hardcoded username
ADMIN_PASSWORD = "password123"  # Hardcoded password in cleartext
DATABASE_PASSWORD = "dbpass123"  # Database credentials in code
API_KEY = "sk_live_51234567890abcdef"  # API key hardcoded

app = Flask(__name__)

# VULNERABILITY #8: Session ID Cookie Not Marked Secure
# VULNERABILITY #6: Missing Session Timeout
# Missing: SESSION_COOKIE_SECURE = True
# Missing: SESSION_COOKIE_HTTPONLY = True
# Missing: PERMANENT_SESSION_LIFETIME
app.secret_key = "insecure_secret_key_123"  # Weak secret key

# VULNERABILITY #9: Clickjacking - Missing X-Frame-Options
# VULNERABILITY #11: Cache Info in Browser - Missing Cache-Control headers
# (These are NOT configured, allowing vulnerabilities)

# Global session store for session fixation vulnerability
user_sessions = {}

# Global file handles (for resource shutdown vulnerability)
open_files = []


# ============================================================================
# DATABASE SETUP
# ============================================================================

def init_database():
    """Initialize SQLite database with sample data"""
    conn = sqlite3.connect('vulnerable_app.db')
    cursor = conn.cursor()
    
    # Users table
    cursor.execute('''CREATE TABLE IF NOT EXISTS users 
                     (id INTEGER PRIMARY KEY, username TEXT, password TEXT, email TEXT, role TEXT)''')
    cursor.execute("DELETE FROM users")
    
    # VULNERABILITY #17: Risky Crypto Algorithm - Using MD5 for password hashing
    weak_hash = hashlib.md5("password123".encode()).hexdigest()
    cursor.execute("INSERT INTO users VALUES (1, 'admin', ?, 'admin@example.com', 'admin')", (weak_hash,))
    cursor.execute("INSERT INTO users VALUES (2, 'alice', 'alice123', 'alice@example.com', 'user')")
    cursor.execute("INSERT INTO users VALUES (3, 'bob', 'bob456', 'bob@example.com', 'user')")
    
    # Accounts table for IDOR vulnerability
    cursor.execute('''CREATE TABLE IF NOT EXISTS accounts 
                     (id INTEGER PRIMARY KEY, username TEXT, balance REAL, account_number TEXT)''')
    cursor.execute("DELETE FROM accounts")
    cursor.execute("INSERT INTO accounts VALUES (1, 'alice', 1000.00, 'ACC001')")
    cursor.execute("INSERT INTO accounts VALUES (2, 'bob', 500.00, 'ACC002')")
    
    conn.commit()
    conn.close()


# ============================================================================
# VULNERABILITY #1: SQL INJECTION
# ============================================================================

@app.route('/login', methods=['GET', 'POST'])
def login():
    """
    VULNERABILITY #1: SQL Injection - Direct string concatenation in SQL query
    VULNERABILITY #7: GET vs POST - Accepting sensitive data via GET
    VULNERABILITY #3: Information Leakage - Detailed error messages
    """
    if request.method == 'GET':
        # VULNERABILITY #7: Accepting password via GET (should only use POST)
        username = request.args.get('username', '')
        password = request.args.get('password', '')
    else:
        username = request.form.get('username', '')
        password = request.form.get('password', '')
    
    if not username or not password:
        return render_template_string('''
            <h2>Login</h2>
            <form method="POST">
                Username: <input name="username"><br>
                Password: <input type="password" name="password"><br>
                <input type="submit" value="Login">
            </form>
        ''')
    
    try:
        conn = sqlite3.connect('vulnerable_app.db')
        cursor = conn.cursor()
        
        # VULNERABILITY #1: SQL Injection - Unsafe string concatenation
        query = f"SELECT * FROM users WHERE username = '{username}' AND password = '{password}'"
        cursor.execute(query)
        user = cursor.fetchone()
        conn.close()
        
        if user:
            session['username'] = user[1]
            session['role'] = user[4]
            return f"<h2>Login successful! Welcome {user[1]}</h2><br><a href='/profile'>View Profile</a>"
        else:
            # VULNERABILITY #3: Information Leakage - Revealing which field is wrong
            return f"<h2>Login failed for user: {username}</h2><p>Invalid credentials provided</p>"
    
    except Exception as e:
        # VULNERABILITY #3: Information Leakage - Exposing stack traces
        return f"<h2>Database Error</h2><pre>{str(e)}</pre>"


# ============================================================================
# VULNERABILITY #2: CROSS-SITE SCRIPTING (XSS)
# ============================================================================

@app.route('/profile')
def profile():
    """
    VULNERABILITY #2: XSS - Unsanitized user input rendered in HTML
    VULNERABILITY #10: Password Hint - Displaying sensitive information
    """
    username = request.args.get('name', session.get('username', 'Guest'))
    
    # VULNERABILITY #2: XSS - No HTML escaping
    html_content = f'''
        <h1>User Profile</h1>
        <p>Welcome, {username}!</p>
        <p>Your comment: {request.args.get('comment', 'No comment')}</p>
    '''
    
    # VULNERABILITY #10: Displaying password hint in cleartext
    if username == 'admin':
        html_content += f'<p style="color:red;">Password Hint: {ADMIN_PASSWORD}</p>'
    
    return render_template_string(html_content)


# ============================================================================
# VULNERABILITY #4: FRAME INJECTION
# ============================================================================

@app.route('/frame_content')
def frame_content():
    """
    VULNERABILITY #4: Frame Injection - Allowing arbitrary iframe sources
    """
    frame_url = request.args.get('url', 'https://example.com')
    
    # VULNERABILITY #4: No validation of iframe source
    html_content = f'''
        <h2>External Content</h2>
        <iframe src="{frame_url}" width="800" height="600"></iframe>
    '''
    return render_template_string(html_content)


# ============================================================================
# VULNERABILITY #5: OPEN URL REDIRECTION
# ============================================================================

@app.route('/redirect')
def open_redirect():
    """
    VULNERABILITY #5: Open URL Redirection - Unvalidated redirects
    """
    target_url = request.args.get('url', '/')
    
    # VULNERABILITY #5: No validation of redirect target
    return redirect(target_url)


# ============================================================================
# VULNERABILITY #12: WEAK ENCRYPTION
# ============================================================================

@app.route('/encrypt')
def encrypt_data():
    """
    VULNERABILITY #12: Weak Encryption - Using DES (deprecated algorithm)
    VULNERABILITY #18: Hardcoded encryption key
    """
    data = request.args.get('data', 'secret message')
    
    # VULNERABILITY #12: Using DES (broken encryption algorithm)
    # VULNERABILITY #18: Hardcoded encryption key
    key = b'8bytekey'  # DES requires 8-byte key
    cipher = DES.new(key, DES.MODE_ECB)
    
    # Pad data to 8-byte blocks
    padded_data = data + ' ' * (8 - len(data) % 8)
    encrypted = cipher.encrypt(padded_data.encode())
    
    return f"<h2>Encrypted Data (using weak DES):</h2><p>{encrypted.hex()}</p>"


# ============================================================================
# VULNERABILITY #13: CRLF INJECTION
# ============================================================================

@app.route('/set_header')
def crlf_injection():
    """
    VULNERABILITY #13: CRLF Injection - Unsanitized input in HTTP headers
    """
    username = request.args.get('username', 'Guest')
    
    response = Response("Welcome!")
    
    # VULNERABILITY #13: CRLF Injection - No sanitization of newlines
    response.headers['X-Username'] = username  # Can inject \r\n to add headers
    
    return response


# ============================================================================
# VULNERABILITY #14: TRUST BOUNDARY VIOLATION
# ============================================================================

@app.route('/process_data')
def trust_boundary():
    """
    VULNERABILITY #14: Trust Boundary Violation - Mixing trusted and untrusted data
    """
    user_input = request.args.get('input', '')
    
    # VULNERABILITY #14: Mixing untrusted user input with trusted session data without validation
    trusted_role = session.get('role', 'guest')
    combined_data = user_input + ':' + trusted_role
    
    # Directly using combined data without validation
    return f"<h2>Processing: {combined_data}</h2>"


# ============================================================================
# VULNERABILITY #15: DIRECTORY TRAVERSAL
# ============================================================================

@app.route('/download')
def directory_traversal():
    """
    VULNERABILITY #15: Directory Traversal - Unvalidated file path
    """
    filename = request.args.get('file', 'readme.txt')
    
    try:
        # VULNERABILITY #15: No path validation, allows ../../../etc/passwd
        with open(filename, 'r') as f:
            content = f.read()
        return f"<pre>{content}</pre>"
    except Exception as e:
        return f"Error reading file: {str(e)}"


# ============================================================================
# VULNERABILITY #16: SESSION FIXATION
# ============================================================================

@app.route('/login_with_session')
def session_fixation():
    """
    VULNERABILITY #16: Session Fixation - Accepting session ID from user
    """
    username = request.args.get('username')
    password = request.args.get('password')
    session_id = request.args.get('session_id')  # Attacker can provide this
    
    if username == ADMIN_USERNAME and password == ADMIN_PASSWORD:
        # VULNERABILITY #16: Using user-provided session ID
        if session_id:
            user_sessions[session_id] = username
            return f"Logged in with session: {session_id}"
        else:
            new_session = secrets.token_hex(16)
            user_sessions[new_session] = username
            return f"Logged in with new session: {new_session}"
    
    return "Login failed"


# ============================================================================
# VULNERABILITY #19: SQL INJECTION VIA ORM
# ============================================================================

@app.route('/search')
def sql_injection_orm():
    """
    VULNERABILITY #19: SQL Injection via ORM - Raw SQL in ORM query
    """
    search_term = request.args.get('q', '')
    
    conn = sqlite3.connect('vulnerable_app.db')
    cursor = conn.cursor()
    
    # VULNERABILITY #19: Using raw SQL with string formatting even in "ORM-style" code
    query = f"SELECT username, email FROM users WHERE username LIKE '%{search_term}%'"
    cursor.execute(query)
    results = cursor.fetchall()
    conn.close()
    
    return f"<h2>Search Results:</h2><pre>{results}</pre>"


# ============================================================================
# VULNERABILITY #20: RESOURCE SHUTDOWN
# ============================================================================

@app.route('/read_log')
def resource_leak():
    """
    VULNERABILITY #20: Resource Shutdown - File handles not properly closed
    """
    log_file = request.args.get('log', 'app.log')
    
    # VULNERABILITY #20: Opening file without proper closure (no try-finally or with statement)
    f = open(log_file, 'w')
    f.write('Log entry: ' + str(time.time()))
    # Missing f.close() - resource leak
    open_files.append(f)
    
    return "Log written (file handle leaked)"


# ============================================================================
# VULNERABILITY #21: CSRF (Cross-Site Request Forgery)
# ============================================================================

@app.route('/transfer_funds', methods=['GET', 'POST'])
def csrf_vulnerability():
    """
    VULNERABILITY #21: CSRF - No CSRF token validation
    """
    if request.method == 'POST' or request.method == 'GET':
        from_account = request.values.get('from')
        to_account = request.values.get('to')
        amount = request.values.get('amount')
        
        # VULNERABILITY #21: No CSRF token check - state-changing operation without protection
        conn = sqlite3.connect('vulnerable_app.db')
        cursor = conn.cursor()
        cursor.execute(f"UPDATE accounts SET balance = balance - {amount} WHERE username = '{from_account}'")
        cursor.execute(f"UPDATE accounts SET balance = balance + {amount} WHERE username = '{to_account}'")
        conn.commit()
        conn.close()
        
        return f"<h2>Transferred ${amount} from {from_account} to {to_account}</h2>"
    
    return '''
        <h2>Transfer Funds (CSRF Vulnerable)</h2>
        <form method="POST">
            From: <input name="from"><br>
            To: <input name="to"><br>
            Amount: <input name="amount"><br>
            <input type="submit" value="Transfer">
        </form>
    '''


# ============================================================================
# VULNERABILITY #22: SSRF (Server-Side Request Forgery)
# ============================================================================

@app.route('/fetch_url')
def ssrf_vulnerability():
    """
    VULNERABILITY #22: SSRF - Fetching arbitrary URLs provided by user
    """
    url = request.args.get('url', 'http://example.com')
    
    try:
        # VULNERABILITY #22: No validation of URL, can access internal resources
        response = urllib.request.urlopen(url, timeout=5)
        content = response.read().decode('utf-8', errors='ignore')
        return f"<h2>Fetched Content:</h2><pre>{content[:500]}</pre>"
    except Exception as e:
        return f"Error fetching URL: {str(e)}"


# ============================================================================
# VULNERABILITY #23: BROKEN ACCESS CONTROL (IDOR)
# ============================================================================

@app.route('/account/<account_id>')
def idor_vulnerability(account_id):
    """
    VULNERABILITY #23: IDOR - No authorization check for account access
    """
    conn = sqlite3.connect('vulnerable_app.db')
    cursor = conn.cursor()
    
    # VULNERABILITY #23: No check if current user owns this account
    cursor.execute(f"SELECT * FROM accounts WHERE id = {account_id}")
    account = cursor.fetchone()
    conn.close()
    
    if account:
        return f"<h2>Account Details</h2><p>Username: {account[1]}<br>Balance: ${account[2]}<br>Account: {account[3]}</p>"
    else:
        return "Account not found"


# ============================================================================
# VULNERABILITY #24: INSECURE DESERIALIZATION
# ============================================================================

@app.route('/load_object', methods=['POST'])
def insecure_deserialization():
    """
    VULNERABILITY #24: Insecure Deserialization - Using pickle on untrusted data
    """
    data = request.data
    
    try:
        # VULNERABILITY #24: Deserializing untrusted data with pickle
        obj = pickle.loads(data)
        return f"<h2>Deserialized Object:</h2><pre>{obj}</pre>"
    except Exception as e:
        return f"Error deserializing: {str(e)}"


# ============================================================================
# VULNERABILITY #25: COMMAND INJECTION
# ============================================================================

@app.route('/ping')
def command_injection():
    """
    VULNERABILITY #25: Command Injection - Unsanitized input in system command
    """
    host = request.args.get('host', 'localhost')
    
    # VULNERABILITY #25: Direct use of user input in shell command
    if os.name == 'nt':  # Windows
        command = f'ping -n 2 {host}'
    else:  # Linux/Mac
        command = f'ping -c 2 {host}'
    
    try:
        result = subprocess.check_output(command, shell=True, stderr=subprocess.STDOUT, timeout=5)
        return f"<h2>Ping Results:</h2><pre>{result.decode()}</pre>"
    except Exception as e:
        return f"Error executing command: {str(e)}"


# ============================================================================
# VULNERABILITY #26: XXE (XML External Entity)
# ============================================================================

@app.route('/parse_xml', methods=['POST'])
def xxe_vulnerability():
    """
    VULNERABILITY #26: XXE - Parsing XML with external entities enabled
    """
    xml_data = request.data.decode()
    
    try:
        # VULNERABILITY #26: Using vulnerable XML parser (ElementTree can process entities)
        root = ET.fromstring(xml_data)
        result = [(child.tag, child.text) for child in root]
        return f"<h2>Parsed XML:</h2><pre>{result}</pre>"
    except Exception as e:
        return f"Error parsing XML: {str(e)}"


# ============================================================================
# ADDITIONAL ROUTES
# ============================================================================

@app.route('/health')
def health():
    """Health check endpoint for monitoring"""
    return {'status': 'healthy', 'service': 'flask-app'}, 200


@app.route('/')
def index():
    """Home page with links to all vulnerable endpoints"""
    return '''
        <h1>Intentionally Vulnerable Web Application</h1>
        <p><strong>WARNING:</strong> This application contains security vulnerabilities for testing purposes.</p>
        
        <h2>Available Endpoints:</h2>
        <ul>
            <li><a href="/health">/health</a> - Health check endpoint</li>
            <li><a href="/login">/login</a> - SQL Injection, Info Leakage, GET vs POST</li>
            <li><a href="/profile?name=test">/profile</a> - XSS, Password Disclosure</li>
            <li><a href="/frame_content?url=https://example.com">/frame_content</a> - Frame Injection</li>
            <li><a href="/redirect?url=https://evil.com">/redirect</a> - Open Redirect</li>
            <li><a href="/encrypt?data=secret">/encrypt</a> - Weak Encryption (DES)</li>
            <li><a href="/set_header?username=test">/set_header</a> - CRLF Injection</li>
            <li><a href="/process_data?input=test">/process_data</a> - Trust Boundary</li>
            <li><a href="/download?file=readme.txt">/download</a> - Directory Traversal</li>
            <li><a href="/login_with_session?username=admin&password=password123">/login_with_session</a> - Session Fixation</li>
            <li><a href="/search?q=alice">/search</a> - SQL Injection via ORM</li>
            <li><a href="/read_log?log=test.log">/read_log</a> - Resource Leak</li>
            <li><a href="/transfer_funds">/transfer_funds</a> - CSRF</li>
            <li><a href="/fetch_url?url=http://localhost:5000">/fetch_url</a> - SSRF</li>
            <li><a href="/account/1">/account/1</a> - IDOR/Access Control</li>
            <li>/load_object (POST) - Insecure Deserialization</li>
            <li><a href="/ping?host=127.0.0.1">/ping</a> - Command Injection</li>
            <li>/parse_xml (POST) - XXE</li>
        </ul>
        
        <h2>Configuration Vulnerabilities:</h2>
        <ul>
            <li>Missing Session Timeout (#6)</li>
            <li>Cookie Flags Not Set (#8 - Secure, HttpOnly)</li>
            <li>Missing X-Frame-Options (#9 - Clickjacking)</li>
            <li>Missing Cache-Control Headers (#11)</li>
            <li>Hardcoded Credentials (#18)</li>
            <li>Weak Crypto Algorithm - MD5 (#17)</li>
        </ul>
    '''


@app.after_request
def after_request(response):
    """
    VULNERABILITY #9: Clickjacking - Missing X-Frame-Options header
    VULNERABILITY #11: Cache Info - Missing Cache-Control headers
    """
    # VULNERABILITY #9: NOT setting X-Frame-Options (should be 'DENY' or 'SAMEORIGIN')
    # response.headers['X-Frame-Options'] = 'DENY'  # COMMENTED OUT - vulnerable
    
    # VULNERABILITY #11: NOT setting Cache-Control (should prevent caching sensitive data)
    # response.headers['Cache-Control'] = 'no-store, no-cache, must-revalidate'  # COMMENTED OUT
    
    return response


# ============================================================================
# MAIN
# ============================================================================

if __name__ == '__main__':
    print("=" * 70)
    print("STARTING INTENTIONALLY VULNERABLE WEB APPLICATION")
    print("=" * 70)
    print("WARNING: This application contains SECURITY VULNERABILITIES!")
    print("DO NOT expose this to the internet or use in production.")
    print("Purpose: Testing SAST/DAST security scanning tools")
    print("=" * 70)
    
    # Initialize database
    init_database()
    print("\n[+] Database initialized with sample data")
    print("[+] Starting Flask server on http://127.0.0.1:5000")
    print("[+] Press Ctrl+C to stop\n")
    
    # VULNERABILITY: Running with debug=True exposes sensitive information
    app.run(debug=True, host='127.0.0.1', port=3000)
