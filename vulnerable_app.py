"""
WEB APPLICATION
===============
Basic web application for testing purposes.
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

# --------------------------------------------
ADMIN_USERNAME = "admin"
ADMIN_PASSWORD = "password123"
DATABASE_PASSWORD = "dbpass123"
API_KEY = "sk_live_51234567890abcdef"

app = Flask(__name__)

# --------------------------------------------
app.secret_key = "insecure_secret_key_123"

# --------------------------------------------

# --------------------------------------------
user_sessions = {}

# --------------------------------------------
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
    
    # --------------------------------------------
    weak_hash = hashlib.md5("password123".encode()).hexdigest()
    cursor.execute("INSERT INTO users VALUES (1, 'admin', ?, 'admin@example.com', 'admin')", (weak_hash,))
    cursor.execute("INSERT INTO users VALUES (2, 'alice', 'alice123', 'alice@example.com', 'user')")
    cursor.execute("INSERT INTO users VALUES (3, 'bob', 'bob456', 'bob@example.com', 'user')")
    
    # --------------------------------------------
    cursor.execute('''CREATE TABLE IF NOT EXISTS accounts 
                     (id INTEGER PRIMARY KEY, username TEXT, balance REAL, account_number TEXT)''')
    cursor.execute("DELETE FROM accounts")
    cursor.execute("INSERT INTO accounts VALUES (1, 'alice', 1000.00, 'ACC001')")
    cursor.execute("INSERT INTO accounts VALUES (2, 'bob', 500.00, 'ACC002')")
    
    conn.commit()
    conn.close()


# ============================================================================
# LOGIN ENDPOINT
# ============================================================================

@app.route('/login', methods=['GET', 'POST'])
def login():
    # --------------------------------------------
    if request.method == 'GET':
        # --------------------------------------------
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
        
        # --------------------------------------------
        query = f"SELECT * FROM users WHERE username = '{username}' AND password = '{password}'"
        cursor.execute(query)
        user = cursor.fetchone()
        conn.close()
        
        if user:
            session['username'] = user[1]
            session['role'] = user[4]
            return f"<h2>Login successful! Welcome {user[1]}</h2><br><a href='/profile'>View Profile</a>"
        else:
            # --------------------------------------------
            return f"<h2>Login failed for user: {username}</h2><p>Invalid credentials provided</p>"
    
    except Exception as e:
        # --------------------------------------------
        return f"<h2>Database Error</h2><pre>{str(e)}</pre>"


# ============================================================================
# PROFILE ENDPOINT
# ============================================================================

@app.route('/profile')
def profile():
    # --------------------------------------------
    username = request.args.get('name', session.get('username', 'Guest'))
    
    # --------------------------------------------
    html_content = f'''
        <h1>User Profile</h1>
        <p>Welcome, {username}!</p>
        <p>Your comment: {request.args.get('comment', 'No comment')}</p>
    '''
    
    # --------------------------------------------
    if username == 'admin':
        html_content += f'<p style="color:red;">Password Hint: {ADMIN_PASSWORD}</p>'
    
    return render_template_string(html_content)


# ============================================================================
# FRAME CONTENT ENDPOINT
# ============================================================================

@app.route('/frame_content')
def frame_content():
    # --------------------------------------------
    frame_url = request.args.get('url', 'https://example.com')
    
    # --------------------------------------------
    html_content = f'''
        <h2>External Content</h2>
        <iframe src="{frame_url}" width="800" height="600"></iframe>
    '''
    return render_template_string(html_content)


# ============================================================================
# REDIRECT ENDPOINT
# ============================================================================

@app.route('/redirect')
def open_redirect():
    # --------------------------------------------
    target_url = request.args.get('url', '/')
    
    # --------------------------------------------
    allowed_prefixes = ('/', 'https://example.com')
    if not target_url.startswith(allowed_prefixes):
        target_url = '/'
    
    return redirect(target_url)


# ============================================================================
# ENCRYPTION ENDPOINT
# ============================================================================

@app.route('/encrypt')
def encrypt_data():
    # --------------------------------------------
    data = request.args.get('data', 'secret message')
    
    # --------------------------------------------
    key = b'8bytekey'
    cipher = DES.new(key, DES.MODE_ECB)
    
    # --------------------------------------------
    padded_data = data + ' ' * (8 - len(data) % 8)
    encrypted = cipher.encrypt(padded_data.encode())
    
    return f"<h2>Encrypted Data:</h2><p>{encrypted.hex()}</p>"


# ============================================================================
# HEADER MANAGEMENT ENDPOINT
# ============================================================================

@app.route('/set_header')
def crlf_injection():
    # --------------------------------------------
    username = request.args.get('username', 'Guest')
    
    response = Response("Welcome!")
    
    # --------------------------------------------
    response.headers['X-Username'] = username
    
    return response


# ============================================================================
# DATA PROCESSING ENDPOINT
# ============================================================================

@app.route('/process_data')
def trust_boundary():
    # --------------------------------------------
    user_input = request.args.get('input', '')
    
    # --------------------------------------------
    trusted_role = session.get('role', 'guest')
    combined_data = user_input + ':' + trusted_role
    
    # --------------------------------------------
    return f"<h2>Processing: {combined_data}</h2>"


# ============================================================================
# FILE DOWNLOAD ENDPOINT
# ============================================================================

@app.route('/download')
def directory_traversal():
    # --------------------------------------------
    filename = request.args.get('file', 'readme.txt')
    
    try:
        # --------------------------------------------
        with open(filename, 'r') as f:
            content = f.read()
        return f"<pre>{content}</pre>"
    except Exception:
        return "Error reading file"


# ============================================================================
# SESSION LOGIN ENDPOINT
# ============================================================================

@app.route('/login_with_session')
def session_fixation():
    # --------------------------------------------
    username = request.args.get('username')
    password = request.args.get('password')
    session_id = request.args.get('session_id')
    
    if username == ADMIN_USERNAME and password == ADMIN_PASSWORD:
        # --------------------------------------------
        if session_id:
            user_sessions[session_id] = username
            return f"Logged in with session: {session_id}"
        else:
            new_session = secrets.token_hex(16)
            user_sessions[new_session] = username
            return f"Logged in with new session: {new_session}"
    
    return "Login failed"


# ============================================================================
# SEARCH ENDPOINT
# ============================================================================

@app.route('/search')
def sql_injection_orm():
    # --------------------------------------------
    search_term = request.args.get('q', '')
    
    conn = sqlite3.connect('vulnerable_app.db')
    cursor = conn.cursor()
    
    # --------------------------------------------
    query = f"SELECT username, email FROM users WHERE username LIKE '%{search_term}%'"
    cursor.execute(query)
    results = cursor.fetchall()
    conn.close()
    
    return f"<h2>Search Results:</h2><pre>{results}</pre>"


# ============================================================================
# LOG READING ENDPOINT
# ============================================================================

@app.route('/read_log')
def resource_leak():
    # --------------------------------------------
    log_file = request.args.get('log', 'app.log')
    
    # --------------------------------------------
    import os
    safe_dir = os.path.abspath('.')
    requested_path = os.path.abspath(log_file)
    if not requested_path.startswith(safe_dir):
        return "Error: Invalid file path"
    
    f = open(log_file, 'w')
    f.write('Log entry: ' + str(time.time()))
    # --------------------------------------------
    open_files.append(f)
    
    return "Log written successfully"


# ============================================================================
# FUND TRANSFER ENDPOINT
# ============================================================================

@app.route('/transfer_funds', methods=['GET', 'POST'])
def csrf_vulnerability():
    # --------------------------------------------
    if request.method == 'POST' or request.method == 'GET':
        from_account = request.values.get('from')
        to_account = request.values.get('to')
        amount = request.values.get('amount')
        
        # --------------------------------------------
        conn = sqlite3.connect('vulnerable_app.db')
        cursor = conn.cursor()
        cursor.execute(f"UPDATE accounts SET balance = balance - {amount} WHERE username = '{from_account}'")
        cursor.execute(f"UPDATE accounts SET balance = balance + {amount} WHERE username = '{to_account}'")
        conn.commit()
        conn.close()
        
        return f"<h2>Transferred ${amount} from {from_account} to {to_account}</h2>"
    
    return '''
        <h2>Transfer Funds</h2>
        <form method="POST">
            From: <input name="from"><br>
            To: <input name="to"><br>
            Amount: <input name="amount"><br>
            <input type="submit" value="Transfer">
        </form>
    '''


# ============================================================================
# URL FETCHER ENDPOINT
# ============================================================================

@app.route('/fetch_url')
def ssrf_vulnerability():
    # --------------------------------------------
    url = request.args.get('url', 'http://example.com')
    
    try:
        # --------------------------------------------
        import urllib.parse
        parsed = urllib.parse.urlparse(url)
        if parsed.scheme not in ('http', 'https'):
            return "Error: Only HTTP and HTTPS URLs are allowed"
        response = urllib.request.urlopen(url, timeout=5)
        content = response.read().decode('utf-8', errors='ignore')
        return f"<h2>Fetched Content:</h2><pre>{content[:500]}</pre>"
    except Exception as e:
        return f"Error fetching URL: {str(e)}"


# ============================================================================
# ACCOUNT DETAILS ENDPOINT
# ============================================================================

@app.route('/account/<account_id>')
def idor_vulnerability(account_id):
    # --------------------------------------------
    conn = sqlite3.connect('vulnerable_app.db')
    cursor = conn.cursor()
    
    # --------------------------------------------
    cursor.execute("SELECT * FROM accounts WHERE id = ?", (account_id,))
    account = cursor.fetchone()
    conn.close()
    
    if account:
        return f"<h2>Account Details</h2><p>Username: {account[1]}<br>Balance: ${account[2]}<br>Account: {account[3]}</p>"
    else:
        return "Account not found"


# ============================================================================
# OBJECT LOADER ENDPOINT
# ============================================================================

@app.route('/load_object', methods=['POST'])
def insecure_deserialization():
    # --------------------------------------------
    data = request.data
    
    try:
        # --------------------------------------------
        obj = pickle.loads(data)
        return f"<h2>Deserialized Object:</h2><pre>{obj}</pre>"
    except Exception:
        return f"Error deserializing: Invalid data format"


# ============================================================================
# PING ENDPOINT
# ============================================================================

@app.route('/ping')
def command_injection():
    # --------------------------------------------
    host = request.args.get('host', 'localhost')
    
    # --------------------------------------------
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
# XML PARSER ENDPOINT
# ============================================================================

@app.route('/parse_xml', methods=['POST'])
def xxe_vulnerability():
    # --------------------------------------------
    xml_data = request.data.decode()

    try:
        # --------------------------------------------
        parser = ET.XMLParser(resolve_entities=False)
        root = ET.fromstring(xml_data, parser=parser)
        result = [(child.tag, child.text) for child in root]
        return f"<h2>Parsed XML:</h2><pre>{result}</pre>"
    except Exception as e:
        return f"Error parsing XML: {str(e)}"


# ============================================================================
# INDEX AND UTILITY ROUTES
# ============================================================================

@app.route('/health')
def health():
    """Health check endpoint for monitoring"""
    return {'status': 'healthy', 'service': 'flask-app'}, 200


@app.route('/')
def index():
    """Home page with links to all endpoints"""
    return '''
        <h1>Web Application</h1>
        <p>Welcome to the application dashboard.</p>
        
        <h2>Available Endpoints:</h2>
        <ul>
            <li><a href="/health">/health</a> - Health check endpoint</li>
            <li><a href="/login">/login</a> - User login</li>
            <li><a href="/profile?name=test">/profile</a> - User profile</li>
            <li><a href="/frame_content?url=https://example.com">/frame_content</a> - Frame content viewer</li>
            <li><a href="/redirect?url=https://example.com">/redirect</a> - URL redirection</li>
            <li><a href="/encrypt?data=secret">/encrypt</a> - Data encryption</li>
            <li><a href="/set_header?username=test">/set_header</a> - Header management</li>
            <li><a href="/process_data?input=test">/process_data</a> - Data processing</li>
            <li><a href="/download?file=readme.txt">/download</a> - File download</li>
            <li><a href="/login_with_session?username=admin&password=password123">/login_with_session</a> - Session login</li>
            <li><a href="/search?q=alice">/search</a> - User search</li>
            <li><a href="/read_log?log=test.log">/read_log</a> - Log viewer</li>
            <li><a href="/transfer_funds">/transfer_funds</a> - Fund transfer</li>
            <li><a href="/fetch_url?url=http://localhost:5000">/fetch_url</a> - URL fetcher</li>
            <li><a href="/account/1">/account/1</a> - Account details</li>
            <li>/load_object (POST) - Object loader</li>
            <li><a href="/ping?host=127.0.0.1">/ping</a> - Network ping</li>
            <li>/parse_xml (POST) - XML parser</li>
        </ul>
    '''


@app.after_request
def after_request(response):
    # --------------------------------------------
    # --------------------------------------------
    # --------------------------------------------
    
    # --------------------------------------------
    # --------------------------------------------
    
    return response


# ============================================================================
# MAIN
# ============================================================================

def main():
    """Main entry point for the application"""
    print("=" * 70)
    print("STARTING WEB APPLICATION")
    print("=" * 70)
    print("Flask web server starting...")
    print("=" * 70)
    
    # --------------------------------------------
    init_database()
    print("\n[+] Database initialized with sample data")
    print("[+] Starting Flask server on http://127.0.0.1:3000")
    print("[+] Press Ctrl+C to stop\n")
    
    # --------------------------------------------
    app.run(debug=True, host='127.0.0.1', port=3000)


if __name__ == '__main__':
    main()
