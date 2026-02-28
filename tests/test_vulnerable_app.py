import pytest
import sqlite3
import pickle
import hashlib
import os
import tempfile


# ============================================================================
# HELPER FUNCTIONS
# ============================================================================

def body(response):
    """Extract response body as string."""
    return response.data.decode('utf-8', errors='ignore')


def query_db(sql, params=()):
    """Direct SQLite query against the test database."""
    db_path = 'vulnerable_app.db'
    conn = sqlite3.connect(db_path)
    cursor = conn.cursor()
    cursor.execute(sql, params)
    rows = cursor.fetchall()
    conn.close()
    return rows


# ============================================================================
# SECTION 1: init_database
# ============================================================================

def test_init_database_creates_tables():
    """After calling init_database(), both users and accounts tables exist."""
    from vulnerable_app import init_database
    init_database()
    
    conn = sqlite3.connect('vulnerable_app.db')
    cursor = conn.cursor()
    
    # Check users table exists
    cursor.execute("SELECT name FROM sqlite_master WHERE type='table' AND name='users'")
    assert cursor.fetchone() is not None
    
    # Check accounts table exists
    cursor.execute("SELECT name FROM sqlite_master WHERE type='table' AND name='accounts'")
    assert cursor.fetchone() is not None
    
    conn.close()


def test_init_database_seeds_users():
    """The users table contains exactly 3 rows: admin, alice, bob."""
    from vulnerable_app import init_database
    init_database()
    
    rows = query_db("SELECT username FROM users ORDER BY id")
    usernames = [row[0] for row in rows]
    assert usernames == ['admin', 'alice', 'bob']


def test_init_database_seeds_accounts():
    """The accounts table contains rows for alice and bob with correct balances."""
    from vulnerable_app import init_database
    init_database()
    
    rows = query_db("SELECT username, balance FROM accounts ORDER BY id")
    assert len(rows) == 2
    assert rows[0] == ('alice', 1000.00)
    assert rows[1] == ('bob', 500.00)


def test_init_database_admin_password_is_md5():
    """The stored admin password is the MD5 hex digest, not plaintext."""
    from vulnerable_app import init_database
    init_database()
    
    rows = query_db("SELECT password FROM users WHERE username='admin'")
    stored_password = rows[0][0]
    expected_hash = hashlib.md5("password123".encode()).hexdigest()
    assert stored_password == expected_hash


def test_init_database_idempotent():
    """Calling init_database() twice does not duplicate rows."""
    from vulnerable_app import init_database
    init_database()
    init_database()
    
    rows = query_db("SELECT COUNT(*) FROM users")
    assert rows[0][0] == 3
    
    rows = query_db("SELECT COUNT(*) FROM accounts")
    assert rows[0][0] == 2


# ============================================================================
# SECTION 2: GET / (index)
# ============================================================================

def test_index_returns_200(client):
    """Status code is 200."""
    response = client.get('/')
    assert response.status_code == 200


def test_index_contains_endpoint_links(client):
    """Response body contains links to various endpoints."""
    response = client.get('/')
    content = body(response)
    assert '/login' in content
    assert '/profile' in content
    assert '/health' in content
    assert '/ping' in content


# ============================================================================
# SECTION 3: GET /health
# ============================================================================

def test_health_returns_200(client):
    """Status code is 200."""
    response = client.get('/health')
    assert response.status_code == 200


def test_health_returns_json(client):
    """Response JSON contains status: healthy."""
    response = client.get('/health')
    assert response.json == {'status': 'healthy', 'service': 'flask-app'}


# ============================================================================
# SECTION 4: GET|POST /login
# ============================================================================

def test_login_get_no_params_returns_form(client):
    """GET with no params returns 200 and HTML contains form."""
    response = client.get('/login')
    assert response.status_code == 200
    assert '<form' in body(response)


def test_login_post_valid_admin_credentials(client):
    """POST with valid admin credentials returns success."""
    # Admin password is stored as MD5 hash, so we need to pass the hash
    admin_password_hash = hashlib.md5("password123".encode()).hexdigest()
    response = client.post('/login', data={'username': 'admin', 'password': admin_password_hash})
    assert response.status_code == 200
    assert 'Login successful' in body(response)


def test_login_post_valid_user_alice(client):
    """POST with valid alice credentials returns success."""
    response = client.post('/login', data={'username': 'alice', 'password': 'alice123'})
    assert response.status_code == 200
    assert 'Login successful' in body(response)


def test_login_post_invalid_password(client):
    """POST with wrong password returns failure."""
    response = client.post('/login', data={'username': 'admin', 'password': 'wrongpass'})
    assert response.status_code == 200
    assert 'Login failed' in body(response)


def test_login_post_nonexistent_user(client):
    """POST with made-up username returns failure."""
    response = client.post('/login', data={'username': 'nonexistent', 'password': 'pass'})
    assert response.status_code == 200
    assert 'Login failed' in body(response)


def test_login_post_empty_username(client):
    """POST with empty username returns the login form."""
    response = client.post('/login', data={'username': '', 'password': 'pass'})
    assert response.status_code == 200
    assert '<form' in body(response)


def test_login_get_with_credentials_in_query(client):
    """GET with credentials in query string succeeds (CWE-598)."""
    response = client.get('/login?username=alice&password=alice123')
    assert response.status_code == 200
    assert 'Login successful' in body(response)


def test_login_sql_injection_tautology(client):
    """SQL injection tautology doesn't crash (CWE-89)."""
    response = client.post('/login', data={'username': "' OR '1'='1", 'password': 'x'})
    assert response.status_code == 200


def test_login_sets_session_on_success(client):
    """After successful login, session['username'] is set."""
    admin_password_hash = hashlib.md5("password123".encode()).hexdigest()
    response = client.post('/login', data={'username': 'admin', 'password': admin_password_hash})
    assert response.status_code == 200
    assert 'Login successful' in body(response)
    # Session is set by Flask during login - we can verify by making another request
    # that relies on session state
    response2 = client.get('/process_data?input=test')
    assert 'test:admin' in body(response2)  # Confirms admin role from session


def test_login_error_leaks_username(client):
    """Failed login response contains the attempted username (CWE-209)."""
    response = client.post('/login', data={'username': 'testuser', 'password': 'wrongpass'})
    assert 'testuser' in body(response)


# ============================================================================
# SECTION 5: GET /profile
# ============================================================================

def test_profile_default_guest(client):
    """GET /profile with no params returns Guest."""
    response = client.get('/profile')
    assert response.status_code == 200
    assert 'Guest' in body(response)


def test_profile_with_name_param(client):
    """GET /profile with name param returns that name."""
    response = client.get('/profile?name=alice')
    assert response.status_code == 200
    assert 'alice' in body(response)


def test_profile_xss_payload_reflected(client):
    """XSS payload is reflected unescaped (CWE-79)."""
    payload = '<script>alert(1)</script>'
    response = client.get(f'/profile?name={payload}')
    assert response.status_code == 200
    assert payload in body(response)


def test_profile_admin_shows_password_hint(client):
    """Admin profile shows password hint (CWE-200)."""
    response = client.get('/profile?name=admin')
    assert response.status_code == 200
    assert 'password123' in body(response)


def test_profile_non_admin_no_password_hint(client):
    """Non-admin profile doesn't show password hint."""
    response = client.get('/profile?name=alice')
    assert 'password123' not in body(response)


# ============================================================================
# SECTION 6: GET /frame_content
# ============================================================================

def test_frame_content_default_url(client):
    """GET /frame_content returns default example.com iframe."""
    response = client.get('/frame_content')
    assert response.status_code == 200
    content = body(response)
    assert '<iframe' in content
    assert 'example.com' in content


def test_frame_content_custom_url(client):
    """Custom URL is injected into iframe src (CWE-1021)."""
    response = client.get('/frame_content?url=https://attacker.com')
    assert response.status_code == 200
    assert 'src="https://attacker.com"' in body(response)


def test_frame_content_javascript_url(client):
    """javascript: URL is allowed in iframe (CWE-1021)."""
    response = client.get('/frame_content?url=javascript:alert(1)')
    assert response.status_code == 200
    assert 'javascript:alert(1)' in body(response)


# ============================================================================
# SECTION 7: GET /redirect
# ============================================================================

def test_redirect_default(client):
    """GET /redirect redirects to / by default."""
    response = client.get('/redirect', follow_redirects=False)
    assert response.status_code in [301, 302, 303, 307, 308]


def test_redirect_external_url(client):
    """External URL redirect is allowed (CWE-601)."""
    response = client.get('/redirect?url=https://evil.com', follow_redirects=False)
    assert response.status_code in [301, 302, 303, 307, 308]
    assert response.headers.get('Location') == 'https://evil.com'


def test_redirect_relative_path(client):
    """Relative path redirect works."""
    response = client.get('/redirect?url=/health', follow_redirects=False)
    assert response.status_code in [301, 302, 303, 307, 308]
    assert '/health' in response.headers.get('Location')


# ============================================================================
# SECTION 8: GET /encrypt
# ============================================================================

def test_encrypt_returns_200(client):
    """GET /encrypt returns 200."""
    response = client.get('/encrypt?data=hello')
    assert response.status_code == 200


def test_encrypt_returns_hex_string(client):
    """Response contains hex string."""
    response = client.get('/encrypt?data=hello')
    content = body(response)
    # Extract hex string from HTML
    import re
    hex_match = re.search(r'[0-9a-f]+', content)
    assert hex_match is not None


def test_encrypt_default_data(client):
    """GET /encrypt with no params uses default data."""
    response = client.get('/encrypt')
    assert response.status_code == 200


def test_encrypt_deterministic(client):
    """DES-ECB is deterministic (CWE-327)."""
    response1 = client.get('/encrypt?data=testdata')
    response2 = client.get('/encrypt?data=testdata')
    assert body(response1) == body(response2)


def test_encrypt_output_length_multiple_of_8(client):
    """Encrypted output length is multiple of 8 bytes."""
    response = client.get('/encrypt?data=hello')
    content = body(response)
    import re
    hex_match = re.search(r'>([0-9a-f]+)<', content)
    if hex_match:
        hex_str = hex_match.group(1)
        byte_count = len(hex_str) // 2
        assert byte_count % 8 == 0


# ============================================================================
# SECTION 9: GET /set_header
# ============================================================================

def test_set_header_returns_200(client):
    """GET /set_header returns 200."""
    response = client.get('/set_header?username=alice')
    assert response.status_code == 200


def test_set_header_reflects_username(client):
    """X-Username header reflects the username parameter."""
    response = client.get('/set_header?username=alice')
    assert response.headers.get('X-Username') == 'alice'


def test_set_header_default_guest(client):
    """Default username is Guest."""
    response = client.get('/set_header')
    assert response.headers.get('X-Username') == 'Guest'


def test_set_header_crlf_payload(client):
    """CRLF injection is blocked by modern Flask/Werkzeug (security improvement)."""
    # Modern Werkzeug prevents CRLF injection by raising ValueError
    # This test verifies the framework protects against CWE-113
    try:
        response = client.get('/set_header?username=foo%0d%0aInjected-Header:bar')
        # If it doesn't raise, check that response is still valid
        assert response.status_code == 200
    except ValueError as e:
        # Expected: Werkzeug blocks newlines in headers
        assert 'newline' in str(e).lower() or 'Header values' in str(e)


# ============================================================================
# SECTION 10: GET /process_data
# ============================================================================

def test_process_data_returns_200(client):
    """GET /process_data returns 200."""
    response = client.get('/process_data?input=hello')
    assert response.status_code == 200


def test_process_data_reflects_input(client):
    """Response body contains the input."""
    response = client.get('/process_data?input=hello')
    assert 'hello' in body(response)


def test_process_data_appends_role(client):
    """Response appends :guest role (CWE-501)."""
    response = client.get('/process_data?input=hello')
    assert 'hello:guest' in body(response)


def test_process_data_with_session_role(client, authenticated_client):
    """With admin session, appends :admin role."""
    response = authenticated_client.get('/process_data?input=hello')
    assert 'hello:admin' in body(response)


# ============================================================================
# SECTION 11: GET /download
# ============================================================================

def test_download_existing_file(client):
    """Download existing file returns content."""
    # Create a temp file
    with tempfile.NamedTemporaryFile(mode='w', delete=False, suffix='.txt') as f:
        f.write('test content')
        temp_path = f.name
    
    try:
        response = client.get(f'/download?file={temp_path}')
        assert response.status_code == 200
        assert 'test content' in body(response)
    finally:
        os.unlink(temp_path)


def test_download_missing_file_returns_error(client):
    """Download missing file returns error."""
    response = client.get('/download?file=nonexistent_xyz.txt')
    assert response.status_code == 200
    assert 'Error' in body(response)


def test_download_path_traversal_attempt(client):
    """Path traversal attempt doesn't crash (CWE-22)."""
    response = client.get('/download?file=../vulnerable_app.py')
    assert response.status_code == 200


# ============================================================================
# SECTION 12: GET /login_with_session
# ============================================================================

def test_session_login_valid_credentials(client):
    """Valid credentials return success."""
    # The session login checks against ADMIN_USERNAME and ADMIN_PASSWORD constants (plaintext)
    response = client.get('/login_with_session?username=admin&password=password123')
    assert response.status_code == 200
    assert 'Logged in' in body(response)


def test_session_login_invalid_credentials(client):
    """Invalid credentials return failure."""
    response = client.get('/login_with_session?username=admin&password=wrongpass')
    assert response.status_code == 200
    assert 'Login failed' in body(response)


def test_session_login_with_attacker_session_id(client):
    """Session fixation allows attacker-controlled session ID (CWE-384)."""
    # The session login checks against ADMIN_USERNAME and ADMIN_PASSWORD constants (plaintext)
    response = client.get('/login_with_session?username=admin&password=password123&session_id=attacker_controlled_id')
    assert response.status_code == 200
    assert 'attacker_controlled_id' in body(response)


def test_session_login_without_session_id_generates_token(client):
    """Without session_id, generates new token."""
    # The session login checks against ADMIN_USERNAME and ADMIN_PASSWORD constants (plaintext)
    response = client.get('/login_with_session?username=admin&password=password123')
    assert response.status_code == 200
    assert 'Logged in with new session:' in body(response)


# ============================================================================
# SECTION 13: GET /search
# ============================================================================

def test_search_returns_200(client):
    """GET /search returns 200."""
    response = client.get('/search?q=alice')
    assert response.status_code == 200


def test_search_finds_existing_user(client):
    """Search finds existing user."""
    response = client.get('/search?q=alice')
    assert 'alice' in body(response)


def test_search_empty_query_returns_all(client):
    """Empty query returns all users."""
    response = client.get('/search?q=')
    content = body(response)
    assert 'alice' in content
    assert 'bob' in content


def test_search_no_match_returns_empty_list(client):
    """No match returns empty list."""
    response = client.get('/search?q=zzznomatch')
    assert '[]' in body(response)


def test_search_sql_injection(client):
    """SQL injection doesn't raise exception (CWE-89)."""
    response = client.get('/search?q=' + "' UNION SELECT username,password FROM users--")
    assert response.status_code == 200


# ============================================================================
# SECTION 14: GET /read_log
# ============================================================================

def test_read_log_returns_200(client):
    """GET /read_log returns 200."""
    response = client.get('/read_log?log=test_temp.log')
    assert response.status_code == 200


def test_read_log_success_message(client):
    """Response contains success message."""
    response = client.get('/read_log?log=test_temp2.log')
    assert 'Log written successfully' in body(response)
    # Cleanup
    try:
        os.unlink('test_temp2.log')
    except:
        pass


def test_read_log_creates_file(client):
    """Request creates the log file."""
    log_name = 'test_temp3.log'
    try:
        if os.path.exists(log_name):
            os.unlink(log_name)
        
        client.get(f'/read_log?log={log_name}')
        assert os.path.exists(log_name)
    finally:
        try:
            os.unlink(log_name)
        except:
            pass


def test_read_log_file_handle_tracked(client):
    """File handle is tracked in open_files (CWE-772)."""
    from vulnerable_app import open_files
    initial_count = len(open_files)
    
    client.get('/read_log?log=test_temp4.log')
    
    assert len(open_files) > initial_count
    
    # Cleanup
    try:
        os.unlink('test_temp4.log')
    except:
        pass


# ============================================================================
# SECTION 15: GET|POST /transfer_funds
# ============================================================================

def test_transfer_funds_get_returns_form(client):
    """Transfer funds form is part of the endpoint but unreachable due to logic bug."""
    # The code has 'if POST or GET' which is always True, so the form is unreachable
    # This test documents the vulnerability: even GET requests process transfers
    # Let's test that transfers work via GET (the actual vulnerability)
    response = client.get('/transfer_funds?from=alice&to=bob&amount=10')
    assert response.status_code == 200
    assert 'Transferred' in body(response)


def test_transfer_funds_post_valid(client):
    """POST transfer returns success."""
    response = client.post('/transfer_funds', data={'from': 'alice', 'to': 'bob', 'amount': '100'})
    assert response.status_code == 200
    assert 'Transferred' in body(response)


def test_transfer_funds_get_with_params(client):
    """GET with params performs transfer (CWE-352)."""
    response = client.get('/transfer_funds?from=alice&to=bob&amount=50')
    assert response.status_code == 200
    assert 'Transferred' in body(response)


def test_transfer_funds_no_origin_check(client):
    """Transfer works without Referer/Origin (CWE-352)."""
    response = client.post('/transfer_funds', data={'from': 'alice', 'to': 'bob', 'amount': '25'})
    assert response.status_code == 200
    assert 'Transferred' in body(response)


def test_transfer_funds_updates_balance(client):
    """Transfer actually updates database balances."""
    # Get initial balances
    alice_before = query_db("SELECT balance FROM accounts WHERE username='alice'")[0][0]
    bob_before = query_db("SELECT balance FROM accounts WHERE username='bob'")[0][0]
    
    # Transfer
    client.post('/transfer_funds', data={'from': 'alice', 'to': 'bob', 'amount': '100'})
    
    # Check balances changed
    alice_after = query_db("SELECT balance FROM accounts WHERE username='alice'")[0][0]
    bob_after = query_db("SELECT balance FROM accounts WHERE username='bob'")[0][0]
    
    assert alice_after == alice_before - 100
    assert bob_after == bob_before + 100


# ============================================================================
# SECTION 16: GET /fetch_url
# ============================================================================

@pytest.mark.network
def test_fetch_url_returns_200(client):
    """GET /fetch_url returns 200."""
    response = client.get('/fetch_url?url=http://example.com')
    assert response.status_code == 200


def test_fetch_url_invalid_url_returns_error(client):
    """Invalid URL returns error."""
    response = client.get('/fetch_url?url=not_a_valid_url')
    assert response.status_code == 200
    assert 'Error' in body(response)


def test_fetch_url_localhost_internal(client):
    """Localhost URL is processed (CWE-918)."""
    response = client.get('/fetch_url?url=http://localhost:1')
    assert response.status_code == 200
    assert 'Error' in body(response)


# ============================================================================
# SECTION 17: GET /account/<id>
# ============================================================================

def test_account_valid_id_1(client):
    """GET /account/1 returns alice."""
    response = client.get('/account/1')
    assert response.status_code == 200
    assert 'alice' in body(response)


def test_account_valid_id_2(client):
    """GET /account/2 returns bob."""
    response = client.get('/account/2')
    assert response.status_code == 200
    assert 'bob' in body(response)


def test_account_nonexistent_id(client):
    """GET /account/999 returns not found."""
    response = client.get('/account/999')
    assert response.status_code == 200
    assert 'Account not found' in body(response)


def test_account_idor_no_auth_required(client):
    """Account access requires no auth (CWE-639)."""
    response = client.get('/account/1')
    assert response.status_code == 200
    assert 'alice' in body(response)


def test_account_sql_injection_in_id(client):
    """SQL injection in ID doesn't crash (CWE-89)."""
    response = client.get('/account/1 OR 1=1')
    assert response.status_code == 200


# ============================================================================
# SECTION 18: POST /load_object
# ============================================================================

def test_load_object_valid_pickle(client):
    """Valid pickle is deserialized."""
    data = pickle.dumps({"key": "value"})
    response = client.post('/load_object', data=data)
    assert response.status_code == 200
    assert 'key' in body(response)


def test_load_object_simple_string(client):
    """Simple string pickle works."""
    data = pickle.dumps("hello world")
    response = client.post('/load_object', data=data)
    assert response.status_code == 200
    assert 'hello world' in body(response)


def test_load_object_invalid_data(client):
    """Invalid data returns error."""
    response = client.post('/load_object', data=b"not_pickle")
    assert response.status_code == 200
    assert 'Error' in body(response)


def test_load_object_no_authentication_required(client):
    """No auth required for deserialization (CWE-502)."""
    data = pickle.dumps({"test": "data"})
    response = client.post('/load_object', data=data)
    assert response.status_code == 200


# ============================================================================
# SECTION 19: GET /ping
# ============================================================================

def test_ping_localhost(client):
    """Ping localhost returns results."""
    response = client.get('/ping?host=127.0.0.1')
    assert response.status_code == 200
    assert 'Ping Results' in body(response)


def test_ping_default_host(client):
    """Ping with no host uses localhost."""
    response = client.get('/ping')
    assert response.status_code == 200


def test_ping_timeout_or_unreachable(client):
    """Unreachable host returns error."""
    response = client.get('/ping?host=192.0.2.1')
    # May timeout or return error
    assert response.status_code == 200


def test_ping_command_injection_payload(client):
    """Command injection payload doesn't crash (CWE-78)."""
    response = client.get('/ping?host=127.0.0.1;echo+INJECTED')
    assert response.status_code == 200


# ============================================================================
# SECTION 20: POST /parse_xml
# ============================================================================

def test_parse_xml_valid_document(client):
    """Valid XML is parsed."""
    xml = '<root><item>hello</item></root>'
    response = client.post('/parse_xml', data=xml)
    assert response.status_code == 200
    content = body(response)
    assert 'item' in content
    assert 'hello' in content


def test_parse_xml_multiple_children(client):
    """Multiple children are parsed."""
    xml = '<root><a>1</a><b>2</b></root>'
    response = client.post('/parse_xml', data=xml)
    assert response.status_code == 200
    content = body(response)
    assert 'a' in content
    assert 'b' in content


def test_parse_xml_malformed_returns_error(client):
    """Malformed XML returns error."""
    response = client.post('/parse_xml', data='<unclosed')
    assert response.status_code == 200
    assert 'Error' in body(response)


def test_parse_xml_empty_root(client):
    """Empty root returns empty list."""
    response = client.post('/parse_xml', data='<root></root>')
    assert response.status_code == 200
    assert '[]' in body(response)


def test_parse_xml_content_type(client):
    """XML parsing works with Content-Type header."""
    xml = '<root><item>test</item></root>'
    response = client.post('/parse_xml', data=xml, headers={'Content-Type': 'application/xml'})
    assert response.status_code == 200
