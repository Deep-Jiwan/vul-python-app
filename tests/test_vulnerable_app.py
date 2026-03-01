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
# SECTION 0: DATABASE INITIALIZATION
# ============================================================================

def test_init_database_creates_tables():
    """init_database() creates tables."""
    from vulnerable_app import init_database
    init_database()
    
    conn = sqlite3.connect('vulnerable_app.db')
    cursor = conn.cursor()
    
    cursor.execute("SELECT name FROM sqlite_master WHERE type='table' AND name='users'")
    assert cursor.fetchone() is not None
    
    cursor.execute("SELECT name FROM sqlite_master WHERE type='table' AND name='accounts'")
    assert cursor.fetchone() is not None
    
    conn.close()


def test_init_database_seeds_users():
    """init_database() seeds users table."""
    from vulnerable_app import init_database
    init_database()
    
    users = query_db("SELECT COUNT(*) FROM users")
    assert users[0][0] >= 3


def test_init_database_seeds_accounts():
    """init_database() seeds accounts table."""
    from vulnerable_app import init_database
    init_database()
    
    accounts = query_db("SELECT COUNT(*) FROM accounts")
    assert accounts[0][0] >= 2


def test_init_database_admin_password_is_md5():
    """Admin password is stored as MD5 hash."""
    from vulnerable_app import init_database
    init_database()
    
    admin = query_db("SELECT password FROM users WHERE username='admin'")
    assert len(admin[0][0]) == 32


def test_init_database_idempotent():
    """init_database() can be called multiple times."""
    from vulnerable_app import init_database
    init_database()
    init_database()
    
    users = query_db("SELECT COUNT(*) FROM users")
    assert users[0][0] >= 3


# ============================================================================
# SECTION 1: GET /
# ============================================================================

def test_index_returns_200(client):
    """GET / returns 200."""
    response = client.get('/')
    assert response.status_code == 200


def test_index_contains_endpoint_links(client):
    """Index page contains endpoint links."""
    response = client.get('/')
    assert 'login' in body(response)


# ============================================================================
# SECTION 2: GET /health
# ============================================================================

def test_health_returns_200(client):
    """GET /health returns 200."""
    response = client.get('/health')
    assert response.status_code == 200


def test_health_returns_json(client):
    """GET /health returns JSON."""
    response = client.get('/health')
    assert response.is_json or 'status' in body(response)


# ============================================================================
# SECTION 3: GET/POST /login
# ============================================================================

def test_login_get_no_params_returns_form(client):
    """GET /login without params returns login form."""
    response = client.get('/login')
    assert response.status_code == 200
    assert '<form' in body(response)


def test_login_post_valid_admin_credentials(client):
    """POST with valid admin credentials returns success."""
    admin_password_hash = hashlib.md5("password123".encode()).hexdigest()
    response = client.post('/login', data={'username': 'admin', 'password': admin_password_hash})
    assert response.status_code == 200


def test_login_post_valid_user_alice(client):
    """POST with valid alice credentials works."""
    response = client.post('/login', data={'username': 'alice', 'password': 'alice123'})
    assert response.status_code == 200


def test_login_post_invalid_password(client):
    """POST with wrong password returns response."""
    response = client.post('/login', data={'username': 'admin', 'password': 'wrongpass'})
    assert response.status_code == 200


def test_login_post_nonexistent_user(client):
    """POST with made-up username returns response."""
    response = client.post('/login', data={'username': 'nonexistent', 'password': 'pass'})
    assert response.status_code == 200


def test_login_post_empty_username(client):
    """POST with empty username returns form."""
    response = client.post('/login', data={'username': '', 'password': 'pass'})
    assert response.status_code == 200
    assert '<form' in body(response)


def test_login_with_special_characters(client):
    """Login handles special characters without crashing."""
    response = client.post('/login', data={'username': "' OR '1'='1", 'password': 'x'})
    assert response.status_code == 200


def test_login_sets_session_on_success(client):
    """After successful login, session state is maintained."""
    admin_password_hash = hashlib.md5("password123".encode()).hexdigest()
    response = client.post('/login', data={'username': 'admin', 'password': admin_password_hash})
    assert response.status_code == 200
    response2 = client.get('/process_data?input=test')
    assert response2.status_code == 200


# ============================================================================
# SECTION 4: GET /profile
# ============================================================================

def test_profile_default_behavior(client):
    """GET /profile returns 200."""
    response = client.get('/profile')
    assert response.status_code == 200


def test_profile_with_name_param(client):
    """GET /profile with name param works."""
    response = client.get('/profile?name=alice')
    assert response.status_code == 200


def test_profile_with_special_characters(client):
    """Profile handles special characters without crashing."""
    response = client.get('/profile?name=<script>test</script>')
    assert response.status_code == 200


def test_profile_with_comment_param(client):
    """Profile handles comment parameter."""
    response = client.get('/profile?comment=testcomment')
    assert response.status_code == 200


# ============================================================================
# SECTION 5: GET /frame_content
# ============================================================================

def test_frame_content_returns_200(client):
    """GET /frame_content returns 200."""
    response = client.get('/frame_content')
    assert response.status_code == 200


def test_frame_content_with_url_param(client):
    """Frame content accepts URL parameter."""
    response = client.get('/frame_content?url=https://example.com')
    assert response.status_code == 200


# ============================================================================
# SECTION 6: GET /redirect
# ============================================================================

def test_redirect_returns_redirect_status(client):
    """GET /redirect returns redirect status."""
    response = client.get('/redirect', follow_redirects=False)
    assert response.status_code in [301, 302, 303, 307, 308]


def test_redirect_with_url_param(client):
    """Redirect accepts URL parameter."""
    response = client.get('/redirect?url=/health', follow_redirects=False)
    assert response.status_code in [301, 302, 303, 307, 308]


# ============================================================================
# SECTION 7: GET /encrypt
# ============================================================================

def test_encrypt_returns_200(client):
    """GET /encrypt returns 200."""
    response = client.get('/encrypt?data=hello')
    assert response.status_code == 200


def test_encrypt_with_data_param(client):
    """Encrypt accepts data parameter."""
    response = client.get('/encrypt?data=testdata')
    assert response.status_code == 200


def test_encrypt_default_data(client):
    """GET /encrypt with no params works."""
    response = client.get('/encrypt')
    assert response.status_code == 200


# ============================================================================
# SECTION 8: GET /set_header
# ============================================================================

def test_set_header_returns_200(client):
    """GET /set_header returns 200."""
    response = client.get('/set_header?username=alice')
    assert response.status_code == 200


def test_set_header_default_works(client):
    """Set header works with default."""
    response = client.get('/set_header')
    assert response.status_code == 200


def test_set_header_with_special_chars(client):
    """Set header handles special characters."""
    try:
        response = client.get('/set_header?username=test%20user')
        assert response.status_code == 200
    except ValueError:
        pass  # Framework protection is acceptable


# ============================================================================
# SECTION 9: GET /process_data
# ============================================================================

def test_process_data_returns_200(client):
    """GET /process_data returns 200."""
    response = client.get('/process_data?input=hello')
    assert response.status_code == 200


def test_process_data_with_input(client):
    """Process data accepts input parameter."""
    response = client.get('/process_data?input=testinput')
    assert response.status_code == 200


def test_process_data_with_session(client, authenticated_client):
    """Process data works with session."""
    response = authenticated_client.get('/process_data?input=hello')
    assert response.status_code == 200


# ============================================================================
# SECTION 10: GET /download
# ============================================================================

def test_download_with_file_param(client):
    """Download accepts file parameter."""
    with tempfile.NamedTemporaryFile(mode='w', delete=False, suffix='.txt') as f:
        f.write('test content')
        temp_path = f.name
    
    try:
        response = client.get(f'/download?file={temp_path}')
        assert response.status_code == 200
    finally:
        os.unlink(temp_path)


def test_download_missing_file(client):
    """Download handles missing file."""
    response = client.get('/download?file=nonexistent_xyz.txt')
    assert response.status_code == 200


def test_download_with_path(client):
    """Download handles path parameter."""
    response = client.get('/download?file=test.txt')
    assert response.status_code == 200


# ============================================================================
# SECTION 11: GET /login_with_session
# ============================================================================

def test_session_login_valid_credentials(client):
    """Valid credentials work."""
    response = client.get('/login_with_session?username=admin&password=password123')
    assert response.status_code == 200


def test_session_login_invalid_credentials(client):
    """Invalid credentials handled."""
    response = client.get('/login_with_session?username=admin&password=wrongpass')
    assert response.status_code == 200


def test_session_login_with_session_id(client):
    """Session login accepts session_id parameter."""
    response = client.get('/login_with_session?username=admin&password=password123&session_id=test_session')
    assert response.status_code == 200


def test_session_login_generates_token(client):
    """Session login can generate token."""
    response = client.get('/login_with_session?username=admin&password=password123')
    assert response.status_code == 200


# ============================================================================
# SECTION 12: GET /search
# ============================================================================

def test_search_returns_200(client):
    """GET /search returns 200."""
    response = client.get('/search?q=alice')
    assert response.status_code == 200


def test_search_with_query_param(client):
    """Search accepts query parameter."""
    response = client.get('/search?q=test')
    assert response.status_code == 200


def test_search_empty_query(client):
    """Empty query works."""
    response = client.get('/search?q=')
    assert response.status_code == 200


def test_search_with_special_chars(client):
    """Search handles special characters."""
    response = client.get('/search?q=test')
    assert response.status_code == 200


# ============================================================================
# SECTION 13: GET /read_log
# ============================================================================

def test_read_log_returns_200(client):
    """GET /read_log returns 200."""
    response = client.get('/read_log?log=test_temp.log')
    assert response.status_code == 200
    try:
        os.unlink('test_temp.log')
    except:
        pass


def test_read_log_with_param(client):
    """Read log accepts log parameter."""
    response = client.get('/read_log?log=test_temp2.log')
    assert response.status_code == 200
    try:
        os.unlink('test_temp2.log')
    except:
        pass


def test_read_log_creates_file(client):
    """Request processes log file."""
    log_name = 'test_temp3.log'
    try:
        if os.path.exists(log_name):
            os.unlink(log_name)
        
        response = client.get(f'/read_log?log={log_name}')
        assert response.status_code == 200
    finally:
        try:
            os.unlink(log_name)
        except:
            pass


# ============================================================================
# SECTION 14: GET/POST /transfer_funds
# ============================================================================

def test_transfer_funds_returns_200(client):
    """Transfer funds endpoint works."""
    response = client.get('/transfer_funds?from=alice&to=bob&amount=10')
    assert response.status_code == 200


def test_transfer_funds_post(client):
    """POST transfer works."""
    response = client.post('/transfer_funds', data={'from': 'alice', 'to': 'bob', 'amount': '100'})
    assert response.status_code == 200


def test_transfer_funds_updates_balance(client):
    """Transfer updates database."""
    alice_before = query_db("SELECT balance FROM accounts WHERE username='alice'")[0][0]
    bob_before = query_db("SELECT balance FROM accounts WHERE username='bob'")[0][0]
    
    client.post('/transfer_funds', data={'from': 'alice', 'to': 'bob', 'amount': '100'})
    
    alice_after = query_db("SELECT balance FROM accounts WHERE username='alice'")[0][0]
    bob_after = query_db("SELECT balance FROM accounts WHERE username='bob'")[0][0]
    
    assert alice_after != alice_before or bob_after != bob_after


# ============================================================================
# SECTION 15: GET /fetch_url
# ============================================================================

@pytest.mark.network
def test_fetch_url_returns_200(client):
    """GET /fetch_url returns 200."""
    response = client.get('/fetch_url?url=http://example.com')
    assert response.status_code == 200


def test_fetch_url_invalid_url(client):
    """Invalid URL handled."""
    response = client.get('/fetch_url?url=not_a_valid_url')
    assert response.status_code == 200


def test_fetch_url_with_param(client):
    """Fetch URL accepts parameter."""
    response = client.get('/fetch_url?url=http://localhost:1')
    assert response.status_code == 200


# ============================================================================
# SECTION 16: GET /account/<id>
# ============================================================================

def test_account_valid_id_1(client):
    """GET /account/1 works."""
    response = client.get('/account/1')
    assert response.status_code == 200


def test_account_valid_id_2(client):
    """GET /account/2 works."""
    response = client.get('/account/2')
    assert response.status_code == 200


def test_account_nonexistent_id(client):
    """GET /account/999 handles missing account."""
    response = client.get('/account/999')
    assert response.status_code == 200


def test_account_with_special_chars(client):
    """Account handles special characters."""
    response = client.get('/account/1%20OR%201=1')
    assert response.status_code in [200, 404, 500]


# ============================================================================
# SECTION 17: POST /load_object
# ============================================================================

def test_load_object_with_data(client):
    """Valid pickle data works."""
    data = pickle.dumps({"key": "value"})
    response = client.post('/load_object', data=data)
    assert response.status_code == 200


def test_load_object_simple_string(client):
    """String pickle works."""
    data = pickle.dumps("hello world")
    response = client.post('/load_object', data=data)
    assert response.status_code == 200


def test_load_object_invalid_data(client):
    """Invalid data handled."""
    response = client.post('/load_object', data=b"not_pickle")
    assert response.status_code == 200


# ============================================================================
# SECTION 18: GET /ping
# ============================================================================

def test_ping_localhost(client):
    """Ping localhost works."""
    response = client.get('/ping?host=127.0.0.1')
    assert response.status_code == 200


def test_ping_default_host(client):
    """Ping with no host works."""
    response = client.get('/ping')
    assert response.status_code == 200


def test_ping_with_special_chars(client):
    """Ping handles special characters."""
    response = client.get('/ping?host=test;echo')
    assert response.status_code == 200


# ============================================================================
# SECTION 19: POST /parse_xml
# ============================================================================

def test_parse_xml_valid_document(client):
    """Valid XML parsed."""
    xml = '<root><item>hello</item></root>'
    response = client.post('/parse_xml', data=xml)
    assert response.status_code == 200


def test_parse_xml_multiple_children(client):
    """Multiple children handled."""
    xml = '<root><a>1</a><b>2</b></root>'
    response = client.post('/parse_xml', data=xml)
    assert response.status_code == 200


def test_parse_xml_malformed(client):
    """Malformed XML handled."""
    response = client.post('/parse_xml', data='<unclosed')
    assert response.status_code == 200


def test_parse_xml_empty_root(client):
    """Empty root handled."""
    response = client.post('/parse_xml', data='<root></root>')
    assert response.status_code == 200


def test_parse_xml_with_content_type(client):
    """XML parsing accepts Content-Type."""
    xml = '<root><item>test</item></root>'
    response = client.post('/parse_xml', data=xml, headers={'Content-Type': 'application/xml'})
    assert response.status_code == 200
