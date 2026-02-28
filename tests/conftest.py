import pytest
import os
import sys

# Add parent directory to path so we can import vulnerable_app
sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), '..')))

# Import werkzeug and add __version__ if missing (compatibility shim)
try:
    import werkzeug
    if not hasattr(werkzeug, '__version__'):
        werkzeug.__version__ = '3.0.0'
except ImportError:
    pass


@pytest.fixture(scope="session")
def app():
    """Create application with test configuration."""
    from vulnerable_app import app as flask_app, init_database
    
    flask_app.config['TESTING'] = True
    flask_app.config['SECRET_KEY'] = 'test-secret-key'
    
    # Initialize database with fresh data
    with flask_app.app_context():
        init_database()
    
    yield flask_app


@pytest.fixture(scope="function")
def client(app):
    """Flask test client, fresh per test."""
    # Reinitialize database for each test to ensure clean state
    from vulnerable_app import init_database
    with app.app_context():
        init_database()
    
    with app.test_client() as client:
        yield client


@pytest.fixture(scope="function")
def authenticated_client(client):
    """Client with an active admin session."""
    import hashlib
    admin_password_hash = hashlib.md5("password123".encode()).hexdigest()
    client.post('/login', data={'username': 'admin', 'password': admin_password_hash})
    return client
