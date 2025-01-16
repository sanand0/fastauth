# Usage: uv run test_app.py

# /// script
# requires-python = ">=3.13"
# dependencies = [
#     "fastapi",
#     "google-auth",
#     "httpx",
#     "pytest",
#     "pytest-asyncio",
#     "python-dotenv",
# ]
# ///
import os
import pytest
from fastapi.testclient import TestClient
from unittest.mock import patch, mock_open

from app import app, get_authorized_emails, is_authorized

client = TestClient(app)


@pytest.fixture
def mock_env():
    """Mock environment variables."""
    with patch.dict(
        os.environ,
        {
            "GOOGLE_CLIENT_ID": "fake-client-id",
            "GOOGLE_CLIENT_SECRET": "fake-secret",
            "REDIRECT_URI": "http://testserver/googleauth/",
            "AUTH": "test@example.com,*@company.com",
        },
    ):
        yield


@pytest.fixture
def mock_auth_file():
    """Mock .auth file content."""
    mock_content = """
*@example.com
specific@email.com
*@*.edu
    """
    with patch("builtins.open", mock_open(read_data=mock_content)):
        with patch("os.path.getmtime") as mock_mtime:
            mock_mtime.return_value = 1000
            yield


@pytest.fixture
def mock_google_verify():
    """Mock Google token verification."""
    with patch("google.oauth2.id_token.verify_oauth2_token") as mock:
        mock.return_value = {"email": "test@example.com"}
        yield mock


def test_login_redirect():
    """Test login endpoint redirects to Google OAuth."""
    response = client.get("/login", follow_redirects=False)
    print("RESPONSE", response.headers)
    assert response.status_code == 307
    assert "accounts.google.com" in response.headers["location"]


@pytest.mark.asyncio(loop_scope="function")
async def test_googleauth_success(mock_env, mock_google_verify):
    """Test successful Google OAuth callback."""
    with patch("httpx.AsyncClient.post") as mock_post:
        mock_post.return_value.json.return_value = {"id_token": "fake-token"}
        mock_post.return_value.raise_for_status = lambda: None

        response = client.get("/googleauth/?code=fake-code")
        assert response.status_code == 307
        assert response.headers["location"] == "/"
        assert "session" in response.cookies


def test_logout():
    """Test logout endpoint clears session cookie."""
    response = client.get("/logout", follow_redirects=False)
    assert response.status_code == 307
    assert response.headers["location"] == "/login"
    assert 'session="";' in response.headers["set-cookie"]


@pytest.mark.parametrize(
    "email,patterns,expected",
    [
        ("user@example.com", ["*@example.com"], True),
        ("user@other.com", ["*@example.com"], False),
        ("test@company.com", ["*@company.com"], True),
        ("user@edu.edu", ["*@*.edu"], True),
        ("specific@email.com", ["specific@email.com"], True),
    ],
)
def test_is_authorized(email, patterns, expected):
    """Test email authorization patterns."""
    with patch("app.get_authorized_emails", return_value=patterns):
        assert is_authorized(email) == expected


def test_get_authorized_emails_from_env(mock_env):
    """Test loading authorized emails from environment variable."""
    emails = get_authorized_emails()
    assert len(emails) == 2
    assert "test@example.com" in emails
    assert "*@company.com" in emails


def test_get_authorized_emails_from_file(mock_auth_file):
    """Test loading authorized emails from .auth file."""
    with patch.dict(os.environ, {"AUTH": ""}):
        emails = get_authorized_emails()
        assert len(emails) == 3
        assert "*@example.com" in emails
        assert "specific@email.com" in emails
        assert "*@*.edu" in emails


def test_static_file_serving_unauthorized():
    """Test unauthorized access to static files."""
    with patch.dict(os.environ, {"AUTH": "user@example.com"}):
        response = client.get("/README.md", cookies={"session": "user@unauthorized.com"})
        assert response.status_code == 403
        assert "Unauthorized" in response.text


def test_static_file_serving_public():
    """Test public access to static files, which is the default."""
    with patch.dict(os.environ, {"AUTH": ""}):
        response = client.get("/README.md", cookies={"session": "user@unauthorized.com"})
        assert response.status_code == 200


@pytest.mark.parametrize(
    "path",
    [
        "/../secret.txt",  # Path traversal attempt
        "/.env",  # Dotfile access attempt
        "/nonexistent",  # Missing file
    ],
)
def test_static_file_security(path):
    """Test security measures for static file serving."""
    with patch("app.is_authorized", return_value=True):
        response = client.get(path, cookies={"session": "test@example.com"})
        assert response.status_code == 404


def test_static_file_serving_success(tmp_path):
    """Test successful static file serving."""
    # Create a test file
    test_file = tmp_path / "test.txt"
    test_file.write_text("test content")

    with (
        patch("app.is_authorized", return_value=True),
        patch("pathlib.Path.resolve", return_value=test_file),
    ):
        response = client.get("/test.txt", cookies={"session": "test@example.com"})
        assert response.status_code == 200
        assert response.text == "test content"
        assert "Cache-Control" in response.headers
        assert "X-Content-Type-Options" in response.headers


if __name__ == "__main__":
    pytest.main()