# /// script
# requires-python = ">=3.11"
# dependencies = [
#     "python-dotenv",
#     "fastapi",
#     "google-auth",
#     "httpx",
#     "requests",
#     "uvicorn",
# ]
# ///
from dotenv import load_dotenv
from fastapi import FastAPI, Request, HTTPException, Security, Depends
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import HTMLResponse, RedirectResponse, FileResponse
from fastapi.security import APIKeyCookie
from fnmatch import fnmatch
from google.auth.transport import requests
from google.oauth2 import id_token
from typing import List
import httpx
import logging
import os
import pathlib

logger = logging.getLogger(__name__)
load_dotenv()

app = FastAPI()
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# Load Google OAuth credentials
GOOGLE_CLIENT_ID = os.getenv("GOOGLE_CLIENT_ID")
GOOGLE_CLIENT_SECRET = os.getenv("GOOGLE_CLIENT_SECRET")
REDIRECT_URI = os.getenv("REDIRECT_URI")

auth_info = {
  "mtime": 0,
  "emails": []
}

cookie_scheme = APIKeyCookie(name="session")

def get_authorized_emails() -> List[str]:
    """Load and cache authorized email patterns from .auth file.

    Returns:
        List[str]: List of authorized email patterns
    """
    try:
        new_time = os.path.getmtime(".auth")
        if new_time > auth_info["mtime"]:
            auth_info["mtime"] = new_time
            with open(".auth") as f:
                patterns = [line.strip() for line in f.readlines()]
                auth_info["emails"] = [pattern for pattern in patterns if pattern]
        return auth_info["emails"]
    except FileNotFoundError:
        return ["*"]

async def get_current_user(session: str = Security(cookie_scheme)) -> str:
    """Validate session cookie and return email.

    Args:
        session: Session cookie value

    Returns:
        str: Authenticated email

    Raises:
        HTTPException: If session is invalid
    """
    if not session or not isinstance(session, str):
        raise HTTPException(status_code=401, detail="Invalid session")
    return session

def is_authorized(email: str) -> bool:
    """Check if email matches any pattern in .auth file."""
    return any(fnmatch(email, pattern) for pattern in get_authorized_emails())

def unauthorized_html(email: str) -> str:
    """Return HTML for unauthorized access page."""
    return f"""
      <div style="
        font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, sans-serif;
        max-width: 600px;
        margin: 100px auto;
        padding: 2rem;
        text-align: center;
        border-radius: 8px;
        box-shadow: 0 2px 4px rgba(0,0,0,0.1);
        background: #fff;
      ">
        <h1 style="
          color: #e53e3e;
          margin-bottom: 1.5rem;
        ">Unauthorized</h1>
        <p style="
          color: #4a5568;
          margin-bottom: 2rem;
          line-height: 1.6;
        ">Your email <strong>{email}</strong> is not authorized to access this content.</p>
        <a href="/logout" style="
          display: inline-block;
          background: #3182ce;
          color: white;
          padding: 0.75rem 1.5rem;
          text-decoration: none;
          border-radius: 4px;
          font-weight: 500;
          transition: background 0.2s;
        ">Login as different user</a>
      </div>
    """

@app.get("/login")
async def login():
    """Redirect to Google OAuth login page."""
    auth_url = f"https://accounts.google.com/o/oauth2/v2/auth?response_type=code&client_id={GOOGLE_CLIENT_ID}&redirect_uri={REDIRECT_URI}&scope=email profile"
    return RedirectResponse(auth_url)

@app.get("/googleauth/")
async def googleauth(code: str):
    """Handle OAuth callback and set session cookie."""
    try:
        token_url = "https://oauth2.googleapis.com/token"
        token_data = {
            "code": code,
            "client_id": GOOGLE_CLIENT_ID,
            "client_secret": GOOGLE_CLIENT_SECRET,
            "redirect_uri": REDIRECT_URI,
            "grant_type": "authorization_code"
        }

        async with httpx.AsyncClient() as client:
            token_response = await client.post(token_url, data=token_data)
            token_response.raise_for_status()
            print(token_response.json())
            id_info = id_token.verify_oauth2_token(
                token_response.json()["id_token"],
                requests.Request(),
                GOOGLE_CLIENT_ID
            )
            print(id_info)

        response = RedirectResponse("/")
        response.set_cookie(
            "session",
            id_info["email"],
            httponly=True,
            secure=True,
            samesite="lax"
        )
        return response
    except Exception as e:
        raise HTTPException(status_code=400, detail=str(e))

@app.get("/logout")
async def logout():
    """Clear session cookie and redirect to login."""
    response = RedirectResponse("/login")
    response.delete_cookie("session")
    return response

@app.get("/{path:path}")
def serve_static(
    request: Request,
    path: str,
    email: str = Depends(get_current_user)
):
    """Serve static files with authentication and security checks.

    Args:
        request: FastAPI request
        path: Requested file path
        email: Authenticated email from session

    Returns:
        FileResponse: Requested file

    Raises:
        HTTPException: If file access is denied or not found
    """
    if not is_authorized(email):
        return HTMLResponse(unauthorized_html(email), status_code=403)

    file_path = pathlib.Path(path or "index.html").resolve()
    root_path = pathlib.Path().resolve()

    # Prevent path traversal
    if not str(file_path).startswith(str(root_path)):
        raise HTTPException(status_code=404)

    # Block dot files
    if any(part.startswith(".") for part in file_path.parts):
        raise HTTPException(status_code=404)

    if not file_path.is_file():
        raise HTTPException(status_code=404)

    return FileResponse(
        file_path,
        headers={
            "Cache-Control": "private, max-age=3600",
            "X-Content-Type-Options": "nosniff",
        }
    )


if __name__ == "__main__":
    import uvicorn

    PORT = int(os.getenv("PORT", 8000))
    uvicorn.run(app, host="0.0.0.0", port=PORT)
