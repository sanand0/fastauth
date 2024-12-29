# FastAuth

A minimal static file server with Google OAuth authentication.

- Serves static files from current directory
- Google OAuth authentication
- Email-based access control via regex patterns
- Blocks access to dotfiles (`.git`, `.env`, etc.)
- CORS enabled

## Usage

```bash
uvx https://raw.githubusercontent.com/sanand0/fastauth/main/app.py
```

## Setup

1. Create OAuth credentials at [Google Cloud Console](https://console.cloud.google.com/apis/credentials)

   - Set authorized redirect URI to `http://localhost:8000/googleauth/`

2. Configure environment variables:

   ```env
   GOOGLE_CLIENT_ID=your-client-id
   GOOGLE_CLIENT_SECRET=your-client-secret
   REDIRECT_URI=http://localhost:8000/googleauth/
   PORT=8000  # Optional, defaults to 8000
   ```

3. Control access by creating `.auth` file:
   ```text
   .*@yourdomain.com     # Allow all emails from domain
   specific@email.com    # Allow specific email
   *                    # Allow all emails (default if no .auth)
   ```
