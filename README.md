# Static Auth

A minimal static file server with Google OAuth authentication.

- Serves static files from current directory
- Google OAuth authentication
- Email-based access control via regex patterns
- Blocks access to dotfiles (`.git`, `.env`, etc.)
- CORS enabled

## Usage

1. Create OAuth credentials at [Google Cloud Console](https://console.cloud.google.com/apis/credentials)
   - Set authorized redirect URI to `http://localhost:8000/googleauth/`
   - If you're deploying at `https://yourdomain.com/`, add `https://yourdomain.com/googleauth/`
2. In the folder where you want to serve files, create a `.env` file with the following variables. (Or set them as environment variables.) This is typically done using CI/CD pipelines.

   ```env
   GOOGLE_CLIENT_ID=your-client-id
   GOOGLE_CLIENT_SECRET=your-client-secret
   REDIRECT_URI=http://localhost:8000/googleauth/
   PORT=8000  # Optional, defaults to 8000
   AUTH=*@yourdomain.com,specific@email.com  # Optional, defaults to all emails
   ```

3. Run the server:

   ```bash
   uv run https://raw.githubusercontent.com/sanand0/staticauth/main/app.py
   ```

Open the browser and navigate to `http://localhost:8000`. Only users that match the pattern in `AUTH` will be able to access the files.

## Restricting access

The `AUTH` environment variable is a comma-separated list of email patterns. The patterns are matched against the email address of the user. For example:

- `*@example.com` matches all emails from `example.com`
- `user@example.com` matches only `user@example.com`
- `user*@example.com` matches all emails from `example.com` that start with `user`
- `*user@example.com` matches all emails from `example.com` that end with `user`
- `*@*.edu` matches all emails from all `.edu` domains
- `*` matches all emails

You can also use a `.auth` file in the folder to restrict access, useful to commit email patterns in the repository.

The `.auth` file is a text file with one pattern per line. The patterns are matched against the email address of the user. For example:

```text
*@example.com       # Allow all emails from example.com
user@example.com    # Allow user@example.com
*@*.edu             # Allow all emails from all .edu domains
```
