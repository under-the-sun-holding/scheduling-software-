# scheduling-software-
schedules field services 

## Local User Database

This project now includes a simple local SQLite user database with secure password hashing.

### Run the app server

```bash
python3 server.py
```

This serves the landing page and auth APIs at `http://localhost:8000`.

You can create users directly in the Login section using the **Create New User** form.

### 1) Initialize the database

```bash
python3 auth_db.py init
```

### 2) Create a user

```bash
python3 auth_db.py create-user <username> <password>
```

Notes:
- Passwords are never stored in plain text.
- Passwords are hashed using PBKDF2-SHA256 with a per-user random salt.

### 3) Verify a login

```bash
python3 auth_db.py verify-user <username> <password>
```

Output will be `valid` or `invalid`.

### API endpoints

When `server.py` is running:

- `POST /api/register` with JSON `{ "username": "email", "password": "secret" }`
- `POST /api/login` with JSON `{ "username": "email", "password": "secret" }`

## QuickBooks OAuth (Real Auth)

To enable real QuickBooks connection, set these environment variables before running the server:

```bash
export QUICKBOOKS_CLIENT_ID="your_intuit_client_id"
export QUICKBOOKS_CLIENT_SECRET="your_intuit_client_secret"
export QUICKBOOKS_REDIRECT_URI="http://localhost:8000/api/quickbooks/callback"
```

In your Intuit app settings, add the same Redirect URI.

When configured, users can click **Connect QuickBooks** in the app and complete OAuth with Intuit.

Server OAuth routes:
- `GET /api/quickbooks/connect?username=<logged_in_username>`
- `GET /api/quickbooks/callback`

## Google Calendar OAuth (Real Auth)

To enable real Google Calendar connection, set these environment variables before running the server:

```bash
export GOOGLE_CLIENT_ID="your_google_client_id"
export GOOGLE_CLIENT_SECRET="your_google_client_secret"
export GOOGLE_REDIRECT_URI="http://localhost:8000/api/google-calendar/callback"
```

To get these credentials:
1. Go to [Google Cloud Console](https://console.cloud.google.com/)
2. Create a new project
3. Enable the Google Calendar API
4. Create an OAuth 2.0 Client ID (Web application)
5. Add your Redirect URI to the authorized redirect URIs
6. Copy the Client ID and Client Secret

When configured, users can click **Connect** and select **Google Calendar** to complete OAuth with Google and view their calendars.

Server OAuth routes:
- `GET /api/google-calendar/connect?username=<logged_in_username>`
- `GET /api/google-calendar/callback`
- `GET /api/google-calendar/calendars?username=<logged_in_username>` (returns available calendars)
