# Lots of Network - Backend API (`api.lotsofnetwork.com`)

FastAPI backend providing:
- **Authentication**: Sign in with Google (OAuth 2.0 / Google Identity Services) with automatic role resolution (`admin` vs `user`).
- **Authorization**: Role-based access control (RBAC) with JWT Bearer tokens.
- **Freemium & API Monetisation**: API key issuance, rate limiting, and plan usage tracking.
- **Admin Portal**: Metrics, user control, and content management for `admin.lotsofnetwork.com`.

---

## 🛠️ Tech Stack
- **Framework**: [FastAPI](https://fastapi.tiangolo.com/) (Python 3.14+)
- **Server**: [Uvicorn](https://www.uvicorn.org/) with `uvloop`
- **Database**: [SQLAlchemy 2.0](https://www.sqlalchemy.org/) (SQLite for local dev, PostgreSQL for production)
- **Validation**: [Pydantic v2](https://docs.pydantic.dev/) + `pydantic-settings`
- **Auth**: Google Identity Services (`google-auth`) + [PyJWT](https://pyjwt.readthedocs.io/)

---

## 📁 Project Structure

```
api.lotsofnetwork.com/
├── app/
│   ├── api/
│   │   ├── deps.py             # Auth dependencies (get_current_user, require_admin)
│   │   └── v1/
│   │       ├── auth.py         # Google login, user profile
│   │       └── admin.py        # Platform statistics, user management
│   ├── models/
│   │   ├── user.py             # User SQLAlchemy model (role: admin | user)
│   │   └── api_key.py          # ApiKey SQLAlchemy model
│   ├── schemas/
│   │   └── auth.py             # Pydantic request/response schemas
│   ├── services/
│   │   ├── google_auth.py      # Google ID token verification
│   │   └── security.py         # JWT generation and decoding
│   ├── config.py               # Environment settings and admin whitelist
│   ├── database.py             # Engine, SessionLocal, Base
│   └── main.py                 # FastAPI application, CORS, router mounts
├── tests/
│   └── test_auth.py            # Automated tests for Google Auth & Admin RBAC
├── .env.example
├── .gitignore
├── pytest.ini
└── requirements.txt
```

---

## 🚀 Quick Start

### 1. Setup Environment
```bash
python3 -m venv .venv
source .venv/bin/activate
pip install -r requirements.txt
```

### 2. Configure Environment Variables
Copy `.env.example` to `.env`:
```bash
cp .env.example .env
```

Key variables:
| Variable | Description |
|---|---|
| `GOOGLE_CLIENT_ID` | OAuth 2.0 Web Client ID from Google Cloud Console |
| `ADMIN_EMAILS` | Comma-separated list of emails with Admin access (e.g. `realbayajitislam@gmail.com,contact@bayajitislam.com`) |
| `SECRET_KEY` | 64-character random string for signing JWT tokens |
| `DATABASE_URL` | `sqlite:///./lotsofnetwork.db` (or PostgreSQL in production) |

### 3. Run Development Server
```bash
uvicorn app.main:app --reload --port 8000
```
Interactive API documentation will be available at:
- **Swagger UI**: [http://localhost:8000/docs](http://localhost:8000/docs)
- **ReDoc**: [http://localhost:8000/redoc](http://localhost:8000/redoc)

---

## 🔐 Authentication Flow

1. **Frontend**: The user clicks **Sign in with Google** via Google Identity Services (`@react-oauth/google` or One Tap).
2. **Frontend -> Backend**: The client sends the Google `credential` (ID Token JWT) to:
   ```http
   POST /api/v1/auth/google
   Content-Type: application/json

   {
     "credential": "<GOOGLE_ID_TOKEN>"
   }
   ```
3. **Backend**:
   - Verifies the Google token signature.
   - Extracts `email`, `name`, `sub`, and `avatar`.
   - Checks if `email` is in `ADMIN_EMAILS`. If yes, sets `role="admin"`. Otherwise `role="user"`.
   - Returns a JWT access token with role claims.
4. **Authenticated Requests**: Subsequent API calls include the header:
   ```http
   Authorization: Bearer <ACCESS_TOKEN>
   ```

---

## 🧪 Running Tests
```bash
pytest -v
```
