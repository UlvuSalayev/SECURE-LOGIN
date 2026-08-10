# Secure Login System

A Flask-based secure user registration/login web application.

## Setup

```bash
pip install -r requirements.txt
python app.py
```

Open `http://127.0.0.1:5000` in your browser.

## How each assignment requirement is met

| Requirement | How it's solved | File |
|---|---|---|
| Encrypted passwords | `bcrypt.hashpw()` — automatic salt, adaptive (slow-by-design) hashing. The plaintext password is never written to disk. | `auth.py` |
| Input validation | Username (regex), email (regex), and password strength (length + upper/lower/digit/symbol) are checked before registration. | `auth.py` |
| SQL injection protection | Every query uses `sqlite3`'s `?` parameterized placeholders; user input is never concatenated into SQL text. | `db.py` |
| Session management + logout | Flask's signed, server-side `session` object; a `login_required` decorator guards protected pages; `/logout` fully clears the session. | `app.py` |
| Two-Factor Authentication (2FA) | TOTP (RFC 6238) via `pyotp`, compatible with Google Authenticator / Authy. QR code generated with `qrcode`. | `auth.py`, `app.py`, `setup_2fa.html` |

## Bonus / extra security measures

- **Brute-force protection:** the account locks for 5 minutes after 5 consecutive failed login attempts.
- **Account-enumeration protection:** the same generic error message is shown for a wrong username and a wrong password, making it harder for an attacker to learn which usernames exist.
- **CSRF protection:** every form carries a random token stored in the session, compared server-side with `secrets.compare_digest()` (timing-attack safe).
- **Two-step 2FA flow:** even with a correct password, a full session isn't established if 2FA is enabled -- the TOTP code must be verified first via `/verify-2fa`.

## Known limitations (worth noting in your project report)

- `SECRET_KEY` is randomly generated on every startup unless set via an environment variable -- in production it should be fixed, secret, and managed as an environment variable.
- There's no HTTPS/TLS in this project; a real deployment must encrypt traffic (e.g. behind a reverse proxy with a Let's Encrypt certificate).
- `users.db` is a local SQLite file; a multi-user/production environment should move to something like PostgreSQL.
- This project was built for a class assignment; it should go through a security review before being used in any real production system.

## File structure

```
secure_login_app/
├── app.py              # Flask routes, session management, CSRF
├── auth.py             # Hashing, validation, TOTP/2FA helpers
├── db.py               # SQLite access (parameterized queries)
├── requirements.txt
├── templates/
│   ├── base.html
│   ├── register.html
│   ├── login.html
│   ├── verify_2fa.html
│   ├── setup_2fa.html
│   └── dashboard.html
└── users.db            # Created automatically on first run
```
