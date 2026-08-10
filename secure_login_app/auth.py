"""
Authentication helpers.

- Password hashing: bcrypt (adaptive, salted, slow-by-design hashing --
  the correct primitive for passwords, unlike a fast hash like SHA-256).
- Input validation: regex-based checks for username, email, and
  password strength, run BEFORE anything touches the database.
- 2FA: TOTP (Time-based One-Time Password, RFC 6238) via pyotp, the
  same standard used by Google Authenticator / Authy.
"""

import re
import bcrypt
import pyotp
import qrcode
import io
import base64

USERNAME_RE = re.compile(r"^[a-zA-Z0-9_]{3,30}$")
EMAIL_RE = re.compile(r"^[^@\s]+@[^@\s]+\.[^@\s]+$")


# --------------------------------------------------------------------------
# Input validation
# --------------------------------------------------------------------------

def validate_username(username: str) -> str | None:
    if not USERNAME_RE.match(username or ""):
        return "Username must be 3-30 characters: letters, numbers, underscores only."
    return None


def validate_email(email: str) -> str | None:
    if not EMAIL_RE.match(email or ""):
        return "Enter a valid email address."
    return None


def validate_password_strength(password: str) -> str | None:
    """Returns an error message, or None if the password is acceptable."""
    if not password or len(password) < 8:
        return "Password must be at least 8 characters."
    if not re.search(r"[a-z]", password):
        return "Password must include a lowercase letter."
    if not re.search(r"[A-Z]", password):
        return "Password must include an uppercase letter."
    if not re.search(r"[0-9]", password):
        return "Password must include a number."
    if not re.search(r"[^a-zA-Z0-9]", password):
        return "Password must include a symbol."
    return None


# --------------------------------------------------------------------------
# Password hashing (bcrypt)
# --------------------------------------------------------------------------

def hash_password(password: str) -> str:
    """bcrypt generates its own random salt and embeds it in the output,
    so no separate salt storage/management is needed."""
    hashed = bcrypt.hashpw(password.encode("utf-8"), bcrypt.gensalt(rounds=12))
    return hashed.decode("utf-8")


def verify_password(password: str, password_hash: str) -> bool:
    try:
        return bcrypt.checkpw(password.encode("utf-8"), password_hash.encode("utf-8"))
    except ValueError:
        return False


# --------------------------------------------------------------------------
# Two-factor authentication (TOTP)
# --------------------------------------------------------------------------

def generate_totp_secret() -> str:
    return pyotp.random_base32()


def get_totp_uri(secret: str, username: str, issuer: str = "SecureLoginApp") -> str:
    return pyotp.totp.TOTP(secret).provisioning_uri(name=username, issuer_name=issuer)


def verify_totp_code(secret: str, code: str) -> bool:
    totp = pyotp.TOTP(secret)
    return totp.verify(code, valid_window=1)  # allow 1 step of clock drift


def generate_qr_code_base64(uri: str) -> str:
    """Returns a base64 PNG data URI, embeddable directly in an <img> tag
    without writing a file to disk."""
    img = qrcode.make(uri)
    buf = io.BytesIO()
    img.save(buf, format="PNG")
    encoded = base64.b64encode(buf.getvalue()).decode("utf-8")
    return f"data:image/png;base64,{encoded}"
