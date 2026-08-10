"""
Secure Login Web Application
Run:
    python app.py
Then open http://127.0.0.1:5000
"""

import os
import re
import secrets
from datetime import datetime, timedelta
from functools import wraps

from flask import (
    Flask, render_template, request, redirect, url_for, session, flash, abort
)

import db
import auth

MAX_FAILED_ATTEMPTS = 5
LOCKOUT_MINUTES = 5

app = Flask(__name__)

app.secret_key = os.environ.get("SECRET_KEY", secrets.token_hex(32))

db.init_db()

def get_csrf_token() -> str:
    if "csrf_token" not in session:
        session["csrf_token"] = secrets.token_hex(16)
    return session["csrf_token"]


@app.context_processor
def inject_csrf_token():
    return {"csrf_token": get_csrf_token()}


def csrf_protect():
    token = session.get("csrf_token")
    submitted = request.form.get("csrf_token")
    if not token or not submitted or not secrets.compare_digest(token, submitted):
        abort(400, description="Invalid or missing CSRF token.")

def login_required(view):
    @wraps(view)
    def wrapped(*args, **kwargs):
        if not session.get("user_id"):
            flash("You must log in to continue.", "error")
            return redirect(url_for("login"))
        return view(*args, **kwargs)
    return wrapped

@app.route("/", methods=["GET"])
def index():
    return redirect(url_for("dashboard") if session.get("user_id") else url_for("login"))


@app.route("/register", methods=["GET", "POST"])
def register():
    if request.method == "GET":
        return render_template("register.html")

    csrf_protect()
    username = request.form.get("username", "").strip()
    email = request.form.get("email", "").strip().lower()
    password = request.form.get("password", "")
    confirm_password = request.form.get("confirm_password", "")

    error = (
        auth.validate_username(username)
        or auth.validate_email(email)
        or auth.validate_password_strength(password)
    )
    if not error and password != confirm_password:
        error = "Passwords do not match."
    if not error and db.get_user_by_username(username):
        error = "That username is already taken."
    if not error and db.get_user_by_email(email):
        error = "That email is already registered."

    if error:
        flash(error, "error")
        return render_template("register.html", form_username=username, form_email=email)

    password_hash = auth.hash_password(password)
    db.create_user(username, email, password_hash)
    flash("Registration successful. You can now log in.", "success")
    return redirect(url_for("login"))


@app.route("/login", methods=["GET", "POST"])
def login():
    if request.method == "GET":
        return render_template("login.html")

    csrf_protect()
    username = request.form.get("username", "").strip()
    password = request.form.get("password", "")

    user = db.get_user_by_username(username)

    
    generic_error = "Incorrect username or password."

    if not user:
        flash(generic_error, "error")
        return render_template("login.html", form_username=username)

    if user["locked_until"]:
        locked_until = datetime.fromisoformat(user["locked_until"])
        if datetime.utcnow() < locked_until:
            flash("Too many failed attempts. The account is temporarily locked -- try again in a few minutes.", "error")
            return render_template("login.html", form_username=username)

    if not auth.verify_password(password, user["password_hash"]):
        attempts = user["failed_attempts"] + 1
        locked_until = None
        if attempts >= MAX_FAILED_ATTEMPTS:
            locked_until = (datetime.utcnow() + timedelta(minutes=LOCKOUT_MINUTES)).isoformat()
        db.record_failed_attempt(user["id"], attempts, locked_until)
        flash(generic_error, "error")
        return render_template("login.html", form_username=username)

    db.reset_failed_attempts(user["id"])

    if user["is_2fa_enabled"]:
        # Don't establish a full session yet -- require the TOTP code first.
        session["pending_2fa_user_id"] = user["id"]
        return redirect(url_for("verify_2fa"))

    session.clear()
    session["user_id"] = user["id"]
    flash("Login successful.", "success")
    return redirect(url_for("dashboard"))


@app.route("/verify-2fa", methods=["GET", "POST"])
def verify_2fa():
    pending_id = session.get("pending_2fa_user_id")
    if not pending_id:
        return redirect(url_for("login"))

    if request.method == "GET":
        return render_template("verify_2fa.html")

    csrf_protect()
    code = request.form.get("code", "").strip()
    user = db.get_user_by_id(pending_id)

    if not user or not user["totp_secret"] or not auth.verify_totp_code(user["totp_secret"], code):
        flash("Invalid verification code.", "error")
        return render_template("verify_2fa.html")

    session.pop("pending_2fa_user_id", None)
    session.clear()
    session["user_id"] = user["id"]
    flash("Login successful.", "success")
    return redirect(url_for("dashboard"))


@app.route("/logout", methods=["POST"])
def logout():
    csrf_protect()
    session.clear()
    flash("Logged out.", "success")
    return redirect(url_for("login"))

@app.route("/dashboard", methods=["GET"])
@login_required
def dashboard():
    user = db.get_user_by_id(session["user_id"])
    return render_template(
        "dashboard.html",
        username=user["username"],
        is_2fa_enabled=bool(user["is_2fa_enabled"]),
    )


@app.route("/setup-2fa", methods=["GET", "POST"])
@login_required
def setup_2fa():
    user = db.get_user_by_id(session["user_id"])

    if request.method == "GET":
        secret = auth.generate_totp_secret()
        session["pending_totp_secret"] = secret
        uri = auth.get_totp_uri(secret, user["username"])
        qr_data_uri = auth.generate_qr_code_base64(uri)
        return render_template("setup_2fa.html", qr_data_uri=qr_data_uri, secret=secret)

    csrf_protect()
    secret = session.get("pending_totp_secret")
    code = request.form.get("code", "").strip()

    if not secret or not auth.verify_totp_code(secret, code):
        flash("Code could not be verified, try again.", "error")
        return redirect(url_for("setup_2fa"))

    db.set_totp_secret(user["id"], secret)
    db.enable_2fa(user["id"])
    session.pop("pending_totp_secret", None)
    flash("2FA enabled successfully.", "success")
    return redirect(url_for("dashboard"))


@app.route("/disable-2fa", methods=["POST"])
@login_required
def disable_2fa_route():
    csrf_protect()
    db.disable_2fa(session["user_id"])
    flash("2FA disabled.", "success")
    return redirect(url_for("dashboard"))


if __name__ == "__main__":
    app.run(debug=False, host="127.0.0.1", port=5000)
