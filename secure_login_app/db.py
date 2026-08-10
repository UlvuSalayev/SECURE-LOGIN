"""
Database layer for the secure login system.

SQL-injection protection: every query below uses parameterized
placeholders ('?') instead of string formatting or f-strings to build
SQL. The sqlite3 driver sends the SQL text and the values separately,
so user input can never be interpreted as SQL syntax -- this is the
standard, correct defense against SQL injection.
"""

import sqlite3
from contextlib import contextmanager

DB_PATH = "users.db"


@contextmanager
def get_db(db_path: str = DB_PATH):
    conn = sqlite3.connect(db_path)
    conn.row_factory = sqlite3.Row
    try:
        yield conn
    finally:
        conn.close()


def init_db(db_path: str = DB_PATH) -> None:
    with get_db(db_path) as conn:
        conn.execute(
            """
            CREATE TABLE IF NOT EXISTS users (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                username TEXT NOT NULL UNIQUE,
                email TEXT NOT NULL UNIQUE,
                password_hash TEXT NOT NULL,
                totp_secret TEXT,
                is_2fa_enabled INTEGER NOT NULL DEFAULT 0,
                failed_attempts INTEGER NOT NULL DEFAULT 0,
                locked_until TEXT,
                created_at TEXT DEFAULT CURRENT_TIMESTAMP
            )
            """
        )
        conn.commit()


# --- All functions below use '?' placeholders -- never string-build SQL ---

def create_user(username: str, email: str, password_hash: str, db_path: str = DB_PATH) -> int:
    with get_db(db_path) as conn:
        cur = conn.execute(
            "INSERT INTO users (username, email, password_hash) VALUES (?, ?, ?)",
            (username, email, password_hash),
        )
        conn.commit()
        return cur.lastrowid


def get_user_by_username(username: str, db_path: str = DB_PATH):
    with get_db(db_path) as conn:
        cur = conn.execute("SELECT * FROM users WHERE username = ?", (username,))
        return cur.fetchone()


def get_user_by_email(email: str, db_path: str = DB_PATH):
    with get_db(db_path) as conn:
        cur = conn.execute("SELECT * FROM users WHERE email = ?", (email,))
        return cur.fetchone()


def get_user_by_id(user_id: int, db_path: str = DB_PATH):
    with get_db(db_path) as conn:
        cur = conn.execute("SELECT * FROM users WHERE id = ?", (user_id,))
        return cur.fetchone()


def set_totp_secret(user_id: int, secret: str, db_path: str = DB_PATH) -> None:
    with get_db(db_path) as conn:
        conn.execute("UPDATE users SET totp_secret = ? WHERE id = ?", (secret, user_id))
        conn.commit()


def enable_2fa(user_id: int, db_path: str = DB_PATH) -> None:
    with get_db(db_path) as conn:
        conn.execute("UPDATE users SET is_2fa_enabled = 1 WHERE id = ?", (user_id,))
        conn.commit()


def disable_2fa(user_id: int, db_path: str = DB_PATH) -> None:
    with get_db(db_path) as conn:
        conn.execute(
            "UPDATE users SET is_2fa_enabled = 0, totp_secret = NULL WHERE id = ?",
            (user_id,),
        )
        conn.commit()


def record_failed_attempt(user_id: int, failed_attempts: int, locked_until, db_path: str = DB_PATH) -> None:
    with get_db(db_path) as conn:
        conn.execute(
            "UPDATE users SET failed_attempts = ?, locked_until = ? WHERE id = ?",
            (failed_attempts, locked_until, user_id),
        )
        conn.commit()


def reset_failed_attempts(user_id: int, db_path: str = DB_PATH) -> None:
    with get_db(db_path) as conn:
        conn.execute(
            "UPDATE users SET failed_attempts = 0, locked_until = NULL WHERE id = ?",
            (user_id,),
        )
        conn.commit()
