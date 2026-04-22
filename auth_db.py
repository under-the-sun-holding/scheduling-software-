#!/usr/bin/env python3
"""Simple local user database with secure password hashing.

Usage:
  python3 auth_db.py init
  python3 auth_db.py create-user <username> <password>
  python3 auth_db.py verify-user <username> <password>
  python3 auth_db.py grant-admin <username>
"""

from __future__ import annotations

import base64
import hashlib
import hmac
import os
import sqlite3
import sys
from pathlib import Path


DB_PATH = Path(__file__).resolve().parent / "users.db"
PBKDF2_ITERATIONS = 200_000


def get_connection() -> sqlite3.Connection:
    return sqlite3.connect(DB_PATH)


def init_db() -> None:
    with get_connection() as conn:
        conn.execute(
            """
            CREATE TABLE IF NOT EXISTS users (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                username TEXT NOT NULL UNIQUE,
                password_hash TEXT NOT NULL,
                is_admin INTEGER DEFAULT 0,
                created_at DATETIME DEFAULT CURRENT_TIMESTAMP
            )
            """
        )
        # Add is_admin column if it doesn't exist (migration)
        cursor = conn.execute("PRAGMA table_info(users)")
        columns = {row[1] for row in cursor.fetchall()}
        if "is_admin" not in columns:
            conn.execute("ALTER TABLE users ADD COLUMN is_admin INTEGER DEFAULT 0")
        conn.commit()


def hash_password(password: str, salt: bytes | None = None) -> str:
    if salt is None:
        salt = os.urandom(16)

    digest = hashlib.pbkdf2_hmac(
        "sha256", password.encode("utf-8"), salt, PBKDF2_ITERATIONS
    )
    salt_b64 = base64.b64encode(salt).decode("ascii")
    digest_b64 = base64.b64encode(digest).decode("ascii")
    return f"pbkdf2_sha256${PBKDF2_ITERATIONS}${salt_b64}${digest_b64}"


def verify_password(password: str, stored_hash: str) -> bool:
    try:
        algorithm, iter_str, salt_b64, digest_b64 = stored_hash.split("$", 3)
        if algorithm != "pbkdf2_sha256":
            return False

        iterations = int(iter_str)
        salt = base64.b64decode(salt_b64.encode("ascii"))
        expected_digest = base64.b64decode(digest_b64.encode("ascii"))
    except (ValueError, TypeError, base64.binascii.Error):
        return False

    computed_digest = hashlib.pbkdf2_hmac(
        "sha256", password.encode("utf-8"), salt, iterations
    )
    return hmac.compare_digest(expected_digest, computed_digest)


def create_user(username: str, password: str) -> None:
    if not username.strip():
        raise ValueError("Username cannot be empty.")
    if len(password) < 8:
        raise ValueError("Password must be at least 8 characters.")

    password_hash = hash_password(password)

    with get_connection() as conn:
        conn.execute(
            "INSERT INTO users (username, password_hash) VALUES (?, ?)",
            (username, password_hash),
        )
        conn.commit()


def grant_admin(username: str) -> None:
    """Grant admin access to a user."""
    with get_connection() as conn:
        result = conn.execute(
            "UPDATE users SET is_admin = 1 WHERE username = ?",
            (username,)
        )
        if result.rowcount == 0:
            raise ValueError(f"User '{username}' not found.")
        conn.commit()


def revoke_admin(username: str) -> None:
    """Revoke admin access from a user."""
    with get_connection() as conn:
        result = conn.execute(
            "UPDATE users SET is_admin = 0 WHERE username = ?",
            (username,)
        )
        if result.rowcount == 0:
            raise ValueError(f"User '{username}' not found.")
        conn.commit()


def verify_user(username: str, password: str) -> bool:
    with get_connection() as conn:
        row = conn.execute(
            "SELECT password_hash FROM users WHERE username = ?", (username,)
        ).fetchone()

    if row is None:
        return False
    return verify_password(password, row[0])


def print_usage() -> None:
    print(__doc__.strip())


def main(argv: list[str]) -> int:
    if len(argv) < 2:
        print_usage()
        return 1

    command = argv[1]

    if command == "init":
        init_db()
        print(f"Initialized database at: {DB_PATH}")
        return 0

    if command == "create-user":
        if len(argv) != 4:
            print("Usage: python3 auth_db.py create-user <username> <password>")
            return 1
        init_db()
        try:
            create_user(argv[2], argv[3])
        except sqlite3.IntegrityError:
            print("Error: username already exists.")
            return 1
        except ValueError as exc:
            print(f"Error: {exc}")
            return 1
        print("User created.")
        return 0

    if command == "verify-user":
        if len(argv) != 4:
            print("Usage: python3 auth_db.py verify-user <username> <password>")
            return 1
        init_db()
        print("valid" if verify_user(argv[2], argv[3]) else "invalid")
        return 0

    if command == "grant-admin":
        if len(argv) != 3:
            print("Usage: python3 auth_db.py grant-admin <username>")
            return 1
        try:
            grant_admin(argv[2])
            print(f"Admin access granted to user '{argv[2]}'.")
            return 0
        except ValueError as exc:
            print(f"Error: {exc}")
            return 1

    print_usage()
    return 1


if __name__ == "__main__":
    raise SystemExit(main(sys.argv))
