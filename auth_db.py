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
import binascii
import hashlib
import hmac
import os
import sqlite3
import sys
from pathlib import Path


DB_PATH = Path(__file__).resolve().parent / "users.db"
PBKDF2_ITERATIONS = 200_000
ALLOWED_ROLES = {"Admin", "Employee", "Client"}


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
        if "role" not in columns:
            conn.execute("ALTER TABLE users ADD COLUMN role TEXT DEFAULT 'Employee'")
            conn.execute(
                """
                UPDATE users
                SET role = CASE
                    WHEN is_admin = 1 THEN 'Admin'
                    ELSE 'Employee'
                END
                """
            )
        else:
            conn.execute(
                """
                UPDATE users
                SET role = CASE
                    WHEN is_admin = 1 THEN 'Admin'
                    WHEN role IS NULL OR TRIM(role) = '' THEN 'Employee'
                    ELSE role
                END
                """
            )
        if "integration_provider" not in columns:
            conn.execute("ALTER TABLE users ADD COLUMN integration_provider TEXT DEFAULT ''")
        if "integration_connected" not in columns:
            conn.execute("ALTER TABLE users ADD COLUMN integration_connected INTEGER DEFAULT 0")
        if "integration_connected_at" not in columns:
            conn.execute("ALTER TABLE users ADD COLUMN integration_connected_at DATETIME")
        if "quickbooks_realm_id" not in columns:
            conn.execute("ALTER TABLE users ADD COLUMN quickbooks_realm_id TEXT DEFAULT ''")
        if "quickbooks_access_token" not in columns:
            conn.execute("ALTER TABLE users ADD COLUMN quickbooks_access_token TEXT DEFAULT ''")
        if "quickbooks_refresh_token" not in columns:
            conn.execute("ALTER TABLE users ADD COLUMN quickbooks_refresh_token TEXT DEFAULT ''")
        if "quickbooks_token_expires_at" not in columns:
            conn.execute("ALTER TABLE users ADD COLUMN quickbooks_token_expires_at DATETIME")
        if "quickbooks_company_name" not in columns:
            conn.execute("ALTER TABLE users ADD COLUMN quickbooks_company_name TEXT DEFAULT ''")
        if "quickbooks_last_sync_at" not in columns:
            conn.execute("ALTER TABLE users ADD COLUMN quickbooks_last_sync_at DATETIME")
        if "quickbooks_tokens_encrypted" not in columns:
            conn.execute("ALTER TABLE users ADD COLUMN quickbooks_tokens_encrypted INTEGER DEFAULT 0")
        if "google_calendar_access_token" not in columns:
            conn.execute("ALTER TABLE users ADD COLUMN google_calendar_access_token TEXT DEFAULT ''")
        if "google_calendar_refresh_token" not in columns:
            conn.execute("ALTER TABLE users ADD COLUMN google_calendar_refresh_token TEXT DEFAULT ''")
        if "google_calendar_token_expires_at" not in columns:
            conn.execute("ALTER TABLE users ADD COLUMN google_calendar_token_expires_at DATETIME")
        if "google_calendar_tokens_encrypted" not in columns:
            conn.execute("ALTER TABLE users ADD COLUMN google_calendar_tokens_encrypted INTEGER DEFAULT 0")

        conn.execute(
            """
            CREATE TABLE IF NOT EXISTS account_profiles (
                user_id INTEGER PRIMARY KEY,
                full_name TEXT DEFAULT '',
                phone TEXT DEFAULT '',
                company_name TEXT DEFAULT '',
                address_line1 TEXT DEFAULT '',
                address_line2 TEXT DEFAULT '',
                city TEXT DEFAULT '',
                state TEXT DEFAULT '',
                postal_code TEXT DEFAULT '',
                notes TEXT DEFAULT '',
                updated_at DATETIME DEFAULT CURRENT_TIMESTAMP,
                FOREIGN KEY(user_id) REFERENCES users(id) ON DELETE CASCADE
            )
            """
        )
        conn.commit()


def normalize_role(role: str) -> str:
    value = str(role or "").strip().lower()
    if value == "admin":
        return "Admin"
    if value == "employee":
        return "Employee"
    if value == "client":
        return "Client"
    raise ValueError("role must be one of: Admin, Employee, Client")


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
    except (ValueError, TypeError, binascii.Error):
        return False

    computed_digest = hashlib.pbkdf2_hmac(
        "sha256", password.encode("utf-8"), salt, iterations
    )
    return hmac.compare_digest(expected_digest, computed_digest)


def create_user(username: str, password: str, role: str = "Employee") -> None:
    username = str(username or "").strip().lower()
    if not username:
        raise ValueError("Username cannot be empty.")
    if len(password) < 8:
        raise ValueError("Password must be at least 8 characters.")

    password_hash = hash_password(password)

    normalized_role = normalize_role(role)

    with get_connection() as conn:
        conn.execute(
            "INSERT INTO users (username, password_hash, is_admin, role) VALUES (?, ?, ?, ?)",
            (username, password_hash, 1 if normalized_role == "Admin" else 0, normalized_role),
        )
        conn.commit()


def grant_admin(username: str) -> None:
    """Grant admin access to a user."""
    username = str(username or "").strip()
    with get_connection() as conn:
        result = conn.execute(
            "UPDATE users SET is_admin = 1, role = 'Admin' WHERE lower(username) = lower(?)",
            (username,)
        )
        if result.rowcount == 0:
            raise ValueError(f"User '{username}' not found.")
        conn.commit()


def revoke_admin(username: str) -> None:
    """Revoke admin access from a user."""
    username = str(username or "").strip()
    with get_connection() as conn:
        result = conn.execute(
            "UPDATE users SET is_admin = 0, role = 'Employee' WHERE lower(username) = lower(?)",
            (username,)
        )
        if result.rowcount == 0:
            raise ValueError(f"User '{username}' not found.")
        conn.commit()


def change_password(username: str, new_password: str) -> None:
    username = str(username or "").strip()
    if len(new_password) < 8:
        raise ValueError("Password must be at least 8 characters.")

    password_hash = hash_password(new_password)

    with get_connection() as conn:
        result = conn.execute(
            "UPDATE users SET password_hash = ? WHERE lower(username) = lower(?)",
            (password_hash, username),
        )
        if result.rowcount == 0:
            raise ValueError(f"User '{username}' not found.")
        conn.commit()


def verify_user(username: str, password: str) -> bool:
    username = str(username or "").strip()
    with get_connection() as conn:
        row = conn.execute(
            "SELECT password_hash FROM users WHERE lower(username) = lower(?)", (username,)
        ).fetchone()

    if row is None:
        return False
    return verify_password(password, row[0])


def find_user_by_username(username: str) -> dict | None:
    normalized = str(username or "").strip()
    if not normalized:
        return None
    with get_connection() as conn:
        row = conn.execute(
            "SELECT id, username, role, is_admin FROM users WHERE lower(username) = lower(?)",
            (normalized,),
        ).fetchone()
    if row is None:
        return None
    role = str(row[2] or "").strip() or ("Admin" if int(row[3] or 0) else "Employee")
    return {
        "id": int(row[0]),
        "username": str(row[1] or "").strip(),
        "role": role,
    }


def find_user_by_id(user_id: int) -> dict | None:
    with get_connection() as conn:
        row = conn.execute(
            "SELECT id, username, role, is_admin FROM users WHERE id = ?",
            (int(user_id),),
        ).fetchone()
    if row is None:
        return None
    role = str(row[2] or "").strip() or ("Admin" if int(row[3] or 0) else "Employee")
    return {
        "id": int(row[0]),
        "username": str(row[1] or "").strip(),
        "role": role,
    }


def get_user_role(username: str) -> str:
    user = find_user_by_username(username)
    if user is None:
        raise ValueError("user not found")
    return str(user.get("role", "Employee"))


def set_user_role(username: str, role: str) -> None:
    username = str(username or "").strip()
    normalized_role = normalize_role(role)
    with get_connection() as conn:
        result = conn.execute(
            "UPDATE users SET role = ?, is_admin = ? WHERE lower(username) = lower(?)",
            (normalized_role, 1 if normalized_role == "Admin" else 0, username),
        )
        if result.rowcount == 0:
            raise ValueError(f"User '{username}' not found.")
        conn.commit()


def get_account_profile(user_id: int) -> dict:
    with get_connection() as conn:
        user_row = conn.execute(
            "SELECT id, username, role FROM users WHERE id = ?",
            (int(user_id),),
        ).fetchone()
        if user_row is None:
            raise ValueError("user not found")

        profile_row = conn.execute(
            """
            SELECT full_name,
                   phone,
                   company_name,
                   address_line1,
                   address_line2,
                   city,
                   state,
                   postal_code,
                   notes,
                   updated_at
            FROM account_profiles
            WHERE user_id = ?
            """,
            (int(user_id),),
        ).fetchone()

    if profile_row is None:
        return {
            "user_id": int(user_row[0]),
            "username": str(user_row[1] or "").strip(),
            "role": str(user_row[2] or "Employee").strip() or "Employee",
            "full_name": "",
            "phone": "",
            "company_name": "",
            "address_line1": "",
            "address_line2": "",
            "city": "",
            "state": "",
            "postal_code": "",
            "notes": "",
            "updated_at": "",
        }

    return {
        "user_id": int(user_row[0]),
        "username": str(user_row[1] or "").strip(),
        "role": str(user_row[2] or "Employee").strip() or "Employee",
        "full_name": str(profile_row[0] or "").strip(),
        "phone": str(profile_row[1] or "").strip(),
        "company_name": str(profile_row[2] or "").strip(),
        "address_line1": str(profile_row[3] or "").strip(),
        "address_line2": str(profile_row[4] or "").strip(),
        "city": str(profile_row[5] or "").strip(),
        "state": str(profile_row[6] or "").strip(),
        "postal_code": str(profile_row[7] or "").strip(),
        "notes": str(profile_row[8] or "").strip(),
        "updated_at": str(profile_row[9] or "").strip(),
    }


def upsert_account_profile(
    user_id: int,
    full_name: str = "",
    phone: str = "",
    company_name: str = "",
    address_line1: str = "",
    address_line2: str = "",
    city: str = "",
    state: str = "",
    postal_code: str = "",
    notes: str = "",
) -> dict:
    with get_connection() as conn:
        user_row = conn.execute(
            "SELECT id FROM users WHERE id = ?",
            (int(user_id),),
        ).fetchone()
        if user_row is None:
            raise ValueError("user not found")

        conn.execute(
            """
            INSERT INTO account_profiles (
                user_id,
                full_name,
                phone,
                company_name,
                address_line1,
                address_line2,
                city,
                state,
                postal_code,
                notes,
                updated_at
            ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, CURRENT_TIMESTAMP)
            ON CONFLICT(user_id) DO UPDATE SET
                full_name = excluded.full_name,
                phone = excluded.phone,
                company_name = excluded.company_name,
                address_line1 = excluded.address_line1,
                address_line2 = excluded.address_line2,
                city = excluded.city,
                state = excluded.state,
                postal_code = excluded.postal_code,
                notes = excluded.notes,
                updated_at = CURRENT_TIMESTAMP
            """,
            (
                int(user_id),
                str(full_name or "").strip(),
                str(phone or "").strip(),
                str(company_name or "").strip(),
                str(address_line1 or "").strip(),
                str(address_line2 or "").strip(),
                str(city or "").strip(),
                str(state or "").strip(),
                str(postal_code or "").strip(),
                str(notes or "").strip(),
            ),
        )
        conn.commit()

    return get_account_profile(int(user_id))


def print_usage() -> None:
    print((__doc__ or "").strip())


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
