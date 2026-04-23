#!/usr/bin/env python3
"""Migrate data from SQLite to PostgreSQL on Render.

Usage:
  python3 migrate_to_postgres.py
"""

from __future__ import annotations

import os
import sqlite3
import sys
from pathlib import Path

try:
    import psycopg2
except ImportError:
    print("ERROR: psycopg2 not installed. Run: pip install psycopg2-binary")
    sys.exit(1)


ROOT = Path(__file__).resolve().parent
SQLITE_DB_PATH = ROOT / "users.db"


def get_database_url() -> str:
    """Get PostgreSQL connection URL from environment."""
    database_url = os.environ.get("DATABASE_URL", "").strip()
    if not database_url:
        print("ERROR: DATABASE_URL environment variable not set")
        print("Set it to: postgresql://user:password@host/database")
        sys.exit(1)
    return database_url


def create_postgres_tables(conn) -> None:
    """Create necessary tables in PostgreSQL."""
    with conn.cursor() as cur:
        # Users table
        cur.execute("""
            CREATE TABLE IF NOT EXISTS users (
                id SERIAL PRIMARY KEY,
                username TEXT NOT NULL UNIQUE,
                password_hash TEXT NOT NULL,
                is_admin INTEGER DEFAULT 0,
                created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                role TEXT DEFAULT 'Employee',
                integration_provider TEXT DEFAULT '',
                integration_connected INTEGER DEFAULT 0,
                integration_connected_at TIMESTAMP,
                quickbooks_realm_id TEXT DEFAULT '',
                quickbooks_access_token TEXT DEFAULT '',
                quickbooks_refresh_token TEXT DEFAULT '',
                quickbooks_token_expires_at TIMESTAMP,
                quickbooks_company_name TEXT DEFAULT '',
                quickbooks_last_sync_at TIMESTAMP,
                quickbooks_tokens_encrypted INTEGER DEFAULT 0,
                google_calendar_access_token TEXT DEFAULT '',
                google_calendar_refresh_token TEXT DEFAULT '',
                google_calendar_token_expires_at TIMESTAMP,
                google_calendar_tokens_encrypted INTEGER DEFAULT 0
            )
        """)

        # Account profiles table
        cur.execute("""
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
                updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                FOREIGN KEY(user_id) REFERENCES users(id) ON DELETE CASCADE
            )
        """)

    conn.commit()
    print("✓ PostgreSQL tables created")


def migrate_data(sqlite_path: Path, postgres_url: str) -> None:
    """Migrate data from SQLite to PostgreSQL."""
    # Connect to SQLite
    sqlite_conn = sqlite3.connect(sqlite_path)
    sqlite_conn.row_factory = sqlite3.Row

    # Connect to PostgreSQL
    try:
        postgres_conn = psycopg2.connect(postgres_url)
    except psycopg2.Error as e:
        print(f"ERROR: Failed to connect to PostgreSQL: {e}")
        sys.exit(1)

    try:
        # Create tables
        create_postgres_tables(postgres_conn)

        # Migrate users
        sqlite_cursor = sqlite_conn.cursor()
        sqlite_cursor.execute("SELECT * FROM users")
        users = sqlite_cursor.fetchall()

        if users:
            print(f"\nMigrating {len(users)} users...")
            with postgres_conn.cursor() as cur:
                for user in users:
                    # Extract all columns
                    cols = list(user.keys())
                    vals = [user[col] for col in cols]
                    
                    # Build INSERT ... ON CONFLICT statement
                    placeholders = ", ".join(["%s"] * len(cols))
                    col_names = ", ".join(cols)
                    update_cols = ", ".join([f"{col}=EXCLUDED.{col}" for col in cols if col != "id"])
                    
                    sql = f"""
                        INSERT INTO users ({col_names})
                        VALUES ({placeholders})
                        ON CONFLICT (username) DO UPDATE SET {update_cols}
                    """
                    try:
                        cur.execute(sql, vals)
                    except psycopg2.Error as e:
                        print(f"  Warning: Could not migrate user {user['username']}: {e}")

            postgres_conn.commit()
            print(f"✓ {len(users)} users migrated")

        # Migrate account profiles
        sqlite_cursor.execute("SELECT * FROM account_profiles")
        profiles = sqlite_cursor.fetchall()

        if profiles:
            print(f"\nMigrating {len(profiles)} account profiles...")
            with postgres_conn.cursor() as cur:
                for profile in profiles:
                    cols = list(profile.keys())
                    vals = [profile[col] for col in cols]
                    
                    placeholders = ", ".join(["%s"] * len(cols))
                    col_names = ", ".join(cols)
                    update_cols = ", ".join([f"{col}=EXCLUDED.{col}" for col in cols if col != "user_id"])
                    
                    sql = f"""
                        INSERT INTO account_profiles ({col_names})
                        VALUES ({placeholders})
                        ON CONFLICT (user_id) DO UPDATE SET {update_cols}
                    """
                    try:
                        cur.execute(sql, vals)
                    except psycopg2.Error as e:
                        print(f"  Warning: Could not migrate profile for user_id {profile['user_id']}: {e}")

            postgres_conn.commit()
            print(f"✓ {len(profiles)} account profiles migrated")

        # Verify counts
        print("\n--- Verification ---")
        with postgres_conn.cursor() as cur:
            cur.execute("SELECT COUNT(*) FROM users")
            user_count = cur.fetchone()[0]
            cur.execute("SELECT COUNT(*) FROM account_profiles")
            profile_count = cur.fetchone()[0]

        print(f"PostgreSQL users: {user_count}")
        print(f"PostgreSQL profiles: {profile_count}")

    finally:
        sqlite_conn.close()
        postgres_conn.close()


def main() -> None:
    print("=== SQLite to PostgreSQL Migration ===\n")

    if not SQLITE_DB_PATH.exists():
        print(f"ERROR: SQLite database not found at {SQLITE_DB_PATH}")
        sys.exit(1)

    database_url = get_database_url()
    print(f"Source: {SQLITE_DB_PATH}")
    print(f"Destination: PostgreSQL (via DATABASE_URL)\n")

    migrate_data(SQLITE_DB_PATH, database_url)
    print("\n✓ Migration complete!")
    print("\nNext steps:")
    print("1. Verify data in Render PostgreSQL")
    print("2. Update auth_db.py to use PostgreSQL")
    print("3. Commit and push changes")
    print("4. Delete local users.db")


if __name__ == "__main__":
    main()
