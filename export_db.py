#!/usr/bin/env python3
"""Export SQLite database to JSON for backup/migration purposes.

Usage:
  python3 export_db.py
"""

import json
import sqlite3
from pathlib import Path


DB_PATH = Path(__file__).resolve().parent / "users.db"


def export_to_json() -> None:
    """Export SQLite data to JSON files."""
    if not DB_PATH.exists():
        print(f"ERROR: Database not found at {DB_PATH}")
        return

    conn = sqlite3.connect(DB_PATH)
    conn.row_factory = sqlite3.Row

    # Export users
    cursor = conn.cursor()
    cursor.execute("SELECT * FROM users")
    users_rows = cursor.fetchall()
    users = [dict(row) for row in users_rows]

    # Export profiles
    cursor.execute("SELECT * FROM account_profiles")
    profiles_rows = cursor.fetchall()
    profiles = [dict(row) for row in profiles_rows]

    conn.close()

    # Write to JSON files
    users_path = Path(__file__).resolve().parent / "backup_users.json"
    profiles_path = Path(__file__).resolve().parent / "backup_profiles.json"

    with open(users_path, "w") as f:
        json.dump(users, f, indent=2)
    print(f"✓ Exported {len(users)} users to {users_path.name}")

    with open(profiles_path, "w") as f:
        json.dump(profiles, f, indent=2)
    print(f"✓ Exported {len(profiles)} profiles to {profiles_path.name}")

    print("\nIMPORTANT for Render migration:")
    print("1. Keep these JSON files as backup")
    print("2. Set BOOTSTRAP_ADMIN_USERNAME and BOOTSTRAP_ADMIN_PASSWORD in Render env vars")
    print("3. The admin account will be created automatically on first deploy")
    print("4. Delete local users.db ONLY after verifying data on Render")


if __name__ == "__main__":
    export_to_json()
