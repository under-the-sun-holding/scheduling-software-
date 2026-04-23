#!/usr/bin/env python3
"""Command-line tool to create and manage admin accounts.

Usage:
  python3 admin_cli.py create <email> <password>
  python3 admin_cli.py list
  python3 admin_cli.py grant <email>
  python3 admin_cli.py revoke <email>
"""

import getpass
import sys
from auth_db import (
    create_user,
    find_user_by_username,
    set_user_role,
    init_db,
)


def main() -> int:
    init_db()
    
    if len(sys.argv) < 2:
        print_usage()
        return 1
    
    command = sys.argv[1].lower()
    
    if command == "create":
        return cmd_create()
    elif command == "list":
        return cmd_list()
    elif command == "grant":
        return cmd_grant()
    elif command == "revoke":
        return cmd_revoke()
    else:
        print(f"Unknown command: {command}")
        print_usage()
        return 1


def print_usage() -> None:
    print("Admin Account Manager")
    print("=" * 50)
    print("Usage:")
    print("  python3 admin_cli.py create <username> [password]")
    print("  python3 admin_cli.py list")
    print("  python3 admin_cli.py grant <username>")
    print("  python3 admin_cli.py revoke <username>")
    print("\nExamples:")
    print("  python3 admin_cli.py create Admin987654321 Gigglewater88")
    print("  python3 admin_cli.py grant user1")
    print("  python3 admin_cli.py list")


def cmd_create() -> int:
    """Create a new admin account."""
    if len(sys.argv) < 3:
        print("Usage: python3 admin_cli.py create <username> [password]")
        return 1
    
    username = sys.argv[2].strip().lower()
    
    if not username:
        print("ERROR: Invalid username")
        return 1
    
    # Get password
    if len(sys.argv) > 3:
        password = sys.argv[3]
    else:
        password = getpass.getpass("Enter password: ")
        confirm = getpass.getpass("Confirm password: ")
        if password != confirm:
            print("ERROR: Passwords do not match")
            return 1
    
    if len(password) < 8:
        print("ERROR: Password must be at least 8 characters")
        return 1
    
    try:
        user = find_user_by_username(username)
        if user:
            print(f"User '{username}' already exists. Use 'grant' to make them admin.")
            return 1
        
        create_user(username, password, role="Admin")
        print(f"✓ Admin account created: {username}")
        return 0
    except Exception as e:
        print(f"ERROR: {e}")
        return 1


def cmd_list() -> int:
    """List all users and their roles."""
    try:
        from auth_db import get_connection
        
        with get_connection() as conn:
            cursor = conn.execute(
                "SELECT id, username, role FROM users ORDER BY username"
            )
            rows = cursor.fetchall()
        
        if not rows:
            print("No users found.")
            return 0
        
        print("\nUsers:")
        print("-" * 60)
        print(f"{'ID':<5} {'Email':<35} {'Role':<15}")
        print("-" * 60)
        
        for row in rows:
            user_id, username, role = row
            print(f"{user_id:<5} {username:<35} {role:<15}")
        
        print("-" * 60)
        print(f"Total: {len(rows)} user(s)")
        return 0
    except Exception as e:
        print(f"ERROR: {e}")
        return 1


def cmd_grant() -> int:
    """Grant admin role to a user."""
    if len(sys.argv) < 3:
        print("Usage: python3 admin_cli.py grant <username>")
        return 1
    
    email = sys.argv[2].strip().lower()
    
    try:
        user = find_user_by_username(email)
        if not user:
            print(f"ERROR: User '{email}' not found")
            return 1
        
        if user.get("role") == "Admin":
            print(f"User '{email}' is already an admin")
            return 0
        
        set_user_role(email, "Admin")
        print(f"✓ Granted admin role to: {email}")
        return 0
    except Exception as e:
        print(f"ERROR: {e}")
        return 1


def cmd_revoke() -> int:
    """Revoke admin role from a user."""
    if len(sys.argv) < 3:
        print("Usage: python3 admin_cli.py revoke <username>")
        return 1
    
    email = sys.argv[2].strip().lower()
    
    try:
        user = find_user_by_username(email)
        if not user:
            print(f"ERROR: User '{email}' not found")
            return 1
        
        if user.get("role") != "Admin":
            print(f"User '{email}' is not an admin")
            return 0
        
        set_user_role(email, "Employee")
        print(f"✓ Revoked admin role from: {email}")
        return 0
    except Exception as e:
        print(f"ERROR: {e}")
        return 1


if __name__ == "__main__":
    sys.exit(main())
