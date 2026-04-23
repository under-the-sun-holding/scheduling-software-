#!/usr/bin/env python3
"""Serve the landing page and auth APIs.

Usage:
  python3 server.py
  python3 server.py 8080
"""

from __future__ import annotations

import hashlib
import hmac
import json
import base64
import os
import secrets
import sqlite3
import sys
import time
import urllib.error
import urllib.parse
import urllib.request
from datetime import datetime, timezone
from http.server import SimpleHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path

from auth_db import create_user, grant_admin, revoke_admin, init_db, verify_user


ROOT = Path(__file__).resolve().parent
JOBS_PATH = ROOT / "jobs.json"
CLIENTS_PATH = ROOT / "clients.json"
EMPLOYEES_PATH = ROOT / "employees.json"
DEFAULT_JOBS = [
    {
        "id": 101,
        "customer_name": "Harbor View Apartments",
        "service_type": "HVAC Repair",
        "time": "08:00 AM",
        "status": "Scheduled",
        "duration_minutes": 120,
        "assigned_tech": "Dave",
        "emergency": True,
        "recurring": False,
        "manual_block_minutes": None,
    },
    {
        "id": 102,
        "customer_name": "Baker Family Residence",
        "service_type": "Electrical Inspection",
        "time": "10:00 AM",
        "status": "In Progress",
        "duration_minutes": 60,
        "assigned_tech": "Sarah",
        "emergency": False,
        "recurring": True,
        "manual_block_minutes": None,
    },
    {
        "id": 103,
        "customer_name": "Oak Street Dental",
        "service_type": "Plumbing Maintenance",
        "time": "Unscheduled",
        "status": "Pending",
        "duration_minutes": 180,
        "assigned_tech": None,
        "emergency": False,
        "recurring": False,
        "manual_block_minutes": None,
    },
    {
        "id": 104,
        "customer_name": "Northside Warehouse",
        "service_type": "Generator Service",
        "time": "03:00 PM",
        "status": "Completed",
        "duration_minutes": 120,
        "assigned_tech": "Alex",
        "emergency": False,
        "recurring": False,
        "manual_block_minutes": None,
    },
]
JOBS: list[dict] = []
CLIENTS: list[dict] = []
EMPLOYEES: list[dict] = []
QUICKBOOKS_AUTH_URL = "https://appcenter.intuit.com/connect/oauth2"
QUICKBOOKS_TOKEN_URL = "https://oauth.platform.intuit.com/oauth2/v1/tokens/bearer"
QUICKBOOKS_SCOPES = "com.intuit.quickbooks.accounting"
QUICKBOOKS_API_BASE_URL = "https://quickbooks.api.intuit.com"
QUICKBOOKS_SANDBOX_API_BASE_URL = "https://sandbox-quickbooks.api.intuit.com"
OAUTH_STATE_TTL_SECONDS = 600
OAUTH_STATES: dict[str, dict[str, object]] = {}
ENCRYPTED_TOKEN_PREFIX = "enc::"


def normalize_client(raw: dict) -> dict:
    return {
        "id": int(raw.get("id", 0)),
        "name": str(raw.get("name", "")).strip(),
        "phone": str(raw.get("phone", "")).strip(),
        "email": str(raw.get("email", "")).strip(),
        "address_line1": str(raw.get("address_line1", "")).strip(),
        "address_line2": str(raw.get("address_line2", "")).strip(),
        "city": str(raw.get("city", "")).strip(),
        "state": str(raw.get("state", "")).strip(),
        "postal_code": str(raw.get("postal_code", "")).strip(),
        "notes": str(raw.get("notes", "")).strip(),
        "integration_provider": str(raw.get("integration_provider", "")).strip(),
        "integration_connected": parse_bool(raw.get("integration_connected", False)),
        "integration_connected_at": str(raw.get("integration_connected_at", "")).strip(),
    }


def load_clients() -> None:
    global CLIENTS
    if CLIENTS_PATH.exists():
        try:
            data = json.loads(CLIENTS_PATH.read_text(encoding="utf-8"))
            if isinstance(data, list):
                CLIENTS = []
                for item in data:
                    if isinstance(item, dict):
                        CLIENTS.append(normalize_client(item))
                return
        except json.JSONDecodeError:
            pass

    CLIENTS = []
    save_clients()


def save_clients() -> None:
    CLIENTS_PATH.write_text(json.dumps(CLIENTS, indent=2), encoding="utf-8")


def find_client(client_id: int) -> dict | None:
    for client in CLIENTS:
        if client.get("id") == client_id:
            return client
    return None


def normalize_employee(raw: dict) -> dict:
    return {
        "id": int(raw.get("id", 0)),
        "name": str(raw.get("name", "")).strip(),
        "source": str(raw.get("source", "manual")).strip() or "manual",
        "quickbooks_employee_id": str(raw.get("quickbooks_employee_id", "")).strip(),
        "title": str(raw.get("title", "")).strip(),
        "phone": str(raw.get("phone", "")).strip(),
        "mobile": str(raw.get("mobile", "")).strip(),
        "email": str(raw.get("email", "")).strip(),
        "active": parse_bool(raw.get("active", True)),
        "added_at": str(raw.get("added_at", "")).strip(),
    }


def load_employees() -> None:
    global EMPLOYEES
    if EMPLOYEES_PATH.exists():
        try:
            data = json.loads(EMPLOYEES_PATH.read_text(encoding="utf-8"))
            if isinstance(data, list):
                EMPLOYEES = []
                for item in data:
                    if isinstance(item, dict):
                        EMPLOYEES.append(normalize_employee(item))
                return
        except json.JSONDecodeError:
            pass

    EMPLOYEES = [
        normalize_employee({"id": 1, "name": "Dave"}),
        normalize_employee({"id": 2, "name": "Sarah"}),
        normalize_employee({"id": 3, "name": "Alex"}),
    ]
    save_employees()


def save_employees() -> None:
    EMPLOYEES_PATH.write_text(json.dumps(EMPLOYEES, indent=2), encoding="utf-8")


def next_employee_id() -> int:
    return max((int(employee.get("id", 0)) for employee in EMPLOYEES), default=0) + 1


def find_employee(employee_id: int) -> dict | None:
    for employee in EMPLOYEES:
        if int(employee.get("id", 0)) == employee_id:
            return employee
    return None


def load_jobs() -> None:
    global JOBS
    if JOBS_PATH.exists():
        try:
            data = json.loads(JOBS_PATH.read_text(encoding="utf-8"))
            if isinstance(data, list):
                JOBS = []
                for job in data:
                    if not isinstance(job, dict):
                        continue
                    normalized = dict(job)
                    normalized["duration_minutes"] = int(
                        normalized.get("duration_minutes", 60)
                    )
                    normalized["assigned_tech"] = normalized.get("assigned_tech")
                    normalized["emergency"] = bool(normalized.get("emergency", False))
                    normalized["recurring"] = bool(normalized.get("recurring", False))
                    manual_block = normalized.get("manual_block_minutes")
                    normalized["manual_block_minutes"] = (
                        int(manual_block)
                        if isinstance(manual_block, (int, float))
                        else None
                    )
                    client_id = normalized.get("client_id")
                    normalized["client_id"] = (
                        int(client_id)
                        if isinstance(client_id, (int, float))
                        else None
                    )
                    normalized["phone"] = str(normalized.get("phone", "")).strip()
                    normalized["email"] = str(normalized.get("email", "")).strip()
                    normalized["address_line1"] = str(
                        normalized.get("address_line1", "")
                    ).strip()
                    normalized["address_line2"] = str(
                        normalized.get("address_line2", "")
                    ).strip()
                    normalized["city"] = str(normalized.get("city", "")).strip()
                    normalized["state"] = str(normalized.get("state", "")).strip()
                    normalized["postal_code"] = str(
                        normalized.get("postal_code", "")
                    ).strip()
                    normalized["notes"] = str(normalized.get("notes", "")).strip()
                    JOBS.append(normalized)
                if not JOBS:
                    JOBS = [dict(job) for job in DEFAULT_JOBS]
                    save_jobs()
                return
        except json.JSONDecodeError:
            pass

    JOBS = [dict(job) for job in DEFAULT_JOBS]
    save_jobs()


def save_jobs() -> None:
    JOBS_PATH.write_text(json.dumps(JOBS, indent=2), encoding="utf-8")


def find_job(job_id: int) -> dict | None:
    for job in JOBS:
        if job.get("id") == job_id:
            return job
    return None


def parse_bool(value: object) -> bool:
    if isinstance(value, bool):
        return value
    if isinstance(value, str):
        return value.strip().lower() in {"1", "true", "yes", "on"}
    if isinstance(value, (int, float)):
        return bool(value)
    return False


def _token_encryption_key() -> bytes | None:
    # If APP_SECRET_KEY is set, derive a stable Fernet key from it.
    raw = os.environ.get("APP_SECRET_KEY", "").strip()
    if not raw:
        return None
    digest = hashlib.sha256(raw.encode("utf-8")).digest()
    return base64.urlsafe_b64encode(digest)


def can_encrypt_quickbooks_tokens() -> bool:
    if _token_encryption_key() is None:
        return False
    try:
        from cryptography.fernet import Fernet  # type: ignore
    except Exception:
        return False
    return Fernet is not None


def encrypt_quickbooks_token(value: str) -> str:
    token = str(value or "").strip()
    if not token:
        return ""
    if token.startswith(ENCRYPTED_TOKEN_PREFIX):
        return token
    key = _token_encryption_key()
    if key is None:
        return token
    try:
        from cryptography.fernet import Fernet  # type: ignore
    except Exception:
        return token
    cipher = Fernet(key)
    encrypted = cipher.encrypt(token.encode("utf-8")).decode("utf-8")
    return f"{ENCRYPTED_TOKEN_PREFIX}{encrypted}"


def decrypt_quickbooks_token(value: str) -> str:
    token = str(value or "").strip()
    if not token:
        return ""
    if not token.startswith(ENCRYPTED_TOKEN_PREFIX):
        return token
    key = _token_encryption_key()
    if key is None:
        return ""
    payload = token[len(ENCRYPTED_TOKEN_PREFIX) :]
    try:
        from cryptography.fernet import Fernet, InvalidToken  # type: ignore
    except Exception:
        return ""
    try:
        cipher = Fernet(key)
        return cipher.decrypt(payload.encode("utf-8")).decode("utf-8").strip()
    except InvalidToken:
        return ""


def mark_quickbooks_sync(username: str, synced_at_iso: str | None = None) -> None:
    from auth_db import get_connection

    synced_at = synced_at_iso or datetime.now(timezone.utc).isoformat()
    with get_connection() as conn:
        conn.execute(
            """
            UPDATE users
            SET quickbooks_last_sync_at = ?
            WHERE username = ?
            """,
            (synced_at, username),
        )
        conn.commit()


def set_quickbooks_company_name(username: str, company_name: str) -> None:
    from auth_db import get_connection

    name = str(company_name or "").strip()
    if not name:
        return
    with get_connection() as conn:
        conn.execute(
            """
            UPDATE users
            SET quickbooks_company_name = ?
            WHERE username = ?
            """,
            (name, username),
        )
        conn.commit()


def fetch_quickbooks_company_name(realm_id: str, access_token: str) -> str:
    payload = quickbooks_query(
        realm_id,
        access_token,
        "SELECT * FROM CompanyInfo STARTPOSITION 1 MAXRESULTS 1",
    )
    query_response = payload.get("QueryResponse", {})
    if not isinstance(query_response, dict):
        return ""
    company_list = query_response.get("CompanyInfo", [])
    if not isinstance(company_list, list) or not company_list:
        return ""
    company_info = company_list[0] if isinstance(company_list[0], dict) else {}
    if not isinstance(company_info, dict):
        return ""
    return str(
        company_info.get("CompanyName")
        or company_info.get("LegalName")
        or company_info.get("Name")
        or ""
    ).strip()


def quickbooks_settings() -> dict[str, str]:
    return {
        "client_id": os.environ.get("QUICKBOOKS_CLIENT_ID", "").strip(),
        "client_secret": os.environ.get("QUICKBOOKS_CLIENT_SECRET", "").strip(),
        "redirect_uri": os.environ.get("QUICKBOOKS_REDIRECT_URI", "").strip(),
    }


def quickbooks_is_configured() -> bool:
    settings = quickbooks_settings()
    return bool(
        settings["client_id"]
        and settings["client_secret"]
        and settings["redirect_uri"]
    )


def prune_oauth_states() -> None:
    now = time.time()
    expired: list[str] = []
    for key, entry in OAUTH_STATES.items():
        created_raw = entry.get("created_at", 0.0)
        created_at = (
            float(created_raw)
            if isinstance(created_raw, (int, float, str))
            else 0.0
        )
        if (now - created_at) > OAUTH_STATE_TTL_SECONDS:
            expired.append(key)
    for key in expired:
        OAUTH_STATES.pop(key, None)


def exchange_quickbooks_code(code: str) -> dict:
    settings = quickbooks_settings()
    payload = urllib.parse.urlencode(
        {
            "grant_type": "authorization_code",
            "code": code,
            "redirect_uri": settings["redirect_uri"],
        }
    ).encode("utf-8")

    basic_auth = f"{settings['client_id']}:{settings['client_secret']}".encode("utf-8")
    auth_header = "Basic " + base64.b64encode(basic_auth).decode("ascii")
    request = urllib.request.Request(
        QUICKBOOKS_TOKEN_URL,
        data=payload,
        headers={
            "Accept": "application/json",
            "Content-Type": "application/x-www-form-urlencoded",
            "Authorization": auth_header,
        },
        method="POST",
    )

    try:
        with urllib.request.urlopen(request, timeout=20) as response:
            body = response.read().decode("utf-8")
            return json.loads(body)
    except urllib.error.HTTPError as exc:
        body = exc.read().decode("utf-8", errors="replace")
        raise ValueError(f"QuickBooks token exchange failed: {body}") from exc
    except urllib.error.URLError as exc:
        raise ValueError(f"Unable to reach QuickBooks: {exc.reason}") from exc


def refresh_quickbooks_tokens(refresh_token: str) -> dict:
    settings = quickbooks_settings()
    payload = urllib.parse.urlencode(
        {
            "grant_type": "refresh_token",
            "refresh_token": refresh_token,
        }
    ).encode("utf-8")

    basic_auth = f"{settings['client_id']}:{settings['client_secret']}".encode("utf-8")
    auth_header = "Basic " + base64.b64encode(basic_auth).decode("ascii")
    request = urllib.request.Request(
        QUICKBOOKS_TOKEN_URL,
        data=payload,
        headers={
            "Accept": "application/json",
            "Content-Type": "application/x-www-form-urlencoded",
            "Authorization": auth_header,
        },
        method="POST",
    )

    try:
        with urllib.request.urlopen(request, timeout=20) as response:
            body = response.read().decode("utf-8")
            return json.loads(body)
    except urllib.error.HTTPError as exc:
        body = exc.read().decode("utf-8", errors="replace")
        raise ValueError(f"QuickBooks refresh failed: {body}") from exc
    except urllib.error.URLError as exc:
        raise ValueError(f"Unable to reach QuickBooks: {exc.reason}") from exc


def parse_iso_datetime(value: str) -> datetime | None:
    raw = str(value or "").strip()
    if not raw:
        return None
    try:
        parsed = datetime.fromisoformat(raw)
    except ValueError:
        return None
    if parsed.tzinfo is None:
        parsed = parsed.replace(tzinfo=timezone.utc)
    return parsed


def quickbooks_api_base_urls() -> list[str]:
    configured = os.environ.get("QUICKBOOKS_API_BASE_URL", "").strip()
    if configured:
        clean = configured.rstrip("/")
        if clean == QUICKBOOKS_SANDBOX_API_BASE_URL:
            return [QUICKBOOKS_SANDBOX_API_BASE_URL, QUICKBOOKS_API_BASE_URL]
        if clean == QUICKBOOKS_API_BASE_URL:
            return [QUICKBOOKS_API_BASE_URL, QUICKBOOKS_SANDBOX_API_BASE_URL]
        return [clean, QUICKBOOKS_API_BASE_URL, QUICKBOOKS_SANDBOX_API_BASE_URL]
    return [QUICKBOOKS_API_BASE_URL, QUICKBOOKS_SANDBOX_API_BASE_URL]


def quickbooks_query(realm_id: str, access_token: str, sql_query: str) -> dict:
    encoded_query = urllib.parse.quote(sql_query, safe="")
    last_error: ValueError | None = None

    for base_url in quickbooks_api_base_urls():
        url = (
            f"{base_url}/v3/company/{urllib.parse.quote(realm_id, safe='')}"
            f"/query?query={encoded_query}&minorversion=75"
        )
        request = urllib.request.Request(
            url,
            headers={
                "Accept": "application/json",
                "Authorization": f"Bearer {access_token}",
            },
            method="GET",
        )
        try:
            with urllib.request.urlopen(request, timeout=20) as response:
                return json.loads(response.read().decode("utf-8"))
        except urllib.error.HTTPError as exc:
            body = exc.read().decode("utf-8", errors="replace")
            last_error = ValueError(f"QuickBooks API query failed: {body}")
            is_env_mismatch = (
                exc.code == 403 and "ApplicationAuthorizationFailed" in body
            )
            if is_env_mismatch:
                continue
            raise last_error from exc
        except urllib.error.URLError as exc:
            raise ValueError(f"Unable to reach QuickBooks: {exc.reason}") from exc

    if last_error is not None:
        raise last_error
    raise ValueError("QuickBooks API query failed")


def normalize_quickbooks_customer(customer: dict) -> dict:
    bill_addr = customer.get("BillAddr") if isinstance(customer, dict) else {}
    bill_addr = bill_addr if isinstance(bill_addr, dict) else {}
    primary_phone = customer.get("PrimaryPhone") if isinstance(customer, dict) else {}
    primary_phone = primary_phone if isinstance(primary_phone, dict) else {}
    primary_email = customer.get("PrimaryEmailAddr") if isinstance(customer, dict) else {}
    primary_email = primary_email if isinstance(primary_email, dict) else {}

    return {
        "id": str(customer.get("Id", "")).strip(),
        "display_name": str(customer.get("DisplayName", "")).strip(),
        "company_name": str(customer.get("CompanyName", "")).strip(),
        "given_name": str(customer.get("GivenName", "")).strip(),
        "family_name": str(customer.get("FamilyName", "")).strip(),
        "phone": str(primary_phone.get("FreeFormNumber", "")).strip(),
        "email": str(primary_email.get("Address", "")).strip(),
        "address_line1": str(bill_addr.get("Line1", "")).strip(),
        "address_line2": str(bill_addr.get("Line2", "")).strip(),
        "city": str(bill_addr.get("City", "")).strip(),
        "state": str(bill_addr.get("CountrySubDivisionCode", "")).strip(),
        "postal_code": str(bill_addr.get("PostalCode", "")).strip(),
        "active": bool(customer.get("Active", True)),
    }


def normalize_quickbooks_employee(employee: dict) -> dict:
    primary_phone = employee.get("PrimaryPhone") if isinstance(employee, dict) else {}
    primary_phone = primary_phone if isinstance(primary_phone, dict) else {}
    mobile_phone = employee.get("Mobile") if isinstance(employee, dict) else {}
    mobile_phone = mobile_phone if isinstance(mobile_phone, dict) else {}
    primary_email = employee.get("PrimaryEmailAddr") if isinstance(employee, dict) else {}
    primary_email = primary_email if isinstance(primary_email, dict) else {}

    return {
        "id": str(employee.get("Id", "")).strip(),
        "display_name": str(employee.get("DisplayName", "")).strip(),
        "given_name": str(employee.get("GivenName", "")).strip(),
        "family_name": str(employee.get("FamilyName", "")).strip(),
        "title": str(employee.get("Title", "")).strip(),
        "phone": str(primary_phone.get("FreeFormNumber", "")).strip(),
        "mobile": str(mobile_phone.get("FreeFormNumber", "")).strip(),
        "email": str(primary_email.get("Address", "")).strip(),
        "active": bool(employee.get("Active", True)),
    }


def merge_quickbooks_employees(employees: list[dict]) -> tuple[int, int]:
    imported = 0
    updated = 0

    for quickbooks_employee in employees:
        qb_id = str(quickbooks_employee.get("id", "")).strip()
        display_name = str(quickbooks_employee.get("display_name", "")).strip()
        given_name = str(quickbooks_employee.get("given_name", "")).strip()
        family_name = str(quickbooks_employee.get("family_name", "")).strip()
        full_name = " ".join(part for part in [given_name, family_name] if part).strip()
        name = display_name or full_name
        if not name:
            continue

        existing = None
        if qb_id:
            existing = next(
                (
                    employee
                    for employee in EMPLOYEES
                    if str(employee.get("quickbooks_employee_id", "")).strip() == qb_id
                ),
                None,
            )
        if existing is None:
            existing = next(
                (
                    employee
                    for employee in EMPLOYEES
                    if str(employee.get("name", "")).strip().lower() == name.lower()
                ),
                None,
            )

        if existing is None:
            EMPLOYEES.append(
                normalize_employee(
                    {
                        "id": next_employee_id(),
                        "name": name,
                        "source": "quickbooks",
                        "quickbooks_employee_id": qb_id,
                        "title": quickbooks_employee.get("title", ""),
                        "phone": quickbooks_employee.get("phone", ""),
                        "mobile": quickbooks_employee.get("mobile", ""),
                        "email": quickbooks_employee.get("email", ""),
                        "active": quickbooks_employee.get("active", True),
                        "added_at": datetime.now(timezone.utc).isoformat(),
                    }
                )
            )
            imported += 1
            continue

        changed = False
        updates = {
            "name": name,
            "source": "quickbooks",
            "quickbooks_employee_id": qb_id,
            "title": str(quickbooks_employee.get("title", "")).strip(),
            "phone": str(quickbooks_employee.get("phone", "")).strip(),
            "mobile": str(quickbooks_employee.get("mobile", "")).strip(),
            "email": str(quickbooks_employee.get("email", "")).strip(),
            "active": bool(quickbooks_employee.get("active", True)),
        }
        for key, value in updates.items():
            if existing.get(key) != value:
                existing[key] = value
                changed = True
        if changed:
            updated += 1

    return imported, updated


def get_quickbooks_user_connection(username: str) -> dict[str, str]:
    from auth_db import get_connection

    with get_connection() as conn:
        row = conn.execute(
            """
            SELECT integration_connected,
                   quickbooks_realm_id,
                   quickbooks_access_token,
                   quickbooks_refresh_token,
                   quickbooks_token_expires_at
            FROM users
            WHERE username = ?
            """,
            (username,),
        ).fetchone()

    if row is None:
        raise ValueError("user not found")

    integration_connected = bool(row[0])
    realm_id = str(row[1] or "").strip()
    access_token = decrypt_quickbooks_token(str(row[2] or "").strip())
    refresh_token = decrypt_quickbooks_token(str(row[3] or "").strip())
    expires_at_iso = str(row[4] or "").strip()

    if not integration_connected:
        raise ValueError("user is not connected to QuickBooks")
    if not realm_id or not access_token or not refresh_token:
        raise ValueError("missing QuickBooks credentials for user")

    return {
        "realm_id": realm_id,
        "access_token": access_token,
        "refresh_token": refresh_token,
        "expires_at": expires_at_iso,
    }


def ensure_valid_quickbooks_access_token(username: str, connection: dict[str, str]) -> dict[str, str]:
    expires_at = parse_iso_datetime(connection.get("expires_at", ""))
    now = datetime.now(timezone.utc)

    if expires_at is not None and (expires_at - now).total_seconds() > 120:
        return connection

    refreshed = refresh_quickbooks_tokens(connection["refresh_token"])
    access_token = str(refreshed.get("access_token", "")).strip()
    refresh_token = str(refreshed.get("refresh_token", connection["refresh_token"]))
    refresh_token = refresh_token.strip()
    expires_in = int(refreshed.get("expires_in", 3600) or 3600)
    new_expiry = datetime.fromtimestamp(
        now.timestamp() + max(expires_in, 60),
        tz=timezone.utc,
    ).isoformat()

    if not access_token or not refresh_token:
        raise ValueError("invalid QuickBooks refresh response")

    encrypted_access_token = encrypt_quickbooks_token(access_token)
    encrypted_refresh_token = encrypt_quickbooks_token(refresh_token)
    tokens_encrypted = int(
        encrypted_access_token.startswith(ENCRYPTED_TOKEN_PREFIX)
        and encrypted_refresh_token.startswith(ENCRYPTED_TOKEN_PREFIX)
    )

    from auth_db import get_connection

    with get_connection() as conn:
        conn.execute(
            """
            UPDATE users
            SET quickbooks_access_token = ?,
                quickbooks_refresh_token = ?,
                quickbooks_token_expires_at = ?,
                quickbooks_tokens_encrypted = ?
            WHERE username = ?
            """,
            (
                encrypted_access_token,
                encrypted_refresh_token,
                new_expiry,
                tokens_encrypted,
                username,
            ),
        )
        conn.commit()

    return {
        "realm_id": connection["realm_id"],
        "access_token": access_token,
        "refresh_token": refresh_token,
        "expires_at": new_expiry,
    }


class AppHandler(SimpleHTTPRequestHandler):
    def __init__(self, *args, **kwargs):
        super().__init__(*args, directory=str(ROOT), **kwargs)

    def do_GET(self) -> None:
        parsed = urllib.parse.urlparse(self.path)
        path = parsed.path

        if path == "/api/jobs":
            self._send_json(200, JOBS)
            return
        if path == "/api/clients":
            self._send_json(200, {"clients": CLIENTS})
            return
        if path == "/api/employees":
            self._send_json(200, {"employees": EMPLOYEES})
            return
        if path == "/api/quickbooks/connect":
            self._handle_quickbooks_connect(parsed)
            return
        if path == "/api/quickbooks/callback":
            self._handle_quickbooks_callback(parsed)
            return
        if path == "/api/quickbooks/customers":
            self._handle_quickbooks_customers(parsed)
            return
        if path == "/api/quickbooks/employees":
            self._handle_quickbooks_employees(parsed)
            return
        if path == "/api/users/connect-status":
            query = urllib.parse.parse_qs(parsed.query)
            username = str((query.get("username") or [""])[0]).strip()
            self._handle_user_connect_status(username)
            return
        super().do_GET()

    def do_POST(self) -> None:
        if self.path == "/api/clients":
            self._handle_create_client()
            return
        if self.path == "/api/employees":
            self._handle_create_employee()
            return
        if self.path == "/api/employees/status":
            self._handle_set_employee_status()
            return
        if self.path == "/api/employees/delete":
            self._handle_delete_employee()
            return
        if self.path == "/api/clients/connect":
            self._handle_connect_client()
            return
        if self.path == "/api/users/disconnect":
            self._handle_disconnect_user()
            return
        if self.path == "/api/users/connect-status":
            self._handle_user_connect_status()
            return
        if self.path == "/api/jobs":
            self._handle_create_job()
            return
        if self.path == "/api/jobs/schedule":
            self._handle_schedule_job()
            return
        if self.path == "/api/quickbooks/clients/import":
            self._handle_quickbooks_clients_import()
            return
        if self.path == "/api/quickbooks/employees/import":
            self._handle_quickbooks_employees_import()
            return
        if self.path == "/api/quickbooks/webhook":
            self._handle_quickbooks_webhook()
            return
        if self.path == "/api/register":
            self._handle_register()
            return
        if self.path == "/api/login":
            self._handle_login()
            return
        if self.path == "/api/users":
            self._handle_get_users()
            return
        if self.path == "/api/users/role":
            self._handle_update_user_role()
            return

        self._send_json(404, {"error": "Not found"})

    def _read_json_body(self) -> dict:
        length = int(self.headers.get("Content-Length", "0"))
        raw = self.rfile.read(length)
        try:
            return json.loads(raw.decode("utf-8"))
        except (json.JSONDecodeError, UnicodeDecodeError):
            return {}

    def _redirect(self, location: str) -> None:
        self.send_response(302)
        self.send_header("Location", location)
        self.send_header("Cache-Control", "no-store")
        self.end_headers()

    def _redirect_qb_error(self, code: str, detail: str = "") -> None:
        safe_code = urllib.parse.quote(str(code or "quickbooks-error").strip(), safe="")
        query = f"qb=error&message={safe_code}"
        detail_clean = str(detail or "").strip()
        if detail_clean:
            query += f"&detail={urllib.parse.quote(detail_clean[:300], safe='')}"
        self._redirect(f"/home.html#{query}")

    def _handle_quickbooks_webhook(self) -> None:
        verifier_token = os.environ.get("QUICKBOOKS_VERIFIER_TOKEN", "").strip()
        length = int(self.headers.get("Content-Length", "0"))
        body = self.rfile.read(length)

        if verifier_token:
            signature = self.headers.get("intuit-signature", "")
            expected = hmac.new(
                verifier_token.encode("utf-8"), body, hashlib.sha256
            ).hexdigest()
            if not hmac.compare_digest(expected, signature):
                self._send_json(401, {"error": "invalid signature"})
                return

        try:
            payload = json.loads(body.decode("utf-8"))
        except (json.JSONDecodeError, UnicodeDecodeError):
            self._send_json(400, {"error": "invalid JSON"})
            return

        # Log received event for now; extend here to process entity updates
        event_notifications = payload.get("eventNotifications", [])
        for note in event_notifications:
            realm_id = note.get("realmId", "")
            for entity in note.get("dataChangeEvent", {}).get("entities", []):
                print(
                    f"[QB webhook] realmId={realm_id} "
                    f"entity={entity.get('name')} "
                    f"id={entity.get('id')} "
                    f"operation={entity.get('operation')}"
                )

        self._send_json(200, {"status": "ok"})

    def _handle_quickbooks_connect(self, parsed: urllib.parse.ParseResult) -> None:
        query = urllib.parse.parse_qs(parsed.query)
        username = str((query.get("username") or [""])[0]).strip()
        if not username:
            self._redirect_qb_error("missing-user")
            return

        if not quickbooks_is_configured():
            self._redirect_qb_error("quickbooks-not-configured")
            return

        prune_oauth_states()
        state = secrets.token_urlsafe(24)
        OAUTH_STATES[state] = {"username": username, "created_at": time.time()}

        settings = quickbooks_settings()
        auth_query = urllib.parse.urlencode(
            {
                "client_id": settings["client_id"],
                "response_type": "code",
                "scope": QUICKBOOKS_SCOPES,
                "redirect_uri": settings["redirect_uri"],
                "state": state,
            }
        )
        self._redirect(f"{QUICKBOOKS_AUTH_URL}?{auth_query}")

    def _quickbooks_username_from_query(self, parsed: urllib.parse.ParseResult) -> str:
        query = urllib.parse.parse_qs(parsed.query)
        return str((query.get("username") or [""])[0]).strip()

    def _fetch_quickbooks_customers(self, username: str) -> list[dict]:
        connection = get_quickbooks_user_connection(username)
        connection = ensure_valid_quickbooks_access_token(username, connection)
        payload = quickbooks_query(
            connection["realm_id"],
            connection["access_token"],
            "SELECT * FROM Customer STARTPOSITION 1 MAXRESULTS 1000",
        )
        query_response = payload.get("QueryResponse", {})
        if not isinstance(query_response, dict):
            return []
        customers_raw = query_response.get("Customer", [])
        if not isinstance(customers_raw, list):
            return []
        return [
            normalize_quickbooks_customer(item)
            for item in customers_raw
            if isinstance(item, dict)
        ]

    def _fetch_quickbooks_employees(self, username: str) -> list[dict]:
        connection = get_quickbooks_user_connection(username)
        connection = ensure_valid_quickbooks_access_token(username, connection)
        payload = quickbooks_query(
            connection["realm_id"],
            connection["access_token"],
            "SELECT * FROM Employee STARTPOSITION 1 MAXRESULTS 1000",
        )
        query_response = payload.get("QueryResponse", {})
        if not isinstance(query_response, dict):
            return []
        employees_raw = query_response.get("Employee", [])
        if not isinstance(employees_raw, list):
            return []
        return [
            normalize_quickbooks_employee(item)
            for item in employees_raw
            if isinstance(item, dict)
        ]

    def _handle_quickbooks_customers(self, parsed: urllib.parse.ParseResult) -> None:
        username = self._quickbooks_username_from_query(parsed)
        if not username:
            self._send_json(400, {"error": "username is required"})
            return

        try:
            customers = self._fetch_quickbooks_customers(username)
        except ValueError as exc:
            self._send_json(400, {"error": str(exc)})
            return
        except Exception as exc:
            self._send_json(500, {"error": str(exc)})
            return

        self._send_json(200, {"ok": True, "customers": customers})

    def _handle_quickbooks_employees(self, parsed: urllib.parse.ParseResult) -> None:
        username = self._quickbooks_username_from_query(parsed)
        if not username:
            self._send_json(400, {"error": "username is required"})
            return

        try:
            employees = self._fetch_quickbooks_employees(username)
        except ValueError as exc:
            self._send_json(400, {"error": str(exc)})
            return
        except Exception as exc:
            self._send_json(500, {"error": str(exc)})
            return

        self._send_json(200, {"ok": True, "employees": employees})

    def _handle_quickbooks_clients_import(self) -> None:
        payload = self._read_json_body()
        username = str(payload.get("username", "")).strip()
        if not username:
            self._send_json(400, {"error": "username is required"})
            return

        try:
            customers = self._fetch_quickbooks_customers(username)
        except ValueError as exc:
            self._send_json(400, {"error": str(exc)})
            return
        except Exception as exc:
            self._send_json(500, {"error": str(exc)})
            return

        existing_names = {
            str(client.get("name", "")).strip().lower(): client for client in CLIENTS
        }
        imported = 0

        for customer in customers:
            name = str(customer.get("display_name") or customer.get("company_name") or "").strip()
            if not name:
                continue
            key = name.lower()
            if key in existing_names:
                continue

            next_id = max((int(client.get("id", 0)) for client in CLIENTS), default=0) + 1
            client = normalize_client(
                {
                    "id": next_id,
                    "name": name,
                    "phone": customer.get("phone", ""),
                    "email": customer.get("email", ""),
                    "address_line1": customer.get("address_line1", ""),
                    "address_line2": customer.get("address_line2", ""),
                    "city": customer.get("city", ""),
                    "state": customer.get("state", ""),
                    "postal_code": customer.get("postal_code", ""),
                    "notes": f"Imported from QuickBooks customer ID {customer.get('id', '')}",
                    "integration_provider": "quickbooks",
                    "integration_connected": True,
                    "integration_connected_at": datetime.now(timezone.utc).isoformat(),
                }
            )
            CLIENTS.append(client)
            existing_names[key] = client
            imported += 1

        save_clients()
        try:
            connection = get_quickbooks_user_connection(username)
            connection = ensure_valid_quickbooks_access_token(username, connection)
            company_name = fetch_quickbooks_company_name(
                connection["realm_id"], connection["access_token"]
            )
            set_quickbooks_company_name(username, company_name)
        except Exception:
            pass
        mark_quickbooks_sync(username)
        self._send_json(
            200,
            {
                "ok": True,
                "imported": imported,
                "total_customers_seen": len(customers),
                "clients": CLIENTS,
            },
        )

    def _handle_quickbooks_employees_import(self) -> None:
        payload = self._read_json_body()
        username = str(payload.get("username", "")).strip()
        if not username:
            self._send_json(400, {"error": "username is required"})
            return

        try:
            employees = self._fetch_quickbooks_employees(username)
        except ValueError as exc:
            self._send_json(400, {"error": str(exc)})
            return
        except Exception as exc:
            self._send_json(500, {"error": str(exc)})
            return

        imported, updated = merge_quickbooks_employees(employees)
        save_employees()
        try:
            connection = get_quickbooks_user_connection(username)
            connection = ensure_valid_quickbooks_access_token(username, connection)
            company_name = fetch_quickbooks_company_name(
                connection["realm_id"], connection["access_token"]
            )
            set_quickbooks_company_name(username, company_name)
        except Exception:
            pass
        mark_quickbooks_sync(username)

        self._send_json(
            200,
            {
                "ok": True,
                "imported": imported,
                "updated": updated,
                "total_employees_seen": len(employees),
                "employees": EMPLOYEES,
            },
        )

    def _handle_quickbooks_callback(self, parsed: urllib.parse.ParseResult) -> None:
        query = urllib.parse.parse_qs(parsed.query)
        state = str((query.get("state") or [""])[0]).strip()
        code = str((query.get("code") or [""])[0]).strip()
        error = str((query.get("error") or [""])[0]).strip()
        realm_id = str((query.get("realmId") or [""])[0]).strip()

        if error:
            self._redirect_qb_error("oauth-denied", error)
            return

        if not state or not code:
            self._redirect_qb_error("missing-oauth-params")
            return

        prune_oauth_states()
        state_entry = OAUTH_STATES.pop(state, None)
        if not state_entry:
            self._redirect_qb_error("invalid-oauth-state")
            return

        username = str(state_entry.get("username", "")).strip()
        if not username:
            self._redirect_qb_error("missing-state-user")
            return

        try:
            token_payload = exchange_quickbooks_code(code)
        except ValueError as exc:
            self._redirect_qb_error("token-exchange-failed", str(exc))
            return

        access_token = str(token_payload.get("access_token", "")).strip()
        refresh_token = str(token_payload.get("refresh_token", "")).strip()
        expires_in = int(token_payload.get("expires_in", 3600) or 3600)
        connected_at = datetime.now(timezone.utc)
        expires_at = connected_at.timestamp() + max(expires_in, 60)
        expires_at_iso = datetime.fromtimestamp(expires_at, tz=timezone.utc).isoformat()

        if not access_token or not refresh_token:
            self._redirect_qb_error("invalid-token-response")
            return

        encrypted_access_token = encrypt_quickbooks_token(access_token)
        encrypted_refresh_token = encrypt_quickbooks_token(refresh_token)
        tokens_encrypted = int(
            encrypted_access_token.startswith(ENCRYPTED_TOKEN_PREFIX)
            and encrypted_refresh_token.startswith(ENCRYPTED_TOKEN_PREFIX)
        )

        company_name = ""
        try:
            company_name = fetch_quickbooks_company_name(realm_id, access_token)
        except Exception:
            company_name = ""

        try:
            from auth_db import get_connection

            with get_connection() as conn:
                result = conn.execute(
                    """
                    UPDATE users
                    SET integration_provider = ?,
                        integration_connected = 1,
                        integration_connected_at = ?,
                        quickbooks_realm_id = ?,
                        quickbooks_access_token = ?,
                        quickbooks_refresh_token = ?,
                        quickbooks_token_expires_at = ?,
                        quickbooks_company_name = ?,
                        quickbooks_tokens_encrypted = ?,
                        quickbooks_last_sync_at = ?
                    WHERE username = ?
                    """,
                    (
                        "quickbooks",
                        connected_at.isoformat(),
                        realm_id,
                        encrypted_access_token,
                        encrypted_refresh_token,
                        expires_at_iso,
                        company_name,
                        tokens_encrypted,
                        connected_at.isoformat(),
                        username,
                    ),
                )
                if result.rowcount == 0:
                    self._redirect_qb_error("user-not-found")
                    return
                conn.commit()
        except Exception as exc:
            self._redirect_qb_error("save-connection-failed", str(exc))
            return

        try:
            employees = self._fetch_quickbooks_employees(username)
            imported, updated = merge_quickbooks_employees(employees)
            if imported > 0 or updated > 0:
                save_employees()
            mark_quickbooks_sync(username, connected_at.isoformat())
        except Exception as exc:
            print(f"[QB employees sync warning] {exc}")

        self._redirect("/home.html#qb=connected")

    def _handle_register(self) -> None:
        payload = self._read_json_body()
        username = str(payload.get("username", "")).strip()
        password = str(payload.get("password", ""))

        if not username or not password:
            self._send_json(400, {"error": "username and password are required"})
            return

        try:
            create_user(username, password)
        except sqlite3.IntegrityError:
            self._send_json(409, {"error": "user already exists"})
            return
        except ValueError as exc:
            self._send_json(400, {"error": str(exc)})
            return

        self._send_json(201, {"ok": True, "message": "user created"})

    def _handle_login(self) -> None:
        payload = self._read_json_body()
        username = str(payload.get("username", "")).strip()
        password = str(payload.get("password", ""))

        if not username or not password:
            self._send_json(400, {"error": "username and password are required"})
            return

        if verify_user(username, password):
            self._send_json(
                200,
                {
                    "ok": True,
                    "message": "login successful",
                    "redirect": "/home.html",
                },
            )
            return

        self._send_json(401, {"ok": False, "error": "invalid credentials"})

    def _handle_get_users(self) -> None:
        # Fetch all users with their admin status
        try:
            from auth_db import get_connection
            with get_connection() as conn:
                rows = conn.execute(
                    "SELECT username, is_admin, created_at FROM users ORDER BY username"
                ).fetchall()
            
            users = [
                {
                    "username": row[0],
                    "role": "Admin" if row[1] else "User",
                    "created_at": row[2]
                }
                for row in rows
            ]
            self._send_json(200, {"users": users})
        except Exception as exc:
            self._send_json(500, {"error": str(exc)})

    def _handle_update_user_role(self) -> None:
        # Update a user's role
        payload = self._read_json_body()
        username = str(payload.get("username", "")).strip()
        role = str(payload.get("role", "")).strip()

        if not username:
            self._send_json(400, {"error": "username is required"})
            return
        
        if role not in ("Admin", "User"):
            self._send_json(400, {"error": "role must be 'Admin' or 'User'"})
            return

        try:
            if role == "Admin":
                grant_admin(username)
            else:
                revoke_admin(username)
            self._send_json(200, {"ok": True, "message": f"User role updated to {role}"})
        except ValueError as exc:
            self._send_json(404, {"error": str(exc)})
        except Exception as exc:
            self._send_json(500, {"error": str(exc)})

    def _handle_schedule_job(self) -> None:
        payload = self._read_json_body()

        try:
            raw_job_id = payload.get("id")
            if not isinstance(raw_job_id, (int, float, str)):
                raise TypeError("id must be an integer")
            job_id = int(raw_job_id)
        except (TypeError, ValueError):
            self._send_json(400, {"error": "id must be an integer"})
            return

        status = str(payload.get("status", "")).strip()
        time_value = str(payload.get("time", "")).strip()
        assigned_tech = payload.get("assigned_tech")
        manual_block = payload.get("manual_block_minutes")

        if not status:
            self._send_json(400, {"error": "status is required"})
            return
        if not time_value:
            self._send_json(400, {"error": "time is required"})
            return

        job = find_job(job_id)
        if job is None:
            self._send_json(404, {"error": "job not found"})
            return

        job["status"] = status
        job["time"] = time_value
        job["assigned_tech"] = str(assigned_tech).strip() if assigned_tech else None
        job["manual_block_minutes"] = (
            int(manual_block)
            if isinstance(manual_block, (int, float)) and int(manual_block) > 0
            else None
        )
        save_jobs()
        self._send_json(200, {"ok": True, "job": job})

    def _handle_create_job(self) -> None:
        payload = self._read_json_body()
        selected_client = None
        raw_client_id = payload.get("client_id")
        client_id = None
        if raw_client_id not in (None, ""):
            try:
                client_id = int(raw_client_id)
            except (TypeError, ValueError):
                self._send_json(400, {"error": "client_id must be an integer"})
                return

            selected_client = find_client(client_id)
            if selected_client is None:
                self._send_json(404, {"error": "client not found"})
                return

        customer_name = str(
            payload.get("customer_name") or (selected_client or {}).get("name", "")
        ).strip()
        service_type = str(payload.get("service_type", "")).strip()
        phone = str(payload.get("phone") or (selected_client or {}).get("phone", "")).strip()
        email = str(payload.get("email") or (selected_client or {}).get("email", "")).strip()
        address_line1 = str(
            payload.get("address_line1") or (selected_client or {}).get("address_line1", "")
        ).strip()
        address_line2 = str(
            payload.get("address_line2") or (selected_client or {}).get("address_line2", "")
        ).strip()
        city = str(payload.get("city") or (selected_client or {}).get("city", "")).strip()
        state = str(payload.get("state") or (selected_client or {}).get("state", "")).strip()
        postal_code = str(
            payload.get("postal_code") or (selected_client or {}).get("postal_code", "")
        ).strip()
        notes = str(payload.get("notes") or (selected_client or {}).get("notes", "")).strip()

        if not customer_name:
            self._send_json(400, {"error": "customer_name is required"})
            return
        if not service_type:
            self._send_json(400, {"error": "service_type is required"})
            return

        try:
            duration_minutes = int(payload.get("duration_minutes", 60))
        except (TypeError, ValueError):
            self._send_json(400, {"error": "duration_minutes must be an integer"})
            return

        if duration_minutes <= 0:
            self._send_json(400, {"error": "duration_minutes must be positive"})
            return

        next_id = max((int(job.get("id", 0)) for job in JOBS), default=100) + 1
        job = {
            "id": next_id,
            "customer_name": customer_name,
            "service_type": service_type,
            "time": "Unscheduled",
            "status": "Pending",
            "duration_minutes": duration_minutes,
            "assigned_tech": None,
            "client_id": client_id,
            "emergency": parse_bool(payload.get("emergency", False)),
            "recurring": parse_bool(payload.get("recurring", False)),
            "manual_block_minutes": None,
            "phone": phone,
            "email": email,
            "address_line1": address_line1,
            "address_line2": address_line2,
            "city": city,
            "state": state,
            "postal_code": postal_code,
            "notes": notes,
        }

        JOBS.append(job)
        save_jobs()
        self._send_json(201, {"ok": True, "job": job})

    def _handle_create_client(self) -> None:
        payload = self._read_json_body()
        name = str(payload.get("name", "")).strip()

        if not name:
            self._send_json(400, {"error": "name is required"})
            return

        next_id = max((int(client.get("id", 0)) for client in CLIENTS), default=0) + 1
        client = normalize_client({
            "id": next_id,
            "name": name,
            "phone": payload.get("phone", ""),
            "email": payload.get("email", ""),
            "address_line1": payload.get("address_line1", ""),
            "address_line2": payload.get("address_line2", ""),
            "city": payload.get("city", ""),
            "state": payload.get("state", ""),
            "postal_code": payload.get("postal_code", ""),
            "notes": payload.get("notes", ""),
            "integration_provider": "",
            "integration_connected": False,
            "integration_connected_at": "",
        })

        CLIENTS.append(client)
        save_clients()
        self._send_json(201, {"ok": True, "client": client})

    def _handle_create_employee(self) -> None:
        payload = self._read_json_body()
        name = str(payload.get("name", "")).strip()

        if not name:
            self._send_json(400, {"error": "name is required"})
            return

        duplicate = next(
            (
                employee
                for employee in EMPLOYEES
                if str(employee.get("name", "")).strip().lower() == name.lower()
            ),
            None,
        )
        if duplicate is not None:
            self._send_json(409, {"error": "employee already exists"})
            return

        employee = normalize_employee(
            {
                "id": next_employee_id(),
                "name": name,
                "source": "manual",
                "quickbooks_employee_id": "",
                "title": str(payload.get("title", "")).strip(),
                "phone": str(payload.get("phone", "")).strip(),
                "mobile": str(payload.get("mobile", "")).strip(),
                "email": str(payload.get("email", "")).strip(),
                "active": True,
                "added_at": datetime.now(timezone.utc).isoformat(),
            }
        )

        EMPLOYEES.append(employee)
        save_employees()
        self._send_json(201, {"ok": True, "employee": employee})

    def _handle_set_employee_status(self) -> None:
        payload = self._read_json_body()

        try:
            raw_employee_id = payload.get("employee_id")
            if not isinstance(raw_employee_id, (int, float, str)):
                raise TypeError("employee_id must be an integer")
            employee_id = int(raw_employee_id)
        except (TypeError, ValueError):
            self._send_json(400, {"error": "employee_id must be an integer"})
            return

        if "active" not in payload:
            self._send_json(400, {"error": "active is required"})
            return

        employee = find_employee(employee_id)
        if employee is None:
            self._send_json(404, {"error": "employee not found"})
            return

        employee["active"] = parse_bool(payload.get("active"))
        save_employees()
        self._send_json(200, {"ok": True, "employee": employee})

    def _handle_delete_employee(self) -> None:
        payload = self._read_json_body()

        try:
            raw_employee_id = payload.get("employee_id")
            if not isinstance(raw_employee_id, (int, float, str)):
                raise TypeError("employee_id must be an integer")
            employee_id = int(raw_employee_id)
        except (TypeError, ValueError):
            self._send_json(400, {"error": "employee_id must be an integer"})
            return

        employee = find_employee(employee_id)
        if employee is None:
            self._send_json(404, {"error": "employee not found"})
            return

        EMPLOYEES.remove(employee)
        save_employees()
        self._send_json(200, {"ok": True, "deleted_employee_id": employee_id})

    def _handle_connect_client(self) -> None:
        payload = self._read_json_body()

        try:
            raw_client_id = payload.get("client_id")
            if not isinstance(raw_client_id, (int, float, str)):
                raise TypeError("client_id must be an integer")
            client_id = int(raw_client_id)
        except (TypeError, ValueError):
            self._send_json(400, {"error": "client_id must be an integer"})
            return

        provider = str(payload.get("provider", "")).strip().lower()
        if provider not in {"quickbooks"}:
            self._send_json(400, {"error": "provider must be quickbooks"})
            return

        client = find_client(client_id)
        if client is None:
            self._send_json(404, {"error": "client not found"})
            return

        client["integration_provider"] = provider
        client["integration_connected"] = True
        client["integration_connected_at"] = datetime.now(timezone.utc).isoformat()

        save_clients()
        self._send_json(200, {"ok": True, "client": client})

    def _handle_user_connect_status(self, username: str = "") -> None:
        username = str(username or "").strip()
        if not username:
            payload = self._read_json_body()
            username = str(payload.get("username", "")).strip()
        if not username:
            self._send_json(400, {"error": "username is required"})
            return

        try:
            from auth_db import get_connection

            with get_connection() as conn:
                row = conn.execute(
                    """
                    SELECT username,
                           integration_provider,
                           integration_connected,
                           integration_connected_at,
                           quickbooks_realm_id,
                           quickbooks_token_expires_at,
                           quickbooks_company_name,
                           quickbooks_last_sync_at,
                           quickbooks_tokens_encrypted
                    FROM users
                    WHERE username = ?
                    """,
                    (username,),
                ).fetchone()
        except Exception as exc:
            self._send_json(500, {"error": str(exc)})
            return

        if row is None:
            self._send_json(404, {"error": "user not found"})
            return

        quickbooks_company_name = str(row[6] or "").strip()
        if bool(row[2]) and not quickbooks_company_name:
            try:
                connection = get_quickbooks_user_connection(username)
                connection = ensure_valid_quickbooks_access_token(username, connection)
                quickbooks_company_name = fetch_quickbooks_company_name(
                    connection["realm_id"], connection["access_token"]
                )
                set_quickbooks_company_name(username, quickbooks_company_name)
            except Exception:
                pass

        self._send_json(
            200,
            {
                "ok": True,
                "user": {
                    "username": row[0],
                    "integration_provider": str(row[1] or "").strip(),
                    "integration_connected": bool(row[2]),
                    "integration_connected_at": str(row[3] or "").strip(),
                    "quickbooks_realm_id": str(row[4] or "").strip(),
                    "quickbooks_token_expires_at": str(row[5] or "").strip(),
                    "quickbooks_company_name": quickbooks_company_name,
                    "quickbooks_last_sync_at": str(row[7] or "").strip(),
                    "quickbooks_tokens_encrypted": bool(row[8]),
                    "quickbooks_configured": quickbooks_is_configured(),
                },
            },
        )

    def _handle_disconnect_user(self) -> None:
        payload = self._read_json_body()
        username = str(payload.get("username", "")).strip()

        if not username:
            self._send_json(400, {"error": "username is required"})
            return

        try:
            from auth_db import get_connection

            with get_connection() as conn:
                result = conn.execute(
                    """
                    UPDATE users
                    SET integration_provider = '',
                        integration_connected = 0,
                        integration_connected_at = NULL,
                        quickbooks_realm_id = '',
                        quickbooks_access_token = '',
                        quickbooks_refresh_token = '',
                        quickbooks_token_expires_at = NULL,
                        quickbooks_company_name = '',
                        quickbooks_last_sync_at = NULL,
                        quickbooks_tokens_encrypted = 0
                    WHERE username = ?
                    """,
                    (username,),
                )
                if result.rowcount == 0:
                    self._send_json(404, {"error": "user not found"})
                    return
                conn.commit()
        except Exception as exc:
            self._send_json(500, {"error": str(exc)})
            return

        self._send_json(
            200,
            {
                "ok": True,
                "user": {
                    "username": username,
                    "integration_provider": "",
                    "integration_connected": False,
                    "integration_connected_at": "",
                },
            },
        )

    def _send_json(self, status: int, payload: object) -> None:
        body = json.dumps(payload).encode("utf-8")
        self.send_response(status)
        self.send_header("Content-Type", "application/json; charset=utf-8")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)


def load_env_file() -> None:
    """Load variables from .env file into os.environ if not already set."""
    env_path = ROOT / ".env"
    if not env_path.exists():
        return
    with env_path.open() as f:
        for line in f:
            line = line.strip()
            if not line or line.startswith("#") or "=" not in line:
                continue
            key, _, value = line.partition("=")
            key = key.strip()
            value = value.strip()
            if key and key not in os.environ:
                os.environ[key] = value


def main(argv: list[str]) -> int:
    port = 8000
    if len(argv) > 1:
        try:
            port = int(argv[1])
        except ValueError:
            print("Port must be an integer.")
            return 1

    init_db()
    load_env_file()
    load_clients()
    load_employees()
    load_jobs()
    server = ThreadingHTTPServer(("0.0.0.0", port), AppHandler)
    print(f"Serving app at http://0.0.0.0:{port}")
    try:
        server.serve_forever()
    except KeyboardInterrupt:
        print("\nShutting down server.")
    finally:
        server.server_close()
    return 0


if __name__ == "__main__":
    raise SystemExit(main(sys.argv))
