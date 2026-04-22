#!/usr/bin/env python3
"""Serve the landing page and auth APIs.

Usage:
  python3 server.py
  python3 server.py 8080
"""

from __future__ import annotations

import json
import sqlite3
import sys
from http.server import SimpleHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path

from auth_db import create_user, grant_admin, revoke_admin, init_db, verify_user


ROOT = Path(__file__).resolve().parent
JOBS_PATH = ROOT / "jobs.json"
CLIENTS_PATH = ROOT / "clients.json"
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


class AppHandler(SimpleHTTPRequestHandler):
    def __init__(self, *args, **kwargs):
        super().__init__(*args, directory=str(ROOT), **kwargs)

    def do_GET(self) -> None:
        if self.path == "/api/jobs":
            self._send_json(200, JOBS)
            return
        if self.path == "/api/clients":
            self._send_json(200, {"clients": CLIENTS})
            return
        super().do_GET()

    def do_POST(self) -> None:
        if self.path == "/api/clients":
            self._handle_create_client()
            return
        if self.path == "/api/jobs":
            self._handle_create_job()
            return
        if self.path == "/api/jobs/schedule":
            self._handle_schedule_job()
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
            job_id = int(payload.get("id"))
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
        })

        CLIENTS.append(client)
        save_clients()
        self._send_json(201, {"ok": True, "client": client})

    def _send_json(self, status: int, payload: dict) -> None:
        body = json.dumps(payload).encode("utf-8")
        self.send_response(status)
        self.send_header("Content-Type", "application/json; charset=utf-8")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)


def main(argv: list[str]) -> int:
    port = 8000
    if len(argv) > 1:
        try:
            port = int(argv[1])
        except ValueError:
            print("Port must be an integer.")
            return 1

    init_db()
    load_clients()
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
