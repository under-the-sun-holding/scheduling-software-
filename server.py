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

from auth_db import create_user, init_db, verify_user


ROOT = Path(__file__).resolve().parent
JOBS_PATH = ROOT / "jobs.json"
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


class AppHandler(SimpleHTTPRequestHandler):
    def __init__(self, *args, **kwargs):
        super().__init__(*args, directory=str(ROOT), **kwargs)

    def do_GET(self) -> None:
        if self.path == "/api/jobs":
            self._send_json(200, JOBS)
            return
        super().do_GET()

    def do_POST(self) -> None:
        if self.path == "/api/jobs/schedule":
            self._handle_schedule_job()
            return
        if self.path == "/api/register":
            self._handle_register()
            return
        if self.path == "/api/login":
            self._handle_login()
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
