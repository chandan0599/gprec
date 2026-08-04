#!/usr/bin/env python3
"""Sends attendance-shortage alerts to every student below 75% (and their guardians), college-wide.

Calls the exact same function the admin dashboard's "Send Attendance Alerts" button uses - this
script exists only to let a real OS-level cron job trigger it unattended, since portal_db_server.py
runs no in-process scheduler of its own (see send_attendance_shortage_alerts's docstring).

Example crontab entry (every Monday 8am):
    0 8 * * 1 cd /path/to/gprec.ac.in/backend/tools && python3 send_attendance_alerts_cron.py
"""
import sys

sys.path.insert(0, __import__("os").path.dirname(__file__))
import portal_db_server as srv

if __name__ == "__main__":
    result = srv.send_attendance_shortage_alerts()
    print(
        f"Attendance shortage alerts: {result['studentsNotified']} student(s) notified, "
        f"guardian SMS/WhatsApp sent to {result['guardianSmsSent']}, skipped {result['guardianSmsSkipped']}."
    )
