#!/usr/bin/env python3
"""Sends fee-due reminders to every student (and their guardian) with a fee due in the next 7 days.

Calls the exact same function the admin dashboard's "Send Fee Reminders Now" button uses - this
script exists only to let a real OS-level cron job trigger it unattended, since portal_db_server.py
runs no in-process scheduler of its own (see send_attendance_alerts_cron.py for the same pattern,
already used for attendance shortage alerts).

Example crontab entry (daily at 9am):
    0 9 * * * cd /path/to/gprec.ac.in/backend/tools && python3 send_fee_reminders_cron.py
"""
import sys

sys.path.insert(0, __import__("os").path.dirname(__file__))
import portal_db_server as srv

if __name__ == "__main__":
    result = srv.send_fee_due_reminders(days_ahead=7)
    print(
        f"Fee due reminders: {result['studentsNotified']} student(s) notified, "
        f"guardian SMS/WhatsApp sent to {result['guardianSmsSent']}, skipped {result['guardianSmsSkipped']}."
    )
