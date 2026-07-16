#!/usr/bin/env bash
# Stops both local servers started by start_servers.sh:
#   - portal_db_server.py (port 8766)
#   - static_server.py    (port 8080)
# Safe to re-run even if nothing is running.

if pkill -f "portal_db_server.py" 2>/dev/null; then
  echo "portal_db_server.py stopped."
else
  echo "portal_db_server.py was not running."
fi

if pkill -f "static_server.py" 2>/dev/null; then
  echo "static_server.py stopped."
else
  echo "static_server.py was not running."
fi
