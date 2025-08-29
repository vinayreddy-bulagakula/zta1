import os
from datetime import datetime
import logging
from logging.handlers import RotatingFileHandler

# ✅ Define LOG_FILE before using it
LOG_FILE = os.path.join(os.path.dirname(__file__), 'zta_events.log')

# ✅ Set up logging handler
handler = RotatingFileHandler(LOG_FILE, maxBytes=10240, backupCount=5)
logging.basicConfig(handlers=[handler], level=logging.INFO)

def log_event(event_type, username, status, message=""):
    timestamp = datetime.now().strftime('%Y-%m-%d %H:%M:%S')
    log_line = f"[{timestamp}] [{event_type}] User: {username} | Status: {status} | {message}"

    logging.info(log_line)
    print(f"[LOGGED] {log_line}")
