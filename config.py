from pathlib import Path
import sys


# =========================================================
# APPLICATION PATH
# =========================================================

# Development:
#   Uses the HomeSOC project directory.
#
# Packaged with PyInstaller:
#   Uses the directory containing HomeSOC.exe.

if getattr(sys, "frozen", False):

    BASE_DIR = Path(
        sys.executable
    ).resolve().parent

else:

    BASE_DIR = Path(
        __file__
    ).resolve().parent


# =========================================================
# DIRECTORIES
# =========================================================

DATA_DIR = BASE_DIR / "data"
LOG_DIR = BASE_DIR / "logs"

DATA_DIR.mkdir(
    parents=True,
    exist_ok=True,
)

LOG_DIR.mkdir(
    parents=True,
    exist_ok=True,
)


# =========================================================
# MONITORING
# =========================================================

SCAN_INTERVAL = 300

OFFLINE_THRESHOLD = 3

SERVICE_CLOSE_THRESHOLD = 2

MONITORED_PORTS = [
    22,
    23,
    53,
    80,
    443,
    554,
    8000,
    8080,
    8443,
]

MAX_SCAN_HOSTS = 1024


# =========================================================
# DATABASE / LOGGING
# =========================================================

DATABASE_PATH = str(
    DATA_DIR / "homesoc.db"
)

LOG_PATH = str(
    LOG_DIR / "homesoc.log"
)


# =========================================================
# DASHBOARD
# =========================================================

DASHBOARD_HOST = "127.0.0.1"

DASHBOARD_PORT = 5000

DASHBOARD_URL = (
    f"http://"
    f"{DASHBOARD_HOST}:"
    f"{DASHBOARD_PORT}"
)