import threading
import logging

logging.getLogger("werkzeug").setLevel(
    logging.ERROR
)

from werkzeug.serving import make_server

from dashboard.app import app

from config import (
    DASHBOARD_HOST,
    DASHBOARD_PORT,
)

from logger import logger


class DashboardServer:

    def __init__(self):

        self._server = None
        self._thread = None
        self._running = False


    def start(self):
        """
        Start the Flask dashboard in a background thread.
        """

        if self._running:
            return False

        self._server = make_server(
            DASHBOARD_HOST,
            DASHBOARD_PORT,
            app,
        )

        self._thread = threading.Thread(
            target=self._server.serve_forever,
            name="HomeSOC-Dashboard",
            daemon=True,
        )

        self._thread.start()

        self._running = True

        logger.info(
            f"Dashboard started at "
            f"http://{DASHBOARD_HOST}:"
            f"{DASHBOARD_PORT}"
        )

        return True


    def stop(self):
        """
        Stop the Flask dashboard.
        """

        if not self._running:
            return False

        if self._server:
            self._server.shutdown()

        self._running = False

        logger.info(
            "Dashboard server stopped"
        )

        return True


    def is_running(self):

        return self._running


dashboard_server = DashboardServer()