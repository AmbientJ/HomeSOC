import threading
import logging
import time

from main import run_scan


logger = logging.getLogger("HomeSOC")


class MonitoringService:

    def __init__(self, scan_interval=300):
        """
        HomeSOC background monitoring service.

        scan_interval:
            Seconds between completed scans.
            Default = 300 seconds (5 minutes).
        """

        self.scan_interval = scan_interval

        self._thread = None
        self._stop_event = threading.Event()
        self._state_lock = threading.Lock()

        self._running = False

        # -------------------------------------------------
        # LIVE MONITORING STATUS
        # -------------------------------------------------

        self._scan_state = "STOPPED"
        self._scan_progress = 0
        self._scan_stage = "Monitoring stopped"

        self._scan_started_at = None
        self._next_scan_at = None

        self._last_error = None


    # =====================================================
    # START / STOP
    # =====================================================

    def start(self):
        """
        Start continuous HomeSOC monitoring.
        """

        with self._state_lock:

            if self._running:

                logger.warning(
                    "Monitoring service is already running"
                )

                return False

            logger.info(
                "Starting HomeSOC monitoring service"
            )

            self._stop_event.clear()

            self._running = True

            self._scan_state = "STARTING"
            self._scan_progress = 0
            self._scan_stage = "Starting scan..."

            self._scan_started_at = None
            self._next_scan_at = None

            self._last_error = None

        self._thread = threading.Thread(
            target=self._monitor_loop,
            name="HomeSOC-Monitor",
            daemon=True,
        )

        self._thread.start()

        return True


    def stop(
        self,
        wait=False,
        timeout=None,
    ):
        """
        Request monitoring shutdown.

        If a scan is currently running, HomeSOC allows
        that scan to finish before the monitoring thread
        exits.

        If HomeSOC is waiting between scans, the wait is
        interrupted immediately.
        """

        with self._state_lock:

            if not self._running:
                return False

            logger.info(
                "Monitoring service stopping"
            )

            self._scan_state = "STOPPING"
            self._scan_stage = "Stopping monitoring..."

            self._next_scan_at = None

        self._stop_event.set()

        if (
            wait
            and self._thread
            and self._thread.is_alive()
        ):

            self._thread.join(
                timeout=timeout
            )

        return True


    # =====================================================
    # STATE
    # =====================================================

    def is_running(self):
        """
        Return True while the monitoring service
        thread is running.
        """

        with self._state_lock:
            return self._running


    def is_stopping(self):
        """
        Return True when a stop has been requested
        but the monitoring thread is still finishing.
        """

        with self._state_lock:

            return (
                self._running
                and self._stop_event.is_set()
            )


    # =====================================================
    # SCAN PROGRESS
    # =====================================================

    def update_progress(
        self,
        progress,
        stage,
    ):
        """
        Called by run_scan() to update dashboard-visible
        scan progress.

        progress:
            Integer from 0 to 100.

        stage:
            Short user-facing description.
        """

        try:
            progress = int(progress)

        except (TypeError, ValueError):
            progress = 0

        progress = max(
            0,
            min(
                100,
                progress,
            ),
        )

        with self._state_lock:

            if not self._running:
                return

            self._scan_state = "SCANNING"
            self._scan_progress = progress
            self._scan_stage = str(stage)

            self._next_scan_at = None


    def get_status(self):
        """
        Return a snapshot of the monitoring service.

        This will later be returned by /monitor/status
        so JavaScript can update the dashboard without
        refreshing the page.
        """

        with self._state_lock:

            return {
                "running": self._running,
                "stopping": (
                    self._running
                    and self._stop_event.is_set()
                ),
                "state": self._scan_state,
                "progress": self._scan_progress,
                "stage": self._scan_stage,
                "scan_started_at": self._scan_started_at,
                "next_scan_at": self._next_scan_at,
                "scan_interval": self.scan_interval,
                "last_error": self._last_error,
            }


    # =====================================================
    # MONITOR LOOP
    # =====================================================

    def _monitor_loop(self):
        """
        Background monitoring loop.

        Flow:

            SCANNING
                ↓
            scan completes
                ↓
            WAITING for 5 minutes
                ↓
            next scan begins
        """

        try:

            while not self._stop_event.is_set():

                # -----------------------------------------
                # START SCAN
                # -----------------------------------------

                with self._state_lock:

                    self._scan_state = "SCANNING"
                    self._scan_progress = 0
                    self._scan_stage = "Starting scan..."

                    self._scan_started_at = time.time()
                    self._next_scan_at = None

                    self._last_error = None

                try:

                    run_scan(
                        progress_callback=self.update_progress
                    )

                    with self._state_lock:

                        self._scan_progress = 100
                        self._scan_stage = "Scan complete"

                except Exception as error:

                    logger.exception(
                        "HomeSOC scan failed"
                    )

                    with self._state_lock:

                        self._last_error = str(error)

                        self._scan_state = "ERROR"
                        self._scan_stage = "Scan failed"

                # Stop was requested while scan was running.
                if self._stop_event.is_set():
                    break

                # -----------------------------------------
                # WAIT FOR NEXT SCAN
                # -----------------------------------------

                next_scan_at = (
                    time.time()
                    + self.scan_interval
                )

                with self._state_lock:

                    self._scan_state = "WAITING"
                    self._scan_progress = 100
                    self._scan_stage = "Scan complete"

                    self._next_scan_at = next_scan_at

                logger.info(
                    f"Next HomeSOC scan in "
                    f"{self.scan_interval} seconds"
                )

                # Event.wait() means Stop can interrupt
                # the five-minute waiting period instantly.

                if self._stop_event.wait(
                    self.scan_interval
                ):
                    break

        finally:

            with self._state_lock:

                self._running = False

                self._scan_state = "STOPPED"
                self._scan_progress = 0
                self._scan_stage = "Monitoring stopped"

                self._scan_started_at = None
                self._next_scan_at = None

            logger.info(
                "HomeSOC monitoring service stopped"
            )


monitoring_service = MonitoringService(
    scan_interval=300
)