import tkinter as tk
from tkinter import messagebox

import webbrowser

from monitor import monitoring_service
from dashboard_server import dashboard_server

from config import (
    DASHBOARD_HOST,
    DASHBOARD_PORT,
)

from logger import logger


class HomeSOCApp:

    def __init__(self, root):

        self.root = root

        self.root.title(
            "HomeSOC"
        )

        self.root.geometry(
            "420x230"
        )

        self.root.resizable(
            False,
            False,
        )

        self.root.configure(
            bg="#0f1014"
        )

        self.root.protocol(
            "WM_DELETE_WINDOW",
            self.on_close,
        )

        # -------------------------
        # TITLE
        # -------------------------

        title_label = tk.Label(
            root,
            text="HomeSOC",
            bg="#0f1014",
            fg="#f4f4f5",
            font=(
                "Segoe UI",
                24,
                "bold",
            ),
        )

        title_label.pack(
            pady=(
                28,
                2,
            )
        )

        subtitle_label = tk.Label(
            root,
            text=(
                "Home Security "
                "Operations Center"
            ),
            bg="#0f1014",
            fg="#85858f",
            font=(
                "Segoe UI",
                10,
            ),
        )

        subtitle_label.pack()

        # -------------------------
        # STATUS
        # -------------------------

        self.status_label = tk.Label(
            root,
            text="Starting HomeSOC...",
            bg="#0f1014",
            fg="#a78bfa",
            font=(
                "Segoe UI",
                10,
                "bold",
            ),
        )

        self.status_label.pack(
            pady=(
                22,
                14,
            )
        )

        # -------------------------
        # OPEN DASHBOARD BUTTON
        # -------------------------

        dashboard_button = tk.Button(
            root,
            text="OPEN DASHBOARD",
            command=self.open_dashboard,

            bg="#7c3aed",
            fg="white",

            activebackground="#6d28d9",
            activeforeground="white",

            relief="flat",

            font=(
                "Segoe UI",
                10,
                "bold",
            ),

            width=24,
            height=2,
        )

        dashboard_button.pack()

        # -------------------------
        # START BACKEND SERVICES
        # -------------------------

        self.start_home_soc()

        # -------------------------
        # STATUS LOOP
        # -------------------------

        self.update_status()


    # =====================================================
    # STARTUP
    # =====================================================

    def start_home_soc(self):

        dashboard_server.start()

        logger.info(
            "HomeSOC desktop launcher started"
        )

        # Open dashboard shortly after Flask starts.
        self.root.after(
            800,
            self.open_dashboard,
        )


    # =====================================================
    # DASHBOARD
    # =====================================================

    def open_dashboard(self):

        if not dashboard_server.is_running():

            dashboard_server.start()

        url = (
            f"http://"
            f"{DASHBOARD_HOST}:"
            f"{DASHBOARD_PORT}"
        )

        webbrowser.open(url)


    # =====================================================
    # STATUS
    # =====================================================

    def update_status(self):

        if monitoring_service.is_stopping():

            self.status_label.config(
                text="Monitoring stopping...",
                fg="#f59e0b",
            )

        elif monitoring_service.is_running():

            self.status_label.config(
                text="Monitoring active",
                fg="#22c55e",
            )

        else:

            self.status_label.config(
                text="Dashboard active • Monitoring stopped",
                fg="#85858f",
            )

        self.root.after(
            1000,
            self.update_status,
        )


    # =====================================================
    # APPLICATION SHUTDOWN
    # =====================================================

    def on_close(self):

        if monitoring_service.is_running():

            result = messagebox.askyesno(
                "Exit HomeSOC",
                (
                    "Monitoring is currently active.\n\n"
                    "Stop monitoring and exit HomeSOC?"
                ),
            )

            if not result:
                return

            monitoring_service.stop(
                wait=False
            )

        dashboard_server.stop()

        logger.info(
            "HomeSOC desktop launcher closed"
        )

        self.root.destroy()


def main():

    root = tk.Tk()

    HomeSOCApp(
        root
    )

    root.mainloop()


if __name__ == "__main__":
    main()