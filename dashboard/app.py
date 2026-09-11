from flask import (
    Flask,
    render_template,
    request,
    redirect,
    url_for,
)
import sqlite3
from datetime import datetime, timezone

from monitor import monitoring_service

from database.database import (
    get_connection,
    initialize_database,
)

app = Flask(__name__)

initialize_database()

from config import DATABASE_PATH

DB_NAME = DATABASE_PATH


# =========================================================
# DATABASE
# =========================================================

def get_connection():
    connection = sqlite3.connect(DB_NAME)
    connection.row_factory = sqlite3.Row
    return connection


# =========================================================
# TIME
# =========================================================

def utc_to_local(timestamp):
    """
    Convert SQLite UTC timestamp to the local timezone
    of the computer running HomeSOC.
    """

    if not timestamp:
        return None

    try:
        utc_time = datetime.strptime(
            timestamp,
            "%Y-%m-%d %H:%M:%S"
        ).replace(
            tzinfo=timezone.utc
        )

    except ValueError:
        return timestamp

    local_time = utc_time.astimezone()

    return local_time.strftime(
        "%Y-%m-%d %I:%M:%S %p"
    )


# =========================================================
# DASHBOARD
# =========================================================

def get_dashboard_data():

    connection = get_connection()
    cursor = connection.cursor()

    # -------------------------
    # ACTIVE NETWORK
    # -------------------------

    cursor.execute("""
        SELECT value
        FROM system_status
        WHERE key = 'active_network_id'
    """)

    active_network_row = cursor.fetchone()

    active_network_id = (
        int(active_network_row["value"])
        if active_network_row
        else None
    )

    active_network = None

    if active_network_id is not None:

        cursor.execute("""
            SELECT
                id,
                network_cidr,
                gateway_ip,
                gateway_mac,
                ssid,
                display_name
            FROM networks
            WHERE id = ?
        """, (
            active_network_id,
        ))

        network_row = cursor.fetchone()

        if network_row:

            active_network = {
                "id": network_row["id"],
                "network_cidr": network_row["network_cidr"],
                "gateway_ip": network_row["gateway_ip"],
                "gateway_mac": network_row["gateway_mac"],
                "ssid": network_row["ssid"],
                "display_name": (
                    network_row["display_name"]
                    or f"Network {network_row['id']}"
                ),
            }

    # -------------------------
    # DEVICE COUNTS
    # -------------------------

    if active_network_id is not None:

        cursor.execute("""
            SELECT COUNT(*)
            FROM network_devices
            WHERE network_id = ?
            AND state = 'ONLINE'
        """, (
            active_network_id,
        ))

        online_devices = cursor.fetchone()[0]

        cursor.execute("""
            SELECT COUNT(*)
            FROM network_devices
            WHERE network_id = ?
            AND state = 'OFFLINE'
        """, (
            active_network_id,
        ))

        offline_devices = cursor.fetchone()[0]

        cursor.execute("""
            SELECT COUNT(*)
            FROM network_devices
            WHERE network_id = ?
            AND state = 'OBSERVED'
        """, (
            active_network_id,
        ))

        observed_devices = cursor.fetchone()[0]

        cursor.execute("""
            SELECT COUNT(*)
            FROM network_devices
            WHERE network_id = ?
        """, (
            active_network_id,
        ))

        total_devices = cursor.fetchone()[0]

    else:

        online_devices = 0
        offline_devices = 0
        observed_devices = 0
        total_devices = 0

    # -------------------------
    # ACTIVE ALERTS
    # -------------------------

    cursor.execute("""
        SELECT
            ip,
            port,
            service,
            risk,
            status
        FROM security_alerts
        WHERE status IN ('NEW', 'ACTIVE')
        ORDER BY
            CASE risk
                WHEN 'CRITICAL' THEN 1
                WHEN 'HIGH' THEN 2
                WHEN 'MEDIUM' THEN 3
                WHEN 'LOW' THEN 4
                ELSE 5
            END
    """)

    alert_rows = cursor.fetchall()

    alerts = []

    for alert in alert_rows:

        alerts.append({
            "ip": alert["ip"],
            "port": alert["port"],
            "service": alert["service"],
            "risk": alert["risk"],
            "status": alert["status"],
        })

    # -------------------------
    # DEVICE INVENTORY
    # -------------------------

    if active_network_id is not None:

        cursor.execute("""
            SELECT
                nd.ip,
                nd.mac,
                nd.state,
                nd.first_seen,
                nd.last_seen,

                p.device_type,
                p.confidence,
                p.evidence,

                m.hostname,
                m.vendor,

                pref.friendly_name,
                pref.trust_status,
                pref.notes

            FROM network_devices nd

            LEFT JOIN device_profiles p
                ON nd.mac = p.mac

            LEFT JOIN device_metadata m
                ON nd.mac = m.mac

            LEFT JOIN device_preferences pref
                ON nd.mac = pref.mac

            WHERE nd.network_id = ?

            ORDER BY
                CASE nd.state
                    WHEN 'ONLINE' THEN 1
                    WHEN 'OBSERVED' THEN 2
                    WHEN 'OFFLINE' THEN 3
                    ELSE 4
                END,
                nd.ip
        """, (
            active_network_id,
        ))

        device_rows = cursor.fetchall()

    else:

        device_rows = []

    devices = []

    for device in device_rows:

        devices.append({
            "ip": device["ip"],
            "mac": device["mac"],
            "state": device["state"],

            "first_seen": utc_to_local(
                device["first_seen"]
            ),

            "last_seen": utc_to_local(
                device["last_seen"]
            ),

            "device_type": device["device_type"],
            "confidence": device["confidence"],
            "evidence": device["evidence"],

            "hostname": device["hostname"],
            "vendor": device["vendor"],

            "friendly_name": device["friendly_name"],

            "trust_status": (
                device["trust_status"]
                or "UNREVIEWED"
            ),

            "notes": device["notes"],
        })

    # -------------------------
    # RECENT EVENTS
    # -------------------------

    cursor.execute("""
        SELECT
            timestamp,
            event_type,
            ip,
            port,
            description
        FROM events
        ORDER BY id DESC
        LIMIT 6
    """)

    event_rows = cursor.fetchall()

    events = []

    for event in event_rows:

        events.append({
            "timestamp": utc_to_local(
                event["timestamp"]
            ),
            "event_type": event["event_type"],
            "ip": event["ip"],
            "port": event["port"],
            "description": event["description"],
        })

    # -------------------------
    # LAST SUCCESSFUL SCAN
    # -------------------------

    cursor.execute("""
        SELECT value
        FROM system_status
        WHERE key = 'last_scan_utc'
    """)

    last_scan_row = cursor.fetchone()

    connection.close()

    if last_scan_row:

        last_scan = utc_to_local(
            last_scan_row["value"]
        )

    else:

        last_scan = "NO SCAN YET"

    return {
        "online_devices": online_devices,
        "offline_devices": offline_devices,
        "observed_devices": observed_devices,
        "total_devices": total_devices,

        "devices": devices,
        "alerts": alerts,
        "events": events,

        "active_network": active_network,
        "last_scan": last_scan,
    }

@app.route("/")
def dashboard():

    data = get_dashboard_data()

    monitor_running = monitoring_service.is_running()
    monitor_stopping = monitoring_service.is_stopping()

    return render_template(
        "dashboard.html",

        online_devices=data["online_devices"],
        offline_devices=data["offline_devices"],
        observed_devices=data["observed_devices"],
        total_devices=data["total_devices"],

        devices=data["devices"],
        alerts=data["alerts"],
        events=data["events"],

        active_network=data["active_network"],
        last_scan=data["last_scan"],

        monitor_running=monitor_running,
        monitor_stopping=monitor_stopping,
    )

@app.route("/dashboard/status")
def dashboard_status():

    return get_dashboard_data()

# =========================================================
# NETWORK SETTINGS
# =========================================================

@app.route("/network/<int:network_id>/rename", methods=["POST"])
def rename_network(network_id):

    display_name = (
        request.form.get(
            "display_name",
            ""
        ).strip()
    )

    if display_name:

        connection = get_connection()
        cursor = connection.cursor()

        cursor.execute("""
            UPDATE networks
            SET display_name = ?
            WHERE id = ?
        """, (
            display_name,
            network_id,
        ))

        connection.commit()
        connection.close()

    return redirect(url_for("dashboard"))


# =========================================================
# DEVICE DETAILS
# =========================================================

@app.route(
    "/device/<mac>",
    methods=["GET", "POST"]
)
def device_detail(mac):

    # Normalize MAC formatting
    mac = mac.lower()

    connection = get_connection()
    cursor = connection.cursor()

    # -------------------------
    # SAVE USER CHANGES
    # -------------------------

    if request.method == "POST":

        friendly_name = (
            request.form.get(
                "friendly_name",
                ""
            ).strip()
        )

        trust_status = (
            request.form.get(
                "trust_status",
                "UNREVIEWED"
            ).upper()
        )

        notes = (
            request.form.get(
                "notes",
                ""
            ).strip()
        )

        allowed_statuses = {
            "UNREVIEWED",
            "TRUSTED",
            "SUSPICIOUS",
        }

        if trust_status not in allowed_statuses:
            trust_status = "UNREVIEWED"

        cursor.execute("""
            INSERT INTO device_preferences
            (
                mac,
                friendly_name,
                trust_status,
                notes,
                updated_at
            )
            VALUES (
                ?, ?, ?, ?, datetime('now')
            )

            ON CONFLICT(mac)
            DO UPDATE SET

                friendly_name =
                    excluded.friendly_name,

                trust_status =
                    excluded.trust_status,

                notes =
                    excluded.notes,

                updated_at =
                    datetime('now')
        """, (
            mac,
            friendly_name or None,
            trust_status,
            notes or None,
        ))

        connection.commit()
        connection.close()

        return redirect(
            url_for(
                "device_detail",
                mac=mac
            )
        )

    # -------------------------
    # DEVICE IDENTITY
    # -------------------------

    cursor.execute("""
        SELECT
            d.ip,
            d.mac,
            d.state,
            d.first_seen,
            d.last_seen,

            p.device_type,
            p.confidence,
            p.evidence,

            m.hostname,
            m.vendor,

            pref.friendly_name,
            pref.trust_status,
            pref.notes,
            pref.updated_at

        FROM devices d

        LEFT JOIN device_profiles p
            ON d.mac = p.mac

        LEFT JOIN device_metadata m
            ON d.mac = m.mac

        LEFT JOIN device_preferences pref
            ON d.mac = pref.mac

        WHERE LOWER(d.mac) = LOWER(?)

        LIMIT 1
    """, (
        mac,
    ))

    device_row = cursor.fetchone()

    if device_row is None:

        connection.close()

        return (
            "Device not found",
            404
        )

    device = {
        "ip": device_row["ip"],
        "mac": device_row["mac"],
        "state": device_row["state"],

        "first_seen": utc_to_local(
            device_row["first_seen"]
        ),

        "last_seen": utc_to_local(
            device_row["last_seen"]
        ),

        "device_type": device_row["device_type"],
        "confidence": device_row["confidence"],
        "evidence": device_row["evidence"],

        "hostname": device_row["hostname"],
        "vendor": device_row["vendor"],

        "friendly_name": (
            device_row["friendly_name"]
            or ""
        ),

        "trust_status": (
            device_row["trust_status"]
            or "UNREVIEWED"
        ),

        "notes": (
            device_row["notes"]
            or ""
        ),

        "preferences_updated": utc_to_local(
            device_row["updated_at"]
        ),
    }

    # -------------------------
    # SERVICES
    # -------------------------

    cursor.execute("""
        SELECT
            port,
            protocol,
            state,
            first_seen,
            last_seen
        FROM services
        WHERE ip = ?
        ORDER BY
            CASE state
                WHEN 'OPEN' THEN 1
                ELSE 2
            END,
            port
    """, (
        device["ip"],
    ))

    service_rows = cursor.fetchall()

    services = []

    for service in service_rows:

        services.append({
            "port": service["port"],
            "protocol": service["protocol"],
            "state": service["state"],

            "first_seen": utc_to_local(
                service["first_seen"]
            ),

            "last_seen": utc_to_local(
                service["last_seen"]
            ),
        })

    # -------------------------
    # DEVICE ALERTS
    # -------------------------

    cursor.execute("""
        SELECT
            timestamp,
            port,
            service,
            risk,
            description,
            status
        FROM security_alerts
        WHERE mac = ?
        ORDER BY id DESC
        LIMIT 20
    """, (
        mac,
    ))

    alert_rows = cursor.fetchall()

    device_alerts = []

    for alert in alert_rows:

        device_alerts.append({
            "timestamp": utc_to_local(
                alert["timestamp"]
            ),

            "port": alert["port"],
            "service": alert["service"],
            "risk": alert["risk"],
            "description": alert["description"],
            "status": alert["status"],
        })

    # -------------------------
    # DEVICE EVENTS
    # -------------------------

    cursor.execute("""
        SELECT
            timestamp,
            event_type,
            ip,
            port,
            description
        FROM events
        WHERE
            mac = ?
            OR ip = ?
        ORDER BY id DESC
        LIMIT 20
    """, (
        mac,
        device["ip"],
    ))

    event_rows = cursor.fetchall()

    device_events = []

    for event in event_rows:

        device_events.append({
            "timestamp": utc_to_local(
                event["timestamp"]
            ),

            "event_type": event["event_type"],
            "ip": event["ip"],
            "port": event["port"],
            "description": event["description"],
        })

    connection.close()

    # -------------------------
    # RENDER DEVICE PAGE
    # -------------------------

    return render_template(
        "device.html",

        device=device,
        services=services,
        alerts=device_alerts,
        events=device_events,
    )


# =========================================================
# MONITORING CONTROL
# =========================================================

@app.route("/monitor/start", methods=["POST"])
def start_monitoring():
    monitoring_service.start()
    return redirect(url_for("dashboard"))


@app.route("/monitor/stop", methods=["POST"])
def stop_monitoring():
    monitoring_service.stop(wait=False)
    return redirect(url_for("dashboard"))


@app.route("/monitor/status")
def monitor_status():

    status_data = monitoring_service.get_status()

    return status_data

# =========================================================
# START FLASK
# =========================================================

if __name__ == "__main__":

    app.run(
        host="127.0.0.1",
        port=5000,
        debug=True,
    )