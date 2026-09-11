import sqlite3

from config import DATABASE_PATH

DB_NAME = DATABASE_PATH

def get_connection():
    return sqlite3.connect(DB_NAME)

def initialize_database():
    connection = sqlite3.connect(DB_NAME)
    cursor = connection.cursor()

    cursor.execute("""
        CREATE TABLE IF NOT EXISTS devices (
            ip TEXT PRIMARY KEY,
            mac TEXT,
            state TEXT,
            first_seen TEXT,
            last_seen TEXT
        )
    """)

    cursor.execute("""
        CREATE TABLE IF NOT EXISTS device_identity (
            mac TEXT PRIMARY KEY,
            first_ip TEXT,
            current_ip TEXT,
            first_seen TEXT,
            last_seen TEXT
        )
    """)

    cursor.execute("""
        CREATE TABLE IF NOT EXISTS device_profiles (
            mac TEXT PRIMARY KEY,
            ip TEXT,
            device_type TEXT,
            confidence TEXT,
            evidence TEXT,
            first_seen TEXT,
            last_seen TEXT
        )
    """)

    cursor.execute("""
        CREATE TABLE IF NOT EXISTS services (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            ip TEXT NOT NULL,
            port INTEGER NOT NULL,
            protocol TEXT NOT NULL,
            state TEXT NOT NULL,
            first_seen TEXT,
            last_seen TEXT,
            UNIQUE(ip, port, protocol)
        )
    """)

    cursor.execute("""
        CREATE TABLE IF NOT EXISTS events (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            timestamp TEXT NOT NULL,
            event_type TEXT NOT NULL,
            ip TEXT,
            mac TEXT,
            port INTEGER,
            description TEXT
        )
    """)

    cursor.execute("""
        CREATE TABLE IF NOT EXISTS security_alerts (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            timestamp TEXT NOT NULL,
            ip TEXT,
            mac TEXT,
            port INTEGER,
            service TEXT,
            risk TEXT,
            description TEXT,
            status TEXT
        )
    """)

    cursor.execute("""
        CREATE TABLE IF NOT EXISTS service_baseline (
            mac TEXT NOT NULL,
            port INTEGER NOT NULL,
            protocol TEXT NOT NULL DEFAULT 'TCP',
            created_at TEXT NOT NULL,
            PRIMARY KEY (
                mac,
                port,
                protocol
            )
        )
    """)

    # -------------------------
    # SECURITY ALERT MIGRATION
    # -------------------------

    cursor.execute("""
        PRAGMA table_info(security_alerts)
    """)

    alert_columns = {
        row[1]
        for row in cursor.fetchall()
    }

    if "first_seen" not in alert_columns:

        cursor.execute("""
            ALTER TABLE security_alerts
            ADD COLUMN first_seen TEXT
        """)

    if "last_seen" not in alert_columns:

        cursor.execute("""
            ALTER TABLE security_alerts
            ADD COLUMN last_seen TEXT
        """)

    if "resolved_at" not in alert_columns:

        cursor.execute("""
            ALTER TABLE security_alerts
            ADD COLUMN resolved_at TEXT
        """)

    if "occurrence_count" not in alert_columns:

        cursor.execute("""
            ALTER TABLE security_alerts
            ADD COLUMN occurrence_count INTEGER DEFAULT 1
        """)

    # Backfill older alerts
    cursor.execute("""
        UPDATE security_alerts
        SET
            first_seen = COALESCE(
                first_seen,
                timestamp
            ),

            last_seen = COALESCE(
                last_seen,
                timestamp
            ),

            occurrence_count = COALESCE(
                occurrence_count,
                1
            )
    """)

    cursor.execute("""
    CREATE TABLE IF NOT EXISTS system_status (
        key TEXT PRIMARY KEY,
        value TEXT
        )
    """)

    cursor.execute("""
    CREATE TABLE IF NOT EXISTS device_metadata (
        mac TEXT PRIMARY KEY,
        hostname TEXT,
        vendor TEXT,
        last_seen TEXT
        )
    """)

    cursor.execute("""
        CREATE TABLE IF NOT EXISTS device_preferences (
            mac TEXT PRIMARY KEY,
            friendly_name TEXT,
            trust_status TEXT NOT NULL DEFAULT 'UNREVIEWED',
            notes TEXT,
            updated_at TEXT
        )
    """)

        # =====================================================
    # NETWORK / SITE TRACKING
    # =====================================================

    cursor.execute("""
        CREATE TABLE IF NOT EXISTS networks (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            network_cidr TEXT NOT NULL,
            gateway_ip TEXT,
            gateway_mac TEXT,
            first_seen TEXT NOT NULL DEFAULT (datetime('now')),
            last_seen TEXT NOT NULL DEFAULT (datetime('now')),
            UNIQUE(network_cidr, gateway_mac)
        )
    """)

    cursor.execute(
            "PRAGMA table_info(networks)"
        )
    
    network_columns = {
            row[1]
            for row in cursor.fetchall()
        }
    
    if "ssid" not in network_columns:
    
            cursor.execute("""
                ALTER TABLE networks
                ADD COLUMN ssid TEXT
            """)

    cursor.execute("""
        CREATE TABLE IF NOT EXISTS network_devices (
            network_id INTEGER NOT NULL,
            mac TEXT NOT NULL,
            ip TEXT,
            state TEXT,
            first_seen TEXT NOT NULL DEFAULT (datetime('now')),
            last_seen TEXT NOT NULL DEFAULT (datetime('now')),

            PRIMARY KEY (
                network_id,
                mac
            ),

            FOREIGN KEY (network_id)
                REFERENCES networks(id)
        )
    """)

    cursor.execute("""
        CREATE INDEX IF NOT EXISTS
        idx_network_devices_network_id
        ON network_devices(network_id)
    """)

    cursor.execute("PRAGMA table_info(networks)")
    network_columns = {
    row[1]
    for row in cursor.fetchall()
    }

    if "display_name" not in network_columns:
        cursor.execute("""
        ALTER TABLE networks
        ADD COLUMN display_name TEXT
    """)

    connection.commit()
    connection.close()


def device_exists(ip):
    connection = sqlite3.connect(DB_NAME)
    cursor = connection.cursor()

    cursor.execute(
        "SELECT ip FROM devices WHERE ip = ?",
        (ip,)
    )

    result = cursor.fetchone()

    connection.close()

    return result is not None


def check_device_identity(mac, ip):
    if not mac:
        return "UNKNOWN"

    connection = sqlite3.connect(DB_NAME)
    cursor = connection.cursor()

    cursor.execute(
        "SELECT current_ip FROM device_identity WHERE mac = ?",
        (mac,)
    )

    result = cursor.fetchone()

    if result is None:
        cursor.execute("""
            INSERT INTO device_identity
            (mac, first_ip, current_ip, first_seen, last_seen)
            VALUES (?, ?, ?, datetime('now'), datetime('now'))
        """, (mac, ip, ip))

        connection.commit()
        connection.close()

        return "NEW"

    previous_ip = result[0]

    cursor.execute("""
        UPDATE device_identity
        SET current_ip = ?,
            last_seen = datetime('now')
        WHERE mac = ?
    """, (ip, mac))

    connection.commit()
    connection.close()

    if previous_ip != ip:
        return "IP_CHANGED"

    return "KNOWN"


def save_device(ip, mac, state):
    connection = sqlite3.connect(DB_NAME)
    cursor = connection.cursor()

    cursor.execute("""
        SELECT state
        FROM devices
        WHERE ip = ?
    """, (ip,))

    result = cursor.fetchone()

    if result is None:

        cursor.execute("""
            INSERT INTO devices
            (ip, mac, state, first_seen, last_seen)
            VALUES (?, ?, ?, datetime('now'), datetime('now'))
        """, (
            ip,
            mac,
            state
        ))

    else:

        cursor.execute("""
            UPDATE devices
            SET mac = ?,
                state = ?,
                last_seen = datetime('now')
            WHERE ip = ?
        """, (
            mac,
            state,
            ip
        ))

    connection.commit()
    connection.close()

def save_service(ip, port, protocol, state):
    connection = get_connection()
    cursor = connection.cursor()

    cursor.execute("""
        SELECT state
        FROM services
        WHERE ip = ?
        AND port = ?
        AND protocol = ?
    """, (
        ip,
        port,
        protocol
    ))

    result = cursor.fetchone()

    if result is None:

        cursor.execute("""
            INSERT INTO services
            (ip, port, protocol, state, first_seen, last_seen)
            VALUES (?, ?, ?, ?, datetime('now'), datetime('now'))
        """, (
            ip,
            port,
            protocol,
            state
        ))

        connection.commit()
        connection.close()

        if state == "OPEN":
            return "NEW"

        return "KNOWN"

    previous_state = result[0]

    cursor.execute("""
        UPDATE services
        SET state = ?,
            last_seen = datetime('now')
        WHERE ip = ?
        AND port = ?
        AND protocol = ?
    """, (
        state,
        ip,
        port,
        protocol
    ))

    connection.commit()
    connection.close()

    if previous_state == "CLOSED" and state == "OPEN":
        return "OPENED"

    if previous_state == "OPEN" and state == "CLOSED":
        return "CLOSED"

    return "KNOWN"

    previous_state = result[0]

    cursor.execute("""
        UPDATE services
        SET state = ?,
            last_seen = datetime('now')
        WHERE ip = ?
        AND port = ?
        AND protocol = ?
    """, (
        state,
        ip,
        port,
        protocol
    ))

    connection.commit()
    connection.close()

    if previous_state == "CLOSED" and state == "OPEN":
        return "OPENED"

    if previous_state == "OPEN" and state == "CLOSED":
        return "CLOSED"

    return "KNOWN"

def save_event(event_type, ip=None, mac=None, port=None, description=None):
    connection = get_connection()
    cursor = connection.cursor()

    cursor.execute("""
        INSERT INTO events
        (timestamp, event_type, ip, mac, port, description)
        VALUES (datetime('now'), ?, ?, ?, ?, ?)
    """, (
        event_type,
        ip,
        mac,
        port,
        description
    ))

    connection.commit()
    connection.close()

def get_baseline_ports(mac):
    """
    Return the TCP ports that are expected to be open
    for a device according to the saved baseline.
    """

    if not mac:
        return set()

    connection = get_connection()
    cursor = connection.cursor()

    cursor.execute("""
        SELECT port
        FROM service_baseline
        WHERE mac = ?
        AND protocol = 'TCP'
    """, (
        mac,
    ))

    rows = cursor.fetchall()

    connection.close()

    return {
        row[0]
        for row in rows
    }


def baseline_exists(mac):
    """
    Determine whether a device has a saved service baseline.
    """

    if not mac:
        return False

    connection = get_connection()
    cursor = connection.cursor()

    cursor.execute("""
        SELECT 1
        FROM service_baseline
        WHERE mac = ?
        LIMIT 1
    """, (
        mac,
    ))

    result = cursor.fetchone()

    connection.close()

    return result is not None


def save_baseline_port(
    mac,
    port,
    protocol="TCP",
):
    """
    Add an expected service to the device baseline.
    """

    if not mac:
        return False

    connection = get_connection()
    cursor = connection.cursor()

    cursor.execute("""
        INSERT OR IGNORE INTO service_baseline
        (
            mac,
            port,
            protocol,
            created_at
        )
        VALUES (
            ?, ?, ?, datetime('now')
        )
    """, (
        mac,
        port,
        protocol,
    ))

    connection.commit()
    connection.close()

    return True

def save_event_once(
    event_type,
    ip=None,
    mac=None,
    port=None,
    description=None,
):
    """
    Save an event only if an identical event for the
    same device/service has not already been recorded.

    Returns True if a new event was created.
    Returns False if the event already exists.
    """

    connection = get_connection()
    cursor = connection.cursor()

    cursor.execute("""
        SELECT id
        FROM events
        WHERE event_type = ?
          AND COALESCE(ip, '') = COALESCE(?, '')
          AND COALESCE(mac, '') = COALESCE(?, '')
          AND COALESCE(port, -1) = COALESCE(?, -1)
        ORDER BY id DESC
        LIMIT 1
    """, (
        event_type,
        ip,
        mac,
        port,
    ))

    existing_event = cursor.fetchone()

    if existing_event is not None:
        connection.close()
        return False

    cursor.execute("""
        INSERT INTO events
        (timestamp, event_type, ip, mac, port, description)
        VALUES (datetime('now'), ?, ?, ?, ?, ?)
    """, (
        event_type,
        ip,
        mac,
        port,
        description,
    ))

    connection.commit()
    connection.close()

    return True

def get_online_devices():
        connection = sqlite3.connect(DB_NAME)
        cursor = connection.cursor()

        cursor.execute("""
        SELECT ip, mac
        FROM devices
        WHERE state = 'ONLINE'
        """)

        results = cursor.fetchall()

        connection.close()

        return results

def get_all_devices():
    connection = sqlite3.connect(DB_NAME)
    cursor = connection.cursor()

    cursor.execute("""
        SELECT ip, mac, state
        FROM devices
    """)

    results = cursor.fetchall()

    connection.close()

    return results

def save_event_once(
    event_type,
    ip=None,
    mac=None,
    port=None,
    description=None,
):
    """
    Save an event only if the same unresolved condition
    has not already been recorded.

    Returns:
        True  -> new event was created
        False -> duplicate active condition was suppressed
    """

    connection = get_connection()
    cursor = connection.cursor()

    cursor.execute("""
        SELECT id
        FROM events
        WHERE event_type = ?
          AND COALESCE(ip, '') = COALESCE(?, '')
          AND COALESCE(mac, '') = COALESCE(?, '')
          AND COALESCE(port, -1) = COALESCE(?, -1)
        ORDER BY id DESC
        LIMIT 1
    """, (
        event_type,
        ip,
        mac,
        port,
    ))

    existing_event = cursor.fetchone()

    if existing_event is not None:
        connection.close()
        return False

    cursor.execute("""
        INSERT INTO events
        (timestamp, event_type, ip, mac, port, description)
        VALUES (datetime('now'), ?, ?, ?, ?, ?)
    """, (
        event_type,
        ip,
        mac,
        port,
        description,
    ))

    connection.commit()
    connection.close()

    return True

def update_device_state(ip, state):
    connection = sqlite3.connect(DB_NAME)
    cursor = connection.cursor()

    cursor.execute("""
        UPDATE devices
        SET state = ?
        WHERE ip = ?
    """, (
        state,
        ip
    ))

    connection.commit()
    connection.close()

def save_device_profile(
    mac,
    ip,
    device_type,
    confidence,
    evidence
):
    if not mac:
        return

    connection = get_connection()
    cursor = connection.cursor()

    cursor.execute("""
        SELECT mac
        FROM device_profiles
        WHERE mac = ?
    """, (mac,))

    result = cursor.fetchone()

    if result is None:

        cursor.execute("""
            INSERT INTO device_profiles
            (mac, ip, device_type, confidence, evidence,
             first_seen, last_seen)
            VALUES (?, ?, ?, ?, ?, datetime('now'), datetime('now'))
        """, (
            mac,
            ip,
            device_type,
            confidence,
            evidence
        ))

    else:

        cursor.execute("""
            UPDATE device_profiles
            SET ip = ?,
                device_type = ?,
                confidence = ?,
                evidence = ?,
                last_seen = datetime('now')
            WHERE mac = ?
        """, (
            ip,
            device_type,
            confidence,
            evidence,
            mac
        ))

    connection.commit()
    connection.close()    

def get_device_profile(mac):
    connection = get_connection()
    cursor = connection.cursor()

    cursor.execute("""
        SELECT
            mac,
            ip,
            device_type,
            confidence,
            evidence,
            first_seen,
            last_seen
        FROM device_profiles
        WHERE mac = ?
    """, (mac,))

    result = cursor.fetchone()

    connection.close()

    return result

def save_security_alert(
    ip,
    mac,
    port,
    service,
    risk,
    description
):
    """
    Create or update a security alert.

    Lifecycle:

        NEW
          ↓
        ACTIVE
          ↓
        RESOLVED

    If a resolved finding appears again later,
    HomeSOC creates a new alert record.
    """

    connection = get_connection()
    cursor = connection.cursor()

    # Find an existing unresolved alert
    cursor.execute("""
        SELECT
            id,
            status,
            occurrence_count
        FROM security_alerts
        WHERE ip = ?
        AND port = ?
        AND service = ?
        AND status IN (
            'NEW',
            'ACTIVE'
        )
        ORDER BY id DESC
        LIMIT 1
    """, (
        ip,
        port,
        service,
    ))

    result = cursor.fetchone()

    # -------------------------
    # NEW ALERT
    # -------------------------

    if result is None:

        cursor.execute("""
            INSERT INTO security_alerts
            (
                timestamp,
                ip,
                mac,
                port,
                service,
                risk,
                description,
                status,
                first_seen,
                last_seen,
                resolved_at,
                occurrence_count
            )
            VALUES
            (
                datetime('now'),
                ?, ?, ?, ?, ?, ?,
                'NEW',
                datetime('now'),
                datetime('now'),
                NULL,
                1
            )
        """, (
            ip,
            mac,
            port,
            service,
            risk,
            description,
        ))

        connection.commit()
        connection.close()

        return "NEW"

    # -------------------------
    # EXISTING ALERT
    # -------------------------

    alert_id = result[0]
    previous_status = result[1]
    occurrence_count = result[2] or 1

    new_count = occurrence_count + 1

    # NEW becomes ACTIVE once it survives another scan
    if previous_status == "NEW":
        new_status = "ACTIVE"

    else:
        new_status = "ACTIVE"

    cursor.execute("""
        UPDATE security_alerts
        SET
            mac = ?,
            risk = ?,
            description = ?,
            status = ?,
            last_seen = datetime('now'),
            occurrence_count = ?
        WHERE id = ?
    """, (
        mac,
        risk,
        description,
        new_status,
        new_count,
        alert_id,
    ))

    connection.commit()
    connection.close()

    return new_status

def save_device_security_alert(
    ip,
    mac,
    event_type,
    risk,
    description
):
    """
    Create or update a device-level security alert.

    Device-level alerts are tracked by MAC address
    and event type rather than IP address and port.
    """

    if not mac:
        return None

    connection = get_connection()
    cursor = connection.cursor()

    # -------------------------
    # FIND EXISTING ALERT
    # -------------------------

    cursor.execute("""
        SELECT
            id,
            status,
            occurrence_count
        FROM security_alerts
        WHERE mac = ?
        AND service = ?
        AND port IS NULL
        AND status IN (
            'NEW',
            'ACTIVE'
        )
        ORDER BY id DESC
        LIMIT 1
    """, (
        mac,
        event_type,
    ))

    result = cursor.fetchone()

    # -------------------------
    # NEW ALERT
    # -------------------------

    if result is None:

        cursor.execute("""
            INSERT INTO security_alerts
            (
                timestamp,
                ip,
                mac,
                port,
                service,
                risk,
                description,
                status,
                first_seen,
                last_seen,
                resolved_at,
                occurrence_count
            )
            VALUES
            (
                datetime('now'),
                ?, ?, NULL, ?, ?, ?,
                'NEW',
                datetime('now'),
                datetime('now'),
                NULL,
                1
            )
        """, (
            ip,
            mac,
            event_type,
            risk,
            description,
        ))

        connection.commit()
        connection.close()

        return "NEW"

    # -------------------------
    # EXISTING ALERT
    # -------------------------

    alert_id = result[0]
    occurrence_count = result[2] or 1

    cursor.execute("""
        UPDATE security_alerts
        SET
            ip = ?,
            risk = ?,
            description = ?,
            status = 'ACTIVE',
            last_seen = datetime('now'),
            occurrence_count = ?
        WHERE id = ?
    """, (
        ip,
        risk,
        description,
        occurrence_count + 1,
        alert_id,
    ))

    connection.commit()
    connection.close()

    return "ACTIVE"


def resolve_missing_alerts(
    active_findings,
    active_device_findings=None,
    scanned_service_ips=None,
):
    """
    Resolve security alerts that are no longer
    present in the current scan.

    Supports:
        - Service-level alerts
        - Device-level security alerts
    """

    if active_device_findings is None:
        active_device_findings = set()

    if scanned_service_ips is None:
        scanned_service_ips = set()

    connection = get_connection()
    cursor = connection.cursor()

    cursor.execute("""
        SELECT
            id,
            ip,
            mac,
            port,
            service,
            risk
        FROM security_alerts
        WHERE status IN (
            'NEW',
            'ACTIVE'
        )
    """)

    alerts = cursor.fetchall()

    resolved_alerts = []

    for (
        alert_id,
        ip,
        mac,
        port,
        service,
        risk,
    ) in alerts:

        # -------------------------
        # DEVICE-LEVEL ALERT
        # -------------------------

        if port is None:

            finding_key = (
                mac,
                service,
            )

            is_active = (
                finding_key
                in active_device_findings
            )

        # -------------------------
        # SERVICE-LEVEL ALERT
        # -------------------------

        else:

         # Do not resolve a service alert unless
            # this device was actually scanned.
            if ip not in scanned_service_ips:
                continue

            finding_key = (
            ip,
            port,
            service,
            )

            is_active = (
            finding_key
            in active_findings
            )

        # -------------------------
        # RESOLVE MISSING ALERT
        # -------------------------

        if not is_active:

            cursor.execute("""
                UPDATE security_alerts
                SET
                    status = 'RESOLVED',
                    resolved_at = datetime('now')
                WHERE id = ?
            """, (
                alert_id,
            ))

            resolved_alerts.append({
                "id": alert_id,
                "ip": ip,
                "mac": mac,
                "port": port,
                "service": service,
                "risk": risk,
            })

    connection.commit()
    connection.close()

    return resolved_alerts

def record_last_scan():
    connection = get_connection()
    cursor = connection.cursor()

    cursor.execute("""
        INSERT OR REPLACE INTO system_status
        (key, value)
        VALUES (
            'last_scan_utc',
            datetime('now')
        )
    """)

    connection.commit()
    connection.close()

def save_device_metadata(
    mac,
    hostname=None,
    vendor=None
):
    if not mac:
        return

    connection = get_connection()
    cursor = connection.cursor()

    cursor.execute("""
        SELECT mac
        FROM device_metadata
        WHERE mac = ?
    """, (mac,))

    result = cursor.fetchone()

    if result is None:

        cursor.execute("""
            INSERT INTO device_metadata
            (
                mac,
                hostname,
                vendor,
                last_seen
            )
            VALUES (
                ?, ?, ?, datetime('now')
            )
        """, (
            mac,
            hostname,
            vendor
        ))

    else:

        cursor.execute("""
            UPDATE device_metadata
            SET hostname = COALESCE(?, hostname),
                vendor = COALESCE(?, vendor),
                last_seen = datetime('now')
            WHERE mac = ?
        """, (
            hostname,
            vendor,
            mac        
        ))

    connection.commit()
    connection.close()

def get_device_preferences(mac):
    """
    Retrieve user-defined information for a device.
    """

    if not mac:
        return None

    connection = get_connection()
    cursor = connection.cursor()

    cursor.execute("""
        SELECT
            mac,
            friendly_name,
            trust_status,
            notes,
            updated_at
        FROM device_preferences
        WHERE mac = ?
    """, (mac,))

    result = cursor.fetchone()

    connection.close()

    return result


def save_device_preferences(
    mac,
    friendly_name=None,
    trust_status="UNREVIEWED",
    notes=None
):
    """
    Save or update user-defined device information.

    Preferences are stored by MAC address so they
    continue to follow a device if its IP changes.
    """

    if not mac:
        return False

    allowed_statuses = {
        "UNREVIEWED",
        "TRUSTED",
        "SUSPICIOUS",
    }

    trust_status = trust_status.upper()

    if trust_status not in allowed_statuses:
        raise ValueError(
            f"Invalid trust status: {trust_status}"
        )

    connection = get_connection()
    cursor = connection.cursor()

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
        ON CONFLICT(mac) DO UPDATE SET
            friendly_name = excluded.friendly_name,
            trust_status = excluded.trust_status,
            notes = excluded.notes,
            updated_at = datetime('now')
    """, (
        mac,
        friendly_name,
        trust_status,
        notes,
    ))

    connection.commit()
    connection.close()

    return True


def set_device_trust(mac, trust_status):
    """
    Change only the trust status of a device.
    """

    if not mac:
        return False

    allowed_statuses = {
        "UNREVIEWED",
        "TRUSTED",
        "SUSPICIOUS",
    }

    trust_status = trust_status.upper()

    if trust_status not in allowed_statuses:
        raise ValueError(
            f"Invalid trust status: {trust_status}"
        )

    connection = get_connection()
    cursor = connection.cursor()

    cursor.execute("""
        INSERT INTO device_preferences
        (
            mac,
            trust_status,
            updated_at
        )
        VALUES (
            ?, ?, datetime('now')
        )
        ON CONFLICT(mac) DO UPDATE SET
            trust_status = excluded.trust_status,
            updated_at = datetime('now')
    """, (
        mac,
        trust_status,
    ))

    connection.commit()
    connection.close()

    return True

def get_baseline_ports(mac):
    """
    Return expected TCP ports for a device.
    """

    if not mac:
        return set()

    connection = get_connection()
    cursor = connection.cursor()

    cursor.execute("""
        SELECT port
        FROM service_baseline
        WHERE mac = ?
        AND protocol = 'TCP'
    """, (mac,))

    rows = cursor.fetchall()

    connection.close()

    return {
        row[0]
        for row in rows
    }


def baseline_exists(mac):
    """
    Check whether a device has a saved baseline.
    """

    if not mac:
        return False

    connection = get_connection()
    cursor = connection.cursor()

    cursor.execute("""
        SELECT 1
        FROM service_baseline
        WHERE mac = ?
        LIMIT 1
    """, (mac,))

    result = cursor.fetchone()

    connection.close()

    return result is not None


def save_baseline_port(
    mac,
    port,
    protocol="TCP",
):
    """
    Save an expected service to the baseline.
    """

    if not mac:
        return False

    connection = get_connection()
    cursor = connection.cursor()

    cursor.execute("""
        INSERT OR IGNORE INTO service_baseline
        (
            mac,
            port,
            protocol,
            created_at
        )
        VALUES (
            ?, ?, ?, datetime('now')
        )
    """, (
        mac,
        port,
        protocol,
    ))

    connection.commit()
    connection.close()

# =========================================================
# NETWORK / SITE TRACKING
# =========================================================

def get_or_create_network(
    network_cidr,
    gateway_ip,
    gateway_mac,
    ssid=None,
):
    """
    Return the database ID for the current network.

    Primary identity:
        subnet + gateway MAC

    Fallback identity:
        subnet + gateway IP

    SSID is stored as additional network context,
    but is not used as the sole identity because
    different networks may share the same SSID.
    """

    connection = get_connection()
    cursor = connection.cursor()

    network_cidr = str(
        network_cidr
    )

    normalized_gateway_mac = (
        gateway_mac.lower()
        if gateway_mac
        else None
    )

    normalized_ssid = (
        ssid.strip()
        if ssid
        else None
    )

    # =====================================================
    # BEST CASE:
    # Gateway MAC is available.
    # =====================================================

    if normalized_gateway_mac:

        cursor.execute("""
            SELECT
                id,
                display_name
            FROM networks
            WHERE network_cidr = ?
            AND gateway_mac = ?
        """, (
            network_cidr,
            normalized_gateway_mac,
        ))

        result = cursor.fetchone()

        if result:

            network_id = result[0]

            cursor.execute("""
                UPDATE networks
                SET gateway_ip = ?,
                    ssid = ?,
                    last_seen = datetime('now')
                WHERE id = ?
            """, (
                gateway_ip,
                normalized_ssid,
                network_id,
            ))

            connection.commit()
            connection.close()

            return network_id


        # -------------------------------------------------
        # UPGRADE OLD FALLBACK RECORD
        #
        # HomeSOC may previously have seen this network
        # before the gateway MAC was available.
        # -------------------------------------------------

        cursor.execute("""
            SELECT
                id,
                display_name
            FROM networks
            WHERE network_cidr = ?
            AND gateway_ip = ?
            AND gateway_mac IS NULL
            ORDER BY id ASC
            LIMIT 1
        """, (
            network_cidr,
            gateway_ip,
        ))

        result = cursor.fetchone()

        if result:

            network_id = result[0]

            cursor.execute("""
                UPDATE networks
                SET gateway_mac = ?,
                    ssid = ?,
                    last_seen = datetime('now')
                WHERE id = ?
            """, (
                normalized_gateway_mac,
                normalized_ssid,
                network_id,
            ))

            connection.commit()
            connection.close()

            return network_id


    # =====================================================
    # FALLBACK:
    # Gateway MAC unavailable.
    # =====================================================

    else:

        cursor.execute("""
            SELECT
                id,
                display_name
            FROM networks
            WHERE network_cidr = ?
            AND gateway_ip = ?
            ORDER BY
                CASE
                    WHEN gateway_mac IS NULL
                    THEN 0
                    ELSE 1
                END,
                id ASC
            LIMIT 1
        """, (
            network_cidr,
            gateway_ip,
        ))

        result = cursor.fetchone()

        if result:

            network_id = result[0]

            cursor.execute("""
                UPDATE networks
                SET ssid = ?,
                    last_seen = datetime('now')
                WHERE id = ?
            """, (
                normalized_ssid,
                network_id,
            ))

            connection.commit()
            connection.close()

            return network_id


    # =====================================================
    # NEW NETWORK
    # =====================================================

    default_display_name = (
        normalized_ssid
        if normalized_ssid
        else None
    )

    cursor.execute("""
        INSERT INTO networks (
            network_cidr,
            gateway_ip,
            gateway_mac,
            ssid,
            display_name,
            first_seen,
            last_seen
        )
        VALUES (
            ?, ?, ?, ?, ?,
            datetime('now'),
            datetime('now')
        )
    """, (
        network_cidr,
        gateway_ip,
        normalized_gateway_mac,
        normalized_ssid,
        default_display_name,
    ))

    network_id = cursor.lastrowid

    connection.commit()
    connection.close()

    return network_id


def save_network_device(
    network_id,
    ip,
    mac,
    state,
):
    """
    Associate a device with a specific network.
    """

    if not mac:
        return

    normalized_mac = mac.lower()

    connection = get_connection()
    cursor = connection.cursor()

    cursor.execute("""
        SELECT network_id
        FROM network_devices
        WHERE network_id = ?
        AND mac = ?
    """, (
        network_id,
        normalized_mac,
    ))

    result = cursor.fetchone()

    if result is None:

        cursor.execute("""
            INSERT INTO network_devices (
                network_id,
                mac,
                ip,
                state,
                first_seen,
                last_seen
            )
            VALUES (
                ?, ?, ?, ?,
                datetime('now'),
                datetime('now')
            )
        """, (
            network_id,
            normalized_mac,
            ip,
            state,
        ))

    else:

        cursor.execute("""
            UPDATE network_devices
            SET ip = ?,
                state = ?,
                last_seen = datetime('now')
            WHERE network_id = ?
            AND mac = ?
        """, (
            ip,
            state,
            network_id,
            normalized_mac,
        ))

    connection.commit()
    connection.close()


def set_active_network(network_id):
    """
    Store which network HomeSOC is currently monitoring.
    """

    connection = get_connection()
    cursor = connection.cursor()

    cursor.execute("""
        INSERT OR REPLACE INTO system_status (
            key,
            value
        )
        VALUES (
            'active_network_id',
            ?
        )
    """, (
        str(network_id),
    ))

    connection.commit()
    connection.close()


def get_active_network_id():
    """
    Return the network currently being monitored.
    """

    connection = get_connection()
    cursor = connection.cursor()

    cursor.execute("""
        SELECT value
        FROM system_status
        WHERE key = 'active_network_id'
    """)

    result = cursor.fetchone()

    connection.close()

    if result is None:
        return None

    return int(result[0])

    return True

def set_network_display_name(network_id, display_name):
    connection = get_connection()
    cursor = connection.cursor()

    cursor.execute("""
        UPDATE networks
        SET display_name = ?
        WHERE id = ?
    """, (
        display_name.strip(),
        network_id,
    ))

    connection.commit()
    connection.close()


def get_networks():
    connection = get_connection()
    cursor = connection.cursor()

    cursor.execute("""
        SELECT
            id,
            network_cidr,
            gateway_ip,
            gateway_mac,
            display_name,
            first_seen,
            last_seen
        FROM networks
        ORDER BY last_seen DESC
    """)

    networks = cursor.fetchall()

    connection.close()

    return networks

def get_network_devices(network_id):
    """
    Return devices previously seen on one specific network.
    """

    connection = get_connection()
    cursor = connection.cursor()

    cursor.execute("""
        SELECT
            ip,
            mac,
            state
        FROM network_devices
        WHERE network_id = ?
    """, (
        network_id,
    ))

    rows = cursor.fetchall()

    connection.close()

    return rows


def update_network_device_state(
    network_id,
    mac,
    state,
):
    """
    Update the availability state of a device
    on a specific network.
    """

    if not mac:
        return

    connection = get_connection()
    cursor = connection.cursor()

    cursor.execute("""
        UPDATE network_devices
        SET state = ?,
            last_seen = datetime('now')
        WHERE network_id = ?
        AND mac = ?
    """, (
        state,
        network_id,
        mac.lower(),
    ))

    connection.commit()
    connection.close()