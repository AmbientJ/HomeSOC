from database.database import get_connection


def check_device_identity(mac, ip):
    """
    Track a device by MAC address and detect IP changes.

    Returns:
        NEW
        IP_CHANGED
        KNOWN
        UNKNOWN
    """

    if not mac:
        return "UNKNOWN"

    connection = get_connection()
    cursor = connection.cursor()

    cursor.execute("""
        SELECT current_ip
        FROM device_identity
        WHERE mac = ?
    """, (mac,))

    result = cursor.fetchone()

    # -------------------------
    # NEW DEVICE IDENTITY
    # -------------------------

    if result is None:

        cursor.execute("""
            INSERT INTO device_identity
            (
                mac,
                first_ip,
                current_ip,
                first_seen,
                last_seen
            )
            VALUES (
                ?,
                ?,
                ?,
                datetime('now'),
                datetime('now')
            )
        """, (
            mac,
            ip,
            ip,
        ))

        connection.commit()
        connection.close()

        return "NEW"

    # -------------------------
    # EXISTING DEVICE
    # -------------------------

    previous_ip = result[0]

    cursor.execute("""
        UPDATE device_identity
        SET
            current_ip = ?,
            last_seen = datetime('now')
        WHERE mac = ?
    """, (
        ip,
        mac,
    ))

    connection.commit()
    connection.close()

    # -------------------------
    # IP CHANGE
    # -------------------------

    if previous_ip != ip:
        return "IP_CHANGED"

    return "KNOWN"


def get_device_trust_status(mac):
    """
    Return the user's trust classification for a device.

    Expected values:

        TRUSTED
        UNREVIEWED
        SUSPICIOUS

    Devices without an explicit classification are
    treated as UNREVIEWED.
    """

    if not mac:
        return "UNREVIEWED"

    connection = get_connection()
    cursor = connection.cursor()

    cursor.execute("""
        SELECT trust_status
        FROM device_preferences
        WHERE mac = ?
    """, (mac,))

    result = cursor.fetchone()

    connection.close()

    if result is None:
        return "UNREVIEWED"

    trust_status = result[0]

    if not trust_status:
        return "UNREVIEWED"

    return trust_status.upper()


def analyze_device_trust(
    mac,
    ip,
    identity_status,
):
    """
    Analyze a device using both identity state and
    user-assigned trust status.

    Returns None when no security finding is needed.

    Otherwise returns:

        {
            "event_type": str,
            "risk": str,
            "description": str,
            "trust_status": str
        }
    """

    trust_status = get_device_trust_status(mac)

    # -------------------------
    # SUSPICIOUS DEVICE
    # -------------------------

    if trust_status == "SUSPICIOUS":

        return {
            "event_type": "SUSPICIOUS_DEVICE_ONLINE",
            "risk": "HIGH",
            "description": (
                f"Device marked SUSPICIOUS is present "
                f"on the network at {ip}"
            ),
            "trust_status": trust_status,
        }

    # -------------------------
    # NEW + UNREVIEWED DEVICE
    # -------------------------

    if (
        identity_status == "NEW"
        and trust_status == "UNREVIEWED"
    ):

        return {
            "event_type": "UNREVIEWED_DEVICE",
            "risk": "MEDIUM",
            "description": (
                f"New unreviewed device detected "
                f"at {ip}"
            ),
            "trust_status": trust_status,
        }

    # -------------------------
    # TRUSTED DEVICE
    # -------------------------

    if trust_status == "TRUSTED":

        return None

    # -------------------------
    # NO SECURITY FINDING
    # -------------------------

    return None