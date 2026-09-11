SERVICE_RISK = {
    22: {
        "service": "SSH",
        "risk": "LOW",
        "description": "Secure remote administration service"
    },

    23: {
        "service": "TELNET",
        "risk": "HIGH",
        "description": "Unencrypted remote administration protocol"
    },

    53: {
        "service": "DNS",
        "risk": "INFO",
        "description": "Domain Name System service"
    },

    80: {
        "service": "HTTP",
        "risk": "MEDIUM",
        "description": "Unencrypted web service"
    },

    443: {
        "service": "HTTPS",
        "risk": "LOW",
        "description": "Encrypted web service"
    },

    554: {
        "service": "RTSP",
        "risk": "MEDIUM",
        "description": "Real Time Streaming Protocol, commonly used by IP cameras"
    },

    8000: {
        "service": "HTTP-ALT",
        "risk": "MEDIUM",
        "description": "Alternative HTTP service"
    },

    8080: {
        "service": "HTTP-ALT",
        "risk": "MEDIUM",
        "description": "Alternative HTTP service"
    },

    8443: {
        "service": "HTTPS-ALT",
        "risk": "LOW",
        "description": "Alternative HTTPS service"
    }
}


def get_contextual_risk(
    port,
    base_risk,
    device_type=None,
    is_gateway=False
):
    """
    Adjust service risk using device context.
    """

    # -------------------------
    # DEFAULT GATEWAY
    # -------------------------

    if is_gateway:

        if port == 53:
            return (
                "INFO",
                "Expected DNS service on the active network gateway"
            )

        if port == 80:
            return (
                "LOW",
                "Unencrypted gateway management interface"
            )

        if port == 443:
            return (
                "INFO",
                "Expected encrypted gateway management interface"
            )

    # -------------------------
    # CAMERA
    # -------------------------

    if device_type in (
        "IP_CAMERA",
        "POSSIBLE_CAMERA",
    ):

        if port == 554:
            return (
                "INFO",
                "RTSP is expected for a camera or video device"
            )

    # -------------------------
    # HOMESOC HOST
    # -------------------------

    if device_type == "HOMESOC_HOST":

        if port in (
            22,
            80,
            443,
            8000,
            8080,
            8443,
        ):
            return (
                "INFO",
                "Service detected on the HomeSOC monitoring host"
            )

    # -------------------------
    # TELNET
    # -------------------------

    if port == 23:
        return (
            "HIGH",
            "TELNET provides unencrypted remote administration"
        )

    # -------------------------
    # SSH
    # -------------------------

    if port == 22:

        if device_type in (
            "COMPUTER",
            "HOMESOC_HOST",
        ):
            return (
                "LOW",
                "SSH detected on a computer-like device"
            )

        return (
            "MEDIUM",
            "SSH detected on a device not identified as a computer"
        )

    # -------------------------
    # UNKNOWN DEVICE + RTSP
    # -------------------------

    if port == 554:

        return (
            "MEDIUM",
            "RTSP detected on a device not confirmed as a camera"
        )

    # -------------------------
    # ALTERNATE WEB SERVICES
    # -------------------------

    if port in (
        8000,
        8080,
    ):
        return (
            "MEDIUM",
            "Alternative unencrypted web service exposed"
        )

    if port == 8443:
        return (
            "LOW",
            "Alternative encrypted web service exposed"
        )

    # -------------------------
    # DEFAULT / BASE RISK
    # -------------------------

    return (
        base_risk,
        SERVICE_RISK[port]["description"]
    )


def analyze_service(
    ip,
    port,
    state,
    device_type=None,
    is_gateway=False
):

    if state != "OPEN":
        return None

    service = SERVICE_RISK.get(port)

    if service is None:
        return None

    risk, description = get_contextual_risk(
        port=port,
        base_risk=service["risk"],
        device_type=device_type,
        is_gateway=is_gateway,
    )

    return {
        "ip": ip,
        "port": port,
        "service": service["service"],
        "risk": risk,
        "description": description,
    }


def analyze_services(
    ip,
    service_results,
    device_type=None,
    is_gateway=False
):

    findings = []

    for port, state in service_results.items():

        finding = analyze_service(
            ip=ip,
            port=port,
            state="OPEN" if state else "CLOSED",
            device_type=device_type,
            is_gateway=is_gateway,
        )

        if finding:
            findings.append(finding)

    return findings