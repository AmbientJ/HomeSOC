def identify_device(
    service_results,
    vendor=None,
    hostname=None,
    ip=None,
    local_ip=None,
    default_gateway=None
):
    """
    Make an evidence-based estimate of device type using:

    - Open network services
    - MAC vendor
    - Hostname
    - Local HomeSOC host identity
    - Active default gateway

    Returns:
        {
            "device_type": str,
            "confidence": str,
            "evidence": list[str]
        }
    """

    open_ports = {
        port
        for port, is_open in service_results.items()
        if is_open
    }

    evidence = []

    vendor_text = (vendor or "").lower()
    hostname_text = (hostname or "").lower()

    # -------------------------
    # HOMESOC HOST
    # -------------------------

    if local_ip and ip == local_ip:

        evidence.append(
            "Device is the local HomeSOC monitoring host"
        )

        if hostname:
            evidence.append(
                f"Hostname: {hostname}"
            )

        return {
            "device_type": "HOMESOC_HOST",
            "confidence": "HIGH",
            "evidence": evidence,
        }

    # -------------------------
    # DEFAULT GATEWAY / ROUTER
    # -------------------------

    if default_gateway and ip == default_gateway:

        evidence.append(
            "Device is the active IPv4 default gateway"
        )

        if 53 in open_ports:
            evidence.append(
                "DNS detected on TCP/53"
            )

        if 80 in open_ports:
            evidence.append(
                "HTTP management detected on TCP/80"
            )

        if 443 in open_ports:
            evidence.append(
                "HTTPS management detected on TCP/443"
            )

        if vendor:
            evidence.append(
                f"Vendor: {vendor}"
            )

        return {
            "device_type": "ROUTER_OR_GATEWAY",
            "confidence": "HIGH",
            "evidence": evidence,
        }

    # -------------------------
    # CAMERA / VIDEO DEVICE
    # -------------------------

    if 554 in open_ports:

        evidence.append(
            "RTSP detected on TCP/554"
        )

        if (
            "anker" in vendor_text
            or "eufy" in vendor_text
        ):
            evidence.append(
                f"Vendor associated with camera/IoT equipment: {vendor}"
            )

            return {
                "device_type": "IP_CAMERA",
                "confidence": "HIGH",
                "evidence": evidence,
            }

        return {
            "device_type": "POSSIBLE_CAMERA",
            "confidence": "MEDIUM",
            "evidence": evidence,
        }

    # -------------------------
    # ROKU / STREAMING DEVICE
    # -------------------------

    if "roku" in vendor_text:

        evidence.append(
            f"Streaming-device vendor detected: {vendor}"
        )

        if hostname:
            evidence.append(
                f"Hostname detected: {hostname}"
            )

        return {
            "device_type": "MEDIA_STREAMING_DEVICE",
            "confidence": "HIGH",
            "evidence": evidence,
        }

    # -------------------------
    # COMPUTER-LIKE HOSTNAME
    # -------------------------

    computer_hostname_terms = (
        "desktop",
        "laptop",
        "pc",
        "workstation",
        "homedesk",
    )

    if any(
        term in hostname_text
        for term in computer_hostname_terms
    ):

        evidence.append(
            f"Computer-like hostname detected: {hostname}"
        )

        if vendor:
            evidence.append(
                f"Vendor: {vendor}"
            )

        return {
            "device_type": "COMPUTER",
            "confidence": "HIGH",
            "evidence": evidence,
        }

    # -------------------------
    # ROUTER / GATEWAY HEURISTIC
    # -------------------------

    if (
        53 in open_ports
        and (
            80 in open_ports
            or 443 in open_ports
        )
    ):

        evidence.append(
            "DNS service detected on TCP/53"
        )

        if 80 in open_ports:
            evidence.append(
                "HTTP management detected on TCP/80"
            )

        if 443 in open_ports:
            evidence.append(
                "HTTPS management detected on TCP/443"
            )

        return {
            "device_type": "ROUTER_OR_GATEWAY",
            "confidence": "MEDIUM",
            "evidence": evidence,
        }

    # -------------------------
    # WINDOWS / PC VENDOR
    # -------------------------

    if (
        "intel" in vendor_text
        or "dell" in vendor_text
        or "lenovo" in vendor_text
        or "hewlett" in vendor_text
        or vendor_text.startswith("hp ")
    ):

        evidence.append(
            f"Computer-related vendor detected: {vendor}"
        )

        if hostname:
            evidence.append(
                f"Hostname detected: {hostname}"
            )

        return {
            "device_type": "COMPUTER",
            "confidence": "MEDIUM",
            "evidence": evidence,
        }

    # -------------------------
    # APPLE DEVICE
    # -------------------------

    if "apple" in vendor_text:

        evidence.append(
            f"Apple vendor detected: {vendor}"
        )

        if hostname:
            evidence.append(
                f"Hostname detected: {hostname}"
            )

        return {
            "device_type": "APPLE_DEVICE",
            "confidence": "MEDIUM",
            "evidence": evidence,
        }

    # -------------------------
    # SAMSUNG DEVICE
    # -------------------------

    if "samsung" in vendor_text:

        evidence.append(
            f"Samsung vendor detected: {vendor}"
        )

        if hostname:
            evidence.append(
                f"Hostname detected: {hostname}"
            )

        return {
            "device_type": "SAMSUNG_DEVICE",
            "confidence": "LOW",
            "evidence": evidence,
        }

    # -------------------------
    # WEB-MANAGED DEVICE
    # -------------------------

    if 80 in open_ports or 443 in open_ports:

        if 80 in open_ports:
            evidence.append(
                "HTTP detected on TCP/80"
            )

        if 443 in open_ports:
            evidence.append(
                "HTTPS detected on TCP/443"
            )

        if vendor:
            evidence.append(
                f"Vendor: {vendor}"
            )

        return {
            "device_type": "WEB_MANAGED_DEVICE",
            "confidence": "LOW",
            "evidence": evidence,
        }

    # -------------------------
    # SSH-ENABLED DEVICE
    # -------------------------

    if 22 in open_ports:

        evidence.append(
            "SSH detected on TCP/22"
        )

        if vendor:
            evidence.append(
                f"Vendor: {vendor}"
            )

        return {
            "device_type": "SSH_ENABLED_DEVICE",
            "confidence": "LOW",
            "evidence": evidence,
        }

    # -------------------------
    # PRIVATE / RANDOMIZED MAC
    # -------------------------

    if vendor == "LOCAL / PRIVATE MAC":

        evidence.append(
            "Locally administered or randomized MAC address"
        )

        if hostname:
            evidence.append(
                f"Hostname detected: {hostname}"
            )

        return {
            "device_type": "PRIVATE_CLIENT_DEVICE",
            "confidence": "LOW",
            "evidence": evidence,
        }

    # -------------------------
    # GENERIC VENDOR DEVICE
    # -------------------------

    if vendor and vendor not in (
        "UNKNOWN VENDOR",
        "LOOKUP ERROR",
    ):

        evidence.append(
            f"Vendor identified as {vendor}"
        )

        if hostname:
            evidence.append(
                f"Hostname detected: {hostname}"
            )

        return {
            "device_type": "VENDOR_IDENTIFIED_DEVICE",
            "confidence": "LOW",
            "evidence": evidence,
        }

    # -------------------------
    # UNKNOWN
    # -------------------------

    if hostname:
        evidence.append(
            f"Hostname detected: {hostname}"
        )

    return {
        "device_type": "UNKNOWN",
        "confidence": "LOW",
        "evidence": evidence,
    }