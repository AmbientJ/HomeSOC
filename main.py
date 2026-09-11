import socket
import time

from database.database import (
    initialize_database,
    save_device,
    save_service,
    save_event,
    save_event_once,
    get_all_devices,
    update_device_state,
    save_security_alert,
    resolve_missing_alerts,
    save_device_profile,
    record_last_scan,
    save_device_metadata,
    save_device_security_alert,
    get_baseline_ports,
    baseline_exists,
    get_or_create_network,
    save_network_device,
    set_active_network,
    get_network_devices,
    update_network_device_state,
)

from logger import logger

from discovery.network import (
    get_local_network,
    discover_ping_devices,
    discover_arp_devices,
    resolve_hostname,
)

from inventory.inventory import build_inventory
from events.events import (
    check_device_identity,
    analyze_device_trust,
)
from services.scanner import scan_ports
from security.risk import analyze_services
from identification.device_id import identify_device
from identification.vendor import lookup_vendor


from config import (
    SCAN_INTERVAL,
    OFFLINE_THRESHOLD,
    SERVICE_CLOSE_THRESHOLD,
    MONITORED_PORTS,
)

offline_counts = {}

service_close_counts = {}

def run_scan(progress_callback=None):

    def set_progress(percent, stage):
        if progress_callback:
            progress_callback(
                percent,
                stage,
            )

    initialize_database()

    logger.info("Scan started")

    set_progress(
        2,
        "Initializing HomeSOC..."
    )

    devices = {}

    active_device_findings = set()
    scanned_service_ips = set()

    set_progress(
        10,
        "Detecting local network..."
    )

    (
        hostname,
        local_ip,
        local_mac,
        default_gateway,
        network,
        ssid,
    ) = get_local_network()

    logger.info(
        f"Network detected: {network} | "
        f"Local IP: {local_ip} | "
        f"Gateway: {default_gateway}"
    )

    print("Home Security Operations Center")
    print("--------------------------------")
    print(f"Hostname: {hostname}")
    print(f"Local IP: {local_ip}")
    print(f"Local MAC: {local_mac or 'Unavailable'}")
    print(f"Gateway: {default_gateway or 'Unavailable'}")
    print(f"Network: {network}")

    print()
    print("Network Discovery")
    print("-----------------")

    set_progress(
        20,
        "Discovering devices..."
    )

    ping_results = discover_ping_devices(network)

    for ip in ping_results:
        print(f"Device responding: {ip}")

    set_progress(
        40,
        "Reading ARP table..."
    )

    arp_devices = discover_arp_devices(network)
    gateway_mac = arp_devices.get(default_gateway)

    set_progress(
        50,
        "Identifying current network..."
    )

    network_id = get_or_create_network(
        network_cidr=str(network),
        gateway_ip=default_gateway,
        gateway_mac=gateway_mac,
        ssid=ssid,
    )

    set_active_network(network_id)

    print(f"Network ID: {network_id}")
    print(f"Gateway MAC: {gateway_mac or 'Unavailable'}")

    historical_devices = get_network_devices(
        network_id
    )

    print()
    print("Device Inventory")
    print("----------------")

    set_progress(
        60,
        "Building device inventory..."
    )

    devices = build_inventory(
        ping_results,
        arp_devices,
    )

    if local_ip not in devices:

        devices[local_ip] = {
            "mac": local_mac,
            "ping": True,
            "state": "ONLINE",
        }

    else:

        devices[local_ip]["mac"] = local_mac
        devices[local_ip]["state"] = "ONLINE"

    # =====================================================
    # DEVICE AVAILABILITY MONITORING
    # =====================================================

    historical = {}

    for ip, mac, state in historical_devices:

        historical[ip] = {
            "mac": mac,
            "state": state,
        }

    current_ips = set(devices.keys())

    for ip, info in historical.items():

        # -------------------------
        # DEVICE MISSING
        # -------------------------

        if ip not in current_ips:

            offline_counts[ip] = (
                offline_counts.get(ip, 0) + 1
            )

            print(
                f"Device missing: {ip} "
                f"(missed scan "
                f"{offline_counts[ip]}/"
                f"{OFFLINE_THRESHOLD})"
            )

            if (
                info["state"] == "ONLINE"
                and offline_counts[ip]
                >= OFFLINE_THRESHOLD
            ):

                print()
                print(f"DEVICE OFFLINE: {ip}")

                logger.warning(
                    f"Device offline: {ip} | "
                    f"MAC: {info['mac']}"
                )

                update_device_state(
                    ip,
                    "OFFLINE",
                )

                update_network_device_state(
                    network_id,
                    info["mac"],
                    "OFFLINE",
                )

                save_event(
                    "DEVICE_OFFLINE",
                    ip=ip,
                    mac=info["mac"],
                    description=(
                        f"Device {ip} has been offline "
                        f"for {OFFLINE_THRESHOLD} scans"
                    ),
                )

        # -------------------------
        # DEVICE PRESENT
        # -------------------------

        else:

            if info["state"] == "OFFLINE":

                print()
                print(f"DEVICE ONLINE: {ip}")

                logger.info(
                    f"Device returned online: {ip}"
                )

                update_device_state(
                    ip,
                    "ONLINE",
                )

                update_network_device_state(
                    network_id,
                    info["mac"],
                    "ONLINE",
                )

                save_event(
                    "DEVICE_ONLINE",
                    ip=ip,
                    mac=devices[ip]["mac"],
                    description=(
                        f"Device {ip} returned "
                        f"to the network"
                    ),
                )

            offline_counts[ip] = 0

    # =====================================================
    # DEVICE INVENTORY / IDENTITY / TRUST
    # =====================================================

    set_progress(
        70,
        "Analyzing devices..."
    )

    for ip in devices:

        # -------------------------
        # HOSTNAME
        # -------------------------

        if ip == local_ip:

            discovered_hostname = hostname

        else:

            discovered_hostname = resolve_hostname(ip)

        # -------------------------
        # DEVICE IDENTITY
        # -------------------------

        identity_status = check_device_identity(
            devices[ip]["mac"],
            ip,
        )

        # -------------------------
        # DEVICE TRUST ANALYSIS
        # -------------------------

        trust_finding = analyze_device_trust(
            mac=devices[ip]["mac"],
            ip=ip,
            identity_status=identity_status,
        )

        if trust_finding is not None:

            event_created = save_event_once(
                trust_finding["event_type"],
                ip=ip,
                mac=devices[ip]["mac"],
                description=(
                    trust_finding["description"]
                ),
            )

            alert_status = (
                save_device_security_alert(
                    ip=ip,
                    mac=devices[ip]["mac"],
                    event_type=(
                        trust_finding["event_type"]
                    ),
                    risk=trust_finding["risk"],
                    description=(
                        trust_finding["description"]
                    ),
                )
            )

            active_device_findings.add(
                (
                    devices[ip]["mac"],
                    trust_finding["event_type"],
                )
            )

            logger.warning(
                f"Device security finding: "
                f"{trust_finding['event_type']} | "
                f"{ip} | "
                f"Risk: {trust_finding['risk']}"
            )

            if event_created:

                print(
                    f"NEW DEVICE SECURITY EVENT: "
                    f"{trust_finding['event_type']} | "
                    f"Risk: "
                    f"{trust_finding['risk']} | "
                    f"{ip}"
                )

            else:

                print(
                    f"DEVICE SECURITY CONDITION ACTIVE: "
                    f"{trust_finding['event_type']} | "
                    f"{ip}"
                )

        # -------------------------
        # SAVE DEVICE
        # -------------------------

        save_device(
            ip,
            devices[ip]["mac"],
            devices[ip]["state"],
        )

        save_network_device(
            network_id=network_id,
            ip=ip,
            mac=devices[ip]["mac"],
            state=devices[ip]["state"],
        )

        # -------------------------
        # VENDOR LOOKUP
        # -------------------------

        vendor_info = lookup_vendor(
            devices[ip]["mac"]
        )

        # -------------------------
        # SAVE DEVICE METADATA
        # -------------------------

        if devices[ip]["mac"]:

            save_device_metadata(
                mac=devices[ip]["mac"],
                hostname=discovered_hostname,
                vendor=vendor_info["vendor"],
            )

        # -------------------------
        # PRINT INVENTORY
        # -------------------------

        print(
            f"{ip} | "
            f"MAC: {devices[ip]['mac']} | "
            f"Hostname: "
            f"{discovered_hostname or 'Unknown'} | "
            f"Vendor: "
            f"{vendor_info['vendor'] or 'Unknown'} | "
            f"State: {devices[ip]['state']}"
        )

        # -------------------------
        # NEW DEVICE EVENT
        # -------------------------

        if identity_status == "NEW":

            print(
                f"NEW DEVICE DETECTED: {ip}"
            )

            logger.info(
                f"New device detected: "
                f"{ip} | "
                f"{devices[ip]['mac']}"
            )

            save_event(
                "NEW_DEVICE",
                ip=ip,
                mac=devices[ip]["mac"],
                description=(
                    f"New device detected at {ip}"
                ),
            )

        # -------------------------
        # IP CHANGE EVENT
        # -------------------------

        elif identity_status == "IP_CHANGED":

            print(
                f"KNOWN DEVICE CHANGED IP: {ip}"
            )

            logger.info(
                f"Known device changed IP: "
                f"{devices[ip]['mac']} -> {ip}"
            )

            save_event(
                "IP_CHANGED",
                ip=ip,
                mac=devices[ip]["mac"],
                description=(
                    f"Known device changed IP to {ip}"
                ),
            )

    # =====================================================
    # SERVICE DISCOVERY
    # =====================================================

    print()
    print("Service Discovery")
    print("-----------------")

    active_findings = set()

    ports = MONITORED_PORTS

    online_ips = [
        ip
        for ip in devices
        if devices[ip]["state"] == "ONLINE"
    ]

    total_online = len(online_ips)

    for index, ip in enumerate(
        online_ips,
        start=1,
    ):  

        if total_online > 0:

            progress = 80 + int(
                (index - 1)
                / total_online
                * 12
            )

        else:

            progress = 80

        set_progress(
            progress,
            (
                f"Scanning device services "
                f"({index}/{total_online})..."
            ),
        )
    
        print()
        print(f"Scanning services on {ip}")

        # -------------------------
        # PORT SCAN
        # -------------------------

        service_results = scan_ports(
            ip,
            ports,
        )

        # -------------------------
        # BASELINE SERVICE RETRY
        # -------------------------

        mac = devices[ip]["mac"]

        if (
            mac
            and baseline_exists(mac)
        ):

            expected_ports = get_baseline_ports(
                mac
            )

            missing_expected_ports = [
                port
                for port in expected_ports
                if not service_results.get(
                    port,
                    False
                )
            ]

            if missing_expected_ports:

                print(
                    f"Rechecking expected services "
                    f"on {ip}: "
                    f"{sorted(missing_expected_ports)}"
                )

                retry_results = scan_ports(
                    ip,
                    missing_expected_ports,
                )

                for (
                    port,
                    is_open
                ) in retry_results.items():

                    if is_open:

                        service_results[port] = True

        # -------------------------
        # SERVICE SCAN CONFIDENCE
        # -------------------------

        service_scan_reliable = True

        if (
            mac
            and baseline_exists(mac)
        ):

            expected_ports = get_baseline_ports(
                mac
            )

            still_missing_expected = [
                port
                for port in expected_ports
                if not service_results.get(
                    port,
                    False
                )
            ]

            # If expected services are unexpectedly
            # missing, do not use this scan to resolve
            # existing security alerts.
            if still_missing_expected:

                service_scan_reliable = False

                print(
                    f"Service scan uncertain on {ip}: "
                    f"expected ports still missing "
                    f"{sorted(still_missing_expected)}"
                )

        if service_scan_reliable:
            scanned_service_ips.add(ip)

        # -------------------------
        # HOSTNAME
        # -------------------------

        if ip == local_ip:

            discovered_hostname = hostname

        else:

            discovered_hostname = (
                resolve_hostname(ip)
            )

        # -------------------------
        # VENDOR
        # -------------------------

        vendor_info = lookup_vendor(
            devices[ip]["mac"]
        )

        # -------------------------
        # DEVICE IDENTIFICATION
        # -------------------------

        device_info = identify_device(
            service_results=service_results,
            vendor=vendor_info["vendor"],
            hostname=discovered_hostname,
            ip=ip,
            local_ip=local_ip,
            default_gateway=default_gateway,
        )

        mac = devices[ip]["mac"]

        if mac:

            evidence_text = "; ".join(
                device_info["evidence"]
            )

            save_device_profile(
                mac,
                ip,
                device_info["device_type"],
                device_info["confidence"],
                evidence_text,
            )

        print()
        print("Device Identification")

        print(
            f"  Type: "
            f"{device_info['device_type']}"
        )

        print(
            f"  Confidence: "
            f"{device_info['confidence']}"
        )

        for evidence_item in (
            device_info["evidence"]
        ):

            print(
                f"  Evidence: "
                f"{evidence_item}"
            )

        # =================================================
        # SECURITY ANALYSIS
        # =================================================

        security_findings = analyze_services(
            ip=ip,
            service_results=service_results,
            device_type=(
                device_info["device_type"]
            ),
            is_gateway=(
                ip == default_gateway
            ),
        )

        if security_findings:

            print()
            print("Security Analysis")

            for finding in security_findings:

                print(
                    f"  Port "
                    f"{finding['port']} | "
                    f"{finding['service']} | "
                    f"Risk: {finding['risk']}"
                )

                # INFO findings are observations only.
                if finding["risk"] == "INFO":
                    continue

                active_findings.add(
                    (
                        ip,
                        finding["port"],
                        finding["service"],
                    )
                )

                alert_status = save_security_alert(
                    ip=ip,
                    mac=devices[ip]["mac"],
                    port=finding["port"],
                    service=finding["service"],
                    risk=finding["risk"],
                    description=(
                        finding["description"]
                    ),
                )

                if alert_status == "NEW":

                    print(
                        f"  NEW SECURITY ALERT: "
                        f"{finding['service']} "
                        f"on "
                        f"{ip}:{finding['port']}"
                    )

                    logger.warning(
                        f"New security alert: "
                        f"{finding['service']} | "
                        f"{ip}:{finding['port']} | "
                        f"Risk: {finding['risk']}"
                    )

                    save_event(
                        "SECURITY_ALERT",
                        ip=ip,
                        mac=devices[ip]["mac"],
                        port=finding["port"],
                        description=(
                            f"{finding['risk']} "
                            f"security finding: "
                            f"{finding['service']} "
                            f"detected on "
                            f"{ip}:{finding['port']}"
                        ),
                    )

        # =================================================
        # BASELINE ANOMALY DETECTION
        # =================================================

        mac = devices[ip]["mac"]

        current_open_ports = {
            port
            for port, is_open
            in service_results.items()
            if is_open
        }

        if (
            mac
            and baseline_exists(mac)
        ):

            expected_open_ports = (
                get_baseline_ports(mac)
            )

            unexpected_ports = (
                current_open_ports
                - expected_open_ports
            )

            for unexpected_port in (
                unexpected_ports
            ):

                if unexpected_port == 23:

                    anomaly_risk = "HIGH"

                else:

                    anomaly_risk = "MEDIUM"

                anomaly_service = (
                    "UNEXPECTED_SERVICE"
                )

                print(
                    f"BASELINE ANOMALY: "
                    f"Unexpected "
                    f"TCP/{unexpected_port} "
                    f"opened on {ip}"
                )

                logger.warning(
                    f"Baseline anomaly: "
                    f"{ip}:{unexpected_port} | "
                    f"Risk: {anomaly_risk}"
                )

                active_findings.add(
                    (
                        ip,
                        unexpected_port,
                        anomaly_service,
                    )
                )

                alert_status = save_security_alert(
                    ip=ip,
                    mac=mac,
                    port=unexpected_port,
                    service=anomaly_service,
                    risk=anomaly_risk,
                    description=(
                        f"TCP/{unexpected_port} "
                        f"is open but is not "
                        f"present in the approved "
                        f"service baseline"
                    ),
                )

                if alert_status == "NEW":

                    save_event(
                        "BASELINE_ANOMALY",
                        ip=ip,
                        mac=mac,
                        port=unexpected_port,
                        description=(
                            f"Unexpected TCP "
                            f"service opened on "
                            f"port "
                            f"{unexpected_port}"
                        ),
                    )

        # =================================================
        # SERVICE STATE TRACKING
        # =================================================

        # =================================================
        # SERVICE STATE TRACKING
        # =================================================

        for port, is_open in service_results.items():

            if is_open:

                service_close_counts[(ip, port)] = 0
                state = "OPEN"

                print(
                    f"Port {port}: OPEN"
                )

            else:

                service_key = (ip, port)

                service_close_counts[service_key] = (
                    service_close_counts.get(
                        service_key,
                        0
                    ) + 1
                )

                missed_count = (
                    service_close_counts[service_key]
                )

                # Baseline services require confirmation
                # before HomeSOC accepts them as CLOSED.
                if (
                    mac
                    and baseline_exists(mac)
                    and port in get_baseline_ports(mac)
                    and missed_count < SERVICE_CLOSE_THRESHOLD
                ):

                    print(
                        f"Port {port}: CLOSED? "
                        f"(confirmation "
                        f"{missed_count}/"
                        f"{SERVICE_CLOSE_THRESHOLD})"
                    )

                    continue

                state = "CLOSED"

                print(
                    f"Port {port}: CLOSED"
                )

            service_status = save_service(
                ip,
                port,
                "TCP",
                state,
            )

            # -------------------------
            # NEW SERVICE
            # -------------------------

            if service_status == "NEW":

                print(
                    f"NEW SERVICE OBSERVED: "
                    f"{ip}:{port} "
                    f"({state})"
                )

                save_event(
                    "NEW_SERVICE",
                    ip=ip,
                    port=port,
                    description=(
                        f"New TCP service "
                        f"observed on "
                        f"port {port}"
                    ),
                )

            # -------------------------
            # SERVICE OPENED
            # -------------------------

            elif service_status == "OPENED":

                print(
                    f"SERVICE OPENED: "
                    f"{ip}:{port}"
                )

                logger.info(
                    f"Service opened: "
                    f"{ip}:{port}/TCP"
                )

                save_event(
                    "SERVICE_OPENED",
                    ip=ip,
                    port=port,
                    description=(
                        f"TCP service opened "
                        f"on port {port}"
                    ),
                )

            # -------------------------
            # SERVICE CLOSED
            # -------------------------

            elif service_status == "CLOSED":

                print(
                    f"SERVICE CLOSED: "
                    f"{ip}:{port}"
                )

                logger.info(
                    f"Service closed: "
                    f"{ip}:{port}/TCP"
                )

                save_event(
                    "SERVICE_CLOSED",
                    ip=ip,
                    port=port,
                    description=(
                        f"TCP service closed "
                        f"on port {port}"
                    ),
                )
    # =====================================================
    # RESOLVE MISSING ALERTS
    # =====================================================

    set_progress(
        92,
        "Processing security findings..."
    )

    resolved_alerts = resolve_missing_alerts(
    active_findings,
    active_device_findings,
    scanned_service_ips,
    )

    for alert in resolved_alerts:

        print(
            f"SECURITY ALERT RESOLVED: "
            f"{alert['service']} "
            f"on "
            f"{alert['ip']}:"
            f"{alert['port']}"
        )

        logger.info(
            f"Security alert resolved: "
            f"{alert['service']} | "
            f"{alert['ip']}:"
            f"{alert['port']}"
        )

        save_event(
            "ALERT_RESOLVED",
            ip=alert["ip"],
            port=alert["port"],
            description=(
                f"{alert['service']} "
                f"security finding "
                f"resolved on "
                f"{alert['ip']}:"
                f"{alert['port']}"
            ),
        )

    record_last_scan()

    logger.info(
        "Scan completed successfully"
    )

    print()
    print("Scan completed successfully.")

    set_progress(
    100,
    "Scan complete"
    )

logger.info("Scan completed")

if __name__ == "__main__":
    run_scan()