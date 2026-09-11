import socket
import ipaddress
import subprocess
import re

from concurrent.futures import ThreadPoolExecutor, as_completed

import psutil


# Maximum number of hosts HomeSOC will automatically scan.
# This prevents accidental scans of very large networks.
MAX_SCAN_HOSTS = 1024


def get_primary_local_ip():
    """
    Determine the IPv4 address currently being used
    for the computer's primary network route.
    """

    sock = socket.socket(
        socket.AF_INET,
        socket.SOCK_DGRAM
    )

    try:
        # This does not establish a real connection.
        # It allows the OS to choose the preferred route.
        sock.connect(("8.8.8.8", 80))

        local_ip = sock.getsockname()[0]

    except OSError:
        local_ip = socket.gethostbyname(
            socket.gethostname()
        )

    finally:
        sock.close()

    return local_ip


def get_subnet_mask(local_ip):
    """
    Find the subnet mask assigned to the interface
    containing the active local IPv4 address.
    """

    interfaces = psutil.net_if_addrs()

    for interface_name, addresses in interfaces.items():

        for address in addresses:

            if (
                address.family == socket.AF_INET
                and address.address == local_ip
            ):

                if address.netmask:
                    return address.netmask

    raise RuntimeError(
        f"Unable to determine subnet mask for {local_ip}"
    )


def validate_local_ip(local_ip):
    """
    Make sure HomeSOC detected a usable LAN address.
    """

    ip_address = ipaddress.ip_address(local_ip)

    if ip_address.is_loopback:
        raise RuntimeError(
            f"HomeSOC detected loopback address {local_ip}. "
            "No usable LAN interface was found."
        )

    if ip_address.is_link_local:
        raise RuntimeError(
            f"HomeSOC detected link-local address {local_ip}. "
            "The computer may not have a valid network connection."
        )

    if ip_address.is_multicast:
        raise RuntimeError(
            f"Invalid multicast address detected: {local_ip}"
        )
    
def get_local_mac(local_ip):
    """
    Find the MAC address for the interface
    that owns the active local IPv4 address.
    """

    interfaces = psutil.net_if_addrs()

    for interface_name, addresses in interfaces.items():

        has_local_ip = any(
            address.family == socket.AF_INET
            and address.address == local_ip
            for address in addresses
        )

        if not has_local_ip:
            continue

        for address in addresses:

            if address.family == psutil.AF_LINK:

                if address.address:

                    mac = address.address.lower()
                    mac = mac.replace(":", "-")

                    if mac != "00-00-00-00-00-00":
                        return mac

    return None

def get_default_gateway(local_ip):
    """
    Determine the active IPv4 default gateway on Windows.
    """

    creation_flags = 0

    if hasattr(subprocess, "CREATE_NO_WINDOW"):
        creation_flags = subprocess.CREATE_NO_WINDOW

    result = subprocess.run(
        ["route", "print", "-4"],
        capture_output=True,
        text=True,
        errors="ignore",
        creationflags=creation_flags,
    )

    candidates = []

    for line in result.stdout.splitlines():

        parts = line.split()

        if len(parts) < 5:
            continue

        if (
            parts[0] == "0.0.0.0"
            and parts[1] == "0.0.0.0"
        ):

            gateway = parts[2]
            interface_ip = parts[3]

            try:
                metric = int(parts[4])
            except ValueError:
                metric = 999999

            if interface_ip == local_ip:
                candidates.append(
                    (metric, gateway)
                )

    if not candidates:
        return None

    candidates.sort(
        key=lambda item: item[0]
    )

    return candidates[0][1]

def get_wifi_ssid():
    """
    Return the currently connected Wi-Fi SSID on Windows.

    Returns None if:
    - the computer is not using Wi-Fi
    - no SSID is available
    - the command fails
    """

    creation_flags = 0

    if hasattr(subprocess, "CREATE_NO_WINDOW"):
        creation_flags = subprocess.CREATE_NO_WINDOW

    try:

        result = subprocess.run(
            [
                "netsh",
                "wlan",
                "show",
                "interfaces",
            ],
            capture_output=True,
            text=True,
            errors="ignore",
            creationflags=creation_flags,
        )

    except OSError:
        return None

    for line in result.stdout.splitlines():

        stripped = line.strip()

        if (
            stripped.startswith("SSID")
            and not stripped.startswith("BSSID")
        ):

            parts = stripped.split(
                ":",
                1,
            )

            if len(parts) == 2:

                ssid = parts[1].strip()

                if ssid:
                    return ssid

    return None

def get_local_network():
    """
    Determine hostname, active IPv4 address,
    subnet mask, and connected IPv4 network.
    """

    hostname = socket.gethostname()

    local_ip = get_primary_local_ip()

    validate_local_ip(local_ip)

    subnet_mask = get_subnet_mask(
        local_ip
    )

    local_mac = get_local_mac(local_ip)

    default_gateway = get_default_gateway(
        local_ip
    )

    ssid = get_wifi_ssid()

    network = ipaddress.ip_network(
        f"{local_ip}/{subnet_mask}",
        strict=False
    )

    return (
        hostname,
        local_ip,
        local_mac,
        default_gateway,
        network,
        ssid,
    )


def validate_scan_scope(network):
    """
    Prevent HomeSOC from automatically scanning
    unexpectedly large networks.
    """

    host_count = max(
        network.num_addresses - 2,
        0
    )

    if host_count > MAX_SCAN_HOSTS:

        raise RuntimeError(
            f"Detected network {network} contains "
            f"{host_count} possible hosts. "
            f"HomeSOC automatic scanning is limited to "
            f"{MAX_SCAN_HOSTS} hosts for safety."
        )

    return host_count


def ping_device(ip):
    """
    Ping a host once.

    Windows ping.exe exit codes alone are not reliable
    enough for host discovery, so HomeSOC verifies that
    the response contains TTL=.

    CREATE_NO_WINDOW prevents ping.exe from opening
    console windows in the packaged GUI application.
    """

    creation_flags = 0

    if hasattr(subprocess, "CREATE_NO_WINDOW"):
        creation_flags = subprocess.CREATE_NO_WINDOW

    result = subprocess.run(
        [
            "ping",
            "-4",
            "-n", "1",
            "-w", "500",
            ip,
        ],
        capture_output=True,
        text=True,
        errors="ignore",
        creationflags=creation_flags,
    )

    output = result.stdout.upper()

    return "TTL=" in output


from concurrent.futures import ThreadPoolExecutor, as_completed


def discover_ping_devices(network):
    """
    Ping hosts concurrently so LAN discovery completes
    much faster than scanning every address sequentially.
    """

    validate_scan_scope(network)

    hosts = [str(host) for host in network.hosts()]
    total = len(hosts)

    ping_results = {}

    # 32 parallel workers is reasonable for a small LAN.
    max_workers = min(32, total)

    with ThreadPoolExecutor(
        max_workers=max_workers
    ) as executor:

        futures = {
            executor.submit(ping_device, ip): ip
            for ip in hosts
        }

        completed = 0

        for future in as_completed(futures):

            ip = futures[future]
            completed += 1

            print(
                f"Scanning {completed}/{total}",
                end="\r"
            )

            try:
                if future.result():
                    ping_results[ip] = True

            except Exception as error:
                print(
                    f"\nPing error for {ip}: {error}"
                )

    print()

    return ping_results


def get_arp_table():
    """
    Retrieve the Windows ARP table
    without opening a console window.
    """

    creation_flags = 0

    if hasattr(subprocess, "CREATE_NO_WINDOW"):
        creation_flags = subprocess.CREATE_NO_WINDOW

    result = subprocess.run(
        ["arp", "-a"],
        capture_output=True,
        text=True,
        errors="ignore",
        creationflags=creation_flags,
    )

    return result.stdout

def discover_arp_devices(network):
    """
    Read dynamic ARP entries and only keep devices
    belonging to the currently detected LAN.
    """

    arp_output = get_arp_table()

    arp_entries = re.findall(
        r"(\d+\.\d+\.\d+\.\d+)\s+"
        r"([0-9a-fA-F-]{17})\s+"
        r"(\w+)",
        arp_output
    )

    arp_devices = {}

    for ip, mac, entry_type in arp_entries:

        if entry_type.lower() != "dynamic":
            continue

        mac = mac.lower()

        if mac == "ff-ff-ff-ff-ff-ff":
            continue

        try:
            ip_address = ipaddress.ip_address(ip)

        except ValueError:
            continue

        if ip_address.is_loopback:
            continue

        if ip_address.is_multicast:
            continue

        if ip_address not in network:
            continue

        arp_devices[ip] = mac

    return arp_devices

def resolve_hostname(ip):
    """
    Attempt to resolve a device hostname using local
    network/DNS information.

    Returns None when no hostname is available.
    """

    try:
        hostname, aliases, addresses = socket.gethostbyaddr(ip)

        return hostname

    except (
        socket.herror,
        socket.gaierror,
        OSError,
    ):
        return None