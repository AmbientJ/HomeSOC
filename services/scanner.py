import socket


def check_port(ip, port):
    sock = socket.socket(
        socket.AF_INET,
        socket.SOCK_STREAM
    )

    sock.settimeout(1)

    try:
        result = sock.connect_ex((ip, port))

        return result == 0

    finally:
        sock.close()


def scan_ports(ip, ports):
    results = {}

    for port in ports:
        results[port] = check_port(ip, port)

    return results