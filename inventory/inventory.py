def build_inventory(ping_results, arp_devices):
    devices = {}

    all_ips = set(ping_results) | set(arp_devices)

    for ip in sorted(
        all_ips,
        key=lambda x: int(x.split(".")[-1])
    ):
        devices[ip] = {
            "mac": arp_devices.get(ip),
            "ping": ip in ping_results
        }

        if devices[ip]["ping"]:
            state = "ONLINE"

        elif devices[ip]["mac"]:
            state = "OBSERVED"

        else:
            state = "UNKNOWN"

        devices[ip]["state"] = state

    return devices