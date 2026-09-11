from mac_vendor_lookup import MacLookup, VendorNotFoundError


_lookup = MacLookup()


def is_locally_administered(mac):
    """
    Determine whether a MAC address is locally administered.
    This is commonly used for randomized/private MAC addresses.
    """

    if not mac:
        return False

    normalized = mac.replace("-", ":").lower()

    try:
        first_octet = int(
            normalized.split(":")[0],
            16
        )
    except (ValueError, IndexError):
        return False

    return bool(first_octet & 0b00000010)


def lookup_vendor(mac):
    """
    Attempt to identify the manufacturer of a MAC address.
    """

    if not mac:
        return {
            "vendor": None,
            "vendor_status": "MAC_UNAVAILABLE",
        }

    if is_locally_administered(mac):
        return {
            "vendor": "LOCAL / PRIVATE MAC",
            "vendor_status": "LOCAL",
        }

    normalized = mac.replace("-", ":")

    try:
        vendor = _lookup.lookup(normalized)

        return {
            "vendor": vendor,
            "vendor_status": "KNOWN",
        }

    except VendorNotFoundError:
        return {
            "vendor": "UNKNOWN VENDOR",
            "vendor_status": "UNKNOWN",
        }

    except Exception:
        return {
            "vendor": "LOOKUP ERROR",
            "vendor_status": "ERROR",
        }