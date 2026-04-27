"""Network utility functions used by Wifishield."""

import socket
from scapy.all import ARP, Ether, conf, srp


def get_default_gateway_ip() -> str:
    """Return default gateway IP using Scapy routing table."""
    route = conf.route.route("0.0.0.0")
    gateway_ip = route[2]
    if not gateway_ip or gateway_ip == "0.0.0.0":
        raise RuntimeError("Unable to detect default gateway IP.")
    return gateway_ip


def resolve_mac(ip_address: str, timeout: int = 2) -> str | None:
    """Resolve MAC address for an IP using ARP request."""
    arp_request = ARP(pdst=ip_address)
    broadcast = Ether(dst="ff:ff:ff:ff:ff:ff")
    packet = broadcast / arp_request

    answered = srp(packet, timeout=timeout, verbose=False)[0]
    if answered:
        return answered[0][1].hwsrc
    return None


def local_ip() -> str:
    """Best-effort local IP detection."""
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    try:
        sock.connect(("8.8.8.8", 80))
        return sock.getsockname()[0]
    finally:
        sock.close()
