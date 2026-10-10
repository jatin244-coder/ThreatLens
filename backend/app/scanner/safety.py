"""Destination validation and DNS resolution used by the scanner transport."""

import ipaddress
import socket
from dataclasses import dataclass
from urllib.parse import SplitResult, urlsplit

from app.core.hostname import normalize_hostname


APPROVED_PORTS = {80, 443}
METADATA_IPS = {"169.254.169.254", "100.100.100.200"}
CGNAT_NETWORK = ipaddress.ip_network("100.64.0.0/10")


class UnsafeDestinationError(ValueError):
    """Raised when a destination is not safe to contact."""


@dataclass(frozen=True)
class ResolvedAddress:
    """An address selected from validated resolver output."""

    family: int
    ip: str


def validate_ip(ip: str) -> ipaddress.IPv4Address | ipaddress.IPv6Address:
    """Reject all address classes that can reach internal or special networks."""
    try:
        address = ipaddress.ip_address(ip)
    except ValueError as error:
        raise UnsafeDestinationError("resolver returned an invalid address") from error
    mapped = getattr(address, "ipv4_mapped", None)
    effective = mapped or address
    if (
        str(address) in METADATA_IPS
        or effective in CGNAT_NETWORK
        or effective.is_loopback
        or effective.is_private
        or effective.is_link_local
        or effective.is_reserved
        or effective.is_multicast
        or effective.is_unspecified
    ):
        raise UnsafeDestinationError("destination address is not publicly routable")
    return address


def resolve_and_validate(hostname: str, port: int) -> list[ResolvedAddress]:
    """Resolve A/AAAA records and validate every returned address."""
    if port not in APPROVED_PORTS:
        raise UnsafeDestinationError("destination port is not approved")
    normalized = normalize_hostname(hostname)
    results: list[ResolvedAddress] = []
    seen: set[tuple[int, str]] = set()
    for family, _socktype, _protocol, _canonname, sockaddr in socket.getaddrinfo(
        normalized, port, type=socket.SOCK_STREAM
    ):
        ip = sockaddr[0]
        validate_ip(ip)
        key = (family, ip)
        if key not in seen:
            results.append(ResolvedAddress(family=family, ip=ip))
            seen.add(key)
    if not results:
        raise UnsafeDestinationError("hostname did not resolve to a usable address")
    return results


def parse_target(url: str) -> tuple[SplitResult, int]:
    """Parse a scanner URL and enforce scheme, credential, and port policy."""
    parsed = urlsplit(url)
    if parsed.scheme not in {"http", "https"} or not parsed.hostname:
        raise UnsafeDestinationError("only HTTP and HTTPS targets are supported")
    if parsed.username is not None or parsed.password is not None:
        raise UnsafeDestinationError("URL credentials are not allowed")
    try:
        port = parsed.port or (443 if parsed.scheme == "https" else 80)
    except ValueError as error:
        raise UnsafeDestinationError("target port is invalid") from error
    if port not in APPROVED_PORTS:
        raise UnsafeDestinationError("target port is not approved")
    normalize_hostname(parsed.hostname)
    return parsed, port
