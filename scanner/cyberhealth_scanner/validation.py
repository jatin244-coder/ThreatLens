import ipaddress
import socket


class UnsafeDomainError(ValueError):
    """Raised when a domain is invalid or unsafe."""


def validate_domain(domain: str) -> str:
    """Validate and normalize a website domain."""

    if not isinstance(domain, str):
        raise UnsafeDomainError("Domain must be text.")

    hostname = domain.strip().lower().rstrip(".")

    if not hostname:
        raise UnsafeDomainError("Domain cannot be empty.")

    if "://" in hostname:
        raise UnsafeDomainError(
            "Enter example.com, not https://example.com"
        )

    if "/" in hostname:
        raise UnsafeDomainError("Paths are not allowed.")

    if ":" in hostname:
        raise UnsafeDomainError("Ports are not allowed.")

    if hostname == "localhost":
        raise UnsafeDomainError("Localhost is not allowed.")

    if hostname.replace(".", "").isdigit():
        raise UnsafeDomainError("IP addresses are not allowed.")

    if "." not in hostname:
        raise UnsafeDomainError(
            "Enter a complete domain such as example.com."
        )

    for label in hostname.split("."):
        if not label:
            raise UnsafeDomainError(
                "Domain contains an empty section."
            )

        if label.startswith("-") or label.endswith("-"):
            raise UnsafeDomainError(
                "Domain sections cannot start or end with a hyphen."
            )

        for character in label:
            if not (
                character.islower()
                or character.isdigit()
                or character == "-"
            ):
                raise UnsafeDomainError(
                    "Domain contains an unsupported character."
                )

    return hostname


def is_public_ip(address: str) -> bool:
    """Return True only for globally routable IP addresses."""

    try:
        ip = ipaddress.ip_address(address)
    except ValueError as error:
        raise UnsafeDomainError(
            f"Invalid IP address: {address}"
        ) from error

    return ip.is_global


def resolve_public_ips(domain: str) -> list[str]:
    """
    Resolve a domain and reject private or local IP addresses.
    """

    hostname = validate_domain(domain)

    try:
        records = socket.getaddrinfo(
            hostname,
            443,
            type=socket.SOCK_STREAM,
        )
    except socket.gaierror as error:
        raise UnsafeDomainError(
            f"Could not resolve domain: {hostname}"
        ) from error

    addresses = sorted(
        {
            record[4][0]
            for record in records
        }
    )

    if not addresses:
        raise UnsafeDomainError(
            "The domain did not resolve to an IP address."
        )

    unsafe_addresses = [
        address
        for address in addresses
        if not is_public_ip(address)
    ]

    if unsafe_addresses:
        raise UnsafeDomainError(
            "The domain resolves to unsafe IP address(es): "
            f"{unsafe_addresses}"
        )

    return addresses


def validate_and_resolve_public_domain(domain: str) -> str:
    """
    Validate a domain and confirm it resolves to public IP addresses.
    """

    hostname = validate_domain(domain)
    resolve_public_ips(hostname)
    return hostname