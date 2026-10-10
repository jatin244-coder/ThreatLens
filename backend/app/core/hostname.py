"""Hostname normalization shared by API validation and scanner safety checks."""

import ipaddress
import re


_LABEL_PATTERN = re.compile(r"^[a-z0-9](?:[a-z0-9-]*[a-z0-9])?$")
_RESERVED_HOSTNAMES = {"localhost", "localhost.localdomain"}


class InvalidHostnameError(ValueError):
    """Raised when a requested hostname is not an allowed assessment target."""


def normalize_hostname(value: str) -> str:
    """Validate and normalize a hostname without performing DNS resolution."""
    candidate = value.strip().rstrip(".").lower()
    if not candidate or any(character.isspace() or ord(character) < 32 for character in candidate):
        raise InvalidHostnameError("hostname must be a valid hostname")
    if "://" in candidate or "/" in candidate or "?" in candidate or "#" in candidate:
        raise InvalidHostnameError("URLs, paths, and fragments are not accepted")
    if "@" in candidate or ":" in candidate or candidate.startswith("["):
        raise InvalidHostnameError("credentials, ports, and IP literals are not accepted")
    try:
        ascii_hostname = candidate.encode("idna").decode("ascii")
    except UnicodeError as error:
        raise InvalidHostnameError("hostname must be a valid hostname") from error
    if ascii_hostname in _RESERVED_HOSTNAMES or ascii_hostname.endswith(".localhost"):
        raise InvalidHostnameError("localhost is not an allowed destination")
    try:
        ipaddress.ip_address(ascii_hostname)
    except ValueError:
        pass
    else:
        raise InvalidHostnameError("IP literals are not accepted")
    if len(ascii_hostname) > 253 or "." not in ascii_hostname:
        raise InvalidHostnameError("hostname must be a fully qualified domain name")
    labels = ascii_hostname.split(".")
    if any(not label or len(label) > 63 or not _LABEL_PATTERN.fullmatch(label) for label in labels):
        raise InvalidHostnameError("hostname must contain valid DNS labels")
    return ascii_hostname
