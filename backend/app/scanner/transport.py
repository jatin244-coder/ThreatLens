"""Minimal HTTP transport with explicit SSRF and redirect controls."""

import socket
import ssl
from email.message import Message
from typing import Callable
from urllib.parse import urljoin, urlunsplit

from app.scanner.models import TransportResponse
from app.scanner.safety import ResolvedAddress, UnsafeDestinationError, parse_target, resolve_and_validate


CONNECT_TIMEOUT_SECONDS = 5.0
READ_TIMEOUT_SECONDS = 5.0
MAX_RESPONSE_BYTES = 1024 * 1024
MAX_HEADER_BYTES = 64 * 1024
MAX_REDIRECTS = 5


class UnsafeRedirectError(UnsafeDestinationError):
    """Raised when a redirect is outside the scanner safety policy."""


def _read_response(connection: socket.socket) -> tuple[int, dict[str, str], bytes]:
    """Read one bounded HTTP response from a connection."""
    connection.settimeout(READ_TIMEOUT_SECONDS)
    data = bytearray()
    while b"\r\n\r\n" not in data:
        if len(data) >= MAX_HEADER_BYTES:
            raise ValueError("response headers exceed the size limit")
        chunk = connection.recv(min(8192, MAX_HEADER_BYTES - len(data)))
        if not chunk:
            break
        data.extend(chunk)
    separator = data.find(b"\r\n\r\n")
    if separator < 0:
        raise ValueError("response headers are incomplete")
    header_bytes = bytes(data[:separator])
    body = bytearray(data[separator + 4 :])
    lines = header_bytes.split(b"\r\n")
    status_line = lines[0].decode("iso-8859-1")
    try:
        status_code = int(status_line.split(" ", 2)[1])
    except (IndexError, ValueError) as error:
        raise ValueError("response status is invalid") from error
    message = Message()
    for line in lines[1:]:
        key, separator, value = line.decode("iso-8859-1").partition(":")
        if separator:
            message[key] = value.strip()
    while len(body) < MAX_RESPONSE_BYTES:
        chunk = connection.recv(min(8192, MAX_RESPONSE_BYTES - len(body)))
        if not chunk:
            break
        body.extend(chunk)
    return status_code, dict(message.items()), bytes(body[:MAX_RESPONSE_BYTES])


def _connect(
    address: ResolvedAddress,
    host: str,
    port: int,
    use_tls: bool,
    socket_factory: Callable[..., socket.socket] = socket.socket,
) -> tuple[socket.socket, dict[str, object] | None]:
    """Connect to the exact validated IP address, then optionally negotiate TLS."""
    connection = socket_factory(address.family, socket.SOCK_STREAM)
    connection.settimeout(CONNECT_TIMEOUT_SECONDS)
    if address.family == socket.AF_INET6:
        connection.connect((address.ip, port, 0, 0))
    else:
        connection.connect((address.ip, port))
    certificate = None
    if use_tls:
        context = ssl.create_default_context()
        connection = context.wrap_socket(connection, server_hostname=host)
        certificate = connection.getpeercert()
    return connection, certificate


def fetch_url(
    url: str,
    *,
    resolver=resolve_and_validate,
    socket_factory: Callable[..., socket.socket] = socket.socket,
) -> TransportResponse:
    """Fetch a URL with validated direct connections and manual redirects."""
    current_url = url
    visited: set[str] = set()
    for _redirect_number in range(MAX_REDIRECTS + 1):
        if current_url in visited:
            raise UnsafeRedirectError("redirect loop detected")
        visited.add(current_url)
        parsed, port = parse_target(current_url)
        host = parsed.hostname
        assert host is not None
        addresses = resolver(host, port)
        connection = None
        certificate = None
        last_error: Exception | None = None
        for address in addresses:
            try:
                connection, certificate = _connect(
                    address, host, port, parsed.scheme == "https", socket_factory
                )
                break
            except (OSError, ssl.SSLError) as error:
                last_error = error
                if connection is not None:
                    connection.close()
                connection = None
        if connection is None:
            raise last_error or TimeoutError("unable to connect to validated destination")
        try:
            path = parsed.path or "/"
            if parsed.query:
                path = f"{path}?{parsed.query}"
            request = (
                f"GET {path} HTTP/1.1\r\n"
                f"Host: {host}\r\n"
                "User-Agent: ThreatLens-Security-Scanner/1.0\r\n"
                "Accept-Encoding: identity\r\n"
                "Connection: close\r\n\r\n"
            ).encode("ascii")
            connection.sendall(request)
            status_code, headers, body = _read_response(connection)
        finally:
            connection.close()
        location = headers.get("Location")
        if status_code in {301, 302, 303, 307, 308} and location:
            next_url = urljoin(urlunsplit(parsed), location)
            try:
                next_parsed, _next_port = parse_target(next_url)
                if next_parsed.hostname is None:
                    raise UnsafeRedirectError("redirect target has no hostname")
            except UnsafeDestinationError as error:
                raise UnsafeRedirectError(str(error)) from error
            current_url = next_url
            continue
        return TransportResponse(
            url=current_url,
            status_code=status_code,
            headers={key.lower(): value for key, value in headers.items()},
            body=body,
            certificate=certificate,
        )
    raise UnsafeRedirectError("redirect limit exceeded")
