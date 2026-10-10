import pytest

from cyberhealth_scanner.validation import (
    UnsafeDomainError,
    is_public_ip,
    resolve_public_ips,
    validate_domain,
)


def test_valid_domain_is_normalized():
    assert validate_domain("  Example.COM. ") == "example.com"


def test_empty_domain_is_rejected():
    with pytest.raises(UnsafeDomainError):
        validate_domain("")


def test_url_is_rejected():
    with pytest.raises(UnsafeDomainError):
        validate_domain("https://example.com")


def test_ip_address_is_rejected():
    with pytest.raises(UnsafeDomainError):
        validate_domain("127.0.0.1")


def test_localhost_is_rejected():
    with pytest.raises(UnsafeDomainError):
        validate_domain("localhost")


def test_domain_with_path_is_rejected():
    with pytest.raises(UnsafeDomainError):
        validate_domain("example.com/login")


def test_public_ip_is_allowed(monkeypatch):
    def fake_getaddrinfo(hostname, port, type):
        return [
            (
                2,
                1,
                6,
                "",
                ("8.8.8.8", port),
            )
        ]

    monkeypatch.setattr(
        "cyberhealth_scanner.validation.socket.getaddrinfo",
        fake_getaddrinfo,
    )

    addresses = resolve_public_ips("example.com")

    assert addresses == ["8.8.8.8"]


def test_private_ip_is_rejected(monkeypatch):
    def fake_getaddrinfo(hostname, port, type):
        return [
            (
                2,
                1,
                6,
                "",
                ("192.168.1.10", port),
            )
        ]

    monkeypatch.setattr(
        "cyberhealth_scanner.validation.socket.getaddrinfo",
        fake_getaddrinfo,
    )

    with pytest.raises(UnsafeDomainError):
        resolve_public_ips("example.com")


def test_localhost_ip_is_not_public():
    assert is_public_ip("127.0.0.1") is False
    assert is_public_ip("192.168.1.1") is False
    assert is_public_ip("8.8.8.8") is True