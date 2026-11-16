"""HMAC-SHA-256 using the lab's SHA-256 implementation (RFC 2104)."""

from .sha256 import sha256


def hmac_sha256(key: bytes, data: bytes) -> bytes:
    """Return the full 32-byte authentication tag for bytes key and data."""
    if not isinstance(key, bytes):
        raise TypeError("key must be bytes")
    if not isinstance(data, bytes):
        raise TypeError("data must be bytes")

    # SHA-256 has a 64-byte block size. Long keys are hashed before padding.
    if len(key) > 64:
        key = sha256(key)
    padded_key = key.ljust(64, b"\x00")
    inner_pad = bytes(value ^ 0x36 for value in padded_key)
    outer_pad = bytes(value ^ 0x5C for value in padded_key)
    return sha256(outer_pad + sha256(inner_pad + data))


def verify_hmac_sha256(key: bytes, data: bytes, tag: bytes) -> bool:
    """Check a full-length tag, comparing all bytes for equal-length inputs."""
    if not isinstance(tag, bytes):
        raise TypeError("tag must be bytes")
    expected = hmac_sha256(key, data)
    if len(tag) != len(expected):
        return False
    difference = 0
    for expected_byte, received_byte in zip(expected, tag):
        difference |= expected_byte ^ received_byte
    return difference == 0
