"""
integrity.py - SHA-256 hashing and verification.   [Member 2]

A hash is a fingerprint: the same input always gives the same 64 hex
characters, and changing ONE character changes about half of the output
bits (the avalanche effect), so tampering is obvious.
"""
import hashlib
import hmac


def sha256_bytes(data: bytes) -> str:
    return hashlib.sha256(data or b"").hexdigest()


def sha256_text(text: str) -> str:
    return sha256_bytes((text or "").encode("utf-8"))


def verify(text: str, expected: str) -> bool:
    """compare_digest takes the same time wherever the strings differ (no timing leak)."""
    return hmac.compare_digest(sha256_text(text), expected.strip().lower())


def tamper_demo(text: str, position: int) -> dict:
    """Flip one bit of one character and compare the two hashes."""
    position = min(max(position, 0), len(text) - 1)
    tampered = text[:position] + chr(ord(text[position]) ^ 1) + text[position + 1:]
    h1, h2 = sha256_text(text), sha256_text(tampered)
    bits = bin(int(h1, 16) ^ int(h2, 16)).count("1")        # how many of 256 bits differ
    return {"tampered": tampered, "hash1": h1, "hash2": h2, "bits_changed": bits}
