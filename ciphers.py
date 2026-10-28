"""Encryption and decryption: two weak classical ciphers and one strong modern one.

Caesar and Vigenere are here to be broken (see breaker.py).
AES-256-GCM is the secure version we compare them to.
"""

import base64
import os

from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC

ALPHABET = "abcdefghijklmnopqrstuvwxyz"


def _shift_letter(ch, shift):
    """Shift one letter by `shift` positions, keeping its case. Other characters stay the same."""
    if ch.isascii() and ch.isalpha():
        base = ord("A") if ch.isupper() else ord("a")
        return chr((ord(ch) - base + shift) % 26 + base)
    return ch


# ---------- Caesar ----------

def caesar_encrypt(text, shift):
    return "".join(_shift_letter(ch, shift) for ch in text)


def caesar_decrypt(text, shift):
    return caesar_encrypt(text, -shift)


# ---------- Vigenere ----------

def _key_shifts(key):
    shifts = [ALPHABET.index(c) for c in key.lower() if c in ALPHABET]
    if not shifts:
        raise ValueError("Vigenere key must contain at least one letter a-z")
    return shifts


def _vigenere(text, key, direction):
    shifts = _key_shifts(key)
    out = []
    i = 0  # only letters move the key forward
    for ch in text:
        if ch.isascii() and ch.isalpha():
            out.append(_shift_letter(ch, direction * shifts[i % len(shifts)]))
            i += 1
        else:
            out.append(ch)
    return "".join(out)


def vigenere_encrypt(text, key):
    return _vigenere(text, key, +1)


def vigenere_decrypt(text, key):
    return _vigenere(text, key, -1)


# ---------- AES-256-GCM ----------
# Output format (Base64): salt (16 bytes) + nonce (12 bytes) + ciphertext + tag

PBKDF2_ITERATIONS = 200_000


def _derive_key(password, salt):
    kdf = PBKDF2HMAC(algorithm=hashes.SHA256(), length=32, salt=salt, iterations=PBKDF2_ITERATIONS)
    return kdf.derive(password.encode("utf-8"))


def aes_encrypt(text, password):
    salt = os.urandom(16)
    nonce = os.urandom(12)
    key = _derive_key(password, salt)
    ct = AESGCM(key).encrypt(nonce, text.encode("utf-8"), None)
    return base64.b64encode(salt + nonce + ct).decode("ascii")


def aes_decrypt(token, password):
    """Raises cryptography.exceptions.InvalidTag if the password is wrong or the data was changed."""
    raw = base64.b64decode(token)
    salt, nonce, ct = raw[:16], raw[16:28], raw[28:]
    key = _derive_key(password, salt)
    return AESGCM(key).decrypt(nonce, ct, None).decode("utf-8")
