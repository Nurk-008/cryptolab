"""Experiment for the paper: how much ciphertext does the Vigenere attack need?

For each text length and key length we encrypt 20 random pieces of English text
with random keys and count how often the attack finds the exact key.
Results are printed and saved to results.csv.

Run:  python experiment.py
"""

import csv
import random
import time

import ciphers
from app import SAMPLE_TEXT
from breaker import break_caesar, break_vigenere, only_letters

random.seed(42)
TRIALS = 20
TEXT_LENGTHS = [50, 100, 200, 400, 600]
KEY_LENGTHS = [3, 5, 8, 12]

letters = only_letters(SAMPLE_TEXT) * 3  # long letters-only source text


def random_piece(n):
    start = random.randrange(len(letters) - n)
    return letters[start:start + n]


def random_key(n):
    return "".join(random.choice(ciphers.ALPHABET) for _ in range(n))


rows = []

# Caesar: all shifts, short texts
for n in [10, 20, 50, 100]:
    ok = 0
    for _ in range(TRIALS):
        shift = random.randrange(1, 26)
        found, _, _ = break_caesar(ciphers.caesar_encrypt(random_piece(n), shift))
        ok += found == shift
    rows.append(("Caesar", n, "-", ok / TRIALS * 100))

# Vigenere
for key_len in KEY_LENGTHS:
    for n in TEXT_LENGTHS:
        ok = 0
        for _ in range(TRIALS):
            key = random_key(key_len)
            found, _, _ = break_vigenere(ciphers.vigenere_encrypt(random_piece(n), key))
            ok += found == key
        rows.append(("Vigenere", n, key_len, ok / TRIALS * 100))

print(f"{'Cipher':<10}{'Letters':>8}{'Key len':>9}{'Success %':>11}")
for cipher, n, k, pct in rows:
    print(f"{cipher:<10}{n:>8}{k:>9}{pct:>10.0f}%")

with open("results.csv", "w", newline="", encoding="utf-8") as f:
    w = csv.writer(f)
    w.writerow(["cipher", "letters", "key_length", "success_percent"])
    w.writerows(rows)

# Speed and key space comparison
start = time.perf_counter()
for _ in range(100):
    break_vigenere(ciphers.vigenere_encrypt(SAMPLE_TEXT, "network"))
ms = (time.perf_counter() - start) * 10
print(f"\nAverage time to break Vigenere (key 'network', {len(only_letters(SAMPLE_TEXT))} letters): {ms:.1f} ms")

start = time.perf_counter()
for _ in range(20):
    ciphers._derive_key("guess", b"0" * 16)
per_guess = (time.perf_counter() - start) / 20
print(f"One AES password guess (PBKDF2, {ciphers.PBKDF2_ITERATIONS} rounds): {per_guess * 1000:.0f} ms")
print("Caesar key space: 26 | Vigenere (8 letters): 26^8 = 2.1e11, but IC attack avoids trying them")
years = 2 ** 256 / 1e12 / 3600 / 24 / 365
print(f"AES-256 key space: 2^256 = 1.2e77 -> at 10^12 guesses per second: {years:.1e} years")
