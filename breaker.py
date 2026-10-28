"""Breaking the weak ciphers without knowing the key.

Caesar:   try all 26 shifts, pick the one whose letters look most like English
          (chi-squared test against English letter frequencies).
Vigenere: 1) guess the key length with the Index of Coincidence (IC),
          2) split the text into columns - each column is just a Caesar cipher,
          3) break each column with the Caesar method above.
"""

from collections import Counter

from ciphers import ALPHABET, caesar_decrypt, vigenere_decrypt

# Relative frequency of letters in English text (percent)
ENGLISH_FREQ = {
    "a": 8.167, "b": 1.492, "c": 2.782, "d": 4.253, "e": 12.702, "f": 2.228,
    "g": 2.015, "h": 6.094, "i": 6.966, "j": 0.153, "k": 0.772, "l": 4.025,
    "m": 2.406, "n": 6.749, "o": 7.507, "p": 1.929, "q": 0.095, "r": 5.987,
    "s": 6.327, "t": 9.056, "u": 2.758, "v": 0.978, "w": 2.360, "x": 0.150,
    "y": 1.974, "z": 0.074,
}

ENGLISH_IC = 0.066   # IC of normal English text
RANDOM_IC = 1 / 26   # IC of random letters (~0.038)


def only_letters(text):
    return "".join(c for c in text.lower() if c in ALPHABET)


def chi_squared(text):
    """How far the letter counts are from English. Smaller = more like English."""
    letters = only_letters(text)
    n = len(letters)
    if n == 0:
        return float("inf")
    counts = Counter(letters)
    score = 0.0
    for ch in ALPHABET:
        expected = ENGLISH_FREQ[ch] / 100 * n
        score += (counts.get(ch, 0) - expected) ** 2 / expected
    return score


def index_of_coincidence(letters):
    """Chance that two random letters from the text are the same."""
    n = len(letters)
    if n < 2:
        return 0.0
    counts = Counter(letters)
    return sum(c * (c - 1) for c in counts.values()) / (n * (n - 1))


# ---------- Caesar ----------

def break_caesar(ciphertext):
    """Returns (best_shift, plaintext, all_candidates sorted by score)."""
    candidates = []
    for shift in range(26):
        plain = caesar_decrypt(ciphertext, shift)
        candidates.append((chi_squared(plain), shift, plain))
    candidates.sort()
    _, shift, plain = candidates[0]
    return shift, plain, candidates


# ---------- Vigenere ----------

def key_length_scores(ciphertext, max_len=20):
    """Average IC of the columns for each possible key length."""
    letters = only_letters(ciphertext)
    scores = {}
    for length in range(1, max_len + 1):
        columns = [letters[i::length] for i in range(length)]
        scores[length] = sum(index_of_coincidence(c) for c in columns) / length
    return scores


def guess_key_length(ciphertext, max_len=20):
    scores = key_length_scores(ciphertext, max_len)
    best = max(scores.values())
    # Multiples of the real length also score high, so take the smallest
    # length that is almost as good as the best one.
    for length in sorted(scores):
        if scores[length] >= 0.9 * best:
            return length, scores
    return max(scores, key=scores.get), scores


def break_vigenere(ciphertext, max_len=20):
    """Returns (key, plaintext, key_length_scores)."""
    letters = only_letters(ciphertext)
    length, scores = guess_key_length(ciphertext, max_len)
    key = ""
    for i in range(length):
        shift, _, _ = break_caesar(letters[i::length])
        key += ALPHABET[shift]
    return key, vigenere_decrypt(ciphertext, key), scores
