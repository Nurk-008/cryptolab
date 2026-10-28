"""Unit tests.  Run:  python -m unittest -v"""

import unittest

from cryptography.exceptions import InvalidTag

import ciphers
from breaker import break_caesar, break_vigenere
from app import SAMPLE_TEXT


class CaesarTests(unittest.TestCase):
    def test_known_example(self):
        self.assertEqual(ciphers.caesar_encrypt("Hello, World!", 3), "Khoor, Zruog!")

    def test_round_trip_all_shifts(self):
        for shift in range(-30, 30):
            ct = ciphers.caesar_encrypt(SAMPLE_TEXT, shift)
            self.assertEqual(ciphers.caesar_decrypt(ct, shift), SAMPLE_TEXT)

    def test_non_letters_unchanged(self):
        self.assertEqual(ciphers.caesar_encrypt("123 !?", 5), "123 !?")


class VigenereTests(unittest.TestCase):
    def test_known_example(self):
        # Classic textbook example
        self.assertEqual(ciphers.vigenere_encrypt("ATTACKATDAWN", "LEMON"), "LXFOPVEFRNHR")

    def test_round_trip(self):
        ct = ciphers.vigenere_encrypt(SAMPLE_TEXT, "network")
        self.assertNotEqual(ct, SAMPLE_TEXT)
        self.assertEqual(ciphers.vigenere_decrypt(ct, "network"), SAMPLE_TEXT)

    def test_bad_key(self):
        with self.assertRaises(ValueError):
            ciphers.vigenere_encrypt("abc", "123")


class AesTests(unittest.TestCase):
    def test_round_trip(self):
        token = ciphers.aes_encrypt(SAMPLE_TEXT, "Str0ng-Pa55")
        self.assertEqual(ciphers.aes_decrypt(token, "Str0ng-Pa55"), SAMPLE_TEXT)

    def test_unicode(self):
        text = "Сәлем, әлем! Привет 👋"
        self.assertEqual(ciphers.aes_decrypt(ciphers.aes_encrypt(text, "k"), "k"), text)

    def test_same_text_gives_different_ciphertext(self):
        # random salt + nonce: the same message never looks the same twice
        self.assertNotEqual(ciphers.aes_encrypt("hi", "k"), ciphers.aes_encrypt("hi", "k"))

    def test_wrong_password_fails(self):
        token = ciphers.aes_encrypt("hi", "right")
        with self.assertRaises(InvalidTag):
            ciphers.aes_decrypt(token, "wrong")


class BreakerTests(unittest.TestCase):
    def test_break_caesar_every_shift(self):
        for shift in range(26):
            found, plain, _ = break_caesar(ciphers.caesar_encrypt(SAMPLE_TEXT, shift))
            self.assertEqual(found, shift)
            self.assertEqual(plain, SAMPLE_TEXT)

    def test_break_vigenere(self):
        for key in ["key", "secret", "network", "university"]:
            found, plain, _ = break_vigenere(ciphers.vigenere_encrypt(SAMPLE_TEXT, key))
            self.assertEqual(found, key)
            self.assertEqual(plain, SAMPLE_TEXT)


if __name__ == "__main__":
    unittest.main()
