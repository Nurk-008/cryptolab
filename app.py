"""CryptoLab - desktop app (Tkinter).

Tab 1: encrypt / decrypt with Caesar, Vigenere or AES-256.
Tab 2: break a Caesar or Vigenere message without the key.

Run:  python app.py
"""

import os
import time
import tkinter as tk
from tkinter import messagebox, ttk

from cryptography.exceptions import InvalidTag

import ciphers
from breaker import break_caesar, break_vigenere

SAMPLE_PATH = os.path.join(os.path.dirname(os.path.abspath(__file__)), "sample_text.txt")
with open(SAMPLE_PATH, encoding="utf-8") as f:
    SAMPLE_TEXT = f.read().strip()

CIPHERS = ["Caesar", "Vigenere", "AES-256"]


def run_cipher(name, text, key, encrypt):
    if name == "Caesar":
        try:
            shift = int(key)
        except ValueError:
            raise ValueError("Caesar key must be a number, for example 3")
        return ciphers.caesar_encrypt(text, shift) if encrypt else ciphers.caesar_decrypt(text, shift)
    if name == "Vigenere":
        return ciphers.vigenere_encrypt(text, key) if encrypt else ciphers.vigenere_decrypt(text, key)
    if not key:
        raise ValueError("AES needs a password")
    if encrypt:
        return ciphers.aes_encrypt(text, key)
    try:
        return ciphers.aes_decrypt(text.strip(), key)
    except InvalidTag:
        raise ValueError("Wrong password or the message was changed")


def text_box(parent, height):
    box = tk.Text(parent, height=height, wrap="word", font=("Consolas", 10))
    box.pack(fill="both", expand=True, padx=8, pady=4)
    return box


def set_text(box, value):
    box.delete("1.0", "end")
    box.insert("1.0", value)


class App(tk.Tk):
    def __init__(self):
        super().__init__()
        self.title("CryptoLab - encrypt, decrypt, break")
        self.geometry("820x640")
        self.tabs = ttk.Notebook(self)
        self.tabs.pack(fill="both", expand=True)
        self.tabs.add(self._build_crypt_tab(self.tabs), text="Encrypt / Decrypt")
        self.tabs.add(self._build_break_tab(self.tabs), text="Break weak cipher")

    # ---------- Tab 1 ----------

    def _build_crypt_tab(self, parent):
        tab = ttk.Frame(parent)
        row = ttk.Frame(tab)
        row.pack(fill="x", padx=8, pady=6)
        ttk.Label(row, text="Cipher:").pack(side="left")
        self.cipher = ttk.Combobox(row, values=CIPHERS, state="readonly", width=12)
        self.cipher.current(1)
        self.cipher.pack(side="left", padx=4)
        ttk.Label(row, text="Key / shift / password:").pack(side="left", padx=(12, 0))
        self.key = ttk.Entry(row, width=24)
        self.key.insert(0, "secret")
        self.key.pack(side="left", padx=4)
        ttk.Button(row, text="Encrypt", command=lambda: self._crypt(True)).pack(side="left", padx=4)
        ttk.Button(row, text="Decrypt", command=lambda: self._crypt(False)).pack(side="left")

        ttk.Label(tab, text="Input").pack(anchor="w", padx=8)
        self.crypt_in = text_box(tab, 10)
        set_text(self.crypt_in, SAMPLE_TEXT)

        bottom = ttk.Frame(tab)
        bottom.pack(fill="x", padx=8)
        ttk.Label(bottom, text="Output").pack(side="left")
        ttk.Button(bottom, text="Output -> Input", command=self._swap).pack(side="right")
        ttk.Button(bottom, text="Send to Break tab", command=self._to_break).pack(side="right", padx=4)
        self.crypt_out = text_box(tab, 10)
        return tab

    def _crypt(self, encrypt):
        try:
            result = run_cipher(self.cipher.get(), self.crypt_in.get("1.0", "end-1c"), self.key.get(), encrypt)
        except ValueError as e:
            messagebox.showerror("Error", str(e))
            return
        set_text(self.crypt_out, result)

    def _swap(self):
        set_text(self.crypt_in, self.crypt_out.get("1.0", "end-1c"))
        self.crypt_out.delete("1.0", "end")

    def _to_break(self):
        set_text(self.break_in, self.crypt_out.get("1.0", "end-1c"))
        if self.cipher.get() in ("Caesar", "Vigenere"):
            self.attack.set(self.cipher.get())
        self.tabs.select(1)

    # ---------- Tab 2 ----------

    def _build_break_tab(self, parent):
        tab = ttk.Frame(parent)
        row = ttk.Frame(tab)
        row.pack(fill="x", padx=8, pady=6)
        ttk.Label(row, text="Attack:").pack(side="left")
        self.attack = tk.StringVar(value="Vigenere")
        for name in ("Caesar", "Vigenere"):
            ttk.Radiobutton(row, text=name, variable=self.attack, value=name).pack(side="left", padx=4)
        ttk.Button(row, text="Break it!", command=self._break).pack(side="left", padx=12)

        ttk.Label(tab, text="Ciphertext (no key needed)").pack(anchor="w", padx=8)
        self.break_in = text_box(tab, 8)
        ttk.Label(tab, text="Result").pack(anchor="w", padx=8)
        self.break_out = text_box(tab, 14)
        return tab

    def _break(self):
        ct = self.break_in.get("1.0", "end-1c")
        start = time.perf_counter()
        if self.attack.get() == "Caesar":
            shift, plain, candidates = break_caesar(ct)
            ms = (time.perf_counter() - start) * 1000
            top = "\n".join(f"  shift {s:2d}  score {score:9.1f}" for score, s, _ in candidates[:5])
            report = (f"Found shift: {shift}   (tried all 26 shifts in {ms:.1f} ms)\n"
                      f"Best 5 by chi-squared (smaller = more like English):\n{top}\n\n"
                      f"Plaintext:\n{plain}")
        else:
            key, plain, scores = break_vigenere(ct)
            ms = (time.perf_counter() - start) * 1000
            ics = "  ".join(f"{n}:{v:.3f}" for n, v in list(scores.items())[:12])
            report = (f"Found key: '{key}'  (length {len(key)}, {ms:.1f} ms)\n"
                      f"Index of Coincidence per key length (English ~0.066, random ~0.038):\n  {ics}\n\n"
                      f"Plaintext:\n{plain}")
        set_text(self.break_out, report)


if __name__ == "__main__":
    App().mainloop()
