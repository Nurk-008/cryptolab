# CryptoLab — encrypt, decrypt, and break

INF 106 Research Project · Track 5 (Security and Infrastructure) · Topic **I2: An encryption program**

A Python desktop program that:

1. **Encrypts and decrypts** messages with three ciphers:
   - **Caesar** (weak): shift every letter by a number
   - **Vigenère** (weak): shift letters using a keyword
   - **AES-256-GCM** (strong): modern cipher; key made from a password with PBKDF2-SHA256 (200,000 rounds), random salt and nonce
2. **Breaks the weak ciphers without the key:**
   - Caesar: tries all 26 shifts and picks the one closest to English letter frequencies (chi-squared test)
   - Vigenère: finds the key length with the **Index of Coincidence**, then breaks each column as a Caesar cipher
3. **Measures** how much ciphertext the attack needs (`experiment.py`).

## Files

| File | What it does |
|---|---|
| `ciphers.py` | Caesar, Vigenère, AES encryption/decryption |
| `breaker.py` | Attacks: chi-squared, Index of Coincidence |
| `app.py` | Desktop app (Tkinter) with two tabs |
| `test_cryptolab.py` | 12 unit tests |
| `experiment.py` | Success rate vs text length → `results.csv` |
| `sample_text.txt` | Demo message |

## Run

```bash
pip install -r requirements.txt
python app.py              # the app
python -m unittest -v      # tests
python experiment.py       # experiment for the paper
```

## Demo script (for the defense, ~3 minutes)

1. **Encrypt / Decrypt** tab → cipher *Vigenère*, key `network` → **Encrypt**. Text becomes unreadable.
2. Click **Send to Break tab** → **Break it!** → the program finds the key `network` in a few milliseconds and shows the IC table: the column for length 7 is close to English (~0.066).
3. Back to tab 1 → cipher *AES-256*, password `Str0ng-Pa55` → **Encrypt**. Encrypt again — the result is different each time (random salt/nonce).
4. Try **Decrypt** with a wrong password → error: AES-GCM detects it. Correct password → original text.
5. Show `experiment.py` output: the weak ciphers fall in milliseconds, AES-256 would need ~10^57 years.

## Test results

All 12 unit tests pass. Experiment (20 trials per cell, random keys, `random.seed(42)`):

| Letters of ciphertext | Key len 3 | Key len 5 | Key len 8 | Key len 12 |
|---|---|---|---|---|
| 50  | 0%  | 10%  | 0%   | 0%   |
| 100 | 15% | 35%  | 5%   | 0%   |
| 200 | 30% | 75%  | 75%  | 0%   |
| 400 | 85% | 100% | 100% | 95%  |
| 600 | 100%| 100% | 100% | 100% |

Caesar: 100% success from 50 letters (75% at 10 letters).
Breaking Vigenère on the 518-letter sample: ~7 ms. One AES password guess: ~32 ms (PBKDF2 slows down guessing on purpose).

**Conclusion:** classical ciphers keep the letter patterns of the language, so a few hundred letters are enough to recover the key automatically. A longer key only needs more text. AES hides all patterns; the only attack is guessing the key or password.
