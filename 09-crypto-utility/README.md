# Secure File Encryption/Decryption Utility

A simple Python mini project that encrypts and decrypts files using
**Fernet** from the standard `cryptography` library (AES + HMAC).

## Why not write our own algorithm?
Homemade cryptography almost always has hidden flaws. Fernet is audited,
handles randomness and padding, and detects tampering automatically.

## Files
| File | Purpose |
|------|---------|
| `encoder.py` | Selects a file and encrypts it to `<name>.enc` |
| `decoder.py` | Selects a `.enc` file and decrypts it to `decrypted_<name>` |
| `main.py` | Menu that runs the encoder/decoder (start here) |
| `requirements.txt` | Dependencies |

## Setup
    pip install -r requirements.txt

## Run
    python main.py          # menu-based use
    python encoder.py       # encrypt only
    python decoder.py       # decrypt only

## How it works
1. **File selection** - a file dialog opens (typed path if no GUI).
2. **Encrypt/Decrypt** - Fernet uses the key stored in `secret.key`.
3. **Integrity/error handling** - a wrong key or modified file raises
   `InvalidToken`, which is caught and explained. Missing file, missing
   key and permission errors are handled too.

## Important notes
- Keep `secret.key` safe and separate from encrypted files. Anyone with
  the key can decrypt your data.
- Generating a new key means old `.enc` files can no longer be decrypted.
- Originals are never overwritten; new files are created instead.