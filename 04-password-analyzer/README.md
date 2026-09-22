# 04 Password Strength Checker & Generator

A small Python project that checks how strong a password is and explains
why, and can also generate secure random passwords or passphrases.
Includes a simple Tkinter GUI. Everything runs locally — no password is
ever saved, logged, or sent anywhere.

## Features

- **Strength checker**
  - Checks length, uppercase, lowercase, digits, and special characters
  - Detects repeated characters/patterns (e.g. `aaa`, `abab`, `123123`)
  - Detects predictable sequences (e.g. `abcd`, `1234`, `qwerty`)
  - Detects common/dictionary words, even with leetspeak swaps (e.g. `P@ssw0rd`)
  - Estimates entropy (in bits) based on the character types used
  - Gives a score out of 100, a strength label, and a list of issues and suggestions
- **Password & passphrase generator**
  - Generates random passwords using Python's `secrets` module (cryptographically secure)
  - Lets you choose length, and whether to include numbers and special characters
  - Generates word-based passphrases (e.g. `Maple-River-stone-42`)
- **GUI (Tkinter)**
  - Two tabs: Check Password and Generate Password
  - Strength meter, colored strength label, and weakness explanation
  - Show/Hide toggle for the entered password
  - Copy-to-clipboard button for generated results

## Project Structure

```
password-checker/
├── password_analyzer.py    # Checks password strength and explains weaknesses
├── password_generator.py   # Generates secure passwords and passphrases
├── app.py                  # Tkinter GUI that ties the two together
└── README.md
```

`app.py` imports from the other two files, so all three must stay in the
same folder.

## Requirements

- Python 3.8 or newer
- No third-party packages needed — the project only uses Python's standard
  library: `math`, `re`, `string`, `getpass`, `secrets`, and `tkinter`.
- On Linux, Tkinter may need to be installed separately:
  ```
  sudo apt install python3-tk
  ```

## Setup (optional: using Miniconda)

```bash
conda create -n password-checker python=3.11
conda activate password-checker
python -c "import tkinter; print('tkinter OK')"
```

## How to Run

**GUI (recommended):**
```bash
python app.py
```

**Command-line strength checker only:**
```bash
python password_analyzer.py
```

**Command-line generator only:**
```bash
python password_generator.py
```

## How It Works

### `password_analyzer.py`
`check_password_strength(password)` runs a series of checks and returns a
dictionary:
```python
{
    "score": 62,
    "label": "Medium",
    "points": 48.3,          # estimated entropy in bits
    "issues": [...],         # list of weaknesses found
    "suggestions": [...]     # list of matching improvement tips
}
```
Points are added for length, character variety, and entropy, then reduced
for repeated patterns, predictable sequences, or common words. A common
word caps the score so it can never be rated above "Weak," even if the
password is long.

### `password_generator.py`
- `generate_password(length, use_numbers, use_special)` builds a password
  by picking at least one character from each required character type,
  filling the rest randomly, then shuffling — so required characters
  aren't always in predictable positions.
- `generate_passphrase(word_count)` picks random words from a small
  built-in word list, randomly capitalizes some, and appends a random
  number.

### `app.py`
A `PasswordApp` class builds a two-tab Tkinter window: one tab calls
`check_password_strength()` and displays the result, the other calls the
generator functions and displays + scores the result.

## Notes & Limitations

- This is a learning project, not a production security tool.
- The dictionary and word lists are intentionally small; add more words to
  `COMMON_WORDS` (in `password_analyzer.py`) and `WORD` (in
  `password_generator.py`) to make both parts stronger.
- Entropy is an estimate based on character variety, not a guarantee of
  real-world crack resistance.

## Possible Future Improvements

- Load a larger common-password list from a file
- Add a "time to crack" estimate
- Add a Streamlit or web version
- Save generator preferences between runs (without ever saving the password itself)