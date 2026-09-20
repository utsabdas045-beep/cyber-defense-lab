# Web Application Security Testing Tool

A lightweight scanner that checks a **local or test web application** for common security weaknesses and reports each one with a severity, evidence, and a suggested fix. It identifies problems only. It never exploits them.

Built as a Python mini project: **Python, Requests, BeautifulSoup and Flask**.

---

## Table of contents

1. [Features](#features)
2. [Project structure](#project-structure)
3. [Installation](#installation)
4. [Usage](#usage)
5. [What the scanner checks](#what-the-scanner-checks)
6. [How it works](#how-it-works)
7. [Scoring](#scoring)
8. [Safety and ethics](#safety-and-ethics)
9. [Example results](#example-results)
10. [Troubleshooting](#troubleshooting)
11. [Limitations](#limitations)
12. [Future scope](#future-scope)
13. [Disclaimer](#disclaimer)

---

## Features

- Web dashboard with a grade (A to F), a 0 to 100 score, and a severity summary bar
- Findings sorted by severity, each with a description, evidence, and a fix
- Filter findings by severity; download the report as **HTML** or **JSON**
- Command-line mode for quick scans and scripting
- Built-in scope guard: local and private-network targets only by default
- A deliberately weak practice app (`demo_target.py`) and a fixed version (`--hardened`) to compare before and after

---

## Project structure

```
websec-scanner/
├── app.py              Flask dashboard (scan form, report page, downloads)
├── scanner.py          Scanner engine and command-line interface
├── demo_target.py      Intentionally weak practice web app (+ --hardened mode)
├── requirements.txt    Python dependencies
├── README.md
├── templates/
│   ├── base.html       Shared page layout
│   ├── index.html      Scan form
│   └── results.html    Report page
└── static/
    └── style.css       Dashboard styles (inlined into downloaded reports)
```

---

## Installation

**Requirements:** Python 3.9 or newer.

### Recommended: use a separate environment

Do not install project packages into your conda `(base)` environment. Removing them later can break conda itself.

**Windows (PowerShell) with conda:**

```powershell
cd path\to\websec-scanner
conda create -n websec python=3.12 -y
conda activate websec
pip install -r requirements.txt
```

**Windows / macOS / Linux with venv:**

```bash
cd websec-scanner
python -m venv venv
venv\Scripts\activate          # Windows
source venv/bin/activate       # macOS / Linux
pip install -r requirements.txt
```

Dependencies: `flask`, `requests`, `beautifulsoup4`.

---

## Usage

The dashboard and the practice target are two separate programs. Run each in its own terminal, with the environment activated in both.

### 1. Start the practice target (terminal 1)

```bash
python demo_target.py               # weak version    -> http://127.0.0.1:5001
python demo_target.py --hardened    # fixed version   -> http://127.0.0.1:5002
```

### 2. Start the dashboard (terminal 2)

```bash
python app.py
```

Open **http://127.0.0.1:5000**, enter `http://127.0.0.1:5001` as the target, choose the checks, and click **Start scan**.

### Command-line mode

```bash
python scanner.py http://127.0.0.1:5001
python scanner.py http://127.0.0.1:5001 --json report.json
python scanner.py http://127.0.0.1:5001 --checks headers cookies --max-pages 5
```

| Option | Meaning | Default |
|---|---|---|
| `target` | URL of the application to scan | required |
| `--max-pages N` | Maximum pages to crawl (1 to 50) | 15 |
| `--delay S` | Seconds to wait between requests | 0.2 |
| `--checks ...` | Any of `headers cookies methods directories forms inputs` | all |
| `--test-post` | Also probe POST forms (submits forms) | off |
| `--json FILE` | Write the full report to a JSON file | off |
| `--i-have-permission` | Allow non-local targets (see [Safety](#safety-and-ethics)) | off |

---

## What the scanner checks

| Check | What it looks for |
|---|---|
| **Security headers** | Missing or weak Content-Security-Policy, HSTS (on HTTPS), clickjacking protection, `X-Content-Type-Options`, `Referrer-Policy`, `Permissions-Policy`; version leaks in `Server` and `X-Powered-By`; CORS `*` |
| **Cookies** | Missing `HttpOnly`, `Secure`, `SameSite`; `SameSite=None` without `Secure` |
| **HTTP methods** | `PUT`, `DELETE`, `TRACE`, `CONNECT` advertised in the `Allow` header; active `TRACE` echo test |
| **Exposed paths** | `/.env`, `/.git/HEAD`, admin and backup folders, database dumps, `phpinfo`, debug consoles, directory listings, `robots.txt` hints |
| **Form hygiene** | POST forms with no anti-CSRF token; password forms submitting over plain HTTP |
| **Input handling** | Harmless marker reflected without HTML encoding (possible XSS); database error or stack trace after a stray quote (possible SQL injection or verbose errors); HTTP 500 on unexpected input |

Every finding contains: **ID, title, severity, category, URL, description, evidence, fix**.

Severity levels: `critical`, `high`, `medium`, `low`, `info`.

---

## How it works

```
Target URL
   │
   ▼
normalize_target()  →  scope guard (is_local_target)
   │
   ▼
Fetch home page  →  Crawl same-origin pages (breadth-first, up to max pages)
   │
   ▼
Run selected checks
   headers · methods · directories · forms · inputs · cookies
   │
   ▼
Findings (deduplicated)  →  sort by severity  →  score and grade
   │
   ▼
Dashboard report  /  HTML download  /  JSON download
```

Key design points in `scanner.py`:

- **One request gateway (`_req`)**: every request goes through it, so the delay, the 400-request budget, timeouts, and error handling apply everywhere.
- **Deduplication (`_add`)**: the same issue is reported once, not once per page.
- **Soft-404 detection**: the scanner first requests a random path to learn how the server answers "not found", so servers that return 200 for everything do not produce false alarms.
- **Content signatures**: a file such as `/.env` is only reported if its content actually looks like an env file.
- **Redaction**: cookie values and `.env` secrets are masked in evidence.

---

## Scoring

```
penalty = 25 x critical + 15 x high + 8 x medium + 3 x low   (info adds 0)
score   = round( 100 x e^(-penalty / 60) )
```

| Score | Grade |
|---|---|
| 90 to 100 | A |
| 75 to 89 | B |
| 60 to 74 | C |
| 40 to 59 | D |
| below 40 | F |

The decay is smooth, so a badly broken app and a terrible one still get different scores.

---

## Safety and ethics

This tool must only be used on systems you own or have written permission to test.

- **Scope guard:** only `localhost` and private-network addresses are allowed by default. Testing anything else requires starting the dashboard with `WEBSEC_ALLOW_EXTERNAL=1` **and** ticking a permission checkbox for each scan (`--i-have-permission` on the command line).
- **No exploitation:** no attack payloads, no brute forcing, no password guessing. Input tests send one harmless marker and one stray quote per parameter and only observe the response.
- **`PUT` and `DELETE` are never sent.** They are only read from the `Allow` header.
- **POST forms are off by default.** Password and file fields are always skipped.
- **Polite scanning:** configurable delay, 400-request cap, same-origin crawl only, logout and delete links skipped.
- **The dashboard binds to `127.0.0.1` only.** It makes outgoing requests to whatever URL you enter, so do not expose it to a network.

---

## Example results

Scanning the built-in practice apps:

| Target | Score | Grade |
|---|---|---|
| `demo_target.py` (weak) | 11 / 100 | F |
| `demo_target.py --hardened` | 90 / 100 | A |

The weak app is reported for missing security headers, unflagged cookies, an open admin panel, a directory listing, an exposed `.env`, a login form without a CSRF token, advertised `PUT`/`DELETE`, unencoded input reflection, and a database error message. Applying the fixes and re-scanning shows the improvement.

*(Add your own screenshots here, for example `docs/dashboard.png` and `docs/report.png`.)*

---

## Troubleshooting

| Problem | Cause and fix |
|---|---|
| **"Could not reach http://127.0.0.1:5001"** | The target app is not running. Start `python demo_target.py` in a second terminal, then scan again. |
| **"This target is not a local or private address"** | The scope guard blocked it. Scan a local app, or see [Safety](#safety-and-ethics) if you are authorised to test an external one. |
| **`ModuleNotFoundError: No module named ...`** | Dependencies are missing in the active environment. Run `pip install -r requirements.txt`. |
| **conda errors with `No module named 'requests'`** | Packages were removed from `(base)`. Run `python -m pip install requests` to repair it, and use a separate environment for projects. |
| **"Address already in use"** | Another program is using port 5000, 5001 or 5002. Close it, or change the `port=` value at the bottom of `app.py` or `demo_target.py`. |
| **Report link says "no longer available"** | Reports are kept in memory (newest 20) and disappear when the dashboard restarts. Download the HTML or JSON to keep them. |
| **Fonts look different offline** | The page uses Google Fonts and falls back to system fonts when offline. |

---

## Limitations

- Automated scanners find only a subset of problems and can be wrong. Treat "possible" findings as leads to verify by hand.
- Only checks a limited set of common issues on pages reachable by crawling. It does not log in, run JavaScript, or test authenticated areas.
- The hardened demo still shows a `Server` version because Flask's development server adds its own header. Running behind gunicorn or nginx removes it.
- Scan history is not saved to disk.

---

## Future scope

- Login support so authenticated pages can be scanned
- Saved scan history (SQLite) and comparison between scans
- TLS certificate and protocol checks
- Open-redirect and cache-control checks
- Subresource integrity checks
- PDF report export
- Asynchronous scans with a live progress bar

---

## Disclaimer

This project is for education and for testing applications you own or are authorised to test. Scanning systems without permission may be illegal. The author accepts no responsibility for misuse.

---

## Author

Name: `<your name>`
Roll number: `<your roll number>`
Institution: `<your institution>`
