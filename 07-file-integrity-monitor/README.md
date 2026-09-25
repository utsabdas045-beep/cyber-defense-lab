# File Integrity Monitoring System

A basic Python mini project that tracks important files and detects whether they
have been **modified, deleted, or replaced** by comparing SHA-256 hashes.

## Files

| File | Purpose |
|------|---------|
| `file_integrity_monitor.py` | Main program (menu: baseline, scan, continuous monitoring) |
| `demo_test.py` | Automatic demo and test that imports the monitor |
| `baseline.json` | Created by the program; stores the original hashes |
| `integrity_report.txt` | Created by the program; history of scan reports |

## Requirements

- Python 3.8+
- No extra packages (uses only `os`, `hashlib`, `json`, `time`, `datetime`)

## How to Run

```
python file_integrity_monitor.py
```

1. Choose **1** and enter the folder to monitor. This saves the original hashes.
2. Choose **2** to run one scan, or **3** for a scan every 10 seconds (Ctrl+C to stop).

To see it work without setting anything up:

```
python demo_test.py
```

## How It Works

1. **Baseline:** every file in the folder (and subfolders) is hashed with SHA-256
   and saved to `baseline.json`.
2. **Scan:** the folder is hashed again and compared with the baseline.
3. **Result per file:**
   - hash differs -> `[MODIFIED]` (this also covers a replaced file)
   - path not in baseline -> `[NEW]`
   - baseline path missing now -> `[DELETED]`
4. **Report:** the status (`OK` or `ALERT`) and the list of changes are printed
   and appended to `integrity_report.txt`.

## Sample Report

```
============================================================
Scan time : 2026-09-24 15:36:43
Folder    : /tmp/fim_test/data
Status    : ALERT - changes detected
------------------------------------------------------------
[MODIFIED] /tmp/fim_test/data/a.txt
[NEW]      /tmp/fim_test/data/d.txt
[DELETED]  /tmp/fim_test/data/b.txt
------------------------------------------------------------
Unchanged: 1 | Modified: 1 | New: 1 | Deleted: 1
============================================================
```

## Important Note

The baseline is **not** updated automatically after a scan. Otherwise a tampered
file would become the "trusted" version. Run option 1 again only when you trust
the current state of the folder.

## Ideas to Extend

- Detect renamed or moved files (same hash, different path)
- Send an email alert when changes are found
- Export the report as CSV or HTML
- Add a simple GUI with Tkinter