# File Integrity Monitoring (FIM)

A Python-based **File Integrity Monitoring (FIM) tool** for detecting unauthorized file changes, creation, and deletion.  
This project is designed to demonstrate **real-world cybersecurity skills**, including hashing, logging, baseline protection, and automated monitoring.

---

## Features

- **Recursive Directory Scanning**  
  Scans all files and subdirectories in the watched folder.

- **Cryptographic Hashing**  
  Uses SHA-256 (configurable) to detect file modifications securely.

- **Baseline Management**  
  Stores a snapshot of file hashes (`baseline.json`) for future comparison.

- **Change Detection**  
  Detects:
  - Modified files
  - New files
  - Deleted files

- **Baseline Tampering Detection**  
  Verifies the integrity of the baseline itself using a separate hash (`baseline.hash`).

- **Logging**  
  All operations and alerts are logged to `logs/fim.log` with severity levels (INFO, WARNING, CRITICAL).

- **Command-Line Interface (CLI)**  
  Use `--init` to create a baseline or `--check` to check file integrity.

- **Scheduled Execution Ready**  
  Compatible with Windows Task Scheduler or Linux cron for automated monitoring.

---

## Project Structure

File-Integrity-Monitor/
├── fim_main.py # Main Python script
├── baseline.json # Baseline file (generated)
├── baseline.hash # Hash of baseline for tamper detection
├── logs/ # Log files (fim.log)
├── watched/ # Directory to monitor
├── .gitignore # Excludes logs and other temp files
└── README.md # Project documentation

## Installation

### 1. Clone the repository:

```
git clone https://github.com/yourusername/file-integrity-monitor.git
cd file-integrity-monitor
```

### 2. Make sure Python 3.9+ is installed.

### 3. Optional: Create a virtual environment:

```
python -m venv venv
source venv/bin/activate   # Linux/Mac
venv\Scripts\activate      # Windows
```

## Usage

### 1. Initialize Baseline

```
python fim_main.py --init
```

- Scans the watched/ directory
- Creates baseline.json and baseline.hash
- Logs operations to logs/fim.log

### 2. Check File Integrity

```
python fim_main.py --check
```

- Verifies the baseline integrity
- Scans all files and compares to baseline
- Logs and prints alerts:
  - New files
  - Deleted files
  - Modified files

### 3. Scheduled Execution

Windows Task Scheduler:

- Program: `python`
- Arguments: `"C:\path\to\fim_main.py" --check`
- Start in: `"C:\path\to\"`

Linux cron:

```
0 * * * * /usr/bin/python3 /path/to/fim_main.py --check >> /path/to/fim.log 2>&1
```

## Security Notes

- Do not commit logs/ or fim.log to GitHub.
- Baseline is protected via baseline.hash to prevent tampering.
- SHA-256 hashing ensures cryptographic integrity of files.

## Example Output

```
INFO | Starting scan: watched
INFO | Hashed file: watched/file_1.txt
CRITICAL | File modified: config/settings.ini
WARNING  | New file detected: malware.exe
WARNING  | File removed: logs/old.log
INFO | Scan completed. Files hashed: 12
```

## Skills Demonstrated

- Python scripting and modular design
- File integrity monitoring (hashing + baseline)
- Logging and alerting
- CLI tool development (argparse)
- Scheduled task automation (cron / Windows Task Scheduler)
- Cybersecurity best practices
