import hashlib
import os
import json
import logging
from pathlib import Path

BASE_DIR = Path(__file__).resolve().parent
LOG_DIR = BASE_DIR / "logs"
LOG_DIR.mkdir(exist_ok=True)

LOG_FILE = LOG_DIR / "fim.log"

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s | %(levelname)s | %(message)s",
    handlers=[
        logging.FileHandler(LOG_FILE),
        logging.StreamHandler()
    ]
)

logger = logging.getLogger("FIM")

def get_file_hash(file_path, algorithm="sha256"):
    """
    Generate the cryptographic hash of a file.
    :parameter file_path: Path to the file
    :parameter algorithm: Hash algorithm (sha256, sha1, md5, etc.)    
    """
    file_path=Path(file_path)
    if not file_path.is_file():    
        logger.error(f"File not found: {file_path}")
        return None

    try:
        hash_func = hashlib.new(algorithm)

        with file_path.open("rb") as file:        
            for chunk in iter(lambda: file.read(4096), b""):
                hash_func.update(chunk) 

        logger.info(f"Hashed file: {file_path}")       
        return hash_func.hexdigest()

    except ValueError:
        logger.error(f"Unsupported hash algorithm: {algorithm}")
    except PermissionError:
        logger.error(f"Permission denied: {file_path}")
    except Exception as e:
        logger.error(f"Unexpected error hashing {file_path}: {e}")

    return None

def scan_and_hash_directory(directory_path, algorithm="sha256"):
    """
    Recursively scan a directory and calculate hashes for all files.

    :param directory_path: Path to the directory to scan
    :param algorithm: Hash algorithm (default: sha256)
    :return: Dictionary {relative_file_path: hash_value}
    """
    directory_path = Path(directory_path)
    file_hashes = {}

    if not directory_path.is_dir():        
        logger.error(f"Directory not found: {directory_path}")
        return file_hashes
    
    logger.info(f"Starting scan: {directory_path}")

    for file_path in directory_path.rglob("*"):
        if file_path.is_file():
            file_hash = get_file_hash(file_path, algorithm)
            if file_hash:
                # Store relative path for readability
                relative_path = file_path.relative_to(directory_path)
                file_hashes[str(relative_path)] = file_hash

    logger.info(f"Scan completed. Files hashed: {len(file_hashes)}")
    return file_hashes

def load_baseline(baseline_file):
    """
    Load baseline hashes from a JSON file.

    :param baseline_file: Path to baseline.json
    :return: Dictionary {relative_path: hash}
    """
    try:
        with open(baseline_file, "r") as f:
            return json.load(f)
    except FileNotFoundError:
        print(f"[ERROR] Baseline file not found: {baseline_file}")
    except json.JSONDecodeError:
        print(f"[ERROR] Invalid JSON in baseline file: {baseline_file}")
    except Exception as e:
        print(f"[ERROR] {e}")

    return {}

def compare_with_baseline(baseline_hashes, current_hashes):
    """
    Compare baseline hashes with current hashes.

    :param baseline_hashes: Dict from baseline.json
    :param current_hashes: Dict from current scan
    :return: Dict with detected changes
    """
    changes = {
        "modified": [],
        "new": [],
        "deleted": []
    }

    baseline_files = set(baseline_hashes.keys())
    current_files = set(current_hashes.keys())

    # Modified files
    for file in baseline_files & current_files:
        if baseline_hashes[file] != current_hashes[file]:
            changes["modified"].append(file)

    # New files
    for file in current_files - baseline_files:
        changes["new"].append(file)

    # Deleted files
    for file in baseline_files - current_files:
        changes["deleted"].append(file)

    return changes

def print_changes(changes):
    if not any(changes.values()):
        logger.info("No file changes detected.")
        return

    for file in changes["added"]:
        logger.warning(f"New file detected: {file}")

    for file in changes["removed"]:
        logger.warning(f"File removed: {file}")

    for file in changes["modified"]:
        logger.critical(f"File modified: {file}")

# IMPLEMENTATION
WATCHED_DIR = BASE_DIR / "watched"
BASELINE_FILE = BASE_DIR / "baseline.json"

if not BASELINE_FILE.exists():
    baseline_hashes = scan_and_hash_directory(WATCHED_DIR, algorithm="sha256")
    with open(BASELINE_FILE, "w") as f:
        json.dump(baseline_hashes, f, indent=4)
    print(f"[INFO] Baseline created at {BASELINE_FILE}")
else:
    print(f"[INFO] Baseline already exists at {BASELINE_FILE}")

baseline_hashes = load_baseline(BASELINE_FILE)
current_hashes = scan_and_hash_directory(WATCHED_DIR, algorithm="sha256")

changes = compare_with_baseline(baseline_hashes, current_hashes)

print_changes(changes)