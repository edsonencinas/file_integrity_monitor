import hashlib
import os
import json
import logging
import argparse
from pathlib import Path

BASE_DIR = Path(__file__).resolve().parent
LOG_DIR = BASE_DIR / "logs"
LOG_DIR.mkdir(exist_ok=True)

LOG_FILE = LOG_DIR / "fim.log"

def parse_arguments():
    parser = argparse.ArgumentParser(
        description="File Interity Monitoring (FIM) Tool"
    )
    parser.add_argument(
        "--init",
        action="store_true",
        help="Initialize baseline hashes"
    )

    parser.add_argument(
        "--check",
        action="store_true",
        help="Check files against baseline"
    )

    return parser.parse_args()

def validate_arguments(args):
    if not args.init and not args.check:
        logger.error("No action specified. Use --init or --check.")
        exit(1)
    
    if args.init and args.check:
        logger.error("Choose only one action: --init OR --check.")
        exit(1)

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
    if not baseline_file.exists():
        logger.error("Baseline file not found. Run with --init first.")
        exit(1)
    
    try:
        with open(baseline_file, "r") as f:
            baseline_hashes=json.load(f)

        logger.info("Baseline loaded successfully.")
        return baseline_hashes

    except Exception as e:
        logger.error(f"Failed to load baseline: {e}")
        exit(1)    


def save_baseline(baseline_hashes, baseline_file, algorithm="sha256"):
    try:
        with open(baseline_file, "w")as f:
            json.dump(baseline_hashes, f, indent=4)

        baseline_hash=get_file_hash(baseline_file, algorithm)
        
        with open(BASELINE_HASH_FILE, "w") as f:
            f.write(baseline_hash)

        logger.info("Baseline and baseline hash saved securely")

    except Exception as e:
        logger.error(f"Failed to save baseline: {e}")
        exit(1)

def verify_baseline_integrity(baseline_file, baseline_hash_file, algorithm="sha256"):
    if not baseline_hash_file.exists():
        logger.critical("Baseline hash file missing! Possible tampering.")
        exit(1)
    
    current_hash= get_file_hash(baseline_file, algorithm)

    with open(baseline_hash_file, "r") as f:
        stored_hash=f.read().strip()

    if current_hash != stored_hash:
        logger.critical("Baseline integrity check FAILED! Baseline was modified.")
        exit(1)
    
    logger.info("Baseline integrity verified.")

def compare_with_baseline(baseline_hashes, current_hashes):
    """
    Compare baseline hashes with current hashes.

    :param baseline_hashes: Dict {file_path: hash}
    :param current_hashes: Dict {file_path: hash}
    :return: dict containing detected changes
    """
    changes = {
        "new": [],
        "deleted": [],
        "modified": []
    }

    # baseline_files = set(baseline_hashes.keys())
    # current_files = set(current_hashes.keys())

    # Detect new and modified files.
    for file_path, current_hash in current_hashes.items():
        if file_path not in baseline_hashes:
            changes["new"].append(file_path)
        elif baseline_hashes[file_path] != current_hash:
            changes["modified"].append(file_path)
    
    # Detect deleted files
    for file_path in baseline_hashes:
        if file_path not in current_hashes:
            changes["deleted"].append(file_path)   

    return changes

def print_changes(changes):
    if not any(changes.values()):
        logger.info("No file changes detected.")
        return

    for file in changes["new"]:
        logger.warning(f"New file detected: {file}")

    for file in changes["deleted"]:
        logger.warning(f"File removed: {file}")

    for file in changes["modified"]:
        logger.critical(f"File modified: {file}")

# IMPLEMENTATION
WATCHED_DIR = BASE_DIR / "watched"
BASELINE_FILE = BASE_DIR / "baseline.json"
BASELINE_HASH_FILE = BASE_DIR / "baseline.hash"
#------ MAIN CONTROL -------
if __name__ == "__main__":
    args= parse_arguments()
    validate_arguments(args)

    if args.init:
        logger.info("Initializing baseline...")
        baseline_hashes=scan_and_hash_directory(WATCHED_DIR)
        save_baseline(baseline_hashes, BASELINE_FILE)
        logger.info("Baseline successfully created.")

    elif args.check:
        logger.info("Verifying baseline integrity...")
        verify_baseline_integrity(BASELINE_FILE, BASELINE_HASH_FILE)

        logger.info("Checking file integrity...")
        baseline_hashes=load_baseline(BASELINE_FILE)
        current_hashes=scan_and_hash_directory(WATCHED_DIR)
        changes=compare_with_baseline(baseline_hashes,current_hashes)
        print_changes(changes)



