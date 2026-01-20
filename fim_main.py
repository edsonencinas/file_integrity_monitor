import hashlib
import os
import json
from pathlib import Path
BASE_DIR = Path(__file__).resolve().parent
#LOG_DIR = BASE_DIR / "logs"

def get_file_hash(file_path, algorithm="sha256"):
    """
    Generate the cryptographic hash of a file.
    :parameter file_path: Path to the file
    :parameter algorithm: Hash algorithm (sha256, sha1, md5, etc.)    
    """
    file_path=Path(file_path)
    if not file_path.is_file():    
        print(f"[ERROR] File not found: {file_path}")
        return None

    try:
        hash_func = hashlib.new(algorithm)

        with file_path.open("rb") as file:        
            for chunk in iter(lambda: file.read(4096), b""):
                hash_func.update(chunk)        
        return hash_func.hexdigest()

    except ValueError:
        print(f"[ERROR] Unsupported hash algorithm: {algorithm}")
    except PermissionError:
        print(f"[ERROR] Permission denied: {file_path}")
    except Exception as e:
        print(f"[ERROR] {e}")

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
        print(f"[ERROR] Directory not found: {directory_path}")
        return file_hashes

    for file_path in directory_path.rglob("*"):
        if file_path.is_file():
            file_hash = get_file_hash(file_path, algorithm)
            if file_hash:
                # Store relative path for readability
                relative_path = file_path.relative_to(directory_path)
                file_hashes[str(relative_path)] = file_hash

    return file_hashes


#Call the Scan directory recursive
WATCHED_DIR = BASE_DIR / "watched"
baseline_hashes = scan_and_hash_directory(WATCHED_DIR)
# for file, hash_value in baseline_hashes.items():    
#     print(f"{file} -> {hash_value}")

BASELINE_FILE = BASE_DIR / "baseline.json"
# Save baseline
with open(BASELINE_FILE, "w") as f:
    json.dump(baseline_hashes, f, indent=4)

print(f"[INFO] Baseline saved to {BASELINE_FILE}")