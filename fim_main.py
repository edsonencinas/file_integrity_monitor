import hashlib
import os
from pathlib import Path
BASE_DIR = Path(__file__).resolve().parent
LOG_DIR = BASE_DIR / "logs"

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

def scan_directory_recursive(directory_path):
    """
    Recursively scan a directory and return a list of all files.

    :param directory_path: Path to the directory to scan
    :return: List of Path objects (files only)
    """
    directory_path = Path(directory_path)

    if not directory_path.is_dir():
        print(f"[ERROR] Directory not found: {directory_path}")
        return []

    files = []

    for path in directory_path.rglob("*"):
        if path.is_file():
            files.append(path)

    return files

#Call the file_hash function
watched_file = BASE_DIR / "watched" / "file_1.txt"
file_hash = get_file_hash(watched_file)

if file_hash:
    print(f"SHA-256 Hash: {file_hash}")

#Call the Scan directory recursive
WATCHED_DIR = BASE_DIR / "watched"

files = scan_directory_recursive(WATCHED_DIR)

for file in files:
    print(file)
