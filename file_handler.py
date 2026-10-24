"""
file_handler.py — Secure File Management for VirusGuard

Provides secure file handling, validation, sanitization, hashing,
and ephemeral quarantine management.
"""

import os
import hashlib
import uuid
from werkzeug.utils import secure_filename

# 32MB default upload limit (matches VirusTotal direct upload limit)
MAX_FILE_SIZE_BYTES = 32 * 1024 * 1024

# Allowed scanning extensions (broad coverage for binaries, docs, archives, scripts)
ALLOWED_EXTENSIONS = {
    # Binaries & Executables
    'exe', 'dll', 'bin', 'elf', 'so', 'dylib', 'msi', 'com', 'scr', 'sys',
    # Archives & Compressed
    'zip', 'rar', '7z', 'tar', 'gz', 'bz2', 'xz', 'iso', 'cab',
    # Documents
    'pdf', 'doc', 'docx', 'xls', 'xlsx', 'ppt', 'pptx', 'odt', 'rtf', 'txt',
    # Scripts & Code
    'py', 'js', 'vbs', 'ps1', 'sh', 'bat', 'cmd', 'php', 'html', 'apk', 'jar'
}


def is_allowed_file(filename: str) -> bool:
    """Verifies that the file has a recognizable extension."""
    if not filename or '.' not in filename:
        return False
    ext = filename.rsplit('.', 1)[1].lower()
    return ext in ALLOWED_EXTENSIONS


def calculate_sha256(file_path: str) -> str:
    """Calculates SHA-256 cryptographic hash of a file on disk."""
    sha256_hash = hashlib.sha256()
    with open(file_path, "rb") as f:
        for byte_block in iter(lambda: f.read(65536), b""):
            sha256_hash.update(byte_block)
    return sha256_hash.hexdigest()


def save_file(file, upload_folder: str) -> tuple[str, str, str]:
    """
    Safely sanitizes and stores an uploaded file in the quarantine directory.

    Returns:
        tuple (file_path, original_filename, file_sha256)
    """
    os.makedirs(upload_folder, exist_ok=True)
    
    # Sanitize the original filename for safe display
    original_filename = secure_filename(file.filename) or "unnamed_sample"
    
    # Extract extension safely
    _, ext = os.path.splitext(original_filename)
    safe_ext = ext.lower() if ext else ".bin"
    
    # Store with random UUID to prevent path traversal, overwrites, or execution
    random_name = f"{uuid.uuid4().hex}{safe_ext}"
    file_path = os.path.join(upload_folder, random_name)
    
    if hasattr(file, 'save'):
        file.save(file_path)
    else:
        with open(file_path, "wb") as f:
            f.write(file.read())

    file_sha256 = calculate_sha256(file_path)
    
    return file_path, original_filename, file_sha256


def delete_file(file_path: str) -> bool:
    """Safely removes a quarantined file from disk after scanning."""
    try:
        if file_path and os.path.exists(file_path):
            os.remove(file_path)
            return True
    except OSError as err:
        print(f"[file_handler] Error deleting file {file_path}: {err}")
    return False
