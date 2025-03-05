import hashlib
from werkzeug.utils import secure_filename

def create_file_hash(file_path):
    """
    Create SHA256 hash of a file.
    """
    hash_sha256 = hashlib.sha256()
    with open(file_path, "rb") as f:
        for chunk in iter(lambda: f.read(4096), b""):
            hash_sha256.update(chunk)
    return hash_sha256.hexdigest()

def sanitize_filename(name):
    """
    Sanitize the image name to create a valid filename.
    """
    sanitized = secure_filename(name.replace("/", "_").replace(":", "_"))
    return sanitized if sanitized else "unnamed_image"
