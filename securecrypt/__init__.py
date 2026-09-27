"""Password-based AES-256-GCM encryption for files and directories."""

from .errors import FormatError, IntegrityError, OutputExistsError, SecureCryptError, WrongPasswordError
from .operations import Removal, decrypt_path, encrypt_path, inspect_path, verify_path

__version__ = "1.0.0"

__all__ = [
    "FormatError",
    "IntegrityError",
    "OutputExistsError",
    "Removal",
    "SecureCryptError",
    "WrongPasswordError",
    "__version__",
    "decrypt_path",
    "encrypt_path",
    "inspect_path",
    "verify_path",
]
