"""Exception hierarchy.

Every error the library raises deliberately derives from :class:`SecureCryptError`, so
front ends can catch one type and show its message to the user verbatim.
"""

from __future__ import annotations


class SecureCryptError(Exception):
    """Base class for all expected, user-facing failures."""


class FormatError(SecureCryptError):
    """The input is not an encrypted file this version understands."""


class WrongPasswordError(SecureCryptError):
    """The header MAC did not verify.

    AES-GCM cannot tell a wrong key from a modified header, so the message says both.
    """

    def __init__(self, message: str = "Wrong password, or the file header has been modified.") -> None:
        super().__init__(message)


class IntegrityError(SecureCryptError):
    """The payload failed authentication: it was modified, reordered or truncated."""


class OutputExistsError(SecureCryptError):
    """Refusing to overwrite an existing path."""
