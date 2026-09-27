"""On-disk header of an encrypted file (format version 1).

Layout, all integers big-endian::

    offset  size  field
    0       8     magic  b"AESFILE\\0"
    8       1     format version (1)
    9       1     payload type (0 = single file, 1 = directory as tar)
    10      1     KDF id (1 = Argon2id, 2 = scrypt)
    11      12    three uint32 KDF parameters
    23      4     plaintext chunk size in bytes
    27      16    KDF salt
    43      7     nonce prefix for the chunk stream
    50      32    HMAC-SHA256 of bytes 0..49 under a key derived from the password
    82            first ciphertext chunk

Bytes 0..49 are also passed as associated data to every AES-GCM chunk, so the header and
the payload are bound together: changing any header field breaks both checks.
"""

from __future__ import annotations

import enum
import os
import struct
from dataclasses import dataclass, field
from typing import BinaryIO

from .errors import FormatError
from .kdf import SALT_LENGTH, KdfParams, params_from_fields

MAGIC = b"AESFILE\x00"
FORMAT_VERSION = 1
NONCE_PREFIX_LENGTH = 7
MAC_LENGTH = 32

DEFAULT_CHUNK_SIZE = 64 * 1024
MIN_CHUNK_SIZE = 16
MAX_CHUNK_SIZE = 16 * 1024 * 1024

_FIELDS = struct.Struct(f">{len(MAGIC)}sBBBIIII{SALT_LENGTH}s{NONCE_PREFIX_LENGTH}s")
HEADER_LENGTH = _FIELDS.size  # authenticated fields, excluding the MAC
TOTAL_HEADER_LENGTH = HEADER_LENGTH + MAC_LENGTH


class PayloadType(enum.IntEnum):
    """What the decrypted byte stream represents."""

    FILE = 0
    DIRECTORY = 1


@dataclass(frozen=True)
class Header:
    """Parameters needed to derive the key and decrypt the payload."""

    payload_type: PayloadType
    kdf: KdfParams
    chunk_size: int = DEFAULT_CHUNK_SIZE
    salt: bytes = field(default_factory=lambda: os.urandom(SALT_LENGTH))
    nonce_prefix: bytes = field(default_factory=lambda: os.urandom(NONCE_PREFIX_LENGTH))
    version: int = FORMAT_VERSION

    def __post_init__(self) -> None:
        if not MIN_CHUNK_SIZE <= self.chunk_size <= MAX_CHUNK_SIZE:
            raise FormatError(f"Chunk size {self.chunk_size} is out of range.")
        if len(self.salt) != SALT_LENGTH or len(self.nonce_prefix) != NONCE_PREFIX_LENGTH:
            raise FormatError("Malformed salt or nonce.")

    def pack(self) -> bytes:
        """Serialise the authenticated header fields (without the MAC)."""
        return _FIELDS.pack(
            MAGIC,
            self.version,
            self.payload_type,
            self.kdf.algorithm,
            *self.kdf.to_fields(),
            self.chunk_size,
            self.salt,
            self.nonce_prefix,
        )

    @classmethod
    def unpack(cls, data: bytes) -> Header:
        """Parse and validate header fields. Does not check the MAC (that needs the key)."""
        if len(data) < HEADER_LENGTH:
            raise FormatError("Not an encrypted file (too short).")
        magic, version, payload, kdf_id, f1, f2, f3, chunk_size, salt, prefix = _FIELDS.unpack(
            data[:HEADER_LENGTH]
        )
        if magic != MAGIC:
            raise FormatError("Not an encrypted file (unrecognised header).")
        if version != FORMAT_VERSION:
            raise FormatError(f"Unsupported format version {version}; this tool reads version {FORMAT_VERSION}.")
        try:
            payload_type = PayloadType(payload)
        except ValueError:
            raise FormatError(f"Unknown payload type {payload}.") from None
        return cls(
            payload_type=payload_type,
            kdf=params_from_fields(kdf_id, (f1, f2, f3)),
            chunk_size=chunk_size,
            salt=salt,
            nonce_prefix=prefix,
            version=version,
        )


def read_header(stream: BinaryIO) -> tuple[Header, bytes, bytes]:
    """Read the header from ``stream``.

    Returns the parsed header, the raw authenticated bytes (used as AAD) and the stored MAC.
    """
    raw = stream.read(TOTAL_HEADER_LENGTH)
    if len(raw) < TOTAL_HEADER_LENGTH:
        # Distinguish "some random short file" from "our file, cut off inside the header".
        if raw.startswith(MAGIC):
            raise FormatError("Encrypted file is truncated (incomplete header).")
        raise FormatError("Not an encrypted file (too short).")
    header = Header.unpack(raw)
    return header, raw[:HEADER_LENGTH], raw[HEADER_LENGTH:]
