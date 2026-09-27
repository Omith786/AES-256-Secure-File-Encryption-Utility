"""Chunked AES-256-GCM streaming encryption.

The plaintext is split into fixed-size chunks and each chunk is sealed independently with
AES-256-GCM, so memory use is bounded by the chunk size rather than the file size. This
follows the STREAM construction (Hoang, Reyhanitabar, Rogaway and Vizar, 2015), with the
same nonce layout as Google Tink's streaming AEAD::

    nonce (12 bytes) = prefix (7 random bytes) || counter (uint32) || last-chunk flag (1 byte)

The counter stops chunks being reordered or dropped from the middle, and the flag marks
the final chunk so that cutting the file at a chunk boundary is detected rather than
silently producing a shorter plaintext.
"""

from __future__ import annotations

import hmac
import struct
from collections.abc import Iterator
from dataclasses import dataclass
from hashlib import sha256
from typing import BinaryIO

from cryptography.exceptions import InvalidTag
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives.kdf.hkdf import HKDF

from .errors import IntegrityError, WrongPasswordError
from .header import Header, read_header
from .kdf import KEY_LENGTH, derive_master_key

TAG_LENGTH = 16
MAX_CHUNKS = 2**32  # the counter is 32 bits wide


@dataclass(frozen=True)
class FileKeys:
    """Independent subkeys, so the header MAC key is never used as an AES key."""

    payload_key: bytes
    header_mac_key: bytes


def derive_file_keys(password: str, header: Header) -> FileKeys:
    """Run the (slow) password KDF once, then split the result with HKDF-SHA256."""
    master = derive_master_key(password, header.salt, header.kdf)

    def expand(label: bytes) -> bytes:
        return HKDF(algorithm=hashes.SHA256(), length=KEY_LENGTH, salt=None, info=label).derive(master)

    return FileKeys(
        payload_key=expand(b"AESFILE v1 payload key"),
        header_mac_key=expand(b"AESFILE v1 header mac key"),
    )


def header_mac(keys: FileKeys, header_bytes: bytes) -> bytes:
    """HMAC-SHA256 over the serialised header fields."""
    return hmac.new(keys.header_mac_key, header_bytes, sha256).digest()


def _chunk_nonce(prefix: bytes, counter: int, last: bool) -> bytes:
    if counter >= MAX_CHUNKS:
        raise IntegrityError("Too many chunks for one file at this chunk size.")
    return prefix + struct.pack(">IB", counter, 1 if last else 0)


class EncryptWriter:
    """Write-only file-like object that encrypts everything written to it.

    It keeps at most one chunk (plus whatever the caller last wrote) in memory. A chunk is
    only sealed once more data has arrived after it, because until then we do not know
    whether it is the final one. :meth:`close` seals the remainder as the final chunk; an
    empty input still produces one (empty) final chunk so that truncation to zero bytes
    of payload is detectable.
    """

    def __init__(self, sink: BinaryIO, header: Header, keys: FileKeys) -> None:
        self._sink = sink
        self._aead = AESGCM(keys.payload_key)
        self._aad = header.pack()
        self._prefix = header.nonce_prefix
        self._chunk_size = header.chunk_size
        self._buffer = bytearray()
        self._counter = 0
        self._closed = False

        sink.write(self._aad)
        sink.write(header_mac(keys, self._aad))

    def _seal(self, data: bytes, last: bool) -> None:
        nonce = _chunk_nonce(self._prefix, self._counter, last)
        self._sink.write(self._aead.encrypt(nonce, data, self._aad))
        self._counter += 1

    def write(self, data: bytes) -> int:
        if self._closed:
            raise ValueError("write to closed EncryptWriter")
        self._buffer += data
        # Strictly greater: a buffer of exactly one chunk might turn out to be the last.
        while len(self._buffer) > self._chunk_size:
            self._seal(bytes(self._buffer[: self._chunk_size]), last=False)
            del self._buffer[: self._chunk_size]
        return len(data)

    def close(self) -> None:
        """Seal the final chunk. Does not close the underlying sink."""
        if self._closed:
            return
        self._seal(bytes(self._buffer), last=True)
        self._buffer.clear()
        self._closed = True

    def __enter__(self) -> EncryptWriter:
        return self

    def __exit__(self, exc_type: object, *_: object) -> None:
        # On error, leave the stream unfinished; the caller discards the partial output.
        if exc_type is None:
            self.close()


def _read_exact(stream: BinaryIO, size: int) -> bytes:
    """Read up to ``size`` bytes, looping over short reads; fewer means EOF."""
    parts: list[bytes] = []
    remaining = size
    while remaining:
        block = stream.read(remaining)
        if not block:
            break
        parts.append(block)
        remaining -= len(block)
    return b"".join(parts)


class DecryptReader:
    """Read-only file-like object yielding authenticated plaintext.

    Every chunk is verified before any of its bytes are returned. The one thing that can
    only be known at the end is whether the stream was cut short, so callers must consume
    the reader to EOF (and treat an exception as "discard everything") before trusting the
    output. :mod:`securecrypt.operations` does this by writing to a temporary path.
    """

    def __init__(self, source: BinaryIO, header: Header, header_bytes: bytes, keys: FileKeys) -> None:
        self._source = source
        self._aead = AESGCM(keys.payload_key)
        self._aad = header_bytes
        self._prefix = header.nonce_prefix
        self._sealed_size = header.chunk_size + TAG_LENGTH
        self._chunks = self._iter_chunks()
        self._pending = b""
        self._eof = False

    def _iter_chunks(self) -> Iterator[bytes]:
        counter = 0
        current = _read_exact(self._source, self._sealed_size)
        if not current:
            raise IntegrityError("Encrypted file is truncated (no data after the header).")
        while True:
            # One chunk of look-ahead tells us whether ``current`` should carry the last flag.
            following = _read_exact(self._source, self._sealed_size)
            last = not following
            nonce = _chunk_nonce(self._prefix, counter, last)
            try:
                yield self._aead.decrypt(nonce, current, self._aad)
            except InvalidTag:
                if last:
                    raise IntegrityError(
                        "Encrypted file is truncated, has extra data appended, or its final chunk was modified."
                    ) from None
                raise IntegrityError(f"Chunk {counter} failed authentication: the file has been modified.") from None
            if last:
                return
            counter += 1
            current = following

    def chunks(self) -> Iterator[bytes]:
        """Yield plaintext chunk by chunk. Exhausting it proves the stream is complete."""
        yield from self._chunks

    def read(self, size: int = -1) -> bytes:
        """File-like read, so the reader can feed :mod:`tarfile` directly."""
        if size is None or size < 0:
            out = self._pending + b"".join(self._chunks)
            self._pending = b""
            return out
        while len(self._pending) < size and not self._eof:
            try:
                self._pending += next(self._chunks)
            except StopIteration:
                self._eof = True
        out, self._pending = self._pending[:size], self._pending[size:]
        return out


def open_decryptor(source: BinaryIO, password: str) -> tuple[Header, DecryptReader]:
    """Parse the header, check the password against the header MAC, and return a reader.

    Raises :class:`WrongPasswordError` before any payload is touched if the MAC fails.
    """
    header, header_bytes, stored_mac = read_header(source)
    keys = derive_file_keys(password, header)
    if not hmac.compare_digest(header_mac(keys, header_bytes), stored_mac):
        raise WrongPasswordError()
    return header, DecryptReader(source, header, header_bytes, keys)
