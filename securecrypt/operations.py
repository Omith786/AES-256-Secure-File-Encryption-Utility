"""High-level file and directory operations used by both the CLI and the GUI.

Outputs are always written to a temporary path next to the destination and renamed into
place only after the whole stream has been processed. For decryption this matters for
security as well as tidiness: a truncated or tampered file is only detected at the point
the bad chunk is reached, and the partial plaintext before it must never be left looking
like a finished result.
"""

from __future__ import annotations

import enum
import os
import shutil
import tarfile
import tempfile
from collections.abc import Iterator
from contextlib import contextmanager, suppress
from dataclasses import dataclass, field
from pathlib import Path
from typing import BinaryIO

from .errors import FormatError, OutputExistsError, SecureCryptError
from .header import DEFAULT_CHUNK_SIZE, Header, PayloadType, read_header
from .kdf import KdfParams, default_params
from .shred import remove_path
from .stream import DecryptReader, EncryptWriter, derive_file_keys, open_decryptor

ENCRYPTED_SUFFIX = ".enc"
_COPY_BLOCK = 1024 * 1024


class Removal(enum.Enum):
    """What to do with the original after a successful, verified encryption."""

    KEEP = "keep"
    DELETE = "delete"
    SHRED = "shred"


@dataclass
class EncryptResult:
    """Outcome of :func:`encrypt_path`."""

    source: Path
    output: Path
    original_removed: bool = False
    skipped: list[str] = field(default_factory=list)


@dataclass
class DecryptResult:
    """Outcome of :func:`decrypt_path`."""

    source: Path
    output: Path
    payload_type: PayloadType


def default_encrypted_path(source: Path) -> Path:
    """``report.pdf`` becomes ``report.pdf.enc``; a directory ``photos`` becomes ``photos.enc``."""
    return source.with_name(source.name + ENCRYPTED_SUFFIX)


def default_decrypted_path(source: Path) -> Path:
    """Strip a trailing ``.enc``, or append ``.decrypted`` if there is none."""
    if source.suffix == ENCRYPTED_SUFFIX and source.stem:
        return source.with_name(source.stem)
    return source.with_name(source.name + ".decrypted")


@contextmanager
def _atomic_file(target: Path, *, overwrite: bool) -> Iterator[BinaryIO]:
    """Yield a temporary file that replaces ``target`` only if the block succeeds.

    ``mkstemp`` creates the file with mode 0600, which is kept after the rename: decrypted
    output is readable by the current user only.
    """
    if target.is_dir():
        raise OutputExistsError(f"{target} is a directory.")
    if target.exists() and not overwrite:
        raise OutputExistsError(f"{target} already exists (use --force to overwrite).")
    target.parent.mkdir(parents=True, exist_ok=True)
    fd, tmp_name = tempfile.mkstemp(dir=target.parent, prefix=f".{target.name}.", suffix=".part")
    try:
        with os.fdopen(fd, "wb") as handle:
            yield handle
            handle.flush()
            os.fsync(handle.fileno())
        os.replace(tmp_name, target)
    except BaseException:
        with suppress(FileNotFoundError):
            os.unlink(tmp_name)
        raise


def _archive_directory(directory: Path, arcname: str, sink: EncryptWriter) -> list[str]:
    """Stream ``directory`` as a tar archive into ``sink``; return entries that were skipped.

    Only regular files, directories and hard links are archived. Symlinks and special
    files are skipped (and reported) rather than stored, because Python's safe ``data``
    extraction filter refuses links pointing outside the tree, which could otherwise make
    an archive impossible to restore after the original was deleted.
    """
    skipped: list[str] = []

    def keep(info: tarfile.TarInfo) -> tarfile.TarInfo | None:
        if info.isfile() or info.isdir() or info.islnk():
            return info
        skipped.append(info.name)
        return None

    with tarfile.open(fileobj=sink, mode="w|", format=tarfile.PAX_FORMAT) as tar:
        tar.add(directory, arcname=arcname, filter=keep)
    return skipped


def encrypt_path(
    source: str | os.PathLike[str],
    password: str,
    *,
    output: str | os.PathLike[str] | None = None,
    kdf: KdfParams | None = None,
    chunk_size: int = DEFAULT_CHUNK_SIZE,
    overwrite: bool = False,
    removal: Removal = Removal.KEEP,
) -> EncryptResult:
    """Encrypt a file or directory tree to a single ``.enc`` file.

    If ``removal`` is not ``KEEP``, the new file is decrypted and checked in full before
    the original is deleted, and the original is kept if any directory entries had to be
    skipped.
    """
    given = Path(source)
    if not given.exists():
        raise SecureCryptError(f"{given}: no such file or directory.")
    real = given.resolve()
    is_dir = real.is_dir()
    if not is_dir and not real.is_file():
        raise SecureCryptError(f"{given} is not a regular file or directory.")

    target = Path(output) if output is not None else default_encrypted_path(given)
    resolved_target = target.resolve()
    if resolved_target == real or (is_dir and resolved_target.is_relative_to(real)):
        raise SecureCryptError("The output must not be the input or lie inside the input directory.")

    header = Header(
        payload_type=PayloadType.DIRECTORY if is_dir else PayloadType.FILE,
        kdf=kdf or default_params(),
        chunk_size=chunk_size,
    )
    keys = derive_file_keys(password, header)

    skipped: list[str] = []
    with _atomic_file(target, overwrite=overwrite) as sink:
        with EncryptWriter(sink, header, keys) as writer:
            if is_dir:
                skipped = _archive_directory(real, given.name, writer)
            else:
                with open(real, "rb") as plain:
                    while block := plain.read(_COPY_BLOCK):
                        writer.write(block)

    result = EncryptResult(source=given, output=target, skipped=skipped)
    if removal is not Removal.KEEP and not skipped:
        verify_path(target, password)
        remove_path(real, shred=removal is Removal.SHRED)
        result.original_removed = True
    return result


def _extract_archive(reader: DecryptReader, target: Path) -> None:
    staging = Path(tempfile.mkdtemp(dir=target.parent, prefix=f".{target.name}.", suffix=".part"))
    try:
        try:
            with tarfile.open(fileobj=reader, mode="r|") as tar:
                tar.extractall(staging, filter="data")
        except tarfile.TarError as exc:
            raise FormatError(f"Decrypted archive is invalid: {exc}") from exc
        # tarfile stops reading at the end-of-archive marker, which need not be the end of
        # the stream. Drain the rest so the final chunk, and with it the truncation check,
        # is always authenticated before the result is moved into place.
        while reader.read(_COPY_BLOCK):
            pass
        entries = list(staging.iterdir())
        if len(entries) != 1 or not entries[0].is_dir() or entries[0].is_symlink():
            raise FormatError("Decrypted archive does not contain a single top-level directory.")
        os.rename(entries[0], target)
    finally:
        shutil.rmtree(staging, ignore_errors=True)


def decrypt_path(
    source: str | os.PathLike[str],
    password: str,
    *,
    output: str | os.PathLike[str] | None = None,
    overwrite: bool = False,
) -> DecryptResult:
    """Decrypt a ``.enc`` file back to the original file or directory.

    Nothing appears at the output path unless the whole file authenticates. Existing
    directories are never overwritten, even with ``overwrite``.
    """
    src = Path(source)
    target = Path(output) if output is not None else default_decrypted_path(src)
    with open(src, "rb") as handle:
        header, reader = open_decryptor(handle, password)
        if header.payload_type is PayloadType.FILE:
            with _atomic_file(target, overwrite=overwrite) as sink:
                for chunk in reader.chunks():
                    sink.write(chunk)
        else:
            if target.exists() or target.is_symlink():
                raise OutputExistsError(f"{target} already exists; move it aside before restoring a directory.")
            target.parent.mkdir(parents=True, exist_ok=True)
            _extract_archive(reader, target)
    return DecryptResult(source=src, output=target, payload_type=header.payload_type)


def verify_path(source: str | os.PathLike[str], password: str) -> Header:
    """Authenticate an entire encrypted file without writing any plaintext to disk."""
    with open(source, "rb") as handle:
        header, reader = open_decryptor(handle, password)
        for _ in reader.chunks():
            pass
    return header


def inspect_path(source: str | os.PathLike[str]) -> Header:
    """Read the public header fields. Needs no password and proves nothing about integrity."""
    with open(source, "rb") as handle:
        header, _, _ = read_header(handle)
    return header
