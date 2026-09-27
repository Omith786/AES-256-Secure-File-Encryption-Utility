"""File and directory level behaviour: naming, atomic output, removal of originals."""

from __future__ import annotations

import io
import os
import stat
import tarfile
from pathlib import Path

import pytest
from conftest import FAST_SCRYPT, PASSWORD

from securecrypt import (
    FormatError,
    IntegrityError,
    OutputExistsError,
    Removal,
    SecureCryptError,
    WrongPasswordError,
    decrypt_path,
    encrypt_path,
    inspect_path,
    verify_path,
)
from securecrypt.header import TOTAL_HEADER_LENGTH, Header, PayloadType
from securecrypt.kdf import KdfAlgorithm
from securecrypt.stream import TAG_LENGTH, EncryptWriter, derive_file_keys


def make_tree(root: Path) -> dict[str, bytes]:
    files = {
        "notes.txt": b"hello world\n",
        "empty.dat": b"",
        "nested/deeper/blob.bin": os.urandom(200_000),
        "nested/unicode é.txt": "café".encode(),
    }
    for rel, content in files.items():
        path = root / rel
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_bytes(content)
    (root / "empty-dir").mkdir()
    return files


def leftovers(directory: Path) -> list[str]:
    return sorted(p.name for p in directory.iterdir() if p.name.endswith(".part"))


def test_file_round_trip_with_default_names(tmp_path: Path) -> None:
    original = tmp_path / "report.pdf"
    data = os.urandom(150_000)
    original.write_bytes(data)

    result = encrypt_path(original, PASSWORD)
    assert result.output == tmp_path / "report.pdf.enc"
    assert data not in result.output.read_bytes()
    original.unlink()

    restored = decrypt_path(result.output, PASSWORD)
    assert restored.output == original
    assert restored.payload_type is PayloadType.FILE
    assert original.read_bytes() == data


def test_decrypted_file_is_private_to_owner(tmp_path: Path) -> None:
    src = tmp_path / "a.txt"
    src.write_text("x")
    enc = encrypt_path(src, PASSWORD).output
    out = decrypt_path(enc, PASSWORD, output=tmp_path / "b.txt").output
    assert stat.S_IMODE(out.stat().st_mode) == 0o600


def test_empty_file_round_trip(tmp_path: Path) -> None:
    src = tmp_path / "empty"
    src.write_bytes(b"")
    enc = encrypt_path(src, PASSWORD).output
    assert enc.stat().st_size == TOTAL_HEADER_LENGTH + TAG_LENGTH
    out = decrypt_path(enc, PASSWORD, output=tmp_path / "empty.out").output
    assert out.read_bytes() == b""


def test_large_file_across_chunk_boundaries(tmp_path: Path) -> None:
    src = tmp_path / "big.bin"
    data = os.urandom(3 * 1024 * 1024 + 1)
    src.write_bytes(data)
    enc = encrypt_path(src, PASSWORD, chunk_size=256 * 1024).output
    out = decrypt_path(enc, PASSWORD, output=tmp_path / "big.out").output
    assert out.read_bytes() == data


def test_scrypt_is_recorded_in_header(tmp_path: Path) -> None:
    src = tmp_path / "s.txt"
    src.write_text("scrypt")
    enc = encrypt_path(src, PASSWORD, kdf=FAST_SCRYPT).output
    assert inspect_path(enc).kdf.algorithm is KdfAlgorithm.SCRYPT
    assert decrypt_path(enc, PASSWORD, output=tmp_path / "s.out").output.read_text() == "scrypt"


def test_directory_round_trip(tmp_path: Path) -> None:
    src = tmp_path / "project"
    files = make_tree(src)
    result = encrypt_path(src, PASSWORD)
    assert result.output == tmp_path / "project.enc"
    assert inspect_path(result.output).payload_type is PayloadType.DIRECTORY

    restored = decrypt_path(result.output, PASSWORD, output=tmp_path / "restored").output
    for rel, content in files.items():
        assert (restored / rel).read_bytes() == content
    assert (restored / "empty-dir").is_dir()
    assert leftovers(tmp_path) == []


def test_directory_symlinks_are_skipped_and_block_removal(tmp_path: Path) -> None:
    src = tmp_path / "linked"
    make_tree(src)
    outside = tmp_path / "outside.txt"
    outside.write_text("do not touch")
    (src / "link").symlink_to(outside)

    result = encrypt_path(src, PASSWORD, removal=Removal.SHRED)
    assert result.skipped == ["linked/link"]
    assert not result.original_removed
    assert src.exists()
    assert outside.read_text() == "do not touch"


@pytest.mark.parametrize("removal", [Removal.DELETE, Removal.SHRED])
def test_original_file_removed_after_verification(tmp_path: Path, removal: Removal) -> None:
    src = tmp_path / "secret.txt"
    src.write_text("top secret")
    result = encrypt_path(src, PASSWORD, removal=removal)
    assert result.original_removed
    assert not src.exists()
    assert decrypt_path(result.output, PASSWORD).output.read_text() == "top secret"


def test_original_directory_removed_after_verification(tmp_path: Path) -> None:
    src = tmp_path / "tree"
    files = make_tree(src)
    result = encrypt_path(src, PASSWORD, removal=Removal.SHRED)
    assert result.original_removed and not src.exists()
    restored = decrypt_path(result.output, PASSWORD).output
    assert restored == src
    assert (restored / "nested/deeper/blob.bin").read_bytes() == files["nested/deeper/blob.bin"]


def test_refuses_to_overwrite_without_force(tmp_path: Path) -> None:
    src = tmp_path / "a.txt"
    src.write_text("new")
    existing = tmp_path / "a.txt.enc"
    existing.write_text("precious")
    with pytest.raises(OutputExistsError):
        encrypt_path(src, PASSWORD)
    assert existing.read_text() == "precious"
    encrypt_path(src, PASSWORD, overwrite=True)
    assert verify_path(existing, PASSWORD).payload_type is PayloadType.FILE


def test_directory_restore_never_overwrites(tmp_path: Path) -> None:
    src = tmp_path / "d"
    make_tree(src)
    enc = encrypt_path(src, PASSWORD).output
    with pytest.raises(OutputExistsError):
        decrypt_path(enc, PASSWORD, overwrite=True)


def test_output_inside_input_directory_is_refused(tmp_path: Path) -> None:
    src = tmp_path / "d"
    make_tree(src)
    with pytest.raises(SecureCryptError):
        encrypt_path(src, PASSWORD, output=src / "self.enc")


def test_missing_input(tmp_path: Path) -> None:
    with pytest.raises(SecureCryptError, match="no such file"):
        encrypt_path(tmp_path / "nope", PASSWORD)


def test_wrong_password_leaves_nothing_behind(tmp_path: Path) -> None:
    src = tmp_path / "a.txt"
    src.write_text("secret")
    enc = encrypt_path(src, PASSWORD).output
    with pytest.raises(WrongPasswordError):
        decrypt_path(enc, "wrong", output=tmp_path / "out.txt")
    assert not (tmp_path / "out.txt").exists()
    assert leftovers(tmp_path) == []


def test_tampered_file_produces_no_output(tmp_path: Path) -> None:
    src = tmp_path / "a.bin"
    src.write_bytes(os.urandom(500_000))
    enc = encrypt_path(src, PASSWORD, chunk_size=16 * 1024).output
    blob = bytearray(enc.read_bytes())
    blob[-100] ^= 0xFF  # inside the final chunk, after lots of good plaintext
    enc.write_bytes(bytes(blob))

    out = tmp_path / "restored.bin"
    with pytest.raises(IntegrityError):
        decrypt_path(enc, PASSWORD, output=out)
    assert not out.exists()
    assert leftovers(tmp_path) == []
    with pytest.raises(IntegrityError):
        verify_path(enc, PASSWORD)


def test_truncated_directory_archive_produces_no_output(tmp_path: Path) -> None:
    src = tmp_path / "d"
    make_tree(src)
    chunk = 1024
    enc = encrypt_path(src, PASSWORD, chunk_size=chunk).output
    blob = enc.read_bytes()
    body = len(blob) - TOTAL_HEADER_LENGTH
    last = body % (chunk + TAG_LENGTH) or chunk + TAG_LENGTH
    enc.write_bytes(blob[: len(blob) - last])  # drop exactly the final chunk

    out = tmp_path / "restored"
    with pytest.raises(IntegrityError):
        decrypt_path(enc, PASSWORD, output=out)
    assert not out.exists()
    assert leftovers(tmp_path) == []


def test_non_encrypted_file_is_rejected(tmp_path: Path) -> None:
    plain = tmp_path / "plain.enc"
    plain.write_bytes(b"not really encrypted" * 10)
    with pytest.raises(FormatError):
        decrypt_path(plain, PASSWORD)
    with pytest.raises(FormatError):
        inspect_path(plain)


def test_decrypted_name_without_enc_suffix(tmp_path: Path) -> None:
    src = tmp_path / "a.txt"
    src.write_text("x")
    enc = encrypt_path(src, PASSWORD, output=tmp_path / "blob").output
    assert decrypt_path(enc, PASSWORD).output == tmp_path / "blob.decrypted"


def test_stream_is_authenticated_past_the_tar_end_marker(tmp_path: Path) -> None:
    """tarfile stops reading at its end marker; the tail must still be checked.

    The payload here is a valid archive followed by padding, so tarfile finishes happily
    long before the (removed) final chunk would have been read.
    """
    archive = io.BytesIO()
    with tarfile.open(fileobj=archive, mode="w") as tar:
        info = tarfile.TarInfo("d")
        info.type = tarfile.DIRTYPE
        tar.addfile(info)
    payload = archive.getvalue() + bytes(50_000)

    chunk = 1024
    header = Header(payload_type=PayloadType.DIRECTORY, kdf=FAST_SCRYPT, chunk_size=chunk)
    sink = io.BytesIO()
    with EncryptWriter(sink, header, derive_file_keys(PASSWORD, header)) as writer:
        writer.write(payload)
    blob = sink.getvalue()
    enc = tmp_path / "crafted.enc"
    enc.write_bytes(blob[: -(len(payload) % chunk + TAG_LENGTH)])

    out = tmp_path / "restored"
    with pytest.raises(IntegrityError):
        decrypt_path(enc, PASSWORD, output=out)
    assert not out.exists()
    assert leftovers(tmp_path) == []
