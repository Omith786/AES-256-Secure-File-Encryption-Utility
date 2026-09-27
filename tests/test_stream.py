"""Low-level tests of the header and chunked AEAD stream."""

from __future__ import annotations

import io
import os
import struct

import pytest
from conftest import FAST_ARGON2, FAST_SCRYPT, PASSWORD

from securecrypt.errors import FormatError, IntegrityError, WrongPasswordError
from securecrypt.header import HEADER_LENGTH, TOTAL_HEADER_LENGTH, Header, PayloadType
from securecrypt.kdf import Argon2Params, KdfParams
from securecrypt.stream import TAG_LENGTH, EncryptWriter, derive_file_keys, header_mac, open_decryptor

CHUNK = 64


def encrypt_bytes(data: bytes, *, chunk_size: int = CHUNK, kdf: KdfParams = FAST_ARGON2) -> bytes:
    header = Header(payload_type=PayloadType.FILE, kdf=kdf, chunk_size=chunk_size)
    sink = io.BytesIO()
    with EncryptWriter(sink, header, derive_file_keys(PASSWORD, header)) as writer:
        writer.write(data)
    return sink.getvalue()


def decrypt_bytes(blob: bytes, password: str = PASSWORD) -> bytes:
    _, reader = open_decryptor(io.BytesIO(blob), password)
    return b"".join(reader.chunks())


def sealed_chunks(blob: bytes, chunk_size: int = CHUNK) -> list[bytes]:
    body = blob[TOTAL_HEADER_LENGTH:]
    step = chunk_size + TAG_LENGTH
    return [body[i : i + step] for i in range(0, len(body), step)]


@pytest.mark.parametrize("size", [0, 1, CHUNK - 1, CHUNK, CHUNK + 1, 2 * CHUNK, 2 * CHUNK + 1, 1000])
def test_round_trip_around_chunk_boundaries(size: int) -> None:
    data = os.urandom(size)
    blob = encrypt_bytes(data)
    assert decrypt_bytes(blob) == data
    expected_chunks = max(1, -(-size // CHUNK))
    assert len(blob) == TOTAL_HEADER_LENGTH + size + expected_chunks * TAG_LENGTH


def test_many_small_writes_match_one_big_write() -> None:
    data = os.urandom(10 * CHUNK + 7)
    header = Header(payload_type=PayloadType.FILE, kdf=FAST_ARGON2, chunk_size=CHUNK)
    sink = io.BytesIO()
    with EncryptWriter(sink, header, derive_file_keys(PASSWORD, header)) as writer:
        for i in range(0, len(data), 5):
            writer.write(data[i : i + 5])
    assert decrypt_bytes(sink.getvalue()) == data


def test_empty_input_is_a_single_authenticated_chunk() -> None:
    blob = encrypt_bytes(b"")
    assert len(blob) == TOTAL_HEADER_LENGTH + TAG_LENGTH
    assert decrypt_bytes(blob) == b""


def test_scrypt_round_trip() -> None:
    data = os.urandom(300)
    assert decrypt_bytes(encrypt_bytes(data, kdf=FAST_SCRYPT)) == data


def test_same_input_encrypts_differently_each_time() -> None:
    data = b"same plaintext" * 10
    first, second = encrypt_bytes(data), encrypt_bytes(data)
    assert first[:HEADER_LENGTH] != second[:HEADER_LENGTH]  # fresh salt and nonce
    assert first[TOTAL_HEADER_LENGTH:] != second[TOTAL_HEADER_LENGTH:]


def test_unicode_password_is_normalised() -> None:
    composed, decomposed = "café-pass", "café-pass"
    header = Header(payload_type=PayloadType.FILE, kdf=FAST_ARGON2, chunk_size=CHUNK)
    sink = io.BytesIO()
    with EncryptWriter(sink, header, derive_file_keys(composed, header)) as writer:
        writer.write(b"hello")
    assert decrypt_bytes(sink.getvalue(), password=decomposed) == b"hello"


def test_wrong_password() -> None:
    blob = encrypt_bytes(b"secret")
    with pytest.raises(WrongPasswordError):
        decrypt_bytes(blob, password="not the password")


@pytest.mark.parametrize("offset", [9, 12, 25, 30, 45, HEADER_LENGTH + 3])
def test_tampered_header_or_mac_is_rejected(offset: int) -> None:
    blob = bytearray(encrypt_bytes(b"secret" * 50))
    blob[offset] ^= 0x01
    with pytest.raises((WrongPasswordError, FormatError)):
        decrypt_bytes(bytes(blob))


def test_header_is_bound_to_payload_as_aad() -> None:
    """Even with a valid MAC over a changed header, the chunks must not decrypt."""
    blob = encrypt_bytes(b"x" * 200)
    original = Header.unpack(blob)
    forged = Header(
        payload_type=PayloadType.DIRECTORY,
        kdf=original.kdf,
        chunk_size=original.chunk_size,
        salt=original.salt,
        nonce_prefix=original.nonce_prefix,
    )
    forged_bytes = forged.pack()
    keys = derive_file_keys(PASSWORD, forged)  # same salt and KDF, so the same keys
    tampered = forged_bytes + header_mac(keys, forged_bytes) + blob[TOTAL_HEADER_LENGTH:]
    with pytest.raises(IntegrityError):
        decrypt_bytes(tampered)


@pytest.mark.parametrize("chunk_index", [0, 1, -1])
def test_flipped_ciphertext_bit_is_detected(chunk_index: int) -> None:
    blob = encrypt_bytes(os.urandom(5 * CHUNK))
    chunks = sealed_chunks(blob)
    target = bytearray(chunks[chunk_index])
    target[3] ^= 0x80
    chunks[chunk_index] = bytes(target)
    with pytest.raises(IntegrityError):
        decrypt_bytes(blob[:TOTAL_HEADER_LENGTH] + b"".join(chunks))


def test_flipped_tag_bit_is_detected() -> None:
    blob = bytearray(encrypt_bytes(os.urandom(3 * CHUNK)))
    blob[-1] ^= 0x01
    with pytest.raises(IntegrityError):
        decrypt_bytes(bytes(blob))


def test_reordered_chunks_are_detected() -> None:
    blob = encrypt_bytes(os.urandom(4 * CHUNK + 10))
    chunks = sealed_chunks(blob)
    chunks[0], chunks[1] = chunks[1], chunks[0]
    with pytest.raises(IntegrityError):
        decrypt_bytes(blob[:TOTAL_HEADER_LENGTH] + b"".join(chunks))


def test_truncation_at_chunk_boundary_is_detected() -> None:
    """Dropping whole trailing chunks leaves valid chunks, but none carries the final flag."""
    blob = encrypt_bytes(os.urandom(4 * CHUNK + 10))
    chunks = sealed_chunks(blob)
    for keep in range(1, len(chunks)):
        with pytest.raises(IntegrityError):
            decrypt_bytes(blob[:TOTAL_HEADER_LENGTH] + b"".join(chunks[:keep]))


@pytest.mark.parametrize("cut", [1, 5, TAG_LENGTH, CHUNK])
def test_truncation_inside_a_chunk_is_detected(cut: int) -> None:
    blob = encrypt_bytes(os.urandom(3 * CHUNK + 20))
    with pytest.raises(IntegrityError):
        decrypt_bytes(blob[:-cut])


def test_truncation_to_bare_header_is_detected() -> None:
    blob = encrypt_bytes(b"data")
    with pytest.raises(IntegrityError, match="truncated"):
        decrypt_bytes(blob[:TOTAL_HEADER_LENGTH])


def test_truncation_inside_header_is_a_format_error() -> None:
    blob = encrypt_bytes(b"data")
    with pytest.raises(FormatError, match="truncated"):
        decrypt_bytes(blob[: TOTAL_HEADER_LENGTH - 1])


def test_appended_data_is_detected() -> None:
    blob = encrypt_bytes(os.urandom(2 * CHUNK + 3))
    with pytest.raises(IntegrityError):
        decrypt_bytes(blob + b"\x00")


def test_non_encrypted_input_is_a_format_error() -> None:
    with pytest.raises(FormatError, match="Not an encrypted file"):
        decrypt_bytes(b"just some ordinary text that happens to be long enough " * 3)


def test_unsupported_version_is_a_format_error() -> None:
    blob = bytearray(encrypt_bytes(b"data"))
    blob[8] = 99
    with pytest.raises(FormatError, match="version"):
        decrypt_bytes(bytes(blob))


def test_hostile_kdf_parameters_are_rejected_before_derivation() -> None:
    """A crafted header must not be able to make us allocate, say, 4 TiB of memory."""
    blob = bytearray(encrypt_bytes(b"data"))
    blob[15:19] = struct.pack(">I", 0xFFFFFFFF)  # Argon2 memory_kib field
    with pytest.raises(FormatError, match="memory"):
        decrypt_bytes(bytes(blob))


def test_chunk_size_limits() -> None:
    with pytest.raises(FormatError):
        Header(payload_type=PayloadType.FILE, kdf=FAST_ARGON2, chunk_size=1)
    with pytest.raises(FormatError):
        Argon2Params(time_cost=0).validate()


def test_reader_supports_partial_reads() -> None:
    data = os.urandom(7 * CHUNK + 5)
    _, reader = open_decryptor(io.BytesIO(encrypt_bytes(data)), PASSWORD)
    pieces = []
    while piece := reader.read(37):
        pieces.append(piece)
    assert b"".join(pieces) == data


def test_large_stream_with_default_chunk_size() -> None:
    """Several MiB across many 64 KiB chunks, with an awkward remainder."""
    data = os.urandom(5 * 1024 * 1024 + 12345)
    blob = encrypt_bytes(data, chunk_size=64 * 1024)
    assert decrypt_bytes(blob) == data
