"""Password-based key derivation.

Two memory-hard KDFs are supported. Argon2id is the default; scrypt is kept as an
alternative that needs nothing beyond ``cryptography``. The chosen algorithm and its cost
parameters are written into every file header, so defaults can be raised in future
without breaking old files.
"""

from __future__ import annotations

import enum
import unicodedata
from dataclasses import dataclass
from typing import Union

from cryptography.hazmat.primitives.kdf.scrypt import Scrypt

from .errors import FormatError

try:
    from argon2.low_level import Type as _Argon2Type
    from argon2.low_level import hash_secret_raw as _argon2_hash

    ARGON2_AVAILABLE = True
except ImportError:  # pragma: no cover - exercised only when argon2-cffi is missing
    ARGON2_AVAILABLE = False

KEY_LENGTH = 32  # AES-256
SALT_LENGTH = 16


class KdfAlgorithm(enum.IntEnum):
    """Identifier stored in the header's KDF byte."""

    ARGON2ID = 1
    SCRYPT = 2


@dataclass(frozen=True)
class Argon2Params:
    """Argon2id cost parameters. ``memory_kib`` is in kibibytes, as the Argon2 spec uses."""

    time_cost: int = 3
    memory_kib: int = 64 * 1024
    parallelism: int = 4

    algorithm = KdfAlgorithm.ARGON2ID

    # Upper bounds applied when *reading* a header, so a crafted file cannot make us
    # allocate unbounded memory or spin for hours before the MAC check fails.
    MAX_TIME_COST = 20
    MAX_MEMORY_KIB = 2 * 1024 * 1024
    MAX_PARALLELISM = 16

    def to_fields(self) -> tuple[int, int, int]:
        return (self.time_cost, self.memory_kib, self.parallelism)

    def validate(self) -> None:
        if not 1 <= self.time_cost <= self.MAX_TIME_COST:
            raise FormatError(f"Argon2 time cost {self.time_cost} is out of range.")
        if not 8 * self.parallelism <= self.memory_kib <= self.MAX_MEMORY_KIB:
            raise FormatError(f"Argon2 memory cost {self.memory_kib} KiB is out of range.")
        if not 1 <= self.parallelism <= self.MAX_PARALLELISM:
            raise FormatError(f"Argon2 parallelism {self.parallelism} is out of range.")

    def describe(self) -> str:
        return f"Argon2id (t={self.time_cost}, m={self.memory_kib // 1024} MiB, p={self.parallelism})"


@dataclass(frozen=True)
class ScryptParams:
    """scrypt cost parameters. ``log2_n`` is stored rather than N so it is always a power of two."""

    log2_n: int = 17
    r: int = 8
    p: int = 1

    algorithm = KdfAlgorithm.SCRYPT

    MAX_LOG2_N = 22
    MAX_R = 32
    MAX_P = 16

    def to_fields(self) -> tuple[int, int, int]:
        return (self.log2_n, self.r, self.p)

    def validate(self) -> None:
        if not 10 <= self.log2_n <= self.MAX_LOG2_N:
            raise FormatError(f"scrypt log2(N) {self.log2_n} is out of range.")
        if not 1 <= self.r <= self.MAX_R:
            raise FormatError(f"scrypt r {self.r} is out of range.")
        if not 1 <= self.p <= self.MAX_P:
            raise FormatError(f"scrypt p {self.p} is out of range.")
        # scrypt needs roughly 128 * r * N bytes; cap it at the same 2 GiB as Argon2.
        if 128 * self.r * 2**self.log2_n > Argon2Params.MAX_MEMORY_KIB * 1024:
            raise FormatError("scrypt memory requirement is out of range.")

    def describe(self) -> str:
        return f"scrypt (N=2^{self.log2_n}, r={self.r}, p={self.p})"


KdfParams = Union[Argon2Params, ScryptParams]


def default_params(algorithm: KdfAlgorithm | None = None) -> KdfParams:
    """Return the recommended parameters for ``algorithm`` (Argon2id when available).

    Argon2id defaults follow the second recommended option in RFC 9106 (t=3, 64 MiB, p=4).
    """
    if algorithm is None:
        algorithm = KdfAlgorithm.ARGON2ID if ARGON2_AVAILABLE else KdfAlgorithm.SCRYPT
    if algorithm is KdfAlgorithm.ARGON2ID:
        if not ARGON2_AVAILABLE:
            raise RuntimeError("Argon2id requested but argon2-cffi is not installed.")
        return Argon2Params()
    return ScryptParams()


def params_from_fields(algorithm_id: int, fields: tuple[int, int, int]) -> KdfParams:
    """Rebuild and bounds-check KDF parameters read from a header."""
    try:
        algorithm = KdfAlgorithm(algorithm_id)
    except ValueError:
        raise FormatError(f"Unknown key derivation function id {algorithm_id}.") from None
    params: KdfParams = Argon2Params(*fields) if algorithm is KdfAlgorithm.ARGON2ID else ScryptParams(*fields)
    params.validate()
    return params


def encode_password(password: str) -> bytes:
    """Encode a password as UTF-8 after NFC normalisation.

    Normalising means the same visible password typed on systems that compose accented
    characters differently still derives the same key.
    """
    return unicodedata.normalize("NFC", password).encode("utf-8")


def derive_master_key(password: str, salt: bytes, params: KdfParams) -> bytes:
    """Stretch ``password`` into a 32-byte master key using the KDF named in ``params``."""
    if not password:
        raise ValueError("Password must not be empty.")
    secret = encode_password(password)
    if isinstance(params, Argon2Params):
        if not ARGON2_AVAILABLE:
            raise FormatError("This file uses Argon2id but argon2-cffi is not installed.")
        return _argon2_hash(
            secret=secret,
            salt=salt,
            time_cost=params.time_cost,
            memory_cost=params.memory_kib,
            parallelism=params.parallelism,
            hash_len=KEY_LENGTH,
            type=_Argon2Type.ID,
        )
    return Scrypt(salt=salt, length=KEY_LENGTH, n=2**params.log2_n, r=params.r, p=params.p).derive(secret)
