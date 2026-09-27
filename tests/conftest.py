"""Shared fixtures.

Real Argon2id defaults take a noticeable fraction of a second per derivation, so the
suite swaps in the cheapest parameters the format accepts. The code paths are identical.
"""

from __future__ import annotations

import pytest

from securecrypt import cli, operations
from securecrypt.kdf import Argon2Params, KdfAlgorithm, KdfParams, ScryptParams

FAST_ARGON2 = Argon2Params(time_cost=1, memory_kib=1024, parallelism=1)
FAST_SCRYPT = ScryptParams(log2_n=10, r=8, p=1)
PASSWORD = "correct horse battery staple"


def fast_params(algorithm: KdfAlgorithm | None = None) -> KdfParams:
    return FAST_SCRYPT if algorithm is KdfAlgorithm.SCRYPT else FAST_ARGON2


@pytest.fixture(autouse=True)
def _fast_kdf(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(operations, "default_params", fast_params)
    monkeypatch.setattr(cli, "default_params", fast_params)
