"""Command-line behaviour, driven through ``main`` with a patched stdin or getpass."""

from __future__ import annotations

import io
from pathlib import Path

import pytest
from conftest import PASSWORD

from securecrypt import cli


def run(monkeypatch: pytest.MonkeyPatch, argv: list[str], stdin: str = PASSWORD + "\n") -> int:
    monkeypatch.setattr("sys.stdin", io.StringIO(stdin))
    return cli.main(argv)


def test_encrypt_decrypt_batch_via_stdin(tmp_path: Path, monkeypatch: pytest.MonkeyPatch, capsys) -> None:
    a, b = tmp_path / "a.txt", tmp_path / "b.txt"
    a.write_text("alpha")
    b.write_text("beta")
    assert run(monkeypatch, ["encrypt", str(a), str(b), "--password-stdin", "--delete-original"]) == 0
    assert not a.exists() and not b.exists()
    assert "original removed" in capsys.readouterr().out

    assert run(monkeypatch, ["decrypt", str(a) + ".enc", str(b) + ".enc", "--password-stdin"]) == 0
    assert a.read_text() == "alpha" and b.read_text() == "beta"


def test_interactive_prompt_requires_matching_confirmation(tmp_path: Path, monkeypatch: pytest.MonkeyPatch, capsys) -> None:
    src = tmp_path / "a.txt"
    src.write_text("x")
    answers = iter(["first password!!", "different password"])
    monkeypatch.setattr(cli.getpass, "getpass", lambda prompt="": next(answers))
    assert cli.main(["encrypt", str(src)]) == 1
    assert "do not match" in capsys.readouterr().err
    assert not (tmp_path / "a.txt.enc").exists()


def test_short_password_warns(tmp_path: Path, monkeypatch: pytest.MonkeyPatch, capsys) -> None:
    src = tmp_path / "a.txt"
    src.write_text("x")
    monkeypatch.setattr(cli.getpass, "getpass", lambda prompt="": "short")
    assert cli.main(["encrypt", str(src)]) == 0
    assert "warning" in capsys.readouterr().err


def test_wrong_password_exit_code(tmp_path: Path, monkeypatch: pytest.MonkeyPatch, capsys) -> None:
    src = tmp_path / "a.txt"
    src.write_text("x")
    assert run(monkeypatch, ["encrypt", str(src), "--password-stdin"]) == 0
    assert run(monkeypatch, ["verify", str(src) + ".enc", "--password-stdin"], stdin="nope\n") == 1
    assert "Wrong password" in capsys.readouterr().err


def test_batch_continues_after_a_failure(tmp_path: Path, monkeypatch: pytest.MonkeyPatch, capsys) -> None:
    good = tmp_path / "good.txt"
    good.write_text("x")
    assert run(monkeypatch, ["encrypt", str(tmp_path / "missing"), str(good), "--password-stdin"]) == 1
    assert (tmp_path / "good.txt.enc").exists()


def test_info_needs_no_password(tmp_path: Path, monkeypatch: pytest.MonkeyPatch, capsys) -> None:
    src = tmp_path / "a.txt"
    src.write_text("x")
    run(monkeypatch, ["encrypt", str(src), "--password-stdin", "--kdf", "scrypt"])
    capsys.readouterr()
    assert cli.main(["info", str(src) + ".enc"]) == 0
    out = capsys.readouterr().out
    assert "scrypt" in out and "AES-256-GCM" in out


def test_empty_password_rejected(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    src = tmp_path / "a.txt"
    src.write_text("x")
    assert run(monkeypatch, ["encrypt", str(src), "--password-stdin"], stdin="\n") == 1


def test_password_is_never_accepted_as_an_argument(tmp_path: Path) -> None:
    with pytest.raises(SystemExit):
        cli.main(["encrypt", str(tmp_path), "--password", "hunter2"])


def test_output_with_multiple_inputs_is_a_usage_error(tmp_path: Path) -> None:
    with pytest.raises(SystemExit) as exc:
        cli.main(["encrypt", "a", "b", "-o", str(tmp_path / "x")])
    assert exc.value.code == 2


def test_chunk_size_validation() -> None:
    with pytest.raises(SystemExit):
        cli.main(["encrypt", "a", "--chunk-size", "0"])
