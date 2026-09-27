"""Best-effort overwrite and removal helpers."""

from __future__ import annotations

import os
from pathlib import Path

from securecrypt.shred import overwrite_file, remove_path


def test_overwrite_replaces_contents_and_keeps_size(tmp_path: Path) -> None:
    target = tmp_path / "f"
    original = b"A" * 3_000_000
    target.write_bytes(original)
    overwrite_file(target)
    after = target.read_bytes()
    assert len(after) == len(original)
    assert after != original


def test_remove_directory_does_not_follow_symlinks(tmp_path: Path) -> None:
    outside = tmp_path / "outside.txt"
    outside.write_text("keep me")
    tree = tmp_path / "tree"
    (tree / "sub").mkdir(parents=True)
    (tree / "sub" / "file").write_bytes(os.urandom(10))
    (tree / "link").symlink_to(outside)

    remove_path(tree, shred=True)
    assert not tree.exists()
    assert outside.read_text() == "keep me"


def test_remove_single_file(tmp_path: Path) -> None:
    target = tmp_path / "f"
    target.write_text("x")
    remove_path(target, shred=False)
    assert not target.exists()
