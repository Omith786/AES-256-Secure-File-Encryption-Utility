"""Removal of original files after encryption.

``shred`` overwrites file contents with random bytes before unlinking. This is a
*best-effort* measure only. On SSDs and flash storage (wear levelling, over-provisioning),
on copy-on-write or journalling filesystems such as APFS, Btrfs, ZFS and ext4 in some
modes, and wherever snapshots, backups or cloud sync exist, the overwrite may land on
different physical blocks and old data can survive. Full-disk encryption is the reliable
answer to that problem; this module does not replace it.
"""

from __future__ import annotations

import os
import shutil
from pathlib import Path

_BLOCK = 1024 * 1024


def overwrite_file(path: Path) -> None:
    """Overwrite a regular file in place with random bytes and flush it to the device."""
    size = path.stat().st_size
    with open(path, "r+b", buffering=0) as handle:
        remaining = size
        while remaining:
            step = min(_BLOCK, remaining)
            handle.write(os.urandom(step))
            remaining -= step
        os.fsync(handle.fileno())


def remove_path(path: Path, *, shred: bool) -> None:
    """Delete a file or directory tree, overwriting regular files first if ``shred``."""
    if path.is_dir() and not path.is_symlink():
        if shred:
            for root, _dirs, files in os.walk(path):
                for name in files:
                    entry = Path(root) / name
                    # Never follow a link out of the tree and overwrite its target.
                    if entry.is_file() and not entry.is_symlink():
                        overwrite_file(entry)
        shutil.rmtree(path)
        return
    if shred and path.is_file() and not path.is_symlink():
        overwrite_file(path)
    path.unlink()
