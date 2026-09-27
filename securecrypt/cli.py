"""Command-line interface.

Passwords are read interactively with :mod:`getpass` or, for scripts, from standard input
with ``--password-stdin``. They are deliberately never accepted as arguments, because
arguments are visible to other users in process listings and end up in shell history.
"""

from __future__ import annotations

import argparse
import getpass
import sys
from collections.abc import Callable, Sequence
from pathlib import Path

from . import __version__
from .errors import SecureCryptError
from .header import DEFAULT_CHUNK_SIZE, MAX_CHUNK_SIZE, PayloadType
from .kdf import ARGON2_AVAILABLE, KdfAlgorithm, default_params
from .operations import Removal, decrypt_path, encrypt_path, inspect_path, verify_path

MIN_RECOMMENDED_PASSWORD = 12


def _read_password(args: argparse.Namespace, *, confirm: bool) -> str:
    if args.password_stdin:
        password = sys.stdin.readline().rstrip("\r\n")
    else:
        password = getpass.getpass("Password: ")
        if confirm and getpass.getpass("Confirm password: ") != password:
            raise SecureCryptError("Passwords do not match.")
    if not password:
        raise SecureCryptError("Password must not be empty.")
    if confirm and len(password) < MIN_RECOMMENDED_PASSWORD:
        print(
            f"warning: passwords shorter than {MIN_RECOMMENDED_PASSWORD} characters are much easier to guess.",
            file=sys.stderr,
        )
    return password


def _chunk_size(value: str) -> int:
    limit = MAX_CHUNK_SIZE // 1024
    try:
        kib = int(value)
    except ValueError:
        raise argparse.ArgumentTypeError("chunk size must be a whole number of KiB") from None
    if not 1 <= kib <= limit:
        raise argparse.ArgumentTypeError(f"chunk size must be between 1 and {limit} KiB")
    return kib * 1024


def _for_each(paths: Sequence[Path], action: Callable[[Path], str]) -> int:
    """Run ``action`` on every path, reporting failures without stopping the batch."""
    failures = 0
    for path in paths:
        try:
            print(action(path))
        except (SecureCryptError, OSError) as exc:
            failures += 1
            print(f"error: {path}: {exc}", file=sys.stderr)
    return 1 if failures else 0


def _cmd_encrypt(args: argparse.Namespace) -> int:
    kdf = default_params(KdfAlgorithm[args.kdf.upper()])
    removal = Removal.SHRED if args.shred else Removal.DELETE if args.delete_original else Removal.KEEP
    password = _read_password(args, confirm=True)

    def run(path: Path) -> str:
        result = encrypt_path(
            path,
            password,
            output=args.output,
            kdf=kdf,
            chunk_size=args.chunk_size,
            overwrite=args.force,
            removal=removal,
        )
        lines = [f"encrypted {path} -> {result.output}"]
        if result.skipped:
            lines.append(f"  skipped {len(result.skipped)} symlink(s)/special file(s): {', '.join(result.skipped)}")
            if removal is not Removal.KEEP:
                lines.append("  original kept because some entries could not be archived")
        elif result.original_removed:
            lines.append(f"  original {'overwritten and ' if removal is Removal.SHRED else ''}removed")
        return "\n".join(lines)

    return _for_each(args.paths, run)


def _cmd_decrypt(args: argparse.Namespace) -> int:
    password = _read_password(args, confirm=False)

    def run(path: Path) -> str:
        result = decrypt_path(path, password, output=args.output, overwrite=args.force)
        return f"decrypted {path} -> {result.output}"

    return _for_each(args.paths, run)


def _cmd_verify(args: argparse.Namespace) -> int:
    password = _read_password(args, confirm=False)

    def run(path: Path) -> str:
        verify_path(path, password)
        return f"OK {path}: authentic and complete"

    return _for_each(args.paths, run)


def _cmd_info(args: argparse.Namespace) -> int:
    def run(path: Path) -> str:
        header = inspect_path(path)
        kind = "directory (tar archive)" if header.payload_type is PayloadType.DIRECTORY else "file"
        return (
            f"{path}\n"
            f"  format version : {header.version}\n"
            f"  contents       : {kind}\n"
            f"  cipher         : AES-256-GCM, {header.chunk_size // 1024} KiB chunks\n"
            f"  key derivation : {header.kdf.describe()}"
        )

    return _for_each(args.paths, run)


def _cmd_gui(_args: argparse.Namespace) -> int:
    from .gui import run_gui  # imported lazily so the CLI works without Tk

    run_gui()
    return 0


def build_parser() -> argparse.ArgumentParser:
    """Construct the argument parser (exposed for testing)."""
    parser = argparse.ArgumentParser(
        prog="securecrypt",
        description="Encrypt and decrypt files and directories with AES-256-GCM and a password.",
    )
    parser.add_argument("--version", action="version", version=f"%(prog)s {__version__}")
    sub = parser.add_subparsers(dest="command", required=True)

    def add_paths(p: argparse.ArgumentParser, what: str, with_password: bool = True) -> None:
        p.add_argument("paths", nargs="+", type=Path, metavar="PATH", help=what)
        if with_password:
            p.add_argument(
                "--password-stdin",
                action="store_true",
                help="read the password from the first line of standard input instead of prompting",
            )

    enc = sub.add_parser("encrypt", help="encrypt files or directories")
    add_paths(enc, "files or directories to encrypt")
    enc.add_argument("-o", "--output", type=Path, help="output path (only with a single input)")
    enc.add_argument(
        "--kdf",
        choices=[a.name.lower() for a in KdfAlgorithm if a is not KdfAlgorithm.ARGON2ID or ARGON2_AVAILABLE],
        default="argon2id" if ARGON2_AVAILABLE else "scrypt",
        help="password key derivation function (default: %(default)s)",
    )
    enc.add_argument(
        "--chunk-size",
        type=_chunk_size,
        default=DEFAULT_CHUNK_SIZE,
        metavar="KIB",
        help=f"plaintext chunk size in KiB (default: {DEFAULT_CHUNK_SIZE // 1024})",
    )
    enc.add_argument("-f", "--force", action="store_true", help="overwrite existing output files")
    removal = enc.add_mutually_exclusive_group()
    removal.add_argument(
        "--delete-original", action="store_true", help="delete the input after the output has been verified"
    )
    removal.add_argument(
        "--shred",
        action="store_true",
        help="overwrite the input with random data before deleting it (best effort; see README)",
    )
    enc.set_defaults(func=_cmd_encrypt)

    dec = sub.add_parser("decrypt", help="decrypt .enc files")
    add_paths(dec, ".enc files to decrypt")
    dec.add_argument("-o", "--output", type=Path, help="output path (only with a single input)")
    dec.add_argument("-f", "--force", action="store_true", help="overwrite existing output files")
    dec.set_defaults(func=_cmd_decrypt)

    ver = sub.add_parser("verify", help="check that .enc files are intact and the password is right")
    add_paths(ver, ".enc files to check")
    ver.set_defaults(func=_cmd_verify)

    info = sub.add_parser("info", help="show header details (no password needed)")
    add_paths(info, ".enc files to describe", with_password=False)
    info.set_defaults(func=_cmd_info)

    gui = sub.add_parser("gui", help="open the graphical interface")
    gui.set_defaults(func=_cmd_gui)
    return parser


def main(argv: Sequence[str] | None = None) -> int:
    """Entry point. Returns a process exit code."""
    parser = build_parser()
    args = parser.parse_args(argv)
    if getattr(args, "output", None) is not None and len(args.paths) > 1:
        parser.error("--output can only be used with a single input path")
    try:
        return int(args.func(args))
    except SecureCryptError as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 1
    except KeyboardInterrupt:
        print("\ninterrupted", file=sys.stderr)
        return 130


if __name__ == "__main__":  # pragma: no cover
    sys.exit(main())
