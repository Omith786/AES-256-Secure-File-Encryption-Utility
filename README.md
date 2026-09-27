# AES-256 Secure File Encryption Utility

A password-based file encryption tool that protects sensitive data with AES-256 while staying simple to use. It encrypts files of any type, and whole directories, into a single `.enc` file using AES-256-GCM, with the key derived from your password by a memory-hard function (Argon2id by default, scrypt as an alternative). The aim is the balance described in the original project: modern, correctly applied cryptography behind an interface that does not require specialist knowledge. There is a command-line tool for everyday and scripted use, and a small desktop window (Tkinter) for people who would rather not use a terminal. Both call exactly the same library code.

## Features

- **Files of any type and whole directories.** A directory is streamed into a tar archive and encrypted as one file, so file names and structure are hidden too.
- **Authenticated encryption.** AES-256-GCM detects any modification, reordering or truncation of the encrypted file, and reports it clearly instead of producing corrupted output.
- **Strong password handling.** Argon2id (RFC 9106 recommended parameters) or scrypt, with a random salt per file. Passwords are prompted for with confirmation and are never accepted as command-line arguments.
- **Streaming, bounded memory.** Data is processed in chunks (64 KiB by default), so multi-gigabyte files do not need to fit in memory.
- **Batch processing.** Pass several files or directories in one command; you are asked for the password once and a failure on one path does not stop the others.
- **Integrity verification.** `verify` checks that a file is complete, unmodified and that the password is right, without writing any plaintext to disk.
- **Safe outputs.** Results are written to a temporary file and renamed into place only on success, so a failed or tampered decryption never leaves partial plaintext behind. Existing files are not overwritten unless you pass `--force`.
- **Optional removal of the original,** only after the new file has been decrypted and checked in full, with an optional best-effort overwrite (see the limitations below for why this is not a guarantee).
- **Self-describing, versioned format.** Every file records its KDF and parameters, so defaults can be strengthened later without breaking old files. `info` shows them without needing the password.

## Security design

**Key derivation.** Your password is normalised (Unicode NFC, so the same visible password always gives the same bytes) and stretched with Argon2id (t=3, 64 MiB, p=4) using a fresh 16-byte random salt, giving a 32-byte master key. scrypt (N=2^17, r=8, p=1) is available with `--kdf scrypt`. The master key is split with HKDF-SHA256 into two independent subkeys: one for AES-256-GCM and one for a header MAC.

**Header.** Each file starts with an 82-byte header: magic bytes, format version, payload type (file or directory), KDF identifier and cost parameters, chunk size, salt and a 7-byte random nonce prefix, followed by an HMAC-SHA256 over those fields. The MAC lets the tool say "wrong password" up front instead of failing part way through. The same header bytes are also passed as associated data (AAD) to every encrypted chunk, so the header cannot be changed without breaking the payload, even by someone who could forge the MAC.

**Chunked AEAD (the STREAM construction).** The plaintext is split into chunks and each is sealed separately with AES-256-GCM. Each chunk's 96-bit nonce is `prefix (7 bytes) || chunk counter (4 bytes) || last-chunk flag (1 byte)`, the same layout Google Tink uses for streaming AEAD. The counter means chunks cannot be reordered, duplicated or dropped from the middle. The flag marks the final chunk, so cutting the file off at a chunk boundary is detected rather than silently accepted as a shorter file. An empty input still produces one authenticated (empty) final chunk. Because every file has its own salt, every file also has its own key, so nonces are never reused under the same key.

**Defensive parsing.** KDF parameters and chunk size read from a header are bounds-checked before any work is done, so a crafted file cannot make the tool allocate gigabytes of memory. Directory archives are extracted with Python's `data` tar filter (no absolute paths, no `..`, no links out of the tree) into a staging directory, and the rest of the stream is authenticated before the result is moved into place.

**File format (version 1).**

| Offset | Size | Field |
|-------:|-----:|-------|
| 0 | 8 | Magic `AESFILE\0` |
| 8 | 1 | Format version (1) |
| 9 | 1 | Payload type (0 = file, 1 = directory as tar) |
| 10 | 1 | KDF (1 = Argon2id, 2 = scrypt) |
| 11 | 12 | Three uint32 KDF parameters |
| 23 | 4 | Chunk size in bytes |
| 27 | 16 | Salt |
| 43 | 7 | Nonce prefix |
| 50 | 32 | HMAC-SHA256 of bytes 0 to 49 |
| 82 | ... | Chunks: ciphertext plus 16-byte GCM tag each |

## Threat model and limitations

This tool is designed to protect the **confidentiality and integrity of files at rest**, for example a file on a USB stick, in cloud storage or sent as an email attachment, against someone who obtains the encrypted file but not your password.

What it does not protect against, and things you should know:

- **Weak passwords.** Argon2id makes each guess expensive, but it cannot rescue a short or common password. Use a long passphrase. The tool warns below 12 characters but does not refuse.
- **A compromised computer.** Malware, keyloggers or anyone with access to your running session can capture the password or the plaintext. Encryption cannot help once the machine itself is untrusted.
- **Secure deletion is best effort only.** `--shred` overwrites the file's contents once with random data before deleting it. On SSDs and flash storage (wear levelling), on copy-on-write or journalling filesystems such as APFS (the macOS default), Btrfs and ZFS, and wherever snapshots, Time Machine or other backups, or cloud sync exist, old copies of the data can survive. Full-disk encryption is the reliable way to deal with remnants on disk.
- **Metadata is not hidden for single files.** The encrypted file's size reveals the approximate size of the original, and the default output name (`report.pdf.enc`) keeps the original name. Rename the output if the name itself is sensitive. Directory contents (names, structure) are inside the encryption.
- **Directories: only regular files, folders and hard links are archived.** Symbolic links and special files are skipped and listed in the output. If anything was skipped, the original is kept even if you asked for it to be deleted. On restore, file permissions come back without group/other write and setuid/setgid bits, while directory permissions and ownership are not restored. These are the rules of Python's safe `data` tar filter.
- **Temporary plaintext during decryption.** Decrypted data is written to a temporary file (mode 0600) next to the destination and deleted if authentication fails, but that deletion is an ordinary one.
- **Passwords in memory.** Python strings are immutable and cannot be reliably wiped, so the password and key may remain in process memory until it exits.
- **No key files, recovery or sharing.** There is no way to recover a file if the password is lost, and no public-key mode for sending files to someone else. Tools such as `age` or GnuPG are better suited to that.
- **Not independently audited.** The design uses standard, well-reviewed primitives from the `cryptography` and `argon2-cffi` libraries rather than implementing any cryptography by hand, but the tool itself has not had a professional security review.

## Project structure

```
AES-256-Secure-File-Encryption-Utility/
├── securecrypt/
│   ├── __init__.py      public API: encrypt_path, decrypt_path, verify_path, inspect_path
│   ├── __main__.py      python -m securecrypt
│   ├── cli.py           argparse front end, password prompting
│   ├── gui.py           Tkinter front end (worker thread keeps the window responsive)
│   ├── operations.py    file/directory handling, atomic outputs, removal of originals
│   ├── stream.py        key schedule, chunked AES-256-GCM writer and reader
│   ├── header.py        versioned on-disk header format
│   ├── kdf.py           Argon2id and scrypt parameters and derivation
│   ├── shred.py         best-effort overwrite and deletion
│   └── errors.py        user-facing exception types
├── tests/               pytest suite
├── pyproject.toml
├── requirements.txt     pinned runtime dependencies
├── requirements-dev.txt pinned test dependencies
└── Makefile
```

The layers are deliberately separate: `stream.py` knows nothing about files on disk, `operations.py` knows nothing about the user interface, and the CLI and GUI are thin wrappers over `operations.py`.

## Tech stack

- Python 3.12 or newer (developed and tested on Python 3.14)
- [`cryptography`](https://cryptography.io/) for AES-GCM, HKDF, HMAC primitives and scrypt
- [`argon2-cffi`](https://argon2-cffi.readthedocs.io/) for Argon2id
- Tkinter (bundled with most Python installations) for the GUI
- pytest for tests

## Getting started

```bash
git clone https://github.com/Omith786/AES-256-Secure-File-Encryption-Utility.git
cd AES-256-Secure-File-Encryption-Utility
python3 -m venv .venv
source .venv/bin/activate
pip install -r requirements-dev.txt
pip install -e . --no-deps      # installs the `securecrypt` command
```

Or simply `make install`. Without installing the package you can run everything as `python -m securecrypt ...` from the project folder.

On some Linux distributions Tkinter is a separate package (for example `sudo apt install python3-tk`). The command-line tool works without it.

## Usage

### Graphical interface

```bash
securecrypt gui
```

Choose a file or folder, type the password twice and press **Encrypt**. To decrypt, choose the `.enc` file, enter the password and press **Decrypt**. **Verify** checks a `.enc` file without writing anything.

### Command line

```bash
# Encrypt a file (prompts for the password twice) -> report.pdf.enc
securecrypt encrypt report.pdf

# Encrypt a whole directory -> photos.enc
securecrypt encrypt photos/

# Several at once; delete the originals once each output has been verified
securecrypt encrypt tax-2025.pdf passport-scan.png --delete-original

# Decrypt (restores report.pdf, or the photos/ directory)
securecrypt decrypt report.pdf.enc photos.enc

# Choose the output name
securecrypt decrypt report.pdf.enc -o restored.pdf

# Check integrity and password without writing plaintext
securecrypt verify report.pdf.enc

# Show the header (no password needed)
securecrypt info report.pdf.enc
```

Example `info` output:

```
report.pdf.enc
  format version : 1
  contents       : file
  cipher         : AES-256-GCM, 64 KiB chunks
  key derivation : Argon2id (t=3, m=64 MiB, p=4)
```

Other options: `--kdf scrypt`, `--chunk-size KIB`, `--force` to overwrite existing outputs, and `--shred` to overwrite originals before deleting them (read the limitations above first).

For scripts, `--password-stdin` reads the password from the first line of standard input, for example from a password manager's CLI:

```bash
pass show backups/key | securecrypt encrypt --password-stdin backup.tar
```

Exit status is 0 on success, 1 if any path failed and 2 for usage errors.

Typical error messages:

```
error: report.pdf.enc: Wrong password, or the file header has been modified.
error: report.pdf.enc: Chunk 3 failed authentication: the file has been modified.
error: report.pdf.enc: Encrypted file is truncated, has extra data appended, or its final chunk was modified.
```

## Testing

```bash
make test        # or: python -m pytest
```

The suite (75 tests) covers round trips at and around chunk boundaries, empty files, a multi-megabyte file across many chunks, wrong passwords, bit flips in the header, MAC, ciphertext and tags, reordered and dropped chunks, truncation at and inside chunk boundaries, appended data, a forged header with a valid MAC (to prove the header is bound as AAD), hostile KDF parameters, Unicode password normalisation, directory archives, atomic output with no leftovers after failures, removal of originals, the CLI, and the GUI's form logic. The GUI test builds the window hidden and never shows it. Tests use the cheapest KDF parameters the format allows so the suite runs in a few seconds; the code paths are otherwise identical.

## Possible future work

- A progress bar with real percentages in the GUI and CLI for very large files
- Optional key files or hardware security keys as a second factor alongside the password
- Public-key recipients (for example X25519) so files can be shared without sharing a password
- Encrypting file names for single-file mode, and padding to hide exact sizes
- Integration with cloud storage, as suggested in the original project, uploading only the encrypted output
- Packaged desktop builds for Windows and macOS

## Licence

MIT, see [LICENSE](LICENSE).
