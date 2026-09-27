"""A small Tkinter front end for people who would rather not use a terminal.

The window only collects input and shows results. All cryptographic work goes through
:mod:`securecrypt.operations`, the same code path as the CLI, and runs on a worker thread
so the window stays responsive while the key derivation and encryption run.
"""

from __future__ import annotations

import queue
import threading
import tkinter as tk
from collections.abc import Callable
from pathlib import Path
from tkinter import filedialog, messagebox, ttk

from .errors import SecureCryptError
from .operations import Removal, decrypt_path, encrypt_path, verify_path

MIN_RECOMMENDED_PASSWORD = 12


def check_inputs(action: str, path: str, password: str, confirm: str) -> str | None:
    """Return a user-facing problem with the form, or ``None`` if it can be submitted."""
    if not path.strip():
        return "Choose a file or folder first."
    if not Path(path).exists():
        return f"{path} does not exist."
    if not password:
        return "Enter a password."
    if action == "encrypt" and password != confirm:
        return "The two passwords do not match."
    return None


class App:
    """Main window. Construct with a root ``Tk`` and call ``root.mainloop()``."""

    def __init__(self, root: tk.Tk) -> None:
        self.root = root
        self._results: queue.Queue[tuple[bool, str]] = queue.Queue()
        root.title("SecureCrypt: AES-256 file encryption")
        root.resizable(True, False)

        self.path = tk.StringVar()
        self.password = tk.StringVar()
        self.confirm = tk.StringVar()
        self.show = tk.BooleanVar(value=False)
        self.delete_original = tk.BooleanVar(value=False)
        self.shred = tk.BooleanVar(value=False)
        self.status = tk.StringVar(value="Choose a file or folder to encrypt, or a .enc file to decrypt.")

        frame = ttk.Frame(root, padding=12)
        frame.grid(sticky="nsew")
        root.columnconfigure(0, weight=1)
        frame.columnconfigure(1, weight=1)

        ttk.Label(frame, text="File or folder").grid(row=0, column=0, sticky="w")
        ttk.Entry(frame, textvariable=self.path, width=48).grid(row=0, column=1, sticky="ew", padx=6)
        picker = ttk.Frame(frame)
        picker.grid(row=0, column=2)
        ttk.Button(picker, text="File...", command=self._choose_file).pack(side="left")
        ttk.Button(picker, text="Folder...", command=self._choose_folder).pack(side="left", padx=(4, 0))

        ttk.Label(frame, text="Password").grid(row=1, column=0, sticky="w", pady=(8, 0))
        self._pw_entry = ttk.Entry(frame, textvariable=self.password, show="•")
        self._pw_entry.grid(row=1, column=1, sticky="ew", padx=6, pady=(8, 0))
        ttk.Checkbutton(frame, text="Show", variable=self.show, command=self._toggle_show).grid(
            row=1, column=2, sticky="w", pady=(8, 0)
        )

        ttk.Label(frame, text="Confirm (encrypt)").grid(row=2, column=0, sticky="w", pady=(4, 0))
        self._confirm_entry = ttk.Entry(frame, textvariable=self.confirm, show="•")
        self._confirm_entry.grid(row=2, column=1, sticky="ew", padx=6, pady=(4, 0))

        options = ttk.Frame(frame)
        options.grid(row=3, column=1, sticky="w", padx=6, pady=(8, 0))
        ttk.Checkbutton(
            options, text="Delete the original after encrypting (checked first)", variable=self.delete_original
        ).pack(anchor="w")
        ttk.Checkbutton(
            options,
            text="Overwrite it with random data before deleting (best effort, not reliable on SSDs)",
            variable=self.shred,
        ).pack(anchor="w")

        buttons = ttk.Frame(frame)
        buttons.grid(row=4, column=0, columnspan=3, pady=(12, 0))
        self._buttons = [
            ttk.Button(buttons, text="Encrypt", command=lambda: self._start("encrypt")),
            ttk.Button(buttons, text="Decrypt", command=lambda: self._start("decrypt")),
            ttk.Button(buttons, text="Verify", command=lambda: self._start("verify")),
        ]
        for button in self._buttons:
            button.pack(side="left", padx=4)

        self._progress = ttk.Progressbar(frame, mode="indeterminate")
        self._progress.grid(row=5, column=0, columnspan=3, sticky="ew", pady=(12, 0))
        ttk.Label(frame, textvariable=self.status, wraplength=520).grid(
            row=6, column=0, columnspan=3, sticky="w", pady=(6, 0)
        )

    def _choose_file(self) -> None:
        if chosen := filedialog.askopenfilename():
            self.path.set(chosen)

    def _choose_folder(self) -> None:
        if chosen := filedialog.askdirectory():
            self.path.set(chosen)

    def _toggle_show(self) -> None:
        mask = "" if self.show.get() else "•"
        self._pw_entry.configure(show=mask)
        self._confirm_entry.configure(show=mask)

    def _job(self, action: str, path: Path, password: str) -> Callable[[], str]:
        if action == "encrypt":
            removal = Removal.KEEP
            if self.delete_original.get() or self.shred.get():
                removal = Removal.SHRED if self.shred.get() else Removal.DELETE

            def run() -> str:
                result = encrypt_path(path, password, removal=removal)
                message = f"Encrypted to {result.output}"
                if result.skipped:
                    message += f"\nSkipped {len(result.skipped)} link(s) or special file(s); the original was kept."
                elif result.original_removed:
                    message += "\nThe original has been removed."
                return message

            return run
        if action == "decrypt":
            return lambda: f"Decrypted to {decrypt_path(path, password).output}"

        def verify() -> str:
            verify_path(path, password)
            return f"{path.name} is intact and the password is correct."

        return verify

    def _start(self, action: str) -> None:
        problem = check_inputs(action, self.path.get(), self.password.get(), self.confirm.get())
        if problem:
            messagebox.showwarning("SecureCrypt", problem, parent=self.root)
            return
        if action == "encrypt" and len(self.password.get()) < MIN_RECOMMENDED_PASSWORD:
            if not messagebox.askokcancel(
                "Short password",
                f"Passwords shorter than {MIN_RECOMMENDED_PASSWORD} characters are much easier to guess. Continue?",
                parent=self.root,
            ):
                return

        job = self._job(action, Path(self.path.get()), self.password.get())
        self._set_busy(True, f"Working ({action})... deriving the key takes a moment.")

        def worker() -> None:
            try:
                self._results.put((True, job()))
            except (SecureCryptError, OSError) as exc:
                self._results.put((False, str(exc)))

        threading.Thread(target=worker, daemon=True).start()
        self.root.after(100, self._poll)

    def _poll(self) -> None:
        try:
            ok, message = self._results.get_nowait()
        except queue.Empty:
            self.root.after(100, self._poll)
            return
        self._set_busy(False, message)
        if ok:
            self.password.set("")
            self.confirm.set("")
            messagebox.showinfo("SecureCrypt", message, parent=self.root)
        else:
            messagebox.showerror("SecureCrypt", message, parent=self.root)

    def _set_busy(self, busy: bool, message: str) -> None:
        self.status.set(message)
        for button in self._buttons:
            button.state(["disabled"] if busy else ["!disabled"])
        if busy:
            self._progress.start(12)
        else:
            self._progress.stop()


def run_gui() -> None:
    """Open the main window and block until it is closed."""
    root = tk.Tk()
    App(root)
    root.mainloop()
