"""GUI tests. Form validation is pure logic; the widget test never shows a window."""

from __future__ import annotations

from pathlib import Path

import pytest
from conftest import PASSWORD

tk = pytest.importorskip("tkinter")

from securecrypt.gui import App, check_inputs  # noqa: E402


def test_check_inputs(tmp_path: Path) -> None:
    existing = tmp_path / "f"
    existing.write_text("x")
    assert check_inputs("encrypt", "", "pw", "pw") is not None
    assert check_inputs("encrypt", str(tmp_path / "missing"), "pw", "pw") is not None
    assert check_inputs("encrypt", str(existing), "", "") is not None
    assert "match" in (check_inputs("encrypt", str(existing), "pw", "other") or "")
    assert check_inputs("decrypt", str(existing), "pw", "") is None
    assert check_inputs("encrypt", str(existing), "pw", "pw") is None


@pytest.fixture
def app():
    try:
        root = tk.Tk()
    except tk.TclError:
        pytest.skip("no display available")
    root.withdraw()
    try:
        yield App(root)
    finally:
        root.destroy()


def test_window_builds_and_jobs_run(app: App, tmp_path: Path) -> None:
    src = tmp_path / "doc.txt"
    src.write_text("from the gui")
    app.delete_original.set(True)

    message = app._job("encrypt", src, PASSWORD)()
    assert "Encrypted" in message and not src.exists()
    enc = tmp_path / "doc.txt.enc"
    assert "intact" in app._job("verify", enc, PASSWORD)()
    app._job("decrypt", enc, PASSWORD)()
    assert src.read_text() == "from the gui"
