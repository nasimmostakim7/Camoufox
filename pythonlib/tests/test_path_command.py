"""
``camoufox path`` and the directory the browser actually lives in.

``fetch`` installs a browser under ``browsers/<channel>/<version>/``, so the
cache root and the directory holding ``camoufox-bin`` stopped being the same
place. ``path`` kept printing the root, and the job that packs the published
release then copied a tree with no binary in it and failed on the far side of a
download -- the release was fine and the command was pointing at the wrong spot.

The regression is invisible by inspection: printing a path never errors, so the
two only disagree silently. These tests compare the commands against the layout
on disk rather than against a literal string, and they pin the older contract of
``path`` as well, because callers depend on the root too.
"""

import os
import sys

import pytest
from click.testing import CliRunner

sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))

from camoufox.__main__ import cli  # noqa: E402


@pytest.fixture
def versioned_layout(tmp_path, monkeypatch):
    """
    A cache root whose binary sits in a per-version subdirectory.

    This is the shape `fetch` produces. The binary is not at the root, which is
    the whole point: a `path` that returns the root cannot find it.
    """
    root = tmp_path / "camoufox"
    browser = root / "browsers" / "official" / "152.0.4-beta.30-5720d45b"
    browser.mkdir(parents=True)
    binpath = browser / "camoufox-bin"
    binpath.write_text("#!/bin/sh\n")
    binpath.chmod(0o755)
    (browser / "properties.json").write_text("{}", encoding="utf-8")
    (browser / "camoufox.cfg").write_text("", encoding="utf-8")
    (browser / "fonts" / "linux").mkdir(parents=True)
    (browser / "fontconfig" / "linux").mkdir(parents=True)

    import camoufox.__main__ as main_mod
    import camoufox.pkgman as pkgman

    monkeypatch.setattr(main_mod, "INSTALL_DIR", str(root))
    monkeypatch.setattr(pkgman, "camoufox_path", lambda *a, **k: browser)
    return root, browser


def run_cli(*args):
    return CliRunner().invoke(cli, list(args))


def test_path_still_prints_the_install_directory(versioned_layout):
    """`path` is the cache root and stays that way; callers rely on it."""
    root, browser = versioned_layout
    result = run_cli("path")
    assert result.exit_code == 0, result.output
    assert result.output.strip() == str(root)
    assert result.output.strip() != str(browser)


def test_path_browser_prints_the_directory_holding_the_binary(versioned_layout):
    """The flag exists so a caller can pack the browser without guessing the layout."""
    root, browser = versioned_layout
    result = run_cli("path", "--browser")
    assert result.exit_code == 0, result.output
    assert result.output.strip() == str(browser)
    assert (browser / "camoufox-bin").is_file()


def test_path_browser_finds_every_artifact_the_browser_needs(versioned_layout):
    """
    The five files the build path and the fetch path both promise.

    Packaging the wrong directory is only one way to fail: a directory with the
    binary but no fonts launches and then renders text as boxes. The fetch job
    asserts the same list, so a change here has to be made in both places.
    """
    _, browser = versioned_layout
    result = run_cli("path", "--browser")
    found = result.output.strip()
    for required in (
        "camoufox-bin",
        "properties.json",
        "camoufox.cfg",
        "fonts/linux",
        "fontconfig/linux",
    ):
        assert os.path.exists(os.path.join(found, required)), required


def test_path_browser_is_not_the_install_dir_in_the_versioned_layout(versioned_layout):
    """Pin the bug directly: the two answers must not coincide here."""
    root, _ = versioned_layout
    browser = run_cli("path", "--browser").output.strip()
    assert browser != str(root), (
        "with the versioned layout, --browser must differ from the install dir"
    )