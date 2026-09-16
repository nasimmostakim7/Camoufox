"""Regression coverage for ``camoufox path`` and the versioned layout.

``fetch`` installs the browser under ``browsers/<repo>/<version>/``, but the
``path`` command kept printing ``INSTALL_DIR`` from before that layout existed.
Anything that then looked for ``$(camoufox path)/camoufox-bin`` -- the CI job
that downloads the published release, or any user script -- failed with "not
found" on a machine where the browser was installed and working.

The command silently pointed at the wrong directory for as long as the two
disagreed, because printing a path never errors. These tests compare the path
against the layout on disk instead of against a string.
"""

import json

import pytest
from click.testing import CliRunner

from camoufox import __main__ as main
from camoufox import multiversion, pkgman
from camoufox.__main__ import cli


def _install(tmp_path, monkeypatch, layout):
    """Build an install dir in the given layout and point the library at it."""
    root = tmp_path / "cache"
    root.mkdir()
    (root / ".0.5_FLAG").write_text("")
    (root / "repo_cache.json").write_text("{}")

    if layout == "versioned":
        relative = "browsers/official/152.0.4-beta.30-5720d45b"
        (root / "config.json").write_text(json.dumps({"active_version": relative}))
        binary_dir = root / relative
        binary_dir.mkdir(parents=True)
    else:
        (root / "config.json").write_text("{}")
        binary_dir = root

    (binary_dir / "version.json").write_text(
        json.dumps({"version": "152.0.4", "build": "beta.30"})
    )
    (binary_dir / pkgman.LAUNCH_FILE[pkgman.OS_NAME]).write_text("#!/bin/sh\n")
    (binary_dir / pkgman.LAUNCH_FILE[pkgman.OS_NAME]).chmod(0o755)

    for module in (pkgman, multiversion):
        monkeypatch.setattr(module, "INSTALL_DIR", root)
    monkeypatch.setattr(multiversion, "BROWSERS_DIR", root / "browsers")
    monkeypatch.setattr(multiversion, "CONFIG_FILE", root / "config.json")
    monkeypatch.setattr(multiversion, "COMPAT_FLAG", root / ".0.5_FLAG")
    # `path` reads the name it imported into __main__, not pkgman's attribute.
    monkeypatch.setattr(main, "INSTALL_DIR", root)
    return root, binary_dir


@pytest.mark.parametrize("layout", ["versioned", "legacy"])
def test_path_points_at_the_directory_holding_the_browser(
    tmp_path, monkeypatch, layout
):
    """`camoufox path` must name a directory that actually holds the launcher."""
    _, binary_dir = _install(tmp_path, monkeypatch, layout)

    result = CliRunner().invoke(cli, ["path"])

    assert result.exit_code == 0, result.output
    printed = result.output.strip()
    assert printed == str(binary_dir), (
        f"path printed {printed}, build is in {binary_dir}"
    )


def test_path_is_not_install_dir_in_the_versioned_layout(tmp_path, monkeypatch):
    """The specific mistake: the versioned build is one level below INSTALL_DIR."""
    root, _ = _install(tmp_path, monkeypatch, "versioned")

    printed = CliRunner().invoke(cli, ["path"]).output.strip()

    assert printed != str(root)
    assert printed.startswith(str(root / "browsers"))


def test_path_falls_back_to_install_dir_when_nothing_is_active(tmp_path, monkeypatch):
    """No install, no crash: the command still prints a usable directory."""
    root = tmp_path / "cache"
    root.mkdir()
    for module in (pkgman, multiversion):
        monkeypatch.setattr(module, "INSTALL_DIR", root)
    monkeypatch.setattr(multiversion, "BROWSERS_DIR", root / "browsers")
    monkeypatch.setattr(multiversion, "CONFIG_FILE", root / "config.json")
    monkeypatch.setattr(main, "INSTALL_DIR", root)

    result = CliRunner().invoke(cli, ["path"])

    assert result.exit_code == 0, result.output
    assert result.output.strip() == str(root)
