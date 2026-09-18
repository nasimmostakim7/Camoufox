"""Guards for how a browser release repository is chosen.

`repos.yml` lists a primary repo followed by fallbacks, and
`list_available_versions()` walks that list until one answers with releases it
can use. The fork is primary, because only its releases are built from this tree
and so carry the Juggler and fingerprint patches the patch guards assert on.
Upstream is the fallback, which is what keeps `camoufox fetch` working while the
fork has no release of the current Firefox generation yet.

That fallback has a trap in it. Before this guard, a repo that answered `200`
with an empty release list was treated as a successful answer and stopped the
walk -- so making the fork primary would have made every fetch fail on the first
repo that had not published yet, hiding upstream completely. An empty list is
not a failure, but it is not an answer either.
"""


from camoufox.pkgman import (
    ARCH_MAP,
    OS_MAP,
    RepoConfig,
    list_available_versions,
)

FORK = "mostakimnasim3/camoufox"
UPSTREAM = "daijro/camoufox"

ASSET = "camoufox-152.0.4-beta.30-lin.x86_64.zip"


class _Response:
    def __init__(self, payload):
        self._payload = payload

    def raise_for_status(self):
        pass

    def json(self):
        return self._payload


def _release(name=ASSET):
    return {
        "prerelease": False,
        "assets": [
            {
                "name": name,
                "browser_download_url": f"https://example.invalid/{name}",
                "id": 1,
                "size": 1,
                "updated_at": "2026-09-05T00:00:00Z",
                "created_at": "2026-09-05T00:00:00Z",
            }
        ],
    }


def _config(repos):
    return RepoConfig(
        repos=repos,
        name="Official",
        pattern="{name}-{version}-{build}-{os}.{arch}.zip",
        os_map=OS_MAP,
        arch_map=ARCH_MAP,
        stable_min="beta.19",
        stable_max="1",
    )


def test_an_empty_primary_falls_through_to_the_fallback(monkeypatch):
    """The fork between release cuts must not hide upstream behind it."""
    payloads = {FORK: [], UPSTREAM: [_release()]}

    def fake_get(url, **kwargs):
        repo = "/".join(url.split("/repos/")[1].split("/")[:2])
        return _Response(payloads[repo])

    monkeypatch.setattr("camoufox.pkgman.requests.get", fake_get)

    versions = list_available_versions(repo_config=_config([FORK, UPSTREAM]))

    assert [v.version.build for v in versions] == ["beta.30"], (
        "an empty release list on the primary repo stopped the walk, so the "
        "fallback was never consulted"
    )


def test_the_primary_repo_wins_when_it_has_a_release(monkeypatch):
    """Ordering is what decides precedence, not which repo answers first."""
    payloads = {FORK: [_release("camoufox-152.0.4-beta.40-lin.x86_64.zip")], UPSTREAM: [_release()]}

    def fake_get(url, **kwargs):
        repo = "/".join(url.split("/repos/")[1].split("/")[:2])
        return _Response(payloads[repo])

    monkeypatch.setattr("camoufox.pkgman.requests.get", fake_get)

    versions = list_available_versions(repo_config=_config([FORK, UPSTREAM]))

    assert [v.version.build for v in versions] == ["beta.40"]


def test_a_failing_primary_falls_through_to_the_fallback(monkeypatch):
    """A 404 on the fork must not take the whole fetch down with it."""
    payloads = {FORK: RuntimeError("404"), UPSTREAM: [_release()]}

    def fake_get(url, **kwargs):
        repo = "/".join(url.split("/repos/")[1].split("/")[:2])
        result = payloads[repo]
        if isinstance(result, Exception):
            raise result
        return _Response(result)

    monkeypatch.setattr("camoufox.pkgman.requests.get", fake_get)

    versions = list_available_versions(repo_config=_config([FORK, UPSTREAM]))

    assert [v.version.build for v in versions] == ["beta.30"]


def test_a_release_for_another_platform_falls_through(monkeypatch):
    """A release is not an answer unless it has an asset this platform can install.

    The fork may publish only the targets CI needs. If the walk stopped at a
    release whose assets do not match the running platform, a Windows or macOS
    user would get "no versions" from a repo that plainly has releases, and never
    reach the fallback.
    """
    payloads = {
        FORK: [_release("camoufox-152.0.4-beta.30-mac.arm64.zip")],
        UPSTREAM: [_release()],
    }

    def fake_get(url, **kwargs):
        repo = "/".join(url.split("/repos/")[1].split("/")[:2])
        return _Response(payloads[repo])

    monkeypatch.setattr("camoufox.pkgman.requests.get", fake_get)

    versions = list_available_versions(
        repo_config=_config([FORK, UPSTREAM]), spoof_os="lin", spoof_arch="x86_64"
    )

    assert [v.version.build for v in versions] == ["beta.30"]


def test_the_default_repo_is_the_fork_with_upstream_behind_it():
    """The shipped config, not a hand-built one: order and fallback matter.

    Only the fork's releases are built from this tree. If upstream were primary,
    a driver-only CI run would download a browser without the patches the patch
    guards assert on, and the guards would fail -- which is exactly the failure
    this ordering exists to prevent.
    """
    repos = RepoConfig.get_default().repos

    assert repos[0] == FORK, f"the primary release repo is {repos[0]!r}, not the fork"
    assert UPSTREAM in repos, "upstream is no longer a fallback"


def test_the_official_name_is_unchanged():
    """`Official` is the default channel and the install directory name.

    Renaming it would move every existing install and change what
    `browsers/official/...` resolves to, so it stays even though the repo behind
    it changed.
    """
    import camoufox.pkgman as pkgman

    assert RepoConfig.get_default_name() == "Official"
    assert pkgman.OS_NAME  # the module imported cleanly against the shipped config