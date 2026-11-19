import argparse
import re
import sys

import pytest

from sandbox import NetworkPolicy
from sandbox.cli import _hosts, _sandbox_env, main


def args(**kw: object) -> argparse.Namespace:
    base = {
        "allow_domain": [],
        "deny_domain": [],
        "allow_request": [],
        "deny_request": [],
        "inject_credential": [],
        "placeholder_credential": [],
        "allow_placeholder_elsewhere": False,
        "deny_read": [],
        "allow_write": [],
    }
    return argparse.Namespace(**(base | kw))


def test_flags_build_one_entry_per_host() -> None:
    hosts = _hosts(
        args(
            allow_domain=["pypi.org"],
            deny_domain=["*:22"],
            allow_request=["GET,HEAD api.github.com/repos/**?state=open*", "api.github.com/meta"],
            deny_request=["DELETE api.github.com"],
        )
    )
    assert {h: a.access for h, a in hosts.items()} == {
        "*:22": "deny",
        "pypi.org": "tunnel",
        "api.github.com": "inspect",
    }
    api = hosts["api.github.com"]
    assert [(f.methods, f.path, f.query) for f in api.allow] == [
        (["GET", "HEAD"], "/repos/**", {"state": "open*"}),
        ([], "/meta", {}),
    ]
    assert [(f.methods, f.path) for f in api.deny] == [(["DELETE"], "/**")]


def test_deny_request_alone_is_refused() -> None:
    with pytest.raises(ValueError, match="at least one allow filter"):
        _hosts(args(deny_request=["DELETE api.github.com"]))


def test_credential_flags(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("GITHUB_TOKEN", "ghp_secret")
    monkeypatch.setenv("API_KEY", "k3y")
    hosts = _hosts(
        args(
            allow_request=["GET api.github.com/**"],
            inject_credential=["api.github.com X-Api-Key: key={API_KEY}"],
            placeholder_credential=["api.github.com GITHUB_TOKEN"],
        )
    )
    api = hosts["api.github.com"]
    assert [(c.header, c.secret_env, c.inject, c.placeholder) for c in api.credentials] == [
        ("X-Api-Key", "API_KEY", "key={secret}", None),
        ("Authorization", "GITHUB_TOKEN", None, "SANDBOX_PLACEHOLDER_GITHUB_TOKEN"),
    ]
    # inside, GITHUB_TOKEN is the placeholder; the real values stay in the host environment
    env = _sandbox_env(hosts)
    assert env["GITHUB_TOKEN"] == "SANDBOX_PLACEHOLDER_GITHUB_TOKEN" and "API_KEY" not in env
    network = NetworkPolicy(hosts=hosts)
    assert "ghp_secret" not in network.model_dump_json() and "k3y" not in str(network)
    assert [c.secret for c in network.resolve_credentials().all] == ["k3y", "ghp_secret"]
    assert not api.credentials[1].allow_placeholder_elsewhere  # refused elsewhere by default
    relaxed = _hosts(
        args(
            allow_request=["GET api.github.com/**"],
            placeholder_credential=["api.github.com GITHUB_TOKEN"],
            allow_placeholder_elsewhere=True,
        )
    )
    assert relaxed["api.github.com"].credentials[0].allow_placeholder_elsewhere


TOKEN = "ghp_pastedInsteadOfAName"


@pytest.mark.parametrize(
    ("kw", "error"),
    [
        ({"inject_credential": ["api.x.com Authorization: Bearer {T}"]}, "inspected host"),
        (
            {"allow_request": ["api.x.com"], "inject_credential": ["api.x.com Authorization"]},
            "one {ENV_VAR}",
        ),
        (
            {"allow_request": ["api.x.com"], "inject_credential": ["api.x.com A: {X} {Y}"]},
            "one {ENV_VAR}",
        ),
        ({"allow_request": ["api.x.com"], "placeholder_credential": ["api.x.com"]}, "HOST ENV"),
        (
            {"allow_request": ["api.x.com"], "placeholder_credential": ["api.x.com UNSET_VAR"]},
            "must name a variable set",
        ),
        ({"allow_request": ["api.x.com"], "allow_placeholder_elsewhere": True}, "needs a"),
    ],
)
def test_bad_credential_flags(kw: dict[str, list[str]], error: str) -> None:
    with pytest.raises(ValueError, match=re.escape(error)):
        _hosts(args(**kw))


@pytest.mark.parametrize(
    "kw",
    [
        {"placeholder_credential": [f"api.x.com {TOKEN}"]},  # a token instead of ENV_VAR
        {"placeholder_credential": [f"api.x.com Authorization {TOKEN} x"]},
        {"inject_credential": [f"api.x.com Authorization: Bearer {TOKEN}"]},
        {"inject_credential": [TOKEN]},
    ],
)
def test_bad_credential_flags_do_not_echo_a_token(kw: dict[str, list[str]]) -> None:
    with pytest.raises(ValueError) as e:
        _hosts(args(allow_request=["api.x.com"], **kw))
    assert TOKEN not in str(e.value)


def test_bad_options_exit_without_a_traceback(monkeypatch: pytest.MonkeyPatch) -> None:
    for argv in (
        ["--inject-credential", "api.x.com Authorization", "--", "true"],
        ["--deny-request", "DELETE api.x.com", "--", "true"],  # a policy validation error
        ["--policy", "/nonexistent/policy.json", "--", "true"],
    ):
        monkeypatch.setattr(sys, "argv", ["sandbox", *argv])
        with pytest.raises(SystemExit) as e:
            main()
        assert isinstance(e.value.code, str) and e.value.code.startswith("sandbox: "), argv
