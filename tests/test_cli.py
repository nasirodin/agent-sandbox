import argparse

import pytest

from sandbox.cli import _hosts


def args(**kw: list[str]) -> argparse.Namespace:
    base = {"allow_domain": [], "deny_domain": [], "allow_request": [], "deny_request": []}
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
