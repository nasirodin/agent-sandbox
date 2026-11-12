"""`sandbox [options] -- <cmd...>`: run one command in the sandbox, for manual testing.

Without `--policy`, the current directory is writable, `$HOME` is hidden except for the
current directory, and there is no network.
"""

import argparse
import asyncio
import os
import sys
import tempfile
from pathlib import Path

from sandbox.policy import FilesystemPolicy, HostAccess, NetworkPolicy, RequestFilter, SandboxPolicy
from sandbox.runtime import Sandbox, SandboxUnavailable


def _request_filter(spec: str) -> tuple[str, RequestFilter]:
    """`"GET,HEAD api.github.com/repos/**?state=open*"` -> (host, filter): methods, path and
    query are optional, and the first `?` starts the query (use `--policy` for `?` globs)."""
    methods: list[str] = []
    head, _, rest = spec.strip().partition(" ")
    spec = head
    if rest:
        methods, spec = head.split(","), rest.strip()
    host, slash, tail = spec.partition("/")
    path, _, query = ("/" + tail).partition("?") if slash else ("/**", "", "")
    params: dict[str, str] = {}
    for pair in query.split("&"):
        if pair:
            name, _, value = pair.partition("=")
            params[name] = value
    return host, RequestFilter(methods=methods, path=path, query=params)


def _hosts(args: argparse.Namespace) -> dict[str, HostAccess]:
    hosts: dict[str, HostAccess] = {h: HostAccess(access="deny") for h in args.deny_domain}
    hosts |= {h: HostAccess(access="tunnel") for h in args.allow_domain}
    filters: dict[str, dict[str, list[RequestFilter]]] = {}
    for key, specs in (("allow", args.allow_request), ("deny", args.deny_request)):
        for spec in specs:
            host, f = _request_filter(spec)
            filters.setdefault(host, {"allow": [], "deny": []})[key].append(f)
    for host, lists in filters.items():
        hosts[host] = HostAccess(access="inspect", **lists)
    return hosts


def _default_policy(args: argparse.Namespace) -> SandboxPolicy:
    cwd = os.getcwd()
    return SandboxPolicy(
        filesystem=FilesystemPolicy(
            deny_read=[str(Path.home()), *args.deny_read],
            allow_read=[cwd],
            allow_write=[cwd, *args.allow_write],
        ),
        network=NetworkPolicy(hosts=_hosts(args)),
        env={"HOME": "/tmp", "LANG": os.environ.get("LANG", "C.UTF-8")},
    )


async def _main(args: argparse.Namespace) -> int:
    if args.policy:
        policy = SandboxPolicy.model_validate_json(Path(args.policy).read_text())
    else:
        policy = _default_policy(args)
    log = Path(args.event_log) if args.event_log not in (None, "-") else None
    with tempfile.TemporaryDirectory(prefix="sandbox-") as session:
        async with Sandbox(policy, Path(session), event_log=log) as sandbox:
            result = await sandbox.exec(args.cmd, timeout_s=args.timeout)
    sys.stdout.write(result.stdout)
    sys.stderr.write(result.stderr)
    if args.event_log == "-":
        for event in result.network_events:
            print(event.model_dump_json(exclude_none=True), file=sys.stderr)
    for v in result.violations:
        print(f"[sandbox] {v.kind}: {v.detail}", file=sys.stderr)
    if result.timed_out:
        print(f"[sandbox] timed out after {args.timeout}s", file=sys.stderr)
    return result.exit_code


def main() -> None:
    p = argparse.ArgumentParser(prog="sandbox", description=__doc__)
    p.add_argument("--policy", help="SandboxPolicy JSON file (overrides the other options)")
    p.add_argument("--allow-write", action="append", default=[], metavar="PATH")
    p.add_argument("--deny-read", action="append", default=[], metavar="PATH")
    p.add_argument(
        "--allow-domain", action="append", default=[], metavar="HOST", help="`tunnel` access"
    )
    p.add_argument(
        "--deny-domain", action="append", default=[], metavar="HOST", help="`deny` access"
    )
    p.add_argument(
        "--allow-request",
        action="append",
        default=[],
        metavar="RULE",
        help='`inspect` access with an allow filter, e.g. "GET api.github.com/repos/**"',
    )
    p.add_argument(
        "--deny-request",
        action="append",
        default=[],
        metavar="RULE",
        help='deny filter for an inspected host, e.g. "DELETE api.github.com/**"',
    )
    p.add_argument(
        "--event-log",
        metavar="PATH",
        help="append every network decision to PATH as JSON lines (`-`: stderr, after the run)",
    )
    p.add_argument("--timeout", type=float, default=120)
    p.add_argument("cmd", nargs="+")
    args = p.parse_args()
    try:
        sys.exit(asyncio.run(_main(args)))
    except SandboxUnavailable as e:
        sys.exit(f"sandbox: {e}")


if __name__ == "__main__":
    main()
