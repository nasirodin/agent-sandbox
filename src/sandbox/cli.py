"""`sandbox [options] -- <cmd...>`: run one command in the sandbox, for manual testing.

Without `--policy`, the current directory is writable, `$HOME` is hidden except for the
current directory, and there is no network.
"""

import argparse
import asyncio
import os
import re
import sys
import tempfile
from pathlib import Path

from sandbox.net.credentials import SECRET_FIELD, CredentialError
from sandbox.policy import (
    Credential,
    FilesystemPolicy,
    HostAccess,
    NetworkPolicy,
    RequestFilter,
    SandboxPolicy,
)
from sandbox.runtime import Sandbox, SandboxUnavailable

_ENV_REF = re.compile(r"\{([A-Za-z_][A-Za-z0-9_]*)\}")


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


def _inject_credential(spec: str) -> tuple[str, Credential]:
    """`"api.github.com Authorization: Bearer {GITHUB_TOKEN}"` -> (host, credential): the
    header is set on every request, `{NAME}` replaced by the host environment variable."""
    host, _, line = spec.strip().partition(" ")
    header, sep, template = line.partition(":")
    names = _ENV_REF.findall(template)
    if not sep or len(names) != 1:
        # quoting nothing of the spec: a token pasted instead of {ENV_VAR} must not be echoed
        raise ValueError(
            "--inject-credential: expected 'HOST Header: value with one {ENV_VAR}' naming "
            "the host environment variable holding the secret"
        )
    value = _ENV_REF.sub(SECRET_FIELD, template.strip())
    return host, Credential(header=header.strip(), secret_env=names[0], inject=value)


def _placeholder_credential(spec: str, elsewhere: bool) -> tuple[str, Credential]:
    """`"api.github.com GITHUB_TOKEN [Header]"` -> (host, credential): inside the sandbox
    the variable holds a placeholder (`_sandbox_env`), which the proxy replaces by the host
    variable's value in the header (default Authorization)."""
    parts = spec.split()
    # Quoting nothing of the spec, and checking that ENV_VAR is set before using it: a
    # token pasted in its place must not be echoed, by this error or a later one.
    if len(parts) not in (2, 3):
        raise ValueError("--placeholder-credential: expected 'HOST ENV_VAR [Header]'")
    host, name, *header = parts
    if name not in os.environ:
        raise ValueError(
            f"--placeholder-credential for {host}: ENV_VAR must name a variable set in the "
            "host environment, holding the secret"
        )
    credential = Credential(
        header=header[0] if header else "Authorization",
        secret_env=name,
        placeholder=f"SANDBOX_PLACEHOLDER_{name}",
        allow_placeholder_elsewhere=elsewhere,
    )
    return host, credential


def _hosts(args: argparse.Namespace) -> dict[str, HostAccess]:
    hosts: dict[str, HostAccess] = {h: HostAccess(access="deny") for h in args.deny_domain}
    hosts |= {h: HostAccess(access="tunnel") for h in args.allow_domain}
    allow: dict[str, list[RequestFilter]] = {}
    deny: dict[str, list[RequestFilter]] = {}
    for into, specs in ((allow, args.allow_request), (deny, args.deny_request)):
        for spec in specs:
            host, f = _request_filter(spec)
            into.setdefault(host, []).append(f)
    credentials: dict[str, list[Credential]] = {}
    for spec in args.inject_credential:
        host, c = _inject_credential(spec)
        credentials.setdefault(host, []).append(c)
    if args.allow_placeholder_elsewhere and not args.placeholder_credential:
        raise ValueError("--allow-placeholder-elsewhere needs a --placeholder-credential")
    for spec in args.placeholder_credential:
        host, c = _placeholder_credential(spec, args.allow_placeholder_elsewhere)
        credentials.setdefault(host, []).append(c)
    for host in credentials.keys() - allow.keys():
        raise ValueError(f"credentials need an inspected host: add --allow-request for {host}")
    for host in allow.keys() | deny.keys():
        hosts[host] = HostAccess(
            access="inspect",
            allow=allow.get(host, []),
            deny=deny.get(host, []),
            credentials=credentials.get(host, []),
        )
    return hosts


def _sandbox_env(hosts: dict[str, HostAccess]) -> dict[str, str]:
    """The command's environment. A placeholder credential's variable holds its
    placeholder, so the command uses it as it would the secret; the secret itself stays in
    the host environment."""
    env = {"HOME": "/tmp", "LANG": os.environ.get("LANG", "C.UTF-8")}
    for h in hosts.values():
        for c in h.credentials:
            if c.placeholder is not None and c.secret_env is not None:
                env[c.secret_env] = c.placeholder
    return env


def _default_policy(args: argparse.Namespace) -> SandboxPolicy:
    cwd = os.getcwd()
    hosts = _hosts(args)
    return SandboxPolicy(
        filesystem=FilesystemPolicy(
            deny_read=[str(Path.home()), *args.deny_read],
            allow_read=[cwd],
            allow_write=[cwd, *args.allow_write],
        ),
        network=NetworkPolicy(hosts=hosts),
        env=_sandbox_env(hosts),
    )


def _policy(args: argparse.Namespace) -> SandboxPolicy:
    if args.policy:
        return SandboxPolicy.model_validate_json(Path(args.policy).read_text())
    return _default_policy(args)


async def _main(args: argparse.Namespace, policy: SandboxPolicy) -> int:
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
        "--inject-credential",
        action="append",
        default=[],
        metavar="RULE",
        help="set a header on requests to an inspected host from a host environment "
        'variable, e.g. "api.github.com Authorization: Bearer {GITHUB_TOKEN}"',
    )
    p.add_argument(
        "--placeholder-credential",
        action="append",
        default=[],
        metavar="RULE",
        help="HOST ENV_VAR [HEADER]: inside the sandbox ENV_VAR holds a placeholder, replaced "
        "by the host's ENV_VAR in HEADER (default Authorization) of requests to an inspected "
        'host, e.g. "api.github.com GITHUB_TOKEN"',
    )
    p.add_argument(
        "--allow-placeholder-elsewhere",
        action="store_true",
        help="forward requests carrying a --placeholder-credential placeholder where it is not "
        "replaced (other hosts, URLs, other headers, bodies) instead of refusing them",
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
        policy = _policy(args)
    except (OSError, ValueError) as e:  # an unreadable --policy, bad options or policy
        sys.exit(f"sandbox: {e}")
    try:
        sys.exit(asyncio.run(_main(args, policy)))
    except (SandboxUnavailable, CredentialError) as e:
        sys.exit(f"sandbox: {e}")


if __name__ == "__main__":
    main()
