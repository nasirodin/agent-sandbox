# agent-sandbox

Run untrusted commands as OS-level sandboxed ("bubble-wrapped") processes.

- **Platforms:** Linux or WSL2 only, with `bwrap` >= 0.5 (`sudo apt-get install bubblewrap`)
  and unprivileged user namespaces. Elsewhere `check_host()` reports the problems and
  `Sandbox.start()` raises `SandboxUnavailable`.
- **Dependencies:** Python 3.14+, stdlib + Pydantic + cryptography.

## Usage

```python
from pathlib import Path
from sandbox import (
    FilesystemPolicy, HostAccess, NetworkPolicy, RequestFilter, Sandbox, SandboxPolicy,
)

policy = SandboxPolicy(
    filesystem=FilesystemPolicy(
        deny_read=[str(Path.home())],     # absolute, literal paths (no globs)
        allow_write=["/work/project"],
    ),
    network=NetworkPolicy(hosts={
        "pypi.org": HostAccess(access="tunnel"),
        "*.pythonhosted.org": HostAccess(access="tunnel"),
        "*:22": HostAccess(access="deny"),
        "api.github.com": HostAccess(
            access="inspect",
            allow=[RequestFilter(methods=["GET"], path="/repos/**")],
            deny=[RequestFilter(path="/repos/*/*/actions/**")],
        ),
    }),
    env={"HOME": "/tmp", "PATH": "/usr/bin:/bin"},  # nothing is inherited from the host
)

async with Sandbox(policy, session_dir=Path("/tmp/my-session")) as sbx:
    result = await sbx.exec(["python3", "-c", "print('hi')"], cwd="/work/project")
    print(result.exit_code, result.stdout, result.violations)
```

`Sandbox(..., approve=callback)` takes an optional async approval callback that is asked
about hosts not covered by `NetworkPolicy.hosts` (default: deny). `check_host(policy)`
returns the reasons the sandbox cannot run on this host.

### Network policy

`NetworkPolicy.hosts` maps host patterns (`pypi.org`, `*.example.com` for strict subdomains,
`api.x.com:443`, `[::1]:8080`, `127.0.0.1:3000`, and `*` / `*:<port>` for `deny` only) to an
access:

| access    | connections | requests |
|-----------|-------------|----------|
| `tunnel`  | allowed, relayed untouched | not looked at (nothing is decrypted) |
| `deny`    | refused | - |
| `inspect` | allowed through the HTTP proxy only (SOCKS is refused) | TLS is intercepted; a request must match no `deny` filter and at least one `allow` filter |

Deny always matches first. When several entries cover a host the most restrictive wins
(`deny`, then `inspect`, then `tunnel`), so a `*.github.com` tunnel does not open an
inspected `api.github.com`. Within an inspected host the deny filters are checked before the
allow filters, and requests with dot segments, `%2e`/`%2f`/`%5c`/`%00` escapes or very long
targets are always refused.

A `RequestFilter` has optional `methods`, a `path` glob over the percent-decoded path (`*`
within a segment, `?` one character, a whole `**` segment any number of segments) and
`query` parameter value globs. An allow filter needs each named parameter present with every
occurrence matching. A deny filter matches more eagerly (one matching occurrence, `;` as a
query separator, the path with `;params` stripped), so a request dressed up to dodge it is
still caught.

To see the requests, the proxy intercepts TLS for `inspect` hosts with a CA generated per
`Sandbox.start()`. Clients inside the sandbox pick it up automatically via `SSL_CERT_FILE`,
`CURL_CA_BUNDLE`, `NODE_EXTRA_CA_CERTS` etc. (the system trust store stays active for other
hosts), and upstream connections are re-encrypted with normal certificate verification. A
client that refuses the session CA gets nothing.

### Network events

Every network decision is a structured `NetworkEvent`, so refused requests can be traced to
the rule that refused them. That covers each tunnel, each HTTP request on a connection
(requests are decided one at a time), and each piece of malformed input:

```json
{"time": "2026-11-11T11:09:27.077Z", "exec_id": "90387b19041cd5c9", "connection": 1,
 "request": 2, "protocol": "http", "decision": "deny", "reason": "request matches a deny filter",
 "rule": "api.github.com: deny GET /admin/**", "host": "api.github.com", "port": 443,
 "method": "GET", "target": "/admin/x", "status": 403}
```

- `decision`: `allow`; `deny` (policy or resolved-address guard); `malformed` (unparseable or
  unsupported input: bad request lines and headers, ambiguous framing, bad chunks, requests a
  proxy does not take, invalid URLs and host names, SOCKS4, a client rejecting the
  interception certificate, ...); `failed` (allowed, but DNS or the upstream failed, or an
  internal proxy error - a bug worth reporting).
- `rule`: the host entry or filter that decided (`api.github.com: allow GET /repos/**`,
  `exec: pypi.org`), `connection` / `request` correlate a tunnel with the requests inside it.
- `ExecResult.network_events` has an exec's events (the first 1000; the rest are counted in
  `network_events_dropped`). `deny` and `malformed` events also become `network` violations.
- `Sandbox(..., event_log=path)` appends every event of every exec to a JSON-lines audit log.
  The file is hidden from the sandbox (it records request targets, query strings included),
  and the CLI takes `--event-log PATH`, or `--event-log -` to print the events after the run.

## Manual testing

```sh
uv run sandbox -- sh -c 'cat ~/.ssh/id_rsa; curl -sI https://example.com'
uv run sandbox --allow-domain pypi.org --allow-request 'GET api.github.com/repos/**' \
    --deny-request 'GET api.github.com/repos/*/*/actions/**' -- curl -s https://api.github.com/repos/python/cpython
```

`--policy policy.json` takes a full `SandboxPolicy` as JSON, e.g.
`{"network": {"hosts": {"api.github.com": {"access": "inspect", "allow": [{"methods": ["GET"]}]}}}}`.

## Development

```sh
uv sync
uv run pytest          # tests/test_integration.py is skipped where bubblewrap is missing
uv run ruff check
uv run ruff format --check
uv run pyright
```
