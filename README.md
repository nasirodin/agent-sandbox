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

### Credentials

An API key handed to the sandbox (a file, an env variable) is one prompt injection away from
being exfiltrated. Instead, give an `inspect` host `credentials`: the proxy adds the secret
to requests on their way upstream, and the real value never enters the sandbox.

```python
from pydantic import SecretStr
from sandbox import Credential

policy = SandboxPolicy(
    network=NetworkPolicy(hosts={
        "api.github.com": HostAccess(
            access="inspect",
            allow=[RequestFilter(methods=["GET"], path="/repos/**")],
            credentials=[
                # placeholder: the sandbox uses a stand-in, the proxy swaps in the secret
                Credential(secret_env="GITHUB_TOKEN", placeholder="SANDBOX_PLACEHOLDER_GITHUB"),
            ],
        ),
        "api.example.com": HostAccess(
            access="inspect",
            allow=[RequestFilter()],
            credentials=[
                # inject: the proxy sets the header on every request, nothing needed inside
                Credential(header="X-Api-Key", secret=SecretStr(api_key), inject="{secret}"),
            ],
        ),
    }),
    env={"HOME": "/tmp", "GITHUB_TOKEN": "SANDBOX_PLACEHOLDER_GITHUB"},  # what the sandbox sees
)
```

- The secret is `secret` (a `SecretStr`, masked in repr and JSON dumps) or `secret_env`, a
  variable of the *host* environment read by `Sandbox.start()` (which raises
  `CredentialError` if it is unset). The sandbox inherits nothing from the host environment.
- A credential's secret never enters the sandbox's environment either: if a variable of
  `SandboxPolicy.env` or of an exec's `env` holds it - under any name, or inside a longer
  value such as `Bearer <secret>` - `Sandbox.start()` / `exec()` raise `CredentialError`
  naming the variable (not the value) and run nothing. A variable named like the secret's
  `secret_env` but holding the placeholder is fine.
- **placeholder**: occurrences of the placeholder in `header` (default `Authorization`) are
  replaced by the secret, e.g. `Bearer <placeholder>`, and also inside `Basic` credentials,
  so `git clone https://x-access-token:$GITHUB_TOKEN@github.com/...` works. Requests without
  the placeholder pass unchanged.
- **inject**: `header` is set to `inject` (`"Bearer {secret}"`) on every request, replacing
  whatever the client sent in it.
- Only the credential's one header is rewritten, so the secret cannot be steered into a
  part of a request the API might store or echo back (an issue body, a query string).
- A placeholder anywhere it is not replaced gets the request refused (403, a `deny` event
  and a violation naming the credential), as a sign of a prompt injection or a
  misconfiguration: in a request to another host (also inside `Basic` credentials, as
  `git push https://x:$TOKEN@elsewhere` sends them) or in a host name, and in the URL
  (also percent-encoded), another header or the body of any request. For a body, found as
  it streams, the rest is not sent and the upstream connection is dropped, so the request
  is never completed there. Set `allow_placeholder_elsewhere=True` on a credential to
  forward such requests with the placeholder as it is instead (e.g. to push files that
  mention it). This is a tripwire, not the boundary: a transformed placeholder (lower case,
  another encoding, inside a `tunnel` host's encrypted traffic) is not recognised.
- Credentials are only added to requests that match an allow filter of *their own* host
  entry. With `api.github.com` allowing `GET /repos/**` with a token and `*.github.com`
  allowing everything without one, a `POST` to `api.github.com` is let through by the
  wildcard entry, but without the token.
- Credentials are only sent over the intercepted TLS connection, verified against the real
  host. A plain-http request that would carry one is refused (`credentials are only sent
  over https`). They never reach other hosts, including redirect targets: each request is
  judged on its own.
- Policy validation errors never carry the input that failed: pydantic would otherwise put
  the whole credential, secret included, into `str(error)`, `errors()` and `json()`. Each
  error keeps its location and message (`network.hosts.api.x.com.credentials.0: inject
  needs exactly one {secret}...`), with the input replaced by `"<hidden>"`.
- Events name the credentials a request used (`"credentials": ["api.github.com:
  Authorization (SANDBOX_PLACEHOLDER_GITHUB)"]`), never their values.

The command can still *use* the credential for anything the allow filters let through,
and responses are relayed unmodified: an endpoint that returns the token (or echoes request
headers) hands it to the sandbox. Keep allow filters as narrow as the task needs.

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

Credentials come from the host environment: `--placeholder-credential 'api.github.com
GITHUB_TOKEN'` sets `GITHUB_TOKEN` inside the sandbox to a placeholder that the proxy
replaces with the host's `$GITHUB_TOKEN` (in `Authorization`, or a header given as a third
word), and `--inject-credential 'api.github.com Authorization: Bearer {GITHUB_TOKEN}'` sets
the header on every request. Both need the host to be inspected (`--allow-request`);
`--allow-placeholder-elsewhere` stops placeholders found elsewhere from being refused.

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
