"""Sandbox policy models (see docs/design.md, "Policy model").

Read is allow-by-default with `deny_read` regions and `allow_read` re-openings; write is
deny-by-default with `allow_write` regions and `deny_write` carve-outs. The more specific
(deeper) rule wins between a read deny and a read allow; a write deny always wins over a
write allow at or below it. All paths are absolute and literal: globs are not supported,
because a deny glob that silently matches nothing is a hole.
"""

import ipaddress
from pathlib import PurePosixPath

from pydantic import BaseModel, ConfigDict, Field, field_validator, model_validator

from sandbox.net.filter import Access, HostRule, parse_host_rule, parse_request_filter
from sandbox.net.filter import RequestFilter as CompiledFilter


class _Strict(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True)


def _absolute(paths: list[str]) -> list[str]:
    for p in paths:
        if not p.startswith("/") or "\0" in p:
            raise ValueError(f"path must be absolute: {p!r}")
        if any(c in p for c in "*?["):
            raise ValueError(f"globs are not supported, list literal paths: {p!r}")
    return [str(PurePosixPath(p)) for p in paths]


class FilesystemPolicy(_Strict):
    deny_read: list[str] = []
    """Regions hidden from the sandbox (an empty tmpfs over directories, /dev/null over files)."""
    allow_read: list[str] = []
    """Re-opened read-only inside `deny_read` regions."""
    allow_write: list[str] = []
    """Writable; everything else is read-only."""
    deny_write: list[str] = []
    """Read-only even inside `allow_write` (deny wins)."""
    scratch_write: list[str] = []
    """Writable like `allow_write` but without dangerous-file protection: scratch areas no
    host tool acts on (the sandbox's own HOME/TMPDIR)."""
    protect_dangerous: bool = True
    """Also deny-write the dangerous files in every write root (see `dangerous.py`)."""

    @field_validator("deny_read", "allow_read", "allow_write", "deny_write", "scratch_write")
    @classmethod
    def _paths(cls, v: list[str]) -> list[str]:
        return _absolute(v)


class RequestFilter(_Strict):
    """Matches requests to an `inspect` host (see `HostAccess.allow` / `HostAccess.deny`)."""

    methods: list[str] = []
    """HTTP methods, e.g. `["GET", "HEAD"]` (case-insensitive); empty matches every method."""
    path: str = "/**"
    """Glob over the percent-decoded request path: `*` within one segment, `?` one character,
    a whole `**` segment zero or more segments (`/repos/**` also matches `/repos`; `**` is
    only valid as a whole segment)."""
    query: dict[str, str] = {}
    """Query parameter -> value glob (`*`/`?`); parameters not named are unconstrained. In an
    allow filter each parameter must be present and every occurrence must match; in a deny
    filter one matching occurrence is enough."""

    @model_validator(mode="after")
    def _compiles(self) -> RequestFilter:
        self.compile()
        return self

    def compile(self) -> CompiledFilter:
        return parse_request_filter(self.methods, self.path, self.query)


class HostAccess(_Strict):
    """How the sandbox may reach one host (see `NetworkPolicy.hosts`)."""

    access: Access
    """`tunnel`: connections are relayed untouched (nothing is decrypted). `deny`: connections
    are refused. `inspect`: TLS is intercepted with a per-session CA the sandbox trusts via
    SSL_CERT_FILE and friends, and every request must match no `deny` filter and at least
    one `allow` filter; reachable through the HTTP proxy only (not SOCKS)."""
    allow: list[RequestFilter] = []
    """`inspect` only, and required: the requests that may pass."""
    deny: list[RequestFilter] = []
    """`inspect` only: requests refused even when an allow filter matches (checked first).
    Requests with dot segments, `%2e`/`%2f`/`%5c`/`%00` escapes or very long targets are
    always refused."""

    @model_validator(mode="after")
    def _filters_fit_access(self) -> HostAccess:
        if self.access != "inspect" and (self.allow or self.deny):
            raise ValueError("only `inspect` hosts take allow/deny request filters")
        if self.access == "inspect" and not self.allow:
            raise ValueError("an `inspect` host needs at least one allow filter")
        return self


class NetworkPolicy(_Strict):
    hosts: dict[str, HostAccess] = {}
    """Host pattern -> access. Patterns: `pypi.org`, `*.pythonhosted.org` (strict
    subdomains), `api.x.com:443`, `[::1]:8080`, `127.0.0.1:3000`, and - for `deny` only -
    `*` and `*:<port>`. When several entries cover a host the most restrictive wins: `deny`,
    then `inspect`, then `tunnel`. Hosts not covered are denied (unless the approval callback
    or an exec's `extra_allowed_domains` allows them as tunnels)."""
    denied_resolved_addresses: list[str] = []
    """Extra CIDRs allowed hostnames must not resolve to (on top of the built-in set)."""
    deny_private_addresses: bool = True
    """Also refuse hostnames resolving to RFC 1918, CGNAT and ULA space."""
    services: dict[str, str] = {}
    """Name -> host Unix socket, bridged to a loopback port inside and exposed as
    `SANDBOX_SVC_<NAME>_URL`."""

    @field_validator("hosts")
    @classmethod
    def _hosts(cls, v: dict[str, HostAccess]) -> dict[str, HostAccess]:
        seen: dict[tuple[str, int | None], str] = {}
        for rule, pattern in zip(_compile_hosts(v), v, strict=True):
            key = (rule.domain.pattern, rule.domain.port)
            if key in seen:
                raise ValueError(f"host listed twice: {seen[key]!r} and {pattern!r}")
            seen[key] = pattern
        return v

    @field_validator("denied_resolved_addresses")
    @classmethod
    def _cidrs(cls, v: list[str]) -> list[str]:
        for c in v:
            ipaddress.ip_network(c, strict=False)
        return v

    @field_validator("services")
    @classmethod
    def _services(cls, v: dict[str, str]) -> dict[str, str]:
        for name, path in v.items():
            if not name.isidentifier() or not name.isascii():
                raise ValueError(f"service name must be an identifier: {name!r}")
            _absolute([path])
        return v

    def host_rules(self) -> list[HostRule]:
        return _compile_hosts(self.hosts)


def _compile_hosts(hosts: dict[str, HostAccess]) -> list[HostRule]:
    return [
        parse_host_rule(
            pattern,
            h.access,
            allow=[f.compile() for f in h.allow],
            deny=[f.compile() for f in h.deny],
        )
        for pattern, h in hosts.items()
    ]


class ResourceLimits(_Strict):
    memory_bytes: int | None = None
    """RLIMIT_AS. Off by default: runtimes that reserve address space (Go, JVM) break under it."""
    cpu_seconds: int | None = None
    file_size_bytes: int | None = 1 << 30
    open_files: int | None = 1024
    max_output_bytes: int = Field(default=256 * 1024, ge=1024)
    """Per stream; the middle of longer output is dropped."""
    max_concurrent: int = Field(default=4, ge=1)


class SandboxPolicy(_Strict):
    filesystem: FilesystemPolicy = FilesystemPolicy()
    network: NetworkPolicy = NetworkPolicy()
    limits: ResourceLimits = ResourceLimits()
    env: dict[str, str] = {}
    """The complete environment of the command; nothing is inherited from the host. Proxy
    variables and service URLs are added on top."""
    block_unix_sockets: bool = True
    """seccomp: refuse socket(AF_UNIX / AF_VSOCK) and io_uring."""
    allow_nested_userns: bool = False
    """Let the command create user/mount namespaces. Undoes every write deny; do not enable
    for untrusted code."""
    bwrap_path: str | None = None
