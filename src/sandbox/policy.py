"""Sandbox policy models (see docs/design.md, "Policy model").

Read is allow-by-default with `deny_read` regions and `allow_read` re-openings; write is
deny-by-default with `allow_write` regions and `deny_write` carve-outs. The more specific
(deeper) rule wins between a read deny and a read allow; a write deny always wins over a
write allow at or below it. All paths are absolute and literal: globs are not supported,
because a deny glob that silently matches nothing is a hole.
"""

import ipaddress
import re
from pathlib import PurePosixPath
from typing import Any, LiteralString, Self, cast

from pydantic import (
    BaseModel,
    ConfigDict,
    Field,
    ModelWrapValidatorHandler,
    SecretStr,
    ValidationError,
    field_validator,
    model_validator,
)
from pydantic_core import InitErrorDetails, PydanticCustomError

from sandbox.net.credentials import SECRET_FIELD, Credentials, check_secret, secret_from_env
from sandbox.net.credentials import Credential as CompiledCredential
from sandbox.net.filter import Access, HostRule, parse_host_rule, parse_request_filter
from sandbox.net.filter import RequestFilter as CompiledFilter

HIDDEN_INPUT = "<hidden>"
"""Stands in for the input in policy validation errors."""


class _Strict(BaseModel):
    """Base of the policy models.

    A policy can hold secrets (`Credential.secret`, and often `SandboxPolicy.env`), and a
    pydantic error carries the input that failed - for a model-level check, the whole dict,
    secret included - in `str()`, `errors()` and `json()` alike. So the validation errors of
    these models never carry input: it is replaced by HIDDEN_INPUT, keeping each error's
    type, location and message, which must therefore not quote values that could be secret.
    Cross-field checks go in `_check`, not in `after` validators: pydantic runs those
    outside the wrap validator below, where their errors would escape the redaction."""

    model_config = ConfigDict(extra="forbid", frozen=True, hide_input_in_errors=True)

    def _check(self) -> None:
        """Cross-field validation of a model whose fields are valid; raise ValueError."""

    @model_validator(mode="wrap")
    @classmethod
    def _validate_without_input(cls, data: Any, handler: ModelWrapValidatorHandler[Self]) -> Self:
        try:
            model = handler(data)
            model._check()
            return model
        except ValidationError as e:  # a field's, or a nested model's (already redacted)
            errors = [
                (err["type"], err["msg"], err["loc"])
                for err in e.errors(include_url=False, include_context=False, include_input=False)
            ]
        except ValueError as e:  # raised here, pydantic would attach `data` as the input
            errors = [("value_error", f"Value error, {e}", ())]
        details: list[InitErrorDetails] = [
            # pydantic's own error type and final message: without a context nothing is
            # formatted into it, and braces in it (`{secret}`) stay as they are
            {
                "type": PydanticCustomError(cast(LiteralString, kind), cast(LiteralString, msg)),
                "loc": loc,
                "input": HIDDEN_INPUT,
            }
            for kind, msg, loc in errors
        ]
        raise ValidationError.from_exception_data(cls.__name__, details, hide_input=True)


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

    def _check(self) -> None:
        self.compile()

    def compile(self) -> CompiledFilter:
        return parse_request_filter(self.methods, self.path, self.query)


_HEADER = re.compile(r"^[!#$%&'*+\-.^_`|~0-9A-Za-z]+$")
_ENV_NAME = re.compile(r"^[A-Za-z_][A-Za-z0-9_]*$")
_PLACEHOLDER = re.compile(r"^[A-Za-z0-9_.\-]{8,256}$")
_RESERVED_HEADERS = {
    "host",
    "content-length",
    "transfer-encoding",
    "connection",
    "keep-alive",
    "proxy-authorization",
    "proxy-authenticate",
    "proxy-connection",
    "te",
    "trailer",
    "upgrade",
    "expect",
}


class Credential(_Strict):
    """A secret the proxy adds to requests to an `inspect` host, so that it never enters the
    sandbox (see `HostAccess.credentials`). Give exactly one of `secret` / `secret_env` and
    exactly one of `placeholder` / `inject`."""

    header: str = "Authorization"
    """The one header the secret goes into. Nothing else in a request is ever rewritten."""
    secret: SecretStr | None = None
    """The secret itself (masked in repr and JSON dumps)."""
    secret_env: str | None = None
    """Name of a variable in the *host* environment holding the secret, read by
    `Sandbox.start()`. (The sandbox inherits nothing from the host environment.)"""
    placeholder: str | None = None
    """Placeholder mode: the sandbox uses this stand-in (e.g. via `SandboxPolicy.env`), and
    the proxy replaces it by the secret in `header` - also inside `Basic` credentials, as
    git sends them. 8-256 characters of `A-Z a-z 0-9 _ . -`."""
    inject: str | None = None
    """Inject mode: `header` is set to this on every request, `{secret}` standing for the
    secret (e.g. `"Bearer {secret}"`); a value the client sent in it is dropped."""
    allow_placeholder_elsewhere: bool = False
    """Placeholder mode only. By default a request carrying the placeholder anywhere it is
    not replaced - sent to another host (or in a host name), in the URL, in another header,
    in the body, or in `header` of a request this credential is not used for - is refused
    (403), as a sign of a prompt injection or a misconfiguration. Set this to forward such
    requests with the placeholder as it is (e.g. to push files that mention it)."""

    def _check(self) -> None:
        # The messages quote no value: a secret pasted into the wrong field must not be
        # echoed by the error pointing it out.
        if not _HEADER.match(self.header):
            raise ValueError("header must be a header name, such as Authorization")
        if self.header.lower() in _RESERVED_HEADERS:
            raise ValueError("header is managed by the proxy and cannot carry a credential")
        if (self.secret is None) == (self.secret_env is None):
            raise ValueError("a credential needs exactly one of secret and secret_env")
        if self.secret is not None:
            check_secret(self.secret.get_secret_value(), "credential secret")
        if self.secret_env is not None and not _ENV_NAME.match(self.secret_env):
            raise ValueError("secret_env must be the name of an environment variable")
        if (self.placeholder is None) == (self.inject is None):
            raise ValueError("a credential needs exactly one of placeholder and inject")
        if self.placeholder is not None and not _PLACEHOLDER.match(self.placeholder):
            raise ValueError("placeholder must be 8-256 characters of A-Z a-z 0-9 _ . -")
        if self.allow_placeholder_elsewhere and self.placeholder is None:
            raise ValueError("allow_placeholder_elsewhere only applies to placeholder mode")
        if self.inject is not None:
            if self.inject.count(SECRET_FIELD) != 1:
                raise ValueError(
                    f"inject needs exactly one {SECRET_FIELD}, standing for the secret"
                    " (the secret itself goes in secret or secret_env)"
                )
            if not self.inject.isascii() or not self.inject.isprintable():
                raise ValueError("inject must be printable ASCII")

    def compile(self, host: str) -> CompiledCredential:
        """Resolve the secret (raises `CredentialError` when `secret_env` is unset)."""
        source = f"{host}: {self.header}"
        if self.placeholder is not None:  # not secret, and tells same-header ones apart
            source += f" ({self.placeholder})"
        if self.secret is not None:
            secret = self.secret.get_secret_value()
        else:
            assert self.secret_env is not None
            secret = secret_from_env(self.secret_env, f"credential {source}")
        return CompiledCredential(
            self.header,
            secret,
            self.placeholder,
            self.inject,
            source,
            allow_placeholder_elsewhere=self.allow_placeholder_elsewhere,
        )


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
    credentials: list[Credential] = []
    """`inspect` only: secrets the proxy adds to the requests that match one of *this
    entry's* allow filters, over the verified TLS connection to the host (a plain-http
    request that would carry one is refused). When several entries cover a host (e.g.
    `api.github.com` and `*.github.com`), a request another entry allows gets through
    without these credentials. Keep the allow filters tight: a credential works for every
    request they let through, and responses are relayed as they are."""

    def _check(self) -> None:
        if self.access != "inspect" and (self.allow or self.deny):
            raise ValueError("only `inspect` hosts take allow/deny request filters")
        if self.access != "inspect" and self.credentials:
            raise ValueError("only `inspect` hosts take credentials")
        if self.access == "inspect" and not self.allow:
            raise ValueError("an `inspect` host needs at least one allow filter")
        placeholders = [c.placeholder for c in self.credentials if c.placeholder is not None]
        if len(placeholders) != len(set(placeholders)):
            raise ValueError("a placeholder is used by two credentials")
        for c in self.credentials:
            claims = [o for o in self.credentials if o.header.lower() == c.header.lower()]
            if c.inject is not None and len(claims) > 1:
                raise ValueError(f"the {c.header} header is injected, so it takes one credential")


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

    def resolve_credentials(self) -> Credentials:
        """The credentials of the host entries with their secrets, keyed like the host
        rules' `domain.source`. Reads `secret_env` variables from the host environment
        (raises `CredentialError`); called by `Sandbox.start()`."""
        return Credentials(
            {
                pattern: [c.compile(pattern) for c in h.credentials]
                for pattern, h in self.hosts.items()
            }
        )


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
    variables and service URLs are added on top. A variable holding a credential's secret
    is refused (`CredentialError` from `Sandbox.start()`), as is one in an exec's `env`."""
    block_unix_sockets: bool = True
    """seccomp: refuse socket(AF_UNIX / AF_VSOCK) and io_uring."""
    allow_nested_userns: bool = False
    """Let the command create user/mount namespaces. Undoes every write deny; do not enable
    for untrusted code."""
    bwrap_path: str | None = None
