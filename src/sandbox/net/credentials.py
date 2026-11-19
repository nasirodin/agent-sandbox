"""Credential injection: secrets the proxy adds to requests the sandbox makes.

A credential belongs to an `inspect` host entry (see `HostAccess.credentials`). The secret
stays in the host process, in a `Credentials` object: the sandbox sees at most a
placeholder, and the proxy puts the secret into the vetted request on its way upstream. Two
modes:

- placeholder: occurrences of the placeholder in the credential's header are replaced by the
  secret (also inside `Basic` credentials, base64-decoded, as git and other HTTP clients
  send a token password). Requests without the placeholder pass unchanged.
- inject: the header is set on every request (`inject` with `{secret}` filled in), replacing
  whatever the client sent in it.

Only the credential's header is ever rewritten - never the URL, the body or other headers -
so the secret cannot be steered into a part of a request the API might echo back. It is
only sent over the verified TLS connection of an intercepted tunnel: a plain-http request
that would carry it is refused instead.

A placeholder anywhere else - in a request to another host, in the URL, another header or
the body - hints at a prompt injection trying to exfiltrate the credential, or at a
misconfiguration. Such requests are refused (`PlaceholderScan`) unless the credential sets
`allow_placeholder_elsewhere`. This is a tripwire, not the boundary: the secret itself only
ever goes into its header, and a placeholder that was transformed (re-encoded, encrypted in
a `tunnel`) is not recognised.
"""

import base64
import os
from collections.abc import Iterable, Mapping, Sequence
from dataclasses import dataclass, field
from urllib.parse import unquote

SECRET_FIELD = "{secret}"


class CredentialError(ValueError):
    """A credential's secret cannot be resolved (e.g. its environment variable is unset)."""


class CredentialRefused(Exception):
    """A request cannot carry its credentials (plain http, or conflicting credentials)."""

    def __init__(self, reason: str, rule: str) -> None:
        super().__init__(reason)
        self.reason = reason
        self.rule = rule


def check_secret(secret: str, what: str) -> str:
    """A secret must fit in an HTTP header value: non-empty printable ASCII."""
    if not secret or not secret.isascii() or not secret.isprintable():
        raise CredentialError(f"{what} must be non-empty printable ASCII")
    return secret


def secret_from_env(name: str, what: str) -> str:
    value = os.environ.get(name)
    if value is None:
        raise CredentialError(f"{what}: environment variable {name} is not set")
    return check_secret(value, f"{what}: environment variable {name}")


@dataclass(frozen=True)
class Credential:
    """One compiled credential of an inspected host."""

    header: str
    """Header name as configured (matched case-insensitively)."""
    secret: str = field(repr=False)
    placeholder: str | None = None
    """Placeholder mode: replaced by the secret within `header`."""
    inject: str | None = None
    """Inject mode: the full header value, `{secret}` standing for the secret."""
    source: str = ""
    """`<host entry>: <header>`, plus ` (<placeholder>)` in placeholder mode: how network
    events name the credential."""
    allow_placeholder_elsewhere: bool = False
    """Forward requests carrying the placeholder where it is not replaced as they are,
    instead of refusing them (see `PlaceholderScan`)."""

    def __post_init__(self) -> None:
        if (self.placeholder is None) == (self.inject is None):
            raise ValueError("a credential needs exactly one of placeholder and inject")

    @property
    def key(self) -> str:
        return self.header.lower()

    def injected_value(self) -> str:
        assert self.inject is not None
        return self.inject.replace(SECRET_FIELD, self.secret)

    def substitute(self, value: str) -> str:
        """`value` with the placeholder replaced, directly or inside a Basic credential."""
        assert self.placeholder is not None
        if self.placeholder in value:
            return value.replace(self.placeholder, self.secret)
        scheme, decoded = _basic(value)
        placeholder = self.placeholder.encode()
        if decoded is None or placeholder not in decoded:
            return value
        replaced = decoded.replace(placeholder, self.secret.encode())
        return f"{scheme} {base64.b64encode(replaced).decode('ascii')}"


def _basic(value: str) -> tuple[str, bytes | None]:
    """The scheme and decoded credentials of a `Basic` header value (None otherwise)."""
    scheme, _, param = value.partition(" ")
    if scheme.lower() != "basic":
        return scheme, None
    try:
        return scheme, base64.b64decode(param.strip(), validate=True)
    except ValueError:  # binascii.Error included
        return scheme, None


def apply_credentials(
    credentials: Sequence[Credential], headers: list[tuple[str, str]], *, secure: bool
) -> tuple[list[tuple[str, str]], list[str]]:
    """The request headers with `credentials` applied, and the sources of those used.

    Raises CredentialRefused when a credential would be used on an insecure (plain http)
    request, or when an injected header is claimed by more than one credential (possible
    when several host entries cover the host)."""
    if not credentials:
        return headers, []
    injects: dict[str, Credential] = {}
    for c in credentials:
        if c.inject is None:
            continue
        # an injected header is the credential's alone: nothing else may claim it
        claims = [o for o in credentials if o.key == c.key]
        if len(claims) > 1:
            raise CredentialRefused(
                f"conflicting credentials for the {c.header} header",
                ", ".join(o.source for o in claims),
            )
        injects[c.key] = c
    substitutions = [c for c in credentials if c.placeholder is not None]
    used: list[Credential] = []
    out: list[tuple[str, str]] = []
    for name, value in headers:
        key = name.lower()
        if key in injects:
            continue  # the client's value is replaced
        for c in substitutions:
            if c.key == key and (new := c.substitute(value)) != value:
                value = new
                if c not in used:
                    used.append(c)
        out.append((name, value))
    for c in injects.values():
        out.append((c.header, c.injected_value()))
        used.append(c)
    if used and not secure:
        raise CredentialRefused("credentials are only sent over https", used[0].source)
    return out, [c.source for c in used]


def check_env(credentials: Iterable[Credential], env: dict[str, str]) -> None:
    """Refuse an environment for the sandbox in which a variable holds a credential's
    secret, e.g. `{"GH_TOKEN": os.environ["GITHUB_TOKEN"]}` passed by accident.

    Judged by value, not by name: a variable named like a credential's `secret_env` but
    holding its placeholder is the intended setup, and a secret under any other name is
    still the secret. A variable whose name or value contains a secret (`Bearer <secret>`,
    a URL with it) is refused; the error names the variables and credentials, never the
    values."""
    leaks: dict[str, str] = {}
    for c in credentials:
        for name, value in env.items():
            if c.secret in name:  # the name itself cannot be quoted
                leaks.setdefault("a variable whose name holds it", c.source)
            elif c.secret in value:
                leaks.setdefault(name, c.source)
    if leaks:
        found = "; ".join(f"{name} (credential {source})" for name, source in leaks.items())
        raise CredentialError(
            f"environment variables for the sandbox hold a credential's secret: {found}. "
            "The sandbox must not see it: give it the placeholder, or nothing (inject mode)"
        )


class PlaceholderScan:
    """Finds placeholders where they are not replaced by their secret.

    Run over what the proxy is about to forward *after* `apply_credentials`: by then every
    placeholder that was due to be replaced is the secret, so any placeholder left is out of
    place - in a request to a host its credential is not for, in the request target, in
    another header, in the body. The methods raise CredentialRefused naming where it was
    found, the rule being the credential's source. Credentials with
    `allow_placeholder_elsewhere` are not looked for; a placeholder several credentials share
    is looked for unless all of them allow it elsewhere."""

    def __init__(self, credentials: Iterable[Credential]) -> None:
        watched: dict[str, Credential] = {}
        for c in credentials:
            if c.placeholder is not None and not c.allow_placeholder_elsewhere:
                watched.setdefault(c.placeholder, c)  # shared: any one that does not allow it
        self._watched = [(p, p.encode(), c) for p, c in watched.items()]
        self.longest = max((len(p) for p, _, _ in self._watched), default=0)

    def __bool__(self) -> bool:
        return bool(self._watched)

    def _find(self, text: str) -> Credential | None:
        return next((c for p, _, c in self._watched if p in text), None)

    def _find_bytes(self, data: bytes) -> Credential | None:
        return next((c for _, p, c in self._watched if p in data), None)

    @staticmethod
    def _refuse(where: str, c: Credential) -> CredentialRefused:
        return CredentialRefused(f"credential placeholder in the {where}", c.source)

    def check_host(self, host: str) -> None:
        """A placeholder as (part of) a host name: DNS is case-insensitive, so is this."""
        low = host.lower()
        if c := next((c for p, _, c in self._watched if p.lower() in low), None):
            raise self._refuse("host name", c)

    def check_request(self, target: str, headers: list[tuple[str, str]]) -> None:
        """The origin-form target (raw and percent-decoded) and the headers to forward
        (values, and the credentials inside `Basic` values)."""
        if c := self._find(target) or self._find(unquote(target, errors="replace")):
            raise self._refuse("request target", c)
        for name, value in headers:
            c = self._find(name) or self._find(value)
            if c is None and (decoded := _basic(value)[1]) is not None:
                c = self._find_bytes(decoded)
            if c is not None:
                raise self._refuse(f"{name[:64]} header", c)

    def body(self) -> BodyScan:
        return BodyScan(self)


class BodyScan:
    """Scans one request body as it streams by, before each piece is forwarded. The
    payload is scanned as one stream - a placeholder split across reads or chunks is found
    when its end arrives (its start may have been forwarded by then) - and framing lines
    (chunk sizes and extensions, trailers) each on their own."""

    def __init__(self, scan: PlaceholderScan) -> None:
        self._scan = scan
        self._carry = b""

    def payload(self, data: bytes) -> None:
        window = self._carry + data
        if c := self._scan._find_bytes(window):
            raise PlaceholderScan._refuse("request body", c)
        keep = self._scan.longest - 1
        self._carry = window[-keep:] if keep > 0 else b""

    def line(self, data: bytes) -> None:
        if c := self._scan._find_bytes(data):
            raise PlaceholderScan._refuse("request body", c)


class Credentials:
    """The resolved credentials of a session, by host entry (the pattern as written in
    `NetworkPolicy.hosts`). Built by `NetworkPolicy.resolve_credentials()`, held by the
    runtime and its proxies: the secrets live here and nowhere else.

    The host rules (`filter.HostRule`) know nothing of credentials: `judge_request` reports
    which entries allowed a request (`RequestVerdict.allowed_by`), and `apply` adds those
    entries' credentials only."""

    def __init__(self, by_entry: Mapping[str, Iterable[Credential]] | None = None) -> None:
        entries = {e: tuple(cs) for e, cs in (by_entry or {}).items()}
        self._by_entry = {e: cs for e, cs in entries.items() if cs}
        self.all = tuple(c for cs in self._by_entry.values() for c in cs)
        self.scan = PlaceholderScan(self.all)
        """Placeholders where they are not replaced (see `PlaceholderScan`)."""

    def __bool__(self) -> bool:
        return bool(self.all)

    def of(self, entries: Iterable[str]) -> tuple[Credential, ...]:
        """The credentials of the given host entries, in order."""
        return tuple(c for e in entries for c in self._by_entry.get(e, ()))

    def apply(
        self, entries: Iterable[str], headers: list[tuple[str, str]], *, secure: bool
    ) -> tuple[list[tuple[str, str]], list[str]]:
        """`apply_credentials` with the credentials of the entries that allowed a request."""
        return apply_credentials(self.of(entries), headers, secure=secure)

    def check_env(self, env: dict[str, str]) -> None:
        """`check_env` against every credential of the session."""
        check_env(self.all, env)


__all__ = [
    "SECRET_FIELD",
    "BodyScan",
    "Credential",
    "CredentialError",
    "CredentialRefused",
    "Credentials",
    "PlaceholderScan",
    "apply_credentials",
    "check_env",
    "check_secret",
    "secret_from_env",
]
