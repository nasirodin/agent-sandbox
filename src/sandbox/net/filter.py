"""Network decisions: host canonicalisation, domain rules and resolved-address vetting.

Mirrors srt's `domain-pattern.ts`, `filterNetworkRequest` and `resolved-address-guard.ts`:

- Hosts are validated and canonicalised before any rule sees them (lower case, no trailing
  dot, IPv6 compressed, IPv4-mapped IPv6 and inet_aton shorthand such as `127.1` or
  `2130706433` turned into dotted quads), and the canonical form is what gets dialed.
- Hosts (`HostRule`, from `NetworkPolicy.hosts`): among the entries covering a host the most
  restrictive access wins - `deny`, then `inspect` (allowed, but the proxy vets every
  request), then `tunnel`; then per-exec extra allows, then the approval callback; anything
  else is denied. Only a literal `True` from the callback allows.
- An allowed *hostname* is resolved once; addresses in the denied set are dropped and a
  surviving address is dialed directly (no second lookup, so DNS rebinding gains nothing).
  IP literals are judged by the rules alone.
"""

import asyncio
import ipaddress
import itertools
import re
import socket
from collections.abc import Awaitable, Callable, Iterable, Sequence
from dataclasses import dataclass
from typing import Literal
from urllib.parse import parse_qsl, unquote

type IPAddress = ipaddress.IPv4Address | ipaddress.IPv6Address
type IPNetwork = ipaddress.IPv4Network | ipaddress.IPv6Network

_LABEL = re.compile(r"^[a-z0-9_]([a-z0-9_-]{0,61}[a-z0-9_])?$")
_NUMERIC_LABEL = re.compile(r"^(0x[0-9a-f]*|[0-9]+)$")
_PORT = re.compile(r"^[1-9][0-9]{0,4}$")


def canonicalize_host(host: str) -> str | None:
    """Return the canonical form of `host`, or None if it is not a valid host name or IP."""
    if not host or len(host) > 255 or not host.isascii():
        return None
    h = host.lower()
    if h.startswith("[") and h.endswith("]"):
        h = h[1:-1]
    if ":" in h:  # IPv6 literal; zone ids (`%eth0`) are refused
        if "%" in h:
            return None
        try:
            addr = ipaddress.IPv6Address(h)
        except ValueError:
            return None
        return str(addr.ipv4_mapped) if addr.ipv4_mapped else str(addr)
    if h.endswith("."):
        h = h[:-1]
    labels = h.split(".")
    if _NUMERIC_LABEL.match(labels[-1]):
        # WHATWG/inet_aton rule: a numeric last label makes the whole host an IPv4 address
        # (`127.1`, `0x7f.1`, `2130706433`); getaddrinfo would accept these forms too.
        try:
            return socket.inet_ntoa(socket.inet_aton(h))
        except OSError:
            return None
    if len(h) > 253 or not all(_LABEL.match(label) for label in labels):
        return None
    return h


def ip_literal(host: str) -> IPAddress | None:
    try:
        return ipaddress.ip_address(host)
    except ValueError:
        return None


@dataclass(frozen=True)
class DomainRule:
    """One allow/deny entry: `example.com`, `*.example.com`, `*`, each with an optional port."""

    pattern: str
    port: int | None
    source: str

    def matches(self, host: str, port: int) -> bool:
        if self.port is not None and self.port != port:
            return False
        if self.pattern == "*":
            return True
        if self.pattern.startswith("*."):
            # strict subdomains only, and never an IP literal
            return ip_literal(host) is None and host.endswith(self.pattern[1:])
        return host == self.pattern


def parse_rule(entry: str, *, allow_star: bool) -> DomainRule:
    raw = entry.strip()
    host, port = raw, None
    if raw.startswith("["):
        m = re.match(r"^\[([^\]]+)\](?::(\d+))?$", raw)
        if not m:
            raise ValueError(f"bad bracketed IPv6 entry: {entry!r}")
        host, port_s = m.group(1), m.group(2)
        if port_s is not None:
            port = _parse_port(port_s, entry)
        if ip_literal(host) is None or ":" not in host:
            raise ValueError(f"not an IPv6 address: {entry!r}")
    elif raw.count(":") > 1:
        raise ValueError(f"IPv6 entries must be bracketed, e.g. [::1]:443: {entry!r}")
    elif ":" in raw:
        host, port_s = raw.rsplit(":", 1)
        port = _parse_port(port_s, entry)

    if host == "*":
        if not allow_star:
            raise ValueError("`*` is only allowed in deny entries")
        return DomainRule("*", port, entry)
    if host.startswith("*."):
        base = canonicalize_host(host[2:])
        if base is None or ip_literal(base) is not None or base.count(".") < 1:
            raise ValueError(f"wildcard needs at least two labels after `*.`: {entry!r}")
        return DomainRule("*." + base, port, entry)
    if "*" in host:
        raise ValueError(f"only a leading `*.` wildcard is supported: {entry!r}")
    canon = canonicalize_host(host)
    if canon is None:
        raise ValueError(f"invalid host: {entry!r}")
    if ip_literal(canon) is None and "." not in canon and canon != "localhost":
        raise ValueError(f"host needs a dot (or be `localhost`): {entry!r}")
    if ip_literal(canon) is not None and ip_literal(host.strip("[]")) is None:
        raise ValueError(f"write IPv4 addresses as dotted quads: {entry!r}")
    return DomainRule(canon, port, entry)


def _parse_port(s: str, entry: str) -> int:
    if not _PORT.match(s) or int(s) > 65535:
        raise ValueError(f"bad port in {entry!r}")
    return int(s)


def parse_network(entries: Iterable[str], *, allow_star: bool) -> list[DomainRule]:
    return [parse_rule(e, allow_star=allow_star) for e in entries]


# --- inspected hosts ---------------------------------------------------------------------

_METHOD = re.compile(r"^[A-Za-z]+$")
_PATH_GLOB = re.compile(r"^/[\x21-\x7e]*$")  # absolute, printable ASCII, no spaces
MAX_TARGET = 4096
"""Longest request target the rules will consider (longer is refused outright)."""


def glob_match(pattern: str, text: str) -> bool:
    """Wildcard match: `*` any run of characters, `?` exactly one. Greedy two-pointer scan,
    so untrusted text cannot trigger the catastrophic backtracking a regex translation of
    the same glob could."""
    pi = ti = 0
    star = star_ti = -1
    while ti < len(text):
        if pi < len(pattern) and (pattern[pi] == text[ti] or pattern[pi] == "?"):
            pi += 1
            ti += 1
        elif pi < len(pattern) and pattern[pi] == "*":
            star, star_ti = pi, ti
            pi += 1
        elif star != -1:  # rewind: let the last `*` swallow one more character
            pi = star + 1
            star_ti += 1
            ti = star_ti
        else:
            return False
    return all(c == "*" for c in pattern[pi:])


@dataclass(frozen=True)
class PathGlob:
    """Compiled path glob: `*` and `?` match within one segment, and a whole `**` segment
    (None below) matches zero or more segments, so `/repos/**` also matches `/repos`."""

    segments: tuple[str | None, ...]
    source: str

    @classmethod
    def parse(cls, pattern: str) -> PathGlob:
        if not _PATH_GLOB.match(pattern) or "#" in pattern:
            raise ValueError(f"path glob must be an absolute, printable path: {pattern!r}")
        segments: list[str | None] = []
        for segment in pattern.split("/")[1:]:
            if "**" in segment and segment != "**":
                raise ValueError(f"`**` must be a whole path segment: {pattern!r}")
            segments.append(None if segment == "**" else segment)
        return cls(tuple(segments), pattern)

    def matches(self, path: str) -> bool:
        if not path.startswith("/"):
            return False
        pats, segs = self.segments, path.split("/")[1:]
        pi = si = 0
        star = star_si = -1
        while si < len(segs):
            if pi < len(pats) and (pat := pats[pi]) is not None and glob_match(pat, segs[si]):
                pi += 1
                si += 1
            elif pi < len(pats) and pats[pi] is None:
                star, star_si = pi, si
                pi += 1
            elif star != -1:  # rewind: let the last `**` swallow one more segment
                pi = star + 1
                star_si += 1
                si = star_si
            else:
                return False
        return all(p is None for p in pats[pi:])


@dataclass(frozen=True)
class _Request:
    """The parts of a request the filters look at, normalised once."""

    method: str
    """Upper case."""
    path: str
    """Percent-decoded (the escapes that could change its structure are refused earlier)."""
    bare_path: str
    """`path` with `;params` cut from every segment, as some servers do before routing."""
    params: list[tuple[str, str]]
    """Decoded query pairs, split on `&` and, as a superset, also on `;`."""


@dataclass(frozen=True)
class RequestFilter:
    """One compiled request filter of an inspected host.

    In an allow list a filter matches when the method is listed, the path matches, and each
    named query parameter is present with every occurrence matching its glob. In a deny list
    it matches more eagerly - the path with or without `;params`, and a parameter when any
    occurrence matches - so a request dressed up to dodge a deny filter is still caught.
    """

    methods: frozenset[str]
    """Upper case; empty matches every method."""
    path_glob: PathGlob
    query: tuple[tuple[str, str], ...]
    source: str

    def matches(self, req: _Request, *, deny: bool) -> bool:
        if self.methods and req.method not in self.methods:
            return False
        paths = (req.path, req.bare_path) if deny else (req.path,)
        if not any(self.path_glob.matches(p) for p in paths):
            return False
        for name, pattern in self.query:
            values = [v for k, v in req.params if k == name]
            hits = [glob_match(pattern, v) for v in values]
            if not (any(hits) if deny else hits and all(hits)):
                return False
        return True


def parse_request_filter(
    methods: Iterable[str] = (), path: str = "/**", query: dict[str, str] | None = None
) -> RequestFilter:
    upper: list[str] = []
    for m in methods:
        if not _METHOD.match(m):
            raise ValueError(f"bad HTTP method: {m!r}")
        upper.append(m.upper())
    for name in query or {}:
        if not name or not name.isascii() or not name.isprintable():
            raise ValueError(f"bad query parameter name: {name!r}")
    q = "&".join(f"{k}={v}" for k, v in (query or {}).items())
    source = f"{','.join(sorted(upper)) or '*'} {path}{'?' + q if q else ''}"
    pairs = tuple((query or {}).items())
    return RequestFilter(frozenset(upper), PathGlob.parse(path), pairs, source)


type Access = Literal["tunnel", "deny", "inspect"]
ACCESS: tuple[Access, ...] = ("tunnel", "deny", "inspect")


@dataclass(frozen=True)
class HostRule:
    """One compiled `NetworkPolicy.hosts` entry.

    - `deny`: connections are refused.
    - `tunnel`: connections are allowed and relayed untouched (nothing is decrypted).
    - `inspect`: reachable through the HTTP proxy only; TLS is intercepted and every request
      must match no `deny` filter and at least one `allow` filter. The entry's
      credentials are not part of the rule: they are kept apart, with their secrets, in
      `credentials.Credentials`, and added to the requests the entry itself allows
      (`RequestVerdict.allowed_by`).
    """

    domain: DomainRule
    access: Access
    allow: tuple[RequestFilter, ...] = ()
    deny: tuple[RequestFilter, ...] = ()

    def covers(self, host: str, port: int) -> bool:
        return self.domain.matches(host, port)


def parse_host_rule(
    host: str,
    access: Access,
    allow: Iterable[RequestFilter] = (),
    deny: Iterable[RequestFilter] = (),
) -> HostRule:
    if access not in ACCESS:
        raise ValueError(f"access must be one of {', '.join(ACCESS)}: {access!r}")
    allow, deny = tuple(allow), tuple(deny)
    if access != "inspect" and (allow or deny):
        raise ValueError(f"only `inspect` hosts take allow/deny request filters: {host!r}")
    if access == "inspect" and not allow:
        raise ValueError(f"an `inspect` host needs at least one allow filter: {host!r}")
    domain = parse_rule(host, allow_star=access == "deny")
    return HostRule(domain, access, allow, deny)


def _request_view(method: str, path: str, query: str) -> _Request:
    decoded = unquote(path, errors="replace")
    bare = "/".join(segment.partition(";")[0] for segment in decoded.split("/"))
    params = parse_qsl(query, keep_blank_values=True)
    if ";" in query:
        params += parse_qsl(query.replace(";", "&"), keep_blank_values=True)
    return _Request(method.upper(), decoded, bare, params)


@dataclass(frozen=True)
class RequestVerdict:
    allowed: bool
    reason: str
    rule: str | None = None
    """The filter that decided, as `<host entry>: <allow|deny> <filter>`; None for the
    built-in refusals and when no allow filter matches."""
    allowed_by: tuple[str, ...] = ()
    """For an allowed request: the host entries (as written) whose *own* allow filters
    match it - the entries whose credentials it gets (`Credentials.apply`). An entry that
    covers the host but does not allow the request lends it none of its credentials."""


def request_denial(rules: Sequence[HostRule], method: str, target: str) -> str | None:
    """Why `method` on the origin-form `target` is refused by `rules`, or None."""
    verdict = judge_request(rules, method, target)
    return None if verdict.allowed else verdict.reason


def judge_request(rules: Sequence[HostRule], method: str, target: str) -> RequestVerdict:
    """Judge `method` on the origin-form `target` against the inspected hosts `rules`. Deny
    comes first: the built-in checks below, then every deny filter, and only then the
    allow filters.

    Filters see the percent-decoded path. Escapes that would change its structure (`%2e`,
    `%2f`, `%5c`, `%00`) and dot segments are refused outright, so decoding cannot turn a
    request into one that reaches a different resource than the filters saw.

    One entry's allow filter is enough to let the request through, but only the entries
    that allow it themselves are listed in `RequestVerdict.allowed_by`.
    """
    refused = _refusal_before_filters(target)
    if refused is not None:
        return RequestVerdict(False, refused)
    path, _, query = target.partition("?")
    req = _request_view(method, path, query)
    for r in rules:
        for f in r.deny:
            if f.matches(req, deny=True):
                rule = f"{r.domain.source}: deny {f.source}"
                return RequestVerdict(False, "request matches a deny filter", rule)
    decided: str | None = None
    allowed_by: list[str] = []
    for r in rules:
        f = next((f for f in r.allow if f.matches(req, deny=False)), None)
        if f is None:
            continue  # this entry does not allow the request: its credentials stay out
        if decided is None:
            decided = f"{r.domain.source}: allow {f.source}"
        allowed_by.append(r.domain.source)
    if decided is None:
        return RequestVerdict(False, "no allow filter matches")
    return RequestVerdict(True, "allow filter matches", decided, tuple(allowed_by))


def _refusal_before_filters(target: str) -> str | None:
    if len(target) > MAX_TARGET:
        return "request target too long"
    path = target.partition("?")[0]
    low = path.lower()
    if not path.startswith("/"):
        return "request target is not an absolute path"
    if any(segment in (".", "..") for segment in path.split("/")):
        return "dot segment in request path"
    if "\\" in path or any(e in low for e in ("%2e", "%2f", "%5c", "%00")):
        return "escaped dot or slash in request path"
    return None


# --- decisions ---------------------------------------------------------------------------


@dataclass(frozen=True)
class NetworkRequest:
    host: str
    """Canonical host."""
    port: int
    exec_id: str


type ApprovalCallback = Callable[[NetworkRequest], Awaitable[bool]]


@dataclass(frozen=True)
class Decision:
    allowed: bool
    reason: str
    host: str
    """Canonical host when valid, else the host as requested."""
    inspect: bool = False
    """Allowed for inspection only: the proxy must vet every request (see `HostRule`)."""
    rule: str | None = None
    """The entry that decided: a `NetworkPolicy.hosts` pattern or `exec: <entry>`."""
    malformed: bool = False
    """Refused because the host or port is not valid at all, before any rule was asked."""


async def decide(
    host: str,
    port: int,
    *,
    exec_id: str,
    hosts: Sequence[HostRule],
    extra_allowed: Sequence[DomainRule] = (),
    approve: ApprovalCallback | None = None,
) -> Decision:
    canon = canonicalize_host(host)
    if canon is None or not 0 < port < 65536:
        return Decision(False, "malformed host", host, malformed=True)
    covering = [r for r in hosts if r.covers(canon, port)]

    def entry(access: Access) -> str | None:
        return next((r.domain.source for r in covering if r.access == access), None)

    # the most restrictive access wins: an inspected host is never also tunnelled
    if rule := entry("deny"):
        return Decision(False, "host is denied", canon, rule=rule)
    if rule := entry("inspect"):
        return Decision(True, "inspect", canon, inspect=True, rule=rule)
    if rule := entry("tunnel"):
        return Decision(True, "tunnel", canon, rule=rule)
    if extra := next((r for r in extra_allowed if r.matches(canon, port)), None):
        return Decision(True, "exec allow list", canon, rule=f"exec: {extra.source}")
    if approve is not None:
        try:
            answer = await approve(NetworkRequest(canon, port, exec_id))
        except Exception:  # noqa: BLE001 - a failing prompt denies
            return Decision(False, "approval failed", canon)
        if answer is True:
            return Decision(True, "approved", canon)
        return Decision(False, "not approved", canon)
    return Decision(False, "host is not allowed", canon)


# --- resolved-address guard ------------------------------------------------------------

_BUILTIN: list[tuple[str, list[str]]] = [
    ("loopback", ["127.0.0.0/8", "::1/128"]),
    ("unspecified", ["0.0.0.0/8", "::/128"]),
    ("link-local", ["169.254.0.0/16", "fe80::/10"]),
    ("multicast", ["224.0.0.0/4", "ff00::/8"]),
    ("reserved", ["240.0.0.0/4"]),  # includes 255.255.255.255
    (
        "cloud metadata",
        [
            "100.100.100.200/32",
            "168.63.129.16/32",
            "192.0.0.192/32",
            "fd00:ec2::/32",
            "fd20:ce::254/128",
            "fd00:c1::a9fe:a9fe/128",
            "fd00:42::42/128",
            "fd00:a9fe:a9fe::1/128",
            "fd00:100::100:200/128",
        ],
    ),
]
_PRIVATE = ["10.0.0.0/8", "172.16.0.0/12", "192.168.0.0/16", "100.64.0.0/10", "fc00::/7"]


def embedded_ipv4(addr: IPAddress) -> ipaddress.IPv4Address | None:
    """The IPv4 address carried by an IPv6 address (mapped, compatible, translated, NAT64
    well-known prefix, 6to4), judged like the IPv4 address itself."""
    if isinstance(addr, ipaddress.IPv4Address):
        return None
    n = int(addr)
    if addr.ipv4_mapped:
        return addr.ipv4_mapped
    if addr.sixtofour:
        return addr.sixtofour
    if n >> 32 == 0 and n > 1:  # ::a.b.c.d (compatible); `::` and `::1` are themselves
        return ipaddress.IPv4Address(n & 0xFFFFFFFF)
    if n >> 32 == 0xFFFF0000:  # ::ffff:0:a.b.c.d (translated)
        return ipaddress.IPv4Address(n & 0xFFFFFFFF)
    if n >> 32 == 0x0064FF9B << 64:  # 64:ff9b::/96
        return ipaddress.IPv4Address(n & 0xFFFFFFFF)
    return None


def local_addresses() -> set[IPAddress]:
    """Addresses assigned to this host's interfaces (Linux /proc; best effort elsewhere)."""
    found: set[IPAddress] = set()
    try:
        with open("/proc/net/fib_trie", encoding="ascii") as f:
            lines = f.read().splitlines()
        for prev, line in itertools.pairwise(lines):
            if "/32 host LOCAL" in line and "|--" in prev:
                found.add(ipaddress.ip_address(prev.split("|--")[1].strip()))
    except OSError:
        pass
    try:
        with open("/proc/net/if_inet6", encoding="ascii") as f:
            for line in f:
                h = line.split()[0]
                found.add(ipaddress.IPv6Address(":".join(h[i : i + 4] for i in range(0, 32, 4))))
    except OSError:
        pass
    try:
        for info in socket.getaddrinfo(socket.gethostname(), None):
            found.add(ipaddress.ip_address(str(info[4][0]).split("%")[0]))
    except OSError:
        pass
    return found


class AddressDenied(Exception):
    def __init__(self, host: str, reason: str) -> None:
        super().__init__(f"{host} {reason}")
        self.reason = reason


class AddressGuard:
    def __init__(
        self,
        *,
        extra: Iterable[str] = (),
        deny_private: bool = True,
        allowed_literals: Iterable[DomainRule] = (),
        local: Callable[[], set[IPAddress]] = local_addresses,
    ) -> None:
        self._classes: list[tuple[str, list[IPNetwork]]] = [
            (name, [ipaddress.ip_network(c) for c in cidrs]) for name, cidrs in _BUILTIN
        ]
        if deny_private:
            self._classes.append(("private", [ipaddress.ip_network(c) for c in _PRIVATE]))
        listed = [ipaddress.ip_network(c, strict=False) for c in extra]
        if listed:
            self._classes.append(("listed", listed))
        self._allowed = [r for r in allowed_literals if ip_literal(r.pattern) is not None]
        self._local = local

    def denial(self, host: str, port: int, addr: IPAddress) -> str | None:
        """Why `host` may not be dialed at `addr`, or None if it may."""
        if any(r.matches(str(addr), port) for r in self._allowed):
            return None  # reaching an explicitly allowed literal by name grants nothing new
        candidates = [a for a in (addr, embedded_ipv4(addr)) if a is not None]
        if host == "localhost" or host.endswith(".localhost"):
            return None if all(a.is_loopback for a in candidates) else "a non-loopback address"
        for name, nets in self._classes:
            if any(a in n for a in candidates for n in nets if a.version == n.version):
                return f"{'an' if name[0] in 'aeiou' else 'a'} {name} address"
        local = self._local()
        if any(a in local for a in candidates):
            return "one of this host's addresses"
        return None

    async def resolve(self, host: str, port: int) -> str:
        """Resolve `host` once and return an address it may be dialed at."""
        if ip_literal(host) is not None:
            return host
        infos = await asyncio.get_running_loop().getaddrinfo(host, port, type=socket.SOCK_STREAM)
        reasons: list[str] = []
        for *_, sockaddr in infos:
            addr = ipaddress.ip_address(str(sockaddr[0]).split("%")[0])
            reason = self.denial(host, port, addr)
            if reason is None:
                return str(addr)
            reasons.append(reason)
        if not reasons:
            raise OSError(f"{host} did not resolve")
        raise AddressDenied(host, "resolved to " + " / ".join(dict.fromkeys(reasons)))


def sanitize(text: str, limit: int = 500) -> str:
    """One line of printable text, safe for an HTTP status phrase and violation logs."""
    out = "".join(c if c.isprintable() and c not in "<>" else " " for c in text)
    out = " ".join(out.split())[:limit]
    return out.encode("ascii", "replace").decode("ascii")


__all__ = [
    "ACCESS",
    "Access",
    "AddressDenied",
    "AddressGuard",
    "ApprovalCallback",
    "Decision",
    "DomainRule",
    "HostRule",
    "NetworkRequest",
    "PathGlob",
    "RequestFilter",
    "RequestVerdict",
    "canonicalize_host",
    "decide",
    "embedded_ipv4",
    "glob_match",
    "judge_request",
    "local_addresses",
    "parse_host_rule",
    "parse_network",
    "parse_request_filter",
    "parse_rule",
    "request_denial",
    "sanitize",
]
