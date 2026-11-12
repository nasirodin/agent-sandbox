import ipaddress

import pytest

from sandbox.net.filter import (
    ACCESS,
    AddressGuard,
    HostRule,
    NetworkRequest,
    PathGlob,
    canonicalize_host,
    decide,
    glob_match,
    parse_host_rule,
    parse_network,
    parse_request_filter,
    parse_rule,
    request_denial,
)
from sandbox.policy import HostAccess, NetworkPolicy, RequestFilter


@pytest.mark.parametrize(
    ("host", "canon"),
    [
        ("Example.COM.", "example.com"),
        ("127.1", "127.0.0.1"),
        ("2130706433", "127.0.0.1"),
        ("0x7f.0.0.1", "127.0.0.1"),
        ("0177.0.0.1", "127.0.0.1"),
        ("[::FFFF:127.0.0.1]", "127.0.0.1"),
        ("[2001:DB8:0:0::1]", "2001:db8::1"),
        ("under_score.example.com", "under_score.example.com"),
    ],
)
def test_canonicalize(host: str, canon: str) -> None:
    assert canonicalize_host(host) == canon


@pytest.mark.parametrize(
    "host",
    [
        "",
        "evil.com\x00.ok.com",
        "a b.com",
        "evil.com\r\nX: y",
        "fe80::1%eth0",
        "bücher.de",
        "1.2.3.999",
        "a..b.com",
        "-a.com",
        "x" * 300,
    ],
)
def test_canonicalize_rejects(host: str) -> None:
    assert canonicalize_host(host) is None


@pytest.mark.parametrize(
    "entry",
    [
        "*.com",
        "evil.com/path",
        "http://x.com",
        "2001:db8::1:443",
        "*",
        "a*.com",
        "127.1",
        "x.com:0",
        "x.com:70000",
        "nodot",
    ],
)
def test_bad_allow_entries(entry: str) -> None:
    with pytest.raises(ValueError):
        parse_rule(entry, allow_star=False)


def test_policy_validates_hosts() -> None:
    def net(**hosts: str) -> NetworkPolicy:
        return NetworkPolicy.model_validate({"hosts": {h: {"access": a} for h, a in hosts.items()}})

    with pytest.raises(ValueError, match="at least two labels"):
        net(**{"*.com": "tunnel"})
    with pytest.raises(ValueError, match="only allowed in"):
        net(**{"*": "tunnel"})  # `*` is for deny only
    with pytest.raises(ValueError, match="listed twice"):
        net(**{"X.com": "tunnel", "x.com.": "deny"})  # same host once canonicalised
    with pytest.raises(ValueError):
        net(**{"x.com": "open"})
    rules = net(**{"*": "deny", "*:22": "deny"}).host_rules()
    assert [(r.domain.pattern, r.domain.port, r.access) for r in rules] == [
        ("*", None, "deny"),
        ("*", 22, "deny"),
    ]
    assert len(net(**{"x.com": "deny", "x.com:443": "tunnel"}).host_rules()) == 2  # distinct


def test_rule_matching() -> None:
    wild, exact, port, v6 = parse_network(
        ["*.example.com", "pypi.org", "api.x.com:443", "[::1]:8080"], allow_star=False
    )
    assert wild.matches("a.example.com", 80) and wild.matches("a.b.example.com", 1)
    assert not wild.matches("example.com", 80)  # strict subdomains only
    assert not wild.matches("evilexample.com", 80)
    assert exact.matches("pypi.org", 443) and not exact.matches("x.pypi.org", 443)
    assert port.matches("api.x.com", 443) and not port.matches("api.x.com", 80)
    assert v6.matches("::1", 8080)


def hosts(**by_access: list[str]) -> list[HostRule]:
    return [
        parse_host_rule(h, a, allow=[parse_request_filter()] if a == "inspect" else [])
        for a in ACCESS
        for h in by_access.get(a, [])
    ]


async def test_decision_order() -> None:
    rules = hosts(tunnel=["*.example.com"], deny=["bad.example.com", "*:22"])
    extra = parse_network(["pypi.org"], allow_star=False)

    async def d(host: str, port: int = 443, **kw):
        return await decide(host, port, exec_id="e", hosts=rules, **kw)

    assert (await d("ok.example.com")).allowed
    assert not (await d("bad.example.com")).allowed
    assert not (await d("ok.example.com", 22)).allowed
    assert not (await d("pypi.org")).allowed
    assert (await d("pypi.org", extra_allowed=extra)).allowed
    assert not (
        await d(
            "bad.example.com", extra_allowed=parse_network(["bad.example.com"], allow_star=False)
        )
    ).allowed
    assert (await d("OK.Example.Com.")).host == "ok.example.com"
    assert (await d("evil\x00.example.com")).reason == "malformed host"
    assert (await d("other.org")).reason == "host is not allowed"


async def test_most_restrictive_access_wins() -> None:
    rules = hosts(
        tunnel=["*.github.com", "open.example.com"],
        inspect=["api.github.com", "*.example.com"],
        deny=["secret.example.com"],
    )

    async def d(host: str):
        return await decide(host, 443, exec_id="e", hosts=rules)

    api = await d("api.github.com")
    assert api.allowed and api.inspect and api.reason == "inspect"  # not also tunnelled
    raw = await d("raw.github.com")
    assert raw.allowed and not raw.inspect and raw.reason == "tunnel"
    assert (await d("open.example.com")).inspect  # the wildcard inspect still applies
    assert (await d("secret.example.com")).reason == "host is denied"


async def test_approval_needs_literal_true() -> None:
    asked: list[NetworkRequest] = []

    async def truthy(req: NetworkRequest) -> bool:
        asked.append(req)
        return "yes"  # type: ignore[return-value]

    async def yes(req: NetworkRequest) -> bool:
        return True

    async def boom(req: NetworkRequest) -> bool:
        raise RuntimeError

    kw = {"exec_id": "e1", "hosts": hosts(deny=["no.com"])}
    assert not (await decide("x.com", 443, approve=truthy, **kw)).allowed
    assert asked == [NetworkRequest("x.com", 443, "e1")]
    assert (await decide("x.com", 443, approve=yes, **kw)).allowed
    assert not (await decide("no.com", 443, approve=yes, **kw)).allowed  # deny first
    assert (await decide("x.com", 443, approve=boom, **kw)).reason == "approval failed"


@pytest.mark.parametrize(
    ("addr", "reason"),
    [
        ("127.0.0.1", "a loopback address"),
        ("::1", "a loopback address"),
        ("::ffff:127.0.0.1", "a loopback address"),
        ("64:ff9b::7f00:1", "a loopback address"),
        ("2002:7f00:1::", "a loopback address"),
        ("169.254.169.254", "a link-local address"),
        ("fd00:ec2::254", "a cloud metadata address"),
        ("100.100.100.200", "a cloud metadata address"),
        ("10.1.2.3", "a private address"),
        ("::ffff:192.168.1.1", "a private address"),
        ("0.0.0.0", "an unspecified address"),
        ("203.0.113.9", "one of this host's addresses"),
        ("93.184.215.14", None),
        ("2606:4700::1", None),
    ],
)
def test_address_guard(addr: str, reason: str | None) -> None:
    guard = AddressGuard(local=lambda: {ipaddress.ip_address("203.0.113.9")})
    assert guard.denial("example.com", 443, ipaddress.ip_address(addr)) == reason


def test_address_guard_options() -> None:
    ip = ipaddress.ip_address
    lenient = AddressGuard(deny_private=False, extra=["198.51.100.0/24"], local=set)
    assert lenient.denial("intranet.corp", 80, ip("10.0.0.5")) is None
    assert lenient.denial("x.com", 80, ip("198.51.100.7")) == "a listed address"
    literal = AddressGuard(allowed_literals=parse_network(["127.0.0.1:3000"], allow_star=False))
    assert literal.denial("myapp.test", 3000, ip("127.0.0.1")) is None
    assert literal.denial("myapp.test", 3001, ip("127.0.0.1")) == "a loopback address"
    assert literal.denial("localhost", 80, ip("127.0.0.1")) is None
    assert literal.denial("localhost", 80, ip("93.184.215.14")) == "a non-loopback address"


async def test_resolve_literal_and_localhost() -> None:
    guard = AddressGuard(local=set)
    assert await guard.resolve("93.184.215.14", 80) == "93.184.215.14"
    assert ipaddress.ip_address(await guard.resolve("localhost", 80)).is_loopback


# --- inspected hosts ---------------------------------------------------------------------


@pytest.mark.parametrize(
    ("pattern", "path", "matches"),
    [
        ("/**", "/", True),
        ("/**", "/a/b/c", True),
        ("/repos/**", "/repos", True),  # `**` matches zero segments
        ("/repos/**", "/repos/a/b", True),
        ("/repos/**", "/repository", False),
        ("/a/*/c", "/a/b/c", True),
        ("/a/*/c", "/a/b/d/c", False),  # `*` stays within one segment
        ("/a/*/c", "/a//c", True),
        ("/v?/users", "/v1/users", True),
        ("/v?/users", "/v12/users", False),
        ("/**/end", "/end", True),
        ("/**/end", "/x/y/end", True),
        ("/file-*.tar.gz", "/file-1.tar.gz", True),
        ("/file-*.tar.gz", "/file-1.tarxgz", False),  # `.` is literal
        ("/trailing/", "/trailing", False),
        ("/trailing/", "/trailing/", True),
    ],
)
def test_path_globs(pattern: str, path: str, matches: bool) -> None:
    assert PathGlob.parse(pattern).matches(path) is matches


@pytest.mark.parametrize(
    "kwargs",
    [
        {"methods": ["GE T"]},
        {"methods": [""]},
        {"path": "relative/path"},
        {"path": "/with space"},
        {"path": "/frag#ment"},
        {"path": "/a**b"},  # `**` only as a whole segment
        {"query": {"": "x"}},
    ],
)
def test_bad_request_filters(kwargs: dict) -> None:
    with pytest.raises(ValueError):
        parse_request_filter(**kwargs)


@pytest.mark.parametrize(
    ("host", "access", "allow", "deny", "error"),
    [
        ("x.com", "tunnel", 1, 0, "only `inspect` hosts"),
        ("x.com", "deny", 0, 1, "only `inspect` hosts"),
        ("x.com", "inspect", 0, 1, "at least one allow filter"),
        ("*", "inspect", 1, 0, "only allowed in"),
        ("x.com", "open", 0, 0, "access must be one of"),
    ],
)
def test_bad_host_rules(host: str, access, allow: int, deny: int, error: str) -> None:
    f = parse_request_filter()
    with pytest.raises(ValueError, match=error):
        parse_host_rule(host, access, allow=[f] * allow, deny=[f] * deny)


def inspect(allow: list[dict], deny: list[dict] = []) -> list:  # noqa: B006
    return [
        parse_host_rule(
            "api.github.com",
            "inspect",
            allow=[parse_request_filter(**f) for f in allow],
            deny=[parse_request_filter(**f) for f in deny],
        )
    ]


@pytest.mark.parametrize(
    ("method", "target", "denial"),
    [
        ("GET", "/repos/octo/cat", None),
        ("get", "/repos/x", None),  # methods are case-insensitive
        ("HEAD", "/repos/x", None),
        ("GET", "/rep%6Fs/x", None),  # filters see the decoded path
        ("POST", "/repos/x", "no allow filter matches"),
        ("GET", "/admin", "no allow filter matches"),
        ("GET", "/repos/../admin", "dot segment in request path"),
        ("GET", "/repos/.", "dot segment in request path"),
        ("GET", "/repos/%2E%2e/admin", "escaped dot or slash in request path"),
        ("GET", "/repos/a%2Fb", "escaped dot or slash in request path"),
        ("GET", "/repos/a%5cb", "escaped dot or slash in request path"),
        ("GET", "/repos/a%00b", "escaped dot or slash in request path"),
        ("GET", "repos/x", "request target is not an absolute path"),
    ],
)
def test_allow_filters(method: str, target: str, denial: str | None) -> None:
    rules = inspect([{"methods": ["GET", "head"], "path": "/repos/**"}])
    assert request_denial(rules, method, target) == denial


def test_allow_query_needs_every_occurrence() -> None:
    rules = inspect([{"path": "/**", "query": {"token": "tk-*"}}])
    assert request_denial(rules, "GET", "/a?token=tk-1") is None
    assert request_denial(rules, "GET", "/a?token=tk-1&other=2") is None  # unlisted: free
    assert request_denial(rules, "GET", "/a?token=tk%2D1") is None  # values compare decoded
    for target in ("/a", "/a?token=nope", "/a?token=tk-1&token=x", "/a?token=tk-1;token=x"):
        assert request_denial(rules, "GET", target) == "no allow filter matches", target


@pytest.mark.parametrize(
    ("method", "target", "denied"),
    [
        ("GET", "/repos/octo/cat", False),
        ("DELETE", "/repos/octo/cat", True),
        ("delete", "/repos/octo/cat", True),
        ("GET", "/repos/octo/secrets/key", True),
        ("GET", "/repos/octo/%73ecrets/key", True),  # escaped letters are decoded
        ("GET", "/repos/octo/secrets;x=1/key", True),  # `;params` some servers strip
        ("GET", "/repos/octo/cat?force=true", True),
        ("GET", "/repos/octo/cat?force=false", False),
        ("GET", "/repos/octo/cat?force=false&force=true", True),  # any occurrence
        ("GET", "/repos/octo/cat?x=1;force=true", True),  # `;` separated too
        ("GET", "/repos/octo/cat?%66orce=true", True),  # decoded names
    ],
)
def test_deny_filters_match_first(method: str, target: str, denied: bool) -> None:
    rules = inspect(
        allow=[{"path": "/**"}],  # everything else is allowed...
        deny=[  # ...so only the deny filters decide
            {"methods": ["DELETE"]},
            {"path": "/repos/*/secrets/**"},
            {"query": {"force": "true"}},
        ],
    )
    expected = "request matches a deny filter" if denied else None
    assert request_denial(rules, method, target) == expected


def test_filters_of_every_covering_inspect_entry_apply() -> None:
    f = parse_request_filter
    rules = [
        parse_host_rule("*.github.com", "inspect", allow=[f(["GET"])], deny=[f(path="/admin/**")]),
        parse_host_rule("api.github.com", "inspect", allow=[f(["POST"], "/admin/x")]),
    ]
    assert request_denial(rules, "POST", "/issues") == "no allow filter matches"
    assert request_denial(rules, "POST", "/admin/x") == "request matches a deny filter"
    assert request_denial(rules, "GET", "/issues") is None


def test_policy_hosts() -> None:
    net = NetworkPolicy(
        hosts={
            "pypi.org": HostAccess(access="tunnel"),
            "*:22": HostAccess(access="deny"),
            "api.github.com": HostAccess(
                access="inspect",
                allow=[RequestFilter(methods=["GET"], path="/repos/**")],
                deny=[RequestFilter(query={"v": "*"})],
            ),
        }
    )
    tunnel, deny, api = net.host_rules()
    assert (tunnel.access, deny.access, deny.domain.port) == ("tunnel", "deny", 22)
    assert api.access == "inspect" and api.covers("api.github.com", 443)
    assert api.allow[0].methods == {"GET"} and api.deny[0].query == (("v", "*"),)
    assert NetworkPolicy.model_validate_json(net.model_dump_json()) == net  # JSON round trip
    with pytest.raises(ValueError, match="at least one allow filter"):
        HostAccess(access="inspect")
    with pytest.raises(ValueError, match="only `inspect` hosts"):
        HostAccess(access="tunnel", allow=[RequestFilter()])
    with pytest.raises(ValueError, match="only `inspect` hosts"):
        NetworkPolicy.model_validate({"hosts": {"x.com": {"access": "deny", "deny": [{}]}}})
    with pytest.raises(ValueError):
        RequestFilter(path="no-slash")


def test_glob_match_is_not_a_regex() -> None:
    import time

    assert glob_match("tk-*", "tk-abc") and not glob_match("tk-*", "kt-abc")
    assert glob_match("a*b*c", "aXbYc") and not glob_match("a*b*c", "aXcYb")
    assert glob_match("??", "ab") and not glob_match("??", "a")
    assert glob_match("*", "") and not glob_match("?", "")
    # a crafted value against a wildcard-heavy glob must not blow up (ReDoS)
    start = time.perf_counter()
    assert not glob_match("a*a*a*a*a*b", "a" * 3000)
    assert not PathGlob.parse("/**/x*x*x*x/**/end").matches("/" + "/".join(["x" * 30] * 80))
    assert time.perf_counter() - start < 1.0


def test_overlong_targets_are_refused() -> None:
    rules = hosts(inspect=["x.com"])
    assert request_denial(rules, "GET", "/" + "a" * 5000) == "request target too long"
