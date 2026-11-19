import asyncio
import base64
import re
import ssl
import sys
from collections.abc import AsyncIterator, Sequence
from pathlib import Path

import pytest

from sandbox.net.credentials import Credential, Credentials
from sandbox.net.events import NetworkEvent
from sandbox.net.filter import (
    AddressGuard,
    HostRule,
    NetworkRequest,
    parse_host_rule,
    parse_request_filter,
)
from sandbox.net.mitm import CertificateAuthority
from sandbox.net.proxy import FilteringProxy

pytestmark = pytest.mark.skipif(not sys.platform.startswith("linux"), reason="Unix sockets")


class Upstream:
    """Loopback server: answers HTTP requests with what it received; echoes anything else."""

    def __init__(self) -> None:
        self.requests: list[bytes] = []

    async def handle(self, r: asyncio.StreamReader, w: asyncio.StreamWriter) -> None:
        first = await r.read(4096)
        if first.startswith(b"GET") or first.startswith(b"POST"):
            self.requests.append(first)
            body = b"hello"
            w.write(b"HTTP/1.1 200 OK\r\nContent-Length: 5\r\nConnection: close\r\n\r\n" + body)
        else:
            w.write(b"echo:" + first)
        await w.drain()
        w.close()


@pytest.fixture
async def upstream() -> AsyncIterator[tuple[Upstream, int]]:
    up = Upstream()
    server = await asyncio.start_server(up.handle, "127.0.0.1", 0)
    port = server.sockets[0].getsockname()[1]
    yield up, port
    server.close()


async def make_proxy(
    tmp_path: Path, allowed: list[str], approve=None
) -> tuple[FilteringProxy, list[NetworkEvent]]:
    records: list[NetworkEvent] = []
    proxy = FilteringProxy(
        str(tmp_path / "p.sock"),
        exec_id="e1",
        hosts=[
            *(parse_host_rule(h, "tunnel") for h in allowed),
            parse_host_rule("blocked.example.com", "deny"),
        ],
        extra_allowed=[],
        guard=AddressGuard(
            local=set, allowed_literals=[parse_host_rule(h, "tunnel").domain for h in allowed]
        ),
        approve=approve,
        on_event=records.append,
    )
    await proxy.start()
    return proxy, records


async def talk(tmp_path: Path, data: bytes, then: bytes = b"") -> bytes:
    r, w = await asyncio.open_unix_connection(str(tmp_path / "p.sock"))
    w.write(data)
    await w.drain()
    if then:
        await asyncio.sleep(0.05)
        w.write(then)
        await w.drain()
    w.write_eof()  # done sending: a kept-alive proxy connection ends here
    out = await asyncio.wait_for(r.read(65536 * 4), 5)
    while chunk := await asyncio.wait_for(r.read(65536), 5):
        out += chunk
    w.close()
    return out


async def test_absolute_http_request(tmp_path: Path, upstream: tuple[Upstream, int]) -> None:
    up, port = upstream
    proxy, records = await make_proxy(tmp_path, [f"127.0.0.1:{port}"])
    resp = await talk(
        tmp_path,
        f"GET http://127.0.0.1:{port}/a?b=1#frag HTTP/1.1\r\nHost: evil.com\r\n"
        "Proxy-Authorization: Basic x\r\nConnection: keep-alive, X-Secret\r\nX-Secret: s\r\n"
        "Accept: */*\r\n\r\n".encode(),
    )
    await proxy.close()
    assert resp.startswith(b"HTTP/1.1 200 OK") and resp.endswith(b"hello")
    sent = up.requests[0].decode()
    assert sent.startswith("GET /a?b=1 HTTP/1.1\r\n")
    assert f"Host: 127.0.0.1:{port}" in sent and "evil.com" not in sent
    assert "Proxy-Authorization" not in sent and "X-Secret" not in sent
    assert "Accept: */*" in sent and "Connection: close" in sent
    assert records[-1].decision == "allow" and records[-1].protocol == "http"
    assert (records[-1].method, records[-1].target) == ("GET", "/a?b=1")


async def test_connect_tunnel(tmp_path: Path, upstream: tuple[Upstream, int]) -> None:
    _, port = upstream
    proxy, _ = await make_proxy(tmp_path, [f"127.0.0.1:{port}"])
    resp = await talk(tmp_path, f"CONNECT 127.0.0.1:{port} HTTP/1.1\r\n\r\n".encode(), b"ping")
    await proxy.close()
    assert resp == b"HTTP/1.1 200 Connection Established\r\n\r\necho:ping"


@pytest.mark.parametrize(
    ("request_bytes", "status"),
    [
        (b"CONNECT blocked.example.com:443 HTTP/1.1\r\n\r\n", b"403 host is denied"),
        (b"CONNECT other.example.org:443 HTTP/1.1\r\n\r\n", b"403 host is not allowed"),
        (b"CONNECT 127.0.0.1:1 HTTP/1.1\r\n\r\n", b"403"),
        (b"CONNECT nonsense HTTP/1.1\r\n\r\n", b"400"),
        (b"GET /origin-form HTTP/1.1\r\nHost: x\r\n\r\n", b"400"),
        (b"GET https://x.com/ HTTP/1.1\r\n\r\n", b"400"),
        (b"GET ftp://x.com/ HTTP/1.1\r\n\r\n", b"400"),
        (
            b"POST http://127.0.0.1:9/ HTTP/1.1\r\nContent-Length: 4\r\n"
            b"Transfer-Encoding: chunked\r\n\r\n",
            b"400 ambiguous message framing",
        ),
        (b"GET http://x.com/ HTTP/1.1\r\nX: a\r\n folded\r\n\r\n", b"400"),
    ],
)
async def test_refusals(tmp_path: Path, request_bytes: bytes, status: bytes) -> None:
    proxy, _ = await make_proxy(tmp_path, ["127.0.0.1:9"])
    resp = await talk(tmp_path, request_bytes)
    await proxy.close()
    assert resp.startswith(b"HTTP/1.1 " + status), resp


async def test_hostname_resolving_to_loopback_is_refused(tmp_path: Path) -> None:
    proxy, records = await make_proxy(tmp_path, ["localhost.example.com"])

    async def fake(host: str, port: int) -> str:
        from sandbox.net.filter import AddressDenied

        raise AddressDenied(host, "resolved to a loopback address")

    proxy._guard.resolve = fake  # type: ignore[method-assign]
    resp = await talk(tmp_path, b"CONNECT localhost.example.com:443 HTTP/1.1\r\n\r\n")
    await proxy.close()
    assert resp.startswith(b"HTTP/1.1 403 resolved to a loopback address")
    assert records[-1].decision == "deny" and records[-1].reason == "resolved to a loopback address"


async def test_socks5(tmp_path: Path, upstream: tuple[Upstream, int]) -> None:
    _, port = upstream
    proxy, records = await make_proxy(tmp_path, [f"127.0.0.1:{port}"])
    ok = await talk(
        tmp_path, b"\x05\x01\x00", b"\x05\x01\x00\x01\x7f\x00\x00\x01" + port.to_bytes(2) + b"hi"
    )
    name = b"blocked.example.com"
    denied = await talk(
        tmp_path, b"\x05\x01\x00", b"\x05\x01\x00\x03" + bytes([len(name)]) + name + b"\x01\xbb"
    )
    bind = await talk(tmp_path, b"\x05\x01\x00", b"\x05\x02\x00\x01\x7f\x00\x00\x01\x00\x50")
    await proxy.close()
    assert ok == b"\x05\x00" + b"\x05\x00\x00\x01" + bytes(6) + b"echo:hi"
    assert denied == b"\x05\x00" + b"\x05\x02\x00\x01" + bytes(6)
    assert bind[2:4] == b"\x05\x07"
    assert [(r.decision, r.reason) for r in records] == [
        ("allow", "tunnel"),
        ("deny", "host is denied"),
        ("malformed", "unsupported SOCKS command"),  # the BIND
    ]
    assert records[1].rule == "blocked.example.com" and records[1].status is None


async def test_approval_is_asked_for_unknown_hosts(tmp_path: Path) -> None:
    asked: list[NetworkRequest] = []

    async def approve(req: NetworkRequest) -> bool:
        asked.append(req)
        return False

    proxy, records = await make_proxy(tmp_path, [], approve=approve)
    resp = await talk(tmp_path, b"CONNECT Unknown.Example.org.:443 HTTP/1.1\r\n\r\n")
    await proxy.close()
    assert resp.startswith(b"HTTP/1.1 403 not approved")
    assert asked == [NetworkRequest("unknown.example.org", 443, "e1")]
    assert records[0].host == "unknown.example.org"


# --- inspected hosts ---------------------------------------------------------------------


def inspect(
    host: str,
    allow: list[dict] | None = None,
    deny: list[dict] = [],  # noqa: B006
) -> HostRule:
    return parse_host_rule(
        host,
        "inspect",
        allow=[parse_request_filter(**f) for f in (allow if allow is not None else [{}])],
        deny=[parse_request_filter(**f) for f in deny],
    )


type Entry = HostRule | tuple[HostRule, Sequence[Credential]]
"""A host rule, or one with its credentials (`with_credentials`)."""


async def make_rules_proxy(
    tmp_path: Path, entries: Sequence[Entry], upstream_tls: ssl.SSLContext | None = None
) -> tuple[FilteringProxy, list[NetworkEvent], CertificateAuthority]:
    pairs = [e if isinstance(e, tuple) else (e, ()) for e in entries]
    rules = [r for r, _ in pairs]
    records: list[NetworkEvent] = []
    ca = CertificateAuthority(tmp_path / "ca")
    proxy = FilteringProxy(
        str(tmp_path / "p.sock"),
        exec_id="e1",
        hosts=rules,
        credentials=Credentials({r.domain.source: cs for r, cs in pairs}),
        extra_allowed=[],
        guard=AddressGuard(local=set, allowed_literals=[r.domain for r in rules]),
        ca=ca,
        upstream_tls=upstream_tls,
        on_event=records.append,
    )
    await proxy.start()
    return proxy, records, ca


async def test_inspect_needs_a_ca(tmp_path: Path) -> None:
    with pytest.raises(ValueError, match="CertificateAuthority"):
        FilteringProxy(
            str(tmp_path / "p.sock"),
            exec_id="e1",
            hosts=[inspect("api.github.com")],
            extra_allowed=[],
            guard=AddressGuard(local=set),
        )


async def test_inspect_plain_http(tmp_path: Path, upstream: tuple[Upstream, int]) -> None:
    up, port = upstream
    rules = [inspect(f"127.0.0.1:{port}", [{"methods": ["GET"], "path": "/ok/**"}])]
    proxy, records, _ = await make_rules_proxy(tmp_path, rules)
    base = f"http://127.0.0.1:{port}"
    ok = await talk(tmp_path, f"GET {base}/ok/sub?x=1 HTTP/1.1\r\nHost: h\r\n\r\n".encode())
    bad_method = await talk(tmp_path, f"POST {base}/ok/a HTTP/1.1\r\nHost: h\r\n\r\n".encode())
    bad_path = await talk(tmp_path, f"GET {base}/other HTTP/1.1\r\nHost: h\r\n\r\n".encode())
    dotted = await talk(tmp_path, f"GET {base}/ok/../etc HTTP/1.1\r\nHost: h\r\n\r\n".encode())
    await proxy.close()
    assert ok.startswith(b"HTTP/1.1 200 OK") and up.requests[0].startswith(b"GET /ok/sub?x=1 ")
    assert bad_method.startswith(b"HTTP/1.1 403 no allow filter matches")
    assert bad_path.startswith(b"HTTP/1.1 403 no allow filter matches")
    assert dotted.startswith(b"HTTP/1.1 403 dot segment in request path")
    denied = [r for r in records if r.decision == "deny"]
    assert [(r.reason, r.method, r.target) for r in denied] == [
        ("no allow filter matches", "POST", "/ok/a"),
        ("no allow filter matches", "GET", "/other"),
        ("dot segment in request path", "GET", "/ok/../etc"),
    ]
    assert all(r.protocol == "http" and r.status == 403 for r in denied)


class TlsUpstream:
    """Loopback HTTPS server that answers every request with what it received."""

    def __init__(self, ca: CertificateAuthority) -> None:
        self.requests: list[bytes] = []
        self.ca = ca

    async def handle(self, r: asyncio.StreamReader, w: asyncio.StreamWriter) -> None:
        head = await r.readuntil(b"\r\n\r\n")
        self.requests.append(head)
        w.write(b"HTTP/1.1 200 OK\r\nContent-Length: 5\r\nConnection: close\r\n\r\nhello")
        await w.drain()
        w.close()


@pytest.fixture
async def tls_upstream(tmp_path: Path) -> AsyncIterator[tuple[TlsUpstream, int]]:
    up = TlsUpstream(CertificateAuthority(tmp_path / "upstream-ca"))
    server = await asyncio.start_server(
        up.handle, "127.0.0.1", 0, ssl=up.ca.server_context("127.0.0.1")
    )
    yield up, server.sockets[0].getsockname()[1]
    server.close()


async def read_response(r: asyncio.StreamReader) -> bytes:
    """One response, framed by its Content-Length (all test servers send one)."""
    head = await asyncio.wait_for(r.readuntil(b"\r\n\r\n"), 5)
    length = next(
        int(line.split(b":")[1])
        for line in head.split(b"\r\n")
        if line.lower().startswith(b"content-length:")
    )
    return head + await asyncio.wait_for(r.readexactly(length), 5)


async def open_tunnel(
    tmp_path: Path, port: int, ca: CertificateAuthority
) -> tuple[asyncio.StreamReader, asyncio.StreamWriter]:
    """CONNECT, then speak TLS trusting the proxy's CA."""
    r, w = await asyncio.open_unix_connection(str(tmp_path / "p.sock"))
    w.write(f"CONNECT 127.0.0.1:{port} HTTP/1.1\r\n\r\n".encode())
    await w.drain()
    assert (await r.readuntil(b"\r\n\r\n")).startswith(b"HTTP/1.1 200")
    ctx = ssl.create_default_context(cadata=ca.ca_pem.decode())
    await w.start_tls(ctx, server_hostname="127.0.0.1")
    return r, w


async def tls_fetch(tmp_path: Path, port: int, ca: CertificateAuthority, request: bytes) -> bytes:
    """One request through an intercepted tunnel; returns its response."""
    r, w = await open_tunnel(tmp_path, port, ca)
    w.write(request)
    await w.drain()
    out = await read_response(r)
    w.close()
    return out


async def test_connect_interception(tmp_path: Path, tls_upstream: tuple[TlsUpstream, int]) -> None:
    up, port = tls_upstream
    trust = ssl.create_default_context()
    trust.load_verify_locations(cadata=up.ca.ca_pem.decode())
    rules = [
        inspect(
            f"127.0.0.1:{port}",
            [{"methods": ["GET"], "path": "/ok/**", "query": {"v": "1*"}}],
            deny=[{"path": "/ok/private/**"}],
        )
    ]
    proxy, records, ca = await make_rules_proxy(tmp_path, rules, upstream_tls=trust)

    ok = await tls_fetch(
        tmp_path,
        port,
        ca,
        b"GET /ok/data?v=1.2 HTTP/1.1\r\nHost: evil.example\r\n"
        b"Proxy-Authorization: Basic x\r\nX-Token: t\r\nConnection: keep-alive\r\n\r\n",
    )
    denied = await tls_fetch(tmp_path, port, ca, b"DELETE /ok/data?v=1 HTTP/1.1\r\nHost: h\r\n\r\n")
    bad_query = await tls_fetch(tmp_path, port, ca, b"GET /ok/data?v=2 HTTP/1.1\r\nHost: h\r\n\r\n")
    private = await tls_fetch(
        tmp_path, port, ca, b"GET /ok/private/key?v=1 HTTP/1.1\r\nHost: h\r\n\r\n"
    )
    await proxy.close()

    assert ok.startswith(b"HTTP/1.1 200 OK") and ok.endswith(b"hello")
    sent = up.requests[0].decode()
    assert sent.startswith("GET /ok/data?v=1.2 HTTP/1.1\r\n")
    assert f"Host: 127.0.0.1:{port}" in sent and "evil.example" not in sent
    assert "Proxy-Authorization" not in sent and "X-Token: t" in sent
    assert "Connection: close" in sent and "keep-alive" not in sent
    assert denied.startswith(b"HTTP/1.1 403 no allow filter matches")
    assert bad_query.startswith(b"HTTP/1.1 403 no allow filter matches")
    assert private.startswith(b"HTTP/1.1 403 request matches a deny filter")  # allow matched too
    assert len(up.requests) == 1
    https = [r for r in records if r.protocol == "https"]
    assert [r.decision for r in https] == ["allow", "deny", "deny", "deny"]
    assert (https[0].reason, https[0].target) == ("allow filter matches", "/ok/data?v=1.2")
    assert https[0].rule == f"127.0.0.1:{port}: allow GET /ok/**?v=1*"
    assert https[3].rule == f"127.0.0.1:{port}: deny * /ok/private/**"
    # a tunnel and the requests inside it share a connection number
    first = [(r.protocol, r.request, r.reason) for r in records if r.connection == 1]
    assert first == [("connect", None, "inspect"), ("https", 1, "allow filter matches")]


async def test_interception_rejects_untrusting_client(
    tmp_path: Path, tls_upstream: tuple[TlsUpstream, int]
) -> None:
    up, port = tls_upstream
    rules = [inspect(f"127.0.0.1:{port}")]
    proxy, _, _ = await make_rules_proxy(tmp_path, rules)
    other = CertificateAuthority(tmp_path / "other-ca")  # client trusts a different CA
    with pytest.raises(ssl.SSLError):
        await tls_fetch(tmp_path, port, other, b"GET / HTTP/1.1\r\nHost: h\r\n\r\n")
    await proxy.close()
    assert not up.requests


async def test_inspected_host_refuses_socks(tmp_path: Path, upstream: tuple[Upstream, int]) -> None:
    _, port = upstream
    rules = [inspect(f"127.0.0.1:{port}")]
    proxy, records, _ = await make_rules_proxy(tmp_path, rules)
    reply = await talk(
        tmp_path, b"\x05\x01\x00", b"\x05\x01\x00\x01\x7f\x00\x00\x01" + port.to_bytes(2)
    )
    await proxy.close()
    assert reply[:4] == b"\x05\x00" + b"\x05\x02"  # connection not allowed by ruleset
    assert records[-1].decision == "deny"
    assert records[-1].reason == "inspected host; use the HTTP proxy"


# --- credentials -------------------------------------------------------------------------

SECRET = "real-secret-value-42"
PLACEHOLDER = "SANDBOX_PLACEHOLDER_TOKEN"


def with_credentials(
    host: str, *credentials: Credential, allow: list[dict] | None = None
) -> tuple[HostRule, Sequence[Credential]]:
    return inspect(host, allow), credentials


def bearer(host: str, secret: str = SECRET) -> Credential:
    return Credential("Authorization", secret, inject="Bearer {secret}", source=f"{host}: Auth")


def stand_in(host: str, header: str = "Authorization", *, elsewhere: bool = False) -> Credential:
    return Credential(
        header,
        SECRET,
        placeholder=PLACEHOLDER,
        source=f"{host}: {header} (ph)",
        allow_placeholder_elsewhere=elsewhere,
    )


def assert_secret_not_in(records: list[NetworkEvent]) -> None:
    assert all(SECRET not in r.model_dump_json() for r in records)


async def test_injected_credential(tmp_path: Path, tls_upstream: tuple[TlsUpstream, int]) -> None:
    up, port = tls_upstream
    trust = ssl.create_default_context(cadata=up.ca.ca_pem.decode())
    host = f"127.0.0.1:{port}"
    rules = [with_credentials(host, bearer(host), allow=[{"path": "/ok/**"}])]
    proxy, records, ca = await make_rules_proxy(tmp_path, rules, upstream_tls=trust)
    r, w = await open_tunnel(tmp_path, port, ca)
    # two requests on one tunnel, the second trying to get the header dropped as hop-by-hop
    w.write(b"GET /ok/1 HTTP/1.1\r\nHost: h\r\nAuthorization: Bearer fake\r\n\r\n")
    first = await read_response(r)
    w.write(b"GET /ok/2 HTTP/1.1\r\nHost: h\r\nConnection: Authorization\r\n\r\n")
    second = await read_response(r)
    w.write(b"GET /private HTTP/1.1\r\nHost: h\r\n\r\n")
    refused = await read_response(r)
    w.close()
    await proxy.close()
    assert first.startswith(b"HTTP/1.1 200") and second.startswith(b"HTTP/1.1 200")
    assert refused.startswith(b"HTTP/1.1 403 no allow filter matches")
    assert len(up.requests) == 2  # the refused request never got anywhere, credential or not
    for sent in up.requests:
        auth = [line for line in sent.split(b"\r\n") if line.lower().startswith(b"authorization")]
        assert auth == [f"Authorization: Bearer {SECRET}".encode()]
    https = [(e.decision, e.credentials) for e in records if e.protocol == "https"]
    assert https == [("allow", [f"{host}: Auth"]), ("allow", [f"{host}: Auth"]), ("deny", None)]
    assert_secret_not_in(records)


async def test_placeholder_credential(
    tmp_path: Path, tls_upstream: tuple[TlsUpstream, int]
) -> None:
    up, port = tls_upstream
    trust = ssl.create_default_context(cadata=up.ca.ca_pem.decode())
    host = f"127.0.0.1:{port}"
    proxy, records, ca = await make_rules_proxy(
        tmp_path, [with_credentials(host, stand_in(host))], upstream_tls=trust
    )
    ok = await tls_fetch(
        tmp_path,
        port,
        ca,
        f"GET /x HTTP/1.1\r\nHost: h\r\nAuthorization: token {PLACEHOLDER}\r\n\r\n".encode(),
    )
    plain = await tls_fetch(tmp_path, port, ca, b"GET /y HTTP/1.1\r\nAuthorization: mine\r\n\r\n")
    await proxy.close()
    assert ok.startswith(b"HTTP/1.1 200") and plain.startswith(b"HTTP/1.1 200")
    sent = up.requests[0].decode()
    assert f"Authorization: token {SECRET}\r\n" in sent and PLACEHOLDER not in sent
    assert "Authorization: mine\r\n" in up.requests[1].decode()
    https = [e.credentials for e in records if e.protocol == "https"]
    assert https == [[f"{host}: Authorization (ph)"], None]
    assert_secret_not_in(records)


async def test_credentials_are_not_sent_over_plain_http(
    tmp_path: Path, upstream: tuple[Upstream, int]
) -> None:
    up, port = upstream
    host = f"127.0.0.1:{port}"
    rules = [with_credentials(host, stand_in(host))]
    proxy, records, _ = await make_rules_proxy(tmp_path, rules)
    base = f"http://{host}"
    refused = await talk(
        tmp_path, f"GET {base}/a HTTP/1.1\r\nAuthorization: Bearer {PLACEHOLDER}\r\n\r\n".encode()
    )
    without = await talk(tmp_path, f"GET {base}/b HTTP/1.1\r\n\r\n".encode())
    await proxy.close()
    assert refused.startswith(b"HTTP/1.1 403 credentials are only sent over https")
    assert without.startswith(b"HTTP/1.1 200")  # no credential involved: fine
    assert len(up.requests) == 1 and up.requests[0].startswith(b"GET /b ")
    assert (records[0].decision, records[0].rule) == ("deny", f"{host}: Authorization (ph)")
    assert_secret_not_in(records)


async def test_injecting_host_refuses_plain_http(
    tmp_path: Path, upstream: tuple[Upstream, int]
) -> None:
    up, port = upstream
    host = f"127.0.0.1:{port}"
    proxy, _, _ = await make_rules_proxy(tmp_path, [with_credentials(host, bearer(host))])
    resp = await talk(tmp_path, f"GET http://{host}/ HTTP/1.1\r\n\r\n".encode())
    await proxy.close()
    assert resp.startswith(b"HTTP/1.1 403 credentials are only sent over https")
    assert not up.requests


class BodyUpstream:
    """Loopback HTTPS server that reads each request's whole body (Content-Length or
    chunked) and answers only a complete request; keeps every byte it received."""

    def __init__(self, ca: CertificateAuthority) -> None:
        self.ca = ca
        self.received: list[bytes] = []
        self.complete: list[bool] = []

    async def handle(self, r: asyncio.StreamReader, w: asyncio.StreamWriter) -> None:
        data, complete = b"", False
        try:
            data = await r.readuntil(b"\r\n\r\n")
            if m := re.search(rb"content-length: *(\d+)", data, re.I):
                data += await r.readexactly(int(m.group(1)))
            elif re.search(rb"transfer-encoding: *chunked", data, re.I):
                data += await r.readuntil(b"\r\n0\r\n\r\n")
            complete = True
            w.write(b"HTTP/1.1 200 OK\r\nContent-Length: 2\r\nConnection: close\r\n\r\nok")
            await w.drain()
        except asyncio.IncompleteReadError as e:
            data += e.partial
        except OSError, asyncio.LimitOverrunError:
            pass
        finally:
            self.received.append(data)
            self.complete.append(complete)
            w.close()


@pytest.fixture
async def body_upstream(tmp_path: Path) -> AsyncIterator[tuple[BodyUpstream, int]]:
    up = BodyUpstream(CertificateAuthority(tmp_path / "upstream-ca"))
    server = await asyncio.start_server(
        up.handle, "127.0.0.1", 0, ssl=up.ca.server_context("127.0.0.1"), limit=1 << 20
    )
    yield up, server.sockets[0].getsockname()[1]
    server.close()


def basic(user: str, password: str) -> str:
    return "Basic " + base64.b64encode(f"{user}:{password}".encode()).decode()


ESCAPED = "%53" + PLACEHOLDER[1:]  # percent-encoded `S`


@pytest.mark.parametrize(
    ("request_bytes", "where"),
    [
        (f"GET /x?q={PLACEHOLDER} HTTP/1.1\r\n\r\n", "request target"),
        (f"GET /x/{ESCAPED} HTTP/1.1\r\n\r\n", "request target"),
        (f"GET /x HTTP/1.1\r\nX-Echo: {PLACEHOLDER}\r\n\r\n", "X-Echo header"),
        (f"GET /x HTTP/1.1\r\nCookie: t={PLACEHOLDER}\r\n\r\n", "Cookie header"),
        (f"GET /x HTTP/1.1\r\nX-Auth: {basic('u', PLACEHOLDER)}\r\n\r\n", "X-Auth header"),
        # also next to a correctly placed one
        (
            f"GET /x HTTP/1.1\r\nAuthorization: Bearer {PLACEHOLDER}\r\n"
            f"X-Copy: {PLACEHOLDER}\r\n\r\n",
            "X-Copy header",
        ),
    ],
)
async def test_misplaced_placeholder_in_a_request_head_is_refused(
    tmp_path: Path, body_upstream: tuple[BodyUpstream, int], request_bytes: str, where: str
) -> None:
    up, port = body_upstream
    trust = ssl.create_default_context(cadata=up.ca.ca_pem.decode())
    host = f"127.0.0.1:{port}"
    proxy, records, ca = await make_rules_proxy(
        tmp_path, [with_credentials(host, stand_in(host))], upstream_tls=trust
    )
    resp = await tls_fetch(tmp_path, port, ca, request_bytes.encode())
    await proxy.close()
    assert resp.startswith(f"HTTP/1.1 403 credential placeholder in the {where}".encode())
    assert not up.received  # refused before anything went upstream
    (event,) = [e for e in records if e.protocol == "https"]
    assert (event.decision, event.rule, event.status) == (
        "deny",
        f"{host}: Authorization (ph)",
        403,
    )
    assert event.violation and event.credentials is None


@pytest.mark.parametrize("size", [1_000, 300_000, 5_000_000])
async def test_large_upload_through_an_intercepted_tunnel(
    tmp_path: Path, body_upstream: tuple[BodyUpstream, int], size: int
) -> None:
    """Regression: with `StreamWriter.start_tls()` an upload that followed the handshake
    closely and overfilled the reader paused the plain socket for good (hung at ~256 KB)."""
    up, port = body_upstream
    trust = ssl.create_default_context(cadata=up.ca.ca_pem.decode())
    proxy, _, ca = await make_rules_proxy(
        tmp_path, [inspect(f"127.0.0.1:{port}")], upstream_tls=trust
    )
    r, w = await open_tunnel(tmp_path, port, ca)
    w.write(b"POST /up HTTP/1.1\r\nContent-Length: %d\r\n\r\n" % size + b"a" * size)
    resp = await read_response(r)
    w.close()
    await proxy.close()
    assert resp.startswith(b"HTTP/1.1 200") and up.complete == [True]
    assert up.received[0].endswith(b"a" * 1000) and len(up.received[0]) > size


def chunked(*chunks: bytes, trailer: bytes = b"") -> bytes:
    body = b"".join(b"%x\r\n%s\r\n" % (len(c), c) for c in chunks)
    return b"Transfer-Encoding: chunked\r\n\r\n" + body + b"0\r\n" + trailer + b"\r\n"


PH = PLACEHOLDER.encode()


@pytest.mark.parametrize(
    "body",
    [
        b"Content-Length: %d\r\n\r\n" % (len(PH) + 7) + b"token=" + PH + b"&",
        # far into a large body: found across reads
        b"Content-Length: %d\r\n\r\n" % (300_001 + len(PH)) + b"a" * 300_001 + PH,
        chunked(b"token=" + PH[:9], PH[9:] + b"&x=1"),  # split across chunks
        chunked(b"x=1", trailer=b"X-Trailer: " + PH + b"\r\n"),
        b"Transfer-Encoding: chunked\r\n\r\n3;ext=" + PH + b"\r\nx=1\r\n0\r\n\r\n",
    ],
)
async def test_placeholder_in_a_request_body_is_refused(
    tmp_path: Path, body_upstream: tuple[BodyUpstream, int], body: bytes
) -> None:
    up, port = body_upstream
    trust = ssl.create_default_context(cadata=up.ca.ca_pem.decode())
    host = f"127.0.0.1:{port}"
    proxy, records, ca = await make_rules_proxy(
        tmp_path, [with_credentials(host, stand_in(host))], upstream_tls=trust
    )
    r, w = await open_tunnel(tmp_path, port, ca)
    w.write(b"POST /upload HTTP/1.1\r\nAuthorization: Bearer " + PH + b"\r\n" + body)
    await w.drain()
    resp = await asyncio.wait_for(r.read(), 5)
    w.close()
    for _ in range(100):  # the upstream notices the abort
        if up.received:
            break
        await asyncio.sleep(0.01)
    await proxy.close()
    # the client is told; the upstream never got a complete request, nor the placeholder
    assert resp.startswith(b"HTTP/1.1 403 credential placeholder in the request body")
    assert up.complete == [False] and PH not in up.received[0]
    https = [(e.decision, e.reason, e.request) for e in records if e.protocol == "https"]
    assert https == [
        ("allow", "allow filter matches", 1),  # the head was fine...
        ("deny", "credential placeholder in the request body", 1),  # ...its body was not
    ]
    assert_secret_not_in(records)


async def test_placeholder_sent_to_another_host_is_refused(
    tmp_path: Path, pipeline: tuple[PipelineUpstream, int]
) -> None:
    up, port = pipeline
    rules = [
        with_credentials("api.example.com", stand_in("api.example.com")),
        parse_host_rule(f"127.0.0.1:{port}", "tunnel"),
    ]
    proxy, records, _ = await make_rules_proxy(tmp_path, rules)
    url = f"http://127.0.0.1:{port}"
    header = await talk(
        tmp_path, f"GET {url}/ HTTP/1.1\r\nAuthorization: Bearer {PLACEHOLDER}\r\n\r\n".encode()
    )
    git = await talk(  # `git push https://x:$TOKEN@127.0.0.1/...`
        tmp_path,
        f"GET {url}/ HTTP/1.1\r\nAuthorization: {basic('x', PLACEHOLDER)}\r\n\r\n".encode(),
    )
    body = await talk(
        tmp_path,
        f"POST {url}/ HTTP/1.1\r\nContent-Length: {len(PH)}\r\n\r\n".encode() + PH,
    )
    fine = await talk(tmp_path, f"GET {url}/ok HTTP/1.1\r\n\r\n".encode())
    await up.settled(2)
    await proxy.close()
    for resp in (header, git):
        assert resp.startswith(b"HTTP/1.1 403 credential placeholder in the Authorization header")
    assert body.startswith(b"HTTP/1.1 403 credential placeholder in the request body")
    assert fine.startswith(b"HTTP/1.1 200")
    # only the POST's head (never completed) and the fine request went upstream
    assert up.lines == ["POST / HTTP/1.1", "GET /ok HTTP/1.1"]
    assert all(PH not in data for data in up.received)
    denied = [e for e in records if e.decision == "deny"]
    assert [e.reason.removeprefix("credential placeholder in the ") for e in denied] == [
        "Authorization header",
        "Authorization header",
        "request body",
    ]
    # the refusals name the credential whose placeholder it is, on the host it was sent to
    assert {(e.host, e.rule) for e in denied} == {
        ("127.0.0.1", "api.example.com: Authorization (ph)")
    }


async def test_placeholder_in_a_host_name_is_refused(tmp_path: Path) -> None:
    asked: list[NetworkRequest] = []

    async def approve(req: NetworkRequest) -> bool:
        asked.append(req)
        return True

    rules = [with_credentials("api.example.com", stand_in("api.example.com"))]
    proxy, records, _ = await make_rules_proxy(tmp_path, rules)
    proxy._approve = approve
    name = f"{PLACEHOLDER.lower()}.attacker.example"  # DNS is case-insensitive
    connect = await talk(tmp_path, f"CONNECT {name}:443 HTTP/1.1\r\n\r\n".encode())
    http = await talk(tmp_path, f"GET http://x.{PLACEHOLDER}.example/ HTTP/1.1\r\n\r\n".encode())
    raw = name.encode()
    socks = await talk(
        tmp_path, b"\x05\x01\x00", b"\x05\x01\x00\x03" + bytes([len(raw)]) + raw + b"\x01\xbb"
    )
    await proxy.close()
    for resp in (connect, http):
        assert resp.startswith(b"HTTP/1.1 403 credential placeholder in the host name")
    assert socks == b"\x05\x00" + b"\x05\x02\x00\x01" + bytes(6)  # not allowed by ruleset
    assert not asked  # never offered for approval
    assert [(e.protocol, e.decision, e.reason) for e in records] == [
        ("connect", "deny", "credential placeholder in the host name"),
        ("http", "deny", "credential placeholder in the host name"),
        ("socks5", "deny", "credential placeholder in the host name"),
    ]


async def test_placeholder_elsewhere_can_be_allowed(
    tmp_path: Path,
    body_upstream: tuple[BodyUpstream, int],
    pipeline: tuple[PipelineUpstream, int],
) -> None:
    up, port = body_upstream
    other, other_port = pipeline
    trust = ssl.create_default_context(cadata=up.ca.ca_pem.decode())
    host = f"127.0.0.1:{port}"
    rules = [
        with_credentials(host, stand_in(host, elsewhere=True)),
        parse_host_rule(f"127.0.0.1:{other_port}", "tunnel"),
    ]
    proxy, records, ca = await make_rules_proxy(tmp_path, rules, upstream_tls=trust)
    own = await tls_fetch(
        tmp_path,
        port,
        ca,
        f"POST /x?q={PLACEHOLDER} HTTP/1.1\r\nAuthorization: token {PLACEHOLDER}\r\n"
        f"X-Echo: {PLACEHOLDER}\r\nContent-Length: {len(PH)}\r\n\r\n".encode()
        + PH,
    )
    elsewhere = await talk(
        tmp_path,
        f"GET http://127.0.0.1:{other_port}/ HTTP/1.1\r\n"
        f"Authorization: {PLACEHOLDER}\r\n\r\n".encode(),
    )
    await other.settled(1)
    await proxy.close()
    assert own.startswith(b"HTTP/1.1 200") and elsewhere.startswith(b"HTTP/1.1 200")
    sent = up.received[0].decode()
    # still only the credential's header is rewritten; the rest goes as it is
    assert f"Authorization: token {SECRET}\r\n" in sent and sent.count(SECRET) == 1
    assert sent.startswith(f"POST /x?q={PLACEHOLDER} ") and f"X-Echo: {PLACEHOLDER}\r\n" in sent
    assert sent.endswith(PLACEHOLDER)
    assert f"Authorization: {PLACEHOLDER}\r\n".encode() in other.received[0]
    assert SECRET.encode() not in other.received[0]
    assert not [e for e in records if e.decision == "deny"]


async def test_conflicting_credentials_refuse_the_request(
    tmp_path: Path, tls_upstream: tuple[TlsUpstream, int]
) -> None:
    up, port = tls_upstream
    trust = ssl.create_default_context(cadata=up.ca.ca_pem.decode())
    # two entries cover the host, each injecting its own Authorization
    rules = [
        with_credentials("127.0.0.1", bearer("127.0.0.1", "one")),
        with_credentials(f"127.0.0.1:{port}", bearer(f"127.0.0.1:{port}", "two")),
    ]
    proxy, records, ca = await make_rules_proxy(tmp_path, rules, upstream_tls=trust)
    resp = await tls_fetch(tmp_path, port, ca, b"GET / HTTP/1.1\r\n\r\n")
    await proxy.close()
    assert resp.startswith(b"HTTP/1.1 403 conflicting credentials for the Authorization header")
    assert not up.requests
    assert records[-1].rule == f"127.0.0.1: Auth, 127.0.0.1:{port}: Auth"


async def test_credentials_only_ride_on_requests_their_own_entry_allows(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """api.github.com allows GET /repos/** with a token; *.github.com allows everything
    without one. A POST or DELETE gets through on the wildcard entry, but not the token."""
    up = TlsUpstream(CertificateAuthority(tmp_path / "upstream-ca"))
    server = await asyncio.start_server(
        up.handle, "127.0.0.1", 0, ssl=up.ca.server_context("api.github.com")
    )
    port = server.sockets[0].getsockname()[1]
    rules = [
        with_credentials(
            "api.github.com",
            bearer("api.github.com"),
            allow=[{"methods": ["GET"], "path": "/repos/**"}],
        ),
        inspect("*.github.com"),  # every method, no credentials
    ]
    trust = ssl.create_default_context(cadata=up.ca.ca_pem.decode())
    proxy, records, ca = await make_rules_proxy(tmp_path, rules, upstream_tls=trust)

    async def loopback(host: str, port: int) -> str:
        return "127.0.0.1"

    monkeypatch.setattr(proxy._guard, "resolve", loopback)
    requests = [
        b"GET /repos/o/r HTTP/1.1\r\n\r\n",
        b"POST /repos/o/r/issues HTTP/1.1\r\nContent-Length: 2\r\n\r\n{}",
        b"DELETE /repos/o/r HTTP/1.1\r\n\r\n",
        b"GET /user HTTP/1.1\r\n\r\n",  # GET, but outside the token's paths
    ]
    responses: list[bytes] = []
    for request in requests:
        r, w = await asyncio.open_unix_connection(str(tmp_path / "p.sock"))
        w.write(f"CONNECT api.github.com:{port} HTTP/1.1\r\n\r\n".encode())
        assert (await r.readuntil(b"\r\n\r\n")).startswith(b"HTTP/1.1 200")
        await w.start_tls(
            ssl.create_default_context(cadata=ca.ca_pem.decode()), server_hostname="api.github.com"
        )
        w.write(request)
        responses.append(await read_response(r))
        w.close()
    await proxy.close()
    server.close()
    assert all(resp.startswith(b"HTTP/1.1 200") for resp in responses)  # all allowed...
    token = f"Authorization: Bearer {SECRET}".encode()
    assert [token in sent for sent in up.requests] == [True, False, False, False]  # ...one token
    https = [(e.method, e.credentials) for e in records if e.protocol == "https"]
    assert https == [
        ("GET", ["api.github.com: Auth"]),
        ("POST", None),
        ("DELETE", None),
        ("GET", None),
    ]


# --- one message at a time ---------------------------------------------------------------


class PipelineUpstream:
    """Worst case: answers every request it can parse on a connection (ignoring
    `Connection: close`), and keeps every byte each connection received."""

    def __init__(self) -> None:
        self.lines: list[str] = []
        self.received: list[bytes] = []

    async def handle(self, r: asyncio.StreamReader, w: asyncio.StreamWriter) -> None:
        data = b""
        try:
            while True:
                head = await r.readuntil(b"\r\n\r\n")
                data += head
                line = head.split(b"\r\n")[0].decode()
                self.lines.append(line)
                if m := re.search(rb"content-length: *(\d+)", head, re.I):
                    data += await r.readexactly(int(m.group(1)))
                body = b"" if line.startswith("HEAD") else b"ok\n"
                w.write(b"HTTP/1.1 200 OK\r\nContent-Length: 3\r\n\r\n" + body)
                await w.drain()
        except asyncio.IncompleteReadError as e:
            data += e.partial
        except ConnectionError:
            pass
        finally:
            self.received.append(data)
            w.close()

    async def settled(self, connections: int) -> None:
        for _ in range(100):
            if len(self.received) >= connections:
                return
            await asyncio.sleep(0.01)


@pytest.fixture
async def pipeline() -> AsyncIterator[tuple[PipelineUpstream, int]]:
    up = PipelineUpstream()
    server = await asyncio.start_server(up.handle, "127.0.0.1", 0)
    yield up, server.sockets[0].getsockname()[1]
    server.close()


@pytest.mark.parametrize(
    ("second", "status"),
    [
        (b"DELETE / HTTP/1.1\r\n\r\n", b"400 only absolute"),  # the bug report, verbatim
        (b"DELETE http://127.0.0.1:{port}/ HTTP/1.1\r\n\r\n", b"403 no allow filter matches"),
        (b"GET http://127.0.0.1:{port}/ HTTP/1.1\r\nX: y\r\n folded\r\n\r\n", b"400 bad header"),
        (b"CONNECT 127.0.0.1:{port} HTTP/1.1\r\n\r\n", b"400 CONNECT must be the first"),
    ],
)
async def test_pipelined_requests_are_each_vetted(
    tmp_path: Path, pipeline: tuple[PipelineUpstream, int], second: bytes, status: bytes
) -> None:
    up, port = pipeline
    proxy, records, _ = await make_rules_proxy(
        tmp_path, [inspect(f"127.0.0.1:{port}", [{"methods": ["GET"]}])]
    )
    first = f"GET http://127.0.0.1:{port}/ HTTP/1.1\r\n\r\n".encode()
    resp = await talk(tmp_path, first + second.replace(b"{port}", str(port).encode()))
    await up.settled(1)
    await proxy.close()
    ok, _, refused = resp.partition(b"ok\n")
    assert ok.startswith(b"HTTP/1.1 200 OK") and refused.startswith(b"HTTP/1.1 " + status)
    assert up.lines == ["GET / HTTP/1.1"]  # nothing after the GET reached the server
    if status.startswith(b"403"):
        assert (records[-1].reason, records[-1].method) == ("no allow filter matches", "DELETE")


@pytest.mark.parametrize(
    ("body_headers", "body"),
    [
        (b"Content-Length: 4\r\n", b"body"),
        (b"Transfer-Encoding: chunked\r\n", b"4;ext=1\r\nbody\r\n0\r\nTrailer-X: 1\r\n\r\n"),
    ],
)
async def test_bodies_are_forwarded_exactly(
    tmp_path: Path, pipeline: tuple[PipelineUpstream, int], body_headers: bytes, body: bytes
) -> None:
    up, port = pipeline
    proxy, _, _ = await make_rules_proxy(
        tmp_path, [inspect(f"127.0.0.1:{port}", [{"methods": ["POST"]}])]
    )
    head = f"POST http://127.0.0.1:{port}/u HTTP/1.1\r\n".encode() + body_headers + b"\r\n"
    smuggled = b"DELETE /x HTTP/1.1\r\n\r\n"  # right after the body, on the same connection
    resp = await talk(tmp_path, head + body + smuggled)
    await up.settled(1)
    await proxy.close()
    assert resp.startswith(b"HTTP/1.1 200 OK") and b"400 only absolute" in resp
    assert up.received[0].endswith(b"\r\n\r\n" + body)  # exactly the body, nothing after
    assert b"DELETE" not in b"".join(up.received)


async def test_keep_alive_serves_each_request(
    tmp_path: Path, pipeline: tuple[PipelineUpstream, int]
) -> None:
    up, port = pipeline
    proxy, _ = await make_proxy(tmp_path, [f"127.0.0.1:{port}"])  # a `tunnel` host
    r, w = await asyncio.open_unix_connection(str(tmp_path / "p.sock"))
    for path in ("/one", "/two"):
        w.write(f"GET http://127.0.0.1:{port}{path} HTTP/1.1\r\n\r\n".encode())
        assert (await read_response(r)).startswith(b"HTTP/1.1 200 OK")
    w.write(f"HEAD http://127.0.0.1:{port}/h HTTP/1.1\r\n\r\n".encode())  # CL but no body
    assert (await asyncio.wait_for(r.readuntil(b"\r\n\r\n"), 5)).startswith(b"HTTP/1.1 200")
    w.write(b"GET http://blocked.example.com/ HTTP/1.1\r\n\r\n")  # another host: decided anew
    assert (await read_response(r)).startswith(b"HTTP/1.1 403 host is denied")
    assert await asyncio.wait_for(r.read(), 5) == b""  # a refusal ends the connection
    w.close()
    await proxy.close()
    assert up.lines == ["GET /one HTTP/1.1", "GET /two HTTP/1.1", "HEAD /h HTTP/1.1"]


async def test_intercepted_tunnel_vets_every_request(
    tmp_path: Path, tls_upstream: tuple[TlsUpstream, int]
) -> None:
    up, port = tls_upstream
    trust = ssl.create_default_context()
    trust.load_verify_locations(cadata=up.ca.ca_pem.decode())
    rules = [inspect(f"127.0.0.1:{port}", [{"methods": ["GET"]}])]
    proxy, records, ca = await make_rules_proxy(tmp_path, rules, upstream_tls=trust)
    r, w = await open_tunnel(tmp_path, port, ca)
    w.write(b"GET /a HTTP/1.1\r\nHost: h\r\n\r\n")  # kept alive...
    assert (await read_response(r)).endswith(b"hello")
    w.write(b"GET /b HTTP/1.1\r\nHost: h\r\n\r\nDELETE /c HTTP/1.1\r\nHost: h\r\n\r\n")
    assert (await read_response(r)).endswith(b"hello")  # ...and pipelined
    assert (await read_response(r)).startswith(b"HTTP/1.1 403 no allow filter matches")
    w.close()
    await proxy.close()
    assert [h.split(b"\r\n")[0] for h in up.requests] == [b"GET /a HTTP/1.1", b"GET /b HTTP/1.1"]
    assert (records[-1].reason, records[-1].target, records[-1].request) == (
        "no allow filter matches",
        "/c",
        3,
    )


async def serve_once(handler) -> tuple[asyncio.Server, int]:
    server = await asyncio.start_server(handler, "127.0.0.1", 0)
    return server, server.sockets[0].getsockname()[1]


async def test_expect_100_continue(tmp_path: Path) -> None:
    async def handler(r: asyncio.StreamReader, w: asyncio.StreamWriter) -> None:
        await r.readuntil(b"\r\n\r\n")
        w.write(b"HTTP/1.1 100 Continue\r\n\r\n")
        body = await r.readexactly(5)
        w.write(b"HTTP/1.1 201 Created\r\nContent-Length: 5\r\n\r\n" + body)
        await w.drain()
        w.close()

    server, port = await serve_once(handler)
    proxy, _ = await make_proxy(tmp_path, [f"127.0.0.1:{port}"])
    r, w = await asyncio.open_unix_connection(str(tmp_path / "p.sock"))
    w.write(
        f"PUT http://127.0.0.1:{port}/ HTTP/1.1\r\nExpect: 100-continue\r\n"
        "Content-Length: 5\r\n\r\n".encode()
    )
    assert await asyncio.wait_for(r.readuntil(b"\r\n\r\n"), 5) == b"HTTP/1.1 100 Continue\r\n\r\n"
    w.write(b"hello")  # only sent once the server asked for it
    assert (await read_response(r)).endswith(b"201 Created\r\nContent-Length: 5\r\n\r\nhello")
    w.close()
    await proxy.close()
    server.close()


@pytest.mark.parametrize(
    ("response", "relayed", "kept"),
    [
        (  # chunked: relayed verbatim, the connection stays usable
            b"HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\nConnection: close\r\n\r\n"
            b"2\r\nhi\r\n0\r\n\r\n",
            b"HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\n\r\n2\r\nhi\r\n0\r\n\r\n",
            True,
        ),
        (  # no length: the body runs to the server's close, so the client's must close too
            b"HTTP/1.1 200 OK\r\nKeep-Alive: x\r\n\r\nuntil close",
            b"HTTP/1.1 200 OK\r\nConnection: close\r\n\r\nuntil close",
            False,
        ),
    ],
)
async def test_response_framing(
    tmp_path: Path, response: bytes, relayed: bytes, kept: bool
) -> None:
    async def handler(r: asyncio.StreamReader, w: asyncio.StreamWriter) -> None:
        await r.readuntil(b"\r\n\r\n")
        w.write(response)
        await w.drain()
        w.close()

    server, port = await serve_once(handler)
    proxy, _ = await make_proxy(tmp_path, [f"127.0.0.1:{port}"])
    r, w = await asyncio.open_unix_connection(str(tmp_path / "p.sock"))
    w.write(f"GET http://127.0.0.1:{port}/ HTTP/1.1\r\n\r\n".encode())
    got = await asyncio.wait_for(r.readexactly(len(relayed)), 5)
    if kept:
        w.write(b"GET http://127.0.0.1:1/ HTTP/1.1\r\n\r\n")  # the connection still serves
    rest = await asyncio.wait_for(r.read(), 5)
    w.close()
    await proxy.close()
    server.close()
    assert got == relayed
    assert rest.startswith(b"HTTP/1.1 403") if kept else rest == b""


# --- network events ----------------------------------------------------------------------


@pytest.mark.parametrize(
    ("data", "then", "reason", "status"),
    [
        (b"HELLO\r\n\r\n", b"", "bad request line", 400),
        (b"CONNECT nonsense HTTP/1.1\r\n\r\n", b"", "bad CONNECT target", 400),
        (b"GET /origin HTTP/1.1\r\n\r\n", b"", "only absolute http:// requests", 400),
        (b"GET http://x.com/ HTTP/1.1\r\nX: a\r\n folded\r\n\r\n", b"", "bad header", 400),
        (
            b"POST http://x.com/ HTTP/1.1\r\nContent-Length: 1\r\nContent-Length: 2\r\n\r\n",
            b"",
            "ambiguous message framing",
            400,
        ),
        (b"GET http://x.com/ HTTP/1.1\r\nX: " + b"a" * 70000, b"", "message head too large", None),
        (b"\x04\x01\x00\x50", b"", "SOCKS4 is not supported", None),
        (b"\x05\x01\x02", b"", "no acceptable SOCKS auth method", None),
        (b"\x05\x01\x00", b"\x04\x01\x00\x01\x7f\x00\x00\x01\x00\x50", "bad SOCKS version", None),
        (b"\x05\x01\x00", b"\x05\x01\x00\x09", "unsupported SOCKS address type", None),
    ],
)
async def test_malformed_input_is_logged(
    tmp_path: Path, data: bytes, then: bytes, reason: str, status: int | None
) -> None:
    proxy, events = await make_proxy(tmp_path, [])
    await talk(tmp_path, data, then)
    await proxy.close()
    assert len(events) == 1, events
    (event,) = events
    assert event.decision == "malformed" and event.reason.startswith(reason)
    assert event.status == status and event.violation


async def test_bad_chunk_in_a_request_body_is_logged(
    tmp_path: Path, pipeline: tuple[PipelineUpstream, int]
) -> None:
    _, port = pipeline
    proxy, events = await make_proxy(tmp_path, [f"127.0.0.1:{port}"])
    await talk(
        tmp_path,
        f"POST http://127.0.0.1:{port}/u HTTP/1.1\r\nTransfer-Encoding: chunked\r\n\r\n".encode()
        + b"zz\r\n",
    )
    await proxy.close()
    assert [(e.decision, e.reason, e.request) for e in events] == [
        ("allow", "tunnel", 1),  # the head was fine...
        ("malformed", "bad chunk", 1),  # ...its body was not
    ]


async def test_client_refusing_the_interception_cert_is_logged(
    tmp_path: Path, tls_upstream: tuple[TlsUpstream, int]
) -> None:
    _, port = tls_upstream
    proxy, events, _ = await make_rules_proxy(tmp_path, [inspect(f"127.0.0.1:{port}")])
    with pytest.raises(ssl.SSLError):
        await open_tunnel(tmp_path, port, CertificateAuthority(tmp_path / "other"))
    await asyncio.sleep(0.05)
    await proxy.close()
    assert [(e.protocol, e.decision) for e in events] == [
        ("connect", "allow"),
        ("connect", "malformed"),
    ]
    assert events[1].reason == "client TLS handshake failed (does it trust the CA?)"


async def test_upstream_failures_are_logged_but_not_violations(tmp_path: Path) -> None:
    proxy, events = await make_proxy(tmp_path, ["127.0.0.1:1"])  # nothing listens there
    resp = await talk(tmp_path, b"GET http://127.0.0.1:1/x HTTP/1.1\r\n\r\n")
    await proxy.close()
    assert resp.startswith(b"HTTP/1.1 502 upstream connection failed")
    assert [(e.decision, e.status, e.target) for e in events] == [
        ("allow", None, "/x"),
        ("failed", 502, "/x"),
    ]
    assert not events[1].violation


async def test_every_request_on_a_connection_is_logged(
    tmp_path: Path, pipeline: tuple[PipelineUpstream, int]
) -> None:
    _, port = pipeline
    proxy, events = await make_proxy(tmp_path, [f"127.0.0.1:{port}"])
    base = f"http://127.0.0.1:{port}"
    await talk(
        tmp_path,
        f"GET {base}/a HTTP/1.1\r\n\r\nPUT {base}/b HTTP/1.1\r\nContent-Length: 1\r\n\r\nx"
        "GET http://blocked.example.com/c HTTP/1.1\r\n\r\n".encode(),
    )
    await proxy.close()
    assert [(e.connection, e.request, e.decision, e.method, e.host, e.target) for e in events] == [
        (1, 1, "allow", "GET", "127.0.0.1", "/a"),
        (1, 2, "allow", "PUT", "127.0.0.1", "/b"),
        (1, 3, "deny", "GET", "blocked.example.com", "/c"),
    ]
    assert events[0].rule == f"127.0.0.1:{port}" and events[2].rule == "blocked.example.com"
    assert events[2].summary() == (
        "deny http blocked.example.com:80 (host is denied: GET /c) [blocked.example.com]"
    )


async def test_a_failing_event_sink_does_not_break_the_proxy(
    tmp_path: Path, upstream: tuple[Upstream, int]
) -> None:
    _, port = upstream

    def boom(event: NetworkEvent) -> None:
        raise RuntimeError("disk full")

    proxy = FilteringProxy(
        str(tmp_path / "p.sock"),
        exec_id="e1",
        hosts=[parse_host_rule(f"127.0.0.1:{port}", "tunnel")],
        extra_allowed=[],
        guard=AddressGuard(
            local=set, allowed_literals=[parse_host_rule(f"127.0.0.1:{port}", "tunnel").domain]
        ),
        on_event=boom,
    )
    await proxy.start()
    resp = await talk(tmp_path, f"GET http://127.0.0.1:{port}/ HTTP/1.1\r\n\r\n".encode())
    await proxy.close()
    assert resp.startswith(b"HTTP/1.1 200 OK")


@pytest.mark.parametrize(
    ("data", "then", "response", "reason"),
    [
        (b"GET http://[ HTTP/1.1\r\n\r\n", b"", b"HTTP/1.1 400", "bad request URL"),  # reported
        (b"GET http://[::1 HTTP/1.1\r\n\r\n", b"", b"HTTP/1.1 400", "bad request URL"),
        (b"GET http://[zz]/ HTTP/1.1\r\n\r\n", b"", b"HTTP/1.1 400", "bad request URL"),
        (b"GET http://[::1]x/ HTTP/1.1\r\n\r\n", b"", b"HTTP/1.1 400", "bad request URL"),
        (b"GET http://a!b.com/ HTTP/1.1\r\n\r\n", b"", b"HTTP/1.1 400", "malformed host"),
        (b"GET http://a..b/ HTTP/1.1\r\n\r\n", b"", b"HTTP/1.1 400", "malformed host"),
        (b"CONNECT a!b.com:443 HTTP/1.1\r\n\r\n", b"", b"HTTP/1.1 400", "malformed host"),
        (b"CONNECT [zz]:443 HTTP/1.1\r\n\r\n", b"", b"HTTP/1.1 400", "bad CONNECT target"),
        (
            b"\x05\x01\x00",
            b"\x05\x01\x00\x03\x05a!b.c\x01\xbb",
            b"\x05\x00\x05\x01",
            "malformed host",
        ),
    ],
)
async def test_bad_urls_and_hosts_are_malformed_not_denied(
    tmp_path: Path, data: bytes, then: bytes, response: bytes, reason: str
) -> None:
    proxy, events = await make_proxy(tmp_path, [])
    resp = await talk(tmp_path, data, then)
    await proxy.close()
    assert resp.startswith(response), resp  # answered, not just dropped
    assert [(e.decision, e.reason) for e in events] == [("malformed", reason)]


async def test_unexpected_errors_are_reported_as_such(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    proxy, events = await make_proxy(tmp_path, [])

    def broken(raw: bytes):
        raise ValueError("a bug")

    monkeypatch.setattr("sandbox.net.proxy._parse_head", broken)
    loop_errors: list[dict] = []
    asyncio.get_running_loop().set_exception_handler(lambda _, ctx: loop_errors.append(ctx))
    await talk(tmp_path, b"GET http://x.com/ HTTP/1.1\r\n\r\n")
    await proxy.close()
    # not mislabelled as a property of the input (it used to read "message head too large")
    assert [(e.decision, e.reason) for e in events] == [
        ("failed", "internal proxy error (ValueError)")
    ]
    assert not events[0].violation
    assert isinstance(loop_errors[0]["exception"], ValueError)  # the traceback still surfaces
