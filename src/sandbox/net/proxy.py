"""Host-side filtering proxy: HTTP (CONNECT + absolute-URI) and SOCKS5 on one Unix socket.

One proxy listens per exec, on a socket bind-mounted into that exec's sandbox only, so every
connection is attributed to its exec by construction (srt has to trust a username the client
presents). The first byte tells the protocols apart: 0x05 is SOCKS5, anything else HTTP.

Every connection: canonicalise the target, decide (see `filter.decide`), resolve once and
vet the addresses (`AddressGuard`), dial the vetted IP. CONNECT and SOCKS tunnels to `tunnel`
hosts are then relayed as bytes, undecrypted. HTTP is never relayed as bytes: each request
on a connection (absolute-form proxy requests, or the requests inside an intercepted tunnel)
is parsed, routed and decided on its own, its body is forwarded exactly as framed, and its
response is framed too, so a pipelined or smuggled second request cannot ride along behind a
vetted one. For `inspect` hosts (`HostRule`) a CONNECT tunnel is terminated with a
certificate minted by the session CA (`mitm.CertificateAuthority`), every request inside is
vetted against the host's deny and allow filters, and it is re-encrypted upstream with
normal verification. Inspected hosts only speak HTTP(S) through the HTTP proxy: SOCKS
tunnels to them are refused because they cannot be inspected. An inspected host's
credentials are added to a vetted request on its way upstream (see `credentials.py`), so
the secrets never enter the sandbox; a credential placeholder anywhere it is not replaced
(host names, request targets, forwarded headers, request bodies) gets the request refused.
"""

import asyncio
import contextlib
import dataclasses
import ipaddress
import re
import ssl
from collections.abc import Callable, Sequence
from dataclasses import dataclass
from urllib.parse import urlsplit

from sandbox.net.credentials import BodyScan, CredentialRefused, Credentials
from sandbox.net.events import NetworkEvent, Outcome, Protocol
from sandbox.net.filter import (
    AddressDenied,
    AddressGuard,
    ApprovalCallback,
    Decision,
    DomainRule,
    HostRule,
    decide,
    judge_request,
    sanitize,
)
from sandbox.net.mitm import CertificateAuthority

HEAD_LIMIT = 64 * 1024
HEAD_TIMEOUT_S = 30.0
CONNECT_TIMEOUT_S = 30.0
_HOP_BY_HOP = {
    "connection",
    "keep-alive",
    "proxy-authenticate",
    "proxy-authorization",
    "proxy-connection",
    "te",
    "trailer",
    "upgrade",
}
_TOKEN = re.compile(r"^[!#$%&'*+\-.^_`|~0-9A-Za-z]+$")
_AUTHORITY = re.compile(r"^(?:\[([^\]]+)\]|([^:\[\]]+)):(\d{1,5})$")


class _Refused(Exception):
    """Refuse the current request or connection: 400 is malformed input, 403 a policy
    denial, 502 an allowed request that failed upstream."""

    def __init__(self, status: int, reason: str, rule: str | None = None) -> None:
        super().__init__(reason)
        self.status = status
        self.reason = reason
        self.rule = rule

    @property
    def outcome(self) -> Outcome:
        return "malformed" if self.status == 400 else "deny" if self.status == 403 else "failed"


@dataclass
class _Conn:
    """A client connection: the context stamped on each of its events."""

    id: int
    protocol: Protocol = "http"
    host: str | None = None
    port: int | None = None
    request: int | None = None
    method: str | None = None
    target: str | None = None

    def next_request(self, *, keep_host: bool) -> None:
        self.request = (self.request or 0) + 1
        self.method = self.target = None
        if not keep_host:
            self.host = self.port = None


class FilteringProxy:
    def __init__(
        self,
        socket_path: str,
        *,
        exec_id: str,
        hosts: Sequence[HostRule],
        credentials: Credentials | None = None,
        extra_allowed: Sequence[DomainRule],
        guard: AddressGuard,
        ca: CertificateAuthority | None = None,
        upstream_tls: ssl.SSLContext | None = None,
        approve: ApprovalCallback | None = None,
        on_event: Callable[[NetworkEvent], None] = lambda e: None,
    ) -> None:
        self.socket_path = socket_path
        self.exec_id = exec_id
        self._hosts, self._extra = list(hosts), list(extra_allowed)
        self._guard = guard
        inspects = any(h.access == "inspect" for h in self._hosts)
        if inspects and ca is None:
            raise ValueError("`inspect` hosts need a CertificateAuthority to intercept TLS")
        self._ca = ca
        self._upstream_tls = upstream_tls or (ssl.create_default_context() if inspects else None)
        self._approve = approve
        self._on_event = on_event
        self._credentials = credentials if credentials is not None else Credentials()
        self._placeholders = self._credentials.scan
        self._connections = 0
        self._server: asyncio.Server | None = None
        self._tasks: set[asyncio.Task[None]] = set()

    async def start(self) -> None:
        self._server = await asyncio.start_unix_server(
            self._handle, path=self.socket_path, limit=HEAD_LIMIT
        )

    async def close(self) -> None:
        if self._server is not None:
            self._server.close()
        for t in list(self._tasks):
            t.cancel()
        await asyncio.gather(*self._tasks, return_exceptions=True)
        if self._server is not None:
            with contextlib.suppress(Exception):
                await self._server.wait_closed()

    # --- shared ---------------------------------------------------------------------------

    async def _handle(self, reader: asyncio.StreamReader, writer: asyncio.StreamWriter) -> None:
        task = asyncio.current_task()
        assert task is not None
        self._tasks.add(task)
        self._connections += 1
        conn = _Conn(self._connections)
        try:
            first = await asyncio.wait_for(reader.readexactly(1), HEAD_TIMEOUT_S)
            if first == b"\x05":
                conn.protocol = "socks5"
                await self._socks5(conn, reader, writer)
            elif first == b"\x04":
                conn.protocol = "socks5"
                self._emit(conn, "malformed", "SOCKS4 is not supported")
            else:
                await self._http(conn, first, reader, writer)
        except asyncio.LimitOverrunError:  # a head without its end within HEAD_LIMIT
            self._emit(conn, "malformed", "message head too large")
        except OSError, asyncio.IncompleteReadError, TimeoutError:
            pass
        except Exception as e:
            # A bug, not a verdict on the input: say so rather than guess, and let asyncio
            # report the traceback.
            self._emit(conn, "failed", f"internal proxy error ({type(e).__name__})")
            raise
        finally:
            self._tasks.discard(task)
            writer.close()

    def _emit(
        self,
        conn: _Conn,
        decision: Outcome,
        reason: str,
        *,
        rule: str | None = None,
        status: int | None = None,
        credentials: list[str] | None = None,
    ) -> None:
        event = NetworkEvent(
            exec_id=self.exec_id,
            connection=conn.id,
            request=conn.request,
            protocol=conn.protocol,
            decision=decision,
            reason=reason,
            rule=rule,
            host=None if conn.host is None else sanitize(conn.host, 255),
            port=conn.port,
            method=sanitize(conn.method, 32) if conn.method else None,
            target=sanitize(conn.target, 500) if conn.target else None,
            status=status,
            credentials=credentials or None,
        )
        with contextlib.suppress(Exception):  # a failing event sink must not break the proxy
            self._on_event(event)

    def _refused(self, conn: _Conn, e: _Refused, *, http: bool = True) -> None:
        self._emit(conn, e.outcome, e.reason, rule=e.rule, status=e.status if http else None)

    async def _authorize(
        self, conn: _Conn, host: str, port: int, *, opaque: bool = False, log: bool = True
    ) -> _Route:
        """Decide and resolve, or raise _Refused. The route's rules are the `inspect` rules
        covering the host - empty unless it is inspected. `log`: emit the allow event here
        (connection-level decisions) rather than per request."""
        try:  # before DNS and the approval prompt see it
            self._placeholders.check_host(host)
        except CredentialRefused as e:
            conn.host, conn.port = host, port
            raise _Refused(403, e.reason, e.rule) from None
        d: Decision = await decide(
            host,
            port,
            exec_id=self.exec_id,
            hosts=self._hosts,
            extra_allowed=self._extra,
            approve=self._approve,
        )
        conn.host, conn.port = d.host, port
        if not d.allowed:
            raise _Refused(400 if d.malformed else 403, d.reason, d.rule)
        if d.inspect and opaque:  # a tunnel we cannot look into must not reach the host
            raise _Refused(403, "inspected host; use the HTTP proxy", d.rule)
        try:
            address = await self._guard.resolve(d.host, port)
        except AddressDenied as e:
            raise _Refused(403, e.reason) from None
        except OSError:
            raise _Refused(502, "did not resolve") from None
        if log:
            self._emit(conn, "allow", d.reason, rule=d.rule)
        rules = [r for r in self._hosts if r.access == "inspect" and r.covers(d.host, port)]
        return _Route(d.host, address, port, rules if d.inspect else [], False, d.reason, d.rule)

    async def _dial(self, address: str, port: int, *, tls_host: str | None = None):
        if tls_host is None:
            conn = asyncio.open_connection(address, port)
        else:
            assert self._upstream_tls is not None
            conn = asyncio.open_connection(
                address, port, ssl=self._upstream_tls, server_hostname=tls_host
            )
        return await asyncio.wait_for(conn, CONNECT_TIMEOUT_S)

    # --- HTTP -----------------------------------------------------------------------------
    #
    # Requests are never relayed as a byte stream: every message on a client connection is
    # parsed, routed, authorized and (for inspected hosts) vetted on its own, its body is
    # forwarded exactly as framed by Content-Length / chunked encoding, and the response is
    # framed the same way so the next request can be read from where this one ended. Each
    # request gets its own upstream connection (`Connection: close` upstream), so nothing a
    # client sends can ever reach a server outside a message the proxy has vetted.

    async def _http(
        self,
        conn: _Conn,
        first: bytes,
        reader: asyncio.StreamReader,
        writer: asyncio.StreamWriter,
    ) -> None:
        raw = first + await asyncio.wait_for(reader.readuntil(b"\r\n\r\n"), HEAD_TIMEOUT_S)
        conn.next_request(keep_host=False)
        try:
            head = _parse_head(raw)
            if head.method == "CONNECT":
                conn.protocol, conn.request = "connect", None
                await self._connect(conn, head.target, reader, writer)
                return
        except _Refused as e:
            self._refused(conn, e)
            await _refuse(writer, e)
            return
        await self._serve(conn, reader, writer, head, tunnel=None)

    async def _connect(
        self,
        conn: _Conn,
        target: str,
        reader: asyncio.StreamReader,
        writer: asyncio.StreamWriter,
    ) -> None:
        m = _AUTHORITY.match(target)
        if not m or not 0 < int(m.group(3)) < 65536 or not _bracketed_ok(m.group(1)):
            raise _Refused(400, "bad CONNECT target")
        host, port = m.group(1) or m.group(2), int(m.group(3))
        conn.host, conn.port = host, port
        route = await self._authorize(conn, host, port)
        if route.rules:
            await self._intercept(conn, dataclasses.replace(route, tls=True), reader, writer)
            return
        try:
            up_reader, up_writer = await self._dial(route.address, route.port)
        except OSError, TimeoutError:
            raise _Refused(502, "upstream connection failed") from None
        writer.write(b"HTTP/1.1 200 Connection Established\r\n\r\n")
        await _relay(reader, writer, up_reader, up_writer)

    async def _intercept(
        self,
        conn: _Conn,
        route: _Route,
        reader: asyncio.StreamReader,
        writer: asyncio.StreamWriter,
    ) -> None:
        """Terminate the tunnel's TLS with a minted certificate, then serve the requests
        inside it one by one, each vetted against the host's filters and re-encrypted
        upstream (verified against the real host)."""
        assert self._ca is not None
        writer.write(b"HTTP/1.1 200 Connection Established\r\n\r\n")
        await writer.drain()
        # Anything in the tunnel that is not TLS from a client trusting the session CA
        # (SSL_CERT_FILE et al.) fails here and the connection drops.
        ctx = self._ca.server_context(route.host)
        try:
            tls_reader, tls_writer = await asyncio.wait_for(_start_tls(writer, ctx), HEAD_TIMEOUT_S)
        except OSError, TimeoutError:  # typically: the client rejected our certificate
            self._emit(conn, "malformed", "client TLS handshake failed (does it trust the CA?)")
            return
        conn.protocol = "https"
        try:
            await self._serve(conn, tls_reader, tls_writer, None, tunnel=route)
        finally:
            tls_writer.close()  # before `_handle` closes the plain stream under it

    async def _serve(
        self,
        conn: _Conn,
        reader: asyncio.StreamReader,
        writer: asyncio.StreamWriter,
        head: _Head | None,
        *,
        tunnel: _Route | None,
    ) -> None:
        """Serve requests until the client is done. `tunnel` is the fixed route inside an
        intercepted CONNECT (origin-form requests); without it every request is an
        absolute-form proxy request, routed and authorized on its own. A refused request
        gets its error response and ends the connection."""
        routes: dict[tuple[str, int], _Route] = {}
        while True:
            try:
                if head is None:
                    conn.next_request(keep_host=tunnel is not None)
                    raw = await _next_head(reader)
                    if raw is None:
                        return
                    head = _parse_head(raw)
                keep = await self._exchange(conn, head, reader, writer, tunnel, routes)
            except _Refused as e:
                self._refused(conn, e)
                await _refuse(writer, e)
                return
            if not keep:
                return
            head = None

    async def _route(
        self, conn: _Conn, target: str, routes: dict[tuple[str, int], _Route]
    ) -> tuple[_Route, str]:
        """Route an absolute-form request; returns the route and the origin-form target.
        A host is authorized once per client connection."""
        try:
            url = urlsplit(target)  # raises on a broken authority such as `http://[`
        except ValueError:
            raise _Refused(400, "bad request URL") from None
        if url.scheme != "http" or not url.hostname:
            # origin-form, https:// (use CONNECT) and every other scheme
            raise _Refused(400, "only absolute http:// requests and CONNECT are supported")
        try:
            port = url.port or 80
        except ValueError:
            raise _Refused(400, "bad port") from None
        target = (url.path or "/") + (f"?{url.query}" if url.query else "")
        conn.host, conn.port, conn.target = url.hostname, port, target
        route = routes.get((url.hostname, port))
        if route is None:
            route = await self._authorize(conn, url.hostname, port, log=False)
            routes[(url.hostname, port)] = route
        return route, target

    async def _exchange(
        self,
        conn: _Conn,
        head: _Head,
        reader: asyncio.StreamReader,
        writer: asyncio.StreamWriter,
        tunnel: _Route | None,
        routes: dict[tuple[str, int], _Route],
    ) -> bool:
        """Vet one request, forward it with exactly its body and relay its response.
        Returns whether the client connection can carry another request."""
        conn.method, conn.target = head.method, head.target
        if head.method.upper() == "CONNECT":
            raise _Refused(400, "CONNECT must be the first request on a connection")
        body = _request_framing(head.headers)
        if tunnel is None:
            route, target = await self._route(conn, head.target, routes)
        elif head.target.startswith("/"):
            route, target = tunnel, head.target
        else:
            raise _Refused(400, "expected an origin-form request inside the tunnel")
        conn.host, conn.port, conn.target = route.host, route.port, target
        reason, rule, allowed_by = route.reason, route.rule, ()
        if route.rules:
            verdict = judge_request(route.rules, head.method, target)
            if not verdict.allowed:
                raise _Refused(403, verdict.reason, verdict.rule)
            reason, rule, allowed_by = verdict.reason, verdict.rule, verdict.allowed_by
        # Credentials go in only now, only those of the host entries that allow this very
        # request themselves (not of every entry covering the host), and only upstream
        # over verified TLS (an intercepted tunnel). Then any placeholder still in what is
        # about to be forwarded is one its credential was not used for.
        try:
            headers, used = self._credentials.apply(
                allowed_by, _end_to_end(head.headers), secure=route.tls
            )
            self._placeholders.check_request(target, headers)
        except CredentialRefused as e:
            raise _Refused(403, e.reason, e.rule) from None
        self._emit(conn, "allow", reason, rule=rule, credentials=used)
        try:
            up_reader, up_writer = await self._dial(
                route.address, route.port, tls_host=route.host if route.tls else None
            )
        except ssl.SSLError:
            raise _Refused(502, "upstream TLS handshake failed") from None
        except OSError, TimeoutError:
            raise _Refused(502, "upstream connection failed") from None
        up_writer.write(_outbound_head(head, headers, target, route))
        # The body goes up while the response comes down (`Expect: 100-continue` needs
        # both at once). A refused upload (a malformed body, a placeholder in it) stops
        # short and closes the upstream, so the request is never complete there, and ends
        # the response; the client then gets the refusal, unless a response is under way.
        scan = self._placeholders.body() if self._placeholders else None
        upload = asyncio.create_task(_upload(reader, up_writer, body, scan))
        upload.add_done_callback(lambda t: t.cancelled() or t.exception())
        responding = asyncio.Event()
        answered = False
        try:
            keep = await _relay_response(up_reader, writer, head, responding)
        except ConnectionAbortedError as e:  # the response broke after its head went out
            self._emit(conn, "failed", str(e))
            raise
        except OSError, asyncio.IncompleteReadError, _Refused:
            refusal = _refusal_of(upload)
            if refusal is None or responding.is_set():
                raise
            answered = True  # `_serve` reports it and answers the client
            raise refusal from None
        finally:
            failure = upload.exception() if upload.done() and not upload.cancelled() else None
            uploaded = upload.done() and not upload.cancelled() and failure is None
            upload.cancel()
            up_writer.close()
            if isinstance(failure, _Refused) and not answered:
                self._refused(conn, failure)
        # If the body was not read to its end we cannot know where the next request starts.
        return keep and uploaded

    # --- SOCKS5 ---------------------------------------------------------------------------

    async def _socks5(
        self, conn: _Conn, reader: asyncio.StreamReader, writer: asyncio.StreamWriter
    ) -> None:
        (n,) = await reader.readexactly(1)
        methods = await reader.readexactly(n)
        if 0 not in methods:
            self._emit(conn, "malformed", "no acceptable SOCKS auth method")
            writer.write(b"\x05\xff")
            return
        writer.write(b"\x05\x00")
        ver, cmd, _, atyp = await asyncio.wait_for(reader.readexactly(4), HEAD_TIMEOUT_S)
        if ver != 5:
            self._emit(conn, "malformed", "bad SOCKS version")
            return
        if atyp == 1:
            host = ".".join(str(b) for b in await reader.readexactly(4))
        elif atyp == 3:
            (ln,) = await reader.readexactly(1)
            host = (await reader.readexactly(ln)).decode("ascii", "replace")
        elif atyp == 4:
            raw = await reader.readexactly(16)
            host = ":".join(raw[i : i + 2].hex() for i in range(0, 16, 2))
        else:
            self._emit(conn, "malformed", "unsupported SOCKS address type")
            writer.write(_socks_reply(8))
            return
        port = int.from_bytes(await reader.readexactly(2))
        conn.host, conn.port = host, port
        if cmd != 1:  # CONNECT only; no BIND / UDP ASSOCIATE
            self._emit(conn, "malformed", "unsupported SOCKS command")
            writer.write(_socks_reply(7))
            return
        try:
            route = await self._authorize(conn, host, port, opaque=True)
        except _Refused as e:
            self._refused(conn, e, http=False)
            writer.write(_socks_reply({403: 2, 400: 1}.get(e.status, 4)))
            return
        try:
            up_reader, up_writer = await self._dial(route.address, port)
        except ConnectionRefusedError:
            self._emit(conn, "failed", "upstream refused the connection")
            writer.write(_socks_reply(5))
            return
        except OSError, TimeoutError:
            self._emit(conn, "failed", "upstream connection failed")
            writer.write(_socks_reply(4))
            return
        writer.write(_socks_reply(0))
        await _relay(reader, writer, up_reader, up_writer)


# --- HTTP/1.1 messages ---------------------------------------------------------------------

_CHUNK_SIZE = re.compile(rb"^[0-9A-Fa-f]{1,16}(?:;[^\r\n]*)?\r\n$")
_DIGITS = re.compile(r"^[0-9]{1,18}$")
CHUNKED = -1
UNTIL_CLOSE = -2
"""Body framings besides a byte count."""


@dataclass(frozen=True)
class _Head:
    method: str
    target: str
    version: str
    headers: list[tuple[str, str]]


@dataclass(frozen=True)
class _Route:
    host: str
    """Canonical."""
    address: str
    """Vetted address to dial."""
    port: int
    rules: list[HostRule]
    """The `inspect` rules covering the host; empty when its requests are not vetted."""
    tls: bool
    """Upstream speaks TLS (an intercepted CONNECT)."""
    reason: str
    """Why the host was allowed (`tunnel`, `inspect`, `exec allow list`, `approved`)."""
    rule: str | None
    """The entry that allowed it."""


def _parse_fields(lines: list[str], status: int) -> list[tuple[str, str]]:
    headers: list[tuple[str, str]] = []
    for line in lines:
        if not line:
            continue
        name, sep, value = line.partition(":")
        if not sep or not _TOKEN.match(name):  # also refuses obsolete line folding
            raise _Refused(status, "bad header")
        if any(c in value for c in "\r\n\0"):
            raise _Refused(status, "bad header")
        headers.append((name, value.strip()))
    return headers


def _parse_head(raw: bytes) -> _Head:
    lines = raw.lstrip(b"\r\n").decode("latin-1").split("\r\n")
    parts = lines[0].split(" ")
    if len(parts) != 3 or not _TOKEN.match(parts[0]) or parts[2] not in ("HTTP/1.0", "HTTP/1.1"):
        raise _Refused(400, "bad request line")
    return _Head(parts[0], parts[1], parts[2], _parse_fields(lines[1:], 400))


def _values(headers: list[tuple[str, str]], name: str) -> list[str]:
    return [v.strip() for n, v in headers if n.lower() == name]


def _tokens(headers: list[tuple[str, str]], name: str) -> set[str]:
    return {t.strip().lower() for v in _values(headers, name) for t in v.split(",") if t.strip()}


def _body_framing(headers: list[tuple[str, str]], status: int) -> int | None:
    """CHUNKED, a byte count, or None when the message declares no body length."""
    cl = set(_values(headers, "content-length"))
    te = [v.lower() for v in _values(headers, "transfer-encoding")]
    if (te and cl) or len(cl) > 1:
        raise _Refused(status, "ambiguous message framing")
    if te:
        if te != ["chunked"]:
            raise _Refused(status, "unsupported transfer-encoding")
        return CHUNKED
    if cl:
        (value,) = cl
        if not _DIGITS.match(value):
            raise _Refused(status, "bad content-length")
        return int(value)
    return None


def _request_framing(headers: list[tuple[str, str]]) -> int:
    framing = _body_framing(headers, 400)
    return 0 if framing is None else framing  # a request without a length has no body


def _end_to_end(headers: list[tuple[str, str]]) -> list[tuple[str, str]]:
    """The request headers to forward: hop-by-hop ones (including those the client lists
    in `Connection`) and Host are dropped."""
    listed = _tokens(headers, "connection")
    return [
        (n, v)
        for n, v in headers
        if (ln := n.lower()) not in _HOP_BY_HOP and ln not in listed and ln != "host"
    ]


def _outbound_head(
    head: _Head, headers: list[tuple[str, str]], target: str, route: _Route
) -> bytes:
    """The rewritten request head with `headers` (`_end_to_end`, credentials applied):
    canonical Host, one request per upstream connection (`Connection: close`)."""
    authority = f"[{route.host}]" if ":" in route.host else route.host
    if route.port != (443 if route.tls else 80):
        authority += f":{route.port}"
    out = [f"{head.method} {target} {head.version}", f"Host: {authority}"]
    out += [f"{n}: {v}" for n, v in headers]
    out.append("Connection: close")
    return ("\r\n".join(out) + "\r\n\r\n").encode("latin-1")


async def _next_head(reader: asyncio.StreamReader) -> bytes | None:
    """The next request head on a kept-alive connection, or None once the client is done
    (clean close between requests, or idle past HEAD_TIMEOUT_S)."""
    try:
        return await asyncio.wait_for(reader.readuntil(b"\r\n\r\n"), HEAD_TIMEOUT_S)
    except asyncio.IncompleteReadError as e:
        if e.partial.strip():
            raise
        return None
    except TimeoutError:
        return None


def _refusal_of(upload: asyncio.Task[None]) -> _Refused | None:
    """The refusal an upload ended with, if it did."""
    if not upload.done() or upload.cancelled():
        return None
    failure = upload.exception()
    return failure if isinstance(failure, _Refused) else None


async def _copy_exact(
    src: asyncio.StreamReader, dst: asyncio.StreamWriter, n: int, scan: BodyScan | None = None
) -> None:
    while n > 0:
        data = await src.read(min(n, 65536))
        if not data:
            raise asyncio.IncompleteReadError(b"", n)
        if scan is not None:
            scan.payload(data)  # before it is forwarded
        dst.write(data)
        await dst.drain()
        n -= len(data)


async def _copy_chunked(
    src: asyncio.StreamReader, dst: asyncio.StreamWriter, status: int, scan: BodyScan | None
) -> None:
    """Relay a chunked body verbatim, stopping exactly after its last chunk and trailers."""
    while True:
        try:
            line = await src.readuntil(b"\r\n")
        except asyncio.LimitOverrunError, ValueError:
            raise _Refused(status, "bad chunk") from None
        if not _CHUNK_SIZE.match(line):
            raise _Refused(status, "bad chunk")
        size = int(line.split(b";", 1)[0].rstrip(b"\r\n"), 16)
        if scan is not None:
            scan.line(line)  # chunk extensions
        dst.write(line)
        if size == 0:
            while (trailer := await src.readuntil(b"\r\n")) != b"\r\n":
                if scan is not None:
                    scan.line(trailer)
                dst.write(trailer)
            dst.write(b"\r\n")
            await dst.drain()
            return
        await _copy_exact(src, dst, size, scan)
        if await src.readexactly(2) != b"\r\n":
            raise _Refused(status, "bad chunk")
        dst.write(b"\r\n")


async def _copy_body(
    src: asyncio.StreamReader,
    dst: asyncio.StreamWriter,
    framing: int,
    status: int,
    scan: BodyScan | None = None,
) -> None:
    """`scan`: look for placeholders in a request body (UNTIL_CLOSE is responses only)."""
    if framing == CHUNKED:
        await _copy_chunked(src, dst, status, scan)
    elif framing == UNTIL_CLOSE:
        while data := await src.read(65536):
            dst.write(data)
            await dst.drain()
    else:
        await _copy_exact(src, dst, framing, scan)
    await dst.drain()


async def _upload(
    reader: asyncio.StreamReader,
    up_writer: asyncio.StreamWriter,
    framing: int,
    scan: BodyScan | None,
) -> None:
    try:
        await _copy_body(reader, up_writer, framing, 400, scan)
    except CredentialRefused as e:
        up_writer.close()  # mid-body: the upstream never gets a complete request
        raise _Refused(403, e.reason, e.rule) from None
    except BaseException:
        up_writer.close()  # the upstream then ends its response instead of waiting
        raise


async def _relay_response(
    up_reader: asyncio.StreamReader,
    writer: asyncio.StreamWriter,
    request: _Head,
    responding: asyncio.Event,
) -> bool:
    """Relay interim responses and the final response, framed; returns whether the client
    connection can carry another request. `responding` is set once the final response
    head is on its way to the client (no other answer can be given after that)."""
    while True:
        try:
            raw = await up_reader.readuntil(b"\r\n\r\n")
        except asyncio.LimitOverrunError, ValueError:
            raise _Refused(502, "upstream response head too large") from None
        lines = raw.decode("latin-1").split("\r\n")
        parts = lines[0].split(" ", 2)
        if len(parts) < 2 or not parts[0].startswith("HTTP/1.") or not _DIGITS.match(parts[1]):
            raise _Refused(502, "bad upstream response")
        status = int(parts[1])
        if status == 101:  # Upgrade is hop-by-hop and never forwarded, so never asked for
            raise _Refused(502, "unexpected protocol switch")
        if status >= 200:
            break
        writer.write(raw)  # 100 Continue, 103 Early Hints, ...
        await writer.drain()
    headers = _parse_fields(lines[1:], 502)
    if request.method.upper() == "HEAD" or status in (204, 304):
        framing = 0
    else:
        declared = _body_framing(headers, 502)
        framing = UNTIL_CLOSE if declared is None else declared
    keep = (
        framing != UNTIL_CLOSE
        and request.version == "HTTP/1.1"
        and "close" not in _tokens(request.headers, "connection")
    )
    listed = _tokens(headers, "connection")
    out = [lines[0]]
    for n, v in headers:
        ln = n.lower()
        if ln not in _HOP_BY_HOP and ln not in listed:
            out.append(f"{n}: {v}")
    if not keep:
        out.append("Connection: close")
    responding.set()
    writer.write(("\r\n".join(out) + "\r\n\r\n").encode("latin-1"))
    try:
        await _copy_body(up_reader, writer, framing, 502)
    except _Refused as e:  # the head is out: an error response would corrupt the stream
        raise ConnectionAbortedError(e.reason) from None
    return keep


async def _start_tls(
    writer: asyncio.StreamWriter, ctx: ssl.SSLContext
) -> tuple[asyncio.StreamReader, asyncio.StreamWriter]:
    """Upgrade a client connection to TLS (server side), returning a fresh stream pair
    over the TLS transport. The plain `writer` must stay referenced until the TLS one is
    closed: a collected StreamWriter closes its transport.

    Not `StreamWriter.start_tls()`: application data that arrives with the end of the
    handshake is decrypted and handed to the stream's reader while that reader still holds
    the plain transport. If it is enough to fill the reader (a large upload following the
    ClientHello), the reader pauses the *plain* transport and later resumes the TLS one, so
    the socket stays paused and the upload stalls for good (seen on Unix sockets, CPython
    3.14). A fresh reader has no transport until the handshake is done, so it cannot pause
    the wrong one."""
    loop = asyncio.get_running_loop()
    reader = asyncio.StreamReader(limit=HEAD_LIMIT, loop=loop)
    protocol = asyncio.StreamReaderProtocol(reader, loop=loop)
    await writer.drain()
    transport = await loop.start_tls(writer.transport, protocol, ctx, server_side=True)
    if transport is None:  # the connection went away during the handshake
        raise ConnectionResetError("closed during the TLS handshake")
    protocol.connection_made(transport)  # start_tls() leaves that to the caller
    return reader, asyncio.StreamWriter(transport, protocol, reader, loop)


async def _refuse(writer: asyncio.StreamWriter, e: _Refused) -> None:
    writer.write(_refusal(e.status, e.reason))
    with contextlib.suppress(OSError):
        await writer.drain()


def _refusal(status: int, reason: str) -> bytes:
    phrase = sanitize(reason, 200) or "Forbidden"
    body = b"Connection blocked by network allowlist\n" if status == 403 else b""
    tag = b"X-Proxy-Error: blocked-by-sandbox\r\n" if status == 403 else b""
    return (
        f"HTTP/1.1 {status} {phrase}\r\nContent-Type: text/plain\r\n".encode("ascii")
        + tag
        + f"Content-Length: {len(body)}\r\nConnection: close\r\n\r\n".encode("ascii")
        + body
    )


def _bracketed_ok(host: str | None) -> bool:
    """`[...]` in an authority must hold an IPv6 address (None: no brackets used)."""
    if host is None:
        return True
    try:
        ipaddress.IPv6Address(host)
    except ValueError:
        return False
    return True


def _socks_reply(code: int) -> bytes:
    return bytes([5, code, 0, 1, 0, 0, 0, 0, 0, 0])


async def _pipe(reader: asyncio.StreamReader, writer: asyncio.StreamWriter) -> None:
    try:
        while data := await reader.read(65536):
            writer.write(data)
            await writer.drain()
        if writer.can_write_eof():
            writer.write_eof()
        else:
            writer.close()  # TLS cannot half-close
    except OSError:
        pass


async def _relay(
    reader: asyncio.StreamReader,
    writer: asyncio.StreamWriter,
    up_reader: asyncio.StreamReader,
    up_writer: asyncio.StreamWriter,
) -> None:
    try:
        await asyncio.gather(_pipe(reader, up_writer), _pipe(up_reader, writer))
    finally:
        up_writer.close()
