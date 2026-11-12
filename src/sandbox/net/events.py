"""Structured network events: one per proxy decision, the audit trail of an exec's network.

Every decision the proxy takes produces exactly one event: a connection or SOCKS tunnel
being allowed or refused, every HTTP request on a connection (each is decided on its own),
malformed or unsupported input, and requests that were allowed but could not be completed.
`connection` and `request` correlate events: an intercepted CONNECT and the requests inside
it share a connection number, and requests count up from 1 within their connection.
"""

from datetime import UTC, datetime
from typing import Literal

from pydantic import BaseModel, Field

type Protocol = Literal["http", "https", "connect", "socks5"]
type Outcome = Literal["allow", "deny", "malformed", "failed"]


class NetworkEvent(BaseModel):
    time: datetime = Field(default_factory=lambda: datetime.now(UTC))
    exec_id: str
    connection: int
    """Client connection to the proxy, numbered from 1 per exec."""
    request: int | None = None
    """HTTP request within the connection, from 1; None for connection-level decisions
    (CONNECT, SOCKS) and for input that never became a request."""
    protocol: Protocol
    """`http`: absolute-form proxy request; `https`: a request inside an intercepted
    tunnel; `connect` / `socks5`: a tunnel."""
    decision: Outcome
    """`allow`: forwarded. `deny`: refused by policy (or the resolved-address guard).
    `malformed`: unparseable or unsupported input (including invalid host names and URLs).
    `failed`: allowed, but DNS or the upstream failed - or the proxy itself hit an internal
    error (`internal proxy error (<exception>)`), which is a bug to report."""
    reason: str
    rule: str | None = None
    """The policy entry that decided: a host entry (`api.github.com`), an inspect filter
    (`api.github.com: deny DELETE /**`), an exec allow (`exec: pypi.org`)."""
    host: str | None = None
    """Canonical host when known."""
    port: int | None = None
    method: str | None = None
    target: str | None = None
    """Origin-form request target (path and query), truncated."""
    status: int | None = None
    """HTTP status the proxy answered a refusal with."""

    @property
    def violation(self) -> bool:
        return self.decision in ("deny", "malformed")

    def summary(self) -> str:
        """One line: `deny https api.github.com:443 (no allow filter matches: GET /x)`."""
        where = f" {self.host}:{self.port}" if self.host is not None else ""
        what = f": {self.method} {self.target}" if self.method and self.target else ""
        rule = f" [{self.rule}]" if self.rule else ""
        return f"{self.decision} {self.protocol}{where} ({self.reason}{what}){rule}"


__all__ = ["NetworkEvent", "Outcome", "Protocol"]
