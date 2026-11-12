import io

from sandbox.net.events import NetworkEvent
from sandbox.runtime import MAX_EXEC_EVENTS, _EventSink


def event(decision: str = "allow", **kw) -> NetworkEvent:
    return NetworkEvent.model_validate(
        {"exec_id": "e1", "connection": 1, "protocol": "https", "decision": decision, "reason": "r"}
        | kw
    )


def test_summary_and_violation() -> None:
    e = event(
        "deny",
        reason="request matches a deny filter",
        host="api.github.com",
        port=443,
        method="DELETE",
        target="/repos/x",
        rule="api.github.com: deny DELETE /**",
        status=403,
    )
    assert e.summary() == (
        "deny https api.github.com:443 (request matches a deny filter: DELETE /repos/x)"
        " [api.github.com: deny DELETE /**]"
    )
    assert e.violation and event("malformed").violation
    assert not event("allow").violation and not event("failed").violation
    assert event("malformed", protocol="socks5", reason="bad SOCKS version").summary() == (
        "malformed socks5 (bad SOCKS version)"
    )


def test_sink_caps_the_result_but_logs_everything() -> None:
    log = io.StringIO()
    sink = _EventSink(log)
    for i in range(MAX_EXEC_EVENTS + 5):
        sink(event("deny" if i % 2 else "allow", request=i))
    assert len(sink.events) == MAX_EXEC_EVENTS and sink.dropped == 5
    assert len(sink.violations) == (MAX_EXEC_EVENTS + 5) // 2  # under the cap: all kept
    lines = log.getvalue().splitlines()
    assert len(lines) == MAX_EXEC_EVENTS + 5
    last = NetworkEvent.model_validate_json(lines[-1])
    assert (last.request, last.decision) == (MAX_EXEC_EVENTS + 4, "allow")


def test_event_json_round_trip() -> None:
    e = event("failed", host="x.com", port=80, status=502)
    assert NetworkEvent.model_validate_json(e.model_dump_json()) == e
