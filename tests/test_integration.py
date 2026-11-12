"""Escape probes against a real sandbox: each attack must fail. Needs bwrap and python3."""

import asyncio
import os
import shutil
import sys
from collections.abc import AsyncIterator
from pathlib import Path

import pytest

from sandbox import (
    FilesystemPolicy,
    HostAccess,
    NetworkPolicy,
    RequestFilter,
    Sandbox,
    SandboxPolicy,
)
from sandbox.net.events import NetworkEvent
from sandbox.net.mitm import CertificateAuthority
from sandbox.policy import ResourceLimits

pytestmark = pytest.mark.skipif(
    not sys.platform.startswith("linux")
    or not shutil.which("bwrap")
    or not shutil.which("python3"),
    reason="needs Linux with bubblewrap and python3",
)


@pytest.fixture
def dirs(tmp_path: Path) -> dict[str, Path]:
    d = {name: tmp_path / name for name in ("ws", "secret", "session", "outside")}
    for p in d.values():
        p.mkdir()
    (d["secret"] / "id_rsa").write_text("PRIVATE")
    (d["ws"] / ".git" / "objects").mkdir(parents=True)
    return d


@pytest.fixture
async def upstream() -> AsyncIterator[int]:
    async def handle(r: asyncio.StreamReader, w: asyncio.StreamWriter) -> None:
        await r.read(4096)
        w.write(b"HTTP/1.1 200 OK\r\nContent-Length: 2\r\nConnection: close\r\n\r\nok")
        await w.drain()
        w.close()

    server = await asyncio.start_server(handle, "127.0.0.1", 0)
    yield server.sockets[0].getsockname()[1]
    server.close()


def make(dirs: dict[str, Path], tunnel: list[str] = []) -> Sandbox:  # noqa: B006
    policy = SandboxPolicy(
        filesystem=FilesystemPolicy(deny_read=[str(dirs["secret"])], allow_write=[str(dirs["ws"])]),
        network=NetworkPolicy(hosts={h: HostAccess(access="tunnel") for h in tunnel}),
        limits=ResourceLimits(max_output_bytes=4096),
        env={"HOME": str(dirs["ws"])},
    )
    return Sandbox(policy, dirs["session"])


async def sh(sb: Sandbox, script: str, **kw):
    return await sb.exec(["sh", "-c", script], **kw)


async def py(sb: Sandbox, code: str, **kw):
    return await sb.exec(["python3", "-c", code], **kw)


async def test_basics(dirs: dict[str, Path]) -> None:
    async with make(dirs) as sb:
        r = await sh(sb, "pwd; cat; echo err >&2; exit 7", stdin=b"in\n")
        assert (r.exit_code, r.stdout, r.stderr) == (7, f"{dirs['ws']}\nin\n", "err\n")
        assert not r.timed_out and not r.violations
        r = await sh(sb, "echo hi > f.txt && env | sort")
        assert (dirs["ws"] / "f.txt").read_text() == "hi\n"
        assert f"HOME={dirs['ws']}" in r.stdout and "HTTPS_PROXY=http://127.0.0.1:3128" in r.stdout
        assert "USER=" not in r.stdout  # nothing inherited from the host
        r = await sb.exec(["no-such-binary"])
        assert r.exit_code == 127


async def test_filesystem_escapes(dirs: dict[str, Path]) -> None:
    async with make(dirs) as sb:
        r = await sh(sb, f"cat {dirs['secret']}/id_rsa; ls -A {dirs['secret']}")
        assert "PRIVATE" not in r.stdout and r.stdout.strip() == ""
        r = await sh(sb, "echo x > /usr/sandbox-escape")
        assert r.exit_code != 0 and r.violations[0].kind == "filesystem"
        await sh(sb, f"echo x > {dirs['outside']}/f")  # /tmp is a private tmpfs inside
        assert not (dirs["outside"] / "f").exists()
        r = await sh(sb, "mkdir -p .git/hooks; echo evil > .git/hooks/pre-commit; echo $?")
        assert r.stdout.strip() != "0"
        r = await sh(sb, "mv .git moved && echo moved")
        assert "moved" not in r.stdout  # pinned: EBUSY
        r = await sh(sb, "echo evil >> .bashrc || echo no-rc; mkdir .vscode || echo no-vscode")
        assert r.stdout.split() == ["no-rc", "no-vscode"]
    # placeholders are gone after the exec, the host tree is unchanged
    assert sorted(p.name for p in dirs["ws"].iterdir()) == [".git"]
    assert sorted(p.name for p in (dirs["ws"] / ".git").iterdir()) == ["objects"]


async def test_kernel_escapes(dirs: dict[str, Path]) -> None:
    async with make(dirs) as sb:
        r = await py(sb, "import socket; socket.socket(socket.AF_UNIX)")
        assert "Operation not permitted" in r.stderr
        assert any(v.kind == "unix_socket" for v in r.violations)
        r = await py(sb, "import os; os.unshare(os.CLONE_NEWUSER)")
        assert "Operation not permitted" in r.stderr
        r = await sh(sb, "unshare -rm true || echo blocked")
        assert "blocked" in r.stdout
        r = await py(sb, "import socket; a, b = socket.socketpair(); print('pair ok')")
        assert r.stdout == "pair ok\n"
        # only the command's own pid namespace is visible, and its init is out of reach
        r = await sh(sb, "ls /proc | grep -c '^[0-9]'; cat /proc/1/environ >/dev/null && echo leak")
        lines = r.stdout.split()
        assert int(lines[0]) <= 5 and "leak" not in lines


async def test_network(dirs: dict[str, Path], upstream: int) -> None:
    allowed = [f"127.0.0.1:{upstream}"]
    async with make(dirs, tunnel=allowed) as sb:
        fetch = (
            "import urllib.request as u, sys; "
            "print(u.urlopen(sys.argv[1], timeout=10).read().decode())"
        )
        env = {"NO_PROXY": "", "no_proxy": ""}
        r = await sb.exec(["python3", "-c", fetch, f"http://127.0.0.1:{upstream}/"], env=env)
        assert r.stdout == "ok\n", r.stderr
        r = await sb.exec(["python3", "-c", fetch, "http://example.com/"], env=env)
        assert "403" in r.stderr
        assert r.violations[0].detail == "deny http example.com:80 (host is not allowed: GET /)"
        r = await sb.exec(
            ["python3", "-c", fetch, "http://example.com/"],
            env=env,
            extra_allowed_domains=["example.org"],
        )
        assert r.violations
        # bypassing the proxy: there is no route out of the network namespace
        r = await py(sb, "import socket; socket.create_connection(('1.1.1.1', 80), timeout=3)")
        assert r.exit_code != 0 and "unreachable" in r.stderr.lower()


async def test_limits(dirs: dict[str, Path]) -> None:
    async with make(dirs) as sb:
        r = await sh(sb, "sleep 30", timeout_s=1)
        assert r.timed_out and r.duration_s < 10
        # stdin larger than the pipe buffer, never read: the deadline still applies
        r = await sh(sb, "sleep 30", stdin=b"x" * (4 << 20), timeout_s=1)
        assert r.timed_out and r.duration_s < 10
        r = await sh(sb, "yes | head -c 100000")
        assert r.truncated and len(r.stdout) < 5000 and "bytes omitted" in r.stdout
        r = await sh(sb, "kill -TERM $$")
        assert r.exit_code == 128 + 15


async def test_parallel_execs(dirs: dict[str, Path]) -> None:
    async with make(dirs) as sb:
        results = await asyncio.gather(*(sh(sb, f"echo {i}") for i in range(6)))
        assert [r.stdout for r in results] == [f"{i}\n" for i in range(6)]
    assert not os.listdir(dirs["session"] / "sock")


@pytest.fixture
async def tls_upstream(tmp_path: Path) -> AsyncIterator[tuple[int, CertificateAuthority]]:
    ca = CertificateAuthority(tmp_path / "upstream-ca")

    async def handle(r: asyncio.StreamReader, w: asyncio.StreamWriter) -> None:
        head = await r.readuntil(b"\r\n\r\n")
        body = b"ok" if head.startswith(b"GET /ok/") else b"??"
        w.write(b"HTTP/1.1 200 OK\r\nContent-Length: 2\r\nConnection: close\r\n\r\n" + body)
        await w.drain()
        w.close()

    server = await asyncio.start_server(handle, "127.0.0.1", 0, ssl=ca.server_context("127.0.0.1"))
    yield server.sockets[0].getsockname()[1], ca
    server.close()


async def test_request_rules(
    dirs: dict[str, Path], tls_upstream: tuple[int, CertificateAuthority]
) -> None:
    port, upstream_ca = tls_upstream
    policy = SandboxPolicy(
        filesystem=FilesystemPolicy(allow_write=[str(dirs["ws"])]),
        network=NetworkPolicy(
            hosts={
                f"127.0.0.1:{port}": HostAccess(
                    access="inspect",
                    allow=[RequestFilter(methods=["GET", "POST"], path="/ok/**")],
                    deny=[RequestFilter(methods=["POST"])],
                )
            }
        ),
        limits=ResourceLimits(max_output_bytes=4096),
        env={"HOME": str(dirs["ws"])},
    )
    env = {"NO_PROXY": "", "no_proxy": ""}
    fetch = (
        "import urllib.request as u, sys; print(u.urlopen(sys.argv[1], timeout=10).read().decode())"
    )
    async with Sandbox(policy, dirs["session"]) as sb:
        assert sb._upstream_tls is not None
        sb._upstream_tls.load_verify_locations(cadata=upstream_ca.ca_pem.decode())
        url = f"https://127.0.0.1:{port}"
        r = await sb.exec(["python3", "-c", fetch, f"{url}/ok/data"], env=env)
        assert r.stdout == "ok\n", r.stderr  # intercepted, vetted, re-encrypted upstream
        assert not r.violations
        r = await sb.exec(["python3", "-c", fetch, f"{url}/admin"], env=env)
        assert "403" in r.stderr and r.stdout == ""
        assert r.violations[0].detail == (
            f"deny https 127.0.0.1:{port} (no allow filter matches: GET /admin)"
        )
        post = "import urllib.request as u, sys; u.urlopen(sys.argv[1], data=b'x', timeout=10)"
        r = await sb.exec(["python3", "-c", post, f"{url}/ok/data"], env=env)
        assert "403" in r.stderr and "request matches a deny filter" in r.violations[0].detail
        # a client that refuses the interception certificate gets nothing, leaks nothing
        r = await sb.exec(
            ["python3", "-c", fetch, f"{url}/ok/data"],
            env={**env, "SSL_CERT_FILE": "/dev/null"},
        )
        assert "CERTIFICATE_VERIFY_FAILED" in r.stderr and r.stdout == ""


async def test_network_audit_log(dirs: dict[str, Path], upstream: int) -> None:
    log = dirs["ws"] / "audit" / "network.jsonl"  # worst case: inside the writable workspace
    policy = SandboxPolicy(
        filesystem=FilesystemPolicy(allow_write=[str(dirs["ws"])]),
        network=NetworkPolicy(hosts={f"127.0.0.1:{upstream}": HostAccess(access="tunnel")}),
        env={"HOME": str(dirs["ws"])},
    )
    probe = (
        "import socket, urllib.request as u, sys\n"
        "print(u.urlopen(sys.argv[1], timeout=10).read().decode())\n"
        "s = socket.create_connection(('127.0.0.1', 3128)); s.sendall(b'NONSENSE\\r\\n\\r\\n')\n"
        "print(s.recv(100).split(b'\\r\\n')[0].decode())\n"
    )
    env = {"NO_PROXY": "", "no_proxy": ""}
    async with Sandbox(policy, dirs["session"], event_log=log) as sb:
        r = await sb.exec(["python3", "-c", probe, f"http://127.0.0.1:{upstream}/ok"], env=env)
        assert r.stdout == "ok\nHTTP/1.1 400 bad request line\n", r.stderr
        hide = await sb.exec(["sh", "-c", f"cat {log}; echo x >> {log} || echo ro; rm {log}"])
    assert hide.stdout == "ro\n"  # the sandbox sees an empty, read-only, undeletable file
    lines = [NetworkEvent.model_validate_json(line) for line in log.read_text().splitlines()]
    assert lines == r.network_events  # the log has exactly what the result reported
    assert [(e.decision, e.protocol, e.reason, e.target) for e in lines] == [
        ("allow", "http", "tunnel", "/ok"),
        ("malformed", "http", "bad request line", None),
    ]
    assert {e.exec_id for e in lines} == {r.network_events[0].exec_id}
    assert lines[0].connection != lines[1].connection
    assert [v.detail for v in r.violations] == ["malformed http (bad request line)"]
