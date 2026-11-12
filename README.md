# agent-sandbox

Run untrusted commands as OS-level sandboxed ("bubble-wrapped") processes.

- **Platforms:** Linux or WSL2 only, with `bwrap` >= 0.5 (`sudo apt-get install bubblewrap`)
  and unprivileged user namespaces. Elsewhere `check_host()` reports the problems and
  `Sandbox.start()` raises `SandboxUnavailable`.
- **Dependencies:** Python 3.14+, stdlib + Pydantic.

## Usage

```python
from pathlib import Path
from sandbox import FilesystemPolicy, NetworkPolicy, Sandbox, SandboxPolicy

policy = SandboxPolicy(
    filesystem=FilesystemPolicy(
        deny_read=[str(Path.home())],     # absolute, literal paths (no globs)
        allow_write=["/work/project"],
    ),
    network=NetworkPolicy(allowed_domains=["pypi.org", "*.pythonhosted.org"]),
    env={"HOME": "/tmp", "PATH": "/usr/bin:/bin"},  # nothing is inherited from the host
)

async with Sandbox(policy, session_dir=Path("/tmp/my-session")) as sbx:
    result = await sbx.exec(["python3", "-c", "print('hi')"], cwd="/work/project")
    print(result.exit_code, result.stdout, result.violations)
```

`Sandbox(..., approve=callback)` takes an optional async approval callback that is asked
about domains not covered by the allow/deny lists (default: deny). `check_host(policy)`
returns the reasons the sandbox cannot run on this host.

## Manual testing

```sh
uv run sandbox -- sh -c 'cat ~/.ssh/id_rsa; curl -sI https://example.com'
```

## Development

```sh
uv sync
uv run pytest          # tests/test_integration.py is skipped where bubblewrap is missing
uv run ruff check
uv run ruff format --check
uv run pyright
```
