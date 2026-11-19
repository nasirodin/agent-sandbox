import base64
import json

import pytest
from pydantic import BaseModel, SecretStr, ValidationError

from sandbox import (
    Credential,
    CredentialError,
    HostAccess,
    NetworkPolicy,
    RequestFilter,
    SandboxPolicy,
)
from sandbox.net.credentials import Credential as Compiled
from sandbox.net.credentials import (
    CredentialRefused,
    Credentials,
    PlaceholderScan,
    apply_credentials,
    check_env,
)
from sandbox.net.filter import judge_request, parse_host_rule, parse_request_filter

SECRET = "ghp_realsecret123"
PLACEHOLDER = "SANDBOX_PLACEHOLDER_TOKEN"


def placeholder(header: str = "Authorization", ph: str = PLACEHOLDER, secret: str = SECRET):
    return Compiled(header, secret, placeholder=ph, source=f"api.x.com: {header} ({ph})")


def inject(header: str = "Authorization", value: str = "Bearer {secret}", secret: str = SECRET):
    return Compiled(header, secret, inject=value, source=f"api.x.com: {header}")


def basic(user: str, password: str) -> str:
    return "Basic " + base64.b64encode(f"{user}:{password}".encode()).decode()


# --- applying credentials ----------------------------------------------------------------


def test_placeholder_is_replaced_in_its_header_only() -> None:
    headers = [
        ("Authorization", f"Bearer {PLACEHOLDER}"),
        ("X-Echo", PLACEHOLDER),  # another header: left alone
        ("Accept", "*/*"),
    ]
    out, used = apply_credentials([placeholder()], headers, secure=True)
    assert out == [
        ("Authorization", f"Bearer {SECRET}"),
        ("X-Echo", PLACEHOLDER),
        ("Accept", "*/*"),
    ]
    assert used == [f"api.x.com: Authorization ({PLACEHOLDER})"]


def test_header_names_match_case_insensitively() -> None:
    out, _ = apply_credentials([placeholder()], [("authorization", PLACEHOLDER)], secure=True)
    assert out == [("authorization", SECRET)]


def test_placeholder_inside_basic_credentials() -> None:
    headers = [("Authorization", basic("x-access-token", PLACEHOLDER))]
    out, used = apply_credentials([placeholder()], headers, secure=True)
    assert out == [("Authorization", basic("x-access-token", SECRET))]
    assert used == [f"api.x.com: Authorization ({PLACEHOLDER})"]
    # not base64, or without the placeholder: untouched
    for value in ("Basic !!notb64", basic("user", "other")):
        assert apply_credentials([placeholder()], [("Authorization", value)], secure=True) == (
            [("Authorization", value)],
            [],
        )


def test_requests_without_the_placeholder_pass_unchanged() -> None:
    headers = [("Authorization", "Bearer own-token")]
    assert apply_credentials([placeholder()], headers, secure=False) == (headers, [])


def test_inject_replaces_what_the_client_sent() -> None:
    headers = [("authorization", "Bearer fake"), ("Accept", "*/*"), ("AUTHORIZATION", "x")]
    out, used = apply_credentials([inject()], headers, secure=True)
    assert out == [("Accept", "*/*"), ("Authorization", f"Bearer {SECRET}")]
    assert used == ["api.x.com: Authorization"]
    out, _ = apply_credentials([inject("X-Api-Key", "{secret}")], [], secure=True)
    assert out == [("X-Api-Key", SECRET)]


def test_several_credentials() -> None:
    creds = [inject("X-Api-Key", "{secret}", "k1"), placeholder(ph="PLACEHOLDER_ONE", secret="s1")]
    creds.append(placeholder(ph="PLACEHOLDER_TWO", secret="s2"))
    out, used = apply_credentials(
        creds, [("Authorization", "PLACEHOLDER_ONE PLACEHOLDER_TWO")], secure=True
    )
    assert out == [("Authorization", "s1 s2"), ("X-Api-Key", "k1")]
    assert used == [
        "api.x.com: Authorization (PLACEHOLDER_ONE)",
        "api.x.com: Authorization (PLACEHOLDER_TWO)",
        "api.x.com: X-Api-Key",
    ]


def test_credentials_are_never_sent_in_the_clear() -> None:
    with pytest.raises(CredentialRefused, match="only sent over https"):
        apply_credentials([inject()], [], secure=False)
    with pytest.raises(CredentialRefused, match="only sent over https") as e:
        apply_credentials([placeholder()], [("Authorization", PLACEHOLDER)], secure=False)
    assert e.value.rule == f"api.x.com: Authorization ({PLACEHOLDER})"
    assert SECRET not in str(e.value)


def test_an_injected_header_takes_one_credential() -> None:
    for other in (inject(secret="other"), placeholder()):
        with pytest.raises(CredentialRefused, match="conflicting credentials"):
            apply_credentials([inject(), other], [], secure=True)


def test_secret_is_not_in_repr() -> None:
    assert SECRET not in repr(inject()) and SECRET not in repr(placeholder())


# --- secrets in the sandbox's environment -------------------------------------------------


@pytest.mark.parametrize(
    "env",
    [
        {"GITHUB_TOKEN": SECRET},  # passed through from the host by accident
        {"GH_TOKEN": SECRET},  # under another name: still the secret
        {"AUTH_HEADER": f"Bearer {SECRET}"},
        {"REMOTE": f"https://x-access-token:{SECRET}@github.com/o/r.git"},
        {f"TOKEN_{SECRET}": "1"},
    ],
)
def test_env_holding_a_secret_is_refused(env: dict[str, str]) -> None:
    with pytest.raises(CredentialError) as e:
        check_env([placeholder(), inject("X-Key", "{secret}", "other")], {"HOME": "/tmp", **env})
    (name,) = env
    label = "a variable whose name holds it" if SECRET in name else name
    message = str(e.value)
    assert SECRET not in message and f"{label} (credential api.x.com: Authorization" in message
    assert "HOME" not in message


def test_env_without_secrets_passes() -> None:
    env = {"GITHUB_TOKEN": PLACEHOLDER, "HOME": "/tmp", "SECRET": "not-the-secret"}
    check_env([placeholder(), inject(secret="other-secret")], env)
    check_env([], {"ANY": SECRET})  # no credentials, nothing known to be secret


def test_env_check_names_every_leak() -> None:
    with pytest.raises(CredentialError) as e:
        check_env(
            [placeholder(), inject("X-Key", "{secret}", "k3y-value")],
            {"A": SECRET, "B": "k3y-value", "C": "fine"},
        )
    message = str(e.value)
    assert "A (credential api.x.com: Authorization" in message
    assert "B (credential api.x.com: X-Key)" in message and "C (" not in message
    assert SECRET not in message and "k3y-value" not in message


# --- placeholders where they are not replaced ---------------------------------------------


def refused_at(check) -> str | None:
    try:
        check()
    except CredentialRefused as e:
        assert e.rule == f"api.x.com: Authorization ({PLACEHOLDER})"
        return e.reason.removeprefix("credential placeholder in the ")
    return None


def test_scan_of_a_request_head() -> None:
    scan = PlaceholderScan([placeholder()])
    ok = [("Authorization", f"Bearer {SECRET}"), ("Accept", "*/*")]  # after substitution

    def head(target: str = "/x", headers: list[tuple[str, str]] = ok):
        return lambda: scan.check_request(target, headers)

    assert refused_at(head()) is None
    assert refused_at(head(f"/x?q={PLACEHOLDER}")) == "request target"
    assert refused_at(head("/x/%53" + PLACEHOLDER[1:])) == "request target"  # escaped
    assert refused_at(head(headers=[*ok, ("X-Echo", f"a{PLACEHOLDER}b")])) == "X-Echo header"
    assert refused_at(head(headers=[(PLACEHOLDER, "1")])) == f"{PLACEHOLDER} header"
    basic_value = basic("git", PLACEHOLDER)  # a git remote URL's credentials, to another host
    assert refused_at(head(headers=[("Authorization", basic_value)])) == "Authorization header"
    assert refused_at(head(headers=[("X", "Basic !!")])) is None  # not base64: nothing to see


def test_scan_of_host_names() -> None:
    scan = PlaceholderScan([placeholder()])
    assert refused_at(lambda: scan.check_host(f"{PLACEHOLDER.lower()}.evil.com")) == "host name"
    assert refused_at(lambda: scan.check_host(f"x.{PLACEHOLDER}.evil.com")) == "host name"
    assert refused_at(lambda: scan.check_host("api.x.com")) is None


def test_scan_of_a_body_across_pieces() -> None:
    scan = PlaceholderScan([placeholder(), placeholder(ph="SHORTER_PLACEHOLDER")])
    body = scan.body()
    ph = PLACEHOLDER.encode()
    body.payload(b"a" * 100 + ph[:5])
    body.payload(ph[5:12])
    assert refused_at(lambda: body.payload(ph[12:] + b"tail")) == "request body"
    body = scan.body()
    for piece in (b"x" * 70_000, ph[:-1], b"!", ph[-1:]):  # near misses
        body.payload(piece)
    assert refused_at(lambda: body.line(b"X-Trailer: " + ph + b"\r\n")) == "request body"


def test_scan_skips_placeholders_allowed_elsewhere() -> None:
    allowed = Compiled(
        "Authorization",
        SECRET,
        placeholder=PLACEHOLDER,
        source="api.x.com: Authorization",
        allow_placeholder_elsewhere=True,
    )
    assert not PlaceholderScan([allowed, inject()])  # nothing to look for
    PlaceholderScan([allowed]).check_request(f"/?q={PLACEHOLDER}", [])
    # a placeholder two credentials share is looked for unless both allow it elsewhere
    shared = PlaceholderScan([allowed, placeholder()])
    assert refused_at(lambda: shared.check_request(f"/?q={PLACEHOLDER}", [])) == "request target"


def test_the_flag_is_compiled(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("SANDBOX_TEST_TOKEN", SECRET)
    for flag in (False, True):
        c = Credential(
            secret_env="SANDBOX_TEST_TOKEN",
            placeholder=PLACEHOLDER,
            allow_placeholder_elsewhere=flag,
        )
        assert c.compile("api.x.com").allow_placeholder_elsewhere is flag
    assert not Credential(secret_env="T", placeholder=PLACEHOLDER).allow_placeholder_elsewhere


# --- which host entry's credentials a request gets ----------------------------------------


def entry(pattern: str, methods: list[str] = [], path: str = "/**"):  # noqa: B006
    return parse_host_rule(pattern, "inspect", allow=[parse_request_filter(methods, path)])


def test_credentials_come_only_from_entries_that_allow_the_request() -> None:
    token = inject()
    creds = Credentials({"api.github.com": [token]})
    rules = [
        entry("api.github.com", methods=["GET"], path="/repos/**"),
        entry("*.github.com"),  # allows everything, carries no credential
    ]
    get = judge_request(rules, "GET", "/repos/o/r")
    assert get.allowed and get.allowed_by == ("api.github.com", "*.github.com")
    assert creds.of(get.allowed_by) == (token,)
    for method, target in [("POST", "/repos/o/r"), ("DELETE", "/repos/o/r"), ("GET", "/user")]:
        verdict = judge_request(rules, method, target)
        assert verdict.allowed and verdict.allowed_by == ("*.github.com",)
        assert creds.of(verdict.allowed_by) == ()  # allowed, but not with the token
        assert verdict.rule == "*.github.com: allow * /**"
    # a placeholder on such a request stays a placeholder
    headers = [("Authorization", f"Bearer {PLACEHOLDER}")]
    creds = Credentials({"api.github.com": [placeholder()]})
    rules = [entry("api.github.com", methods=["GET"]), entry("*.github.com")]
    post = judge_request(rules, "POST", "/x")
    assert creds.apply(post.allowed_by, headers, secure=True) == (headers, [])


def test_credentials_of_every_entry_that_allows_the_request() -> None:
    a, b = inject("X-A", "{secret}", "a"), inject("X-B", "{secret}", "b")
    creds = Credentials({"api.github.com": [a], "*.github.com": [b]})
    rules = [entry("api.github.com", methods=["GET"]), entry("*.github.com")]
    assert creds.of(judge_request(rules, "GET", "/").allowed_by) == (a, b)
    assert creds.of(judge_request(rules, "POST", "/").allowed_by) == (b,)
    # two entries injecting one header only clash on requests both of them allow
    creds = Credentials(
        {"api.github.com": [inject(secret="a")], "*.github.com": [inject(secret="b")]}
    )
    rules = [entry("api.github.com", methods=["GET"]), entry("*.github.com", methods=["POST"])]
    for method, secret in [("GET", "a"), ("POST", "b")]:
        out, _ = creds.apply(judge_request(rules, method, "/").allowed_by, [], secure=True)
        assert out == [("Authorization", f"Bearer {secret}")]


def test_denied_requests_carry_no_credentials() -> None:
    rule = parse_host_rule(
        "api.github.com",
        "inspect",
        allow=[parse_request_filter()],
        deny=[parse_request_filter(["DELETE"])],
    )
    assert judge_request([rule], "DELETE", "/x").allowed_by == ()
    assert judge_request([rule], "GET", "/a/../b").allowed_by == ()


def test_the_session_credentials() -> None:
    a, b = inject("X-A", "{secret}", "a"), placeholder(secret="b")
    creds = Credentials({"api.x.com": [a], "*.x.com": [b], "other.com": []})
    assert creds and creds.all == (a, b) and creds.scan
    assert creds.of(["unknown.com", "*.x.com", "api.x.com"]) == (b, a)  # in the order asked
    with pytest.raises(CredentialError, match="LEAK"):
        creds.check_env({"LEAK": "Bearer b"})
    assert not Credentials() and not Credentials().scan


# --- policy ------------------------------------------------------------------------------


def host(*credentials: Credential) -> HostAccess:
    return HostAccess(access="inspect", allow=[RequestFilter()], credentials=list(credentials))


def test_policy_compiles_and_masks_the_secret() -> None:
    c = Credential(secret=SecretStr(SECRET), inject="Bearer {secret}")
    policy = NetworkPolicy(hosts={"api.x.com": host(c)})
    assert SECRET not in repr(policy) and SECRET not in policy.model_dump_json()
    assert policy.resolve_credentials().all == (
        Compiled(
            "Authorization", SECRET, inject="Bearer {secret}", source="api.x.com: Authorization"
        ),
    )
    # JSON policies (the CLI's --policy) take the secret as a plain string
    loaded = NetworkPolicy.model_validate_json(
        '{"hosts": {"api.x.com": {"access": "inspect", "allow": [{}], "credentials": '
        '[{"secret": "s3cret", "placeholder": "PLACEHOLDER_X"}]}}}'
    )
    assert loaded.resolve_credentials().all[0].secret == "s3cret"


def test_secret_env_is_read_when_compiled(monkeypatch: pytest.MonkeyPatch) -> None:
    c = Credential(secret_env="SANDBOX_TEST_TOKEN", placeholder=PLACEHOLDER)
    policy = NetworkPolicy(hosts={"api.x.com": host(c)})  # validating needs no secret
    monkeypatch.delenv("SANDBOX_TEST_TOKEN", raising=False)
    assert len(policy.host_rules()) == 1  # nor does compiling the host rules
    with pytest.raises(CredentialError, match="SANDBOX_TEST_TOKEN is not set"):
        policy.resolve_credentials()
    monkeypatch.setenv("SANDBOX_TEST_TOKEN", "bad\r\nX-Injected: 1")
    with pytest.raises(CredentialError, match="printable ASCII"):
        policy.resolve_credentials()
    monkeypatch.setenv("SANDBOX_TEST_TOKEN", SECRET)
    assert policy.resolve_credentials().all[0].secret == SECRET


@pytest.mark.parametrize(
    ("fields", "error"),
    [
        ({"inject": "Bearer {secret}"}, "one of secret and secret_env"),
        ({"secret": "s", "secret_env": "T", "inject": "{secret}"}, "one of secret and"),
        ({"secret": "s"}, "one of placeholder and inject"),
        ({"secret": "s", "placeholder": PLACEHOLDER, "inject": "{secret}"}, "one of placeholder"),
        ({"secret": "s", "inject": "Bearer"}, r"exactly one \{secret\}"),
        ({"secret": "s", "inject": "{secret}{secret}"}, r"exactly one \{secret\}"),
        ({"secret": "s", "inject": "{secret}\r\nX: y"}, "printable ASCII"),
        ({"secret": "s", "placeholder": "short"}, "placeholder must be"),
        ({"secret": "s", "placeholder": "has space in it"}, "placeholder must be"),
        (
            {"secret": "s", "inject": "{secret}", "allow_placeholder_elsewhere": True},
            "only applies to placeholder mode",
        ),
        ({"secret": "a\nb", "placeholder": PLACEHOLDER}, "printable ASCII"),
        ({"secret": "", "placeholder": PLACEHOLDER}, "printable ASCII"),
        (
            {"secret_env": "NOT-A-NAME", "placeholder": PLACEHOLDER},
            "name of an environment variable",
        ),
        ({"secret": "s", "inject": "{secret}", "header": "Host"}, "managed by the proxy"),
        ({"secret": "s", "inject": "{secret}", "header": "Proxy-Authorization"}, "managed by"),
        ({"secret": "s", "inject": "{secret}", "header": "Bad Header"}, "must be a header"),
    ],
)
def test_bad_credentials(fields: dict, error: str) -> None:
    with pytest.raises(ValidationError, match=error):
        Credential.model_validate(fields)


def test_credentials_need_an_inspected_host() -> None:
    c = Credential(secret=SecretStr("s"), inject="{secret}")
    with pytest.raises(ValidationError, match="only `inspect` hosts take credentials"):
        HostAccess(access="tunnel", credentials=[c])


def test_credential_clashes_within_a_host() -> None:
    a = Credential(secret=SecretStr("a"), inject="{secret}")
    b = Credential(secret=SecretStr("b"), header="authorization", placeholder=PLACEHOLDER)
    with pytest.raises(ValidationError, match="injected, so it takes one credential"):
        host(a, b)
    with pytest.raises(ValidationError, match="placeholder is used by two credentials"):
        host(b, b.model_copy(update={"header": "X-Other"}))
    # two placeholders in one header are fine
    host(b, b.model_copy(update={"placeholder": "OTHER_PLACEHOLDER"}))


# --- validation errors never carry the secret --------------------------------------------

LEAKY = "ghp_SUPERSECRET123"


def hosts(*credentials: dict, access: str = "inspect", **more) -> dict:
    entry = {"access": access, "credentials": list(credentials), **more}
    return {"hosts": {"api.x.com": entry | ({"allow": [{}]} if access == "inspect" else {})}}


class Embedding(BaseModel):  # an application's own config model, holding a policy
    sandbox: SandboxPolicy


@pytest.mark.parametrize(
    "validate",
    [
        # the example from the bug report: a model-level check, the input dict has the secret
        lambda: Credential.model_validate({"placeholder": "short", "secret": LEAKY}),
        lambda: Credential.model_validate({"placeholder": "PLACEHOLDER_X", "secret": LEAKY + "\n"}),
        lambda: Credential.model_validate({"secrett": LEAKY, "inject": "{secret}"}),  # typo
        lambda: Credential.model_validate({"secret": LEAKY, "inject": f"Bearer {LEAKY}"}),
        lambda: Credential.model_validate({"header": f"Authorization: {LEAKY}", "secret": "s"}),
        lambda: Credential.model_validate({"secret_env": f"{LEAKY}!", "inject": "{secret}"}),
        lambda: Credential.model_validate({"secret": "s", "placeholder": f"{LEAKY}+/="}),
        # checks of the enclosing models, whose input holds the raw credential dicts
        lambda: NetworkPolicy.model_validate(
            hosts(*[{"secret": LEAKY, "placeholder": "PLACEHOLDER_X", "header": h} for h in "AB"])
        ),
        lambda: NetworkPolicy.model_validate(
            hosts({"secret": LEAKY, "inject": "{secret}"}, access="tunnel")
        ),
        lambda: NetworkPolicy.model_validate(
            {
                "hosts": {
                    h: {
                        "access": "inspect",
                        "allow": [{}],
                        "credentials": [{"secret": LEAKY, "inject": "{secret}"}],
                    }
                    for h in ("API.x.com", "api.x.com")
                }
            }
        ),
        lambda: SandboxPolicy.model_validate_json(
            json.dumps({"network": hosts({"secret": LEAKY, "placeholder": "short"})})
        ),
        lambda: SandboxPolicy.model_validate({"env": {"TOKEN": LEAKY}, "limits": {"x": 1}}),
        lambda: SandboxPolicy.model_validate({"env": {"TOKEN": LEAKY, "N": 1}}),
        lambda: Embedding.model_validate(
            {"sandbox": {"network": hosts({"secret": LEAKY, "placeholder": "short"})}}
        ),
    ],
)
def test_validation_errors_do_not_leak_secrets(validate) -> None:
    with pytest.raises(ValidationError) as e:
        validate()
    for text in (str(e.value), repr(e.value), repr(e.value.errors()), e.value.json()):
        assert LEAKY not in text
    assert all(err["input"] == "<hidden>" for err in e.value.errors())


def test_validation_errors_stay_useful() -> None:
    with pytest.raises(ValidationError) as e:
        SandboxPolicy.model_validate(
            {
                "filesystem": {"deny_read": ["relative"]},
                "network": hosts({"secret": LEAKY, "inject": "Bearer"}, bogus=1),
            }
        )
    assert [(err["loc"], err["type"], err["msg"]) for err in e.value.errors()] == [
        (
            ("filesystem", "deny_read"),
            "value_error",
            "Value error, path must be absolute: 'relative'",
        ),
        (
            ("network", "hosts", "api.x.com", "credentials", 0),
            "value_error",
            "Value error, inject needs exactly one {secret}, standing for the secret"
            " (the secret itself goes in secret or secret_env)",
        ),
        (
            ("network", "hosts", "api.x.com", "bogus"),
            "extra_forbidden",
            "Extra inputs are not permitted",
        ),
    ]
