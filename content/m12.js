export default {
  id: "m12",
  number: 12,
  title: "Expert practice: types, tests and tooling",
  focus: "proving it",
  subtitle:
    "The difference between knowing the rules and shipping code that follows them: types that encode invariants, tests that encode attacks, fuzzing that finds what you did not think of, and a linter you wrote yourself.",
  objectives: [
    "Use type annotations to make invalid states unrepresentable, and run a type checker.",
    "Write security regression tests, including the attack that caused the fix.",
    "Generate adversarial inputs with property-based testing.",
    "Write an AST-based linter for a rule your team actually needs.",
    "Audit an unfamiliar application and report findings a team can act on.",
  ],
  rules: [
    { id: "PY-EVAL", what: "the rule your own linter will enforce" },
    { id: "PY-ASSERT-AUTH", what: "the rule a type checker cannot catch" },
    { id: "PY-SWALLOWED-ERROR", what: "the rule a test catches only if you write it" },
  ],
  capstone:
    "Day 66 audits a complete vulnerable application and produces a prioritised report with a remediation and a regression test for every finding.",

  lessons: [
    /* ----------------------------------------------------------------- 56 */
    {
      id: "m12l01",
      day: 62,
      title: "Types that make invalid states unrepresentable",
      minutes: 60,
      secure: "invariants in the type system",
      cwe: ["CWE-704", "CWE-1287"],
      tags: ["typing", "mypy", "newtype", "literal", "protocol"],
      lede:
        "Annotations are not checked at runtime, which makes them sound decorative. Their value is that a checker reads them before the code runs, and a reviewer reads them before that.",
      blocks: [
        {
          t: "code",
          label: "example",
          code: `from typing import Literal, NewType, Sequence

UserId = NewType("UserId", int)
Role = Literal["member", "editor", "admin"]

def promote(user_id: UserId, role: Role) -> bool:
    ...

promote(7, "admin")             # mypy: error -- 7 is int, not UserId
promote(UserId(7), "root")      # mypy: error -- "root" is not a Role`,
          cap: "`NewType` is free at runtime — `UserId(7)` *is* `7` — and distinct to the checker. `Literal` turns a set of permitted strings into a type.",
        },
        {
          t: "box",
          kind: "rule",
          title: "Encode the trust boundary in the types",
          md: `\`\`\`
RawInput = NewType("RawInput", str)        # untrusted
SafePath = NewType("SafePath", Path)       # validated and confined
Escaped  = NewType("Escaped", str)         # encoded for HTML
\`\`\`

Now \`open(raw)\` is a type error, and the only way to obtain a \`SafePath\` is to call the validator that produces one. The checker enforces, at every call site, the discipline that was previously a convention.`,
        },
        {
          t: "table",
          head: ["Construct", "Use"],
          rows: [
            ["`Literal[\"a\", \"b\"]`", "A closed set of permitted values."],
            ["`NewType`", "A distinct type with no runtime cost."],
            ["`Final`", "A constant the checker will not let you rebind."],
            ["`Protocol`", "Structural typing — 'anything with .read()'."],
            ["`TypedDict`", "A dict with known keys, for JSON shapes."],
            ["`@overload`", "Different return types for different arguments."],
            ["`assert_never`", "Exhaustiveness: a new enum member becomes a type error."],
          ],
        },
        {
          t: "code",
          label: "fixed",
          code: `from typing import assert_never, Literal

Action = Literal["read", "write", "delete"]

def authorise(action: Action, is_admin: bool) -> bool:
    if action == "read":
        return True
    if action == "write":
        return is_admin
    if action == "delete":
        return is_admin
    assert_never(action)          # adding "share" to Action breaks the BUILD`,
          cap: "Exhaustiveness checking is the most under-used safety feature in Python's type system. A new permission that nobody handled fails in CI rather than in production.",
        },
        {
          t: "box",
          kind: "warn",
          title: "Annotations are not validation",
          md: `\`def f(x: int)\` happily receives \`"drop table"\` at runtime. The checker only sees code it analyses; data arriving from a socket is never checked by it.

Types discipline *your* code. Validation disciplines *their* data. You need both — annotate the function and parse the input at the boundary.`,
        },
        {
          t: "box",
          kind: "good",
          title: "Running the checker",
          md: `\`\`\`
pip install mypy
mypy --strict src/
\`\`\`

\`--strict\` requires annotations everywhere and forbids implicit \`Any\`. On an existing codebase, adopt it per module with \`# mypy: strict\` at the top of files as you touch them, and set \`disallow_untyped_defs\` first — most of the value comes from that one flag.`,
        },
      ],
      quiz: [
        {
          q: "Does `def f(x: int)` prevent a string being passed at runtime?",
          options: [
            "Yes.",
            "No — annotations are not enforced at runtime; a checker reads them beforehand.",
            "Only with `--strict`.",
          ],
          answer: 1,
          why: "Types catch bugs in code you analyse. Data from outside still needs a parser at the boundary.",
        },
        {
          q: "What does `assert_never` buy you?",
          options: [
            "A runtime guard.",
            "Exhaustiveness: adding a member to a Literal/enum turns every unhandled branch into a type error.",
            "Faster dispatch.",
          ],
          answer: 1,
          why: "A new permission or state that nobody handled fails the build rather than falling through at runtime.",
        },
        {
          q: "Why wrap a validated path in `NewType(\"SafePath\", Path)`?",
          options: [
            "For documentation.",
            "The only way to obtain one is through the validator, so the checker enforces that discipline at every call site.",
            "It makes paths immutable.",
          ],
          answer: 1,
          why: "It converts a convention people must remember into a constraint the tooling enforces, at zero runtime cost.",
        },
      ],
      exercise: {
        title: "A typed, exhaustive permission model",
        brief: `Build a permission model whose invariants live in the types *and* are enforced at runtime (since this course runs the code, not a checker).

1. \`UserId = NewType("UserId", int)\` and \`make_user_id(value)\` — returns a \`UserId\`, raising \`ValueError\` for anything that is not a positive \`int\` (reject \`bool\`).
2. \`ACTIONS = ("read", "write", "delete", "share")\` — the closed set of actions, with \`Action\` annotated as a \`Literal\` over them.
3. \`authorise(action, *, is_admin, is_owner)\` returning \`bool\`:
   - \`"read"\` → always \`True\`
   - \`"write"\` → \`is_admin or is_owner\`
   - \`"delete"\` → \`is_admin\`
   - \`"share"\` → \`is_owner\`
   - anything else → \`ValueError(f"unhandled action: {action!r}")\` (this is the runtime stand-in for \`assert_never\`)
4. \`Settings\` as a \`TypedDict\` with \`host: str\`, \`port: int\`, \`debug: bool\`; and \`parse_settings(raw)\` validating a dict against it — unknown keys, missing keys and wrong types all raise \`ValueError\`.
5. \`describe_types()\` returning a dict mapping each function name to its return annotation as a string, read from \`__annotations__\` — proving the annotations are present and machine-readable.`,
        rubric: [
          "`make_user_id` validates and returns an int-compatible value",
          "Every action is handled; an unknown one raises rather than returning False",
          "`parse_settings` enforces keys and types exactly",
          "Annotations exist and are readable via `__annotations__`",
          "`bool` is rejected where an int is required",
        ],
        starter: `from typing import Literal, NewType, TypedDict

UserId = NewType("UserId", int)

ACTIONS = ("read", "write", "delete", "share")
Action = Literal["read", "write", "delete", "share"]


class Settings(TypedDict):
    host: str
    port: int
    debug: bool


def make_user_id(value) -> UserId:
    """Return a validated UserId."""


def authorise(action: Action, *, is_admin: bool, is_owner: bool) -> bool:
    """Decide one action. Every member of Action must be handled."""


def parse_settings(raw) -> Settings:
    """Validate a raw dict against the Settings shape."""


def describe_types() -> dict:
    """Return {function_name: return annotation} from __annotations__."""


print(authorise("write", is_admin=False, is_owner=True))
print(parse_settings({"host": "db.internal", "port": 5432, "debug": False}))
`,
        stdin: [],
        tests: [
          {
            name: "user ids are validated",
            code: `assert make_user_id(7) == 7
for bad in (0, -1, "7", 7.0, None, True):
    with raises(ValueError):
        make_user_id(bad)`,
          },
          {
            name: "every action is handled",
            code: `cases = {
    ("read", False, False): True,
    ("write", False, False): False,
    ("write", True, False): True,
    ("write", False, True): True,
    ("delete", True, False): True,
    ("delete", False, True): False,
    ("share", False, True): True,
    ("share", True, False): False,
}
for (action, admin, owner), expected in cases.items():
    got = authorise(action, is_admin=admin, is_owner=owner)
    assert got is expected, f"{action} admin={admin} owner={owner}: got {got!r}"`,
          },
          {
            name: "an unknown action raises rather than denying quietly",
            code: `for bad in ("publish", "READ", "", None, 5):
    try:
        authorise(bad, is_admin=True, is_owner=True)
        raise AssertionError(f"{bad!r} should have raised")
    except ValueError as e:
        assert "unhandled" in str(e), f"got {str(e)!r}"`,
          },
          {
            name: "every declared action is actually implemented",
            code: `for action in ACTIONS:
    got = authorise(action, is_admin=True, is_owner=True)
    assert got in (True, False), f"{action!r} returned {got!r}"`,
          },
          {
            name: "settings are validated by key and type",
            code: `ok = {"host": "db.internal", "port": 5432, "debug": False}
assert parse_settings(ok) == ok
for bad in ({}, {"host": "h"}, {**ok, "extra": 1}, {**ok, "port": "5432"},
            {**ok, "debug": "false"}, {**ok, "host": 5}, [1], None):
    with raises(ValueError):
        parse_settings(bad)`,
          },
          {
            name: "bool is not an acceptable port",
            code: `with raises(ValueError):
    parse_settings({"host": "h", "port": True, "debug": False})`,
          },
          {
            name: "annotations are present and readable",
            code: `info = describe_types()
assert "authorise" in info and "make_user_id" in info, f"got {info!r}"
assert "bool" in str(info["authorise"]), f"got {info['authorise']!r}"
assert authorise.__annotations__.get("return") is not None
assert "is_admin" in authorise.__annotations__, "annotate the keyword parameters too"`,
          },
        ],
        requirements: [
          { kind: "defines", value: "authorise" },
          { kind: "defines", value: "parse_settings" },
          { kind: "uses_module", value: "typing" },
        ],
        hints: [
          "`NewType` returns a callable that is the identity at runtime: `return UserId(value)` after validating.",
          "Handle the four actions with explicit `if` branches and end with `raise ValueError(f\"unhandled action: {action!r}\")` — the runtime equivalent of `assert_never`.",
          "`Settings.__annotations__` gives you `{\"host\": str, \"port\": int, \"debug\": bool}`, so `parse_settings` can loop over it instead of repeating the field names.",
          "`isinstance(value, bool)` must be checked before `isinstance(value, int)` for the port — and note that `debug` legitimately *is* a bool, so the check is per field.",
        ],
        solution: `from typing import Literal, NewType, TypedDict

UserId = NewType("UserId", int)

ACTIONS = ("read", "write", "delete", "share")
Action = Literal["read", "write", "delete", "share"]


class Settings(TypedDict):
    host: str
    port: int
    debug: bool


def make_user_id(value) -> UserId:
    """Return a validated UserId."""
    if isinstance(value, bool) or not isinstance(value, int) or value <= 0:
        raise ValueError("user id must be a positive int")
    return UserId(value)


def authorise(action: Action, *, is_admin: bool, is_owner: bool) -> bool:
    """Decide one action. Every member of Action must be handled."""
    if action == "read":
        return True
    if action == "write":
        return bool(is_admin or is_owner)
    if action == "delete":
        return bool(is_admin)
    if action == "share":
        return bool(is_owner)

    # The runtime stand-in for typing.assert_never: a new action added to
    # ACTIONS without a branch here fails loudly instead of denying silently.
    raise ValueError(f"unhandled action: {action!r}")


def parse_settings(raw) -> Settings:
    """Validate a raw dict against the Settings shape."""
    if not isinstance(raw, dict):
        raise ValueError("settings must be an object")

    expected = Settings.__annotations__

    unknown = set(raw) - set(expected)
    if unknown:
        raise ValueError(f"unknown settings: {sorted(unknown)}")

    missing = set(expected) - set(raw)
    if missing:
        raise ValueError(f"missing settings: {sorted(missing)}")

    clean = {}
    for field, field_type in expected.items():
        value = raw[field]
        if field_type is bool:
            if not isinstance(value, bool):
                raise ValueError(f"{field} must be a bool")
        elif field_type is int:
            if isinstance(value, bool) or not isinstance(value, int):
                raise ValueError(f"{field} must be an int")
        elif not isinstance(value, field_type):
            raise ValueError(f"{field} must be {field_type.__name__}")
        clean[field] = value

    return clean


def describe_types() -> dict:
    """Return {function_name: return annotation} from __annotations__."""
    return {
        fn.__name__: fn.__annotations__.get("return")
        for fn in (make_user_id, authorise, parse_settings, describe_types)
    }


print(authorise("write", is_admin=False, is_owner=True))
print(parse_settings({"host": "db.internal", "port": 5432, "debug": False}))`,
        why: `\`authorise\` raises on an unknown action instead of returning \`False\`, and that choice is the opposite of the fail-closed advice from Module 2 — deliberately. A \`False\` here would be fail-closed for the *request* and fail-open for the *codebase*: a new \`"share"\` action added to \`ACTIONS\` but never implemented would be denied silently, the feature would appear broken, and someone would "fix" it by adding a permissive default. Raising surfaces the omission at the first call, in a test, before the permissive default gets written.

That is what \`typing.assert_never\` does at build time, and the \`raise\` is its runtime twin. Under a type checker both fire: \`assert_never\` turns an unhandled \`Literal\` member into a compile error, and the \`raise\` covers the data that arrives from outside, which the checker never sees.

\`parse_settings\` derives its rules from \`Settings.__annotations__\` rather than repeating the field names. Adding a field to the \`TypedDict\` automatically makes it required and type-checked, so the declaration and the validator cannot drift apart — the single-source-of-truth principle applied to a shape instead of a value.

The \`bool\` handling is the detail that makes it correct. \`isinstance(True, int)\` is \`True\`, so a naive loop would accept \`{"port": true}\` from a JSON body and connect to port 1. Checking \`bool\` first, and only where \`bool\` is the declared type, keeps \`debug\` working while closing the port case.

\`NewType\` costs nothing at runtime — \`UserId(7)\` is \`7\` — and yet under \`mypy\` it makes \`promote(7, ...)\` an error. That asymmetry is the whole argument for gradual typing: the constraint lives entirely in the tooling, so you can add it to existing code without changing a single runtime behaviour.`,
      },
      wrapup: `- Annotations discipline your code; parsers discipline external data. Both, always.
- \`Literal\` + exhaustiveness turns a forgotten branch into a build failure.
- \`NewType\` makes "this value was validated" a type the checker enforces, for free.
- Derive validators from the declared shape so they cannot drift.`,
      refs: [
        { label: "typing", url: "https://docs.python.org/3/library/typing.html" },
        { label: "mypy documentation", url: "https://mypy.readthedocs.io/" },
      ],
    },

    /* ----------------------------------------------------------------- 57 */
    {
      id: "m12l02",
      day: 63,
      title: "Tests that encode attacks",
      minutes: 60,
      secure: "security regression tests",
      cwe: ["CWE-1006"],
      tags: ["pytest", "testing", "regression", "fixtures", "coverage"],
      lede:
        "Every vulnerability you fix should leave behind a test that fails if it comes back. Without one, the fix has a half-life measured in refactors.",
      blocks: [
        {
          t: "code",
          label: "example",
          code: `# test_auth.py
import pytest
from app.auth import login

def test_wrong_password_is_rejected():
    assert login("ada@example.com", "wrong")[0] is False

@pytest.mark.parametrize("payload", [
    "' OR '1'='1",
    "'; DROP TABLE users; --",
    "admin'--",
])
def test_sql_payloads_do_not_authenticate(payload):
    """Regression: CVE-internal-2026-04."""
    assert login(payload, "x")[0] is False

def test_failure_messages_are_identical():
    """Regression: user enumeration via distinct error messages."""
    unknown = login("nobody@example.com", "x")
    wrong = login("ada@example.com", "wrong")
    assert unknown == wrong`,
          cap: "`parametrize` turns one test into a corpus. The docstring naming the original incident is what stops a future reader from deleting it as redundant.",
        },
        {
          t: "box",
          kind: "rule",
          title: "Three tests per fix",
          md: `1. **The attack** — the exact input that exploited it, asserting it now fails.
2. **The neighbourhood** — variations the attacker would try next: other encodings, other fields, the same trick one layer deeper.
3. **The happy path** — proof the fix did not break the feature, which is what otherwise causes the fix to be reverted.`,
        },
        {
          t: "table",
          head: ["Property", "How to test it"],
          rows: [
            ["No SQL injection", "Payload returns zero rows; the table is unchanged afterwards."],
            ["No command injection", "A breach ledger / a spy on `subprocess` records nothing."],
            ["No IDOR", "Another tenant's id raises, with the same error as a missing id."],
            ["No XSS", "The rendered output contains no `<script` and the payload appears escaped."],
            ["Constant-time compare", "Assert the source calls `compare_digest` — timing itself is too noisy to test."],
            ["No secret in logs", "Capture the log output and assert the secret is absent."],
          ],
        },
        {
          t: "code",
          label: "example",
          code: `def test_secret_never_reaches_the_log(caplog):
    cfg = DbConfig("db.internal", 5432, "app", "s3cr3t-prod-pw")
    with caplog.at_level("DEBUG"):
        connect(cfg)
    assert "s3cr3t-prod-pw" not in caplog.text`,
          cap: "`caplog` is a built-in pytest fixture. Asserting on the *absence* of a string is one of the most valuable security tests you can write, and one of the rarest.",
        },
        {
          t: "box",
          kind: "pitfall",
          title: "A test that cannot fail",
          md: `\`\`\`
def test_sql_injection():
    result = search("' OR '1'='1")
    assert result is not None          # passes whatever search does
\`\`\`

Before trusting a security test, **break the fix and watch the test fail**. A test that passes against the vulnerable code is worse than no test: it ends an investigation with false confidence.`,
        },
        {
          t: "box",
          kind: "good",
          title: "Coverage is a map, not a score",
          md: `\`pytest --cov\` shows which lines ran. High coverage with weak assertions proves nothing; low coverage reliably shows *where you have not looked*.

Use it to find untested error paths — the \`except\` branches and permission denials that are exactly where security bugs live — rather than as a number to maximise.`,
        },
      ],
      quiz: [
        {
          q: "Why write a test for a vulnerability you have already fixed?",
          options: [
            "For documentation.",
            "So a future refactor that reintroduces it fails CI instead of reaching production.",
            "To increase coverage.",
          ],
          answer: 1,
          why: "A fix without a regression test survives only until someone touches that code with good intentions.",
        },
        {
          q: "How do you know a security test is meaningful?",
          options: [
            "It passes.",
            "You reverted the fix and watched it fail.",
            "It has an assertion.",
          ],
          answer: 1,
          why: "A test that passes against the vulnerable version is worse than nothing — it grants confidence it has not earned.",
        },
        {
          q: "The most practical way to test 'no secret in logs':",
          options: [
            "Read the code.",
            "Capture the log output in the test and assert the secret string is absent.",
            "It cannot be tested.",
          ],
          answer: 1,
          why: "Asserting on absence is cheap, exact, and catches the `__repr__` that leaks after someone adds a field.",
        },
      ],
      exercise: {
        title: "A security test suite for a login function",
        brief: `A deliberately imperfect \`login\` implementation is given in the starter (do not change it — your job is to test it). Write a mini test framework and a suite that would catch regressions.

1. \`run_tests(tests)\` — \`tests\` is a list of \`(name, callable)\`. Call each, catching \`AssertionError\` and \`Exception\`. Return \`{"passed": [names], "failed": {name: reason}}\`, names sorted within each.
2. \`check_identical_failures(login_fn)\` — returns \`True\` when an unknown account and a wrong password produce **identical** return values.
3. \`check_payloads_rejected(login_fn, payloads)\` — returns the list of payloads that **did** authenticate (empty list is the good result).
4. \`check_no_secret_in_output(fn, secret)\` — call \`fn()\` while capturing stdout; return \`True\` when \`secret\` does not appear in it.
5. \`security_suite(login_fn)\` — assemble the three checks above into tests and run them through \`run_tests\`, returning its result.

The given \`login\` passes some of these and fails others — your suite must report that accurately rather than being written to pass.`,
        rubric: [
          "`run_tests` isolates failures and reports reasons",
          "The enumeration check compares full return values",
          "The payload check reports which payloads authenticated",
          "The stdout check actually captures output",
          "`security_suite` reports the given implementation's real state",
        ],
        starter: `import io
import contextlib

USERS = {"ada@example.com": "correct-horse"}


def login(email, password):
    """The implementation under test. Do not modify it."""
    if email not in USERS:
        print(f"auth: no such account {email}")
        return False, "no such account"
    if USERS[email] != password:
        return False, "incorrect password"
    return True, "ok"


def run_tests(tests):
    """Run (name, callable) pairs; return {'passed': [...], 'failed': {...}}."""


def check_identical_failures(login_fn):
    """True when unknown-account and wrong-password results are identical."""


def check_payloads_rejected(login_fn, payloads):
    """Return the payloads that authenticated (empty is good)."""


def check_no_secret_in_output(fn, secret):
    """True when calling fn() prints nothing containing secret."""


def security_suite(login_fn):
    """Run the three checks and report."""


print(security_suite(login))
`,
        stdin: [],
        tests: [
          {
            name: "run_tests isolates and reports",
            code: `def good():
    assert 1 == 1
def bad():
    assert 1 == 2, "one is not two"
def boom():
    raise ValueError("exploded")
got = run_tests([("good", good), ("bad", bad), ("boom", boom)])
assert got["passed"] == ["good"], f"got {got!r}"
assert set(got["failed"]) == {"bad", "boom"}, f"got {got!r}"
assert "one is not two" in got["failed"]["bad"], f"got {got['failed']!r}"
assert "exploded" in got["failed"]["boom"]`,
          },
          {
            name: "run_tests sorts names",
            code: `def ok():
    pass
got = run_tests([("z", ok), ("a", ok), ("m", ok)])
assert got["passed"] == ["a", "m", "z"], f"got {got!r}"`,
          },
          {
            name: "the enumeration check detects distinct failures",
            code: `assert check_identical_failures(login) is False, "this login leaks which accounts exist"

def fixed(email, password):
    if email not in USERS or USERS[email] != password:
        return False, "invalid username or password"
    return True, "ok"

assert check_identical_failures(fixed) is True`,
          },
          {
            name: "the payload check reports what got through",
            code: `payloads = ["' OR '1'='1", "admin'--", "correct-horse"]
assert check_payloads_rejected(login, payloads) == [], f"got {check_payloads_rejected(login, payloads)!r}"

def broken(email, password):
    return True, "ok"

got = check_payloads_rejected(broken, payloads)
assert sorted(got) == sorted(payloads), f"got {got!r}"`,
          },
          {
            name: "the output check captures stdout",
            code: `def leaky():
    print("connecting with password hunter2")
def quiet():
    print("connecting")
assert check_no_secret_in_output(leaky, "hunter2") is False
assert check_no_secret_in_output(quiet, "hunter2") is True`,
          },
          {
            name: "the suite reports the real state of this login",
            code: `got = security_suite(login)
assert set(got) == {"passed", "failed"}, f"got {got!r}"
assert got["failed"], "this implementation has real problems; the suite must report them"
all_names = set(got["passed"]) | set(got["failed"])
assert len(all_names) >= 3, f"expected at least three checks, got {sorted(all_names)}"`,
          },
          {
            name: "the suite passes a fixed implementation",
            code: `def fixed(email, password):
    if email not in USERS or USERS[email] != password:
        return False, "invalid username or password"
    return True, "ok"

got = security_suite(fixed)
assert got["failed"] == {}, f"a correct implementation should pass everything: {got!r}"`,
          },
        ],
        requirements: [
          { kind: "defines", value: "run_tests" },
          { kind: "defines", value: "security_suite" },
          { kind: "no_finding", value: "PY-BARE-EXCEPT" },
        ],
        hints: [
          "`run_tests`: catch `AssertionError` first (using `str(e) or \"assertion failed\"` as the reason), then `Exception` with `f\"{type(e).__name__}: {e}\"`.",
          "`check_identical_failures` must compare the *whole* return value — `login(\"nobody@...\", \"x\") == login(\"ada@...\", \"wrong\")`. Comparing only the boolean would miss the leak in the message.",
          "`check_no_secret_in_output`: `buf = io.StringIO()` then `with contextlib.redirect_stdout(buf): fn()`, and inspect `buf.getvalue()`.",
          "In `security_suite`, wrap each check in a small closure that asserts, so `run_tests` can report it: `lambda: (_ for _ in ()).throw(...)` is unnecessary — a plain `def` with an `assert` reads better.",
        ],
        solution: `import io
import contextlib

USERS = {"ada@example.com": "correct-horse"}

PAYLOADS = ["' OR '1'='1", "admin'--", "' UNION SELECT 1 --", "correct-horse"]


def login(email, password):
    """The implementation under test. Do not modify it."""
    if email not in USERS:
        print(f"auth: no such account {email}")
        return False, "no such account"
    if USERS[email] != password:
        return False, "incorrect password"
    return True, "ok"


def run_tests(tests):
    """Run (name, callable) pairs; return {'passed': [...], 'failed': {...}}."""
    passed, failed = [], {}

    for name, test in tests:
        try:
            test()
        except AssertionError as exc:
            failed[name] = str(exc) or "assertion failed"
        except Exception as exc:                 # reported, never swallowed
            failed[name] = f"{type(exc).__name__}: {exc}"
        else:
            passed.append(name)

    return {"passed": sorted(passed), "failed": failed}


def check_identical_failures(login_fn):
    """True when unknown-account and wrong-password results are identical."""
    unknown = login_fn("nobody@example.com", "whatever")
    wrong = login_fn("ada@example.com", "definitely-wrong")
    return unknown == wrong


def check_payloads_rejected(login_fn, payloads):
    """Return the payloads that authenticated (empty is good)."""
    got_through = []
    for payload in payloads:
        ok, _ = login_fn(payload, payload)
        if ok:
            got_through.append(payload)
    return got_through


def check_no_secret_in_output(fn, secret):
    """True when calling fn() prints nothing containing secret."""
    buffer = io.StringIO()
    with contextlib.redirect_stdout(buffer):
        fn()
    return secret not in buffer.getvalue()


def security_suite(login_fn):
    """Run the three checks and report."""

    def no_enumeration():
        assert check_identical_failures(login_fn), (
            "unknown account and wrong password return different values"
        )

    def payloads_rejected():
        leaked = check_payloads_rejected(login_fn, PAYLOADS)
        assert not leaked, f"these payloads authenticated: {leaked}"

    def no_account_in_output():
        probe = "nobody@example.com"
        assert check_no_secret_in_output(lambda: login_fn(probe, "x"), probe), (
            "the probed account name was printed"
        )

    return run_tests([
        ("no_enumeration", no_enumeration),
        ("payloads_rejected", payloads_rejected),
        ("no_account_in_output", no_account_in_output),
    ])`,
        why: `The suite is written against the *property*, not against the implementation, which is why it reports the given \`login\` as failing and the fixed one as passing without a line changing between the two runs. A test written to pass is a test that proves nothing; these would have caught the enumeration leak the day it was introduced.

\`check_identical_failures\` compares the whole return value rather than just the boolean. Both implementations return \`False\` for a bad login, so a test asserting \`result[0] is False\` passes against the vulnerable version — exactly the "test that cannot fail" from the lesson. The leak lives in the *message*, so the comparison has to include it.

\`check_no_secret_in_output\` captures stdout and asserts on **absence**. Absence assertions are rare and disproportionately valuable: they catch the \`print\` added during debugging, the \`__repr__\` that starts including a new field, and the exception handler that logs the request body. Here it catches \`login\` printing the probed account name — a second, separate enumeration channel in the same function, which the message comparison alone would have missed.

\`run_tests\` distinguishes \`AssertionError\` from every other exception, because they mean different things: an assertion failure is *the property does not hold*, while a \`TypeError\` is *the test is broken*. Collapsing them hides broken tests inside a failure count, and a broken test is a check you believe you have and do not.

The payload list includes \`"correct-horse"\` — a valid password used as a username. It must not authenticate, and including it guards against the implementation that compares the wrong pair of fields, which a list of pure SQL payloads would never reach.`,
      },
      wrapup: `- Three tests per fix: the attack, its neighbourhood, and the happy path.
- Break the fix and watch the test fail, or you do not know what it proves.
- Assert on absence — secrets in logs, payloads in output — not only on presence.
- Distinguish "the property failed" from "the test is broken".`,
      refs: [
        { label: "pytest", url: "https://docs.pytest.org/" },
        { label: "OWASP Web Security Testing Guide", url: "https://owasp.org/www-project-web-security-testing-guide/" },
      ],
    },

    /* ----------------------------------------------------------------- 58 */
    {
      id: "m12l03",
      day: 64,
      title: "Property-based testing and fuzzing",
      minutes: 60,
      secure: "inputs you did not think of",
      cwe: ["CWE-20"],
      tags: ["hypothesis", "fuzzing", "properties", "invariants", "atheris"],
      lede:
        "Example-based tests check the inputs you imagined. Property-based tests state a rule and let a generator spend thousands of attempts trying to break it.",
      blocks: [
        {
          t: "p",
          md: `A {{property}} is a statement that must hold for *all* valid inputs:

- parsing then serialising returns the original (round-trip),
- a validator never raises an unexpected exception type,
- an escaped string never contains an unescaped \`<\`,
- a path builder never returns a path outside its base.

The generator searches for a counterexample, then **shrinks** it to the smallest input that still fails — which is usually what makes the bug obvious.`,
        },
        {
          t: "code",
          label: "example",
          code: `from hypothesis import given, strategies as st

@given(st.text())
def test_escape_never_leaves_angle_brackets(value):
    assert "<" not in escape(value)

@given(st.text(min_size=1, max_size=200))
def test_validator_raises_only_valueerror(value):
    try:
        parse_username(value)
    except ValueError:
        pass                       # the documented failure

@given(st.text(), st.text())
def test_signature_rejects_mismatched_input(body, other):
    assume(body != other)
    sig = sign(body, KEY)
    assert not verify(other, sig, KEY)`,
          cap: "`hypothesis` is the standard tool. The second test is a contract test: the function may fail, but only in the documented way.",
        },
        {
          t: "box",
          kind: "rule",
          title: "Properties worth writing for security code",
          md: `- **Total**: never raises anything but the documented exception type.
- **Idempotent**: \`f(f(x)) == f(x)\` for normalisers and escapers.
- **Confined**: every output path is inside the base directory.
- **Conservative**: a validator never *widens* what it accepts after normalisation.
- **Constant shape**: every failure returns the same value (enumeration resistance).`,
        },
        {
          t: "box",
          kind: "cve",
          title: "What fuzzing finds",
          md: `OSS-Fuzz has found tens of thousands of bugs in open-source C and C++ code. In Python the crash surface is smaller, but fuzzing still finds unhandled exception types, catastrophic regexes, infinite loops, and parsers that disagree with each other — the parser-differential bugs behind many request-smuggling and filter-bypass vulnerabilities.

\`atheris\` is the coverage-guided fuzzer for Python; \`hypothesis\` covers most of the same ground with far less setup.`,
        },
        { t: "h", text: "A generator you can write yourself" },
        {
          t: "p",
          md: `You do not need a library to get most of the value. A loop over a corpus of nasty strings plus a few mutations will find the unhandled \`TypeError\` in a validator this afternoon — which is the exercise below.`,
        },
        {
          t: "code",
          label: "example",
          code: `NASTY = ["", " ", "\\x00", "\\n", "../", "%2e%2e%2f", "<script>",
         "' OR '1'='1", "\\u0430dmin", "a" * 10_000, "\\ufeff", "–"]

def contract_holds(fn, inputs, allowed=(ValueError,)):
    """fn must return, or raise only the allowed types."""
    violations = []
    for value in inputs:
        try:
            fn(value)
        except allowed:
            pass
        except Exception as exc:
            violations.append((value[:40], type(exc).__name__))
    return violations`,
          cap: "An unexpected `TypeError`, `IndexError` or `AttributeError` from a validator is a 500 — and a 500 on a validation path is often an oracle, a resource leak, or both.",
        },
      ],
      quiz: [
        {
          q: "What is shrinking?",
          options: [
            "Compressing the test corpus.",
            "Reducing a failing input to the smallest one that still fails, so the cause is obvious.",
            "Running fewer tests.",
          ],
          answer: 1,
          why: "A 4 000-character counterexample is noise; shrunk to `\"\\x00\"` it is a diagnosis.",
        },
        {
          q: "Which property is worth asserting about a validator?",
          options: [
            "It is fast.",
            "It either returns or raises only its documented exception type — never `TypeError` or `IndexError`.",
            "It accepts all strings.",
          ],
          answer: 1,
          why: "An undocumented exception becomes a 500, and a 500 on a validation path leaks behaviour and may leak a traceback.",
        },
        {
          q: "Why is `f(f(x)) == f(x)` worth testing for a normaliser?",
          options: [
            "Performance.",
            "Non-idempotent normalisation means the checked form and the used form can differ — the Module 2 bypass.",
            "It is required by Unicode.",
          ],
          answer: 1,
          why: "If normalising twice changes the value, some layer downstream sees something the validator never saw.",
        },
      ],
      exercise: {
        title: "A property checker and a corpus",
        brief: `Build the minimum viable fuzzing harness.

1. \`NASTY\` — a module-level list of at least 12 hostile strings, including: empty, whitespace-only, a NUL byte, a newline, \`"../"\`, a percent-encoded traversal, a script tag, a SQL payload, a Cyrillic homoglyph, a 10 000-character string, a BOM, and a right-to-left override.
2. \`mutate(value, *, rounds=3)\` — deterministically derive variants: upper-case, with a trailing newline, doubled, percent-encoded prefix, and truncated to one character. Return a list including the original.
3. \`check_contract(fn, inputs, *, allowed=(ValueError,))\` — call \`fn(value)\` for each input; return a list of \`{"input": <first 40 chars>, "exception": <type name>}\` for every input that raised something outside \`allowed\`. Catch \`Exception\`, not \`BaseException\`.
4. \`check_property(prop, inputs)\` — \`prop\` is a callable returning a bool; return the list of inputs (first 40 chars) for which it returned falsy or raised.
5. \`fuzz(fn, *, allowed=(ValueError,))\` — run \`check_contract\` over \`NASTY\` plus every mutation of it, returning the violations.

Then demonstrate: \`fuzz(parse_tag)\` where \`parse_tag\` is given in the starter and has a genuine bug — your harness must find it.`,
        rubric: [
          "`NASTY` covers the listed categories",
          "`mutate` is deterministic and includes the original",
          "`check_contract` reports only non-allowed exception types",
          "`check_property` reports falsy results and exceptions alike",
          "`fuzz` finds the planted bug in `parse_tag`",
        ],
        starter: `NASTY = []


def parse_tag(value):
    """Buggy on purpose: it is the target of your harness."""
    value = value.strip()
    if len(value) > 20:
        raise ValueError("too long")
    if value[0].isdigit():            # IndexError on an empty string
        raise ValueError("must not start with a digit")
    return value.lower()


def mutate(value, *, rounds=3):
    """Deterministic variants of one input, including the original."""


def check_contract(fn, inputs, *, allowed=(ValueError,)):
    """Report inputs that raised something outside the allowed types."""


def check_property(prop, inputs):
    """Report inputs for which prop returned falsy or raised."""


def fuzz(fn, *, allowed=(ValueError,)):
    """Run the contract check over NASTY and its mutations."""


print(fuzz(parse_tag))
`,
        stdin: [],
        tests: [
          {
            name: "the corpus covers the hostile categories",
            code: `assert len(NASTY) >= 12, f"only {len(NASTY)} entries"
joined = "\\u0001".join(NASTY)
assert "" in NASTY, "include the empty string"
assert any(s.strip() == "" and s for s in NASTY), "include a whitespace-only string"
assert "\\x00" in joined, "include a NUL byte"
assert "\\n" in joined, "include a newline"
assert "../" in joined, "include a traversal"
assert "%2e" in joined.lower(), "include a percent-encoded traversal"
assert "<script" in joined.lower(), "include a script tag"
assert "' OR" in joined or "'1'='1" in joined, "include a SQL payload"
assert "\\u0430" in joined, "include a Cyrillic homoglyph"
assert any(len(s) >= 10_000 for s in NASTY), "include a very long string"
assert "\\ufeff" in joined, "include a BOM"
assert "\\u202e" in joined, "include a right-to-left override"`,
          },
          {
            name: "mutate is deterministic and includes the original",
            code: `a = mutate("abc")
b = mutate("abc")
assert a == b, "mutation must be deterministic"
assert "abc" in a, "the original must be included"
assert len(a) >= 4, f"expected several variants, got {a!r}"
assert any(v.endswith("\\n") for v in a), "include a trailing-newline variant"
assert any(v == "ABC" for v in a), "include an upper-case variant"
assert mutate("") == mutate(""), "empty input must not crash"`,
          },
          {
            name: "check_contract reports only unexpected exceptions",
            code: `def raises_value(v):
    raise ValueError("expected")
def raises_type(v):
    raise TypeError("unexpected")
def fine(v):
    return v
assert check_contract(raises_value, ["a", "b"]) == []
assert check_contract(fine, ["a"]) == []
got = check_contract(raises_type, ["abc"])
assert len(got) == 1 and got[0]["exception"] == "TypeError", f"got {got!r}"
assert got[0]["input"] == "abc", f"got {got!r}"`,
          },
          {
            name: "allowed types are configurable",
            code: `def raises_key(v):
    raise KeyError("k")
assert check_contract(raises_key, ["a"], allowed=(KeyError,)) == []
assert len(check_contract(raises_key, ["a"])) == 1`,
          },
          {
            name: "long inputs are truncated in the report",
            code: `def raises_type(v):
    raise TypeError("x")
got = check_contract(raises_type, ["y" * 500])
assert len(got[0]["input"]) <= 40, f"report entries must be truncated: {len(got[0]['input'])}"`,
          },
          {
            name: "check_property reports falsy and raising inputs",
            code: `got = check_property(lambda v: len(v) < 3, ["a", "abcd", "xy"])
assert got == ["abcd"], f"got {got!r}"
got = check_property(lambda v: v[0] == "a", ["abc", ""])
assert got == [""], f"an exception counts as a failure: {got!r}"`,
          },
          {
            name: "the harness finds the planted bug",
            code: `violations = fuzz(parse_tag)
assert violations, "the harness found nothing; parse_tag crashes on an empty string"
kinds = {v["exception"] for v in violations}
assert "IndexError" in kinds, f"expected an IndexError, got {kinds!r}"`,
          },
          {
            name: "a fixed function fuzzes clean",
            code: `def fixed(value):
    if not isinstance(value, str):
        raise ValueError("must be text")
    value = value.strip()
    if not value or len(value) > 20:
        raise ValueError("bad length")
    if value[0].isdigit():
        raise ValueError("must not start with a digit")
    return value.lower()
assert fuzz(fixed) == [], f"a correct function should fuzz clean: {fuzz(fixed)!r}"`,
          },
        ],
        requirements: [
          { kind: "defines", value: "fuzz" },
          { kind: "defines", value: "check_contract" },
          { kind: "no_finding", value: "PY-BARE-EXCEPT" },
        ],
        hints: [
          "Keep `NASTY` literal and readable — one string per line with a comment saying what it probes. A corpus you can read is a corpus people extend.",
          "`mutate` must handle the empty string: guard the truncation with `value[:1]` rather than `value[0]`.",
          "In `check_contract`, order the clauses `except allowed: pass` then `except Exception as exc: record`. Catching `Exception` first would swallow everything.",
          "`fuzz` is a flat-map: build one list from `NASTY` plus every `mutate(v)` and pass it to `check_contract`.",
        ],
        solution: `NASTY = [
    "",                                  # empty
    "   ",                               # whitespace only
    "\\x00",                              # NUL
    "line\\nbreak",                       # newline (regex anchors, log injection)
    "../../etc/passwd",                  # traversal
    "%2e%2e%2fetc%2fpasswd",             # encoded traversal
    "<script>alert(1)</script>",         # XSS
    "' OR '1'='1",                       # SQL
    "\\u0430dmin",                        # Cyrillic homoglyph
    "a" * 10_000,                        # length
    "\\ufeffbom",                         # byte-order mark
    "abc\\u202edef",                      # right-to-left override
    "{}{}{}",                            # format string
    "-flag",                             # argument injection
]

MAX_REPORT = 40


def parse_tag(value):
    """Buggy on purpose: it is the target of your harness."""
    value = value.strip()
    if len(value) > 20:
        raise ValueError("too long")
    if value[0].isdigit():            # IndexError on an empty string
        raise ValueError("must not start with a digit")
    return value.lower()


def mutate(value, *, rounds=3):
    """Deterministic variants of one input, including the original."""
    return [
        value,
        value.upper(),
        value + "\\n",
        value * 2,
        "%2e" + value,
        value[:1],
    ]


def check_contract(fn, inputs, *, allowed=(ValueError,)):
    """Report inputs that raised something outside the allowed types."""
    violations = []

    for value in inputs:
        try:
            fn(value)
        except allowed:
            pass                                   # the documented failure
        except Exception as exc:                   # noqa: BLE001 - reported
            violations.append({
                "input": value[:MAX_REPORT],
                "exception": type(exc).__name__,
            })

    return violations


def check_property(prop, inputs):
    """Report inputs for which prop returned falsy or raised."""
    failures = []

    for value in inputs:
        try:
            if not prop(value):
                failures.append(value[:MAX_REPORT])
        except Exception:                          # a raise is a failed property
            failures.append(value[:MAX_REPORT])

    return failures


def fuzz(fn, *, allowed=(ValueError,)):
    """Run the contract check over NASTY and its mutations."""
    corpus = []
    for value in NASTY:
        corpus.extend(mutate(value))
    return check_contract(fn, corpus, allowed=allowed)


print(fuzz(parse_tag))`,
        why: `The property being tested is **totality**: \`parse_tag\` must either return a value or raise \`ValueError\`. It does neither for the empty string — \`value[0]\` raises \`IndexError\` — and the harness finds that without anyone having thought about empty input specifically. That is the entire argument for this style of testing: the corpus encodes *categories of hostility*, and the categories catch the cases you did not enumerate.

An undocumented exception from a validator matters more than it first appears. It becomes a 500 rather than a 400, so the caller cannot distinguish "my input was bad" from "the server is broken"; it often reaches an error tracker that captures frame locals, which may include the input; and in a batch loop it ends the batch. A validator that raises only \`ValueError\` is a validator whose failure mode is part of its contract.

\`mutate\` being deterministic is a deliberate limitation. Randomised fuzzing finds more, but a harness whose failures cannot be reproduced on the next run is a harness people stop trusting. For a pre-commit or CI check, deterministic beats thorough — and the moment you want thorough, \`hypothesis\` already does the random search *and* the shrinking.

The corpus entries are the module in miniature: traversal and its encoding (Module 6), homoglyphs (Module 5), SQL and XSS payloads (Modules 5 and 10), a BOM and an RTL override (Module 5), a 10 000-character string (Module 11), and \`-flag\` for argument injection (Module 5). Each one has caused real incidents, which is why the comments naming them belong in the code.

Truncating reported inputs to 40 characters keeps the report readable when the offender is 10 000 characters long — and avoids dumping a payload into a log, which is the same instinct as redacting error messages in Module 4.`,
      },
      wrapup: `- State properties, not examples: totality, idempotence, confinement, constant failure shape.
- A validator that raises an undocumented exception type is a 500 waiting to happen.
- Shrinking is what turns a counterexample into a diagnosis — use \`hypothesis\` when you can.
- A hand-written corpus of hostile strings finds real bugs this afternoon.`,
      refs: [
        { label: "Hypothesis", url: "https://hypothesis.readthedocs.io/" },
        { label: "Atheris — Python fuzzing", url: "https://github.com/google/atheris" },
        { label: "OSS-Fuzz", url: "https://google.github.io/oss-fuzz/" },
      ],
    },

    /* ----------------------------------------------------------------- 59 */
    {
      id: "m12l04",
      day: 65,
      title: "Write your own security linter",
      minutes: 60,
      secure: "enforcing your own rules",
      cwe: ["CWE-1006"],
      tags: ["ast", "linter", "bandit", "semgrep", "static-analysis"],
      lede:
        "This course's auditor is 600 lines of `ast` walking. Your team's specific rules — the ones no off-the-shelf tool knows — are an afternoon of work and catch regressions forever.",
      blocks: [
        {
          t: "p",
          md: `Off-the-shelf tools cover the general rules: \`bandit\` for Python security patterns, \`semgrep\` for syntactic rules across languages, \`ruff\` for speed and lint breadth.

What they cannot know is your codebase's rules: *every database call goes through \`db.safe_query\`*, *no module imports \`internal.secrets\` outside \`config\`*, *every route handler is decorated with \`@require_role\`*. Those are the ones that actually break in your incidents, and they are the easiest to write.`,
        },
        {
          t: "code",
          label: "example",
          code: `import ast

class RequireDecorator(ast.NodeVisitor):
    """Every function named handle_* must carry @require_role."""

    def __init__(self):
        self.findings = []

    def visit_FunctionDef(self, node):
        if node.name.startswith("handle_"):
            names = {
                d.id if isinstance(d, ast.Name) else getattr(d.func, "id", "")
                for d in node.decorator_list
            }
            if "require_role" not in names:
                self.findings.append((node.lineno, node.name))
        self.generic_visit(node)`,
          cap: "`NodeVisitor` dispatches by node type: define `visit_<NodeType>` and it is called. `generic_visit` continues into children — forget it and you only see the top level.",
        },
        {
          t: "box",
          kind: "rule",
          title: "Why AST and not regex",
          md: `A regex cannot tell code from a string, a comment or a docstring. \`grep "eval("\` matches a comment saying *never use eval(* and misses \`e = eval; e(x)\`.

An AST sees structure: this is a \`Call\` whose \`func\` resolves to the builtin \`eval\`, and that other thing is a \`Constant\` of type \`str\`. The false-positive rate is what decides whether a linter stays switched on.`,
        },
        {
          t: "table",
          head: ["Node", "Matches"],
          rows: [
            ["`ast.Call`", "`f(x)` — `.func`, `.args`, `.keywords`"],
            ["`ast.Attribute`", "`a.b` — `.value`, `.attr`"],
            ["`ast.Name`", "a bare identifier — `.id`"],
            ["`ast.Constant`", "a literal — `.value`"],
            ["`ast.Assign`", "`x = y` — `.targets`, `.value`"],
            ["`ast.FunctionDef`", "`.name`, `.args`, `.decorator_list`, `.body`"],
            ["`ast.ImportFrom`", "`.module`, `.names`"],
            ["`ast.Try` / `ast.ExceptHandler`", "`.type`, `.body`"],
          ],
        },
        {
          t: "box",
          kind: "good",
          title: "Make findings actionable",
          md: `A finding needs: **file, line, rule id, severity, one sentence of why, and the fix**. That is the format this course's auditor uses, and it is the difference between a tool people run and a tool people mute.

Add a suppression mechanism (\`# noqa: RULE-ID\`) from the start. Without one, the first false positive gets the whole linter disabled.`,
        },
        {
          t: "box",
          kind: "warn",
          title: "What static analysis cannot see",
          md: `Aliasing (\`f = eval\`), dynamic dispatch, values arriving at runtime, and anything crossing a process boundary. A clean linter run means *these specific patterns are absent*, never *this code is secure*.

Say that in the output. A tool that implies more coverage than it has ends investigations that should have continued.`,
        },
      ],
      quiz: [
        {
          q: "Why is `grep -r 'eval('` a poor security check?",
          options: [
            "It is slow.",
            "It cannot distinguish code from comments or strings, and misses aliased or indirect calls.",
            "`eval` is always safe.",
          ],
          answer: 1,
          why: "Both false positives and false negatives. The AST knows the difference between a call and a mention.",
        },
        {
          q: "You forget `generic_visit` in a `visit_FunctionDef`. What happens?",
          options: [
            "Nothing.",
            "Children of that function are never visited, so nested code is silently unchecked.",
            "A RecursionError.",
          ],
          answer: 1,
          why: "A silently incomplete scan is the worst failure mode for a linter — it reports clean while skipping the code you cared about.",
        },
        {
          q: "Why ship a suppression comment mechanism?",
          options: [
            "To let people ignore findings.",
            "Because the first false positive otherwise gets the entire linter disabled.",
            "It is required by CI.",
          ],
          answer: 1,
          why: "A targeted, reviewable suppression keeps the other 200 rules running.",
        },
      ],
      exercise: {
        title: "A linter for your team's rules",
        brief: `Write \`lint(source, *, filename="<input>")\` returning findings sorted by line, each \`{"line", "rule", "severity", "message", "fix"}\`.

Rules:

| rule | severity | fires when |
|---|---|---|
| \`"NO-EVAL"\` | \`"critical"\` | a call to \`eval\`, \`exec\` or \`compile\` |
| \`"DB-DIRECT"\` | \`"high"\` | a call to \`.execute(\` on anything **other** than an object named \`safe_db\` (your team's wrapper) |
| \`"HANDLER-AUTH"\` | \`"high"\` | a function named \`handle_*\` without a \`require_role\` decorator (bare or called) |
| \`"SWALLOW"\` | \`"medium"\` | an \`except\` block whose body is only \`pass\` |
| \`"SECRET-IMPORT"\` | \`"medium"\` | \`from internal.secrets import ...\` or \`import internal.secrets\` anywhere |

Also:

- \`# noqa\` on a line suppresses **all** findings for that line; \`# noqa: RULE-ID\` suppresses only that rule.
- A \`SyntaxError\` returns a single finding \`{"line": <lineno>, "rule": "SYNTAX", "severity": "critical", ...}\`.
- \`report(findings, filename)\` returns a text block: a header \`"<filename>: <n> findings (<c> critical, <h> high, <m> medium)"\` then one line per finding as \`"  <line>:<rule> [<severity>] <message>"\`.`,
        rubric: [
          "Each rule fires on its pattern and not on the clean equivalent",
          "`safe_db.execute` is permitted; `cursor.execute` is not",
          "Decorator detection handles both `@require_role` and `@require_role(\"admin\")`",
          "`# noqa` and `# noqa: RULE` suppress correctly",
          "Syntax errors are reported, not raised",
          "The report counts by severity",
        ],
        starter: `import ast

SEVERITY_ORDER = {"critical": 0, "high": 1, "medium": 2}

FIXES = {
    "NO-EVAL": "parse instead of execute: int(), json.loads(), or a dispatch dict",
    "DB-DIRECT": "route the query through safe_db.execute()",
    "HANDLER-AUTH": "add @require_role to the handler",
    "SWALLOW": "log and re-raise, or return an explicit failure",
    "SECRET-IMPORT": "read secrets through config, not directly",
}


def lint(source, *, filename="<input>"):
    """Return findings sorted by line."""


def report(findings, filename):
    """Render findings as text."""


SAMPLE = '''
import ast
from internal.secrets import TOKEN

def handle_delete(request):
    cursor.execute("DELETE FROM docs WHERE id = " + request["id"])
    try:
        audit(request)
    except Exception:
        pass

@require_role("admin")
def handle_list(request):
    return safe_db.execute("SELECT * FROM docs", ())
'''
print(report(lint(SAMPLE, filename="api.py"), "api.py"))
`,
        stdin: [],
        tests: [
          {
            name: "eval, exec and compile are critical",
            code: `got = lint("x = eval(raw)\\ny = exec(raw)\\nz = compile(raw, 'f', 'exec')\\n")
assert len(got) == 3, f"got {got!r}"
assert all(f["rule"] == "NO-EVAL" and f["severity"] == "critical" for f in got), f"got {got!r}"
assert [f["line"] for f in got] == [1, 2, 3]
assert lint("x = int(raw)\\n") == []`,
          },
          {
            name: "direct database access is flagged, the wrapper is not",
            code: `got = lint("cursor.execute('SELECT 1')\\n")
assert len(got) == 1 and got[0]["rule"] == "DB-DIRECT", f"got {got!r}"
assert lint("safe_db.execute('SELECT 1', ())\\n") == [], "the team wrapper is permitted"
got = lint("conn.cursor().execute('SELECT 1')\\n")
assert len(got) == 1, f"chained calls should still be caught: {got!r}"`,
          },
          {
            name: "handlers must carry the decorator",
            code: `bad = "def handle_delete(request):\\n    return 1\\n"
got = lint(bad)
assert len(got) == 1 and got[0]["rule"] == "HANDLER-AUTH", f"got {got!r}"
for ok in ("@require_role\\ndef handle_x(r):\\n    return 1\\n",
           "@require_role('admin')\\ndef handle_y(r):\\n    return 1\\n"):
    assert lint(ok) == [], f"{ok!r} should be clean: {lint(ok)!r}"
assert lint("def helper(r):\\n    return 1\\n") == [], "only handle_* functions are checked"`,
          },
          {
            name: "swallowed exceptions and secret imports",
            code: `got = lint("try:\\n    f()\\nexcept Exception:\\n    pass\\n")
assert len(got) == 1 and got[0]["rule"] == "SWALLOW" and got[0]["severity"] == "medium", f"got {got!r}"
assert lint("try:\\n    f()\\nexcept ValueError:\\n    raise\\n") == []
for src in ("from internal.secrets import TOKEN\\n", "import internal.secrets\\n"):
    got = lint(src)
    assert len(got) == 1 and got[0]["rule"] == "SECRET-IMPORT", f"{src!r}: got {got!r}"
assert lint("from config import TOKEN\\n") == []`,
          },
          {
            name: "noqa suppresses",
            code: `assert lint("x = eval(raw)  # noqa\\n") == []
assert lint("x = eval(raw)  # noqa: NO-EVAL\\n") == []
got = lint("x = eval(raw)  # noqa: DB-DIRECT\\n")
assert len(got) == 1 and got[0]["rule"] == "NO-EVAL", f"a different rule must still fire: {got!r}"`,
          },
          {
            name: "syntax errors are reported",
            code: `got = lint("def broken(:\\n")
assert len(got) == 1, f"got {got!r}"
assert got[0]["rule"] == "SYNTAX" and got[0]["severity"] == "critical", f"got {got!r}"
assert isinstance(got[0]["line"], int)`,
          },
          {
            name: "findings carry a fix and are sorted",
            code: `got = lint(SAMPLE)
assert got, "the sample has several problems"
assert [f["line"] for f in got] == sorted(f["line"] for f in got), f"not sorted: {got!r}"
assert all(f["fix"] for f in got), "every finding needs a fix"
rules = {f["rule"] for f in got}
assert {"DB-DIRECT", "HANDLER-AUTH", "SWALLOW", "SECRET-IMPORT"} <= rules, f"got {rules!r}"`,
          },
          {
            name: "the report counts by severity",
            code: `out = report(lint(SAMPLE), "api.py")
lines = out.splitlines()
assert lines[0].startswith("api.py: "), f"got {lines[0]!r}"
assert "critical" in lines[0] and "high" in lines[0] and "medium" in lines[0], f"got {lines[0]!r}"
assert len(lines) == len(lint(SAMPLE)) + 1, f"expected one line per finding: {out!r}"
assert report([], "x.py").splitlines()[0] == "x.py: 0 findings (0 critical, 0 high, 0 medium)"`,
          },
        ],
        requirements: [
          { kind: "defines", value: "lint" },
          { kind: "defines", value: "report" },
          { kind: "uses_module", value: "ast" },
        ],
        hints: [
          "Collect the source lines up front so the `# noqa` check is a simple lookup by line number at the end — filter once, rather than checking inside every rule.",
          "For `DB-DIRECT`, match `ast.Call` whose `func` is an `ast.Attribute` with `attr == \"execute\"`, then exclude the case where `func.value` is a `Name` with `id == \"safe_db\"`.",
          "Decorators are either `ast.Name` (bare) or `ast.Call` whose `.func` is a `Name`. Handle both when collecting the names.",
          "Remember `self.generic_visit(node)` at the end of every visitor method, or nested functions and nested try blocks are never examined.",
        ],
        solution: `import ast

SEVERITY_ORDER = {"critical": 0, "high": 1, "medium": 2}

FIXES = {
    "NO-EVAL": "parse instead of execute: int(), json.loads(), or a dispatch dict",
    "DB-DIRECT": "route the query through safe_db.execute()",
    "HANDLER-AUTH": "add @require_role to the handler",
    "SWALLOW": "log and re-raise, or return an explicit failure",
    "SECRET-IMPORT": "read secrets through config, not directly",
}

MESSAGES = {
    "NO-EVAL": "runtime data must never reach eval/exec/compile",
    "DB-DIRECT": "database access must go through the safe_db wrapper",
    "HANDLER-AUTH": "request handler has no role check",
    "SWALLOW": "exception silently discarded",
    "SECRET-IMPORT": "secrets module imported outside config",
}


class Linter(ast.NodeVisitor):
    def __init__(self):
        self.findings = []

    def add(self, node, rule, severity):
        self.findings.append({
            "line": getattr(node, "lineno", 0),
            "rule": rule,
            "severity": severity,
            "message": MESSAGES[rule],
            "fix": FIXES[rule],
        })

    # -- rules ------------------------------------------------------------
    def visit_Call(self, node):
        func = node.func

        if isinstance(func, ast.Name) and func.id in ("eval", "exec", "compile"):
            self.add(node, "NO-EVAL", "critical")

        if isinstance(func, ast.Attribute) and func.attr == "execute":
            wrapper = isinstance(func.value, ast.Name) and func.value.id == "safe_db"
            if not wrapper:
                self.add(node, "DB-DIRECT", "high")

        self.generic_visit(node)

    def visit_FunctionDef(self, node):
        if node.name.startswith("handle_"):
            names = set()
            for decorator in node.decorator_list:
                if isinstance(decorator, ast.Name):
                    names.add(decorator.id)
                elif isinstance(decorator, ast.Call) and isinstance(decorator.func, ast.Name):
                    names.add(decorator.func.id)
            if "require_role" not in names:
                self.add(node, "HANDLER-AUTH", "high")
        self.generic_visit(node)

    def visit_ExceptHandler(self, node):
        if len(node.body) == 1 and isinstance(node.body[0], ast.Pass):
            self.add(node, "SWALLOW", "medium")
        self.generic_visit(node)

    def visit_ImportFrom(self, node):
        if (node.module or "").startswith("internal.secrets"):
            self.add(node, "SECRET-IMPORT", "medium")
        self.generic_visit(node)

    def visit_Import(self, node):
        for alias in node.names:
            if alias.name.startswith("internal.secrets"):
                self.add(node, "SECRET-IMPORT", "medium")
        self.generic_visit(node)


def _suppressed(line_text, rule):
    """Honour '# noqa' and '# noqa: RULE-ID'."""
    if "# noqa" not in line_text:
        return False
    _, _, rest = line_text.partition("# noqa")
    rest = rest.strip()
    if not rest.startswith(":"):
        return True                                  # bare noqa suppresses everything
    return rule in {part.strip() for part in rest[1:].split(",")}


def lint(source, *, filename="<input>"):
    """Return findings sorted by line."""
    try:
        tree = ast.parse(source)
    except SyntaxError as exc:
        return [{
            "line": exc.lineno or 1,
            "rule": "SYNTAX",
            "severity": "critical",
            "message": f"could not parse: {exc.msg}",
            "fix": "fix the syntax error before linting",
        }]

    linter = Linter()
    linter.visit(tree)

    lines = source.splitlines()
    kept = []
    for finding in linter.findings:
        index = finding["line"] - 1
        text = lines[index] if 0 <= index < len(lines) else ""
        if not _suppressed(text, finding["rule"]):
            kept.append(finding)

    kept.sort(key=lambda f: (f["line"], SEVERITY_ORDER.get(f["severity"], 9), f["rule"]))
    return kept


def report(findings, filename):
    """Render findings as text."""
    counts = {"critical": 0, "high": 0, "medium": 0}
    for finding in findings:
        if finding["severity"] in counts:
            counts[finding["severity"]] += 1

    header = (f"{filename}: {len(findings)} findings "
              f"({counts['critical']} critical, {counts['high']} high, {counts['medium']} medium)")
    body = [f"  {f['line']}:{f['rule']} [{f['severity']}] {f['message']}" for f in findings]
    return "\\n".join([header] + body)


SAMPLE = '''
import ast
from internal.secrets import TOKEN

def handle_delete(request):
    cursor.execute("DELETE FROM docs WHERE id = " + request["id"])
    try:
        audit(request)
    except Exception:
        pass

@require_role("admin")
def handle_list(request):
    return safe_db.execute("SELECT * FROM docs", ())
'''
print(report(lint(SAMPLE, filename="api.py"), "api.py"))`,
        why: `The suppression filter runs **after** the walk, as a single pass over the collected findings. Checking \`# noqa\` inside each rule would mean five places to get it wrong and five places to update when the syntax changes; here it is one function with one test.

That suppression mechanism is not a convenience — it is what keeps the linter installed. A rule with a 2% false-positive rate across a large codebase produces dozens of wrong findings, and the fastest path for an engineer under deadline is to delete the whole check from CI. A targeted \`# noqa: DB-DIRECT\` with a code-review conversation attached keeps the other four rules running.

\`DB-DIRECT\` is the rule that justifies the exercise. No off-the-shelf tool knows that your team routes queries through \`safe_db\`, and that single convention — once enforced mechanically — eliminates SQL injection from the codebase more reliably than reviewing every \`execute\` call forever. The same shape applies to \`@require_role\` on handlers: a naming convention plus a linter turns "remember to add the decorator" into a build failure.

Every visitor ends with \`generic_visit\`, which is the easiest thing to omit and the most damaging. Without it a nested handler, a \`try\` inside a function, or a call inside a comprehension is never examined — and the linter reports clean, which is worse than reporting nothing.

The honest limitation belongs in the tool's documentation: this sees patterns, not behaviour. \`run = eval\` then \`run(x)\` passes, as does any call through a variable, a dictionary or a framework's dispatch. A clean run means *these five patterns are absent from this file*, and saying exactly that is what stops a green CI badge from ending an investigation early.`,
      },
      wrapup: `- Your team's conventions are the rules no vendor tool knows, and the easiest to enforce.
- \`ast\` distinguishes code from comments and strings; regex cannot.
- Every visitor needs \`generic_visit\`, or the scan is silently incomplete.
- Ship suppression from day one, and state what the tool cannot see.`,
      refs: [
        { label: "ast — abstract syntax trees", url: "https://docs.python.org/3/library/ast.html" },
        { label: "Bandit", url: "https://bandit.readthedocs.io/" },
        { label: "Semgrep", url: "https://semgrep.dev/" },
      ],
    },

    /* ----------------------------------------------------------------- 60 */
    {
      id: "m12l05",
      day: 66,
      title: "Capstone: audit an application",
      minutes: 60,
      secure: "the whole discipline",
      cwe: ["CWE-1006"],
      tags: ["capstone", "audit", "review", "report", "threat-model"],
      lede:
        "Sixty days of rules, applied to code you did not write: find the defects, rank them by what an attacker gains, and report them so a team can act this week.",
      blocks: [
        {
          t: "h",
          text: "How to read unfamiliar code for security",
        },
        {
          t: "p",
          md: `Do not start at line 1. Start at the **boundaries**, because that is where untrusted data enters and where damage exits.

1. **Find the inputs.** \`input()\`, request handlers, file reads, environment, queue messages, database rows.
2. **Find the sinks.** \`subprocess\`, \`execute\`, \`open\`, \`eval\`, \`pickle\`, template rendering, outbound HTTP, response bodies.
3. **Trace input to sink.** Every path from an input to a sink without validation in between is a finding.
4. **Check the decisions.** Every \`if\` that grants something: what happens when it falls through?
5. **Check the secrets.** Where do they come from, where do they go, who can read the output?`,
        },
        {
          t: "table",
          head: ["Severity", "Means", "Examples"],
          rows: [
            ["**critical**", "Remote code execution, or full data compromise", "`eval` on input, `pickle.loads`, SQL injection, `shell=True`"],
            ["**high**", "Cross-tenant access, credential disclosure, auth bypass", "IDOR, hardcoded secret, `verify=False`, SSRF"],
            ["**medium**", "Information disclosure, DoS, weakened control", "Enumeration, secret in logs, ReDoS, missing rate limit"],
            ["**low**", "Hardening gaps", "Missing timeout, weak error handling, no CSP"],
          ],
        },
        {
          t: "box",
          kind: "rule",
          title: "What a finding must contain",
          md: `- **Where** — file and line.
- **What** — the defect in one sentence, with its CWE.
- **So what** — what an attacker achieves. This is the field that gets the ticket prioritised, and the one most reports omit.
- **Fix** — the specific change, ideally the diff.
- **Proof** — a test that fails before and passes after.

A report without the "so what" is a list of opinions. A report without the fix is homework for the person who has least context.`,
        },
        {
          t: "box",
          kind: "good",
          title: "Lead with the highest-leverage change",
          md: `Fifteen findings across eight files usually have two or three root causes: no input validation layer, no object-level authorisation, queries built by formatting. Say that first.

*"Routing all four handlers through a single \`parse_request\` closes six of the fifteen"* is the sentence that gets the work scheduled.`,
        },
      ],
      quiz: [
        {
          q: "Where do you start when auditing unfamiliar code?",
          options: [
            "Line 1, reading forward.",
            "At the boundaries — inputs and sinks — then trace the paths between them.",
            "The test suite.",
          ],
          answer: 1,
          why: "Vulnerabilities live on the path from untrusted input to a dangerous operation. Find both ends first.",
        },
        {
          q: "Which field do security reports most often omit, and most need?",
          options: [
            "The line number.",
            "What an attacker actually achieves — the impact that justifies the priority.",
            "The CWE id.",
          ],
          answer: 1,
          why: "Without impact, every finding looks the same and the list gets triaged by whoever shouts loudest.",
        },
        {
          q: "You find eleven issues with three root causes. What leads the report?",
          options: [
            "The eleven findings in file order.",
            "The root causes and the single change that fixes the most.",
            "The easiest fixes.",
          ],
          answer: 1,
          why: "Reports are read by people deciding what to schedule. Give them the leverage first.",
        },
      ],
      exercise: {
        title: "audit(): find, rank and report",
        brief: `Write an auditor for a small application's source, returning findings ranked by severity.

\`audit(source, *, filename="app.py")\` returns a list of \`{"line", "rule", "severity", "cwe", "impact", "fix"}\`, sorted by severity (critical → high → medium → low) then line.

Detect, using \`ast\`:

| rule | severity | CWE | fires on |
|---|---|---|---|
| \`"RCE-EVAL"\` | critical | CWE-95 | \`eval\`/\`exec\` call |
| \`"RCE-PICKLE"\` | critical | CWE-502 | \`pickle.loads\`/\`pickle.load\` |
| \`"SQLI"\` | critical | CWE-89 | \`.execute(...)\` whose first argument is an f-string, a `+` concatenation, or a \`%\` |
| \`"CMD-SHELL"\` | critical | CWE-78 | \`os.system\`/\`os.popen\`, or \`subprocess.*\` with \`shell=True\` |
| \`"SECRET"\` | high | CWE-798 | a string literal assigned to a name matching \`password/secret/token/api_key\` |
| \`"TLS-OFF"\` | high | CWE-295 | \`verify=False\` in any call |
| \`"SWALLOW"\` | medium | CWE-390 | \`except ...: pass\` |
| \`"NO-TIMEOUT"\` | low | CWE-400 | a \`requests.*\` call with no \`timeout\` keyword |

Then \`summarise(findings)\` returning \`{"critical": n, "high": n, "medium": n, "low": n}\`, and \`top_fix(findings)\` returning the rule id with the most findings (ties broken by severity, then alphabetically) — the highest-leverage change.`,
        rubric: [
          "Every rule fires on its pattern and stays quiet on the fixed form",
          "Findings carry a CWE, an impact and a fix",
          "Sorting is severity-then-line and deterministic",
          "`summarise` counts all four levels",
          "`top_fix` identifies the most frequent rule",
        ],
        starter: `import ast

SEVERITY_ORDER = {"critical": 0, "high": 1, "medium": 2, "low": 3}

RULES = {
    "RCE-EVAL": ("critical", "CWE-95", "runs attacker-supplied code with the process's privileges",
                 "parse instead: int(), json.loads(), or a dispatch dict"),
    "RCE-PICKLE": ("critical", "CWE-502", "deserialising untrusted bytes executes arbitrary code",
                   "use json.loads for data crossing a trust boundary"),
    "SQLI": ("critical", "CWE-89", "attacker controls the query grammar: full read and write of the database",
             "use placeholders: cur.execute(sql, (value,))"),
    "CMD-SHELL": ("critical", "CWE-78", "shell metacharacters in input become commands",
                  "subprocess.run([prog, arg], shell=False)"),
    "SECRET": ("high", "CWE-798", "the credential is in every clone, backup and image, and cannot be rotated",
               "read it from the environment or a mounted secret at runtime"),
    "TLS-OFF": ("high", "CWE-295", "any host on the path can read and rewrite the traffic",
                "remove verify=False; point verify at the CA bundle if needed"),
    "SWALLOW": ("medium", "CWE-390", "a failed security check continues as though it succeeded",
                "log and re-raise, or return an explicit failure"),
    "NO-TIMEOUT": ("low", "CWE-400", "one slow upstream holds a worker indefinitely",
                   "pass timeout=(connect, read) on every call"),
}

SECRET_NAMES = ("password", "passwd", "secret", "token", "api_key", "apikey")


def audit(source, *, filename="app.py"):
    """Return ranked findings for one source file."""


def summarise(findings):
    """Count findings by severity."""


def top_fix(findings):
    """The rule id with the most findings."""


VULNERABLE = '''
import os, pickle, requests

API_TOKEN = "sk-live-9f2b41ccd8e7"

def handle(request, cur):
    cur.execute("SELECT * FROM docs WHERE id = " + request["id"])
    os.system("convert " + request["file"])
    data = pickle.loads(request["blob"])
    r = requests.get(request["url"], verify=False)
    try:
        verify_signature(request)
    except Exception:
        pass
    return eval(request["expr"])
'''
for f in audit(VULNERABLE):
    print(f["severity"], f["line"], f["rule"], "-", f["impact"])
print(summarise(audit(VULNERABLE)), top_fix(audit(VULNERABLE)))
`,
        stdin: [],
        tests: [
          {
            name: "the vulnerable sample is fully diagnosed",
            code: `got = audit(VULNERABLE)
rules = {f["rule"] for f in got}
expected = {"RCE-EVAL", "RCE-PICKLE", "SQLI", "CMD-SHELL", "SECRET", "TLS-OFF", "SWALLOW"}
assert expected <= rules, f"missed {expected - rules}"`,
          },
          {
            name: "findings carry impact, fix and CWE",
            code: `for f in audit(VULNERABLE):
    assert f["cwe"].startswith("CWE-"), f"got {f!r}"
    assert len(f["impact"]) > 20, f"impact too thin: {f!r}"
    assert len(f["fix"]) > 10, f"fix too thin: {f!r}"
    assert isinstance(f["line"], int) and f["line"] > 0`,
          },
          {
            name: "ranked by severity then line",
            code: `got = audit(VULNERABLE)
keys = [(SEVERITY_ORDER[f["severity"]], f["line"]) for f in got]
assert keys == sorted(keys), f"not ranked: {keys!r}"
assert got[0]["severity"] == "critical", f"criticals must lead: {got[0]!r}"`,
          },
          {
            name: "sql injection detection covers the three shapes",
            code: `for src in ('cur.execute("SELECT * FROM t WHERE a = " + x)\\n',
            'cur.execute(f"SELECT * FROM t WHERE a = {x}")\\n',
            'cur.execute("SELECT * FROM t WHERE a = %s" % x)\\n'):
    got = [f for f in audit(src) if f["rule"] == "SQLI"]
    assert len(got) == 1, f"{src!r}: got {got!r}"
assert [f for f in audit('cur.execute("SELECT 1", (x,))\\n') if f["rule"] == "SQLI"] == []`,
          },
          {
            name: "shell detection covers both forms",
            code: `for src in ('import os\\nos.system(cmd)\\n',
            'import subprocess\\nsubprocess.run(cmd, shell=True)\\n',
            'import os\\nos.popen(cmd)\\n'):
    got = [f for f in audit(src) if f["rule"] == "CMD-SHELL"]
    assert len(got) == 1, f"{src!r}: got {got!r}"
assert [f for f in audit('import subprocess\\nsubprocess.run(["ls"], check=True)\\n')
        if f["rule"] == "CMD-SHELL"] == []`,
          },
          {
            name: "secrets and TLS",
            code: `assert [f for f in audit('API_TOKEN = "sk-live-abc123"\\n') if f["rule"] == "SECRET"]
assert [f for f in audit('import os\\nAPI_TOKEN = os.environ["T"]\\n') if f["rule"] == "SECRET"] == []
assert [f for f in audit('r = requests.get(u, verify=False, timeout=5)\\n') if f["rule"] == "TLS-OFF"]
assert [f for f in audit('r = requests.get(u, timeout=5)\\n') if f["rule"] == "TLS-OFF"] == []`,
          },
          {
            name: "timeouts are low severity",
            code: `got = [f for f in audit('import requests\\nr = requests.get(u)\\n') if f["rule"] == "NO-TIMEOUT"]
assert len(got) == 1 and got[0]["severity"] == "low", f"got {got!r}"
assert [f for f in audit('import requests\\nr = requests.get(u, timeout=(3, 10))\\n')
        if f["rule"] == "NO-TIMEOUT"] == []`,
          },
          {
            name: "clean code audits clean, broken code does not crash",
            code: `clean = ('import json, subprocess, requests, os\\n'
         'TOKEN = os.environ["TOKEN"]\\n'
         'def handle(request, cur):\\n'
         '    cur.execute("SELECT * FROM docs WHERE id = ?", (request["id"],))\\n'
         '    subprocess.run(["convert", request["file"]], check=True)\\n'
         '    data = json.loads(request["blob"])\\n'
         '    r = requests.get("https://api.example.com", timeout=(3, 10))\\n'
         '    try:\\n'
         '        verify_signature(request)\\n'
         '    except ValueError:\\n'
         '        raise\\n'
         '    return int(request["expr"])\\n')
assert audit(clean) == [], f"false positives: {audit(clean)!r}"
assert audit("def broken(:") == [], "a syntax error should produce no findings, not an exception"`,
          },
          {
            name: "summary and leverage",
            code: `got = audit(VULNERABLE)
s = summarise(got)
assert set(s) == {"critical", "high", "medium", "low"}, f"got {s!r}"
assert s["critical"] >= 4, f"got {s!r}"
assert sum(s.values()) == len(got)
assert summarise([]) == {"critical": 0, "high": 0, "medium": 0, "low": 0}
assert top_fix(got) in {f["rule"] for f in got}
assert top_fix([]) is None`,
          },
        ],
        requirements: [
          { kind: "defines", value: "audit" },
          { kind: "defines", value: "summarise" },
          { kind: "defines", value: "top_fix" },
          { kind: "uses_module", value: "ast" },
        ],
        hints: [
          "Build one `NodeVisitor` with `visit_Call`, `visit_Assign` and `visit_ExceptHandler`, and a small `add(node, rule)` that pulls severity, CWE, impact and fix from the `RULES` table.",
          "For the SQL shapes: `isinstance(arg, ast.JoinedStr)` is an f-string; `ast.BinOp` with `ast.Add` or `ast.Mod` covers concatenation and `%`.",
          "`verify=False` is a keyword whose value is `ast.Constant` with `value is False` — check `node.keywords`.",
          "`top_fix`: use `collections.Counter` over the rule ids, then sort by `(-count, SEVERITY_ORDER[severity], rule)` and take the first.",
        ],
        solution: `import ast
from collections import Counter

SEVERITY_ORDER = {"critical": 0, "high": 1, "medium": 2, "low": 3}

RULES = {
    "RCE-EVAL": ("critical", "CWE-95", "runs attacker-supplied code with the process's privileges",
                 "parse instead: int(), json.loads(), or a dispatch dict"),
    "RCE-PICKLE": ("critical", "CWE-502", "deserialising untrusted bytes executes arbitrary code",
                   "use json.loads for data crossing a trust boundary"),
    "SQLI": ("critical", "CWE-89", "attacker controls the query grammar: full read and write of the database",
             "use placeholders: cur.execute(sql, (value,))"),
    "CMD-SHELL": ("critical", "CWE-78", "shell metacharacters in input become commands",
                  "subprocess.run([prog, arg], shell=False)"),
    "SECRET": ("high", "CWE-798", "the credential is in every clone, backup and image, and cannot be rotated",
               "read it from the environment or a mounted secret at runtime"),
    "TLS-OFF": ("high", "CWE-295", "any host on the path can read and rewrite the traffic",
                "remove verify=False; point verify at the CA bundle if needed"),
    "SWALLOW": ("medium", "CWE-390", "a failed security check continues as though it succeeded",
                "log and re-raise, or return an explicit failure"),
    "NO-TIMEOUT": ("low", "CWE-400", "one slow upstream holds a worker indefinitely",
                   "pass timeout=(connect, read) on every call"),
}

SECRET_NAMES = ("password", "passwd", "secret", "token", "api_key", "apikey")
HTTP_VERBS = ("get", "post", "put", "delete", "head", "patch", "request")


def _dotted(node):
    parts = []
    while isinstance(node, ast.Attribute):
        parts.append(node.attr)
        node = node.value
    if isinstance(node, ast.Name):
        parts.append(node.id)
        return ".".join(reversed(parts))
    return ""


def _is_built(node):
    """True for an f-string, a concatenation or a % format."""
    if isinstance(node, ast.JoinedStr):
        return True
    return isinstance(node, ast.BinOp) and isinstance(node.op, (ast.Add, ast.Mod))


class Auditor(ast.NodeVisitor):
    def __init__(self):
        self.findings = []

    def add(self, node, rule):
        severity, cwe, impact, fix = RULES[rule]
        self.findings.append({
            "line": getattr(node, "lineno", 0),
            "rule": rule,
            "severity": severity,
            "cwe": cwe,
            "impact": impact,
            "fix": fix,
        })

    def visit_Call(self, node):
        target = _dotted(node.func)
        attr = node.func.attr if isinstance(node.func, ast.Attribute) else ""
        first = node.args[0] if node.args else None

        if target in ("eval", "exec"):
            self.add(node, "RCE-EVAL")
        if target in ("pickle.loads", "pickle.load"):
            self.add(node, "RCE-PICKLE")
        if target in ("os.system", "os.popen"):
            self.add(node, "CMD-SHELL")

        if target.startswith("subprocess."):
            for keyword in node.keywords:
                if keyword.arg == "shell" and isinstance(keyword.value, ast.Constant) \\
                        and keyword.value.value is True:
                    self.add(node, "CMD-SHELL")

        if attr in ("execute", "executemany") and first is not None and _is_built(first):
            self.add(node, "SQLI")

        for keyword in node.keywords:
            if keyword.arg == "verify" and isinstance(keyword.value, ast.Constant) \\
                    and keyword.value.value is False:
                self.add(node, "TLS-OFF")

        if target.startswith("requests.") and target.split(".")[-1] in HTTP_VERBS:
            if not any(k.arg == "timeout" for k in node.keywords):
                self.add(node, "NO-TIMEOUT")

        self.generic_visit(node)

    def visit_Assign(self, node):
        if isinstance(node.value, ast.Constant) and isinstance(node.value.value, str):
            for target in node.targets:
                name = target.id if isinstance(target, ast.Name) else ""
                if name and any(s in name.lower() for s in SECRET_NAMES):
                    if len(node.value.value) >= 4:
                        self.add(node, "SECRET")
        self.generic_visit(node)

    def visit_ExceptHandler(self, node):
        if len(node.body) == 1 and isinstance(node.body[0], ast.Pass):
            self.add(node, "SWALLOW")
        self.generic_visit(node)


def audit(source, *, filename="app.py"):
    """Return ranked findings for one source file."""
    try:
        tree = ast.parse(source)
    except SyntaxError:
        return []

    auditor = Auditor()
    auditor.visit(tree)
    auditor.findings.sort(key=lambda f: (SEVERITY_ORDER[f["severity"]], f["line"], f["rule"]))
    return auditor.findings


def summarise(findings):
    """Count findings by severity."""
    counts = {"critical": 0, "high": 0, "medium": 0, "low": 0}
    for finding in findings:
        if finding["severity"] in counts:
            counts[finding["severity"]] += 1
    return counts


def top_fix(findings):
    """The rule id with the most findings."""
    if not findings:
        return None

    counts = Counter(f["rule"] for f in findings)
    worst = {f["rule"]: SEVERITY_ORDER[f["severity"]] for f in findings}
    return sorted(counts, key=lambda rule: (-counts[rule], worst[rule], rule))[0]


VULNERABLE = '''
import os, pickle, requests

API_TOKEN = "sk-live-9f2b41ccd8e7"

def handle(request, cur):
    cur.execute("SELECT * FROM docs WHERE id = " + request["id"])
    os.system("convert " + request["file"])
    data = pickle.loads(request["blob"])
    r = requests.get(request["url"], verify=False)
    try:
        verify_signature(request)
    except Exception:
        pass
    return eval(request["expr"])
'''
for f in audit(VULNERABLE):
    print(f["severity"], f["line"], f["rule"], "-", f["impact"])
print(summarise(audit(VULNERABLE)), top_fix(audit(VULNERABLE)))`,
        why: `Each finding answers the four questions a triage meeting asks: where, what, **so what**, and what do I change. The \`impact\` strings are written for the person deciding whether this blocks the release — "full read and write of the database" schedules work in a way that "SQL injection detected" does not.

Ranking by severity before line number is what makes the output usable. A reader stops after the criticals and already knows whether to stop the deploy; file order would bury an \`eval\` on line 14 beneath a missing timeout on line 2.

The sort key ends with the rule id, which makes the output byte-identical across runs. That matters because this is a tool for CI: a report whose ordering shifts produces noisy diffs, and noisy diffs get ignored.

\`top_fix\` encodes the leverage argument from the lesson. Counting rules rather than listing findings turns "eleven issues" into "six of them are the same missing abstraction", which is the sentence that gets the work scheduled. Breaking ties by severity rather than count alone keeps a single critical from being outranked by three low-severity nits.

The clean-code test is the one that gives the tool credibility. It is the same application, written correctly — parameterised query, argv subprocess, \`json.loads\`, environment secret, explicit timeout, specific exception — and it audits to zero findings. A scanner that flags the correct code is a scanner nobody runs twice.

And the limitation remains the one from yesterday: this reads patterns in one file. It cannot see aliasing, dynamic dispatch, or anything that crosses a process boundary, and a clean run is evidence about these eight patterns rather than a verdict on the application. The audit it supports is still performed by a person who starts at the boundaries and traces input to sink — which is what the last sixty days have been training.`,
      },
      wrapup: `- Start at the boundaries: find inputs, find sinks, trace the paths between them.
- Rank by what an attacker gains, not by how interesting the bug is.
- Every finding: where, what, so what, fix, and a test that proves it.
- Lead with the root cause that closes the most findings at once.`,
      refs: [
        { label: "CWE Top 25 Most Dangerous Software Weaknesses", url: "https://cwe.mitre.org/top25/" },
        { label: "OWASP Code Review Guide", url: "https://owasp.org/www-project-code-review-guide/" },
        { label: "OWASP ASVS — verification standard", url: "https://owasp.org/www-project-application-security-verification-standard/" },
      ],
    },
  ],
};
