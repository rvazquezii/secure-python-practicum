export default {
  id: "m02",
  number: 2,
  title: "Control flow and input validation",
  focus: "fail closed",
  subtitle:
    "Branches, loops and the decision tree an attacker walks through. Every `if` that grants something needs an `else` that denies it.",
  objectives: [
    "Write `if`/`elif`/`else` chains whose default branch denies rather than permits.",
    "Write loops that always terminate, with an explicit bound on untrusted work.",
    "Choose an allowlist over a denylist and explain why denylists always lose.",
    "Build validators that return a clean value or raise — never a half-checked one.",
    "Resist user enumeration and brute force in an authentication gate.",
  ],
  rules: [
    { id: "PY-ASSERT-AUTH", what: "`assert` disappears under -O; never use it for authorization" },
    { id: "PY-SWALLOWED-ERROR", what: "a check that fails silently fails open" },
    { id: "PY-TIMING-COMPARE", what: "compare secrets in constant time" },
  ],
  capstone:
    "Day 16 builds a login gate: generic errors, per-account lockout, constant-time comparison, and an audit trail that names no secret.",

  lessons: [
    /* ------------------------------------------------------------------ 6 */
    {
      id: "m02l01",
      day: 12,
      title: "Branches, and the missing else that grants access",
      minutes: 60,
      secure: "fail-closed decisions",
      cwe: ["CWE-636", "CWE-617"],
      tags: ["if", "elif", "else", "authorization", "fail-closed"],
      lede:
        "A conditional is a decision about what is allowed. Write them so the path of least resistance — the one taken when nothing matches — is the one that denies.",
      blocks: [
        {
          t: "code",
          label: "example",
          code: `role = "editor"

if role == "admin":
    print("full access")
elif role == "editor":
    print("can publish")
else:
    print("read only")`,
          cap: "Indentation is the block structure. Four spaces, consistently — Python will refuse to run a file that mixes tabs and spaces.",
        },
        {
          t: "table",
          head: ["Operator", "Means", "Note"],
          rows: [
            ["`==` `!=`", "value equality", "Can be overridden by a class."],
            ["`is` `is not`", "same object", "Use for `None`, `True`, `False` only."],
            ["`<` `<=` `>` `>=`", "ordering", "`TypeError` across incompatible types — a feature."],
            ["`in` `not in`", "membership", "O(1) on a `set`, O(n) on a `list`."],
            ["`and` `or` `not`", "boolean logic", "Short-circuit: the right side may never run."],
            ["`1 <= port <= 65535`", "chained comparison", "Reads like maths; evaluates `port` once."],
          ],
        },
        { t: "h", text: "Fail closed means the default branch denies" },
        {
          t: "code",
          label: "vulnerable",
          code: `def can_delete(user, document):
    if user.role == "admin":
        return True
    if user.role == "owner" and document.owner_id == user.id:
        return True
    if user.role == "guest":
        return False
    # no final return -> Python returns None`,
          cap: "`None` is falsy, so this *looks* safe. Then someone writes `if can_delete(u, d) is not None:` or `if can_delete(...) != False:` and every role becomes an admin.",
        },
        {
          t: "code",
          label: "fixed",
          code: `def can_delete(user, document):
    if user.role == "admin":
        return True
    if user.role == "owner" and document.owner_id == user.id:
        return True
    return False          # explicit denial: the only way out of this function`,
          cap: "One explicit `return False` at the end. The function now returns a bool on every path, and a new role added next year is denied by default.",
        },
        {
          t: "box",
          kind: "rule",
          title: "Default deny",
          md: `Write the permit cases explicitly and make the last line a denial. Then adding a new role, a new document type or a new endpoint **fails closed** until someone deliberately permits it.

The inverse — listing the denials and permitting everything else — means every new case is permitted by accident. That is how a staging-only endpoint ends up public.`,
        },
        { t: "h", text: "Short-circuit evaluation is a security tool" },
        {
          t: "p",
          md: `\`A and B\` does not evaluate \`B\` when \`A\` is false. \`A or B\` does not evaluate \`B\` when \`A\` is true. Order your conditions so the cheap, safe check runs first:`,
        },
        {
          t: "code",
          label: "fixed",
          code: `if user is not None and user.is_active and has_permission(user, doc):
    publish(doc)`,
          cap: "`user.is_active` never runs on `None`, and the expensive permission lookup never runs for an inactive account.",
        },
        {
          t: "box",
          kind: "pitfall",
          title: "`assert` is not a check",
          md: `\`\`\`
assert user.is_admin, "not an admin"
\`\`\`

Python removes every \`assert\` statement when run with \`-O\` or \`PYTHONOPTIMIZE=1\`. Many container base images and deployment scripts set exactly that, for performance. Your authorization check becomes a comment.

Use \`assert\` for internal invariants you believe can never be false. Use \`if ...: raise PermissionError(...)\` for anything a user can influence. The auditor flags assert-based authorization as **high**.`,
        },
        {
          t: "box",
          kind: "cve",
          title: "The shape of a real one",
          md: `CVE-2022-31214 and a long line of similar bugs come down to a privilege check with a path that returns neither True nor False — an early \`return\`, an exception swallowed by a broad \`except\`, or a branch the author did not think was reachable. The exploit is rarely clever; it is a request that takes the branch nobody tested.`,
        },
      ],
      spot: {
        label: "document API, permission layer",
        prompt: "Click the line that lets an unauthenticated request through.",
        lines: [9],
        why:
          "Line 9. When `user` is `None` (no session), none of the branches match and the function falls off the end returning `None`. The caller does `if not can_view(...): deny()` today — but the function's contract is broken, and the first caller that writes `if can_view(...) == False` grants access to anonymous users. Add `return False`.",
        code: `def can_view(user, doc):
    if user is None:
        pass
    elif user.role == "admin":
        return True
    elif doc.owner_id == user.id:
        return True
    elif doc.visibility == "public":
        return True`,
      },
      quiz: [
        {
          q: "A function has branches returning `True` for three roles and no final `return`. What does it return for a fourth role?",
          options: ["`False`", "`None`", "It raises"],
          answer: 1,
          why:
            "`None`. It is falsy, so it behaves correctly under `if perm:` and incorrectly under `if perm is not None:` or `!= False`. Never rely on the caller using exactly the right truthiness test.",
        },
        {
          q: "Why is `assert token_is_valid(t)` unacceptable as an authentication check?",
          options: [
            "Assertions are slow.",
            "`python -O` strips assert statements entirely, removing the check in production.",
            "`assert` cannot call functions.",
          ],
          answer: 1,
          why:
            "Optimised mode discards asserts. The check vanishes exactly where it matters. Raise an explicit exception instead.",
        },
        {
          q: "Which ordering is correct for `user` possibly being `None`?",
          options: [
            "`if user.is_active and user is not None:`",
            "`if user is not None and user.is_active:`",
            "Both work — Python evaluates all conditions.",
          ],
          answer: 1,
          why:
            "`and` short-circuits left to right, so the `None` check must come first. The first option raises `AttributeError` on `None` before it ever reaches the guard.",
        },
      ],
      exercise: {
        title: "An access decision that denies by default",
        brief: `Implement \`can_access(user, doc)\` returning **only** \`True\` or \`False\`.

\`user\` is \`None\` (anonymous) or a dict with \`id\`, \`role\` and \`active\`. \`doc\` is a dict with \`owner_id\` and \`visibility\` (\`"public"\` or \`"private"\`).

Grant access when, and only when:

1. the document is \`"public"\` — anyone, including anonymous, may read it; **or**
2. the user is not \`None\`, \`active\` is \`True\`, and either their \`role\` is \`"admin"\` or their \`id\` equals \`doc["owner_id"]\`.

Everything else is denied. An inactive account is denied even if it owns the document. An unknown role is denied. Do not use \`assert\`.`,
        rubric: [
          "Returns a real `bool` on every path — never `None`",
          "Anonymous user + public doc → `True`; anonymous + private → `False`",
          "Inactive admin → `False`",
          "Owner of a private doc → `True`; non-owner → `False`",
          "Unknown role (`\"intern\"`) on a private doc they do not own → `False`",
          "No `assert` used for the decision",
        ],
        starter: `def can_access(user, doc):
    """Return True only when access is positively justified."""
    # public documents first -- the only anonymous path


print(can_access(None, {"owner_id": 1, "visibility": "public"}))
`,
        stdin: [],
        tests: [
          {
            name: "always returns a bool",
            code: `cases = [(None, {"owner_id": 1, "visibility": "private"}),
         ({"id": 9, "role": "intern", "active": True}, {"owner_id": 1, "visibility": "private"})]
for u, d in cases:
    got = can_access(u, d)
    assert got is True or got is False, f"returned {got!r} for user={u}; must be True or False"`,
          },
          {
            name: "public documents are readable by anyone",
            code: `pub = {"owner_id": 1, "visibility": "public"}
assert can_access(None, pub) is True
assert can_access({"id": 7, "role": "intern", "active": False}, pub) is True`,
          },
          {
            name: "anonymous cannot read private",
            code: `assert can_access(None, {"owner_id": 1, "visibility": "private"}) is False`,
          },
          {
            name: "admins read private documents",
            code: `priv = {"owner_id": 1, "visibility": "private"}
assert can_access({"id": 5, "role": "admin", "active": True}, priv) is True`,
          },
          {
            name: "inactive accounts are denied",
            code: `priv = {"owner_id": 1, "visibility": "private"}
assert can_access({"id": 5, "role": "admin", "active": False}, priv) is False
assert can_access({"id": 1, "role": "member", "active": False}, priv) is False`,
          },
          {
            name: "owners read their own private documents",
            code: `priv = {"owner_id": 42, "visibility": "private"}
assert can_access({"id": 42, "role": "member", "active": True}, priv) is True
assert can_access({"id": 43, "role": "member", "active": True}, priv) is False`,
          },
          {
            name: "unknown roles get nothing",
            code: `priv = {"owner_id": 1, "visibility": "private"}
for role in ("intern", "", "ADMIN", "superuser"):
    assert can_access({"id": 9, "role": role, "active": True}, priv) is False, f"role {role!r} was granted access"`,
          },
          { name: "prints the first decision", code: `assert "True" in _stdout` },
        ],
        requirements: [
          { kind: "defines", value: "can_access" },
          { kind: "forbids", value: "\\bassert\\b", message: "Remove `assert` — it vanishes under `python -O`. Use an explicit return." },
        ],
        hints: [
          "Handle the public case first and return early: `if doc[\"visibility\"] == \"public\": return True`.",
          "Then the guard for anonymous and inactive: `if user is None or not user.get(\"active\"): return False`. Note the order — `None` must be excluded before you touch the dict.",
          "Finish with the two positive cases and a final, unconditional `return False`.",
          "`\"ADMIN\"` must fail: compare exactly, do not lowercase the role. Roles are identifiers, not free text.",
        ],
        solution: `def can_access(user, doc):
    """Return True only when access is positively justified."""
    if doc.get("visibility") == "public":
        return True

    if user is None:
        return False
    if not user.get("active"):
        return False

    if user.get("role") == "admin":
        return True
    if user.get("id") == doc.get("owner_id"):
        return True

    return False


print(can_access(None, {"owner_id": 1, "visibility": "public"}))`,
        why: `The function is a sequence of guards ending in a denial, which gives three properties worth having:

- **Every path returns a bool.** No caller can be surprised by \`None\`.
- **New cases fail closed.** Add a \`"reviewer"\` role next quarter and it is denied until someone writes the branch — the failure is a support ticket, not a breach.
- **The anonymous check precedes every dict access.** Reordering those two lines turns a denial into an \`AttributeError\`, and an unhandled exception in a permission layer is its own vulnerability.

Using \`.get()\` rather than \`[...]\` means a malformed document (missing \`visibility\`) is treated as private rather than raising — fail closed again.`,
      },
      wrapup: `- End every authorization function with an explicit \`return False\`.
- Default deny: list what is permitted, deny the rest, so new cases are safe by construction.
- \`and\`/\`or\` short-circuit — order guards cheapest and safest first.
- \`assert\` is stripped by \`python -O\`. It is not a security control.`,
      refs: [
        { label: "Python tutorial — control flow", url: "https://docs.python.org/3/tutorial/controlflow.html" },
        { label: "CWE-636: Not Failing Securely", url: "https://cwe.mitre.org/data/definitions/636.html" },
      ],
    },

    /* ------------------------------------------------------------------ 7 */
    {
      id: "m02l02",
      day: 13,
      title: "Loops that always terminate",
      minutes: 60,
      secure: "bounded work, no infinite loops",
      cwe: ["CWE-835", "CWE-400"],
      tags: ["for", "while", "range", "break", "dos", "bounds"],
      lede:
        "`for` is for a known sequence; `while` is for a condition. A `while` whose condition depends on untrusted data is a denial-of-service waiting to be discovered.",
      blocks: [
        {
          t: "code",
          label: "example",
          code: `for attempt in range(3):
    print("attempt", attempt)        # 0, 1, 2

for char in "abc":
    print(char)

for i, name in enumerate(["ada", "lin"], start=1):
    print(i, name)                   # 1 ada / 2 lin

total = 0
while total < 10:
    total += 3
print(total)                         # 12`,
          cap: "`range(3)` is 0, 1, 2 — the end is excluded. `enumerate` gives you the index without manual counters.",
        },
        {
          t: "box",
          kind: "note",
          title: "`break`, `continue`, and the `else` nobody knows",
          md: `- \`break\` leaves the loop immediately.
- \`continue\` skips to the next iteration.
- A loop's \`else:\` block runs **only if the loop finished without \`break\`**. It is the cleanest way to express "searched everything and found nothing":

\`\`\`
for host in allowed_hosts:
    if host == target:
        break
else:
    raise ValueError("host not in allowlist")
\`\`\``,
        },
        { t: "h", text: "The unbounded loop" },
        {
          t: "code",
          label: "vulnerable",
          code: `def fetch_all_pages(client, start_url):
    url = start_url
    results = []
    while url:                       # server controls 'next'
        page = client.get(url)
        results.extend(page["items"])
        url = page.get("next")       # a hostile server never stops
    return results`,
          cap: "A paginating API that returns `next` pointing at itself turns your client into a memory bomb. The server does not even need to be malicious — a bug produces the same outcome.",
        },
        {
          t: "code",
          label: "fixed",
          code: `MAX_PAGES = 100
MAX_ITEMS = 50_000

def fetch_all_pages(client, start_url):
    url = start_url
    results = []
    for page_num in range(MAX_PAGES):          # hard bound, not a while
        if not url:
            break
        page = client.get(url, timeout=(3, 10))
        results.extend(page["items"])
        if len(results) > MAX_ITEMS:
            raise ValueError(f"response exceeded {MAX_ITEMS} items; aborting")
        url = page.get("next")
    else:
        raise ValueError(f"pagination did not terminate within {MAX_PAGES} pages")
    return results`,
          cap: "`for ... in range(MAX)` cannot loop forever. The `else` fires only when the bound was hit, which turns a hang into a clear error.",
        },
        {
          t: "box",
          kind: "rule",
          title: "Bound every loop that touches untrusted data",
          md: `Ask of each loop: *who decides when this stops?* If the answer involves a network, a file, a user or a parser, give it an upper bound and an error path.

This applies to retry loops, polling loops, parser loops, recursive descent, and \`while True:\` with a \`break\` buried inside a conditional.`,
        },
        { t: "h", text: "Iterating a file without loading it" },
        {
          t: "code",
          label: "fixed",
          code: `MAX_LINES = 1_000_000
MAX_LINE_LEN = 4096

with open("access.log", encoding="utf-8", errors="replace") as fh:
    for n, line in enumerate(fh):                 # streams, one line at a time
        if n >= MAX_LINES:
            raise ValueError("log file too large")
        if len(line) > MAX_LINE_LEN:
            continue                              # skip absurd lines, keep going
        handle(line)`,
          cap: "`for line in fh` reads lazily. `fh.read()` or `fh.readlines()` on an attacker-supplied file is a memory exhaustion in one call.",
        },
        {
          t: "box",
          kind: "pitfall",
          title: "Mutating a list while looping over it",
          md: `\`\`\`
for item in queue:
    if item.expired:
        queue.remove(item)     # skips the next element, silently
\`\`\`

Removal shifts every later element down while the iterator's index moves up. Half your expired items survive. Build a new list instead: \`queue = [i for i in queue if not i.expired]\`.`,
        },
      ],
      quiz: [
        {
          q: "`while url:` where `url` comes from the server's `next` field. What is the risk?",
          options: [
            "None — the loop ends when the server stops.",
            "A hostile or buggy server can make it loop forever, exhausting memory and a worker.",
            "It is slower than a `for` loop.",
          ],
          answer: 1,
          why:
            "The remote end decides your termination condition. Bound it with `for _ in range(MAX_PAGES)` and raise when the bound is reached.",
        },
        {
          q: "What does a `for ... else:` block do?",
          options: [
            "Runs when the loop body never executed.",
            "Runs when the loop completed without hitting `break`.",
            "Runs after every loop.",
          ],
          answer: 1,
          why:
            "It is the 'searched everything, found nothing' branch — ideal for allowlist scans and for detecting that a bound was exhausted.",
        },
        {
          q: "Which reads a 10 GB log safely?",
          options: [
            "`data = fh.read().split(\"\\n\")`",
            "`for line in fh:`",
            "`lines = fh.readlines()`",
          ],
          answer: 1,
          why: "Iterating the file object streams one line at a time. The other two materialise the whole file in memory first.",
        },
      ],
      exercise: {
        title: "A retry loop that gives up",
        brief: `Write \`fetch_with_retry(fetch, max_attempts=5, max_total_items=1000)\`.

\`fetch\` is a zero-argument callable that either returns a list of items or raises \`ConnectionError\`.

- Call \`fetch()\` up to \`max_attempts\` times.
- Return the first successful result, as soon as it succeeds.
- If a successful result has more than \`max_total_items\` items, raise \`ValueError\` (do not return it, do not retry).
- If every attempt raises \`ConnectionError\`, raise \`TimeoutError\` whose message contains the number of attempts made.
- Catch **only** \`ConnectionError\`. Any other exception must propagate unchanged — a \`TypeError\` in your own code is a bug, not a transient failure.
- Also return the attempt count: return a tuple \`(items, attempts_used)\`.`,
        rubric: [
          "Succeeds on the first try → `(items, 1)`",
          "Succeeds on the third try → `(items, 3)`; `fetch` called exactly 3 times",
          "All attempts fail → `TimeoutError` mentioning the attempt count, after exactly `max_attempts` calls",
          "An oversized result raises `ValueError` immediately",
          "A `ValueError` raised by `fetch` itself propagates — it is not retried",
          "No bare `except:` and no `except Exception: pass`",
        ],
        starter: `def fetch_with_retry(fetch, max_attempts=5, max_total_items=1000):
    """Return (items, attempts_used) or raise."""


calls = []
def flaky():
    calls.append(1)
    if len(calls) < 3:
        raise ConnectionError("reset by peer")
    return ["a", "b"]


print(fetch_with_retry(flaky))
`,
        stdin: [],
        tests: [
          {
            name: "returns immediately on success",
            code: `n = []
def ok():
    n.append(1)
    return [1, 2, 3]
assert fetch_with_retry(ok) == ([1, 2, 3], 1), f"got {fetch_with_retry(ok)!r}"
assert len(n) == 1, f"fetch called {len(n)} times, expected 1"`,
          },
          {
            name: "retries then succeeds, reporting the count",
            code: `n = []
def flaky():
    n.append(1)
    if len(n) < 3:
        raise ConnectionError("reset")
    return ["x"]
assert fetch_with_retry(flaky) == (["x"], 3), "should report 3 attempts"
assert len(n) == 3, f"fetch called {len(n)} times"`,
          },
          {
            name: "gives up after max_attempts",
            code: `n = []
def always_fail():
    n.append(1)
    raise ConnectionError("down")
with raises(TimeoutError):
    fetch_with_retry(always_fail, max_attempts=4)
assert len(n) == 4, f"fetch called {len(n)} times, expected exactly 4"`,
          },
          {
            name: "the give-up message names the attempt count",
            code: `def always_fail():
    raise ConnectionError("down")
try:
    fetch_with_retry(always_fail, max_attempts=3)
    raise AssertionError("expected TimeoutError")
except TimeoutError as e:
    assert "3" in str(e), f"message should mention 3 attempts, got {str(e)!r}"`,
          },
          {
            name: "oversized responses are rejected, not retried",
            code: `n = []
def huge():
    n.append(1)
    return list(range(5000))
with raises(ValueError):
    fetch_with_retry(huge, max_total_items=1000)
assert len(n) == 1, "an oversized response must not be retried"`,
          },
          {
            name: "unexpected exceptions are not swallowed",
            code: `def broken():
    raise ValueError("bug in my own code")
with raises(ValueError):
    fetch_with_retry(broken)`,
          },
          { name: "prints a result", code: `assert "'a'" in _stdout or "a" in _stdout` },
        ],
        requirements: [
          { kind: "defines", value: "fetch_with_retry" },
          { kind: "no_finding", value: "PY-BARE-EXCEPT" },
          { kind: "no_finding", value: "PY-SWALLOWED-ERROR" },
        ],
        hints: [
          "`for attempt in range(1, max_attempts + 1):` gives you a bounded loop and a 1-based count in one line.",
          "Inside the loop: `try: items = fetch()` / `except ConnectionError: continue`. Only `ConnectionError` — anything broader hides real bugs.",
          "Check the size *after* a successful fetch and raise `ValueError` there, before returning. Raising inside the loop exits it immediately, which is what 'do not retry' means.",
          "After the loop ends normally, raise `TimeoutError(f\"giving up after {max_attempts} attempts\")`. Putting it after the `for` (not in an `else`) is fine here because every success path returns.",
        ],
        solution: `def fetch_with_retry(fetch, max_attempts=5, max_total_items=1000):
    """Return (items, attempts_used) or raise."""
    if max_attempts < 1:
        raise ValueError("max_attempts must be at least 1")

    last_error = None
    for attempt in range(1, max_attempts + 1):
        try:
            items = fetch()
        except ConnectionError as exc:
            last_error = exc
            continue

        if len(items) > max_total_items:
            raise ValueError(
                f"response has {len(items)} items, limit is {max_total_items}"
            )
        return items, attempt

    raise TimeoutError(
        f"giving up after {max_attempts} attempts; last error: {last_error}"
    )


calls = []
def flaky():
    calls.append(1)
    if len(calls) < 3:
        raise ConnectionError("reset by peer")
    return ["a", "b"]


print(fetch_with_retry(flaky))`,
        why: `The loop is bounded by \`range\`, so it cannot run forever regardless of what \`fetch\` does. Three decisions carry the security weight:

- **Only \`ConnectionError\` is caught.** A \`TypeError\` from a signature change, or a \`KeyError\` from a schema change, propagates immediately instead of being retried five times and then reported as a timeout — which would send you hunting the network for a bug in your own code.
- **The size check raises rather than retrying.** An oversized response is a refusal, not a transient condition; retrying it would multiply the damage.
- **The give-up error carries the last underlying error.** Without it, every failure looks identical and no one can tell DNS failure from connection refused.

Note what is *not* here: no \`time.sleep\` in a tight loop, no \`while True\`, and no \`except Exception\`.`,
      },
      wrapup: `- \`for\` over a bounded sequence is safer than \`while\` over a condition someone else controls.
- Bound retries, pages, parse iterations and recursion depth. State the bound as a named constant.
- \`for ... else\` runs when no \`break\` happened — perfect for "exhausted the allowlist" and "hit the limit".
- Stream files line by line; \`.read()\` on untrusted input is an allocation decision made by the attacker.`,
      refs: [
        { label: "CWE-835: Loop with Unreachable Exit Condition", url: "https://cwe.mitre.org/data/definitions/835.html" },
        { label: "CWE-400: Uncontrolled Resource Consumption", url: "https://cwe.mitre.org/data/definitions/400.html" },
      ],
    },

    /* ------------------------------------------------------------------ 8 */
    {
      id: "m02l03",
      day: 14,
      title: "Allowlists beat denylists, every time",
      minutes: 60,
      secure: "allowlist validation",
      cwe: ["CWE-184", "CWE-20"],
      tags: ["allowlist", "denylist", "validation", "normalisation"],
      lede:
        "A denylist enumerates what you thought of. An allowlist enumerates what you support. Only one of those lists is finite.",
      blocks: [
        {
          t: "p",
          md: `Suppose you must block path traversal. The obvious move is to reject \`..\`:`,
        },
        {
          t: "code",
          label: "vulnerable",
          code: `def safe_name(name):
    if ".." in name:
        raise ValueError("no traversal")
    return name`,
        },
        {
          t: "p",
          md: `Now work through what the attacker sends next:

- \`....//\` — removing \`..\` once leaves \`../\`
- \`%2e%2e%2f\` — URL-encoded, decoded later by another layer
- \`..%c0%af\` — overlong UTF-8 encoding
- \`\\..\\\` — backslash separators on Windows
- \`/etc/passwd\` — an absolute path needs no \`..\` at all
- \`\\u002e\\u002e/\` — Unicode escapes resolved by a JSON parser upstream

Each one is a patch to the denylist. The attacker only needs the one you missed; you need all of them, forever, including the ones invented after you ship.`,
        },
        {
          t: "code",
          label: "fixed",
          code: `import re

SAFE_NAME = re.compile(r"\\A[a-zA-Z0-9_-]{1,64}\\.(csv|json|txt)\\Z")

def safe_name(name):
    if not SAFE_NAME.match(name):
        raise ValueError(f"filename not permitted: {name!r}")
    return name`,
          cap: "Describe exactly what is acceptable. Anything not matching that description is rejected, including the encodings nobody has invented yet.",
        },
        {
          t: "box",
          kind: "rule",
          title: "Allowlist, and anchor it",
          md: `Use \`\\A\` and \`\\Z\` (or \`fullmatch\`) rather than \`^\` and \`$\`. In Python, \`$\` also matches immediately before a trailing newline, so \`re.match(r"^[a-z]+$", "abc\\nrm -rf /")\` **succeeds**. \`\\Z\` matches only at the very end.

This single detail has produced real authentication bypasses.`,
        },
        {
          t: "repl",
          lines: [
            ">>> import re",
            '>>> bool(re.match(r"^[a-z]+$", "abc\\nmalicious"))',
            "True          # <- the newline trick",
            '>>> bool(re.match(r"\\\\A[a-z]+\\\\Z", "abc\\\\nmalicious"))',
            "False         # <- anchored properly",
          ],
        },
        { t: "h", text: "Normalise first, then validate, then use" },
        {
          t: "p",
          md: `If you validate one form of a value and use a different form, the validation is decorative. Decode, normalise and canonicalise **before** the check, then pass the canonical value onward — never the original.`,
        },
        {
          t: "code",
          label: "vulnerable",
          code: `import urllib.parse

def handle(raw_name):
    if "/" in raw_name:
        raise ValueError("no slashes")
    path = urllib.parse.unquote(raw_name)   # decoded AFTER the check
    return open(f"/srv/files/{path}")       # "%2fetc%2fpasswd" -> "/etc/passwd"`,
        },
        {
          t: "code",
          label: "fixed",
          code: `import urllib.parse

def handle(raw_name):
    name = urllib.parse.unquote(raw_name)   # decode FIRST
    if not SAFE_NAME.match(name):
        raise ValueError("filename not permitted")
    return open(f"/srv/files/{name}")       # the validated value is the one used`,
        },
        {
          t: "table",
          head: ["Decision", "Denylist (fragile)", "Allowlist (robust)"],
          rows: [
            ["File names", "block `..`, `/`", "`\\A[\\w-]{1,64}\\.(csv|txt)\\Z`"],
            ["Redirect targets", "block `evil.com`", "a set of exact permitted URLs"],
            ["HTML", "strip `<script>`", "an allowlist of tags and attributes"],
            ["SQL", "escape quotes", "parameterised queries — no string building at all"],
            ["Shell", "escape `;`", "`subprocess.run([...])` — no shell at all"],
            ["Uploads", "block `.exe`", "allow `.png`, `.jpg`, and verify the magic bytes"],
          ],
        },
        {
          t: "box",
          kind: "cve",
          title: "Denylists in production",
          md: `Log4Shell's first patch (2.15.0) was a denylist of JNDI lookup forms; researchers bypassed it within days, producing CVE-2021-45046. The fix that held was removing the capability entirely — the allowlist of "nothing".

When a denylist needs a second patch, that is the signal to invert the design.`,
        },
      ],
      spot: {
        label: "file download endpoint",
        prompt: "Click the line that makes the validation above it pointless.",
        lines: [8],
        why:
          "Line 8. The check on line 6 inspects `name`, but line 8 opens `decoded` — a different string. `%2e%2e%2fetc%2fpasswd` passes the check and then becomes `../etc/passwd`. Validate the canonical value and use *that same value*.",
        code: `import urllib.parse

BASE = "/srv/files/"

def download(name):
    if "/" in name or ".." in name:
        raise ValueError("bad name")
    decoded = urllib.parse.unquote(name)
    with open(BASE + decoded, "rb") as fh:
        return fh.read()`,
      },
      quiz: [
        {
          q: "Why is `re.match(r\"^[a-z]+$\", value)` unsafe as an allowlist?",
          options: [
            "`^` is slow.",
            "`$` also matches before a trailing newline, so `\"abc\\nrm -rf /\"` passes.",
            "`match` only checks the first character.",
          ],
          answer: 1,
          why: "Use `\\A...\\Z` or `re.fullmatch`. The newline-before-end behaviour is a documented Python detail that has caused real bypasses.",
        },
        {
          q: "You must accept uploaded images. Which is the allowlist approach?",
          options: [
            "Reject `.exe`, `.sh`, `.php`, `.bat`.",
            "Accept only `.png`/`.jpg` extensions and verify the file's magic bytes match.",
            "Accept anything under 2 MB.",
          ],
          answer: 1,
          why:
            "Name the small set you support and verify the content, because the extension is attacker-controlled metadata. Blocking known-bad extensions misses `.phtml`, `.svg`, `.jsp` and whatever your web server decides to execute next year.",
        },
        {
          q: "Validation passes `name`, then the code uses `unquote(name)`. What is the flaw?",
          options: [
            "Nothing, decoding is safe.",
            "The validated value and the used value are different strings; the check does not apply to what is used.",
            "`unquote` is deprecated.",
          ],
          answer: 1,
          why: "Canonicalise first, validate the canonical form, then use exactly that form. Any transformation after validation reopens the hole.",
        },
      ],
      exercise: {
        title: "A report-name allowlist",
        brief: `A reporting service receives a URL-encoded report name and must resolve it to a file in \`/srv/reports/\`.

Write \`resolve_report(raw)\` that:

1. URL-decodes \`raw\` with \`urllib.parse.unquote\` **first**,
2. accepts only names matching: 1–40 characters of ASCII letters, digits, underscore or hyphen, followed by \`.csv\` or \`.json\`,
3. returns the full path \`"/srv/reports/<name>"\` built from the **decoded, validated** name,
4. raises \`ValueError\` for anything else.

Use an anchored regular expression (\`\\A\`/\`\\Z\` or \`fullmatch\`). Do not write a denylist.`,
        rubric: [
          "`resolve_report(\"q4.csv\")` → `\"/srv/reports/q4.csv\"`",
          "`resolve_report(\"q%34.csv\")` → `\"/srv/reports/q4.csv\"` (decoded before validation)",
          "Traversal in every encoding is rejected: `../`, `%2e%2e%2f`, `....//`, absolute paths, backslashes",
          "A trailing-newline payload (`\"ok.csv\\nrm -rf /\"`) is rejected — proving the anchors are `\\A`/`\\Z`",
          "Wrong extensions and over-long names are rejected",
        ],
        starter: `import re
import urllib.parse

BASE = "/srv/reports/"
# Describe what IS allowed, anchored at both ends.
SAFE = re.compile(r"")


def resolve_report(raw):
    """Decode, validate against the allowlist, and return the full path."""


print(resolve_report("q4%2Ecsv"))
`,
        stdin: [],
        tests: [
          {
            name: "accepts plain names",
            code: `assert resolve_report("q4.csv") == "/srv/reports/q4.csv", f"got {resolve_report('q4.csv')!r}"
assert resolve_report("region_report-2026.json") == "/srv/reports/region_report-2026.json"`,
          },
          {
            name: "decodes before validating",
            code: `assert resolve_report("q%34.csv") == "/srv/reports/q4.csv", "decode first, then validate"
assert resolve_report("q4%2Ecsv") == "/srv/reports/q4.csv"`,
          },
          {
            name: "rejects traversal in every encoding",
            code: `for bad in ("../etc/passwd", "..%2fetc%2fpasswd", "%2e%2e%2fetc%2fpasswd",
            "....//q4.csv", "/etc/passwd", "\\\\\\\\windows\\\\\\\\win.ini", "sub/dir/q4.csv"):
    with raises(ValueError):
        resolve_report(bad)`,
          },
          {
            name: "anchors reject the trailing-newline trick",
            code: `for bad in ("q4.csv\\nrm -rf /", "q4.csv\\n", "\\nq4.csv"):
    with raises(ValueError):
        resolve_report(bad)`,
          },
          {
            name: "rejects wrong extensions and empty names",
            code: `for bad in ("", "q4", "q4.exe", "q4.csv.exe", "q4.CSV", ".csv", "q4.php"):
    with raises(ValueError):
        resolve_report(bad)`,
          },
          {
            name: "rejects over-long names",
            code: `with raises(ValueError):
    resolve_report("a" * 41 + ".csv")
assert resolve_report("a" * 40 + ".csv").endswith(".csv"), "40 characters must still be accepted"`,
          },
          { name: "prints a resolved path", code: `assert "/srv/reports/q4.csv" in _stdout` },
        ],
        requirements: [
          { kind: "defines", value: "resolve_report" },
          { kind: "uses_module", value: "re" },
          { kind: "regex", value: "\\\\A|fullmatch", message: "Anchor the pattern with `\\A`...`\\Z` or use `re.fullmatch`." },
        ],
        hints: [
          "The pattern: `r\"\\A[A-Za-z0-9_-]{1,40}\\.(csv|json)\\Z\"`. Note the escaped dot — an unescaped `.` matches any character, which would accept `q4Xcsv`.",
          "Decode first: `name = urllib.parse.unquote(raw)`. Then match `name`, then build the path from `name`.",
          "`re.fullmatch(pattern, name)` is equivalent to anchoring and reads more clearly. Either satisfies the requirement.",
          "Return `BASE + name` — never `BASE + raw`. Using the undecoded original is the bug this exercise is about.",
        ],
        solution: `import re
import urllib.parse

BASE = "/srv/reports/"
SAFE = re.compile(r"\\A[A-Za-z0-9_-]{1,40}\\.(csv|json)\\Z")


def resolve_report(raw):
    """Decode, validate against the allowlist, and return the full path."""
    if not isinstance(raw, str):
        raise ValueError("report name must be text")

    name = urllib.parse.unquote(raw)

    if not SAFE.match(name):
        raise ValueError(f"report name not permitted: {name!r}")

    return BASE + name


print(resolve_report("q4%2Ecsv"))`,
        why: `The pattern states the entire grammar of an acceptable name: a bounded run of three character classes, a literal dot, one of two extensions, nothing before, nothing after. There is no list of bad things to keep up to date.

Three details do the real work:

- **\`\\A\` and \`\\Z\`** — with \`^\`/\`$\`, \`"q4.csv\\nrm -rf /"\` would match, because \`$\` matches before a final newline.
- **Decode, then validate, then use the decoded value.** Every traversal encoding collapses into the same canonical string before the check sees it, and the string that was checked is the string that is used.
- **The length bound is inside the pattern**, so a 10 MB name is rejected by the same expression rather than by a separate check someone can forget.

The function still does not open anything — resolving and opening are separate concerns, and Module 6 adds the second line of defence (confining the resolved path to the base directory).`,
      },
      wrapup: `- Denylists enumerate what you imagined; allowlists enumerate what you support.
- Anchor with \`\\A\`/\`\\Z\` or \`fullmatch\`. \`$\` matches before a trailing newline.
- Canonicalise → validate → use the canonical value. Never transform after validating.
- When a denylist needs its second patch, replace it with an allowlist.`,
      refs: [
        { label: "re — regular expression operations", url: "https://docs.python.org/3/library/re.html" },
        { label: "OWASP Input Validation Cheat Sheet", url: "https://cheatsheetseries.owasp.org/cheatsheets/Input_Validation_Cheat_Sheet.html" },
        { label: "CWE-184: Incomplete List of Disallowed Input", url: "https://cwe.mitre.org/data/definitions/184.html" },
      ],
    },

    /* ------------------------------------------------------------------ 9 */
    {
      id: "m02l04",
      day: 15,
      title: "Validators that return a clean value",
      minutes: 60,
      secure: "parse, don't validate",
      cwe: ["CWE-20", "CWE-1284"],
      tags: ["validation", "match", "parsing", "functions", "contracts"],
      lede:
        "A function named `is_valid_email()` returns a bool and leaves you holding the original string. A function named `parse_email()` returns a value you can use. The second design makes the mistake impossible.",
      blocks: [
        {
          t: "p",
          md: `There are two shapes for input handling. They look equivalent and are not.`,
        },
        {
          t: "code",
          label: "vulnerable",
          code: `def is_valid_amount(raw):
    return raw.isdigit() and 0 < int(raw) <= 10_000

# caller, six months later, in a different file:
if is_valid_amount(raw):
    charge(int(raw))        # re-parses -- fine today
process_refund(raw)         # forgot the check entirely -- nothing stops them`,
          cap: "Validation and use are separated by distance. The type system cannot tell a checked string from an unchecked one, because they are both `str`.",
        },
        {
          t: "code",
          label: "fixed",
          code: `def parse_amount(raw):
    """Return a validated int, or raise ValueError."""
    if not (raw.isascii() and raw.isdigit()):
        raise ValueError("amount must be digits")
    value = int(raw)
    if not 0 < value <= 10_000:
        raise ValueError("amount out of range")
    return value

amount = parse_amount(raw)   # from here on, amount cannot be anything else
charge(amount)
process_refund(amount)`,
          cap: "The validated value has a different type from the raw one. Code downstream receives `int`, so there is no unchecked string left to misuse.",
        },
        {
          t: "box",
          kind: "rule",
          title: "Parse, don't validate",
          md: `Make your validator **return the usable value** rather than a boolean. The result carries the proof that checking happened.

The pattern scales: \`parse_port\` → \`int\`, \`parse_email\` → a normalised address, \`parse_path\` → a resolved \`Path\`, \`parse_user_id\` → a \`UserId\`. Each conversion is a one-way door that untrusted data cannot walk back through.`,
        },
        { t: "h", text: "Collecting errors instead of stopping at the first" },
        {
          t: "p",
          md: `For a form with ten fields, failing on the first error makes users submit ten times. Validate every field, collect the failures, and raise once:`,
        },
        {
          t: "code",
          label: "fixed",
          code: `class ValidationError(ValueError):
    def __init__(self, errors):
        super().__init__(f"{len(errors)} invalid field(s)")
        self.errors = errors          # {"field": "reason"}

def parse_signup(form):
    errors, clean = {}, {}
    for field, parser in (("email", parse_email), ("age", parse_age)):
        try:
            clean[field] = parser(form.get(field, ""))
        except ValueError as exc:
            errors[field] = str(exc)
    if errors:
        raise ValidationError(errors)
    return clean`,
          cap: "One pass, all failures reported, and `clean` is only returned when every field parsed. Partial results never escape.",
        },
        { t: "h", text: "match: dispatch on shape" },
        {
          t: "code",
          label: "example",
          code: `def handle(event):
    match event:
        case {"type": "login", "user": str(user)}:
            return f"login:{user}"
        case {"type": "delete", "id": int(doc_id)} if doc_id > 0:
            return f"delete:{doc_id}"
        case {"type": str(unknown)}:
            raise ValueError(f"unsupported event type: {unknown!r}")
        case _:
            raise ValueError("malformed event")`,
          cap: "`str(user)` and `int(doc_id)` are type *patterns* — they match only when the value has that type and bind it. The final `case _` is the default-deny branch.",
        },
        {
          t: "box",
          kind: "warn",
          title: "`match` is not a validator by itself",
          md: `A \`match\` with no final \`case _\` falls through silently, returning \`None\` — the same fail-open shape as a missing \`else\`. Always write the catch-all, and make it raise.`,
        },
        {
          t: "box",
          kind: "good",
          title: "Normalise inside the parser",
          md: `A parser is the right place to canonicalise: strip surrounding whitespace, lower-case a domain, collapse internal spacing, convert to NFC. Do it **after** the structural checks and return the normalised form, so every caller sees one spelling of the same value.

Be deliberate about case: lower-casing an email's domain is correct; lower-casing a role name before comparing it to \`"admin"\` turns \`"ADMIN"\` into a privilege grant.`,
        },
      ],
      quiz: [
        {
          q: "Why is `parse_amount(raw) -> int` safer than `is_valid_amount(raw) -> bool`?",
          options: [
            "It is faster.",
            "The return value carries proof of validation, so downstream code cannot use the unchecked original.",
            "Booleans cannot represent validation results.",
          ],
          answer: 1,
          why:
            "With a boolean, the raw string survives and any later line can use it unchecked. With a parser, the usable value only exists after the check — the mistake becomes unexpressible.",
        },
        {
          q: "A `match` statement with no `case _:` and no matching case does what?",
          options: ["Raises `MatchError`", "Falls through, and the function returns `None`", "Repeats the first case"],
          answer: 1,
          why: "Silent fall-through — the same fail-open shape as a missing `else`. Always end with `case _:` that raises.",
        },
        {
          q: "Where should `email.strip().lower()` happen?",
          options: [
            "In each caller, as needed.",
            "Inside the parser, after structural checks, so every caller receives one canonical spelling.",
            "Nowhere; normalisation is cosmetic.",
          ],
          answer: 1,
          why:
            "Normalising in one place prevents the classic account-duplication and comparison bugs where `Ada@Example.com` and `ada@example.com` are treated as different accounts in one code path and the same in another.",
        },
      ],
      exercise: {
        title: "parse_user(): one pass, all errors, clean output",
        brief: `Write \`parse_user(form)\` taking a dict of raw strings and returning a clean dict, or raising \`ValidationError\`.

Fields and rules:

| field | rule | cleaned form |
|---|---|---|
| \`username\` | 3–20 chars, ASCII letters/digits/underscore only, must start with a letter | lower-cased |
| \`email\` | must contain exactly one \`@\`, non-empty local part, domain containing a dot, no whitespace, ≤ 254 chars | stripped, domain lower-cased, local part left as typed |
| \`age\` | ASCII digits, 13–120 | \`int\` |
| \`role\` | exactly one of \`"member"\`, \`"editor"\` (compared case-**sensitively**) | unchanged |

Missing fields are errors too. \`ValidationError\` must carry an \`errors\` dict mapping field name to a reason string, and must be a subclass of \`ValueError\`.

Report **every** failing field in one raise, not just the first.`,
        rubric: [
          "A fully valid form returns `{\"username\", \"email\", \"age\", \"role\"}` with cleaned values",
          "`age` is an `int`; `username` is lower-cased; the email domain is lower-cased",
          "Three bad fields produce one `ValidationError` with three entries in `.errors`",
          "`ValidationError` is a subclass of `ValueError`",
          "`\"ADMIN\"` and `\"Member\"` are rejected — roles are compared exactly",
          "A missing field is reported, not crashed on",
        ],
        starter: `class ValidationError(ValueError):
    def __init__(self, errors):
        super().__init__(f"{len(errors)} invalid field(s)")
        self.errors = errors


def parse_username(raw):
    """Return the cleaned username or raise ValueError."""


def parse_email(raw):
    """Return the cleaned email or raise ValueError."""


def parse_age(raw):
    """Return the age as an int or raise ValueError."""


def parse_role(raw):
    """Return the role unchanged or raise ValueError."""


def parse_user(form):
    """Return a clean dict, or raise ValidationError listing every bad field."""


print(parse_user({"username": "Ada_L", "email": "ada@Example.COM", "age": "36", "role": "editor"}))
`,
        stdin: [],
        tests: [
          {
            name: "a valid form is cleaned",
            code: `got = parse_user({"username": "Ada_L", "email": " ada@Example.COM ", "age": "36", "role": "editor"})
assert got["username"] == "ada_l", f"username should be lower-cased, got {got['username']!r}"
assert got["email"] == "ada@example.com", f"got {got['email']!r}"
assert got["age"] == 36 and type(got["age"]) is int, f"age should be int 36, got {got['age']!r}"
assert got["role"] == "editor"`,
          },
          {
            name: "ValidationError is a ValueError",
            code: `assert issubclass(ValidationError, ValueError)`,
          },
          {
            name: "every bad field is reported at once",
            code: `try:
    parse_user({"username": "x", "email": "nope", "age": "7", "role": "admin"})
    raise AssertionError("expected ValidationError")
except ValidationError as e:
    assert set(e.errors) == {"username", "email", "age", "role"}, f"got {sorted(e.errors)}"`,
          },
          {
            name: "missing fields are errors, not crashes",
            code: `try:
    parse_user({})
    raise AssertionError("expected ValidationError")
except ValidationError as e:
    assert set(e.errors) == {"username", "email", "age", "role"}, f"got {sorted(e.errors)}"`,
          },
          {
            name: "username rules",
            code: `ok = {"email": "a@b.co", "age": "20", "role": "member"}
for bad in ("ab", "a" * 21, "1ada", "_ada", "ada-lovelace", "ada lovelace", "adaé"):
    with raises(ValidationError):
        parse_user({**ok, "username": bad})
assert parse_user({**ok, "username": "abc"})["username"] == "abc"`,
          },
          {
            name: "email rules",
            code: `ok = {"username": "ada", "age": "20", "role": "member"}
for bad in ("nope", "a@@b.co", "@b.co", "a@bco", "a b@c.co", "a@b.co " + "x" * 300):
    with raises(ValidationError):
        parse_user({**ok, "email": bad})`,
          },
          {
            name: "age rules",
            code: `ok = {"username": "ada", "email": "a@b.co", "role": "member"}
for bad in ("12", "121", "-1", "36.5", "", "abc"):
    with raises(ValidationError):
        parse_user({**ok, "age": bad})
assert parse_user({**ok, "age": "13"})["age"] == 13
assert parse_user({**ok, "age": "120"})["age"] == 120`,
          },
          {
            name: "roles are compared exactly",
            code: `ok = {"username": "ada", "email": "a@b.co", "age": "20"}
for bad in ("admin", "ADMIN", "Member", "editor ", "owner", ""):
    with raises(ValidationError):
        parse_user({**ok, "role": bad})`,
          },
        ],
        requirements: [
          { kind: "defines", value: "parse_user" },
          { kind: "defines", value: "ValidationError" },
          { kind: "no_finding", value: "PY-SWALLOWED-ERROR" },
        ],
        hints: [
          "Write one small parser per field, each raising `ValueError` with a human reason. Then `parse_user` loops over `(name, parser)` pairs, catching `ValueError` and recording the message.",
          "Use `form.get(field, \"\")` so a missing field flows into the same parser and fails there — no separate 'missing' branch needed.",
          "Username: `raw.isascii()`, `raw.replace(\"_\", \"\").isalnum()`, `raw[0].isalpha()`, and a length check. Return `raw.lower()`.",
          "Email: `local, sep, domain = raw.strip().partition(\"@\")` then check `sep`, that `\"@\" not in domain`, `local`, `\".\" in domain`, and no whitespace anywhere. Return `f\"{local}@{domain.lower()}\"`.",
          "Collect into `errors = {}` and `clean = {}`, then `if errors: raise ValidationError(errors)` — the `clean` dict must never be returned partially filled.",
        ],
        solution: `MAX_EMAIL_LEN = 254
ROLES = ("member", "editor")


class ValidationError(ValueError):
    def __init__(self, errors):
        super().__init__(f"{len(errors)} invalid field(s)")
        self.errors = errors


def parse_username(raw):
    """Return the cleaned username or raise ValueError."""
    if not isinstance(raw, str) or not 3 <= len(raw) <= 20:
        raise ValueError("must be 3 to 20 characters")
    if not raw.isascii():
        raise ValueError("ASCII letters, digits and underscore only")
    if not raw.replace("_", "").isalnum():
        raise ValueError("ASCII letters, digits and underscore only")
    if not raw[0].isalpha():
        raise ValueError("must start with a letter")
    return raw.lower()


def parse_email(raw):
    """Return the cleaned email or raise ValueError."""
    if not isinstance(raw, str):
        raise ValueError("required")
    value = raw.strip()
    if not value or len(value) > MAX_EMAIL_LEN:
        raise ValueError(f"must be 1 to {MAX_EMAIL_LEN} characters")
    if any(ch.isspace() for ch in value):
        raise ValueError("must not contain whitespace")
    local, sep, domain = value.partition("@")
    if not sep or "@" in domain:
        raise ValueError("must contain exactly one @")
    if not local:
        raise ValueError("local part is empty")
    if "." not in domain or domain.startswith(".") or domain.endswith("."):
        raise ValueError("domain must contain a dot")
    return f"{local}@{domain.lower()}"


def parse_age(raw):
    """Return the age as an int or raise ValueError."""
    if not isinstance(raw, str) or not (raw.isascii() and raw.isdigit()):
        raise ValueError("must be digits")
    age = int(raw)
    if not 13 <= age <= 120:
        raise ValueError("must be between 13 and 120")
    return age


def parse_role(raw):
    """Return the role unchanged or raise ValueError."""
    if raw not in ROLES:
        raise ValueError(f"must be one of {', '.join(ROLES)}")
    return raw


FIELDS = (
    ("username", parse_username),
    ("email", parse_email),
    ("age", parse_age),
    ("role", parse_role),
)


def parse_user(form):
    """Return a clean dict, or raise ValidationError listing every bad field."""
    errors, clean = {}, {}
    for field, parser in FIELDS:
        try:
            clean[field] = parser(form.get(field, ""))
        except ValueError as exc:
            errors[field] = str(exc)

    if errors:
        raise ValidationError(errors)
    return clean


print(parse_user({"username": "Ada_L", "email": "ada@Example.COM", "age": "36", "role": "editor"}))`,
        why: `Each field parser is independently testable and returns a *usable* value, so nothing downstream handles raw strings. \`parse_user\` is then just a loop — adding a field is one tuple entry.

The security-relevant choices:

- **\`parse_role\` compares against a tuple of exact strings.** No \`.lower()\`, no \`.strip()\`. Normalising a role before comparison is how \`" admin "\` and \`"ADMIN"\` become privilege grants; an identifier is matched exactly or rejected.
- **\`clean\` is built but never returned when \`errors\` is non-empty.** A partially validated dict escaping the function is the subtle version of this bug.
- **Only \`ValueError\` is caught.** A \`TypeError\` from a parser bug propagates instead of being reported to the user as "invalid field".
- **The email length cap comes before the structural work**, so a 10 MB string is rejected cheaply.`,
      },
      wrapup: `- Return the parsed value, not a boolean. The value is the proof.
- Normalise inside the parser — but never normalise an identifier you are about to compare for authorization.
- Collect all field errors in one pass; never return a partially validated structure.
- \`match\` needs a \`case _\` that raises, for the same reason \`if\` needs an \`else\`.`,
      refs: [
        { label: "PEP 636 — Structural Pattern Matching tutorial", url: "https://peps.python.org/pep-0636/" },
        { label: "CWE-1284: Improper Validation of Specified Quantity in Input", url: "https://cwe.mitre.org/data/definitions/1284.html" },
      ],
    },

    /* ----------------------------------------------------------------- 10 */
    {
      id: "m02l05",
      day: 16,
      title: "Capstone: a login gate that gives nothing away",
      minutes: 60,
      secure: "enumeration resistance, lockout, constant-time compare",
      cwe: ["CWE-204", "CWE-307", "CWE-208"],
      tags: ["capstone", "authentication", "lockout", "enumeration", "hmac"],
      lede:
        "Everything from this module in one function: default deny, bounded attempts, an allowlist of outcomes, and error messages that tell an attacker nothing they did not already know.",
      blocks: [
        {
          t: "h",
          text: "Three ways a login endpoint leaks",
        },
        {
          t: "table",
          head: ["Leak", "How the attacker sees it", "Fix"],
          rows: [
            ["Different messages", "`\"no such user\"` vs `\"wrong password\"`", "One message for both."],
            ["Different timing", "Unknown user returns in 2 ms, known user in 90 ms (hashing ran)", "Do the same work either way."],
            ["Different status/shape", "404 vs 401, or a different JSON key", "Identical response for every failure."],
          ],
        },
        {
          t: "p",
          md: `{{User enumeration}} is the first step of a credential-stuffing campaign: confirm which of ten million leaked addresses have accounts here, then spend the attack budget only on those. A distinguishable failure message turns a 10-million-address list into a 40-thousand-address target list.`,
        },
        {
          t: "code",
          label: "vulnerable",
          code: `def login(username, password):
    user = USERS.get(username)
    if user is None:
        return {"ok": False, "error": "no account with that email"}   # leak 1
    if user["password_hash"] != hash_password(password):              # leak 2 (timing)
        return {"ok": False, "error": "incorrect password"}           # leak 1 again
    return {"ok": True, "user": username}`,
          cap: "Two distinct messages, and the hash comparison only runs for accounts that exist — a timing oracle even if the messages were identical.",
        },
        {
          t: "code",
          label: "fixed",
          code: `import hmac

GENERIC = "invalid username or password"
DUMMY_HASH = hash_password("x" * 32)      # so unknown users cost the same

def login(username, password):
    user = USERS.get(username)
    expected = user["password_hash"] if user else DUMMY_HASH
    candidate = hash_password(password)   # always runs

    if not hmac.compare_digest(candidate, expected) or user is None:
        return {"ok": False, "error": GENERIC}
    return {"ok": True, "user": username}`,
          cap: "Identical message, identical work, constant-time comparison. The `or user is None` is still needed — the dummy hash must never be matchable.",
        },
        {
          t: "box",
          kind: "rule",
          title: "`hmac.compare_digest`, not `==`",
          md: `\`==\` on strings or bytes returns as soon as two bytes differ. Over a network that difference is measurable with enough samples, and it leaks the secret one byte at a time — turning a 2^128 search into 16 × 256 guesses.

\`hmac.compare_digest(a, b)\` always examines the full length. Use it for password hashes, API keys, HMAC signatures, CSRF tokens and reset tokens. The auditor flags \`==\` on secret-named values as **medium**.`,
        },
        { t: "h", text: "Rate limiting is part of authentication" },
        {
          t: "p",
          md: `Even a perfect constant-time check falls to an attacker with unlimited attempts. Lock the **account** after a small number of consecutive failures, and make the lockout response identical to the failure response — otherwise lockout state becomes its own enumeration oracle.`,
        },
        {
          t: "box",
          kind: "warn",
          title: "Lockout is a denial-of-service lever",
          md: `An attacker who knows your lockout threshold can lock every account in your system by failing five times against each. Mitigations used in practice: exponential backoff instead of hard lockout, per-IP limits alongside per-account limits, and CAPTCHA before lockout. For this exercise, a simple counter is the right scope — but know what you are trading.`,
        },
        {
          t: "box",
          kind: "cve",
          title: "Where the timing attack is real",
          md: `Remote timing attacks on HMAC comparison were demonstrated practically by Lawson (2009) against Google Keyczar, and the technique has been repeated against API-key checks in web frameworks ever since. Network jitter raises the sample count; it does not prevent the attack. Python ships \`hmac.compare_digest\` precisely because \`==\` is not safe here.`,
        },
      ],
      spot: {
        label: "password reset endpoint",
        prompt: "Click the line that tells an attacker which email addresses have accounts.",
        lines: [5],
        why:
          "Line 5. Returning a different message for an unknown address turns the reset form into an account-existence oracle — no login required, no rate limit triggered. Both branches must return the same text: \"if that address has an account, we have sent a link\".",
        code: `def request_reset(email):
    user = USERS.get(email)
    if user is None:
        return {"sent": False,
                "message": "we have no account for that address"}
    token = issue_reset_token(user)
    send_email(email, token)
    return {"sent": True, "message": "check your inbox"}`,
      },
      quiz: [
        {
          q: "Why compute a hash even when the username does not exist?",
          options: [
            "To keep the CPU warm.",
            "So the response time does not reveal whether the account exists.",
            "It is required by the hashing library.",
          ],
          answer: 1,
          why:
            "Skipping the expensive hash for unknown users makes the two cases distinguishable by timing even when the messages are identical. Do the same work on both paths.",
        },
        {
          q: "`stored_hash == candidate_hash` versus `hmac.compare_digest(stored_hash, candidate_hash)`:",
          options: [
            "Identical; both compare all bytes.",
            "`==` short-circuits on the first differing byte, leaking position information through timing.",
            "`compare_digest` is only for HMACs.",
          ],
          answer: 1,
          why:
            "`compare_digest` is constant-time over the full length and is the correct tool for any secret comparison — hashes, tokens, signatures, API keys.",
        },
        {
          q: "An account locks after 5 failures with the message \"account temporarily locked\". What did you just build?",
          options: [
            "Nothing new — it is a security improvement.",
            "An enumeration oracle: only real accounts can be locked, so the message confirms existence.",
            "A performance problem.",
          ],
          answer: 1,
          why:
            "Lockout state must return the same generic failure as a wrong password. Log the distinction server-side where only you can read it.",
        },
      ],
      exercise: {
        title: "login(): generic failures, bounded attempts, constant-time",
        brief: `Build an authentication gate over a fixed user store.

\`\`\`
USERS = {"ada@example.com": {"pw_hash": _h("correct-horse"), "active": True},
         "lin@example.com": {"pw_hash": _h("battery-staple"), "active": False}}
\`\`\`

(\`_h\` and \`USERS\` are provided in the starter — do not change them.)

Write \`login(email, password, state)\` where \`state\` is a dict used to track failures across calls (the grader passes a fresh \`{}\`).

Rules:

1. **Every failure returns exactly** \`{"ok": False, "error": "invalid username or password"}\` — unknown account, wrong password, inactive account, and locked-out account are indistinguishable to the caller.
2. Success returns \`{"ok": True, "email": <email>}\`.
3. Compare hashes with \`hmac.compare_digest\`, never \`==\`.
4. Always compute the candidate hash, even for unknown accounts.
5. After **5** consecutive failures for an email, that email is locked: every later attempt fails, *even with the correct password*, until \`state\` is reset.
6. A successful login resets that email's failure count to 0.
7. Return a second value too: make \`login\` return \`(response, reason)\` where \`reason\` is a server-side-only string — one of \`"ok"\`, \`"no_such_user"\`, \`"bad_password"\`, \`"inactive"\`, \`"locked"\`. This is what you would log; it must never appear in \`response\`.`,
        rubric: [
          "All four failure modes return byte-identical response dicts",
          "`reason` distinguishes them for the server log",
          "Correct password for an active account succeeds and clears the counter",
          "The 6th consecutive failure is locked; a correct password after lockout still fails with reason `\"locked\"`",
          "Inactive accounts never succeed",
          "`hmac.compare_digest` is used; the auditor reports no `PY-TIMING-COMPARE`",
          "The hash is computed on every path, including unknown accounts",
        ],
        setup: "",
        starter: `import hashlib
import hmac

MAX_FAILURES = 5
GENERIC = {"ok": False, "error": "invalid username or password"}


def _h(password):
    """A real KDF, with a deliberately tiny work factor so the grader stays fast.
    Module 9 covers salts and choosing the iteration count properly."""
    return hashlib.pbkdf2_hmac("sha256", password.encode(), b"demo-salt", 1000).hex()


USERS = {
    "ada@example.com": {"pw_hash": _h("correct-horse"), "active": True},
    "lin@example.com": {"pw_hash": _h("battery-staple"), "active": False},
}
DUMMY_HASH = _h("not-a-real-password-placeholder")


def login(email, password, state):
    """Return (response, reason). response is identical for every failure."""


fresh = {}
print(login("ada@example.com", "correct-horse", fresh))
`,
        stdin: [],
        tests: [
          {
            name: "correct credentials succeed",
            code: `resp, reason = login("ada@example.com", "correct-horse", {})
assert resp == {"ok": True, "email": "ada@example.com"}, f"got {resp!r}"
assert reason == "ok", f"got reason {reason!r}"`,
          },
          {
            name: "all failures are indistinguishable to the caller",
            code: `seen = []
for email, pw in [("nobody@example.com", "x"), ("ada@example.com", "wrong"), ("lin@example.com", "battery-staple")]:
    resp, _ = login(email, pw, {})
    seen.append(resp)
assert all(r == GENERIC for r in seen), f"responses differ: {seen!r}"`,
          },
          {
            name: "the server-side reason distinguishes them",
            code: `assert login("nobody@example.com", "x", {})[1] == "no_such_user"
assert login("ada@example.com", "wrong", {})[1] == "bad_password"
assert login("lin@example.com", "battery-staple", {})[1] == "inactive"`,
          },
          {
            name: "the reason never leaks into the response",
            code: `for email, pw in [("nobody@example.com", "x"), ("ada@example.com", "wrong"), ("lin@example.com", "battery-staple")]:
    resp, reason = login(email, pw, {})
    assert reason not in str(resp), f"reason {reason!r} leaked into {resp!r}"
    assert set(resp) == {"ok", "error"}, f"unexpected keys in {resp!r}"`,
          },
          {
            name: "lockout after 5 consecutive failures",
            code: `st = {}
for i in range(5):
    resp, reason = login("ada@example.com", "wrong", st)
    assert reason == "bad_password", f"attempt {i + 1} gave reason {reason!r}"
resp, reason = login("ada@example.com", "wrong", st)
assert reason == "locked", f"6th attempt should be locked, got {reason!r}"
assert resp == GENERIC`,
          },
          {
            name: "a locked account rejects the correct password",
            code: `st = {}
for _ in range(5):
    login("ada@example.com", "wrong", st)
resp, reason = login("ada@example.com", "correct-horse", st)
assert resp == GENERIC and reason == "locked", f"got {resp!r} {reason!r}"`,
          },
          {
            name: "success clears the counter",
            code: `st = {}
for _ in range(4):
    login("ada@example.com", "wrong", st)
assert login("ada@example.com", "correct-horse", st)[1] == "ok"
for i in range(5):
    assert login("ada@example.com", "wrong", st)[1] == "bad_password", f"counter not reset (attempt {i + 1})"`,
          },
          {
            name: "lockout is per account",
            code: `st = {}
for _ in range(6):
    login("ada@example.com", "wrong", st)
assert login("nobody@example.com", "x", st)[1] == "no_such_user", "one locked account must not lock the others"`,
          },
          {
            name: "the dummy hash is never a valid password",
            code: `resp, reason = login("nobody@example.com", "not-a-real-password-placeholder", {})
assert reason == "no_such_user", f"the placeholder must never authenticate, got {reason!r}"
assert resp == GENERIC`,
          },
        ],
        requirements: [
          { kind: "defines", value: "login" },
          { kind: "calls", value: "hmac.compare_digest" },
          { kind: "no_finding", value: "PY-TIMING-COMPARE" },
        ],
        hints: [
          "Track failures as `state.setdefault(\"failures\", {})` keyed by email, or simply `state.get(email, 0)`. Check the lockout *before* doing anything else for that email.",
          "`user = USERS.get(email)` then `expected = user[\"pw_hash\"] if user else DUMMY_HASH`. Compute `candidate = _h(password)` unconditionally so both paths cost the same.",
          "`matched = hmac.compare_digest(candidate, expected)` — then decide the reason: no user → `\"no_such_user\"`, not matched → `\"bad_password\"`, not active → `\"inactive\"`. Return `GENERIC` for all three.",
          "Write a small `_fail(state, email, reason)` helper that increments the counter and returns `(GENERIC, reason)` — then every failure path is one line and cannot accidentally return a different dict.",
          "Return a *copy* (`dict(GENERIC)`) or the constant itself consistently; the tests compare by value, but returning the shared constant is fine as long as you never mutate it.",
        ],
        solution: `import hashlib
import hmac

MAX_FAILURES = 5
GENERIC = {"ok": False, "error": "invalid username or password"}


def _h(password):
    """A real KDF, with a deliberately tiny work factor so the grader stays fast.
    Module 9 covers salts and choosing the iteration count properly."""
    return hashlib.pbkdf2_hmac("sha256", password.encode(), b"demo-salt", 1000).hex()


USERS = {
    "ada@example.com": {"pw_hash": _h("correct-horse"), "active": True},
    "lin@example.com": {"pw_hash": _h("battery-staple"), "active": False},
}
DUMMY_HASH = _h("not-a-real-password-placeholder")


def _failures(state):
    return state.setdefault("failures", {})


def _fail(state, email, reason):
    """Record a failed attempt and return the one response every failure gives."""
    counts = _failures(state)
    counts[email] = counts.get(email, 0) + 1
    return dict(GENERIC), reason


def login(email, password, state):
    """Return (response, reason). response is identical for every failure."""
    counts = _failures(state)

    if counts.get(email, 0) >= MAX_FAILURES:
        return dict(GENERIC), "locked"

    user = USERS.get(email)
    expected = user["pw_hash"] if user is not None else DUMMY_HASH

    # Always hash, so an unknown account costs the same as a known one.
    candidate = _h(password)
    matched = hmac.compare_digest(candidate, expected)

    if user is None:
        return _fail(state, email, "no_such_user")
    if not matched:
        return _fail(state, email, "bad_password")
    if not user["active"]:
        return _fail(state, email, "inactive")

    counts[email] = 0
    return {"ok": True, "email": email}, "ok"


fresh = {}
print(login("ada@example.com", "correct-horse", fresh))`,
        why: `Four distinct failure conditions, one response. The caller — and therefore the attacker — learns only "that did not work". The \`reason\` channel exists for your logs and your metrics, which is where the distinction belongs.

The ordering is deliberate:

- **Lockout is checked first**, before the user lookup, so a locked account consumes no hashing work and gives no new information.
- **The hash is computed before any branch on \`user\`**, so the unknown-account path costs the same as the known-account path. Moving \`candidate = _h(password)\` below \`if user is None\` would reintroduce the timing oracle that the identical messages were meant to close.
- **\`hmac.compare_digest\` runs even for the dummy hash.** Its cost is part of the constant work.
- **\`_fail\` is the single exit for failures**, so a future edit cannot accidentally give one branch a different message or forget to increment the counter.

What this deliberately does *not* do: unlock after a timeout, limit by IP, or use a real password KDF. The first two are policy you would tune with real traffic; the third is Module 9, where \`sha256\` on a password becomes a finding rather than a placeholder.`,
      },
      wrapup: `- One generic failure message, one response shape, one timing profile.
- Compute the same work on the unknown-account path, or timing re-opens what the message closed.
- \`hmac.compare_digest\` for every secret comparison.
- Bound the attempts, and keep the reason for the distinction in your logs — never in the response.`,
      refs: [
        { label: "hmac.compare_digest", url: "https://docs.python.org/3/library/hmac.html#hmac.compare_digest" },
        { label: "OWASP Authentication Cheat Sheet", url: "https://cheatsheetseries.owasp.org/cheatsheets/Authentication_Cheat_Sheet.html" },
        { label: "CWE-204: Observable Response Discrepancy", url: "https://cwe.mitre.org/data/definitions/204.html" },
      ],
    },
  ],
};
