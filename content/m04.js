export default {
  id: "m04",
  number: 4,
  title: "Functions, scope and failure",
  focus: "error hygiene",
  subtitle:
    "Designing functions whose contract cannot be misread, and handling failure so that errors are neither swallowed nor turned into reconnaissance for an attacker.",
  objectives: [
    "Write functions with narrow, explicit signatures and a single return contract.",
    "Use `*args`, `**kwargs` and keyword-only parameters without widening your attack surface.",
    "Raise and catch specific exceptions; never swallow, never catch broadly.",
    "Design error messages that help the caller and tell an attacker nothing.",
    "Use `with` and `finally` so cleanup and release happen on every path.",
  ],
  rules: [
    { id: "PY-SWALLOWED-ERROR", what: "`except: pass` turns a failed check into a granted one" },
    { id: "PY-BARE-EXCEPT", what: "bare `except:` catches KeyboardInterrupt and SystemExit too" },
    { id: "PY-TRACEBACK-LEAK", what: "tracebacks disclose paths, versions and queries" },
  ],
  capstone:
    "Day 26 builds a conversion library with a two-channel error design: a rich internal diagnostic and a deliberately boring message for the caller.",

  lessons: [
    /* ----------------------------------------------------------------- 16 */
    {
      id: "m04l01",
      day: 22,
      title: "Functions, contracts, and the single return shape",
      minutes: 60,
      secure: "unambiguous contracts",
      cwe: ["CWE-393", "CWE-754"],
      tags: ["def", "return", "arguments", "contract", "docstring"],
      lede:
        "A function that sometimes returns a value, sometimes `None` and sometimes a string explaining what went wrong is three functions wearing one name. Every caller gets to guess which one they received.",
      blocks: [
        {
          t: "code",
          label: "example",
          code: `def rename(path, new_name, *, overwrite=False):
    """Rename a file.

    Args:
        path: the existing file.
        new_name: the new base name.
        overwrite: replace an existing target. Keyword-only on purpose.

    Returns:
        The new path.

    Raises:
        FileExistsError: when the target exists and overwrite is False.
    """
    ...`,
          cap: "The `*` makes everything after it keyword-only. `rename(p, n, True)` becomes a TypeError instead of a silent, destructive surprise.",
        },
        {
          t: "box",
          kind: "rule",
          title: "Dangerous parameters should be keyword-only",
          md: `\`overwrite\`, \`force\`, \`verify\`, \`recursive\`, \`insecure\`, \`skip_validation\` — any flag whose wrong value causes damage belongs after a \`*\`.

Positional booleans are unreadable at the call site (\`copy(a, b, True, False, True)\`) and a reordered signature silently changes meaning. Keyword-only makes both failure modes impossible.`,
        },
        { t: "h", text: "One return shape" },
        {
          t: "code",
          label: "vulnerable",
          code: `def get_user(uid):
    row = db.find(uid)
    if row is None:
        return None                      # not found
    if row["deleted"]:
        return "deleted"                 # a string?
    if not row["active"]:
        return False                     # a bool?
    return row                           # a dict`,
          cap: "Four return types. `if get_user(uid):` is True for the dict and the non-empty string `\"deleted\"` — so a deleted account passes the check.",
        },
        {
          t: "code",
          label: "fixed",
          code: `class UserNotFound(LookupError):
    pass

class UserInactive(PermissionError):
    pass

def get_user(uid):
    """Return the user record. Raise on anything that is not a usable user."""
    row = db.find(uid)
    if row is None or row["deleted"]:
        raise UserNotFound(uid)          # deleted and missing look identical
    if not row["active"]:
        raise UserInactive(uid)
    return row                           # the ONLY successful return`,
          cap: "One happy path, explicit failures. Note that deleted and missing raise the same error — a distinction here would be an enumeration oracle.",
        },
        { t: "h", text: "Scope, and why globals bite" },
        {
          t: "p",
          md: `Python resolves names {{local}} → {{enclosing}} → {{global}} → {{built-in}}. Assigning to a name anywhere in a function makes it local *for the whole function*, which produces the classic confusing error:`,
        },
        {
          t: "repl",
          lines: [
            ">>> attempts = 0",
            ">>> def record():",
            "...     attempts = attempts + 1",
            "...",
            ">>> record()",
            "UnboundLocalError: cannot access local variable 'attempts' where it is not associated with a value",
          ],
        },
        {
          t: "box",
          kind: "warn",
          title: "`global` in a server is shared state",
          md: `\`global counter\` works, and in a single-threaded script it is merely inelegant. In a threaded web server it is a data race: two requests increment the same counter and one update disappears, or worse, request A's value is read by request B.

Pass state in and return it out, or put it on an object. Module-level mutable state is the bug you cannot reproduce.`,
        },
        {
          t: "box",
          kind: "pitfall",
          title: "Returning `None` to mean failure",
          md: `\`\`\`
user = get_user(uid)
if user:                     # None, False, {} and "" are all falsy
    grant_access(user)
\`\`\`

The check works until \`get_user\` returns an empty dict for "found but no fields", at which point access is silently denied — or the reverse, when the sentinel is truthy. Raise for failure; return only success.`,
        },
      ],
      spot: {
        label: "token verification helper",
        prompt: "Click the line whose return value will be misread by a caller.",
        lines: [7],
        why:
          "Line 7. Returning the string `\"expired\"` is truthy, so the standard caller `if verify(tok): allow()` grants access to every expired token. Lines 5 and 9 return a bool and are consistent; the odd one out is the one that breaks the contract.",
        code: `def verify(token):
    claims = decode(token)
    if claims is None:
        return False
    if claims["exp"] < now():
        return "expired"
    return True`,
      },
      quiz: [
        {
          q: "Why make `overwrite` keyword-only with `*`?",
          options: [
            "It is faster.",
            "`f(a, b, True)` is unreadable and silently changes meaning if the signature is reordered.",
            "Positional booleans are a SyntaxError.",
          ],
          answer: 1,
          why:
            "Call sites become self-documenting, and inserting a parameter later cannot turn `True` into the wrong flag. For destructive flags that difference is data loss.",
        },
        {
          q: "A function returns a dict on success, `None` when missing, and `\"deleted\"` when deleted. What breaks?",
          options: [
            "Nothing.",
            "`if result:` is true for `\"deleted\"`, so deleted records pass the success check.",
            "Python forbids multiple return types.",
          ],
          answer: 1,
          why: "Non-empty strings are truthy. Mixed return types push the error handling into every caller, where it will be done inconsistently.",
        },
        {
          q: "`UnboundLocalError` for a module-level variable means:",
          options: [
            "The variable does not exist.",
            "The function assigns to that name somewhere, making it local throughout the function.",
            "You need an import.",
          ],
          answer: 1,
          why:
            "Assignment anywhere in the body makes the name local for the entire body. Prefer passing values in and returning them out over reaching for `global`.",
        },
      ],
      exercise: {
        title: "A lookup with one success shape",
        brief: `Rewrite a mixed-contract lookup into one with a single return shape.

Given this record store (provided in the starter):

\`\`\`
RECORDS = {
    1: {"id": 1, "name": "ada", "active": True, "deleted": False},
    2: {"id": 2, "name": "lin", "active": False, "deleted": False},
    3: {"id": 3, "name": "mo", "active": True, "deleted": True},
}
\`\`\`

Define exceptions \`RecordNotFound(LookupError)\` and \`RecordInactive(PermissionError)\`, then write:

\`get_record(record_id, *, include_inactive=False)\`

- Returns a **copy** of the record dict on success.
- Raises \`RecordNotFound\` when the id is absent **or** the record is deleted — the two cases must be indistinguishable to the caller, including in the message, which must be exactly \`"no such record"\`.
- Raises \`RecordInactive\` when the record exists, is not deleted, but is inactive — **unless** \`include_inactive=True\`, in which case it is returned.
- \`include_inactive\` must be keyword-only: \`get_record(1, True)\` must raise \`TypeError\`.
- Raises \`TypeError\` when \`record_id\` is not an \`int\` (and \`bool\` does not count).`,
        rubric: [
          "Success always returns a dict copy; mutating it does not change `RECORDS`",
          "Missing and deleted ids raise `RecordNotFound` with the identical message `\"no such record\"`",
          "Inactive raises `RecordInactive`, unless `include_inactive=True`",
          "`get_record(1, True)` raises `TypeError` — the flag is keyword-only",
          "`RecordNotFound` subclasses `LookupError`; `RecordInactive` subclasses `PermissionError`",
          "No `None` is ever returned",
        ],
        starter: `RECORDS = {
    1: {"id": 1, "name": "ada", "active": True, "deleted": False},
    2: {"id": 2, "name": "lin", "active": False, "deleted": False},
    3: {"id": 3, "name": "mo", "active": True, "deleted": True},
}


class RecordNotFound(LookupError):
    pass


class RecordInactive(PermissionError):
    pass


def get_record(record_id):
    """Return a copy of the record, or raise. Make include_inactive keyword-only."""


print(get_record(1)["name"])
`,
        stdin: [],
        tests: [
          {
            name: "returns a copy on success",
            code: `got = get_record(1)
assert got["name"] == "ada", f"got {got!r}"
got["name"] = "tampered"
assert RECORDS[1]["name"] == "ada", "get_record returned the live record, not a copy"`,
          },
          {
            name: "missing and deleted are indistinguishable",
            code: `msgs = set()
for bad in (99, 3):
    try:
        get_record(bad)
        raise AssertionError(f"{bad} should have raised")
    except RecordNotFound as e:
        msgs.add(str(e))
assert msgs == {"no such record"}, f"messages differ or are wrong: {msgs!r}"`,
          },
          {
            name: "inactive records are refused by default",
            code: `try:
    get_record(2)
    raise AssertionError("expected RecordInactive")
except RecordInactive:
    pass`,
          },
          {
            name: "include_inactive opens the door, by keyword only",
            code: `assert get_record(2, include_inactive=True)["name"] == "lin"
with raises(TypeError):
    get_record(2, True)`,
          },
          {
            name: "include_inactive does not resurrect deleted records",
            code: `with raises(RecordNotFound):
    get_record(3, include_inactive=True)`,
          },
          {
            name: "exception hierarchy is usable",
            code: `assert issubclass(RecordNotFound, LookupError)
assert issubclass(RecordInactive, PermissionError)
try:
    get_record(99)
except LookupError:
    pass`,
          },
          {
            name: "ids are type-checked",
            code: `for bad in ("1", 1.0, None, True):
    with raises(TypeError):
        get_record(bad)`,
          },
          { name: "prints a name", code: `assert "ada" in _stdout` },
        ],
        requirements: [
          { kind: "defines", value: "get_record" },
          { kind: "regex", value: "\\*,", message: "Make `include_inactive` keyword-only with a bare `*` in the signature." },
        ],
        hints: [
          "Signature: `def get_record(record_id, *, include_inactive=False):` — the bare `*` is what produces the TypeError for positional use.",
          "Check `isinstance(record_id, bool) or not isinstance(record_id, int)` first and raise `TypeError`.",
          "Collapse missing and deleted into one branch: `row = RECORDS.get(record_id)` then `if row is None or row[\"deleted\"]: raise RecordNotFound(\"no such record\")`.",
          "`dict(row)` is the copy. Returning `row` hands the caller your live store.",
        ],
        solution: `RECORDS = {
    1: {"id": 1, "name": "ada", "active": True, "deleted": False},
    2: {"id": 2, "name": "lin", "active": False, "deleted": False},
    3: {"id": 3, "name": "mo", "active": True, "deleted": True},
}


class RecordNotFound(LookupError):
    pass


class RecordInactive(PermissionError):
    pass


def get_record(record_id, *, include_inactive=False):
    """Return a copy of the record, or raise."""
    if isinstance(record_id, bool) or not isinstance(record_id, int):
        raise TypeError(f"record_id must be an int, got {type(record_id).__name__}")

    row = RECORDS.get(record_id)
    if row is None or row["deleted"]:
        raise RecordNotFound("no such record")

    if not row["active"] and not include_inactive:
        raise RecordInactive("record is not active")

    return dict(row)


print(get_record(1)["name"])`,
        why: `There is exactly one \`return\`, and reaching it means the record is real, not deleted, and either active or explicitly permitted. A caller cannot hold a value from this function that needs further checking.

The design decisions that are specifically security decisions:

- **Missing and deleted raise the same exception with the same message.** A distinct "this record was deleted" tells an attacker that the id was valid — enough to enumerate your id space and learn how many customers you lost last quarter.
- **\`include_inactive\` is keyword-only**, so \`get_record(uid, True)\` cannot be written by accident during a refactor. Inactive accounts are exactly the ones that get re-enabled by mistake.
- **\`include_inactive\` does not override deletion.** Widening flags should widen one thing, never two; a flag that quietly resurrects deleted records is how "soft delete" stops meaning anything.
- **The return is a copy**, so a caller's later mutation cannot corrupt the store for every subsequent request in the process.`,
      },
      wrapup: `- One success shape, explicit exceptions for everything else.
- Dangerous flags go after \`*\` so call sites read as English.
- Collapse "not found" and "not permitted to know" into one indistinguishable failure.
- Module-level mutable state is a data race in any threaded server.`,
      refs: [
        { label: "Python tutorial — defining functions", url: "https://docs.python.org/3/tutorial/controlflow.html#defining-functions" },
        { label: "CWE-393: Return of Wrong Status Code", url: "https://cwe.mitre.org/data/definitions/393.html" },
      ],
    },

    /* ----------------------------------------------------------------- 17 */
    {
      id: "m04l02",
      day: 23,
      title: "*args, **kwargs, and the parameters you did not mean to accept",
      minutes: 60,
      secure: "narrow signatures, mass assignment",
      cwe: ["CWE-915"],
      tags: ["args", "kwargs", "unpacking", "mass-assignment", "signatures"],
      lede:
        "`**kwargs` is how a function says *I accept anything*. Combine it with a database update and you have built the mass-assignment vulnerability that turns an ordinary user into an administrator.",
      blocks: [
        {
          t: "code",
          label: "example",
          code: `def audit(*events, source="cli", **tags):
    print(events)     # tuple of positional arguments
    print(source)     # keyword with a default
    print(tags)       # dict of everything else

audit("login", "logout", source="api", region="emea", tier="gold")
# ('login', 'logout')
# api
# {'region': 'emea', 'tier': 'gold'}`,
        },
        {
          t: "repl",
          lines: [
            ">>> def f(a, b, *, c=0): return a, b, c",
            ">>> args = (1, 2); kw = {\"c\": 3}",
            ">>> f(*args, **kw)        # unpacking",
            "(1, 2, 3)",
            ">>> merged = {**defaults, **overrides}   # later wins",
          ],
        },
        { t: "h", text: "Mass assignment" },
        {
          t: "code",
          label: "vulnerable",
          code: `def update_profile(user_id, **fields):
    """Update any field the caller names."""
    db.update("users", user_id, **fields)

# the HTTP layer, being helpful:
update_profile(session.user_id, **request.json)
# request body: {"display_name": "ada", "role": "admin", "email_verified": true}`,
          cap: "The client chooses which columns to write. `role`, `is_admin`, `account_balance`, `email_verified` and `password_hash` are all in scope.",
        },
        {
          t: "code",
          label: "fixed",
          code: `EDITABLE = ("display_name", "bio", "timezone")

def update_profile(user_id, fields):
    """Update only the fields a user is allowed to change."""
    unknown = set(fields) - set(EDITABLE)
    if unknown:
        raise ValueError(f"not editable: {sorted(unknown)}")
    clean = {k: fields[k] for k in EDITABLE if k in fields}
    db.update("users", user_id, **clean)`,
          cap: "An explicit tuple of editable fields, and the update is built from it. Rejecting unknown fields loudly beats ignoring them silently — the client learns its request was wrong.",
        },
        {
          t: "box",
          kind: "cve",
          title: "GitHub, 2012",
          md: `A Rails developer demonstrated mass assignment against GitHub itself by adding a \`public_key\` parameter to an ordinary form post, gaining commit access to the Rails repository. Same bug class, different language: the framework helpfully bound every submitted parameter to a model attribute.

Python frameworks are equally willing. \`Model(**request.json)\`, \`setattr(obj, k, v)\` in a loop, and \`dataclasses.replace(obj, **body)\` all have this shape.`,
        },
        { t: "h", text: "When *args/**kwargs is the right call" },
        {
          t: "p",
          md: `Decorators and thin wrappers legitimately forward arguments they do not understand:`,
        },
        {
          t: "code",
          label: "example",
          code: `import functools

def audited(fn):
    @functools.wraps(fn)
    def wrapper(*args, **kwargs):
        log.info("calling %s", fn.__name__)        # names, not values
        return fn(*args, **kwargs)
    return wrapper`,
          cap: "`functools.wraps` copies the name and docstring so the wrapper does not erase the identity of what it wraps. Note that the log records the function name, not the arguments — arguments are where the secrets are.",
        },
        {
          t: "box",
          kind: "rule",
          title: "Narrow at the boundary, wide in the middle",
          md: `Functions that face untrusted input take **named parameters only**. Generic plumbing in the interior may forward \`**kwargs\`.

The moment a \`**kwargs\` function can write to storage, change a permission, or build a query, it needs an explicit field allowlist.`,
        },
        {
          t: "box",
          kind: "pitfall",
          title: "`dict(**untrusted)` is not validation",
          md: `Copying a dict does not restrict its keys. Neither does type-annotating the parameter — annotations are not enforced at runtime. The only thing that restricts keys is code that compares them to a list you wrote.`,
        },
      ],
      spot: {
        label: "settings endpoint",
        prompt: "Click the line that lets a client set any column in the row.",
        lines: [6],
        why:
          "Line 6. `**body` expands every key the client sent into the update call, so `{\"theme\":\"dark\",\"is_admin\":true}` writes `is_admin`. Line 4's authentication is irrelevant — the user is authenticated, they are simply writing fields they should not control.",
        code: `def save_settings(request):
    body = request.json
    user = request.user
    if not user.is_authenticated:
        raise PermissionError("login required")
    db.update("users", user.id, **body)
    return {"ok": True}`,
      },
      quiz: [
        {
          q: "`def update(**fields): db.update(table, id, **fields)` called with `**request.json`. What is the vulnerability?",
          options: [
            "SQL injection",
            "Mass assignment — the client chooses which columns are written",
            "Nothing, if the user is authenticated",
          ],
          answer: 1,
          why:
            "CWE-915. Authentication establishes *who* is writing, not *what* they may write. The fix is an explicit allowlist of editable fields.",
        },
        {
          q: "What does `functools.wraps` do, and why care?",
          options: [
            "Makes the wrapper faster.",
            "Copies `__name__`, `__doc__` and `__wrapped__` so the decorated function keeps its identity.",
            "Validates arguments.",
          ],
          answer: 1,
          why:
            "Without it, every decorated function reports itself as `wrapper`, which makes logs, tracebacks and introspection-based routing useless — and introspection-based routing that matches on the wrong name is its own bug.",
        },
        {
          q: "Where is `**kwargs` acceptable?",
          options: [
            "Anywhere; it is flexible.",
            "In interior plumbing such as decorators, not in functions that take untrusted input and write state.",
            "Never.",
          ],
          answer: 1,
          why: "Forwarding is a legitimate use. Accepting arbitrary named fields from a request and persisting them is not.",
        },
      ],
      exercise: {
        title: "A profile updater with an editable-field allowlist",
        brief: `A users table is simulated as a dict of dicts (provided). Write \`update_profile(store, user_id, fields, *, actor_role="member")\`.

Rules:

1. \`fields\` is a dict supplied by the client. Only these may be written by anyone: \`"display_name"\`, \`"bio"\`, \`"timezone"\`.
2. These may be written **only** when \`actor_role == "admin"\`: \`"role"\`, \`"active"\`.
3. Any other key — including \`"id"\`, \`"password_hash"\`, \`"balance"\` and anything unknown — raises \`ValueError\` listing the rejected keys sorted: \`"not editable: ['balance', 'id']"\`.
4. A non-admin naming an admin-only field raises \`PermissionError\` with message \`"insufficient role"\`. (Check unknown keys **first**: an unknown key is a \`ValueError\` even for an admin.)
5. \`display_name\` is truncated to 40 characters; \`bio\` to 200. \`timezone\` must be a string containing \`/\` (e.g. \`"Europe/Madrid"\`), else \`ValueError\`.
6. \`actor_role\` is keyword-only.
7. Return a **copy** of the updated record. The store is updated in place.
8. An empty \`fields\` dict changes nothing and returns the record.`,
        rubric: [
          "Unknown and protected keys raise `ValueError` listing them sorted",
          "Admin-only fields raise `PermissionError` for non-admins and succeed for admins",
          "Unknown keys are rejected before the role check",
          "Lengths are enforced; a bad timezone raises",
          "`actor_role` is keyword-only",
          "The returned record is a copy; the store is updated",
        ],
        starter: `EDITABLE = ("display_name", "bio", "timezone")
ADMIN_ONLY = ("role", "active")
MAX_NAME = 40
MAX_BIO = 200

STORE = {
    7: {"id": 7, "display_name": "ada", "bio": "", "timezone": "Europe/Madrid",
        "role": "member", "active": True, "password_hash": "<redacted>", "balance": 100},
}


def update_profile(store, user_id, fields):
    """Apply only permitted fields. Make actor_role keyword-only."""


print(update_profile(STORE, 7, {"display_name": "Ada L."})["display_name"])
`,
        stdin: [],
        tests: [
          {
            name: "ordinary fields are written",
            code: `st = {1: {"id": 1, "display_name": "a", "bio": "", "timezone": "Europe/Madrid", "role": "member", "active": True}}
got = update_profile(st, 1, {"display_name": "Ada", "bio": "hello"})
assert got["display_name"] == "Ada" and got["bio"] == "hello", f"got {got!r}"
assert st[1]["display_name"] == "Ada", "the store was not updated"`,
          },
          {
            name: "protected and unknown keys are refused by name",
            code: `st = {1: {"id": 1, "display_name": "a", "bio": "", "timezone": "Europe/Madrid", "role": "member", "active": True}}
try:
    update_profile(st, 1, {"id": 2, "balance": 99, "display_name": "x"})
    raise AssertionError("expected ValueError")
except ValueError as e:
    assert str(e) == "not editable: ['balance', 'id']", f"got {str(e)!r}"
assert st[1]["id"] == 1, "the store was modified despite the error"`,
          },
          {
            name: "admin-only fields need the admin role",
            code: `st = {1: {"id": 1, "display_name": "a", "bio": "", "timezone": "Europe/Madrid", "role": "member", "active": True}}
try:
    update_profile(st, 1, {"role": "admin"})
    raise AssertionError("expected PermissionError")
except PermissionError as e:
    assert str(e) == "insufficient role", f"got {str(e)!r}"
got = update_profile(st, 1, {"role": "admin"}, actor_role="admin")
assert got["role"] == "admin"`,
          },
          {
            name: "unknown keys are rejected before the role check",
            code: `st = {1: {"id": 1, "display_name": "a", "bio": "", "timezone": "Europe/Madrid", "role": "member", "active": True}}
with raises(ValueError):
    update_profile(st, 1, {"wat": 1}, actor_role="admin")
try:
    update_profile(st, 1, {"wat": 1, "role": "admin"})
    raise AssertionError("expected an error")
except ValueError:
    pass
except PermissionError:
    raise AssertionError("unknown keys must be checked before the role check")`,
          },
          {
            name: "values are bounded and validated",
            code: `st = {1: {"id": 1, "display_name": "a", "bio": "", "timezone": "Europe/Madrid", "role": "member", "active": True}}
assert len(update_profile(st, 1, {"display_name": "x" * 200})["display_name"]) == 40
assert len(update_profile(st, 1, {"bio": "y" * 500})["bio"]) == 200
for bad in ("Madrid", "", 5, None):
    with raises(ValueError):
        update_profile(st, 1, {"timezone": bad})`,
          },
          {
            name: "actor_role is keyword-only",
            code: `st = {1: {"id": 1, "display_name": "a", "bio": "", "timezone": "Europe/Madrid", "role": "member", "active": True}}
with raises(TypeError):
    update_profile(st, 1, {"role": "admin"}, "admin")`,
          },
          {
            name: "the result is a copy and empty updates are fine",
            code: `st = {1: {"id": 1, "display_name": "a", "bio": "", "timezone": "Europe/Madrid", "role": "member", "active": True}}
got = update_profile(st, 1, {})
got["display_name"] = "tampered"
assert st[1]["display_name"] == "a", "returned the live record"`,
          },
          {
            name: "a missing user is a LookupError",
            code: `st = {1: {"id": 1, "display_name": "a", "bio": "", "timezone": "Europe/Madrid", "role": "member", "active": True}}
try:
    update_profile(st, 999, {"bio": "x"})
    raise AssertionError("expected an error for a missing user")
except LookupError:
    pass`,
          },
        ],
        requirements: [
          { kind: "defines", value: "update_profile" },
          { kind: "regex", value: "\\*,", message: "Make `actor_role` keyword-only with a bare `*`." },
        ],
        hints: [
          "Compute the rejected set first: `unknown = set(fields) - set(EDITABLE) - set(ADMIN_ONLY)` and raise `ValueError(\"not editable: \" + repr(sorted(unknown)))` — note the test expects the sorted list's `repr`.",
          "Then the role check: `restricted = set(fields) & set(ADMIN_ONLY)` and `if restricted and actor_role != \"admin\": raise PermissionError(\"insufficient role\")`.",
          "Validate *all* values before writing any of them, so a failure in the third field does not leave the first two applied. Build a `clean` dict, then update the record from it.",
          "`KeyError` is a subclass of `LookupError`, so `store[user_id]` raising naturally satisfies the missing-user test — but an explicit check with a clear message is better.",
        ],
        solution: `EDITABLE = ("display_name", "bio", "timezone")
ADMIN_ONLY = ("role", "active")
MAX_NAME = 40
MAX_BIO = 200

STORE = {
    7: {"id": 7, "display_name": "ada", "bio": "", "timezone": "Europe/Madrid",
        "role": "member", "active": True, "password_hash": "<redacted>", "balance": 100},
}


def _clean_value(key, value):
    """Validate and normalise one permitted field."""
    if key == "display_name":
        if not isinstance(value, str) or not value.strip():
            raise ValueError("display_name must be a non-empty string")
        return value[:MAX_NAME]
    if key == "bio":
        if not isinstance(value, str):
            raise ValueError("bio must be a string")
        return value[:MAX_BIO]
    if key == "timezone":
        if not isinstance(value, str) or "/" not in value:
            raise ValueError("timezone must look like 'Area/City'")
        return value
    if key == "role":
        if value not in ("member", "editor", "admin"):
            raise ValueError("unknown role")
        return value
    if key == "active":
        if not isinstance(value, bool):
            raise ValueError("active must be a boolean")
        return value
    raise ValueError(f"not editable: {key}")


def update_profile(store, user_id, fields, *, actor_role="member"):
    """Apply only permitted fields."""
    if not isinstance(fields, dict):
        raise ValueError("fields must be an object")

    record = store.get(user_id)
    if record is None:
        raise LookupError("no such record")

    unknown = set(fields) - set(EDITABLE) - set(ADMIN_ONLY)
    if unknown:
        raise ValueError(f"not editable: {sorted(unknown)}")

    restricted = set(fields) & set(ADMIN_ONLY)
    if restricted and actor_role != "admin":
        raise PermissionError("insufficient role")

    # Validate everything before writing anything, so a late failure
    # cannot leave the record half-updated.
    clean = {key: _clean_value(key, value) for key, value in fields.items()}
    record.update(clean)
    return dict(record)


print(update_profile(STORE, 7, {"display_name": "Ada L."})["display_name"])`,
        why: `The writable surface is two tuples at the top of the file. A reviewer can see the entire set of client-controllable columns without reading the function, and \`password_hash\`, \`balance\` and \`id\` are not in it — so no request body can reach them regardless of what the HTTP layer forwards.

Three details:

- **Unknown keys are checked before the role check**, which keeps the error specific: an admin sending a typo gets "not editable", not a confusing permission error. It also avoids leaking which unknown names happen to be admin-only.
- **All values are validated before any are written.** The dict comprehension raises before \`record.update\` runs, so a request with a good \`display_name\` and a bad \`timezone\` applies neither. Partial updates are how records end up in states the application does not expect.
- **The error message lists the rejected keys.** This is safe — the client already knows what it sent — and it turns a frustrating 400 into an actionable one.`,
      },
      wrapup: `- \`**kwargs\` plus a write is mass assignment. Name the editable fields explicitly.
- Keyword-only parameters for anything whose wrong value is destructive.
- Validate every value before applying any of them; half-written records are their own bug class.
- \`functools.wraps\` on every decorator, and log the function name rather than its arguments.`,
      refs: [
        { label: "CWE-915: Improperly Controlled Modification of Dynamically-Determined Object Attributes", url: "https://cwe.mitre.org/data/definitions/915.html" },
        { label: "functools.wraps", url: "https://docs.python.org/3/library/functools.html#functools.wraps" },
      ],
    },

    /* ----------------------------------------------------------------- 18 */
    {
      id: "m04l03",
      day: 24,
      title: "Exceptions: catch what you can handle, nothing else",
      minutes: 60,
      secure: "no swallowed failures",
      cwe: ["CWE-390", "CWE-396", "CWE-755"],
      tags: ["exceptions", "try", "except", "finally", "raise"],
      lede:
        "`except Exception: pass` is the most dangerous four words in Python. A security check that raises and is silently ignored is a security check that passed.",
      blocks: [
        {
          t: "code",
          label: "example",
          code: `try:
    value = int(raw)
except ValueError as exc:
    raise ValueError(f"not a number: {raw!r}") from exc   # chain the cause
else:
    print("parsed", value)        # runs only when no exception occurred
finally:
    cleanup()                     # runs on every path, including return/raise`,
          cap: "`else` is for the code that must not be inside the `try` — otherwise an exception from `print` would be caught by the `except` above it.",
        },
        {
          t: "table",
          head: ["Pattern", "Catches", "Verdict"],
          rows: [
            ["`except ValueError:`", "exactly that", "**Correct.**"],
            ["`except (ValueError, KeyError):`", "two specific types", "**Correct.**"],
            ["`except OSError:`", "file/network errors", "**Correct** — a real category."],
            ["`except Exception:`", "almost everything", "Only at a top-level boundary, and it must log and re-raise or return a failure."],
            ["`except:`", "everything, incl. `KeyboardInterrupt`, `SystemExit`", "**Never.** Ctrl-C stops working."],
            ["`except Exception: pass`", "everything, silently", "**Never.** This is the bug."],
          ],
        },
        { t: "h", text: "The swallowed security check" },
        {
          t: "code",
          label: "vulnerable",
          code: `def is_signature_valid(payload, signature):
    try:
        verify(payload, signature)
        return True
    except Exception:
        pass
    return True              # the author meant False -- and nothing told them`,
          cap: "A deliberately exaggerated version of a real pattern. The subtler form has no `return True` at the end, so the function returns `None` — falsy today, until a caller writes `is not None`.",
        },
        {
          t: "code",
          label: "fixed",
          code: `def is_signature_valid(payload, signature):
    try:
        verify(payload, signature)
    except InvalidSignature:
        log.warning("signature rejected for payload id=%s", payload.get("id"))
        return False
    except (TypeError, ValueError) as exc:
        # malformed input is not the same as a bad signature -- surface it
        raise ValueError("malformed signature input") from exc
    return True`,
          cap: "Two failure categories, handled differently, both loud. A verification function should never have a path that quietly yields the permissive answer.",
        },
        {
          t: "box",
          kind: "rule",
          title: "Three questions before catching",
          md: `1. **Which exception** can this block actually raise? Catch that one.
2. **Can I handle it here?** If not, let it propagate — a failure that reaches a top-level handler and returns a 500 is far better than one that is silently absorbed.
3. **Does the caller learn the truth?** Returning the success value after a failure is the defect; returning a failure value or re-raising is the fix.`,
        },
        { t: "h", text: "Exception chaining and what the caller sees" },
        {
          t: "code",
          label: "fixed",
          code: `try:
    row = db.fetch(user_id)
except DatabaseError as exc:
    # keep the real cause for the logs, give the caller nothing useful to an attacker
    log.exception("db fetch failed for user_id=%s", user_id)
    raise LookupError("record unavailable") from exc`,
          cap: "`raise ... from exc` preserves the chain for your traceback while the caller sees a bland message. `from None` suppresses the chain entirely — use it when the original error itself contains sensitive detail.",
        },
        {
          t: "box",
          kind: "pitfall",
          title: "`finally` can silently discard an exception",
          md: `\`\`\`
try:
    verify(token)
finally:
    return True        # <- swallows the exception entirely
\`\`\`

A \`return\`, \`break\` or \`continue\` inside \`finally\` discards any in-flight exception. Keep \`finally\` for cleanup only: closing, releasing, restoring.`,
        },
        {
          t: "box",
          kind: "cve",
          title: "Error handling as the vulnerability",
          md: `CWE-755 ("Improper Handling of Exceptional Conditions") appears in breach write-ups far more often than exotic memory bugs. The recurring shape: certificate validation, signature verification or a permission lookup throws, a broad handler catches it, and the code continues on the success path because nobody wrote the failure path.`,
        },
      ],
      spot: {
        label: "webhook receiver",
        prompt: "Click the line that makes every forged webhook acceptable.",
        lines: [6],
        why:
          "Line 6. Any failure inside `verify_hmac` — including the `InvalidSignature` it raises for a forged request — is caught and ignored, and execution continues to `process(body)` on line 8. The handler must `return` or `raise`, never fall through to the success path.",
        code: `def receive(request):
    body = request.body
    sig = request.headers.get("X-Signature", "")
    try:
        verify_hmac(body, sig, SECRET)
    except Exception:
        pass
    process(body)
    return {"ok": True}`,
      },
      quiz: [
        {
          q: "Why is bare `except:` worse than `except Exception:`?",
          options: [
            "It is slower.",
            "It also catches `KeyboardInterrupt` and `SystemExit`, so the process cannot be stopped cleanly.",
            "They are identical.",
          ],
          answer: 1,
          why:
            "`BaseException` includes the control-flow exceptions. A bare except in a loop makes Ctrl-C and orderly shutdown stop working, which turns a routine restart into a hard kill.",
        },
        {
          q: "`raise ValueError(\"bad input\") from exc` — what does `from exc` do?",
          options: [
            "Re-raises the original exception.",
            "Records the original as `__cause__` so the traceback shows both, while the caller sees your message.",
            "Suppresses the traceback.",
          ],
          answer: 1,
          why:
            "You keep the diagnostic chain internally and control what the caller sees. `from None` is the variant that deliberately drops the chain when the original contains sensitive data.",
        },
        {
          q: "`try: check() finally: return True` — what happens when `check()` raises?",
          options: [
            "The exception propagates after the return.",
            "The `return` discards the exception; the function returns `True`.",
            "SyntaxError.",
          ],
          answer: 1,
          why:
            "A `return` in `finally` swallows in-flight exceptions. This is the same failure as `except: pass`, wearing different syntax.",
        },
      ],
      exercise: {
        title: "A verifier that cannot fail open",
        brief: `Implement \`verify_webhook(body, signature, secret, *, max_body=10_000)\` returning \`(ok, reason)\`.

Use \`hmac\` and \`hashlib\`: the expected signature is \`hmac.new(secret_bytes, body_bytes, hashlib.sha256).hexdigest()\`.

Return values:

| situation | return |
|---|---|
| signature matches | \`(True, "ok")\` |
| signature does not match | \`(False, "bad_signature")\` |
| \`signature\` is not a str, or not 64 lowercase hex characters | \`(False, "malformed_signature")\` |
| \`body\` longer than \`max_body\` bytes | \`(False, "too_large")\` |
| \`body\` is not \`str\`/\`bytes\`, or \`secret\` is empty | raise \`ValueError\` — this is a programming error on your side, not a rejected request |

Requirements: compare with \`hmac.compare_digest\`; no bare \`except:\`; no \`except Exception: pass\`; every path returns a tuple or raises — there must be no way to reach a \`True\` result except a genuine match.`,
        rubric: [
          "A correct signature returns `(True, \"ok\")`",
          "A wrong signature, a tampered body, and a wrong secret all return `(False, \"bad_signature\")`",
          "Malformed signatures are distinguished from wrong ones, and never return True",
          "Oversized bodies are rejected before hashing",
          "Programming errors (bad types, empty secret) raise rather than returning False",
          "`hmac.compare_digest` is used; no broad or swallowed exception handling",
        ],
        starter: `import hashlib
import hmac
import re

HEX64 = re.compile(r"\\A[0-9a-f]{64}\\Z")


def sign(body, secret):
    """Helper: return the hex HMAC-SHA256 of body under secret."""
    body_bytes = body.encode() if isinstance(body, str) else body
    return hmac.new(secret.encode(), body_bytes, hashlib.sha256).hexdigest()


def verify_webhook(body, signature, secret, *, max_body=10_000):
    """Return (ok, reason). Never return True unless the signature genuinely matches."""


SECRET = "s" * 32
payload = '{"event":"push"}'
print(verify_webhook(payload, sign(payload, SECRET), SECRET))
`,
        stdin: [],
        tests: [
          {
            name: "a genuine signature verifies",
            code: `s = "k" * 32
body = '{"event":"push"}'
assert verify_webhook(body, sign(body, s), s) == (True, "ok")`,
          },
          {
            name: "tampering is detected",
            code: `s = "k" * 32
body = '{"amount":10}'
sig = sign(body, s)
assert verify_webhook('{"amount":99}', sig, s) == (False, "bad_signature")
assert verify_webhook(body, sign(body, "other-secret" * 3), s) == (False, "bad_signature")`,
          },
          {
            name: "malformed signatures are their own category",
            code: `s = "k" * 32
body = "x"
for bad in ("", "abc", "Z" * 64, "A" * 64, None, 123, sign(body, s) + "0"):
    ok, reason = verify_webhook(body, bad, s)
    assert ok is False, f"{bad!r} must not verify"
    assert reason == "malformed_signature", f"got {reason!r} for {bad!r}"`,
          },
          {
            name: "bytes bodies work too",
            code: `s = "k" * 32
body = b'{"event":"push"}'
assert verify_webhook(body, sign(body, s), s) == (True, "ok")`,
          },
          {
            name: "oversized bodies are refused",
            code: `s = "k" * 32
big = "x" * 20_000
assert verify_webhook(big, sign(big, s), s) == (False, "too_large")
assert verify_webhook("x" * 50, sign("x" * 50, s), s, max_body=10) == (False, "too_large")`,
          },
          {
            name: "programming errors raise",
            code: `s = "k" * 32
for bad_body in (None, 42, {"a": 1}):
    with raises(ValueError):
        verify_webhook(bad_body, "a" * 64, s)
with raises(ValueError):
    verify_webhook("x", "a" * 64, "")`,
          },
          {
            name: "always a 2-tuple of (bool, str)",
            code: `s = "k" * 32
for body, sig in [("a", sign("a", s)), ("a", "0" * 64), ("a", "nope")]:
    got = verify_webhook(body, sig, s)
    assert isinstance(got, tuple) and len(got) == 2, f"got {got!r}"
    assert isinstance(got[0], bool) and isinstance(got[1], str), f"got {got!r}"`,
          },
        ],
        requirements: [
          { kind: "defines", value: "verify_webhook" },
          { kind: "calls", value: "hmac.compare_digest" },
          { kind: "no_finding", value: "PY-BARE-EXCEPT" },
          { kind: "no_finding", value: "PY-SWALLOWED-ERROR" },
        ],
        hints: [
          "Order the checks by cost: type errors raise, then the size check, then the signature *shape*, and only then the expensive HMAC.",
          "`HEX64.match(signature)` enforces 64 lowercase hex characters. Uppercase must fail — it is a different string, and accepting both doubles the formats you must reason about.",
          "Compute the body's byte length (`len(body.encode())` for str) rather than its character length; a 5 000-character string can be 15 000 bytes.",
          "Finish with `return (hmac.compare_digest(expected, signature), ...)`-style logic, but map it explicitly: `if not hmac.compare_digest(...): return False, \"bad_signature\"` then `return True, \"ok\"`.",
        ],
        solution: `import hashlib
import hmac
import re

HEX64 = re.compile(r"\\A[0-9a-f]{64}\\Z")


def sign(body, secret):
    """Helper: return the hex HMAC-SHA256 of body under secret."""
    body_bytes = body.encode() if isinstance(body, str) else body
    return hmac.new(secret.encode(), body_bytes, hashlib.sha256).hexdigest()


def verify_webhook(body, signature, secret, *, max_body=10_000):
    """Return (ok, reason). Never return True unless the signature genuinely matches."""
    if not isinstance(body, (str, bytes)):
        raise ValueError("body must be str or bytes")
    if not isinstance(secret, str) or not secret:
        raise ValueError("secret must be a non-empty string")

    body_bytes = body.encode() if isinstance(body, str) else body

    if len(body_bytes) > max_body:
        return False, "too_large"

    if not isinstance(signature, str) or not HEX64.match(signature):
        return False, "malformed_signature"

    expected = hmac.new(secret.encode(), body_bytes, hashlib.sha256).hexdigest()

    if not hmac.compare_digest(expected, signature):
        return False, "bad_signature"

    return True, "ok"


SECRET = "s" * 32
payload = '{"event":"push"}'
print(verify_webhook(payload, sign(payload, SECRET), SECRET))`,
        why: `There is exactly one \`return True\`, and the only way to reach it is through \`compare_digest\` returning true. No exception handler exists that could route around it, because the function does not catch anything — every error it can produce is either a deliberate return or a deliberate raise.

That is the structural answer to fail-open verification: rather than wrapping the check in \`try\` and hoping the handler is right, remove the handler and make each failure an explicit branch.

The ordering is also a control:

- **Size before hashing.** Hashing a 2 GB body to then reject it is a free denial of service.
- **Shape before comparison.** A 10-character signature cannot be valid, and rejecting it early keeps \`compare_digest\` working on equal-length inputs, which is what it is designed for.
- **Type errors raise, request errors return.** A caller passing a dict as the body has a bug in *their* code and needs a stack trace; a client sending a bad signature needs a clean rejection. Collapsing those two into \`(False, ...)\` would hide your own bugs behind a plausible-looking rejection.`,
      },
      wrapup: `- Catch the specific exception you can act on; let the rest propagate.
- \`except Exception: pass\` and \`return\` inside \`finally\` both discard failures silently.
- \`raise X from exc\`: rich detail in your logs, a boring message for the caller.
- A verification function should have one \`return True\`, reachable only by genuine success.`,
      refs: [
        { label: "Errors and exceptions", url: "https://docs.python.org/3/tutorial/errors.html" },
        { label: "CWE-755: Improper Handling of Exceptional Conditions", url: "https://cwe.mitre.org/data/definitions/755.html" },
      ],
    },

    /* ----------------------------------------------------------------- 19 */
    {
      id: "m04l04",
      day: 25,
      title: "Error messages that help you and not the attacker",
      minutes: 60,
      secure: "information disclosure in errors",
      cwe: ["CWE-209", "CWE-532"],
      tags: ["exceptions", "custom-errors", "logging", "disclosure", "with"],
      lede:
        "The caller gets a sentence and a correlation id. You get the table name, the file path, the query and the stack. Both of those are the same incident, logged twice, in two different places.",
      blocks: [
        {
          t: "p",
          md: `An error has two audiences with opposite needs. The operator needs everything. The caller needs enough to fix their own request and nothing more. Code that serves one message to both always under-serves the operator or over-serves the attacker.`,
        },
        {
          t: "code",
          label: "vulnerable",
          code: `@app.errorhandler(Exception)
def on_error(exc):
    return {"error": str(exc), "trace": traceback.format_exc()}, 500`,
          cap: "This returns the ORM's SQL, your file paths, library versions, local variable names and sometimes bound parameters — which include credentials.",
        },
        {
          t: "code",
          label: "fixed",
          code: `import logging, secrets

log = logging.getLogger(__name__)

def on_error(exc):
    incident = secrets.token_hex(8)
    log.exception("unhandled error incident=%s", incident)   # full detail, our side
    return {"error": "internal error", "incident": incident}, 500`,
          cap: "One random id ties the user's screenshot to your log line. The user can quote it in a support ticket; it reveals nothing on its own.",
        },
        {
          t: "box",
          kind: "rule",
          title: "Two channels, one event",
          md: `- **Outbound:** a stable, generic message plus a correlation id. No types, no paths, no identifiers from your internals.
- **Inbound:** \`log.exception(...)\` with every piece of context you will want at 3 a.m.

If you find yourself tempted to add detail to the outbound message "so support can debug it", add it to the log and give support access to the log.`,
        },
        { t: "h", text: "Custom exception hierarchies" },
        {
          t: "code",
          label: "example",
          code: `class AppError(Exception):
    """Base for everything this application raises deliberately."""
    public_message = "request failed"

    def __init__(self, detail="", *, incident=None):
        super().__init__(detail or self.public_message)
        self.detail = detail                 # internal
        self.incident = incident

class ValidationFailed(AppError):
    public_message = "invalid request"

class NotAuthorised(AppError):
    public_message = "not permitted"

class UpstreamUnavailable(AppError):
    public_message = "service temporarily unavailable"`,
          cap: "`public_message` is the contract with the outside world; `detail` is for the log. One base class lets a handler catch `AppError` and treat anything else as a genuine 500.",
        },
        {
          t: "box",
          kind: "good",
          title: "Catch your own errors, not everything",
          md: `\`\`\`
try:
    result = handler(request)
except AppError as exc:
    log.warning("handled: %s", exc.detail)
    return {"error": exc.public_message}, exc.status
except Exception:
    incident = secrets.token_hex(8)
    log.exception("unexpected incident=%s", incident)
    return {"error": "internal error", "incident": incident}, 500
\`\`\`

Two handlers, two meanings: *the request was wrong* versus *we were wrong*. Only the second is an alert worth waking someone for.`,
        },
        { t: "h", text: "`with`: cleanup that happens on every path" },
        {
          t: "code",
          label: "example",
          code: `with open("report.csv", encoding="utf-8") as fh:
    process(fh)           # fh.close() runs even if process() raises

import threading
lock = threading.Lock()
with lock:
    update_shared_state()  # released even on exception`,
        },
        {
          t: "code",
          label: "example",
          code: `from contextlib import contextmanager

@contextmanager
def audited(action, actor):
    log.info("start action=%s actor=%s", action, actor)
    try:
        yield
    except Exception:
        log.warning("failed action=%s actor=%s", action, actor)
        raise                     # re-raise: the context manager observes, it does not swallow
    else:
        log.info("ok action=%s actor=%s", action, actor)`,
          cap: "A context manager that returns a truthy value from `__exit__` *suppresses* the exception. `@contextmanager` with a bare `raise` keeps the failure visible — which is what an audit trail requires.",
        },
        {
          t: "box",
          kind: "cve",
          title: "Debug pages are remote shells",
          md: `Flask and Django debug pages render an interactive console or a full local-variable dump on any traceback. Reachable from a network, the Werkzeug debugger is unauthenticated remote code execution — the auditor rates \`debug=True\` as **critical** for that reason.

Shodan consistently finds thousands of internet-exposed Python debug pages. The usual cause is an environment variable that defaulted to on.`,
        },
      ],
      quiz: [
        {
          q: "An API returns `\"duplicate key value violates unique constraint users_email_key\"`. What has leaked?",
          options: [
            "Nothing useful.",
            "The database engine, a table name, an index name, and confirmation that the address is registered.",
            "Only the table name.",
          ],
          answer: 1,
          why:
            "It is both a technology fingerprint and an account-existence oracle. The correct outbound message is a generic 409; the constraint name belongs in your log.",
        },
        {
          q: "What does returning `True` from a context manager's `__exit__` do?",
          options: [
            "Nothing special.",
            "Suppresses the exception that was propagating.",
            "Re-raises it.",
          ],
          answer: 1,
          why:
            "It is `except: pass` in another costume. A context manager that silently suppresses is a serious hazard in audit, transaction and locking code.",
        },
        {
          q: "Why attach a random incident id to a 500 response?",
          options: [
            "To rate-limit the client.",
            "It correlates the user's report with the full server-side log entry without disclosing anything.",
            "It is required by HTTP.",
          ],
          answer: 1,
          why:
            "The id is meaningless to an attacker and invaluable to support. Use `secrets.token_hex` rather than a counter, which would leak your traffic volume.",
        },
      ],
      exercise: {
        title: "A two-channel error boundary",
        brief: `Build the error-handling boundary for a service.

Define:

1. \`AppError(Exception)\` with class attributes \`public_message = "request failed"\` and \`status = 400\`, and \`__init__(self, detail="")\` storing \`self.detail\`.
2. \`ValidationFailed(AppError)\` — \`public_message = "invalid request"\`, \`status = 400\`.
3. \`NotAuthorised(AppError)\` — \`public_message = "not permitted"\`, \`status = 403\`.
4. \`UpstreamUnavailable(AppError)\` — \`public_message = "service temporarily unavailable"\`, \`status = 503\`.

Then write \`handle(fn, audit_log, make_id=...)\`:

- Calls \`fn()\` and returns \`{"ok": True, "data": <result>}, 200\` on success.
- On \`AppError\`: returns \`{"ok": False, "error": <public_message>}, <status>\`. Appends \`f"handled {type(exc).__name__}: {exc.detail}"\` to \`audit_log\`.
- On any **other** exception: generates an id via \`make_id()\` (default: \`secrets.token_hex(8)\`), returns \`{"ok": False, "error": "internal error", "incident": <id>}, 500\`, and appends \`f"unhandled {type(exc).__name__} incident={id}: {exc}"\` to \`audit_log\`.
- The outbound dict must **never** contain the detail, the exception type name, or the original message.
- \`KeyboardInterrupt\` and \`SystemExit\` must propagate — they are not request failures.`,
        rubric: [
          "Success, AppError and unexpected-exception paths return the documented shapes and statuses",
          "No internal detail reaches the outbound dict in any case",
          "The audit log receives the detail for handled errors and the type+incident for unhandled ones",
          "The incident id in the response matches the one in the log",
          "`KeyboardInterrupt`/`SystemExit` propagate rather than becoming a 500",
        ],
        starter: `import secrets


class AppError(Exception):
    public_message = "request failed"
    status = 400

    def __init__(self, detail=""):
        super().__init__(detail or self.public_message)
        self.detail = detail


# ValidationFailed, NotAuthorised, UpstreamUnavailable go here


def handle(fn, audit_log, make_id=None):
    """Run fn() and translate any failure into a safe (body, status) pair."""


log = []
print(handle(lambda: {"value": 42}, log))
`,
        stdin: [],
        tests: [
          {
            name: "success is wrapped",
            code: `log = []
body, status = handle(lambda: {"value": 42}, log)
assert (body, status) == ({"ok": True, "data": {"value": 42}}, 200), f"got {body!r} {status!r}"
assert log == [], f"success should not log an error: {log!r}"`,
          },
          {
            name: "the hierarchy carries public messages and statuses",
            code: `assert issubclass(ValidationFailed, AppError)
assert issubclass(NotAuthorised, AppError)
assert issubclass(UpstreamUnavailable, AppError)
assert (ValidationFailed.public_message, ValidationFailed.status) == ("invalid request", 400)
assert (NotAuthorised.public_message, NotAuthorised.status) == ("not permitted", 403)
assert (UpstreamUnavailable.public_message, UpstreamUnavailable.status) == ("service temporarily unavailable", 503)`,
          },
          {
            name: "AppErrors become their public message",
            code: `log = []
def boom():
    raise NotAuthorised("user 7 lacks role admin on doc 99")
body, status = handle(boom, log)
assert body == {"ok": False, "error": "not permitted"}, f"got {body!r}"
assert status == 403
assert "user 7 lacks role admin" in log[0], f"detail missing from the log: {log!r}"`,
          },
          {
            name: "no internal detail escapes",
            code: `log = []
def boom():
    raise ValidationFailed("field 'ssn' failed regex ^\\\\d{3}-\\\\d{2}-\\\\d{4}$ in users_v3")
body, _ = handle(boom, log)
blob = str(body)
for leak in ("ssn", "users_v3", "regex", "ValidationFailed"):
    assert leak not in blob, f"{leak!r} leaked into the response {body!r}"`,
          },
          {
            name: "unexpected exceptions become an incident",
            code: `log = []
def boom():
    raise KeyError("users_v3.password_hash")
body, status = handle(boom, log, make_id=lambda: "deadbeef")
assert status == 500
assert body == {"ok": False, "error": "internal error", "incident": "deadbeef"}, f"got {body!r}"
assert "KeyError" in log[0] and "deadbeef" in log[0], f"got {log!r}"
assert "password_hash" in log[0], "the real cause must reach the log"
assert "password_hash" not in str(body), "the real cause must not reach the caller"`,
          },
          {
            name: "ids are generated when not supplied",
            code: `log = []
def boom():
    raise RuntimeError("x")
body, _ = handle(boom, log)
assert "incident" in body and len(body["incident"]) >= 8, f"got {body!r}"
assert body["incident"] in log[0], "the response id must match the logged id"`,
          },
          {
            name: "control-flow exceptions are not swallowed",
            code: `log = []
def stop():
    raise KeyboardInterrupt()
try:
    handle(stop, log)
    raise AssertionError("KeyboardInterrupt should propagate")
except KeyboardInterrupt:
    pass
def leave():
    raise SystemExit(1)
try:
    handle(leave, log)
    raise AssertionError("SystemExit should propagate")
except SystemExit:
    pass`,
          },
        ],
        requirements: [
          { kind: "defines", value: "handle" },
          { kind: "defines", value: "AppError" },
          { kind: "no_finding", value: "PY-BARE-EXCEPT" },
        ],
        hints: [
          "Order the handlers from specific to general: `except AppError as exc:` first, then `except Exception as exc:`. Python takes the first matching clause.",
          "`except Exception` does **not** catch `KeyboardInterrupt` or `SystemExit` — they derive from `BaseException` directly. So the propagation requirement is satisfied for free, as long as you never write a bare `except:`.",
          "Subclasses only need two class attributes: `public_message` and `status`. They inherit `__init__`.",
          "Generate the id once and use the same value in both the log line and the response — that is the entire point of a correlation id.",
        ],
        solution: `import secrets


class AppError(Exception):
    public_message = "request failed"
    status = 400

    def __init__(self, detail=""):
        super().__init__(detail or self.public_message)
        self.detail = detail


class ValidationFailed(AppError):
    public_message = "invalid request"
    status = 400


class NotAuthorised(AppError):
    public_message = "not permitted"
    status = 403


class UpstreamUnavailable(AppError):
    public_message = "service temporarily unavailable"
    status = 503


def handle(fn, audit_log, make_id=None):
    """Run fn() and translate any failure into a safe (body, status) pair."""
    make_id = make_id or (lambda: secrets.token_hex(8))

    try:
        data = fn()
    except AppError as exc:
        audit_log.append(f"handled {type(exc).__name__}: {exc.detail}")
        return {"ok": False, "error": exc.public_message}, exc.status
    except Exception as exc:
        incident = make_id()
        audit_log.append(f"unhandled {type(exc).__name__} incident={incident}: {exc}")
        return {"ok": False, "error": "internal error", "incident": incident}, 500

    return {"ok": True, "data": data}, 200


log = []
print(handle(lambda: {"value": 42}, log))`,
        why: `Every piece of information splits cleanly: \`exc.detail\` goes left into the log, \`exc.public_message\` goes right to the caller. The outbound dict is assembled from class attributes that a reviewer can read in one screen — there is no path by which an exception's own text reaches the response, because the response is never built *from* the exception.

Three structural points:

- **Two handlers, two meanings.** An \`AppError\` is a request that was wrong and is not worth an alert; anything else is a bug in this service and gets an incident id. Collapsing them into one handler loses that distinction permanently.
- **\`except Exception\`, not \`except BaseException\`.** \`KeyboardInterrupt\` and \`SystemExit\` derive from \`BaseException\`, so they pass straight through and shutdown keeps working. The tests verify this because it is the difference between a service you can deploy and one you have to \`kill -9\`.
- **The success path is outside the \`try\`'s exception clauses by construction** — \`data = fn()\` is the only statement that can fail, and the \`return\` after the block runs only when nothing was raised. Putting the \`return\` inside the \`try\` would let an error during response construction be caught by the handler below it and reported as the caller's fault.`,
      },
      wrapup: `- Two channels: generic message plus incident id outward, full detail inward.
- Give exceptions a \`public_message\`; never build a response from \`str(exc)\`.
- \`except Exception\` leaves \`KeyboardInterrupt\`/\`SystemExit\` alone — bare \`except:\` does not.
- \`with\` guarantees cleanup; a context manager that returns truthy from \`__exit__\` silently swallows errors.`,
      refs: [
        { label: "CWE-209: Generation of Error Message Containing Sensitive Information", url: "https://cwe.mitre.org/data/definitions/209.html" },
        { label: "contextlib", url: "https://docs.python.org/3/library/contextlib.html" },
      ],
    },

    /* ----------------------------------------------------------------- 20 */
    {
      id: "m04l05",
      day: 26,
      title: "Capstone: a conversion library nobody can misuse",
      minutes: 60,
      secure: "defensive API design",
      cwe: ["CWE-754", "CWE-20"],
      tags: ["capstone", "api-design", "parsing", "errors", "library"],
      lede:
        "Everything from this module, applied to the kind of module every codebase grows: the one with `to_int`, `to_bool` and `to_date` in it. Libraries are where a weak contract gets copied into fifty call sites.",
      blocks: [
        {
          t: "p",
          md: `A utility module is leverage in both directions. Get the contract right and every caller inherits the safety; get it wrong and you have distributed the same defect across the codebase, where it will be found one call site at a time.`,
        },
        {
          t: "table",
          head: ["Design choice", "Weak version", "Strong version"],
          rows: [
            ["Failure signalling", "return `None`", "raise a specific exception"],
            ["Defaults", "`to_int(x, default=0)` always", "default only when explicitly passed"],
            ["Silent coercion", "`to_int(\"3.9\")` → 3", "`ValueError` — the caller must say what they meant"],
            ["Bounds", "caller's problem", "`minimum`/`maximum` parameters, checked here"],
            ["Error text", "`str(exc)` from the internals", "a message naming the *field*, never the value's contents"],
            ["Booleans", "`bool(\"false\")` → True", "explicit spelling allowlist"],
          ],
        },
        {
          t: "box",
          kind: "rule",
          title: "A default is a decision, not a convenience",
          md: `\`to_int(raw, default=0)\` as a *signature default* means every careless call site silently turns bad input into zero. Make the default **sentinel-based**, so "no default supplied" is distinguishable from "the default is None":

\`\`\`
_MISSING = object()

def to_int(raw, *, default=_MISSING):
    try:
        return _parse(raw)
    except ValueError:
        if default is _MISSING:
            raise
        return default
\`\`\`

Now \`to_int(x)\` raises, \`to_int(x, default=None)\` yields \`None\`, and the difference is visible at the call site.`,
        },
        {
          t: "box",
          kind: "pitfall",
          title: "The sentinel must not be `None`",
          md: `Using \`default=None\` as the "no default" marker makes it impossible for a caller to legitimately default to \`None\`. A module-level \`_MISSING = object()\` is unique, falsy-free, and unambiguous. The standard library uses this pattern throughout (\`dict.pop\`, \`getattr\`, \`inspect.Parameter.empty\`).`,
        },
        {
          t: "box",
          kind: "good",
          title: "Name the field, not the value",
          md: `\`ValueError("invalid value: 4111111111111111")\` puts a card number into every log that catches it.

\`ValueError("field 'card_number' is not a valid integer")\` is just as actionable and carries nothing. Accept a \`field\` parameter in your parsers and use it in the message.`,
        },
      ],
      quiz: [
        {
          q: "Why is `def to_int(raw, default=0)` a poor signature?",
          options: [
            "Defaults are slow.",
            "Every call site silently converts invalid input to 0, including the ones that should have failed.",
            "`0` cannot be a default.",
          ],
          answer: 1,
          why:
            "The dangerous behaviour becomes the easy one. With a sentinel, falling back is something a caller must ask for in writing.",
        },
        {
          q: "Why use `_MISSING = object()` instead of `None` as the no-default marker?",
          options: [
            "It is faster.",
            "So a caller can legitimately pass `default=None` and have it mean something.",
            "`None` cannot be compared with `is`.",
          ],
          answer: 1,
          why: "With `None` as the marker, 'fall back to None' is unexpressible. A unique sentinel separates 'not supplied' from 'supplied as None'.",
        },
        {
          q: "Your parser's error message should contain:",
          options: [
            "The offending value, for debugging.",
            "The field name and the expected format.",
            "The full traceback.",
          ],
          answer: 1,
          why:
            "The caller already knows what they sent. Everyone reading your logs afterwards does not need it — and the value is exactly the thing that might be a password, a card number or a token.",
        },
      ],
      exercise: {
        title: "convert.py — the module every codebase needs",
        brief: `Build a small conversion library with a consistent, misuse-resistant contract.

\`\`\`
class ConversionError(ValueError): ...
_MISSING = object()
\`\`\`

Write four functions. Each takes \`raw\`, a keyword-only \`field="value"\` used in error messages, and a keyword-only \`default=_MISSING\`.

| function | accepts | rejects |
|---|---|---|
| \`to_int(raw, *, field, default, minimum=None, maximum=None)\` | ASCII-digit strings (optionally a leading \`-\`) and real \`int\`s | \`bool\`, floats, \`"3.9"\`, \`"1_0"\`, non-ASCII digits, whitespace padding, out-of-range |
| \`to_bool(raw, *, field, default)\` | real \`bool\`s; the strings \`1/true/yes/on\` and \`0/false/no/off\` (case-insensitive, surrounding whitespace allowed) | every other string, every number, \`None\` |
| \`to_str(raw, *, field, default, max_length=200, allow_empty=False)\` | \`str\` | non-str, longer than \`max_length\`, and empty/whitespace-only when \`allow_empty\` is False |
| \`to_choice(raw, choices, *, field, default)\` | a value that is \`in choices\`, compared **exactly** | everything else |

Rules:

- On rejection: if \`default\` was supplied, return it; otherwise raise \`ConversionError\`.
- The error message must contain the \`field\` name and must **not** contain the offending value.
- \`to_str\` returns the string unchanged except for \`strip()\`ping — do not truncate, reject instead.
- Out-of-range in \`to_int\` is a rejection like any other (so \`default\` applies).`,
        rubric: [
          "Every function raises `ConversionError` when no default is supplied and returns the default when one is",
          "`default=None` is distinguishable from no default",
          "Error messages name the field and never echo the value",
          "`bool` is rejected by `to_int`; `\"3.9\"` and `\"١٢\"` are rejected",
          "`to_bool` parses spellings rather than testing truthiness",
          "`to_choice` compares exactly — no case folding",
        ],
        starter: `class ConversionError(ValueError):
    pass


_MISSING = object()

TRUE_WORDS = {"1", "true", "yes", "on"}
FALSE_WORDS = {"0", "false", "no", "off"}


def to_int(raw, *, field="value", default=_MISSING, minimum=None, maximum=None):
    """Return an int, the default, or raise ConversionError."""


def to_bool(raw, *, field="value", default=_MISSING):
    """Return a bool, the default, or raise ConversionError."""


def to_str(raw, *, field="value", default=_MISSING, max_length=200, allow_empty=False):
    """Return a stripped string, the default, or raise ConversionError."""


def to_choice(raw, choices, *, field="value", default=_MISSING):
    """Return raw when it is in choices, the default, or raise ConversionError."""


print(to_int("42", field="port"), to_bool("off", field="debug"))
`,
        stdin: [],
        tests: [
          {
            name: "to_int accepts the right things",
            code: `assert to_int("42") == 42
assert to_int(42) == 42
assert to_int("-7") == -7
assert to_int("0") == 0
assert type(to_int("42")) is int`,
          },
          {
            name: "to_int rejects the wrong things",
            code: `for bad in ("3.9", "1_0", " 42", "42 ", "", "0x2a", "١٢", None, 4.0, True, False, [4]):
    try:
        to_int(bad)
        raise AssertionError(f"{bad!r} should have been rejected")
    except ConversionError:
        pass`,
          },
          {
            name: "to_int honours bounds as rejections",
            code: `assert to_int("5", minimum=1, maximum=10) == 5
assert to_int("5", minimum=5, maximum=5) == 5
with raises(ConversionError):
    to_int("0", minimum=1)
with raises(ConversionError):
    to_int("11", maximum=10)
assert to_int("11", maximum=10, default=-1) == -1`,
          },
          {
            name: "defaults are opt-in and None is a real default",
            code: `with raises(ConversionError):
    to_int("nope")
assert to_int("nope", default=0) == 0
assert to_int("nope", default=None) is None
assert to_bool("nope", default=None) is None
assert to_str("", default=None) is None
assert to_choice("x", ("a", "b"), default=None) is None`,
          },
          {
            name: "messages name the field and hide the value",
            code: `try:
    to_int("4111111111111111x", field="card_number")
    raise AssertionError("expected ConversionError")
except ConversionError as e:
    msg = str(e)
    assert "card_number" in msg, f"message should name the field: {msg!r}"
    assert "4111111111111111" not in msg, f"message leaked the value: {msg!r}"`,
          },
          {
            name: "to_bool parses spellings",
            code: `for yes in (True, "1", "true", "TRUE", " yes ", "on"):
    assert to_bool(yes) is True, f"{yes!r} should be True"
for no in (False, "0", "false", "FALSE", " no ", "off"):
    assert to_bool(no) is False, f"{no!r} should be False"
for bad in ("maybe", "", "2", None, 1, 0, "trueish"):
    with raises(ConversionError):
        to_bool(bad)`,
          },
          {
            name: "to_str strips, bounds and refuses empties",
            code: `assert to_str("  hello  ") == "hello"
assert to_str("", allow_empty=True) == ""
assert to_str("   ", allow_empty=True) == ""
for bad in ("", "   ", None, 5, True):
    with raises(ConversionError):
        to_str(bad)
with raises(ConversionError):
    to_str("x" * 201)
assert to_str("x" * 201, max_length=500) == "x" * 201`,
          },
          {
            name: "to_choice is exact",
            code: `assert to_choice("member", ("member", "admin")) == "member"
for bad in ("Member", "MEMBER", " member", "owner", "", None):
    with raises(ConversionError):
        to_choice(bad, ("member", "admin"))
assert to_choice(3, (1, 2, 3)) == 3`,
          },
          {
            name: "keyword-only discipline",
            code: `with raises(TypeError):
    to_int("1", "field")
with raises(TypeError):
    to_bool("1", "field")`,
          },
        ],
        requirements: [
          { kind: "defines", value: "to_int" },
          { kind: "defines", value: "to_bool" },
          { kind: "defines", value: "to_str" },
          { kind: "defines", value: "to_choice" },
          { kind: "no_finding", value: "PY-BARE-EXCEPT" },
        ],
        hints: [
          "Write one private helper, `_fail(field, expected, default)`, that either returns the default or raises `ConversionError(f\"{field} must be {expected}\")`. Every rejection becomes a single `return _fail(...)` line.",
          "`to_int`: accept a real `int` early (rejecting `bool` first), then for strings check `raw.isascii()` and that `raw.lstrip(\"-\").isdigit()` — and that there is at most one leading `-`.",
          "Bounds come after parsing and are a rejection, so route them through the same `_fail` helper and the default applies to them too.",
          "`to_bool` must check `isinstance(raw, bool)` before anything else, because `True` is also an `int` and `str(True)` is `\"True\"` which your word sets would otherwise have to know about.",
          "Remember that `0` and `1` as *integers* are rejected by `to_bool` — only real booleans and the listed spellings are accepted.",
        ],
        solution: `class ConversionError(ValueError):
    pass


_MISSING = object()

TRUE_WORDS = {"1", "true", "yes", "on"}
FALSE_WORDS = {"0", "false", "no", "off"}


def _fail(field, expected, default):
    """Either produce the caller's default, or refuse with a value-free message."""
    if default is not _MISSING:
        return default
    raise ConversionError(f"{field} must be {expected}")


def to_int(raw, *, field="value", default=_MISSING, minimum=None, maximum=None):
    """Return an int, the default, or raise ConversionError."""
    if isinstance(raw, bool):
        return _fail(field, "a whole number, not a boolean", default)

    if isinstance(raw, int):
        value = raw
    elif isinstance(raw, str):
        body = raw[1:] if raw.startswith("-") else raw
        if not (raw.isascii() and body.isdigit()):
            return _fail(field, "a whole number in digits", default)
        value = int(raw)
    else:
        return _fail(field, "a whole number in digits", default)

    if minimum is not None and value < minimum:
        return _fail(field, f"at least {minimum}", default)
    if maximum is not None and value > maximum:
        return _fail(field, f"at most {maximum}", default)
    return value


def to_bool(raw, *, field="value", default=_MISSING):
    """Return a bool, the default, or raise ConversionError."""
    if isinstance(raw, bool):
        return raw
    if isinstance(raw, str):
        text = raw.strip().lower()
        if text in TRUE_WORDS:
            return True
        if text in FALSE_WORDS:
            return False
    return _fail(field, "one of: " + ", ".join(sorted(TRUE_WORDS | FALSE_WORDS)), default)


def to_str(raw, *, field="value", default=_MISSING, max_length=200, allow_empty=False):
    """Return a stripped string, the default, or raise ConversionError."""
    if not isinstance(raw, str) or isinstance(raw, bool):
        return _fail(field, "text", default)
    if len(raw) > max_length:
        return _fail(field, f"at most {max_length} characters", default)
    value = raw.strip()
    if not value and not allow_empty:
        return _fail(field, "non-empty text", default)
    return value


def to_choice(raw, choices, *, field="value", default=_MISSING):
    """Return raw when it is in choices, the default, or raise ConversionError."""
    if raw in choices:
        return raw
    return _fail(field, "one of: " + ", ".join(str(c) for c in choices), default)


print(to_int("42", field="port"), to_bool("off", field="debug"))`,
        why: `Every rejection in this module goes through \`_fail\`, which is the only place that decides between "return the default" and "raise". That means the default semantics cannot drift between functions, and adding a fifth converter cannot accidentally get them wrong.

The contract is uniform and strict in the directions that matter:

- **Failure is the default behaviour.** \`to_int(raw)\` raises; silence has to be requested in writing with \`default=\`. The careless call site is the safe one.
- **\`_MISSING\` is a unique object**, so \`default=None\` is a legitimate instruction rather than an accident. This is why \`to_int(x, default=None) is None\` is in the tests.
- **Messages state the expectation, never the input.** \`"card_number must be a whole number in digits"\` is actionable for the caller and inert in a log. Echoing the value would put card numbers, tokens and passwords into every handler that catches a \`ConversionError\`.
- **\`bool\` is rejected everywhere it would be ambiguous.** \`to_int(True)\` returning 1 is how a JSON body of \`{"quantity": true}\` becomes an order for one unit, and \`to_bool(1)\` accepting an integer would quietly re-admit truthiness testing through the back door.
- **Bounds are rejections, not a separate error class**, so a caller who supplied a default gets it for an out-of-range value too — one rule, no special cases.`,
      },
      wrapup: `- A library's contract is copied to every call site; make the easy path the strict one.
- Use a unique \`_MISSING\` sentinel so "no default" and "default is None" stay distinct.
- Centralise rejection in one helper so semantics cannot drift between functions.
- Error messages name the field and the expectation — never the value.`,
      refs: [
        { label: "CWE-754: Improper Check for Unusual or Exceptional Conditions", url: "https://cwe.mitre.org/data/definitions/754.html" },
        { label: "Python glossary — sentinel patterns in the stdlib", url: "https://docs.python.org/3/library/inspect.html#inspect.Parameter.empty" },
      ],
    },
  ],
};
