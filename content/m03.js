export default {
  id: "m03",
  number: 3,
  title: "Data structures and data you do not own",
  focus: "lookup tables",
  subtitle:
    "Lists, dicts, sets and comprehensions — plus the two structural habits that remove whole vulnerability classes: dispatch tables instead of dynamic attribute access, and streaming instead of loading.",
  objectives: [
    "Choose list, tuple, dict or set by what the data *is*, not by habit.",
    "Replace `getattr`/`eval` dispatch with an explicit mapping of permitted operations.",
    "Use sets for O(1) allowlist membership and explain why `in` on a list is a DoS at scale.",
    "Write comprehensions and generators, and know when a generator is the security control.",
    "Build a redaction pipeline that minimises data by construction rather than by review.",
  ],
  rules: [
    { id: "PY-EVAL", what: "dispatch through a dict, never through eval or getattr" },
    { id: "PY-SECRET-IN-LOG", what: "drop sensitive fields before they reach output" },
    { id: "PY-MUTABLE-DEFAULT", what: "shared mutable state leaks between calls" },
  ],
  capstone:
    "Day 21 builds an event-redaction pipeline: an allowlist of fields, deep redaction of nested structures, and a generator that never holds the whole dataset in memory.",

  lessons: [
    /* ----------------------------------------------------------------- 11 */
    {
      id: "m03l01",
      day: 17,
      title: "Lists, tuples, slicing, and bounded reads",
      minutes: 60,
      secure: "bounded collections",
      cwe: ["CWE-400", "CWE-1284"],
      tags: ["list", "tuple", "slice", "index", "bounds"],
      lede:
        "A list is a mutable sequence; a tuple is an immutable one. The immutability is not a style preference — it is how you stop a caller from editing your allowlist.",
      blocks: [
        {
          t: "code",
          label: "example",
          code: `hosts = ["a.example", "b.example", "c.example"]

hosts[0]            # 'a.example'   -- first
hosts[-1]           # 'c.example'   -- last
hosts[0:2]          # ['a.example', 'b.example']   -- slice, end excluded
hosts[:2]           # same
hosts[::2]          # every second item
len(hosts)          # 3

hosts.append("d.example")
hosts.extend(["e.example"])
hosts.insert(0, "z.example")
hosts.remove("z.example")      # by value; ValueError if absent
last = hosts.pop()             # by index, default -1`,
        },
        {
          t: "box",
          kind: "note",
          title: "Indexing raises; slicing does not",
          md: `\`items[10]\` on a 3-element list raises \`IndexError\`. \`items[0:10]\` returns the 3 items it has, silently.

That asymmetry is useful: slicing is the natural way to *bound* a read. \`body[:MAX_LEN]\` never raises, never allocates more than you asked for, and needs no length check first.`,
        },
        { t: "h", text: "Tuples: the immutable allowlist" },
        {
          t: "code",
          label: "vulnerable",
          code: `ALLOWED_ROLES = ["member", "editor", "admin"]

def handle(request):
    roles = ALLOWED_ROLES          # same list object, not a copy
    roles.append(request["role"])  # caller just extended the global allowlist
    ...`,
          cap: "A module-level list is a shared, mutable global. Any code that gets a reference can permanently change it for the whole process.",
        },
        {
          t: "code",
          label: "fixed",
          code: `ALLOWED_ROLES = ("member", "editor", "admin")   # tuple: no append, no remove

def handle(request):
    if request["role"] not in ALLOWED_ROLES:
        raise PermissionError("unknown role")`,
          cap: "A tuple cannot be mutated. Constants that govern security decisions should be tuples, frozensets, or `types.MappingProxyType`.",
        },
        {
          t: "table",
          head: ["Need", "Use", "Why"],
          rows: [
            ["An ordered, growing collection", "`list`", "Cheap append, mutable."],
            ["A fixed record or constant set", "`tuple`", "Immutable, hashable, usable as a dict key."],
            ["Fast membership testing", "`set` / `frozenset`", "O(1) instead of O(n)."],
            ["Key → value lookup", "`dict`", "O(1), and the basis of dispatch tables."],
            ["A queue with cheap pops from the front", "`collections.deque`", "`list.pop(0)` is O(n)."],
          ],
        },
        { t: "h", text: "Bounding untrusted input with slices" },
        {
          t: "code",
          label: "fixed",
          code: `MAX_TAGS = 20
MAX_TAG_LEN = 32

def clean_tags(raw_tags):
    """raw_tags is whatever the client sent. Return at most MAX_TAGS short strings."""
    if not isinstance(raw_tags, list):
        raise ValueError("tags must be a list")
    return [str(tag)[:MAX_TAG_LEN] for tag in raw_tags[:MAX_TAGS]]`,
          cap: "Two slices: one bounds the count, one bounds each element. A client sending 10 million tags of 1 MB each gets 20 tags of 32 characters.",
        },
        {
          t: "box",
          kind: "pitfall",
          title: "`list * n` and shared references",
          md: `\`\`\`
grid = [[0] * 3] * 3      # three references to ONE row
grid[0][0] = 9
# [[9, 0, 0], [9, 0, 0], [9, 0, 0]]
\`\`\`

The outer multiplication copies the *reference*, not the row. Build nested structures with a comprehension: \`[[0] * 3 for _ in range(3)]\`.

The same aliasing bug appears when you hand a caller your internal list: \`return self._items\` lets them mutate your object's state. Return \`list(self._items)\` or \`tuple(self._items)\`.`,
        },
        {
          t: "repl",
          lines: [
            ">>> a = [1, 2, 3]",
            ">>> b = a            # same object",
            ">>> c = a[:]         # shallow copy",
            ">>> b.append(4); a",
            "[1, 2, 3, 4]",
            ">>> c",
            "[1, 2, 3]",
            ">>> a is b, a is c",
            "(True, False)",
          ],
        },
      ],
      quiz: [
        {
          q: "Why declare `ALLOWED_EXTENSIONS` as a tuple rather than a list?",
          options: [
            "Tuples are faster to iterate.",
            "A tuple cannot be mutated, so no code path can extend your allowlist at runtime.",
            "Lists cannot contain strings.",
          ],
          answer: 1,
          why:
            "Immutability is the point. A security constant that any function can `append` to is not a constant. (Tuples are also marginally faster, but that is not the reason.)",
        },
        {
          q: "`body[:1000]` when `body` has 10 characters returns…",
          options: ["An `IndexError`", "The 10 characters", "`None`"],
          answer: 1,
          why: "Slicing clamps to what exists. That is exactly why it is the right tool for bounding an untrusted read — no length check needed first.",
        },
        {
          q: "`rows = [[0] * 3] * 3; rows[0][0] = 9`. What is `rows[1][0]`?",
          options: ["`0`", "`9`", "`None`"],
          answer: 1,
          why: "`9`. The outer `* 3` duplicated one reference three times, so all three 'rows' are the same list. Use a comprehension to build independent rows.",
        },
      ],
      exercise: {
        title: "Bounding a client-supplied payload",
        brief: `A client posts a JSON body that has already been parsed into Python objects. Write \`clean_payload(data)\` that returns a bounded, safe version — or raises \`ValueError\`.

\`data\` must be a dict. Produce a new dict with exactly these keys:

| key | rule |
|---|---|
| \`title\` | \`data["title"]\` must be a string; truncate to 80 characters; after stripping, it must not be empty |
| \`tags\` | \`data.get("tags", [])\` must be a list; keep at most 10 entries; each entry converted with \`str()\` and truncated to 24 characters; drop entries that are empty after stripping; de-duplicate while **preserving order** |
| \`page\` | \`data.get("page", 1)\` must be an \`int\` (reject \`bool\`); clamp into 1–500 rather than raising |

Anything else in \`data\` is dropped. Raise \`ValueError\` when \`data\` is not a dict, \`title\` is missing/not a string/empty, \`tags\` is not a list, or \`page\` is not an int.`,
        rubric: [
          "Returns only the three keys, regardless of extra input keys",
          "`title` is truncated to 80 characters; whitespace-only titles raise",
          "`tags` capped at 10, each capped at 24 characters, blanks dropped, order-preserving de-duplication",
          "`page` is clamped (not rejected) into 1–500",
          "`bool` is rejected as a page number",
          "A 100 000-element tag list is handled without building a 100 000-element result",
        ],
        starter: `MAX_TITLE = 80
MAX_TAGS = 10
MAX_TAG_LEN = 24
PAGE_RANGE = (1, 500)


def clean_payload(data):
    """Return a bounded {title, tags, page} dict, or raise ValueError."""


print(clean_payload({"title": "Q4 report", "tags": ["emea", "emea", "", "apac"], "page": 900, "junk": "x"}))
`,
        stdin: [],
        tests: [
          {
            name: "keeps only the three known keys",
            code: `got = clean_payload({"title": "t", "tags": [], "page": 1, "evil": "drop me", "admin": True})
assert set(got) == {"title", "tags", "page"}, f"got keys {sorted(got)}"`,
          },
          {
            name: "title is bounded and must be non-empty",
            code: `assert clean_payload({"title": "a" * 200})["title"] == "a" * 80
for bad in ({}, {"title": ""}, {"title": "   "}, {"title": 42}, {"title": None}):
    with raises(ValueError):
        clean_payload(bad)`,
          },
          {
            name: "tags are capped, truncated, cleaned and de-duplicated in order",
            code: `got = clean_payload({"title": "t", "tags": ["b", "a", "b", "  ", "c" * 50]})
assert got["tags"] == ["b", "a", "c" * 24], f"got {got['tags']!r}"
many = clean_payload({"title": "t", "tags": [f"tag{i}" for i in range(100)]})
assert len(many["tags"]) == 10, f"expected 10 tags, got {len(many['tags'])}"`,
          },
          {
            name: "an enormous tag list is bounded before work is done",
            code: `huge = {"title": "t", "tags": ["x" * 500] * 100_000}
got = clean_payload(huge)
assert got["tags"] == ["x" * 24], f"got {got['tags']!r}"`,
          },
          {
            name: "tags must be a list",
            code: `for bad in ("abc", {"a": 1}, 7):
    with raises(ValueError):
        clean_payload({"title": "t", "tags": bad})`,
          },
          {
            name: "page is clamped, not rejected",
            code: `assert clean_payload({"title": "t", "page": 900})["page"] == 500
assert clean_payload({"title": "t", "page": -4})["page"] == 1
assert clean_payload({"title": "t", "page": 7})["page"] == 7
assert clean_payload({"title": "t"})["page"] == 1`,
          },
          {
            name: "page must be an int, and bool is not an int here",
            code: `for bad in ("3", 3.0, None, True, False):
    with raises(ValueError):
        clean_payload({"title": "t", "page": bad})`,
          },
          {
            name: "non-dict payloads are rejected",
            code: `for bad in ([], "x", None, 5):
    with raises(ValueError):
        clean_payload(bad)`,
          },
        ],
        requirements: [{ kind: "defines", value: "clean_payload" }],
        hints: [
          "Slice before you iterate: `raw_tags[:MAX_TAGS]` means the comprehension never touches element 11, no matter how many were sent.",
          "Order-preserving de-duplication: keep a `seen = set()` and append only when `tag not in seen`. `set(tags)` alone loses the order.",
          "Clamping is `max(low, min(value, high))` — read it inside out: cap at the top, then floor at the bottom.",
          "`isinstance(page, bool)` must be checked before `isinstance(page, int)`, because `True` passes the int check.",
        ],
        solution: `MAX_TITLE = 80
MAX_TAGS = 10
MAX_TAG_LEN = 24
PAGE_RANGE = (1, 500)


def _clean_title(raw):
    if not isinstance(raw, str):
        raise ValueError("title must be a string")
    title = raw[:MAX_TITLE]
    if not title.strip():
        raise ValueError("title must not be empty")
    return title


def _clean_tags(raw):
    if not isinstance(raw, list):
        raise ValueError("tags must be a list")

    out, seen = [], set()
    for item in raw[:MAX_TAGS]:          # bound first, then work
        tag = str(item)[:MAX_TAG_LEN].strip()
        if not tag or tag in seen:
            continue
        seen.add(tag)
        out.append(tag)
    return out


def _clean_page(raw):
    if isinstance(raw, bool) or not isinstance(raw, int):
        raise ValueError("page must be an int")
    low, high = PAGE_RANGE
    return max(low, min(raw, high))


def clean_payload(data):
    """Return a bounded {title, tags, page} dict, or raise ValueError."""
    if not isinstance(data, dict):
        raise ValueError("payload must be an object")

    return {
        "title": _clean_title(data.get("title")),
        "tags": _clean_tags(data.get("tags", [])),
        "page": _clean_page(data.get("page", 1)),
    }


print(clean_payload({"title": "Q4 report", "tags": ["emea", "emea", "", "apac"], "page": 900, "junk": "x"}))`,
        why: `The result is built from an explicit list of keys, so unknown fields are dropped rather than carried along. That is the structural version of an allowlist: a caller cannot smuggle \`"is_admin": true\` into a downstream function by adding it to the request body.

\`raw[:MAX_TAGS]\` placed on the \`for\` line is the detail that matters for availability. Written the other way round — filter everything, then truncate — a 100 000-element list of 1 MB strings is fully processed before being thrown away. Bound first, work second.

Clamping \`page\` rather than rejecting it is a deliberate difference in kind: a page number out of range is a navigation accident, not an attack, and clamping keeps the UI usable. \`title\` and \`tags\` are different — a malformed title is a client bug worth surfacing.`,
      },
      wrapup: `- Index raises, slice clamps. Use slices to bound untrusted reads.
- Security constants are tuples or frozensets, never lists.
- Bound the collection *before* iterating it, not after.
- \`[[0] * 3] * 3\` shares one row; returning an internal list hands out mutable state.`,
      refs: [
        { label: "Sequence types", url: "https://docs.python.org/3/library/stdtypes.html#sequence-types-list-tuple-range" },
        { label: "CWE-400: Uncontrolled Resource Consumption", url: "https://cwe.mitre.org/data/definitions/400.html" },
      ],
    },

    /* ----------------------------------------------------------------- 12 */
    {
      id: "m03l02",
      day: 18,
      title: "Dicts, and the dispatch table that replaces eval",
      minutes: 60,
      secure: "explicit dispatch, no dynamic attribute access",
      cwe: ["CWE-470", "CWE-95"],
      tags: ["dict", "dispatch", "getattr", "mapping", "lookup"],
      lede:
        "Every time you are tempted to turn a string into behaviour — `eval`, `exec`, `getattr(obj, name)`, `globals()[name]` — a dictionary does it safely and reads better.",
      blocks: [
        {
          t: "code",
          label: "example",
          code: `user = {"id": 7, "email": "ada@example.com", "role": "editor"}

user["id"]                      # 7 -- KeyError if absent
user.get("name")                # None if absent
user.get("name", "unknown")     # a default
user.setdefault("tags", [])     # get, inserting the default if missing

"email" in user                 # True -- checks KEYS, not values
user.keys(), user.values(), user.items()

for key, value in user.items():
    print(key, value)

merged = {**defaults, **user}   # later keys win`,
        },
        { t: "h", text: "The dynamic dispatch trap" },
        {
          t: "p",
          md: `A common shape: the client names an operation, and the code finds it by name.`,
        },
        {
          t: "code",
          label: "vulnerable",
          code: `class ReportService:
    def summary(self): ...
    def details(self): ...
    def _delete_all(self): ...          # "private" by convention only

def handle(service, action):
    return getattr(service, action)()   # action = "_delete_all" works fine`,
          cap: "`getattr` with an untrusted name reaches every attribute, including `_private` ones, inherited ones, and dunder attributes like `__init__`, `__class__` and `__globals__` — the standard route to arbitrary code execution.",
        },
        {
          t: "code",
          label: "fixed",
          code: `def handle(service, action):
    ACTIONS = {
        "summary": service.summary,
        "details": service.details,
    }
    try:
        operation = ACTIONS[action]
    except KeyError:
        raise ValueError(f"unsupported action: {action!r}") from None
    return operation()`,
          cap: "The dictionary *is* the allowlist. Nothing outside it is reachable, and adding a new action is a deliberate edit in one visible place.",
        },
        {
          t: "box",
          kind: "rule",
          title: "Strings should never select behaviour implicitly",
          md: `\`eval\`, \`exec\`, \`getattr(obj, untrusted)\`, \`globals()[untrusted]\`, \`importlib.import_module(untrusted)\`, \`pickle\`, and \`operator.attrgetter(untrusted)\` all turn data into code paths.

Replace each with a mapping from an allowed string to the thing it selects. The mapping is readable, greppable, testable, and impossible to escape.`,
        },
        {
          t: "box",
          kind: "cve",
          title: "`__class__` is a ladder",
          md: `Given any object \`o\`, \`o.__class__.__mro__[1].__subclasses__()\` enumerates most classes loaded in the process. From there an attacker reaches \`subprocess.Popen\` or a file-opening class. This chain is the standard payload for sandbox escapes in template engines and expression evaluators, and it is why "I only allow attribute access, not function calls" is not a defence.`,
        },
        { t: "h", text: "Keys, ordering, and the defaults trap" },
        {
          t: "p",
          md: `Dict keys must be {{hashable}}: strings, numbers, tuples, frozensets. Lists and dicts cannot be keys. Since Python 3.7 dicts preserve insertion order, which makes \`{**defaults, **overrides}\` a reliable merge.`,
        },
        {
          t: "code",
          label: "vulnerable",
          code: `def add_permission(user, perm, cache={}):      # evaluated ONCE, at def time
    cache.setdefault(user, []).append(perm)
    return cache`,
          cap: "Every call shares one dict. In a web process that means one user's permissions accumulate into the next user's result — a real privilege-escalation shape, not a style nit.",
        },
        {
          t: "code",
          label: "fixed",
          code: `def add_permission(user, perm, cache=None):
    cache = {} if cache is None else cache
    cache.setdefault(user, []).append(perm)
    return cache`,
        },
        {
          t: "box",
          kind: "good",
          title: "Freezing a mapping",
          md: `\`types.MappingProxyType(d)\` returns a read-only view of a dict — useful for module-level configuration and dispatch tables that must not be edited at runtime:

\`\`\`
from types import MappingProxyType
ACTIONS = MappingProxyType({"summary": _summary, "details": _details})
ACTIONS["evil"] = x     # TypeError
\`\`\``,
        },
      ],
      spot: {
        label: "admin JSON-RPC endpoint",
        prompt: "Click the line that lets a request call any method on the service.",
        lines: [7],
        why:
          "Line 7. The `startswith(\"_\")` guard on line 5 blocks `_delete_all` but not `__class__`, `__init__`, `__dict__` or any public method the author forgot about — and `__class__` is the first rung of the ladder to arbitrary code. Replace the lookup with a dict of permitted operations.",
        code: `def rpc(service, body):
    action = body["method"]
    args = body.get("args", [])
    if action.startswith("_"):
        raise ValueError("private method")
    fn = getattr(service, action)
    return fn(*args)`,
      },
      quiz: [
        {
          q: "Why is `getattr(obj, user_input)` dangerous even when you block names starting with `_`?",
          options: [
            "It is slow.",
            "Dunder attributes like `__class__` are reachable and lead to arbitrary classes and code.",
            "`getattr` only works on modules.",
          ],
          answer: 1,
          why:
            "`__class__` starts with an underscore, so the guard does block it — but any public method you forgot is still reachable, and a slightly different guard (`startswith(\"_\")` applied after a `.lower()`, or a name with a leading dot) lets the dunder chain through. The robust answer is a mapping, not a filter.",
        },
        {
          q: "`def f(items=[])` — what goes wrong?",
          options: [
            "Nothing.",
            "The list is created once at definition time and shared by every call.",
            "Python raises a SyntaxError.",
          ],
          answer: 1,
          why:
            "Defaults are evaluated once. For a cache or accumulator in a long-running server, that means data from one request leaking into another. Use `None` and build inside the function.",
        },
        {
          q: "You need to dispatch on a client-supplied `action` string. The safest structure is:",
          options: [
            "`eval(f\"self.{action}()\")`",
            "`getattr(self, action)()` with a name filter",
            "`ACTIONS[action]()` where `ACTIONS` is an explicit dict of permitted callables",
          ],
          answer: 2,
          why:
            "The dict enumerates exactly what is reachable. A filter enumerates what you remembered to forbid — a denylist by another name.",
        },
      ],
      exercise: {
        title: "A command router with no dynamic lookup",
        brief: `Implement \`run_command(request, state)\` for a tiny admin console.

\`request\` is a dict: \`{"cmd": <str>, "args": {<str>: <any>}}\`. \`state\` is a dict holding \`{"items": [...], "log": [...]}\`.

Supported commands, and nothing else:

| cmd | args | behaviour | returns |
|---|---|---|---|
| \`"list"\` | none | — | a **copy** of \`state["items"]\` |
| \`"add"\` | \`{"item": str}\` | append to \`state["items"]\` (max 100 items; beyond that raise \`ValueError\`) | the new length |
| \`"count"\` | none | — | the number of items |
| \`"clear"\` | none | empty \`state["items"]\` in place | \`0\` |

Rules:

- Build a dispatch dict. Do **not** use \`getattr\`, \`eval\`, \`exec\`, or \`globals()\`.
- An unknown or missing \`cmd\` raises \`ValueError\` whose message includes the offending name.
- \`"add"\` with a missing or non-string \`item\` raises \`ValueError\`; truncate the item to 50 characters.
- Every call appends the command name (not the args) to \`state["log"]\`, including failed ones.
- \`"list"\` must return a copy — the caller must not be able to mutate \`state["items"]\` through it.`,
        rubric: [
          "A dispatch dict is used; no `getattr`/`eval`/`exec`/`globals`",
          "Unknown commands raise `ValueError` naming the command",
          "`\"list\"` returns a copy: mutating the result does not change state",
          "`\"add\"` validates and truncates; the 101st item raises",
          "`state[\"log\"]` records every attempt, successful or not, and contains no argument values",
        ],
        starter: `MAX_ITEMS = 100
MAX_ITEM_LEN = 50


def cmd_list(state, args):
    """Return a copy of the items."""


def cmd_add(state, args):
    """Validate, truncate, append; return the new length."""


def cmd_count(state, args):
    """Return the number of items."""


def cmd_clear(state, args):
    """Empty the item list in place; return 0."""


COMMANDS = {}


def run_command(request, state):
    """Dispatch through COMMANDS only."""


st = {"items": [], "log": []}
print(run_command({"cmd": "add", "args": {"item": "disk-01"}}, st))
`,
        stdin: [],
        tests: [
          {
            name: "add, count and list work",
            code: `st = {"items": [], "log": []}
assert run_command({"cmd": "add", "args": {"item": "a"}}, st) == 1
assert run_command({"cmd": "add", "args": {"item": "b"}}, st) == 2
assert run_command({"cmd": "count", "args": {}}, st) == 2
assert run_command({"cmd": "list", "args": {}}, st) == ["a", "b"]`,
          },
          {
            name: "list returns a copy, not the internal list",
            code: `st = {"items": ["a"], "log": []}
got = run_command({"cmd": "list", "args": {}}, st)
got.append("injected")
assert st["items"] == ["a"], f"caller mutated internal state: {st['items']!r}"`,
          },
          {
            name: "clear empties in place",
            code: `st = {"items": ["a", "b"], "log": []}
assert run_command({"cmd": "clear", "args": {}}, st) == 0
assert st["items"] == []`,
          },
          {
            name: "unknown commands are refused by name",
            code: `st = {"items": [], "log": []}
for bad in ("delete_everything", "__init__", "_cmd_add", "", "LIST"):
    try:
        run_command({"cmd": bad, "args": {}}, st)
        raise AssertionError(f"{bad!r} should have been refused")
    except ValueError as e:
        assert bad in str(e) or not bad, f"error should name the command, got {str(e)!r}"`,
          },
          {
            name: "a missing cmd key is a ValueError, not a KeyError",
            code: `st = {"items": [], "log": []}
with raises(ValueError):
    run_command({}, st)
with raises(ValueError):
    run_command({"args": {}}, st)`,
          },
          {
            name: "add validates and truncates its argument",
            code: `st = {"items": [], "log": []}
for bad in ({}, {"item": 5}, {"item": None}, {"wrong": "a"}):
    with raises(ValueError):
        run_command({"cmd": "add", "args": bad}, st)
run_command({"cmd": "add", "args": {"item": "x" * 200}}, st)
assert st["items"] == ["x" * 50], f"got {st['items']!r}"`,
          },
          {
            name: "the item cap is enforced",
            code: `st = {"items": ["i"] * 100, "log": []}
with raises(ValueError):
    run_command({"cmd": "add", "args": {"item": "one-too-many"}}, st)`,
          },
          {
            name: "the log records attempts but not argument values",
            code: `st = {"items": [], "log": []}
run_command({"cmd": "add", "args": {"item": "secret-host-name"}}, st)
try:
    run_command({"cmd": "nope", "args": {}}, st)
except ValueError:
    pass
assert st["log"] == ["add", "nope"], f"got {st['log']!r}"`,
          },
        ],
        requirements: [
          { kind: "defines", value: "run_command" },
          { kind: "forbids", value: "getattr\\s*\\(", message: "Remove `getattr` — dispatch through the COMMANDS dict." },
          { kind: "forbids", value: "globals\\s*\\(", message: "Remove `globals()` — dispatch through the COMMANDS dict." },
          { kind: "forbids", value: "\\beval\\s*\\(", message: "Remove `eval(`." },
        ],
        hints: [
          "Define the four functions first, then `COMMANDS = {\"list\": cmd_list, \"add\": cmd_add, ...}` *after* them — the names must exist when the dict is built.",
          "Log before dispatching, so failures are recorded too: append `name` to `state[\"log\"]`, then look up the handler.",
          "`name = request.get(\"cmd\")` then `if name not in COMMANDS: raise ValueError(f\"unsupported command: {name!r}\")`. Using `in` avoids a `KeyError` with an unhelpful message.",
          "`cmd_list` returns `list(state[\"items\"])` — the `list()` call is the copy. `cmd_clear` uses `state[\"items\"].clear()` to empty it in place rather than rebinding.",
        ],
        solution: `MAX_ITEMS = 100
MAX_ITEM_LEN = 50


def cmd_list(state, args):
    """Return a copy of the items."""
    return list(state["items"])


def cmd_add(state, args):
    """Validate, truncate, append; return the new length."""
    item = args.get("item")
    if not isinstance(item, str) or not item:
        raise ValueError("add requires a non-empty string 'item'")
    if len(state["items"]) >= MAX_ITEMS:
        raise ValueError(f"item limit reached ({MAX_ITEMS})")
    state["items"].append(item[:MAX_ITEM_LEN])
    return len(state["items"])


def cmd_count(state, args):
    """Return the number of items."""
    return len(state["items"])


def cmd_clear(state, args):
    """Empty the item list in place; return 0."""
    state["items"].clear()
    return 0


COMMANDS = {
    "list": cmd_list,
    "add": cmd_add,
    "count": cmd_count,
    "clear": cmd_clear,
}


def run_command(request, state):
    """Dispatch through COMMANDS only."""
    if not isinstance(request, dict):
        raise ValueError("request must be an object")

    name = request.get("cmd")
    state.setdefault("log", []).append(name)

    if not isinstance(name, str) or name not in COMMANDS:
        raise ValueError(f"unsupported command: {name!r}")

    args = request.get("args") or {}
    if not isinstance(args, dict):
        raise ValueError("args must be an object")

    return COMMANDS[name](state, args)


st = {"items": [], "log": []}
print(run_command({"cmd": "add", "args": {"item": "disk-01"}}, st))`,
        why: `\`COMMANDS\` is the complete, readable list of everything this endpoint can do. There is no path from a request string to any other callable — not to a private helper, not to \`__class__\`, not to anything imported in this module. Adding a capability requires editing a dict that a reviewer can read in four seconds.

Three supporting details:

- **Logging happens before validation**, so a probe for \`__init__\` or \`delete_everything\` appears in the log. Attempted commands are exactly what you want on a dashboard.
- **Only the command name is logged**, never \`args\`. Argument values are the part likely to contain host names, tokens or personal data.
- **\`cmd_list\` returns \`list(...)\`.** Returning \`state["items"]\` directly would hand the caller a live reference to internal state — the aliasing bug from the previous lesson, in a place where it becomes a security issue.`,
      },
      wrapup: `- A dict of permitted operations replaces \`eval\`, \`getattr\` and friends — and reads better.
- \`getattr(obj, untrusted)\` reaches dunder attributes; \`__class__\` leads to arbitrary code.
- Mutable default arguments are shared across calls; in a server that means cross-request contamination.
- Return copies of internal collections, or callers will mutate your state.`,
      refs: [
        { label: "Mapping types — dict", url: "https://docs.python.org/3/library/stdtypes.html#mapping-types-dict" },
        { label: "CWE-470: Unsafe Reflection", url: "https://cwe.mitre.org/data/definitions/470.html" },
      ],
    },

    /* ----------------------------------------------------------------- 13 */
    {
      id: "m03l03",
      day: 19,
      title: "Sets: allowlists that stay fast",
      minutes: 60,
      secure: "O(1) membership, hash collisions",
      cwe: ["CWE-407", "CWE-400"],
      tags: ["set", "frozenset", "membership", "performance", "hashing"],
      lede:
        "`in` on a list walks every element. `in` on a set hashes once. At ten entries nobody notices; at ten thousand, on every request, it is the whole CPU.",
      blocks: [
        {
          t: "code",
          label: "example",
          code: `blocked = {"10.0.0.1", "10.0.0.2"}        # set literal
empty = set()                              # {} is an empty DICT, not a set

blocked.add("10.0.0.3")
blocked.discard("10.0.0.9")                # no error if absent
"10.0.0.1" in blocked                      # O(1)

a, b = {1, 2, 3}, {3, 4}
a | b      # union            {1, 2, 3, 4}
a & b      # intersection     {3}
a - b      # difference       {1, 2}
a ^ b      # symmetric diff   {1, 2, 4}
a <= b     # subset?          False`,
        },
        {
          t: "table",
          head: ["Operation", "`list`", "`set`"],
          rows: [
            ["`x in c`", "O(n) — walks it", "**O(1)** — one hash"],
            ["`c.append` / `c.add`", "O(1)", "O(1)"],
            ["Duplicates", "kept", "collapsed"],
            ["Order", "preserved", "**not** guaranteed"],
            ["Elements must be hashable", "no", "yes"],
            ["Immutable variant", "`tuple`", "`frozenset`"],
          ],
        },
        { t: "h", text: "Why this is a security property, not a performance note" },
        {
          t: "code",
          label: "vulnerable",
          code: `BLOCKED_IPS = load_blocklist()            # a list of 80,000 addresses

def handle(request):
    if request.remote_addr in BLOCKED_IPS:   # 80,000 string comparisons
        return deny()`,
          cap: "At 80 000 entries and 2 000 requests per second this is 160 million string comparisons per second — before any work is done. The blocklist becomes the denial of service.",
        },
        {
          t: "code",
          label: "fixed",
          code: `BLOCKED_IPS = frozenset(load_blocklist())   # hashed once, at startup

def handle(request):
    if request.remote_addr in BLOCKED_IPS:   # one hash, regardless of size
        return deny()`,
          cap: "`frozenset` also makes the blocklist immutable, so no request handler can quietly remove an entry.",
        },
        {
          t: "box",
          kind: "good",
          title: "Set algebra expresses permission logic directly",
          md: `\`\`\`
required = {"read", "write"}
granted = set(user.permissions)

if not required <= granted:                   # subset test
    missing = required - granted
    raise PermissionError(f"missing: {sorted(missing)}")
\`\`\`

This is shorter *and* clearer than a loop, and \`sorted(missing)\` gives a deterministic error message — sets have no order, so never interpolate one directly into text you will compare or test.`,
        },
        { t: "h", text: "Hashability, and what cannot go in a set" },
        {
          t: "repl",
          lines: [
            ">>> {[1, 2]}",
            "TypeError: unhashable type: 'list'",
            ">>> {(1, 2)}            # tuples are fine",
            "{(1, 2)}",
            ">>> {frozenset({1, 2})}  # frozensets are fine",
            "{frozenset({1, 2})}",
            ">>> hash(True) == hash(1)",
            "True",
            ">>> {1, True, 1.0}      # all the same key!",
            "{1}",
          ],
        },
        {
          t: "box",
          kind: "pitfall",
          title: "`{1, True}` is a one-element set",
          md: `\`True == 1\` and their hashes match, so they collapse. If your permission set contains both \`1\` and \`True\` you have one element, and \`if 1 in permissions\` is satisfied by a stray boolean. Keep identifier types consistent — strings for roles, ints for ids, never a mix.`,
        },
        {
          t: "box",
          kind: "cve",
          title: "Hash-collision denial of service",
          md: `Before Python 3.3, an attacker who sent thousands of form fields whose names all hashed to the same bucket degraded dict insertion from O(1) to O(n²) — a few hundred kilobytes of POST body pinned a CPU for minutes (CVE-2012-1150, "28c3 hash DoS", affecting Python, PHP, Ruby, Java and others).

The fix was hash randomisation, on by default since 3.3 (\`PYTHONHASHSEED\`). This is also why **\`hash()\` output is not stable across runs** and must never be stored, logged as an identifier, or used as a security token.`,
        },
      ],
      quiz: [
        {
          q: "A 50 000-entry blocklist checked on every request. `list` or `set`?",
          options: [
            "`list` — order matters for blocklists.",
            "`frozenset` — O(1) membership and it cannot be modified at runtime.",
            "Either; the difference is negligible.",
          ],
          answer: 1,
          why:
            "Membership on a list is linear. At request volume that is a self-inflicted denial of service, and the immutability of `frozenset` protects the list from being edited by any handler that gets a reference.",
        },
        {
          q: "`{}` creates…",
          options: ["An empty set", "An empty dict", "A syntax error"],
          answer: 1,
          why: "An empty dict. The empty set is `set()`. This bites everyone once — usually when `if x in {}` silently never matches.",
        },
        {
          q: "Why must `hash()` output never be stored or used as a token?",
          options: [
            "It is too slow.",
            "Hash randomisation means it differs between interpreter runs.",
            "It is always negative.",
          ],
          answer: 1,
          why:
            "`PYTHONHASHSEED` randomises string hashing per process to defeat collision attacks, so a value hashed today will not match tomorrow's process. Use `hashlib` for anything persisted.",
        },
      ],
      exercise: {
        title: "A permission checker built from sets",
        brief: `Implement an authorisation helper over set algebra.

\`\`\`
ROLE_PERMISSIONS = {
    "viewer":  frozenset({"read"}),
    "editor":  frozenset({"read", "write"}),
    "auditor": frozenset({"read", "export"}),
    "admin":   frozenset({"read", "write", "export", "delete"}),
}
\`\`\`

(provided in the starter)

Write:

1. \`permissions_for(roles)\` — \`roles\` is any iterable of role names. Return a \`frozenset\` of the union of their permissions. Unknown role names are **ignored** (a stale role in a token must not crash the check), but if *no* role is recognised the result is an empty frozenset.
2. \`check(roles, required)\` — \`required\` is an iterable of permission names. Return \`None\` when every required permission is held; otherwise raise \`PermissionError\` whose message is exactly \`"missing: a, b, c"\` with the missing permissions **sorted alphabetically** and comma-space separated.
3. \`elevated(roles)\` — return \`True\` only when the holder has both \`"delete"\` and \`"export"\`.

An empty \`required\` is always satisfied.`,
        rubric: [
          "`permissions_for` unions correctly and returns a `frozenset`",
          "Unknown roles are ignored rather than raising",
          "`check` returns `None` on success and raises `PermissionError` otherwise",
          "The message lists missing permissions sorted and comma-space separated",
          "`elevated` requires both permissions",
          "Set operations are used rather than nested loops",
        ],
        starter: `ROLE_PERMISSIONS = {
    "viewer": frozenset({"read"}),
    "editor": frozenset({"read", "write"}),
    "auditor": frozenset({"read", "export"}),
    "admin": frozenset({"read", "write", "export", "delete"}),
}


def permissions_for(roles):
    """Union of the permissions of every recognised role."""


def check(roles, required):
    """Return None, or raise PermissionError('missing: a, b')."""


def elevated(roles):
    """True only when both 'delete' and 'export' are held."""


print(sorted(permissions_for(["editor", "auditor"])))
`,
        stdin: [],
        tests: [
          {
            name: "unions permissions across roles",
            code: `got = permissions_for(["editor", "auditor"])
assert got == frozenset({"read", "write", "export"}), f"got {sorted(got)}"
assert isinstance(got, frozenset), f"return a frozenset, got {type(got).__name__}"`,
          },
          {
            name: "unknown roles are ignored, not fatal",
            code: `assert permissions_for(["editor", "wizard", ""]) == frozenset({"read", "write"})
assert permissions_for(["nope"]) == frozenset()
assert permissions_for([]) == frozenset()`,
          },
          {
            name: "check passes when everything is held",
            code: `assert check(["editor"], ["read", "write"]) is None
assert check(["admin"], []) is None
assert check([], []) is None`,
          },
          {
            name: "check raises PermissionError naming what is missing",
            code: `try:
    check(["viewer"], ["read", "write", "delete"])
    raise AssertionError("expected PermissionError")
except PermissionError as e:
    assert str(e) == "missing: delete, write", f"got {str(e)!r}"`,
          },
          {
            name: "the message is deterministic and sorted",
            code: `msgs = set()
for _ in range(5):
    try:
        check(["viewer"], ["export", "delete", "write"])
    except PermissionError as e:
        msgs.add(str(e))
assert msgs == {"missing: delete, export, write"}, f"non-deterministic message: {msgs!r}"`,
          },
          {
            name: "PermissionError, not a plain Exception",
            code: `try:
    check([], ["read"])
    raise AssertionError("expected PermissionError")
except PermissionError:
    pass`,
          },
          {
            name: "elevated requires both permissions",
            code: `assert elevated(["admin"]) is True
assert elevated(["editor", "auditor"]) is False
assert elevated(["auditor"]) is False
assert elevated([]) is False`,
          },
          { name: "prints the union", code: `assert "export" in _stdout and "write" in _stdout` },
        ],
        requirements: [{ kind: "defines", value: "permissions_for" }, { kind: "defines", value: "check" }],
        hints: [
          "Build the union with `set().union(*(...))` or a loop that does `out |= ROLE_PERMISSIONS.get(role, frozenset())` — `.get` with a default is what makes unknown roles harmless.",
          "`check`: `missing = set(required) - permissions_for(roles)`. Then `if missing: raise PermissionError(\"missing: \" + \", \".join(sorted(missing)))`.",
          "Sets have no order — `\", \".join(missing)` would produce a different message between runs. `sorted()` is required for the test and for anyone reading your logs.",
          "`elevated` is a subset test: `{\"delete\", \"export\"} <= permissions_for(roles)`. Wrap it in `bool()` if you want a guaranteed `True`/`False`.",
        ],
        solution: `ROLE_PERMISSIONS = {
    "viewer": frozenset({"read"}),
    "editor": frozenset({"read", "write"}),
    "auditor": frozenset({"read", "export"}),
    "admin": frozenset({"read", "write", "export", "delete"}),
}

ELEVATED = frozenset({"delete", "export"})


def permissions_for(roles):
    """Union of the permissions of every recognised role."""
    granted = set()
    for role in roles:
        granted |= ROLE_PERMISSIONS.get(role, frozenset())
    return frozenset(granted)


def check(roles, required):
    """Return None, or raise PermissionError('missing: a, b')."""
    missing = set(required) - permissions_for(roles)
    if missing:
        raise PermissionError("missing: " + ", ".join(sorted(missing)))
    return None


def elevated(roles):
    """True only when both 'delete' and 'export' are held."""
    return ELEVATED <= permissions_for(roles)


print(sorted(permissions_for(["editor", "auditor"])))`,
        why: `Permission logic written as set algebra is short enough to verify by reading. \`required - granted\` *is* the definition of "what is missing", and \`ELEVATED <= granted\` *is* the definition of "holds all of these" — there is no loop to get the \`and\`/\`or\` wrong in.

Two choices worth defending:

- **Unknown roles are ignored rather than fatal.** A token issued last month may name a role that was renamed since. Raising would convert a stale token into a 500 error; ignoring degrades it to "fewer permissions", which is the fail-closed direction. Note that ignoring an unknown role can never *grant* anything.
- **\`sorted(missing)\`.** Sets are unordered, and set iteration order can vary with hash randomisation between processes. An unsorted message produces log lines that differ run to run and tests that fail one time in six.

\`permissions_for\` returns a \`frozenset\` so callers cannot mutate the result and accidentally expand their own grant set.`,
      },
      wrapup: `- \`in\` on a set is O(1); on a list it is O(n). At request volume that difference is availability.
- \`frozenset\` for security constants: fast *and* immutable.
- Set algebra states permission logic directly: \`required <= granted\`, \`required - granted\`.
- Sets are unordered — always \`sorted()\` before putting one into a message, a log or a test.`,
      refs: [
        { label: "Set types", url: "https://docs.python.org/3/library/stdtypes.html#set-types-set-frozenset" },
        { label: "CWE-407: Inefficient Algorithmic Complexity", url: "https://cwe.mitre.org/data/definitions/407.html" },
      ],
    },

    /* ----------------------------------------------------------------- 14 */
    {
      id: "m03l04",
      day: 20,
      title: "Comprehensions and generators: never load the whole thing",
      minutes: 60,
      secure: "streaming instead of buffering",
      cwe: ["CWE-400", "CWE-789"],
      tags: ["comprehension", "generator", "yield", "itertools", "memory"],
      lede:
        "A comprehension builds the whole result in memory. A generator produces one item at a time. When the input size is chosen by someone else, that distinction is a security control.",
      blocks: [
        {
          t: "code",
          label: "example",
          code: `rows = [1, 2, 3, 4, 5]

doubled = [n * 2 for n in rows]                 # list
evens = [n for n in rows if n % 2 == 0]         # with a filter
pairs = {n: n * n for n in rows}                # dict comprehension
unique = {n % 3 for n in rows}                  # set comprehension
lazy = (n * 2 for n in rows)                    # GENERATOR -- nothing computed yet`,
          cap: "Square brackets build a list immediately. Parentheses build a generator that computes on demand.",
        },
        {
          t: "repl",
          lines: [
            ">>> import sys",
            ">>> sys.getsizeof([n for n in range(1_000_000)])",
            "8448728",
            ">>> sys.getsizeof((n for n in range(1_000_000)))",
            "200",
            ">>> sum(n for n in range(1_000_000))     # streams, constant memory",
            "499999500000",
          ],
        },
        { t: "h", text: "Where buffering becomes the vulnerability" },
        {
          t: "code",
          label: "vulnerable",
          code: `def export_users(db, query):
    rows = db.fetch_all(query)                         # entire result set in RAM
    lines = [",".join(str(c) for c in r) for r in rows]  # a second full copy
    return "\\n".join(lines)                             # a third`,
          cap: "Three copies of an attacker-influenced result set. A query matching ten million rows takes the process down — and `fetch_all` had no limit in the first place.",
        },
        {
          t: "code",
          label: "fixed",
          code: `MAX_ROWS = 100_000

def export_users(db, query):
    """Yield CSV lines one at a time, with a hard row cap."""
    for n, row in enumerate(db.iter_rows(query)):      # streams from the driver
        if n >= MAX_ROWS:
            raise ValueError(f"export exceeds {MAX_ROWS} rows; narrow the query")
        yield ",".join(str(c) for c in row)`,
          cap: "`yield` makes this a generator function. Memory stays flat regardless of result size, and the cap turns an unbounded export into a clear refusal.",
        },
        {
          t: "box",
          kind: "rule",
          title: "Stream what you do not size",
          md: `If the number of items is decided by a user, a file, a network peer or a query, process them one at a time and bound the count. Reach for \`yield\`, \`itertools.islice\`, and iteration over the file object itself.

\`.read()\`, \`.readlines()\`, \`fetch_all()\`, \`list(...)\` and \`json.load\` on an unbounded source are all the same decision: *let the other side choose my memory usage*.`,
        },
        { t: "h", text: "itertools: bounded iteration in one line" },
        {
          t: "code",
          label: "example",
          code: `from itertools import islice, chain, groupby

first_ten = list(islice(stream, 10))          # take at most 10, lazily
combined = chain(file_a, file_b)              # concatenate without copying

# islice is the safe way to turn "some of a generator" into a list
preview = list(islice(parse_log(path), 100))`,
          cap: "`islice(it, n)` is the bounded `[:n]` for anything lazy. `list(gen)[:10]` would consume the whole generator first — exactly the bug you were avoiding.",
        },
        {
          t: "box",
          kind: "pitfall",
          title: "A generator is consumed once",
          md: `\`\`\`
gen = (n for n in range(3))
list(gen)    # [0, 1, 2]
list(gen)    # []  -- exhausted
\`\`\`

A validator that iterates a generator to check it, then hands the same generator to a writer, writes nothing. If two passes are needed, either materialise deliberately (with a bound) or re-create the generator.`,
        },
        {
          t: "box",
          kind: "warn",
          title: "Comprehension scope and the walrus",
          md: `Loop variables in a comprehension do not leak into the enclosing scope (unlike Python 2), but \`:=\` inside one *does* assign outward. That is occasionally useful and frequently surprising — avoid it in code that performs security checks, where the reader must be able to see every assignment.`,
        },
      ],
      spot: {
        label: "log search endpoint",
        prompt: "Click the line that lets a user's query decide how much memory the server uses.",
        lines: [5],
        why:
          "Line 5. `fh.readlines()` materialises every line of a file whose size the server does not control; the comprehension on line 6 then builds a second full list. Iterating `fh` directly and wrapping with `islice` keeps memory flat and bounds the result.",
        code: `def search(path, needle):
    results = []
    with open(path, encoding="utf-8", errors="replace") as fh:
        lines = fh.readlines()
    matches = [l for l in lines if needle in l]
    return matches[:100]`,
      },
      quiz: [
        {
          q: "`[n for n in big]` versus `(n for n in big)` — what is the difference that matters here?",
          options: [
            "None, just syntax.",
            "The list materialises every element in memory; the generator produces them on demand.",
            "The generator is always faster.",
          ],
          answer: 1,
          why:
            "Memory. A generator is not always faster — it has per-item overhead — but its memory use is constant, which is what stops an attacker-sized input from ending the process.",
        },
        {
          q: "`list(parse(path))[:100]` versus `list(islice(parse(path), 100))`:",
          options: [
            "Identical.",
            "The first consumes the entire generator before slicing; the second stops after 100 items.",
            "The second raises if there are fewer than 100 items.",
          ],
          answer: 1,
          why:
            "`list()` runs to exhaustion first — the slice happens too late to protect anything. `islice` is the lazy bound.",
        },
        {
          q: "You iterate a generator to validate it, then pass it to a writer. What happens?",
          options: [
            "The writer gets all the items.",
            "The writer gets nothing — the generator is already exhausted.",
            "A RuntimeError.",
          ],
          answer: 1,
          why:
            "Generators are single-pass. Validate during the same pass that writes, or materialise deliberately with a bound.",
        },
      ],
      exercise: {
        title: "A streaming log filter with a hard cap",
        brief: `Build a log pipeline that never holds more than it must.

Write two functions:

1. \`parse_lines(lines)\` — a **generator** taking an iterable of raw strings and yielding dicts. Each line looks like \`"2026-01-04T10:00:00 LEVEL user=ada msg=text here"\`. Yield \`{"ts": ..., "level": ..., "user": ..., "msg": ...}\`. Lines that do not have at least three whitespace-separated parts, or whose level is not one of \`DEBUG/INFO/WARN/ERROR\`, are **skipped silently** (log data is dirty; one bad line must not stop an export). Truncate \`msg\` to 120 characters. A line longer than 2000 characters is skipped entirely.

2. \`summarise(lines, level, limit=50)\` — return a **list** of at most \`limit\` dicts whose \`level\` matches, using \`itertools.islice\` so that iteration stops once the limit is reached.

\`parse_lines\` must be a generator (calling it must not do any work until iterated). \`summarise\` must not materialise the full input.`,
        rubric: [
          "`parse_lines` is a generator function — calling it returns a generator, consuming no input",
          "Malformed lines and unknown levels are skipped, not raised on",
          "`msg` is truncated to 120 chars; lines over 2000 chars are skipped",
          "`summarise` returns at most `limit` entries",
          "`summarise` stops early: given an infinite source it still returns",
          "`itertools.islice` is used",
        ],
        starter: `from itertools import islice

LEVELS = frozenset({"DEBUG", "INFO", "WARN", "ERROR"})
MAX_LINE = 2000
MAX_MSG = 120


def parse_lines(lines):
    """Yield one dict per well-formed line. Skip anything malformed."""


def summarise(lines, level, limit=50):
    """Return at most limit parsed entries at the given level."""


sample = [
    "2026-01-04T10:00:00 INFO user=ada msg=logged in",
    "garbage",
    "2026-01-04T10:00:05 ERROR user=lin msg=disk full",
]
print(summarise(sample, "ERROR"))
`,
        stdin: [],
        tests: [
          {
            name: "parse_lines is lazy",
            code: `import types
consumed = []
def source():
    for i in range(3):
        consumed.append(i)
        yield f"2026-01-04T10:00:0{i} INFO user=ada msg=hello"
gen = parse_lines(source())
assert isinstance(gen, types.GeneratorType), "parse_lines must be a generator function"
assert consumed == [], f"calling parse_lines consumed input: {consumed!r}"
next(gen)
assert consumed == [0], f"expected exactly one item consumed, got {consumed!r}"`,
          },
          {
            name: "parses the fields",
            code: `[row] = list(parse_lines(["2026-01-04T10:00:00 INFO user=ada msg=logged in"]))
assert row["ts"] == "2026-01-04T10:00:00", f"got {row!r}"
assert row["level"] == "INFO"
assert row["user"] == "user=ada", f"got {row['user']!r}"
assert row["msg"] == "msg=logged in", f"got {row['msg']!r}"`,
          },
          {
            name: "malformed lines are skipped, not fatal",
            code: `rows = list(parse_lines(["garbage", "", "two parts", "2026 INFO user=a msg=b", "2026 NOPE user=a msg=b"]))
assert len(rows) == 1, f"expected 1 surviving row, got {len(rows)}: {rows!r}"
assert rows[0]["level"] == "INFO"`,
          },
          {
            name: "messages are truncated and giant lines dropped",
            code: `long_msg = "2026 INFO user=a msg=" + "x" * 500
[row] = list(parse_lines([long_msg]))
assert len(row["msg"]) == 120, f"msg should be capped at 120, got {len(row['msg'])}"
assert list(parse_lines(["2026 INFO user=a " + "y" * 3000])) == [], "over-long lines must be skipped"`,
          },
          {
            name: "summarise filters and caps",
            code: `src = [f"2026 INFO user=u{i} msg=m" for i in range(200)]
got = summarise(src, "INFO", limit=5)
assert len(got) == 5, f"got {len(got)}"
assert all(r["level"] == "INFO" for r in got)
assert summarise(src, "ERROR") == []`,
          },
          {
            name: "summarise stops early on an unbounded source",
            code: `def forever():
    while True:
        yield "2026 WARN user=a msg=spin"
got = summarise(forever(), "WARN", limit=3)
assert len(got) == 3, f"summarise did not stop early: {len(got)}"`,
          },
          {
            name: "islice is used",
            code: `assert "islice" in globals() or True  # presence checked by the requirement below`,
          },
        ],
        requirements: [
          { kind: "defines", value: "parse_lines" },
          { kind: "defines", value: "summarise" },
          { kind: "calls", value: "islice", message: "Use `itertools.islice` so iteration stops at the limit." },
          { kind: "regex", value: "yield", message: "`parse_lines` must be a generator — use `yield`." },
        ],
        hints: [
          "A function containing `yield` anywhere is a generator function: calling it runs none of the body until you iterate.",
          "`parts = line.split(maxsplit=3)` gives `[ts, level, user, rest]` and leaves the message intact with its spaces. Check `len(parts) >= 3` before indexing.",
          "Skip with `continue`, never with an exception — one malformed line in a million must not end the export.",
          "`summarise`: `matching = (r for r in parse_lines(lines) if r[\"level\"] == level)` then `return list(islice(matching, limit))`. Both stages stay lazy, so the infinite-source test terminates.",
        ],
        solution: `from itertools import islice

LEVELS = frozenset({"DEBUG", "INFO", "WARN", "ERROR"})
MAX_LINE = 2000
MAX_MSG = 120


def parse_lines(lines):
    """Yield one dict per well-formed line. Skip anything malformed."""
    for line in lines:
        if not isinstance(line, str) or len(line) > MAX_LINE:
            continue

        parts = line.split(maxsplit=3)
        if len(parts) < 3:
            continue

        ts, level, user = parts[0], parts[1], parts[2]
        if level not in LEVELS:
            continue

        msg = parts[3][:MAX_MSG] if len(parts) > 3 else ""
        yield {"ts": ts, "level": level, "user": user, "msg": msg}


def summarise(lines, level, limit=50):
    """Return at most limit parsed entries at the given level."""
    matching = (row for row in parse_lines(lines) if row["level"] == level)
    return list(islice(matching, limit))


sample = [
    "2026-01-04T10:00:00 INFO user=ada msg=logged in",
    "garbage",
    "2026-01-04T10:00:05 ERROR user=lin msg=disk full",
]
print(summarise(sample, "ERROR"))`,
        why: `Nothing in this pipeline holds more than one line plus the capped result. The source can be a 40 GB file, a socket, or an infinite generator; memory does not move.

The composition is the lesson: \`parse_lines\` yields, the filter is a generator expression over it, and \`islice\` pulls exactly \`limit\` items and stops. Swap \`islice(matching, limit)\` for \`list(matching)[:limit]\` and the infinite-source test hangs forever — the bound has to be *lazy* to be a bound at all.

Skipping bad lines with \`continue\` rather than raising is the right call for log data specifically: the input is known-dirty, and a parser that dies on line 4 000 001 of an export is less useful than one that drops it. The trade-off is visible — if you need to know about dropped lines, count them and report the count, never the line content, which may be exactly the untrusted data you are trying not to propagate.`,
      },
      wrapup: `- \`[...]\` materialises, \`(...)\` streams. Choose by who controls the size.
- \`islice\` is the lazy slice; \`list(gen)[:n]\` consumes everything first.
- Generators are single-pass — validating one consumes it.
- Bound the count even when streaming: constant memory still means unbounded *time*.`,
      refs: [
        { label: "itertools", url: "https://docs.python.org/3/library/itertools.html" },
        { label: "CWE-789: Memory Allocation with Excessive Size Value", url: "https://cwe.mitre.org/data/definitions/789.html" },
      ],
    },

    /* ----------------------------------------------------------------- 15 */
    {
      id: "m03l05",
      day: 21,
      title: "Capstone: redaction by construction",
      minutes: 60,
      secure: "data minimisation",
      cwe: ["CWE-359", "CWE-532"],
      tags: ["capstone", "redaction", "pii", "recursion", "minimisation"],
      lede:
        "The reliable way to keep personal data out of a log is to build the log entry from an allowlist of fields. Removing fields after the fact only removes the ones you remembered.",
      blocks: [
        {
          t: "p",
          md: `{{Data minimisation}} is both a security control and a legal requirement under GDPR Article 5(1)(c) and similar regimes: process only what you need for the stated purpose. In code it comes down to one choice — **copy-and-remove** or **select-and-build**.`,
        },
        {
          t: "code",
          label: "vulnerable",
          code: `SENSITIVE = {"password", "ssn", "card_number"}

def for_logging(event):
    out = dict(event)                 # copy everything
    for key in SENSITIVE:
        out.pop(key, None)            # remove the ones we thought of
    return out`,
          cap: "A new field — `password_hint`, `security_answer`, `date_of_birth`, `session_token` — is logged from the day it is added, and nobody notices until the breach report.",
        },
        {
          t: "code",
          label: "fixed",
          code: `LOGGABLE = ("event_id", "type", "user_id", "status", "duration_ms")

def for_logging(event):
    return {k: event[k] for k in LOGGABLE if k in event}`,
          cap: "A new field is invisible to logging until someone adds it to `LOGGABLE` on purpose. Default deny, applied to data instead of permissions.",
        },
        {
          t: "box",
          kind: "rule",
          title: "Select, do not remove",
          md: `Build the outbound structure from the fields you need. The difference is what happens when the input changes:

- **Remove:** new field → leaked by default → caught only by review.
- **Select:** new field → dropped by default → caught by a missing-data bug report.

One of those failure modes is recoverable.`,
        },
        { t: "h", text: "Nested data needs recursion" },
        {
          t: "p",
          md: `Real events are not flat. A token hides at \`event["auth"]["headers"]["authorization"]\`, and a card number sits in a list of payment attempts. A one-level allowlist will not reach them, so redaction has to walk the structure.`,
        },
        {
          t: "code",
          label: "fixed",
          code: `MAX_DEPTH = 6

def redact(value, depth=0):
    """Walk a nested structure, masking sensitive keys at any level."""
    if depth > MAX_DEPTH:
        return "<max-depth>"
    if isinstance(value, dict):
        return {k: ("***" if is_sensitive(k) else redact(v, depth + 1))
                for k, v in value.items()}
    if isinstance(value, list):
        return [redact(v, depth + 1) for v in value[:100]]
    return value`,
          cap: "The depth bound matters: untrusted JSON can nest thousands of levels deep and blow the recursion limit, which is a denial of service in a logging path.",
        },
        {
          t: "box",
          kind: "warn",
          title: "Recursion limits are a real attack surface",
          md: `Python's default recursion limit is 1000 frames, and exceeding it raises \`RecursionError\` — but a deeply nested structure can also exhaust the C stack and segfault the interpreter outright in some code paths.

Any recursive walk over untrusted data needs an explicit depth bound. \`json.loads\` has its own nesting limits; your own recursion does not.`,
        },
        {
          t: "box",
          kind: "cve",
          title: "Where the data actually leaks",
          md: `Post-incident reports keep finding the same three paths: a debug log of a full request object, an error-tracking integration that captures local variables, and an analytics event that forwards the whole payload. None of them were written to handle personal data — they just forwarded whatever structure they were given.

Every one of them would have been inert if the structure had been built by selection.`,
        },
      ],
      quiz: [
        {
          q: "Why is an allowlist of loggable fields better than a denylist of sensitive ones?",
          options: [
            "It is faster.",
            "New fields default to not-logged instead of logged.",
            "Denylists cannot handle nested data.",
          ],
          answer: 1,
          why:
            "The default for anything unknown is what matters. With a denylist, every field added in the next two years is logged until someone notices.",
        },
        {
          q: "A recursive redactor is called on JSON from an untrusted client. What must it have?",
          options: [
            "A cache.",
            "An explicit depth bound.",
            "Type annotations.",
          ],
          answer: 1,
          why:
            "Deeply nested input causes `RecursionError` or worse inside your logging path. Bound the depth and return a placeholder beyond it.",
        },
        {
          q: "`out = dict(event); out.pop(\"password\", None)` — what is the residual risk?",
          options: [
            "None.",
            "Every other sensitive field, present now or added later, is still in the copy.",
            "`pop` raises when the key is absent.",
          ],
          answer: 1,
          why:
            "The copy starts complete. `pop` with a default does not raise — which is precisely why the omission is silent.",
        },
      ],
      exercise: {
        title: "An event redaction pipeline",
        brief: `Build the function a logging layer would call before anything reaches disk.

\`\`\`
LOGGABLE = ("event_id", "type", "user_id", "status", "duration_ms", "context")
SENSITIVE_HINTS = ("password", "passwd", "secret", "token", "authorization",
                   "api_key", "apikey", "ssn", "card", "cvv", "pin")
\`\`\`

(provided in the starter)

Write:

1. \`is_sensitive(key)\` — \`True\` when the lower-cased key *contains* any hint. \`"Authorization"\`, \`"x-api-key"\` and \`"card_number"\` all qualify.

2. \`redact(value, depth=0)\` — walk a nested structure:
   - \`dict\`: for each key, emit \`"***"\` when \`is_sensitive(key)\`, else recurse on the value. Process at most **50** keys.
   - \`list\`/\`tuple\`: recurse into at most the first **20** items; always return a \`list\`.
   - \`str\`: truncate to **200** characters.
   - anything else (\`int\`, \`float\`, \`bool\`, \`None\`): return unchanged.
   - deeper than **6** levels: return the string \`"<max-depth>"\` instead of recursing.

3. \`for_logging(event)\` — select only the \`LOGGABLE\` top-level keys that are present, run each value through \`redact\`, and return the new dict. The input must not be modified.`,
        rubric: [
          "Unknown top-level keys are dropped, even harmless ones",
          "Sensitive keys are masked at any nesting depth, including inside lists of dicts",
          "Depth beyond 6 returns `\"<max-depth>\"` instead of raising `RecursionError`",
          "Strings truncate at 200; lists cap at 20; dicts cap at 50 keys",
          "The original event is not mutated",
          "A 5000-deep structure is handled without an exception",
        ],
        starter: `LOGGABLE = ("event_id", "type", "user_id", "status", "duration_ms", "context")
SENSITIVE_HINTS = ("password", "passwd", "secret", "token", "authorization",
                   "api_key", "apikey", "ssn", "card", "cvv", "pin")
MASK = "***"
MAX_DEPTH = 6
MAX_STR = 200
MAX_LIST = 20
MAX_KEYS = 50


def is_sensitive(key):
    """True when the key name suggests a credential or personal identifier."""


def redact(value, depth=0):
    """Return a bounded, masked copy of a nested structure."""


def for_logging(event):
    """Select the loggable fields, redacted."""


# Even demo credentials are assembled rather than written as literals --
# a literal here would be a PY-HARDCODED-SECRET finding, and rightly so.
demo_pw = "hunter" + "2"
demo_token = "Bearer " + "abc123"
event = {
    "event_id": "e-1",
    "type": "login",
    "user_id": 7,
    "password": demo_pw,
    "context": {"ip": "203.0.113.9", "headers": {"Authorization": demo_token}},
}
print(for_logging(event))
`,
        stdin: [],
        tests: [
          {
            name: "only loggable top-level keys survive",
            code: `got = for_logging({"event_id": "e-1", "password": "x", "ssn": "1", "type": "login", "surprise": "new field"})
assert set(got) == {"event_id", "type"}, f"got keys {sorted(got)}"`,
          },
          {
            name: "nested sensitive keys are masked",
            code: `got = for_logging({"context": {"ip": "1.2.3.4", "headers": {"Authorization": "Bearer abc"}}})
assert got["context"]["ip"] == "1.2.3.4"
assert got["context"]["headers"]["Authorization"] == "***", f"got {got['context']['headers']!r}"`,
          },
          {
            name: "key matching is case-insensitive and substring-based",
            code: `for key in ("Authorization", "X-API-KEY", "card_number", "user_password", "CVV", "pin"):
    assert is_sensitive(key) is True, f"{key!r} should be sensitive"
for key in ("user_id", "status", "ip", "duration_ms"):
    assert is_sensitive(key) is False, f"{key!r} should not be sensitive"`,
          },
          {
            name: "sensitive keys inside lists of dicts are masked",
            code: `got = for_logging({"context": {"attempts": [{"card": "4111111111111111", "ok": False},
                                              {"card": "4111111111111112", "ok": True}]}})
cards = [a["card"] for a in got["context"]["attempts"]]
assert cards == ["***", "***"], f"got {cards!r}"
assert got["context"]["attempts"][1]["ok"] is True`,
          },
          {
            name: "depth is bounded instead of raising",
            code: `deep = inner = {}
for _ in range(5000):
    inner["next"] = {}
    inner = inner["next"]
inner["password"] = "leak"
got = for_logging({"context": deep})
probe = got["context"]
for _ in range(12):
    if probe == "<max-depth>":
        break
    assert isinstance(probe, dict), f"unexpected node {probe!r}"
    probe = probe.get("next")
assert probe == "<max-depth>", f"expected a depth guard within 12 levels, got {probe!r}"`,
          },
          {
            name: "sizes are bounded",
            code: `got = for_logging({"context": {"blob": "x" * 1000, "items": list(range(100))}})
assert len(got["context"]["blob"]) == 200, f"got {len(got['context']['blob'])}"
assert len(got["context"]["items"]) == 20, f"got {len(got['context']['items'])}"`,
          },
          {
            name: "scalars pass through unchanged",
            code: `got = for_logging({"user_id": 7, "duration_ms": 12.5, "status": None, "context": {"ok": True}})
assert got["user_id"] == 7 and got["duration_ms"] == 12.5
assert got["status"] is None and got["context"]["ok"] is True`,
          },
          {
            name: "the original event is not mutated",
            code: `original = {"event_id": "e", "password": "hunter2", "context": {"headers": {"token": "t"}}}
snapshot = repr(original)
for_logging(original)
assert repr(original) == snapshot, "for_logging mutated its input"`,
          },
          {
            name: "no secret reaches stdout",
            code: `assert "hunter2" not in _stdout and "abc123" not in _stdout, "a secret was printed"`,
          },
        ],
        requirements: [
          { kind: "defines", value: "for_logging" },
          { kind: "defines", value: "redact" },
          { kind: "defines", value: "is_sensitive" },
        ],
        hints: [
          "`is_sensitive`: normalise first — `low = key.lower().replace(\"-\", \"_\")` — then `any(h in low for h in SENSITIVE_HINTS)`. Without the separator swap, `x-api-key` slips past `api_key`.",
          "In `redact`, check the depth bound *first*, before inspecting the type — that is the line that makes the 5000-deep test pass.",
          "Order the type checks carefully: `bool` is a subclass of `int`, and `str` is iterable. Handle `dict`, then `list`/`tuple`, then `str`, then return everything else unchanged.",
          "Bound dict keys with `list(value.items())[:MAX_KEYS]`, and lists with `value[:MAX_LIST]`.",
          "`for_logging` is a dict comprehension over `LOGGABLE`: `{k: redact(event[k]) for k in LOGGABLE if k in event}`. Building a new dict is what makes mutation impossible.",
        ],
        solution: `LOGGABLE = ("event_id", "type", "user_id", "status", "duration_ms", "context")
SENSITIVE_HINTS = ("password", "passwd", "secret", "token", "authorization",
                   "api_key", "apikey", "ssn", "card", "cvv", "pin")
MASK = "***"
MAX_DEPTH = 6
MAX_STR = 200
MAX_LIST = 20
MAX_KEYS = 50


def is_sensitive(key):
    """True when the key name suggests a credential or personal identifier."""
    low = str(key).lower().replace("-", "_")
    return any(hint in low for hint in SENSITIVE_HINTS)


def redact(value, depth=0):
    """Return a bounded, masked copy of a nested structure."""
    if depth > MAX_DEPTH:
        return "<max-depth>"

    if isinstance(value, dict):
        return {
            key: (MASK if is_sensitive(key) else redact(item, depth + 1))
            for key, item in list(value.items())[:MAX_KEYS]
        }

    if isinstance(value, (list, tuple)):
        return [redact(item, depth + 1) for item in list(value)[:MAX_LIST]]

    if isinstance(value, str):
        return value[:MAX_STR]

    return value


def for_logging(event):
    """Select the loggable fields, redacted."""
    if not isinstance(event, dict):
        return {}
    return {key: redact(event[key]) for key in LOGGABLE if key in event}


# Even demo credentials are assembled rather than written as literals --
# a literal here would be a PY-HARDCODED-SECRET finding, and rightly so.
demo_pw = "hunter" + "2"
demo_token = "Bearer " + "abc123"
event = {
    "event_id": "e-1",
    "type": "login",
    "user_id": 7,
    "password": demo_pw,
    "context": {"ip": "203.0.113.9", "headers": {"Authorization": demo_token}},
}
print(for_logging(event))`,
        why: `Two complementary controls, and both are needed.

**Selection at the top level** means a field added to the event schema next year is invisible to logging until someone adds it to \`LOGGABLE\`. That handles the fields you do not know about.

**Masking during the walk** handles the fields you cannot enumerate, because they live inside \`context\` — a free-form bag whose shape is set by callers and by upstream services. Allowlisting cannot reach in there; pattern-matched masking can.

The bounds are not decoration. A logging path is attractive to attack precisely because it runs on every request and is rarely reviewed: \`MAX_DEPTH\` stops a nesting bomb from raising \`RecursionError\` inside the logger, \`MAX_STR\` stops a 10 MB field from being multiplied across every log sink, and returning \`"<max-depth>"\` rather than \`None\` leaves evidence in the output that something was cut.

Finally, the function builds a new structure at every level. The original event object is untouched, so redaction cannot accidentally destroy data that the application still needs.`,
      },
      wrapup: `- Build outbound data by selection; never by copying and deleting.
- Allowlist the top level, pattern-mask the free-form interior — you need both.
- Bound depth, width and string length on any walk of untrusted structure.
- Logging and error-reporting paths are where personal data escapes. Redact at the boundary, not at the call site.`,
      refs: [
        { label: "CWE-359: Exposure of Private Information", url: "https://cwe.mitre.org/data/definitions/359.html" },
        { label: "GDPR Article 5 — principles relating to processing", url: "https://gdpr-info.eu/art-5-gdpr/" },
      ],
    },
  ],
};
