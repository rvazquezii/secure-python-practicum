export default {
  id: "m07",
  number: 7,
  title: "Objects and secure design",
  focus: "invariants",
  subtitle:
    "Classes as a place to put guarantees: an object that cannot be constructed in an invalid state, cannot be mutated into one, and cannot leak its secret into a log line.",
  objectives: [
    "Write classes whose constructor establishes an invariant the rest of the code can rely on.",
    "Use properties and name mangling to control what callers can read and write.",
    "Build immutable value objects with `dataclasses` and redact them in `__repr__`.",
    "Choose composition over inheritance, and keep subclasses substitutable.",
    "Implement `__eq__` and `__hash__` correctly, including constant-time comparison for secrets.",
  ],
  rules: [
    { id: "PY-SECRET-IN-LOG", what: "a default `__repr__` prints every attribute" },
    { id: "PY-TIMING-COMPARE", what: "`__eq__` on a secret must be constant-time" },
    { id: "PY-MUTABLE-DEFAULT", what: "class-level mutable attributes are shared by every instance" },
  ],
  capstone:
    "Day 35 builds a `Credential` type that validates on construction, refuses to be printed, compares in constant time, and cannot be serialised by accident.",

  lessons: [
    /* ----------------------------------------------------------------- 31 */
    {
      id: "m07l01",
      day: 31,
      title: "Classes, and invariants established at construction",
      minutes: 60,
      secure: "valid by construction",
      cwe: ["CWE-665"],
      tags: ["class", "init", "invariant", "self", "state"],
      lede:
        "If an object can only be created in a valid state, every method can assume validity. The alternative is re-checking the same thing in fifteen places and missing the sixteenth.",
      blocks: [
        {
          t: "code",
          label: "example",
          code: `class Account:
    def __init__(self, owner_id, balance_cents=0):
        self.owner_id = owner_id
        self.balance_cents = balance_cents

    def deposit(self, amount_cents):
        self.balance_cents += amount_cents
        return self.balance_cents

acct = Account(7, 1000)
acct.deposit(250)      # 1250`,
          cap: "`__init__` is the initialiser — Python has already created the object by then. `self` is that object, passed explicitly.",
        },
        { t: "h", text: "The constructor is where guarantees come from" },
        {
          t: "code",
          label: "vulnerable",
          code: `class Account:
    def __init__(self, owner_id, balance_cents=0):
        self.owner_id = owner_id              # could be a string, None, anything
        self.balance_cents = balance_cents    # could be negative, a float, a str

    def withdraw(self, amount):
        if amount > self.balance_cents:       # str > int raises; float is imprecise
            raise ValueError("insufficient funds")
        self.balance_cents -= amount`,
          cap: "Every method now has to defend itself, because the object could have been built from anything.",
        },
        {
          t: "code",
          label: "fixed",
          code: `class Account:
    """An account whose balance is always a non-negative integer of cents."""

    def __init__(self, owner_id, balance_cents=0):
        if isinstance(owner_id, bool) or not isinstance(owner_id, int) or owner_id <= 0:
            raise ValueError("owner_id must be a positive int")
        if isinstance(balance_cents, bool) or not isinstance(balance_cents, int):
            raise TypeError("balance must be an int number of cents")
        if balance_cents < 0:
            raise ValueError("balance cannot start negative")

        self.owner_id = owner_id
        self._balance_cents = balance_cents    # underscore: internal

    def withdraw(self, amount_cents):
        """The invariant lets this method be three lines instead of ten."""
        if isinstance(amount_cents, bool) or not isinstance(amount_cents, int) or amount_cents <= 0:
            raise ValueError("amount must be a positive int")
        if amount_cents > self._balance_cents:
            raise ValueError("insufficient funds")
        self._balance_cents -= amount_cents
        return self._balance_cents`,
          cap: "The constructor validates once; `withdraw` validates only its own argument and can trust everything else.",
        },
        {
          t: "box",
          kind: "rule",
          title: "State the invariant in the docstring, enforce it in `__init__`",
          md: `An {{invariant}} is a property that is true for the entire lifetime of the object: *the balance is a non-negative integer*, *the path is inside the base directory*, *the token has been verified*.

Write it down, enforce it at construction, and protect it in every method that mutates state. Then the rest of the system can hold an \`Account\` and know what it has.`,
        },
        { t: "h", text: "Class attributes are shared" },
        {
          t: "code",
          label: "vulnerable",
          code: `class Session:
    permissions = []            # ONE list for every instance, ever

    def grant(self, perm):
        self.permissions.append(perm)

a, b = Session(), Session()
a.grant("admin")
b.permissions               # ['admin']  -- b is now an admin`,
          cap: "The same bug as a mutable default argument, at class scope. In a web process it is cross-request privilege escalation.",
        },
        {
          t: "code",
          label: "fixed",
          code: `class Session:
    MAX_PERMISSIONS = 32        # a constant is fine as a class attribute

    def __init__(self):
        self.permissions = []   # per-instance, created in __init__

    def grant(self, perm):
        if len(self.permissions) >= self.MAX_PERMISSIONS:
            raise ValueError("too many permissions")
        self.permissions.append(perm)`,
        },
        {
          t: "box",
          kind: "note",
          title: "Underscore conventions",
          md: `- \`name\` — public API.
- \`_name\` — internal. A convention, not enforcement; tooling and reviewers respect it.
- \`__name\` — **name-mangled** to \`_ClassName__name\`. Not private either, but it will not be clobbered by a subclass, which is its actual purpose.

None of these stop a determined caller. They communicate intent, and that is worth a great deal when the reviewer is deciding whether a line is a bug.`,
        },
      ],
      quiz: [
        {
          q: "Why validate in `__init__` rather than in each method?",
          options: [
            "It is faster.",
            "One check establishes an invariant every method can rely on, so there is no sixteenth place to forget.",
            "Methods cannot raise exceptions.",
          ],
          answer: 1,
          why:
            "Validation scattered across methods is validation that will be inconsistent. The constructor is the single door into the object's lifetime.",
        },
        {
          q: "`class Session: permissions = []` — what is wrong?",
          options: [
            "Nothing.",
            "The list is a class attribute shared by every instance, so one session's grant affects all of them.",
            "Lists cannot be class attributes.",
          ],
          answer: 1,
          why: "Mutable class attributes are shared state. Create per-instance collections in `__init__`.",
        },
        {
          q: "What does `__balance` (double underscore) actually do?",
          options: [
            "Makes it private and inaccessible.",
            "Mangles the name to `_ClassName__balance` so subclasses cannot accidentally collide with it.",
            "Nothing at all.",
          ],
          answer: 1,
          why:
            "Python has no private attributes. Mangling prevents accidental overrides in subclasses; it does not stop `obj._ClassName__balance`.",
        },
      ],
      exercise: {
        title: "An account that cannot hold an invalid balance",
        brief: `Write a class \`Account\` enforcing this invariant: **the balance is always a non-negative \`int\` number of cents, and never exceeds \`MAX_BALANCE\` (10 000 000).**

- \`Account(owner_id, balance_cents=0)\`:
  - \`owner_id\` must be a positive \`int\` (reject \`bool\`) → \`ValueError\`;
  - \`balance_cents\` must be an \`int\` (reject \`bool\`) → \`TypeError\`; negative or above \`MAX_BALANCE\` → \`ValueError\`.
- \`balance\` is a read-only **property** returning the cents. Assigning to it must raise \`AttributeError\`.
- \`deposit(amount_cents)\` and \`withdraw(amount_cents)\`: the amount must be a positive \`int\` (reject \`bool\` and non-int) → \`ValueError\`/\`TypeError\`. Withdrawing more than the balance raises \`ValueError("insufficient funds")\`. Exceeding \`MAX_BALANCE\` on deposit raises \`ValueError\`. Both return the new balance.
- \`history\` is a per-instance list of \`("deposit"|"withdraw", amount)\` tuples; \`Account.history\` must **not** be shared between instances.
- A failed operation must leave the balance and the history unchanged.`,
        rubric: [
          "Invalid construction raises; the object never exists in a bad state",
          "`balance` is read-only",
          "Deposits and withdrawals validate their argument and maintain the invariant",
          "A failed operation changes nothing",
          "Two accounts have independent histories",
          "`bool` is rejected wherever an int is required",
        ],
        starter: `class Account:
    """An account whose balance is always an int in 0..MAX_BALANCE cents."""

    MAX_BALANCE = 10_000_000

    def __init__(self, owner_id, balance_cents=0):
        pass

    @property
    def balance(self):
        pass

    def deposit(self, amount_cents):
        pass

    def withdraw(self, amount_cents):
        pass


a = Account(7, 1000)
print(a.deposit(250), a.balance)
`,
        stdin: [],
        tests: [
          {
            name: "construction validates",
            code: `a = Account(7, 1000)
assert a.balance == 1000
assert Account(1).balance == 0
for bad in (0, -1, "7", 7.0, None, True):
    with raises(ValueError if not isinstance(bad, (str, float, type(None))) else Exception):
        Account(bad)`,
          },
          {
            name: "balance bounds are enforced at construction",
            code: `with raises(ValueError):
    Account(1, -1)
with raises(ValueError):
    Account(1, 10_000_001)
assert Account(1, 10_000_000).balance == 10_000_000
for bad in (10.0, "100", None, True):
    with raises(TypeError):
        Account(1, bad)`,
          },
          {
            name: "balance is read-only",
            code: `a = Account(1, 500)
try:
    a.balance = 999_999
    raise AssertionError("balance should not be assignable")
except AttributeError:
    pass
assert a.balance == 500`,
          },
          {
            name: "deposit and withdraw maintain the invariant",
            code: `a = Account(1, 1000)
assert a.deposit(500) == 1500
assert a.withdraw(200) == 1300
assert a.balance == 1300`,
          },
          {
            name: "overdrawing is refused and changes nothing",
            code: `a = Account(1, 1000)
try:
    a.withdraw(1001)
    raise AssertionError("expected ValueError")
except ValueError as e:
    assert "insufficient" in str(e), f"got {str(e)!r}"
assert a.balance == 1000, "a failed withdrawal changed the balance"
assert a.history == [], f"a failed withdrawal was recorded: {a.history!r}"`,
          },
          {
            name: "amounts are validated",
            code: `a = Account(1, 1000)
for bad in (0, -5):
    with raises(ValueError):
        a.deposit(bad)
for bad in (1.5, "10", None, True):
    with raises(TypeError):
        a.deposit(bad)
assert a.balance == 1000`,
          },
          {
            name: "the ceiling holds on deposit",
            code: `a = Account(1, 9_999_900)
with raises(ValueError):
    a.deposit(200)
assert a.balance == 9_999_900
assert a.deposit(100) == 10_000_000`,
          },
          {
            name: "history is per instance",
            code: `a, b = Account(1), Account(2)
a.deposit(100)
a.withdraw(50)
assert a.history == [("deposit", 100), ("withdraw", 50)], f"got {a.history!r}"
assert b.history == [], f"history is shared between instances: {b.history!r}"`,
          },
        ],
        requirements: [
          { kind: "defines", value: "Account" },
          { kind: "regex", value: "@property", message: "Expose `balance` as a read-only property." },
        ],
        hints: [
          "Store the real value in `self._balance_cents` and expose it through `@property def balance(self)`. Defining a getter with no setter is what makes assignment raise `AttributeError`.",
          "Write one private helper, `_check_amount(value)`, that raises `TypeError` for non-ints (including `bool`) and `ValueError` for anything not positive. Both public methods call it first.",
          "Validate *before* mutating. Compute the new balance, check it, then assign — that is what makes a failed operation leave no trace.",
          "Append to `self.history` only after the assignment succeeds, and create `self.history = []` in `__init__`, never at class level.",
        ],
        solution: `class Account:
    """An account whose balance is always an int in 0..MAX_BALANCE cents."""

    MAX_BALANCE = 10_000_000

    def __init__(self, owner_id, balance_cents=0):
        if isinstance(owner_id, bool) or not isinstance(owner_id, int):
            raise ValueError("owner_id must be a positive int")
        if owner_id <= 0:
            raise ValueError("owner_id must be a positive int")

        if isinstance(balance_cents, bool) or not isinstance(balance_cents, int):
            raise TypeError("balance must be an int number of cents")
        if not 0 <= balance_cents <= self.MAX_BALANCE:
            raise ValueError(f"balance must be between 0 and {self.MAX_BALANCE}")

        self.owner_id = owner_id
        self._balance_cents = balance_cents
        self.history = []

    @property
    def balance(self):
        """Read-only: the invariant is maintained by deposit and withdraw only."""
        return self._balance_cents

    @staticmethod
    def _check_amount(amount_cents):
        if isinstance(amount_cents, bool) or not isinstance(amount_cents, int):
            raise TypeError("amount must be an int number of cents")
        if amount_cents <= 0:
            raise ValueError("amount must be positive")

    def deposit(self, amount_cents):
        self._check_amount(amount_cents)
        new_balance = self._balance_cents + amount_cents
        if new_balance > self.MAX_BALANCE:
            raise ValueError(f"balance would exceed {self.MAX_BALANCE}")

        self._balance_cents = new_balance
        self.history.append(("deposit", amount_cents))
        return self._balance_cents

    def withdraw(self, amount_cents):
        self._check_amount(amount_cents)
        if amount_cents > self._balance_cents:
            raise ValueError("insufficient funds")

        self._balance_cents -= amount_cents
        self.history.append(("withdraw", amount_cents))
        return self._balance_cents


a = Account(7, 1000)
print(a.deposit(250), a.balance)`,
        why: `Both mutating methods follow the same three-step shape: **validate the argument, compute the candidate state, commit only if it is legal.** That ordering is what makes a failed operation a true no-op — balance unchanged, history unchanged, no partial effect to unwind.

The read-only property is doing real work. With a plain \`self.balance\` attribute, any line anywhere in the codebase could write \`account.balance = 0\` and the invariant would be gone with no error, no log entry and no stack trace. A getter without a setter turns that line into an \`AttributeError\` at the moment it is written.

\`history\` is created in \`__init__\`, so each account owns its own list. At class level it would be one list shared by every instance in the process — which in a server means one customer's transactions appearing in another's statement.

\`_check_amount\` is a \`staticmethod\` because it does not touch instance state. That is a small signal to the reader: this is a pure validation rule, and it can be tested without constructing an account.`,
      },
      wrapup: `- Enforce the invariant in \`__init__\`; then methods can trust the object.
- Validate, compute, commit — in that order — so failures leave no trace.
- Mutable class attributes are shared by every instance. Create them in \`__init__\`.
- A property with no setter is the cheapest way to stop a one-line invariant violation.`,
      refs: [
        { label: "Python tutorial — classes", url: "https://docs.python.org/3/tutorial/classes.html" },
        { label: "CWE-665: Improper Initialization", url: "https://cwe.mitre.org/data/definitions/665.html" },
      ],
    },

    /* ----------------------------------------------------------------- 32 */
    {
      id: "m07l02",
      day: 32,
      title: "Properties, encapsulation, and attributes that refuse to be set",
      minutes: 60,
      secure: "controlled mutation",
      cwe: ["CWE-915", "CWE-668"],
      tags: ["property", "setter", "slots", "encapsulation", "validation"],
      lede:
        "A property lets you keep attribute syntax while running code on access. That is how you validate on write, compute on read, and make a field that can be set exactly once.",
      blocks: [
        {
          t: "code",
          label: "example",
          code: `class Document:
    def __init__(self, title):
        self._title = ""
        self.title = title            # goes through the setter, so it validates

    @property
    def title(self):
        return self._title

    @title.setter
    def title(self, value):
        if not isinstance(value, str) or not value.strip():
            raise ValueError("title must be a non-empty string")
        self._title = value.strip()[:200]

    @property
    def slug(self):
        """Computed on read; there is nothing to keep in sync."""
        return self._title.lower().replace(" ", "-")`,
          cap: "Assigning in `__init__` through the setter means construction and later mutation share one validation path.",
        },
        {
          t: "box",
          kind: "rule",
          title: "Derived values should be computed, not stored",
          md: `Every stored copy of a derived value is a chance for it to go stale. If \`is_admin\` is stored alongside \`role\`, the day someone changes \`role\` without updating \`is_admin\` is the day authorisation breaks.

A read-only property that computes from the source of truth cannot disagree with it.`,
        },
        { t: "h", text: "Write-once fields" },
        {
          t: "code",
          label: "fixed",
          code: `class Session:
    def __init__(self, user_id):
        self._user_id = user_id
        self._token = None

    @property
    def token(self):
        return self._token

    @token.setter
    def token(self, value):
        if self._token is not None:
            raise AttributeError("token is already set and cannot be replaced")
        if not isinstance(value, str) or len(value) < 32:
            raise ValueError("token must be at least 32 characters")
        self._token = value`,
          cap: "Session fixation is the attack this prevents: an attacker plants a known session token, waits for the victim to authenticate, and reuses it. A token that cannot be reassigned removes the primitive.",
        },
        {
          t: "box",
          kind: "good",
          title: "`__slots__`: no attributes you did not declare",
          md: `\`\`\`
class Point:
    __slots__ = ("x", "y")
\`\`\`

With \`__slots__\`, instances have no \`__dict__\` and assigning an undeclared attribute raises \`AttributeError\`. Besides saving memory, it closes a quiet failure mode: \`user.is_admn = True\` silently creating a typo'd attribute that a later \`getattr(user, "is_admin", False)\` never sees — or worse, a real one that something does.`,
        },
        {
          t: "repl",
          lines: [
            ">>> class P:",
            '...     __slots__ = ("x",)',
            ">>> p = P()",
            ">>> p.x = 1",
            ">>> p.y = 2",
            "AttributeError: 'P' object has no attribute 'y'",
          ],
        },
        {
          t: "box",
          kind: "pitfall",
          title: "`setattr` in a loop is mass assignment again",
          md: `\`\`\`
for key, value in request.json.items():
    setattr(user, key, value)        # the client picks the attribute names
\`\`\`

Properties do not save you here — \`setattr\` goes through them, but any attribute *without* a property is written directly. Combine an explicit field allowlist (Module 4) with \`__slots__\` so unknown names cannot be created at all.`,
        },
      ],
      spot: {
        label: "user model",
        prompt: "Click the line that lets authorisation drift away from the truth.",
        lines: [5],
        why:
          "Line 5. `is_admin` is stored at construction, so it keeps saying `True` after `role` changes on line 9. Make it a computed property — `return self._role == \"admin\"` — and the two can never disagree.",
        code: `class User:
    def __init__(self, user_id, role):
        self.user_id = user_id
        self._role = role
        self.is_admin = (role == "admin")

    def demote(self):
        self._role = "member"
        return self._role`,
      },
      quiz: [
        {
          q: "Why compute `is_admin` from `role` instead of storing it?",
          options: [
            "It uses less memory.",
            "A stored copy can drift out of sync with the source of truth; a computed one cannot.",
            "Properties are faster.",
          ],
          answer: 1,
          why: "Two representations of one fact will eventually disagree, and the authorisation check is where that disagreement surfaces.",
        },
        {
          q: "What does `__slots__` prevent?",
          options: [
            "Subclassing.",
            "Creating attributes that were not declared, including typos.",
            "Reading attributes.",
          ],
          answer: 1,
          why: "No `__dict__` means no ad-hoc attributes. Typos raise instead of silently creating a new field.",
        },
        {
          q: "A setter that raises when the field is already set is useful for:",
          options: [
            "Performance.",
            "Write-once values such as session tokens, where replacement is the attack.",
            "Nothing; it just annoys callers.",
          ],
          answer: 1,
          why: "Session fixation depends on being able to set a token that is later blessed by authentication. Write-once removes that.",
        },
      ],
      exercise: {
        title: "A session object that resists fixation",
        brief: `Write class \`Session\` with these rules:

- \`Session(user_id, role)\` — \`user_id\` a positive \`int\` (reject \`bool\`), \`role\` one of \`"member"\`, \`"editor"\`, \`"admin"\` compared exactly. Invalid → \`ValueError\`.
- \`__slots__\` declares exactly: \`"_user_id"\`, \`"_role"\`, \`"_token"\`. Setting any other attribute must raise \`AttributeError\`.
- \`user_id\` — read-only property.
- \`role\` — property with a setter that validates against the allowlist. Assigning an invalid role raises \`ValueError\` and leaves the old role in place.
- \`is_admin\` — read-only property **computed** from \`role\`. It must follow role changes.
- \`token\` — property; the setter accepts a \`str\` of at least 32 characters **once**. A second assignment raises \`AttributeError("token is already set")\`; an invalid first value raises \`ValueError\` and leaves the token unset.
- \`rotate(new_token)\` — the *legitimate* way to replace a token after a privilege change: it clears the old one and sets the new, validating the same way. (This is how real systems avoid fixation: the token changes at the authentication boundary, under the server's control, not the client's.)`,
        rubric: [
          "Undeclared attributes raise `AttributeError` (`__slots__` in effect)",
          "`user_id` cannot be assigned",
          "`is_admin` tracks `role` after a change",
          "An invalid role assignment leaves the previous role intact",
          "`token` can be set once; the second assignment raises",
          "`rotate` replaces the token and validates it",
        ],
        starter: `class Session:
    """A session whose token can be set once and rotated only deliberately."""

    ROLES = ("member", "editor", "admin")
    MIN_TOKEN = 32
    __slots__ = ("_user_id", "_role", "_token")

    def __init__(self, user_id, role):
        pass


s = Session(7, "member")
s.token = "t" * 40
print(s.user_id, s.role, s.is_admin, s.token[:4])
`,
        stdin: [],
        tests: [
          {
            name: "construction validates",
            code: `s = Session(7, "member")
assert s.user_id == 7 and s.role == "member"
for bad_id in (0, -1, "7", 7.0, None, True):
    with raises(ValueError):
        Session(bad_id, "member")
for bad_role in ("admin ", "ADMIN", "owner", "", None, 1):
    with raises(ValueError):
        Session(7, bad_role)`,
          },
          {
            name: "__slots__ blocks undeclared attributes",
            code: `s = Session(7, "member")
for name in ("is_admn", "permissions", "_secret"):
    try:
        setattr(s, name, True)
        raise AssertionError(f"setting {name!r} should have failed")
    except AttributeError:
        pass`,
          },
          {
            name: "user_id is read-only",
            code: `s = Session(7, "member")
with raises(AttributeError):
    s.user_id = 9
assert s.user_id == 7`,
          },
          {
            name: "is_admin is computed, not stored",
            code: `s = Session(7, "member")
assert s.is_admin is False
s.role = "admin"
assert s.is_admin is True, "is_admin must follow role"
s.role = "editor"
assert s.is_admin is False, "is_admin must follow role back down"
with raises(AttributeError):
    s.is_admin = True`,
          },
          {
            name: "an invalid role change is rejected and changes nothing",
            code: `s = Session(7, "editor")
for bad in ("root", "Admin", "", None):
    with raises(ValueError):
        s.role = bad
assert s.role == "editor", f"role was changed by a rejected assignment: {s.role!r}"`,
          },
          {
            name: "token is write-once",
            code: `s = Session(7, "member")
assert s.token is None
s.token = "a" * 32
assert s.token == "a" * 32
try:
    s.token = "b" * 32
    raise AssertionError("a second assignment should fail")
except AttributeError as e:
    assert "already set" in str(e), f"got {str(e)!r}"
assert s.token == "a" * 32`,
          },
          {
            name: "an invalid token leaves the field unset",
            code: `s = Session(7, "member")
for bad in ("short", "", None, 12345, "x" * 31):
    with raises(ValueError):
        s.token = bad
assert s.token is None, f"a rejected token was stored: {s.token!r}"
s.token = "c" * 32
assert s.token == "c" * 32`,
          },
          {
            name: "rotate replaces deliberately and still validates",
            code: `s = Session(7, "member")
s.token = "a" * 32
assert s.rotate("d" * 40) == "d" * 40
assert s.token == "d" * 40
with raises(ValueError):
    s.rotate("tooshort")
assert s.token == "d" * 40, "a rejected rotation changed the token"`,
          },
        ],
        requirements: [
          { kind: "defines", value: "Session" },
          { kind: "regex", value: "__slots__", message: "Declare `__slots__`." },
          { kind: "regex", value: "@property", message: "Use properties for the controlled attributes." },
        ],
        hints: [
          "With `__slots__`, `__init__` must assign only the declared names. Set `self._token = None` before anything can read it.",
          "Validate the role through the setter in `__init__` too — `self.role = role` runs the setter, so there is one validation path rather than two.",
          "The write-once check is `if self._token is not None: raise AttributeError(...)`. Put it *before* the value validation so a second assignment of a bad token still reports the right problem.",
          "`rotate` should set `self._token = None` first and then reuse the setter — but validate before clearing, or a rejected rotation would wipe a good token.",
        ],
        solution: `class Session:
    """A session whose token can be set once and rotated only deliberately."""

    ROLES = ("member", "editor", "admin")
    MIN_TOKEN = 32
    __slots__ = ("_user_id", "_role", "_token")

    def __init__(self, user_id, role):
        if isinstance(user_id, bool) or not isinstance(user_id, int) or user_id <= 0:
            raise ValueError("user_id must be a positive int")

        self._user_id = user_id
        self._token = None
        self._role = None
        self.role = role                      # one validation path, via the setter

    # -- identity ---------------------------------------------------------
    @property
    def user_id(self):
        return self._user_id

    # -- role -------------------------------------------------------------
    @property
    def role(self):
        return self._role

    @role.setter
    def role(self, value):
        if value not in self.ROLES:
            raise ValueError(f"role must be one of {', '.join(self.ROLES)}")
        self._role = value

    @property
    def is_admin(self):
        """Computed, so it can never disagree with role."""
        return self._role == "admin"

    # -- token ------------------------------------------------------------
    @staticmethod
    def _check_token(value):
        if not isinstance(value, str) or len(value) < Session.MIN_TOKEN:
            raise ValueError(f"token must be a string of at least {Session.MIN_TOKEN} characters")

    @property
    def token(self):
        return self._token

    @token.setter
    def token(self, value):
        if self._token is not None:
            raise AttributeError("token is already set")
        self._check_token(value)
        self._token = value

    def rotate(self, new_token):
        """Replace the token at a privilege boundary, under our control."""
        self._check_token(new_token)          # validate BEFORE discarding the old one
        self._token = new_token
        return self._token


s = Session(7, "member")
s.token = "t" * 40
print(s.user_id, s.role, s.is_admin, s.token[:4])`,
        why: `Three different access policies, each expressed in the type rather than in the callers:

- **\`user_id\` is immutable** — a getter with no setter. The identity of a session is not something any code path should be able to edit.
- **\`role\` is mutable but validated** — and because \`__init__\` assigns through the setter, construction and later mutation cannot diverge. Note that the allowlist comparison is exact: no \`.strip()\`, no \`.lower()\`. Normalising a role string before comparing it is how \`"Admin "\` becomes a privilege grant.
- **\`token\` is write-once, with one deliberate escape hatch.** Client-driven replacement is session fixation; server-driven replacement at an authentication boundary is the *defence* against it. Making the two different operations — assignment versus \`rotate()\` — means the safe one is easy and the dangerous one does not exist.

\`_check_token\` running before \`self._token = None\` inside \`rotate\` is the detail worth copying. The obvious implementation clears the old token first and then validates, so a rejected rotation logs the user out. Validate, then commit — the same ordering as the previous lesson.

\`__slots__\` closes the last gap: with properties alone, \`session.is_admn = True\` would silently create an attribute. Here it raises.`,
      },
      wrapup: `- Assign through the setter in \`__init__\` so there is one validation path.
- Compute derived facts; a stored copy will eventually disagree with its source.
- Write-once fields remove the fixation primitive; provide an explicit rotate for the legitimate case.
- \`__slots__\` makes a typo an error instead of a new attribute.`,
      refs: [
        { label: "property", url: "https://docs.python.org/3/library/functions.html#property" },
        { label: "OWASP Session Management Cheat Sheet", url: "https://cheatsheetseries.owasp.org/cheatsheets/Session_Management_Cheat_Sheet.html" },
      ],
    },

    /* ----------------------------------------------------------------- 33 */
    {
      id: "m07l03",
      day: 33,
      title: "dataclasses, immutability, and the repr that leaks",
      minutes: 60,
      secure: "redacted representations",
      cwe: ["CWE-532", "CWE-209"],
      tags: ["dataclass", "frozen", "repr", "immutable", "redaction"],
      lede:
        "Python's default `__repr__` prints every attribute. Put an object in a log line, a traceback or an error-tracker breadcrumb, and every field goes with it.",
      blocks: [
        {
          t: "code",
          label: "example",
          code: `from dataclasses import dataclass, field

@dataclass(frozen=True, slots=True)
class Endpoint:
    host: str
    port: int = 443
    tags: tuple = ()

e = Endpoint("api.example.com", 8443)
e.port            # 8443
e.port = 80       # FrozenInstanceError`,
          cap: "`frozen=True` blocks attribute assignment and gives you `__hash__`. `slots=True` (3.10+) removes `__dict__`. The decorator writes `__init__`, `__repr__` and `__eq__` for you.",
        },
        {
          t: "box",
          kind: "warn",
          title: "`frozen` is shallow",
          md: `\`\`\`
@dataclass(frozen=True)
class Config:
    hosts: list = field(default_factory=list)

c = Config()
c.hosts.append("evil.example")     # allowed -- the LIST is still mutable
\`\`\`

Freezing prevents rebinding the attribute, not mutating what it points at. Use tuples and frozensets inside frozen dataclasses, and never \`field(default=[])\` — a mutable default raises at class-creation time, which is why \`default_factory\` exists.`,
        },
        { t: "h", text: "The repr leak" },
        {
          t: "code",
          label: "vulnerable",
          code: `from dataclasses import dataclass

@dataclass
class DbConfig:
    host: str
    user: str
    password: str

cfg = DbConfig("db.internal", "app", "s3cr3t-prod-pw")
print(cfg)
# DbConfig(host='db.internal', user='app', password='s3cr3t-prod-pw')`,
          cap: "That line appears in a log on the first connection failure. `logging.exception` prints locals in many setups; error trackers capture frame locals by default.",
        },
        {
          t: "code",
          label: "fixed",
          code: `from dataclasses import dataclass, field

@dataclass(frozen=True)
class DbConfig:
    host: str
    user: str
    password: str = field(repr=False)        # excluded from __repr__

    def __str__(self):
        return f"DbConfig(host={self.host!r}, user={self.user!r}, password=***)"

cfg = DbConfig("db.internal", "app", "s3cr3t-prod-pw")
print(cfg)       # DbConfig(host='db.internal', user='app', password=***)
print(repr(cfg)) # DbConfig(host='db.internal', user='app')`,
          cap: "`field(repr=False)` drops it from the generated repr. Writing `__str__` as well covers `print()`, f-strings and `\"%s\"` formatting, which do not use `__repr__`.",
        },
        {
          t: "box",
          kind: "rule",
          title: "Both `__repr__` and `__str__`",
          md: `- \`repr(obj)\` — used by the debugger, the console, \`%r\`, and collection displays (\`[obj]\` calls \`repr\` on its members).
- \`str(obj)\` — used by \`print\`, f-strings, \`%s\`, and most logging formatters.

A secret-bearing object must redact in **both**. Overriding only one leaves the other as the leak, and the one you forgot is usually the one the logger calls.`,
        },
        {
          t: "table",
          head: ["Option", "Effect"],
          rows: [
            ["`@dataclass(frozen=True)`", "No attribute assignment; adds `__hash__`."],
            ["`@dataclass(slots=True)`", "No `__dict__`; undeclared attributes raise."],
            ["`@dataclass(kw_only=True)`", "All fields keyword-only at construction."],
            ["`field(repr=False)`", "Excluded from the generated `__repr__`."],
            ["`field(compare=False)`", "Excluded from `__eq__`/ordering."],
            ["`field(default_factory=list)`", "A fresh mutable default per instance."],
            ["`__post_init__`", "Where validation goes."],
          ],
        },
        {
          t: "code",
          label: "fixed",
          code: `@dataclass(frozen=True, slots=True)
class Port:
    number: int

    def __post_init__(self):
        if isinstance(self.number, bool) or not isinstance(self.number, int):
            raise TypeError("port must be an int")
        if not 1 <= self.number <= 65535:
            raise ValueError("port out of range")`,
          cap: "`__post_init__` runs after the generated `__init__`. In a frozen dataclass you cannot assign there — use `object.__setattr__(self, \"field\", value)` if you must normalise.",
        },
      ],
      spot: {
        label: "connection error path",
        prompt: "Click the line that writes a production password to the log.",
        lines: [11],
        why:
          "Line 11. The f-string calls `__str__` on the dataclass, which defaults to `__repr__`, which prints every field including `password`. Exclude it with `field(repr=False)` and define `__str__`. Line 10's generic message is fine.",
        code: `from dataclasses import dataclass
import logging

@dataclass
class DbConfig:
    host: str
    password: str

def connect(cfg):
    try:
        return driver.connect(cfg.host, cfg.password)
    except OSError:
        logging.error(f"connection failed for {cfg}")
        raise`,
      },
      quiz: [
        {
          q: "`@dataclass(frozen=True)` with a `list` field — can the list be modified?",
          options: [
            "No, frozen blocks it.",
            "Yes — freezing stops rebinding the attribute, not mutating the object it refers to.",
            "Only through `object.__setattr__`.",
          ],
          answer: 1,
          why: "Shallow immutability. Use `tuple`/`frozenset` inside frozen dataclasses if you want the contents fixed too.",
        },
        {
          q: "You override `__repr__` to redact a secret. Is the object safe to log?",
          options: [
            "Yes.",
            "No — `print`, f-strings and `%s` use `__str__`, which must also be redacted.",
            "No — logging never calls either.",
          ],
          answer: 1,
          why:
            "Without `__str__`, Python falls back to `__repr__` *only if you did not define `__str__`* — so overriding `__repr__` does help, but the reverse (overriding only `__str__`) leaves `%r` and collection displays leaking. Define both deliberately.",
        },
        {
          q: "Where does validation go in a dataclass?",
          options: ["`__init__`", "`__post_init__`", "A separate function callers must remember"],
          answer: 1,
          why: "The decorator generates `__init__`; `__post_init__` runs immediately after it and is the designed hook.",
        },
      ],
      exercise: {
        title: "A config object that cannot leak",
        brief: `Build \`@dataclass\` class \`DbConfig\` with fields \`host: str\`, \`port: int\`, \`user: str\`, \`password: str\`.

Requirements:

1. Frozen — attribute assignment raises.
2. Validated in \`__post_init__\`: \`host\` a non-empty \`str\` ≤ 253 characters; \`port\` an \`int\` in 1–65535 (reject \`bool\`); \`user\` a non-empty \`str\`; \`password\` a \`str\` of at least 8 characters. Failures raise \`ValueError\` (use \`TypeError\` for the wrong type on \`port\`).
3. \`password\` must not appear in \`repr()\` **or** \`str()\`. Both must show \`host\`, \`port\` and \`user\`.
4. \`password\` must not participate in equality: two configs differing only by password compare **equal** (this is deliberate — equality here means "same endpoint and account").
5. A method \`dsn()\` returning \`"postgresql://<user>@<host>:<port>/app"\` — note the password is **not** in it.
6. A method \`connect_args()\` returning the dict \`{"host":..., "port":..., "user":..., "password":...}\` — the one place the secret is deliberately exposed, for passing to a driver.`,
        rubric: [
          "Frozen: assignment raises",
          "Validation rejects bad host/port/user/password",
          "Neither `repr()` nor `str()` contains the password",
          "Equality ignores the password",
          "`dsn()` excludes the password; `connect_args()` includes it",
        ],
        starter: `from dataclasses import dataclass, field


@dataclass(frozen=True)
class DbConfig:
    host: str
    port: int
    user: str
    password: str

    def __post_init__(self):
        pass


cfg = DbConfig("db.internal", 5432, "app", "s3cr3t-prod-pw")
print(cfg)
print(cfg.dsn())
`,
        stdin: [],
        tests: [
          {
            name: "constructs and is frozen",
            code: `cfg = DbConfig("db.internal", 5432, "app", "hunter2-long")
assert cfg.host == "db.internal" and cfg.port == 5432
try:
    cfg.port = 1
    raise AssertionError("frozen dataclass should refuse assignment")
except Exception as e:
    assert "rozen" in type(e).__name__ or isinstance(e, AttributeError), f"got {type(e).__name__}"`,
          },
          {
            name: "validation rejects bad values",
            code: `for bad in ("", "x" * 254, None, 5):
    with raises(ValueError):
        DbConfig(bad, 5432, "app", "hunter2-long")
for bad in (0, 65536, -1):
    with raises(ValueError):
        DbConfig("h", bad, "app", "hunter2-long")
for bad in ("5432", 5432.0, None, True):
    with raises(TypeError):
        DbConfig("h", bad, "app", "hunter2-long")
for bad in ("", None, 5):
    with raises(ValueError):
        DbConfig("h", 5432, bad, "hunter2-long")
for bad in ("short", "", None, 1234567):
    with raises(ValueError):
        DbConfig("h", 5432, "app", bad)`,
          },
          {
            name: "repr and str both redact",
            code: `secret = "s3cr3t-prod-pw"
cfg = DbConfig("db.internal", 5432, "app", secret)
for rendered in (repr(cfg), str(cfg), f"{cfg}", "%s" % cfg, "{}".format(cfg)):
    assert secret not in rendered, f"password leaked via {rendered!r}"
for rendered in (repr(cfg), str(cfg)):
    assert "db.internal" in rendered and "app" in rendered, f"too little detail: {rendered!r}"`,
          },
          {
            name: "collections do not leak either",
            code: `secret = "s3cr3t-prod-pw"
cfg = DbConfig("db.internal", 5432, "app", secret)
assert secret not in str([cfg]), "a list display leaked the password"
assert secret not in str({"cfg": cfg}), "a dict display leaked the password"`,
          },
          {
            name: "equality ignores the password",
            code: `a = DbConfig("h", 5432, "app", "password-one")
b = DbConfig("h", 5432, "app", "password-two")
c = DbConfig("h", 5433, "app", "password-one")
assert a == b, "configs for the same endpoint/account should compare equal"
assert a != c`,
          },
          {
            name: "dsn excludes the secret, connect_args includes it",
            code: `secret = "s3cr3t-prod-pw"
cfg = DbConfig("db.internal", 5432, "app", secret)
dsn = cfg.dsn()
assert dsn == "postgresql://app@db.internal:5432/app", f"got {dsn!r}"
assert secret not in dsn
args = cfg.connect_args()
assert args == {"host": "db.internal", "port": 5432, "user": "app", "password": secret}, f"got {args!r}"`,
          },
        ],
        requirements: [
          { kind: "defines", value: "DbConfig" },
          { kind: "uses_module", value: "dataclasses" },
          { kind: "regex", value: "repr\\s*=\\s*False", message: "Exclude the password from the generated repr with `field(repr=False)`." },
        ],
        hints: [
          "`password: str = field(repr=False, compare=False)` handles requirements 3 (half) and 4 in one line.",
          "Define `__str__` yourself — the generated `__repr__` is only used by `str()` when no `__str__` exists, and you want an explicit redaction either way.",
          "In a frozen dataclass you cannot assign in `__post_init__`; you can only read and raise. That is all this exercise needs.",
          "Check `isinstance(port, bool)` before `isinstance(port, int)`, and raise `TypeError` for type problems but `ValueError` for range problems — the tests distinguish them.",
        ],
        solution: `from dataclasses import dataclass, field

MAX_HOST = 253
MIN_PASSWORD = 8


@dataclass(frozen=True)
class DbConfig:
    host: str
    port: int
    user: str
    password: str = field(repr=False, compare=False)

    def __post_init__(self):
        if not isinstance(self.host, str) or not self.host or len(self.host) > MAX_HOST:
            raise ValueError(f"host must be a non-empty string of at most {MAX_HOST} characters")

        if isinstance(self.port, bool) or not isinstance(self.port, int):
            raise TypeError("port must be an int")
        if not 1 <= self.port <= 65535:
            raise ValueError("port must be between 1 and 65535")

        if not isinstance(self.user, str) or not self.user:
            raise ValueError("user must be a non-empty string")

        if not isinstance(self.password, str) or len(self.password) < MIN_PASSWORD:
            raise ValueError(f"password must be at least {MIN_PASSWORD} characters")

    def __str__(self):
        return f"DbConfig(host={self.host!r}, port={self.port}, user={self.user!r}, password=***)"

    def dsn(self):
        """A connection string safe to log: no credential in it."""
        return f"postgresql://{self.user}@{self.host}:{self.port}/app"

    def connect_args(self):
        """The one place the secret is handed out, deliberately and visibly."""
        return {
            "host": self.host,
            "port": self.port,
            "user": self.user,
            "password": self.password,
        }


cfg = DbConfig("db.internal", 5432, "app", "s3cr3t-prod-pw")
print(cfg)
print(cfg.dsn())`,
        why: `The password is present in the object and absent from every path that produces text. \`field(repr=False)\` removes it from the generated \`__repr__\` — which is what a debugger, a console session and a list display all call — and the explicit \`__str__\` covers \`print\`, f-strings and \`%s\`. Covering only one leaves the other as the leak, and which one your logging stack uses is not something you control.

\`compare=False\` encodes a design decision worth being explicit about: two configs pointing at the same endpoint with the same account *are* the same config, and rotating the password does not make it a different one. The security side-effect is that comparing configs never compares secrets, so there is no timing channel and no accidental \`assert a == b\` printing both on failure.

The two accessor methods make the trust boundary visible in the API surface. \`dsn()\` is the thing you log, put in a metric label or show in a health endpoint. \`connect_args()\` is the thing you pass to a driver and nowhere else. A reviewer grepping for \`connect_args\` sees every place the credential is handed out — which is the property you want, and which a plain attribute access could never give you.

Validation lives in \`__post_init__\` because the decorator owns \`__init__\`. In a frozen dataclass that hook can read and raise but not assign, which is a constraint rather than a problem: validation that needs to *change* the value is normalisation, and normalisation belongs in a classmethod constructor such as \`DbConfig.from_url(...)\`.`,
      },
      wrapup: `- \`@dataclass(frozen=True, slots=True)\` gives immutability, no stray attributes, and a free \`__hash__\`.
- Freezing is shallow — put tuples and frozensets inside.
- Redact in both \`__repr__\` and \`__str__\`; the logger will use the one you forgot.
- Make the secret-exposing method explicit and greppable.`,
      refs: [
        { label: "dataclasses", url: "https://docs.python.org/3/library/dataclasses.html" },
        { label: "CWE-532: Insertion of Sensitive Information into Log File", url: "https://cwe.mitre.org/data/definitions/532.html" },
      ],
    },

    /* ----------------------------------------------------------------- 34 */
    {
      id: "m07l04",
      day: 34,
      title: "Inheritance, composition, and subclasses that break the rules",
      minutes: 60,
      secure: "substitutability of security controls",
      cwe: ["CWE-1023"],
      tags: ["inheritance", "composition", "lsp", "super", "abc"],
      lede:
        "A subclass that relaxes its parent's guarantees is a security bug with good manners: every caller still believes the parent's contract.",
      blocks: [
        {
          t: "code",
          label: "example",
          code: `class Validator:
    def validate(self, value):
        raise NotImplementedError

class LengthValidator(Validator):
    def __init__(self, maximum):
        self.maximum = maximum

    def validate(self, value):
        if len(value) > self.maximum:
            raise ValueError(f"longer than {self.maximum}")
        return value`,
        },
        {
          t: "p",
          md: `The {{Liskov substitution principle}} says a subclass must be usable anywhere its parent is, without the caller noticing. For ordinary code that is a design guideline. For a security control it is the whole contract — the caller holds a \`Validator\` and believes validation happened.`,
        },
        {
          t: "code",
          label: "vulnerable",
          code: `class PathValidator:
    """Guarantees: returns a path inside BASE, or raises."""
    def validate(self, name):
        path = (BASE / name).resolve()
        if not path.is_relative_to(BASE):
            raise ValueError("escapes base")
        return path

class FastPathValidator(PathValidator):
    """Someone's optimisation, six months later."""
    def validate(self, name):
        if name in self.cache:        # cache hit skips the check entirely
            return self.cache[name]
        return super().validate(name)`,
          cap: "The subclass silently weakens the parent's guarantee. Every caller still has a `PathValidator`-shaped object and still believes the docstring.",
        },
        {
          t: "box",
          kind: "rule",
          title: "A subclass may strengthen, never weaken",
          md: `A subclass may accept *more* inputs and guarantee *more* about its outputs. It must never accept fewer inputs, return less-validated output, or raise exceptions its parent's contract did not allow.

When you find yourself overriding a method to skip work, the honest move is a separate class — not a subclass of the thing whose promise you are breaking.`,
        },
        { t: "h", text: "Composition is usually the right answer" },
        {
          t: "code",
          label: "fixed",
          code: `class CachedValidator:
    """Composes a validator; does not claim to BE one."""

    def __init__(self, inner, max_entries=1000):
        self._inner = inner
        self._cache = {}
        self._max = max_entries

    def validate(self, name):
        if name not in self._cache:
            if len(self._cache) >= self._max:
                self._cache.clear()
            self._cache[name] = self._inner.validate(name)   # still validated
        return self._cache[name]`,
          cap: "The wrapper caches the *result of validation* rather than skipping it, and holding an inner object makes the delegation visible.",
        },
        {
          t: "box",
          kind: "good",
          title: "`abc` makes the contract explicit",
          md: `\`\`\`
from abc import ABC, abstractmethod

class Validator(ABC):
    @abstractmethod
    def validate(self, value):
        """Return the validated value or raise ValueError."""
\`\`\`

An abstract base class cannot be instantiated and a subclass that forgets \`validate\` fails at construction rather than at the first call — which, for a security control, is the difference between a startup error and a production incident.`,
        },
        {
          t: "box",
          kind: "pitfall",
          title: "Forgetting `super().__init__()`",
          md: `\`\`\`
class AuditedSession(Session):
    def __init__(self, user_id, role, actor):
        self.actor = actor          # parent __init__ never ran
\`\`\`

Every invariant the parent established is now absent: \`_token\` does not exist, \`_role\` was never validated. The object looks like a \`Session\` and satisfies \`isinstance\`, but none of its guarantees hold.

Call \`super().__init__(...)\` first, then add.`,
        },
        {
          t: "box",
          kind: "note",
          title: "MRO in one sentence",
          md: `With multiple inheritance, \`super()\` follows the {{method resolution order}} — a linearisation of the class graph, visible as \`Class.__mro__\`. Cooperative multiple inheritance requires every class in the chain to call \`super()\`; one that does not silently truncates the chain, skipping initialisers you assumed had run.`,
        },
      ],
      quiz: [
        {
          q: "A subclass overrides `validate` to return early for cached names. What is the problem?",
          options: [
            "It is slower.",
            "It weakens the parent's guarantee while remaining substitutable, so every caller is misled.",
            "Caching is never acceptable.",
          ],
          answer: 1,
          why:
            "Callers hold the parent type and rely on its contract. Caching the *result of* validation is fine; skipping validation is not.",
        },
        {
          q: "Why use `abc.abstractmethod` for a security interface?",
          options: [
            "For documentation.",
            "A subclass that forgets to implement it cannot be instantiated — the failure moves to startup.",
            "It makes the method faster.",
          ],
          answer: 1,
          why: "Failing at construction beats failing at the first call, which may be months later and in production.",
        },
        {
          q: "A subclass's `__init__` does not call `super().__init__()`. What happens?",
          options: [
            "Python calls it automatically.",
            "The parent's initialisation never runs, so its invariants do not hold.",
            "A TypeError at class definition.",
          ],
          answer: 1,
          why: "Python does not chain initialisers implicitly. The object passes `isinstance` while being internally invalid.",
        },
      ],
      exercise: {
        title: "A validator chain that cannot be weakened",
        brief: `Build a small validation framework.

1. \`Validator(ABC)\` with an abstract method \`validate(self, value)\` documented as *returns the validated value or raises ValueError*. Instantiating \`Validator\` directly must raise \`TypeError\`.
2. \`LengthValidator(Validator)\` — \`LengthValidator(maximum)\`; rejects values longer than \`maximum\` and non-strings.
3. \`CharsetValidator(Validator)\` — \`CharsetValidator(allowed)\` where \`allowed\` is a string of permitted characters; rejects any value containing anything else.
4. \`ChainValidator(Validator)\` — \`ChainValidator(*validators)\`; runs each in order, passing the result of one into the next, and returns the final value. An empty chain returns the value unchanged.
5. \`CachingValidator(Validator)\` — \`CachingValidator(inner, max_entries=100)\`; caches **validated results** by input value. It must call \`inner.validate\` on every cache miss, must never return an unvalidated value, and must clear the cache when it reaches \`max_entries\`. A value that raises must **not** be cached (so repeated bad input keeps raising).

All validators are substitutable: anything accepted by the chain has passed every component.`,
        rubric: [
          "`Validator()` raises `TypeError`; a subclass missing `validate` cannot be instantiated",
          "Length and charset validators reject correctly",
          "The chain applies every validator in order",
          "Caching returns validated values and re-raises for bad input every time",
          "The cache is bounded",
        ],
        starter: `from abc import ABC, abstractmethod


class Validator(ABC):
    @abstractmethod
    def validate(self, value):
        """Return the validated value, or raise ValueError."""


class LengthValidator(Validator):
    pass


class CharsetValidator(Validator):
    pass


class ChainValidator(Validator):
    pass


class CachingValidator(Validator):
    pass


chain = ChainValidator(LengthValidator(10), CharsetValidator("abcdefghijklmnopqrstuvwxyz"))
print(chain.validate("ada"))
`,
        stdin: [],
        tests: [
          {
            name: "the abstract base cannot be instantiated",
            code: `with raises(TypeError):
    Validator()

class Incomplete(Validator):
    pass

with raises(TypeError):
    Incomplete()`,
          },
          {
            name: "length validation",
            code: `v = LengthValidator(5)
assert v.validate("abcde") == "abcde"
for bad in ("abcdef", "x" * 100):
    with raises(ValueError):
        v.validate(bad)
for bad in (None, 123, ["a"]):
    with raises(ValueError):
        v.validate(bad)`,
          },
          {
            name: "charset validation",
            code: `v = CharsetValidator("abc")
assert v.validate("cab") == "cab"
for bad in ("abd", "AB", "a b", "a1"):
    with raises(ValueError):
        v.validate(bad)`,
          },
          {
            name: "the chain applies everything in order",
            code: `chain = ChainValidator(LengthValidator(4), CharsetValidator("abcdef"))
assert chain.validate("face") == "face"
with raises(ValueError):
    chain.validate("faced")       # too long
with raises(ValueError):
    chain.validate("fxce")        # bad charset
assert ChainValidator().validate("anything") == "anything"`,
          },
          {
            name: "the chain is itself a Validator",
            code: `inner = ChainValidator(LengthValidator(4))
outer = ChainValidator(inner, CharsetValidator("abcdef"))
assert outer.validate("face") == "face"
assert isinstance(inner, Validator)`,
          },
          {
            name: "caching never returns an unvalidated value",
            code: `calls = []

class Counting(Validator):
    def validate(self, value):
        calls.append(value)
        if value == "bad":
            raise ValueError("nope")
        return value.upper()

c = CachingValidator(Counting())
assert c.validate("ada") == "ADA"
assert c.validate("ada") == "ADA"
assert calls == ["ada"], f"inner should be called once per distinct value: {calls!r}"`,
          },
          {
            name: "failures are not cached",
            code: `calls = []

class Counting(Validator):
    def validate(self, value):
        calls.append(value)
        if value == "bad":
            raise ValueError("nope")
        return value

c = CachingValidator(Counting())
for _ in range(3):
    with raises(ValueError):
        c.validate("bad")
assert calls == ["bad", "bad", "bad"], f"a rejected value was cached: {calls!r}"`,
          },
          {
            name: "the cache is bounded",
            code: `class Pass(Validator):
    def validate(self, value):
        return value

c = CachingValidator(Pass(), max_entries=10)
for i in range(50):
    c.validate(f"v{i}")
size = len(getattr(c, "_cache", {}))
assert size <= 10, f"cache grew to {size} entries"`,
          },
        ],
        requirements: [
          { kind: "defines", value: "CachingValidator" },
          { kind: "uses_module", value: "abc" },
        ],
        hints: [
          "`CachingValidator.__init__` stores `self._inner` and `self._cache = {}` — composition, not inheritance of the thing it wraps.",
          "On a miss, call `self._inner.validate(value)` and store the result *only after* it returns. If it raises, the exception propagates and nothing is cached — which is exactly the required behaviour, achieved by doing nothing special.",
          "Clear the cache before inserting when `len(self._cache) >= self._max`. Clearing is crude but bounded; a real system would use an LRU.",
          "`ChainValidator` stores `self._validators = validators` (the tuple from `*args`) and folds: `for v in self._validators: value = v.validate(value)`.",
        ],
        solution: `from abc import ABC, abstractmethod


class Validator(ABC):
    @abstractmethod
    def validate(self, value):
        """Return the validated value, or raise ValueError."""


class LengthValidator(Validator):
    def __init__(self, maximum):
        self.maximum = maximum

    def validate(self, value):
        if not isinstance(value, str):
            raise ValueError("value must be a string")
        if len(value) > self.maximum:
            raise ValueError(f"longer than {self.maximum} characters")
        return value


class CharsetValidator(Validator):
    def __init__(self, allowed):
        self.allowed = frozenset(allowed)

    def validate(self, value):
        if not isinstance(value, str):
            raise ValueError("value must be a string")
        if not set(value) <= self.allowed:
            raise ValueError("value contains unsupported characters")
        return value


class ChainValidator(Validator):
    def __init__(self, *validators):
        self._validators = validators

    def validate(self, value):
        for validator in self._validators:
            value = validator.validate(value)
        return value


class CachingValidator(Validator):
    """Caches the RESULT of validation. It never skips validation."""

    def __init__(self, inner, max_entries=100):
        self._inner = inner
        self._cache = {}
        self._max = max_entries

    def validate(self, value):
        try:
            return self._cache[value]
        except (KeyError, TypeError):
            # TypeError: an unhashable value simply cannot be cached.
            pass

        result = self._inner.validate(value)   # raises before anything is stored

        try:
            if len(self._cache) >= self._max:
                self._cache.clear()
            self._cache[value] = result
        except TypeError:
            pass
        return result


chain = ChainValidator(LengthValidator(10), CharsetValidator("abcdefghijklmnopqrstuvwxyz"))
print(chain.validate("ada"))`,
        why: `\`CachingValidator\` **has** a validator rather than **being** a specialised one. That single structural choice is what keeps the guarantee intact: there is no inherited \`validate\` to override and weaken, and the only way to produce a result is to call the inner validator.

The cache stores outcomes of successful validation, keyed by input. A hit returns a value that was validated — just not on this call. A miss calls through. There is no third path, and in particular there is no "trusted" input that bypasses the chain.

Failures are not cached, and that falls out of the ordering rather than from special handling: \`self._inner.validate(value)\` is on the line *before* the insertion, so an exception leaves the cache untouched. The alternative — caching the exception — would be a quiet denial of service, where one malformed request poisons that input for every later caller.

The \`TypeError\` guards handle unhashable values (a list, a dict) by declining to cache rather than crashing. Note that the inner validator still runs in that case: when caching is impossible, the fallback is to do the work, never to skip it.

The \`ABC\` turns "forgot to implement \`validate\`" into a \`TypeError\` at construction. For a validator that is the right place to fail — at startup, where a deployment check catches it, rather than on the first request that needs the control.`,
      },
      wrapup: `- A subclass may strengthen a contract, never weaken it.
- Prefer composition when you want to add behaviour around a control, not inside it.
- \`abc.abstractmethod\` moves "forgot to implement" from runtime to construction.
- Always call \`super().__init__()\`, or the parent's invariants never exist.`,
      refs: [
        { label: "abc — abstract base classes", url: "https://docs.python.org/3/library/abc.html" },
        { label: "CWE-1023: Incomplete Comparison with Missing Factors", url: "https://cwe.mitre.org/data/definitions/1023.html" },
      ],
    },

    /* ----------------------------------------------------------------- 35 */
    {
      id: "m07l05",
      day: 35,
      title: "Capstone: a Credential type that refuses to leak",
      minutes: 60,
      secure: "constant-time __eq__, no accidental serialisation",
      cwe: ["CWE-208", "CWE-532"],
      tags: ["capstone", "dunder", "eq", "hash", "hmac", "credential"],
      lede:
        "Everything from this module in one object: validated at construction, immutable, invisible in logs, constant-time to compare, and impossible to serialise by accident.",
      blocks: [
        {
          t: "h",
          text: "`__eq__`, `__hash__`, and the contract between them",
        },
        {
          t: "p",
          md: `If \`a == b\` then \`hash(a)\` **must** equal \`hash(b)\`. Breaking that puts objects into dicts and sets where they can never be found again. Defining \`__eq__\` without \`__hash__\` makes the class unhashable, which is the safe default Python chooses for you.`,
        },
        {
          t: "code",
          label: "vulnerable",
          code: `class ApiKey:
    def __init__(self, value):
        self.value = value

    def __eq__(self, other):
        return self.value == other.value      # byte-by-byte, short-circuits`,
          cap: "`==` on strings returns at the first differing byte. Over a network, the timing difference leaks the key one character at a time.",
        },
        {
          t: "code",
          label: "fixed",
          code: `import hmac

class ApiKey:
    __slots__ = ("_value",)

    def __init__(self, value):
        if not isinstance(value, str) or len(value) < 32:
            raise ValueError("api key must be at least 32 characters")
        self._value = value

    def __eq__(self, other):
        if not isinstance(other, ApiKey):
            return NotImplemented
        return hmac.compare_digest(self._value, other._value)

    def __hash__(self):
        # Hash a constant: equal objects must hash equally, and hashing the
        # secret itself would put a derivative of it in memory structures.
        return hash(ApiKey)

    def __repr__(self):
        return "ApiKey(***)"

    __str__ = __repr__`,
          cap: "`NotImplemented` (not `False`) lets Python try the reflected operation and fall back to identity — returning `False` would claim inequality with types you know nothing about.",
        },
        {
          t: "box",
          kind: "warn",
          title: "The hash trade-off",
          md: `Hashing a constant makes every \`ApiKey\` land in the same bucket, so a set of 10 000 keys degrades to a linear scan. That is acceptable for a type you hold one or two of, and wrong for a type you store in bulk.

The alternative — \`hash(self._value)\` — is fast but places a value derived from the secret into dict internals and makes \`hash()\` a weak oracle. Pick deliberately, and write down which problem you chose to have.`,
        },
        { t: "h", text: "Blocking accidental serialisation" },
        {
          t: "code",
          label: "fixed",
          code: `    def __reduce__(self):
        raise TypeError("Credential objects must not be pickled")

    def __getstate__(self):
        raise TypeError("Credential objects must not be serialised")`,
          cap: "Without these, a credential sitting in a session, a cache or a Celery task argument is silently pickled and written to Redis, where it is readable by anyone with access to the cache.",
        },
        {
          t: "box",
          kind: "cve",
          title: "Where secrets actually end up",
          md: `Credential objects have reached disk through: pickled Celery task arguments, Django session serialisation, \`copy.deepcopy\` into a debug context, \`json.dumps(default=str)\` in a generic API encoder, and error-tracker breadcrumbs capturing frame locals.

Every one of those is a *generic* mechanism that reflects over your object. The defence is to make the object hostile to reflection: no \`__dict__\`, a redacted repr, and dunders that refuse.`,
        },
      ],
      quiz: [
        {
          q: "Why return `NotImplemented` rather than `False` from `__eq__` for an unknown type?",
          options: [
            "They are the same.",
            "`NotImplemented` lets Python try the other operand's `__eq__` and then fall back to identity; `False` asserts inequality you cannot know.",
            "`False` raises a warning.",
          ],
          answer: 1,
          why: "Returning `False` breaks symmetry with types that could legitimately compare equal to yours, such as a test double.",
        },
        {
          q: "You define `__eq__` and nothing else. What happens to `hash()`?",
          options: [
            "It keeps the default.",
            "The class becomes unhashable — Python sets `__hash__ = None`.",
            "It raises at class definition.",
          ],
          answer: 1,
          why: "A safe default: a mutable-equality object in a set would be a bug. Define `__hash__` explicitly when you need hashability.",
        },
        {
          q: "Why override `__reduce__` to raise?",
          options: [
            "To make the class faster.",
            "To stop generic machinery — pickling into caches, sessions or task queues — from writing the secret to storage.",
            "It is required for `__slots__`.",
          ],
          answer: 1,
          why: "The leak is rarely a line someone wrote about this object; it is a framework serialising whatever it was handed.",
        },
      ],
      exercise: {
        title: "Credential: validated, silent, constant-time",
        brief: `Write a class \`Credential\` holding a secret string.

1. \`Credential(value, *, label="credential")\` — \`value\` must be a \`str\` of at least 16 characters (else \`ValueError\`); \`label\` a non-empty \`str\` used in representations.
2. \`__slots__\` with exactly \`("_value", "_label")\`. No other attribute may be set.
3. \`label\` is a read-only property. There is **no** property exposing the secret.
4. \`reveal()\` — the single, explicit accessor returning the raw string.
5. \`__repr__\` and \`__str__\` both return \`"Credential(<label>, ***)"\`. The secret must never appear.
6. \`__eq__\` compares with \`hmac.compare_digest\` against another \`Credential\`, returns \`NotImplemented\` for other types.
7. \`__hash__\` returns a constant so the equality/hash contract holds.
8. \`__reduce__\`, \`__getstate__\` and \`__copy__\` all raise \`TypeError\` mentioning serialisation or copying, so pickling and copying fail loudly.
9. \`matches(candidate)\` — accepts a raw \`str\` and compares it in constant time, returning a \`bool\`.`,
        rubric: [
          "Short or non-string values are rejected",
          "The secret appears in no representation, and `vars()`/`__dict__` is unavailable",
          "Equality is constant-time and type-safe",
          "Equal credentials hash equally",
          "Pickling raises instead of writing the secret",
          "`reveal()` is the only way to get the raw value",
        ],
        starter: `import hmac


class Credential:
    """A secret that is hard to leak by accident."""

    MIN_LENGTH = 16
    __slots__ = ("_value", "_label")

    def __init__(self, value, *, label="credential"):
        pass


c = Credential("s3cr3t-value-01234567", label="deploy-token")
print(c)
print(c.matches("s3cr3t-value-01234567"))
`,
        stdin: [],
        tests: [
          {
            name: "construction validates",
            code: `c = Credential("x" * 16)
assert c.label == "credential"
for bad in ("short", "", None, 12345, b"x" * 20):
    with raises(ValueError):
        Credential(bad)
for bad in ("", None, 5):
    with raises(ValueError):
        Credential("x" * 20, label=bad)`,
          },
          {
            name: "label is keyword-only and read-only",
            code: `with raises(TypeError):
    Credential("x" * 20, "a-label")
c = Credential("x" * 20, label="deploy")
assert c.label == "deploy"
with raises(AttributeError):
    c.label = "other"`,
          },
          {
            name: "the secret never appears in any representation",
            code: `secret = "s3cr3t-value-01234567"
c = Credential(secret, label="deploy-token")
for rendered in (repr(c), str(c), f"{c}", "%s" % c, "%r" % c, str([c]), str({"k": c})):
    assert secret not in rendered, f"secret leaked via {rendered!r}"
assert "deploy-token" in repr(c) and "***" in repr(c), f"got {repr(c)!r}"`,
          },
          {
            name: "no instance dict to reflect over",
            code: `c = Credential("x" * 20)
try:
    vars(c)
    raise AssertionError("instances should have no __dict__")
except TypeError:
    pass
with raises(AttributeError):
    c.extra = 1`,
          },
          {
            name: "reveal is the only accessor",
            code: `secret = "x" * 20
c = Credential(secret)
assert c.reveal() == secret
assert not any(name for name in dir(c) if name in ("value", "secret", "password"))`,
          },
          {
            name: "equality is type-safe and value-based",
            code: `a = Credential("same-secret-value-1")
b = Credential("same-secret-value-1")
d = Credential("other-secret-value")
assert a == b
assert a != d
assert (a == "same-secret-value-1") is False, "a raw string is not a Credential"
assert (a == 42) is False
assert a.__eq__(42) is NotImplemented`,
          },
          {
            name: "equal credentials hash equally",
            code: `a = Credential("same-secret-value-1")
b = Credential("same-secret-value-1")
assert hash(a) == hash(b)
assert len({a, b}) == 1, "equal credentials should collapse in a set"`,
          },
          {
            name: "serialisation and copying are refused",
            code: `import copy, pickle
c = Credential("x" * 20)
for attempt in (lambda: pickle.dumps(c), lambda: copy.copy(c)):
    try:
        attempt()
        raise AssertionError("serialisation/copy should be refused")
    except TypeError as e:
        assert "serialis" in str(e).lower() or "cop" in str(e).lower(), f"got {str(e)!r}"`,
          },
          {
            name: "matches compares raw strings in constant time",
            code: `c = Credential("x" * 20)
assert c.matches("x" * 20) is True
assert c.matches("y" * 20) is False
assert c.matches("x" * 19) is False
assert c.matches(None) is False
assert c.matches(12345) is False`,
          },
        ],
        requirements: [
          { kind: "defines", value: "Credential" },
          { kind: "calls", value: "hmac.compare_digest" },
          { kind: "no_finding", value: "PY-TIMING-COMPARE" },
          { kind: "regex", value: "__slots__", message: "Declare `__slots__` so instances carry no `__dict__`." },
        ],
        hints: [
          "`pickle.dumps` consults `__reduce_ex__`, which falls back to `__reduce__`; raising there covers pickling. `copy.copy` consults `__copy__`.",
          "`__eq__` must return the literal `NotImplemented` (not raise, not return False) for foreign types — the test checks `a.__eq__(42) is NotImplemented`, and Python turns that into `False` for the `==` operator automatically.",
          "`matches` should return `False` rather than raising for a non-string candidate: a wrong *type* of credential is still a failed authentication, and raising would make the error path distinguishable.",
          "`__hash__ = lambda self: hash(Credential)` works, but a plain method reads better. Any constant satisfies the contract.",
        ],
        solution: `import hmac


class Credential:
    """A secret that is hard to leak by accident."""

    MIN_LENGTH = 16
    __slots__ = ("_value", "_label")

    def __init__(self, value, *, label="credential"):
        if not isinstance(value, str) or len(value) < self.MIN_LENGTH:
            raise ValueError(f"credential must be a string of at least {self.MIN_LENGTH} characters")
        if not isinstance(label, str) or not label:
            raise ValueError("label must be a non-empty string")

        self._value = value
        self._label = label

    # -- read-only surface -------------------------------------------------
    @property
    def label(self):
        return self._label

    def reveal(self):
        """The single, greppable place the raw secret is handed out."""
        return self._value

    # -- representation ----------------------------------------------------
    def __repr__(self):
        return f"Credential({self._label}, ***)"

    __str__ = __repr__

    # -- comparison --------------------------------------------------------
    def __eq__(self, other):
        if not isinstance(other, Credential):
            return NotImplemented
        return hmac.compare_digest(self._value, other._value)

    def __hash__(self):
        # A constant: equal objects must hash equally, and hashing the secret
        # would put a derivative of it into dict and set internals.
        return hash(Credential)

    def matches(self, candidate):
        """Constant-time comparison against a raw string."""
        if not isinstance(candidate, str):
            return False
        return hmac.compare_digest(self._value, candidate)

    # -- refuse generic machinery -----------------------------------------
    def __reduce__(self):
        raise TypeError("Credential objects must not be serialised")

    def __getstate__(self):
        raise TypeError("Credential objects must not be serialised")

    def __copy__(self):
        raise TypeError("Credential objects must not be copied")

    def __deepcopy__(self, memo):
        raise TypeError("Credential objects must not be copied")


c = Credential("s3cr3t-value-01234567", label="deploy-token")
print(c)
print(c.matches("s3cr3t-value-01234567"))`,
        why: `The secret has exactly one exit: \`reveal()\`. Everything else that would normally expose an object's contents has been closed deliberately.

- **\`__slots__\`** removes \`__dict__\`, so \`vars(c)\`, \`json.dumps(c.__dict__)\` and every generic "serialise the attributes" helper fail rather than succeed quietly.
- **\`__repr__\` and \`__str__\`** both redact, covering logging, f-strings, \`%s\`, \`%r\`, and the collection displays that call \`repr\` on members.
- **\`__reduce__\`/\`__getstate__\`/\`__copy__\`/\`__deepcopy__\`** turn pickling and copying into loud failures. This is the one that catches the real-world leak: a credential placed in a session, a Celery argument or a cache is serialised by machinery nobody wrote for this object, and lands in Redis in plaintext.
- **\`__eq__\` via \`compare_digest\`** removes the timing channel, and returning \`NotImplemented\` for foreign types keeps comparison symmetric instead of asserting an inequality the class cannot know.

The constant \`__hash__\` is a deliberate trade, not an oversight. It satisfies the equality/hash contract (equal objects hash equally) without deriving anything from the secret, at the cost of degrading a large set of credentials to linear lookup. For a type you hold a handful of, that is the right side of the trade — and the comment in the code says so, which matters more than the choice itself.

\`matches\` returning \`False\` for a non-string keeps authentication failures uniform. Raising \`TypeError\` there would make a malformed credential distinguishable from a wrong one, which is the enumeration problem from Module 2 reappearing at the type level.`,
      },
      wrapup: `- \`__eq__\` on a secret uses \`hmac.compare_digest\`, and returns \`NotImplemented\` for foreign types.
- Equal objects must hash equally; choose the hash deliberately and write down the trade-off.
- Redact in \`__repr__\` **and** \`__str__\`.
- Make the object hostile to generic reflection: no \`__dict__\`, refuse pickling and copying.`,
      refs: [
        { label: "Data model — special method names", url: "https://docs.python.org/3/reference/datamodel.html#special-method-names" },
        { label: "CWE-208: Observable Timing Discrepancy", url: "https://cwe.mitre.org/data/definitions/208.html" },
      ],
    },
  ],
};
