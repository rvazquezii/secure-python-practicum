export default {
  id: "m01",
  number: 1,
  title: "Foundations and the secure mindset",
  focus: "trust boundaries",
  subtitle:
    "Values, types and printing — taught alongside the one question that separates a programmer from a secure programmer: *where did this data come from?*",
  objectives: [
    "Run Python three ways: the console, a script, and a function under test.",
    "Name the type of every value you handle, and convert types deliberately rather than by accident.",
    "Identify the trust boundary in a program and say what crosses it.",
    "Format output with f-strings without putting secrets into logs.",
    "Choose int, float and Decimal for the right reasons, including money.",
  ],
  rules: [
    { id: "PY-EVAL", what: "never hand runtime strings to eval/exec" },
    { id: "PY-SECRET-IN-LOG", what: "secrets must not reach stdout or logs" },
    { id: "PY-HARDCODED-SECRET", what: "credentials never live in source" },
  ],
  capstone:
    "Day 5 closes the module with a settings loader that reports its own configuration safely: types checked, secrets redacted, no credential in the source file.",

  lessons: [
    /* ------------------------------------------------------------------ 1 */
    {
      id: "m01l01",
      day: 1,
      title: "The console, values, and your first trust boundary",
      minutes: 60,
      secure: "trust boundaries",
      cwe: ["CWE-20"],
      tags: ["repl", "print", "expressions", "trust"],
      lede:
        "Python is an interpreter: you hand it an expression, it hands you back a value. Before you write anything longer than one line, you need a habit — ask of every value, *who controls this?*",
      blocks: [
        {
          t: "p",
          md: `Open the **Python console** at the bottom of this page (click it, or press \`⌃\`\`). That prompt — \`>>>\` — is a live Python process. Type an expression and it answers immediately.

This is not a toy. Professional Python developers keep a console open all day: it is the fastest way to check what a function actually returns instead of guessing.`,
        },
        {
          t: "repl",
          lines: [">>> 2 + 3", "5", ">>> 7 / 2", "3.5", ">>> 7 // 2", "3", '>>> "secure" + " python"', "'secure python'", '>>> len("hunter2")', "7"],
        },
        {
          t: "box",
          kind: "note",
          title: "Expression vs statement",
          md: `An {{expression}} produces a value: \`2 + 3\`, \`len(name)\`, \`"a" * 3\`. A {{statement}} *does* something: \`x = 5\`, \`print(x)\`, \`import os\`.

The console prints the value of an expression automatically. A script does not — in a script you must \`print()\` what you want to see. That difference causes more early confusion than anything else in the language.`,
        },
        { t: "h", text: "print() is how a program speaks" },
        {
          t: "code",
          label: "example",
          code: `print("Audit starting")
print("checks:", 12, "failures:", 0)
print("no newline, ", end="")
print("same line")`,
          cap: "`print` accepts any number of values, separates them with a space, and ends with a newline unless you say otherwise.",
        },
        { t: "h", text: "The question that defines security work" },
        {
          t: "p",
          md: `Every input to your program sits on one side of a line called the {{trust boundary}}. On your side: values you wrote, values your code computed. On the other side: everything a person, a network, a file or another system handed you.

Code that treats the second kind like the first kind is the root cause of the majority of real vulnerabilities. Not clever cryptographic breaks — just data from the outside being used as if it were data from the inside.`,
        },
        {
          t: "table",
          head: ["Source of a value", "Trusted?", "Why"],
          rows: [
            ["A literal in your source: `MAX = 100`", "Yes", "You wrote it; it cannot change at runtime."],
            ["`input()` from a user", "**No**", "The person types anything, including 10 MB of `../`."],
            ["A command-line argument", "**No**", "Whoever launches the process controls it."],
            ["An environment variable", "Partly", "Trusted operators set it — but so does anyone who can spawn your process."],
            ["A file your program wrote", "Partly", "Only if nothing else can write that path."],
            ["An HTTP request body", "**No**", "Anonymous, remote, unlimited, and hostile by default."],
            ["A row from your own database", "**No**", "It got there from one of the untrusted sources above."],
          ],
        },
        {
          t: "box",
          kind: "cve",
          title: "Why this matters on day one",
          md: `The 2017 Equifax breach (147 million records) began with an untrusted HTTP field being interpreted as code. The 2021 Log4Shell vulnerability was the same shape: attacker-controlled text reaching an evaluator. Neither needed a password, a zero-day in the OS, or physical access.

The defect class is always the same sentence: *data from outside was used as if it came from inside.*`,
        },
        { t: "h", text: "The first forbidden function: eval()" },
        {
          t: "p",
          md: `Python has a function that converts a string into running code. It looks like a convenient calculator. It is a remote shell.`,
        },
        {
          t: "code",
          label: "vulnerable",
          stdin: ["__import__('os').system('cat /etc/shadow')"],
          code: `answer = input("Enter a calculation: ")
print(eval(answer))          # user types: __import__('os').system('cat /etc/shadow')`,
          cap: "`eval` compiles and executes whatever it receives, with your program's full privileges.",
        },
        {
          t: "code",
          label: "fixed",
          stdin: ["21"],
          code: `answer = input("Enter a whole number: ")
value = int(answer)          # raises ValueError on anything that is not a number
print(value * 2)`,
          cap: "Parse instead of execute. `int()` either produces a number or refuses.",
        },
        {
          t: "box",
          kind: "rule",
          title: "Rule PY-EVAL",
          md: `Never pass runtime data to \`eval\`, \`exec\`, or \`compile\`. The auditor in this course treats it as a **critical** finding and will not let a lesson pass. When you need to turn text into a value, use a parser: \`int()\`, \`float()\`, \`json.loads()\`, \`ast.literal_eval()\`, or a dictionary of allowed operations.`,
        },
      ],
      spot: {
        label: "a 'harmless' debug helper",
        prompt: "One line here turns a diagnostic tool into remote code execution. Which?",
        lines: [4],
        why:
          "Line 4. `eval(expr)` executes the operator's string as Python. Anyone who can reach this prompt — including a script, a log-replay tool, or an attacker who got one command in — owns the process. Line 3's `print` is noisy but not dangerous.",
        code: `def debug_shell():
    expr = input("inspect> ")
    print("evaluating:", expr)
    print(eval(expr))`,
      },
      quiz: [
        {
          q: "You are reviewing code that does `total = eval(request_body)`. The developer says it is safe because the endpoint requires a login. Is it?",
          options: [
            "Yes — authentication puts the data inside the trust boundary.",
            "No — authentication identifies the caller but does not make their data safe.",
            "Yes, provided the body is shorter than 100 characters.",
          ],
          answer: 1,
          why:
            "Authentication tells you *who* sent the data, not *what* it contains. Any logged-in account — stolen, bought, or created — now has code execution. Length limits do not help: a payload fits in 40 characters.",
        },
        {
          q: "Which of these values is on the trusted side of the boundary?",
          options: [
            "`os.environ['HOME']`",
            "`open('config.json').read()`",
            "`RETRY_LIMIT = 3` written in the source file",
          ],
          answer: 2,
          why:
            "Only the literal. Environment variables come from whoever launched the process, and a file is only as trusted as the set of accounts that can write to it.",
        },
        {
          q: "In a *script* (not the console), what does the line `2 + 3` print?",
          options: ["`5`", "Nothing", "An error"],
          answer: 1,
          why:
            "Nothing. The console echoes expression values as a convenience; a script evaluates the expression, discards the result, and moves on. You need `print(2 + 3)`.",
        },
      ],
      exercise: {
        title: "A greeting that states its own trust level",
        brief: `Write a program that:

1. reads a name with \`input("Name: ")\`,
2. prints \`Hello, <name>.\` on its own line,
3. prints the length of the name as \`Characters: <n>\`,
4. prints the literal line \`Source: untrusted\` — because \`input()\` crosses the trust boundary.

The grader supplies the name \`ada\` on stdin. Use \`int\`/\`len\`, not \`eval\`.`,
        rubric: [
          "Output contains `Hello, ada.`",
          "Output contains `Characters: 3`",
          "Output contains `Source: untrusted`",
          "No use of `eval`, `exec` or `compile` (auditor rule PY-EVAL)",
        ],
        starter: `name = input("Name: ")
# print the greeting, the length, and the trust label
`,
        stdin: ["ada"],
        tests: [
          { name: "greets the name it was given", code: `assert "Hello, ada." in _stdout, f"expected 'Hello, ada.' in output, got: {_stdout!r}"` },
          { name: "reports the character count", code: `assert "Characters: 3" in _stdout, f"expected 'Characters: 3', got: {_stdout!r}"` },
          { name: "labels the input untrusted", code: `assert "Source: untrusted" in _stdout, "print the line 'Source: untrusted'"` },
        ],
        requirements: [{ kind: "forbids", value: "\\beval\\s*\\(", message: "Remove `eval(` — parse values, never execute them." }],
        hints: [
          "`input()` always hands you a string. `len(name)` gives its length as an int.",
          "`print(\"Characters:\", len(name))` prints the label and the number with a space between them — which matches the expected text exactly.",
        ],
        solution: `name = input("Name: ")

print(f"Hello, {name}.")
print("Characters:", len(name))
print("Source: untrusted")`,
        why: `Three separate \`print\` calls, no string arithmetic on the input, and no evaluation. The name is *displayed*, never *executed* — which is the whole lesson. Notice the f-string interpolates the value into text; it does not run it.`,
      },
      wrapup: `- The console echoes expression values; a script does not. Use \`print()\` in scripts.
- Every value has a source, and the source decides how much you may assume.
- \`eval\`/\`exec\` on runtime data is code execution, not convenience. Parse instead.
- "It requires a login" is not a defence against malicious content.`,
      refs: [
        { label: "Python tutorial — an informal introduction", url: "https://docs.python.org/3/tutorial/introduction.html" },
        { label: "CWE-20: Improper Input Validation", url: "https://cwe.mitre.org/data/definitions/20.html" },
      ],
    },

    /* ------------------------------------------------------------------ 2 */
    {
      id: "m01l02",
      day: 2,
      title: "Variables, types, and the string that pretends to be a number",
      minutes: 60,
      secure: "type confusion at the edge",
      cwe: ["CWE-20", "CWE-704"],
      tags: ["types", "int", "str", "conversion", "validation"],
      lede:
        "Python infers types, which is comfortable until an attacker exploits the gap between what you assumed and what you got. `input()` returns a string. Always. Even when it looks like a number.",
      blocks: [
        {
          t: "p",
          md: `A {{variable}} is a name bound to a value. The name has no type; the value does. Rebinding is free, and nothing stops you from pointing a name at a different kind of thing later — which is both Python's great convenience and the source of a whole bug class.`,
        },
        {
          t: "repl",
          lines: [
            ">>> port = 8080",
            ">>> type(port)",
            "<class 'int'>",
            '>>> port = "8080"',
            ">>> type(port)",
            "<class 'str'>",
            ">>> port + 1",
            'TypeError: can only concatenate str (not "int") to str',
          ],
        },
        {
          t: "table",
          head: ["Type", "Example", "What it is for"],
          rows: [
            ["`int`", "`42`, `-7`, `10_000`", "Whole numbers. Arbitrary size in Python — no overflow."],
            ["`float`", "`3.14`, `2e-3`", "Approximate decimals. Never money."],
            ["`str`", "`\"ada\"`", "Text. A sequence of Unicode characters."],
            ["`bytes`", "`b\"\\x89PNG\"`", "Raw octets from files, networks, crypto."],
            ["`bool`", "`True`, `False`", "A decision. Subclass of `int`, oddly."],
            ["`NoneType`", "`None`", "The absence of a value."],
          ],
        },
        { t: "h", text: "The conversion that fails loudly is the one you want" },
        {
          t: "p",
          md: `There are two ways to turn \`"8080"\` into \`8080\`. One of them refuses bad input; the other invites an attacker in. You have already met the dangerous one.`,
        },
        {
          t: "code",
          label: "vulnerable",
          stdin: ["__import__('os').system('id')"],
          code: `raw = input("Port: ")
port = eval(raw)      # "9" -> 9, but "__import__('os').system('id')" -> compromise`,
        },
        {
          t: "code",
          label: "fixed",
          stdin: ["9; rm -rf /"],
          code: `raw = input("Port: ")
port = int(raw)       # "9" -> 9, "9; rm -rf /" -> ValueError`,
          cap: "`int()` is a parser. It accepts exactly one shape of input and rejects everything else.",
        },
        {
          t: "box",
          kind: "good",
          title: "Parse, don't validate-then-trust",
          md: `Convert untrusted text into a *typed value* as early as possible, at a single place, then pass the typed value inward. Code deeper in your program should never have to wonder whether \`port\` is a string that happens to contain digits.

This single habit — a narrow, typed entry point — removes entire categories of bug before they are written.`,
        },
        { t: "h", text: "What int() accepts, exactly" },
        {
          t: "repl",
          lines: [
            '>>> int("42")',
            "42",
            '>>> int("  42  ")        # surrounding whitespace is allowed',
            "42",
            '>>> int("4_2")           # underscores are allowed!',
            "42",
            '>>> int("٤٢")            # Arabic-Indic digits are allowed!',
            "42",
            '>>> int("42.0")',
            "ValueError: invalid literal for int() with base 10: '42.0'",
            '>>> int("")',
            "ValueError: invalid literal for int() with base 10: ''",
          ],
        },
        {
          t: "box",
          kind: "warn",
          title: "`int()` is more permissive than you expect",
          md: `\`int()\` accepts Unicode decimal digits from any script and underscores as separators. For a port number that is harmless. For an identifier you will later print, log or compare, it is a spoofing surface: \`int("٤٢") == 42\` is \`True\`, but the two strings are not equal.

When the exact text matters, validate the string *and* the parsed value: \`if not raw.isascii() or not raw.isdigit(): reject\`.`,
        },
        { t: "h", text: "Range checks are part of parsing" },
        {
          t: "p",
          md: `A value of the right *type* can still be absurd. \`int()\` happily returns \`-5\` or \`99999999\` for a port. Parsing without a range check is half a job.`,
        },
        {
          t: "code",
          label: "fixed",
          stdin: ["70000"],
          code: `raw = input("Port: ")
if not raw.isascii() or not raw.isdigit():
    raise ValueError("port must be digits only")
port = int(raw)
if not 1 <= port <= 65535:
    raise ValueError(f"port out of range: {port}")`,
          cap: "Shape, then type, then range. Each gate is cheap; together they are a validator.",
        },
      ],
      quiz: [
        {
          q: "`age = input(\"Age: \")` then `if age > 17:` — what happens when the user types `21`?",
          options: [
            "It works; Python compares the number 21 to 17.",
            "`TypeError: '>' not supported between instances of 'str' and 'int'`",
            "It is always False because strings sort after numbers.",
          ],
          answer: 1,
          why:
            "`input()` returns the string `\"21\"`, and Python refuses to order a str against an int. This is a case where Python's strictness saves you: a language that coerced silently would compare `\"21\" > \"17\"` lexicographically and get the right answer for the wrong reason — until the user typed `9`.",
        },
        {
          q: "Which converts untrusted text to a number *and* rejects malformed input?",
          options: ["`eval(raw)`", "`int(raw)`", "`exec(raw)`"],
          answer: 1,
          why: "`int()` parses one grammar and raises ValueError otherwise. `eval` and `exec` execute arbitrary Python.",
        },
        {
          q: "`int(\"4_2\")` returns…",
          options: ["`ValueError`", "`42`", "`4`"],
          answer: 1,
          why:
            "42 — PEP 515 numeric underscores apply to `int()` parsing too. Another reason to check the string's shape with `isdigit()` when the exact format matters.",
        },
      ],
      exercise: {
        title: "A port parser that refuses nonsense",
        brief: `Define a function \`parse_port(raw)\` that turns untrusted text into a valid TCP port.

- Return the port as an \`int\` when \`raw\` is ASCII digits describing a number from **1 to 65535**.
- Raise \`ValueError\` for anything else: empty string, \`"80.5"\`, \`"-1"\`, \`"0"\`, \`"70000"\`, \`"8o80"\`, \`"٤٢"\`, or \`" 80 "\` (reject surrounding whitespace — the caller should send clean data).
- Do not use \`eval\`, \`exec\`, or a bare \`except\`.

Then print the result of \`parse_port("8080")\`.`,
        rubric: [
          "`parse_port(\"8080\")` returns the int `8080`",
          "`parse_port(\"1\")` and `parse_port(\"65535\")` are accepted (boundaries included)",
          "`\"0\"`, `\"65536\"`, `\"-1\"`, `\"80.5\"`, `\"\"`, `\" 80 \"`, `\"٤٢\"` all raise `ValueError`",
          "No `eval`/`exec`; no bare `except:`",
        ],
        starter: `def parse_port(raw):
    """Return raw as an int port in 1..65535, or raise ValueError."""
    # 1. shape: ASCII digits only
    # 2. type: int()
    # 3. range: 1..65535


print(parse_port("8080"))
`,
        stdin: [],
        tests: [
          { name: "accepts a normal port", code: `assert parse_port("8080") == 8080, f"got {parse_port('8080')!r}"` },
          { name: "returns an int, not a string", code: `assert type(parse_port("443")) is int, "return an int, not a str"` },
          { name: "accepts both boundaries", code: `assert parse_port("1") == 1 and parse_port("65535") == 65535` },
          {
            name: "rejects out-of-range values",
            code: `for bad in ("0", "65536", "99999999"):
    with raises(ValueError):
        parse_port(bad)`,
          },
          {
            name: "rejects malformed text",
            code: `for bad in ("", "80.5", "-1", "8o80", "0x50", "eighty"):
    with raises(ValueError):
        parse_port(bad)`,
          },
          {
            name: "rejects padding and non-ASCII digits",
            code: `for bad in (" 80 ", "\\t443", "٤٢"):
    with raises(ValueError):
        parse_port(bad)`,
          },
          { name: "prints the parsed port", code: `assert "8080" in _stdout, "print(parse_port(\\"8080\\"))"` },
        ],
        requirements: [
          { kind: "defines", value: "parse_port" },
          { kind: "forbids", value: "\\beval\\s*\\(", message: "Remove `eval(`." },
        ],
        hints: [
          "`raw.isdigit()` is True for Unicode digits too. Combine it with `raw.isascii()` to get ASCII-only digits — and note that `isdigit()` is False for `\"\"`, `\" 80 \"` and `\"-1\"`, which handles three of the bad cases at once.",
          "Structure: `if not (raw.isascii() and raw.isdigit()): raise ValueError(...)`, then `port = int(raw)`, then `if not 1 <= port <= 65535: raise ValueError(...)`, then `return port`.",
          "`raise ValueError(f\"...\")` — include the offending value in the message so the caller can debug, but never include a secret.",
        ],
        solution: `def parse_port(raw):
    """Return raw as an int port in 1..65535, or raise ValueError."""
    if not isinstance(raw, str):
        raise ValueError("port must be text")
    if not (raw.isascii() and raw.isdigit()):
        raise ValueError(f"port must be ASCII digits, got {raw!r}")
    port = int(raw)
    if not 1 <= port <= 65535:
        raise ValueError(f"port out of range 1..65535: {port}")
    return port


print(parse_port("8080"))`,
        why: `Three gates in a fixed order, each one cheap:

- **shape** — \`isascii() and isdigit()\` kills whitespace padding, signs, decimal points, hex prefixes and non-Latin digit scripts in one line,
- **type** — \`int()\` now cannot fail, but it is still the only place conversion happens,
- **range** — the business rule, stated once and loudly.

The function either returns a usable \`int\` or raises. There is no third outcome, which means no caller downstream has to re-check.`,
      },
      wrapup: `- Names have no type; values do. \`input()\` gives you \`str\` every time.
- Parse untrusted text into a typed value at one narrow entry point.
- \`int()\` accepts underscores and non-ASCII digits — check the string's shape when exactness matters.
- A validator checks shape, type **and** range. Two out of three is a bug waiting for a report.`,
      refs: [
        { label: "Built-in types", url: "https://docs.python.org/3/library/stdtypes.html" },
        { label: "CWE-704: Incorrect Type Conversion", url: "https://cwe.mitre.org/data/definitions/704.html" },
      ],
    },

    /* ------------------------------------------------------------------ 3 */
    {
      id: "m01l03",
      day: 3,
      title: "f-strings, and how secrets end up in log files",
      minutes: 60,
      secure: "sensitive data in logs",
      cwe: ["CWE-532", "CWE-209"],
      tags: ["f-string", "format", "logging", "redaction", "repr"],
      lede:
        "String formatting is the most-used feature in Python and the most common way credentials escape into places they can never be deleted from.",
      blocks: [
        {
          t: "p",
          md: `An {{f-string}} is a string literal prefixed with \`f\`, where \`{expr}\` is replaced by the value of that expression. It is faster and clearer than every alternative, and it is what you should use.`,
        },
        {
          t: "code",
          label: "example",
          code: `user = "ada"
failures = 3
ratio = 2 / 3

print(f"user={user} failures={failures}")
print(f"ratio={ratio:.2f}")          # 2 decimal places
print(f"{failures:>5}|")             # right-align in 5 columns
print(f"{user!r}")                   # repr(): shows the quotes
print(f"{failures=}")                # self-documenting: failures=3`,
          cap: "Format specifiers live after a colon; `!r` applies `repr()`; a trailing `=` prints the expression text as well as its value.",
        },
        {
          t: "box",
          kind: "note",
          title: "Three formatting styles, one recommendation",
          md: `- \`f"user={user}"\` — f-string. **Use this.**
- \`"user={}".format(user)\` — older, still fine for templates stored in variables.
- \`"user=%s" % user\` — printf style. Avoid, except in logging calls (see below).

They are equally capable. f-strings keep the value next to the placeholder, which is why they produce fewer mistakes.`,
        },
        { t: "h", text: "Now the security half" },
        {
          t: "p",
          md: `A log line is forever. It is shipped to an aggregator, replicated to a warm standby, retained for a compliance window measured in years, and read by on-call engineers who were never granted access to the credential you just printed. There is no delete button on a log pipeline.`,
        },
        {
          t: "code",
          label: "vulnerable",
          code: `import logging

def login(user, password, api_token):
    logging.info(f"login attempt user={user} password={password}")
    logging.debug(f"calling upstream with token={api_token}")`,
          cap: "Two lines, two permanent credential disclosures. The debug line is worse: debug logging is routinely enabled in production during an incident.",
        },
        {
          t: "code",
          label: "fixed",
          code: `import logging

def login(user, password, api_token):
    logging.info("login attempt user=%s pw_len=%d", user, len(password))
    logging.debug("calling upstream with token=%s", redact(api_token))

def redact(secret):
    """Show only enough to correlate, never enough to use."""
    if not secret:
        return "<empty>"
    return f"{secret[:3]}***{len(secret)}"`,
          cap: "Log *facts about* the secret — its length, its first characters, a hash — never the secret.",
        },
        {
          t: "box",
          kind: "cve",
          title: "This is not a theoretical risk",
          md: `In 2018 Twitter asked all 330 million users to change their password: a logging path had written plaintext passwords to an internal log before hashing. In 2019 Facebook disclosed hundreds of millions of Instagram and Facebook passwords stored in readable logs. In 2022 GitHub rotated keys after discovering npm's internal logs contained plaintext credentials from package publishing.

In all three the code was otherwise competent. One format string was not.`,
        },
        { t: "h", text: "Why `%s` and not an f-string in logging calls" },
        {
          t: "p",
          md: `\`logging.info("user=%s", user)\` defers formatting until the handler decides the record will actually be emitted. With an f-string the text is built even when the level is disabled — wasted work, and worse, it means a \`__str__\` that raises can crash a code path that was supposed to be silent. Use \`%s\` arguments in logging calls; use f-strings everywhere else.`,
        },
        {
          t: "box",
          kind: "pitfall",
          title: "The other leak: exception text",
          md: `\`print(f"query failed: {e}")\` on a database error can emit the full SQL statement including bound parameters. \`traceback.print_exc()\` to a user-facing response emits file paths, library versions and local variable names — a free map of your system.

Log the detail where only you can read it; return a generic message plus a correlation id to the caller.`,
        },
        {
          t: "box",
          kind: "rule",
          title: "Rule PY-SECRET-IN-LOG",
          md: `The auditor flags \`print()\` and \`logging.*\` calls whose arguments name a secret: anything matching *password, passwd, pwd, secret, token, api_key, private_key, credential, session_id, otp, signature*. It is a **medium** finding — it will not block a lesson, but it will keep appearing until you form the habit.`,
        },
      ],
      spot: {
        label: "payment service, error path",
        prompt: "Click the line that will put a usable credential into permanent storage.",
        lines: [8],
        why:
          "Line 8. The f-string interpolates `card_token` straight into the error log, so every failed charge writes a live payment credential to disk. Line 5 is fine — it logs an amount and an id. Line 10's generic message to the caller is exactly right.",
        code: `import logging

def charge(card_token, amount_cents, order_id):
    logging.info("charging order=%s amount=%d", order_id, amount_cents)
    try:
        result = gateway.charge(card_token, amount_cents)
    except GatewayError as e:
        logging.error(f"charge failed token={card_token} err={e}")
        raise
    return result`,
      },
      quiz: [
        {
          q: "Which line is safe to ship?",
          options: [
            "`logging.info(f\"auth ok for {user} with {token}\")`",
            "`logging.info(\"auth ok for user=%s token_len=%d\", user, len(token))`",
            "`print(\"auth ok\", user, token[:20])`",
          ],
          answer: 1,
          why:
            "Only the second. The third looks cautious but 20 characters of many token formats is enough to use or to brute-force the remainder — and it is still a credential in a log file.",
        },
        {
          q: "Why prefer `logging.info(\"x=%s\", x)` over `logging.info(f\"x={x}\")`?",
          options: [
            "The %s form is formatted only if the record is actually emitted.",
            "The f-string form cannot be parsed by log aggregators.",
            "There is no difference.",
          ],
          answer: 0,
          why:
            "Deferred formatting avoids the cost — and the risk of a raising `__str__` — when the level is disabled. Aggregators parse both fine.",
        },
        {
          q: "An API returns `f\"user {uid} not found in table accounts_v3 at /srv/app/db/users.py:214\"`. What is the problem?",
          options: [
            "Nothing; detailed errors help users.",
            "It discloses internal structure that helps an attacker map the system.",
            "It is too slow to format.",
          ],
          answer: 1,
          why:
            "Table names, file paths and line numbers are reconnaissance. Return `\"not found\"` plus a correlation id; keep the detail in your own logs.",
        },
      ],
      exercise: {
        title: "A redactor you can trust",
        brief: `Write \`redact(secret)\` and \`audit_line(user, secret)\`.

**\`redact(secret)\`** returns a string safe to log:
- \`None\` or \`""\` → \`"<empty>"\`
- a string of 8 characters or fewer → \`"***"\` (too short to show any of it)
- longer → the first 3 characters, then \`"***"\`, then the length, e.g. \`redact("glpat-7x2Qd91ZvKmA")\` → \`"gla***18"\`... careful: that is \`"gla"\` only if the first three characters are \`g\`, \`l\`, \`a\`. For \`"glpat-7x2Qd91ZvKmA"\` (18 chars) the result is \`"glp***18"\`.

**\`audit_line(user, secret)\`** returns exactly \`"user=<user> token=<redacted>"\` using \`redact\`.

Then print \`audit_line("ada", "glpat-7x2Qd91ZvKmA")\`. The raw secret must never appear in your output.`,
        rubric: [
          "`redact(None)` and `redact(\"\")` return `\"<empty>\"`",
          "`redact(\"short\")` returns `\"***\"` (8 characters or fewer)",
          "`redact(\"glpat-7x2Qd91ZvKmA\")` returns `\"glp***18\"`",
          "`audit_line(\"ada\", s)` returns `\"user=ada token=glp***18\"`",
          "The full secret never appears in stdout",
        ],
        starter: `def redact(secret):
    """Return a loggable stand-in for a secret."""


def audit_line(user, secret):
    """Return 'user=<user> token=<redacted>'."""


print(audit_line("ada", "glpat-7x2Qd91ZvKmA"))
`,
        stdin: [],
        tests: [
          { name: "empty values", code: `assert redact(None) == "<empty>" and redact("") == "<empty>", "None and '' must give '<empty>'"` },
          {
            name: "short secrets reveal nothing",
            code: `for s in ("a", "abc", "12345678"):
    assert redact(s) == "***", f"redact({s!r}) should be '***', got {redact(s)!r}"`,
          },
          {
            name: "long secrets show 3 chars and a length",
            code: `assert redact("glpat-7x2Qd91ZvKmA") == "glp***18", f"got {redact('glpat-7x2Qd91ZvKmA')!r}"
assert redact("123456789") == "123***9", f"got {redact('123456789')!r}"`,
          },
          {
            name: "audit_line has the exact shape",
            code: `got = audit_line("ada", "glpat-7x2Qd91ZvKmA")
assert got == "user=ada token=glp***18", f"got {got!r}"`,
          },
          {
            name: "the secret does not leak to stdout",
            code: `assert "glpat-7x2Qd91ZvKmA" not in _stdout, "the full secret appeared in the output"
assert "glp***18" in _stdout, "print the audit line"`,
          },
        ],
        requirements: [
          { kind: "defines", value: "redact" },
          { kind: "defines", value: "audit_line" },
        ],
        hints: [
          "Handle the falsy case first: `if not secret: return \"<empty>\"`. That catches both `None` and `\"\"`.",
          "`len(secret) <= 8` → `return \"***\"`. Otherwise `return f\"{secret[:3]}***{len(secret)}\"`.",
          "`audit_line` should call `redact` rather than reimplementing it — one redaction rule, one place to fix it.",
        ],
        solution: `def redact(secret):
    """Return a loggable stand-in for a secret."""
    if not secret:
        return "<empty>"
    if len(secret) <= 8:
        return "***"
    return f"{secret[:3]}***{len(secret)}"


def audit_line(user, secret):
    """Return 'user=<user> token=<redacted>'."""
    return f"user={user} token={redact(secret)}"


print(audit_line("ada", "glpat-7x2Qd91ZvKmA"))`,
        why: `The redaction rule lives in exactly one function, so there is one place to tighten it when someone decides three characters is two too many. Short secrets reveal *nothing* rather than most of themselves — a 6-character token with 3 characters shown is a 3-character brute force.

The length is included because it is operationally useful (it distinguishes a truncated token from a wrong one) and not useful to an attacker who already knows the token format.`,
      },
      wrapup: `- f-strings everywhere, \`%s\` arguments in \`logging\` calls.
- Logs are permanent, replicated and widely read. Treat every log line as public.
- Log *facts about* a secret — length, prefix, hash — never the secret.
- Exception text is output too: it leaks schemas, paths and versions.`,
      refs: [
        { label: "PEP 498 — Literal String Interpolation", url: "https://peps.python.org/pep-0498/" },
        { label: "CWE-532: Insertion of Sensitive Information into Log File", url: "https://cwe.mitre.org/data/definitions/532.html" },
        { label: "OWASP Logging Cheat Sheet", url: "https://cheatsheetseries.owasp.org/cheatsheets/Logging_Cheat_Sheet.html" },
      ],
    },

    /* ------------------------------------------------------------------ 4 */
    {
      id: "m01l04",
      day: 4,
      title: "Numbers: floats lie about money, ints never overflow",
      minutes: 60,
      secure: "rounding and limit checks",
      cwe: ["CWE-682", "CWE-1339"],
      tags: ["int", "float", "decimal", "rounding", "money"],
      lede:
        "Python's integers are unbounded, which removes the classic overflow vulnerability. Its floats are IEEE-754 binary, which introduces a subtler one: a limit check that passes when it should fail.",
      blocks: [
        {
          t: "repl",
          lines: [
            ">>> 0.1 + 0.2",
            "0.30000000000000004",
            ">>> 0.1 + 0.2 == 0.3",
            "False",
            ">>> 2 ** 1000        # no overflow, ever",
            "1071508607186267320948425049060001810561404811705533607443750388370351051124936122493198378815695858127594672917553146825187145285692314043598457757469857480393456777482423098542107460506237114187795418215304647498358194126739876755916554394607706291457119647768654216766042983165262438683720566245062932722485...",
            ">>> round(2.675, 2)  # not 2.68",
            "2.67",
          ],
        },
        {
          t: "p",
          md: `A \`float\` is a binary fraction. \`0.1\` is not representable in binary, exactly as \`1/3\` is not representable in decimal. Every arithmetic step adds a little error, and the error is **not** always in the direction you expect.`,
        },
        { t: "h", text: "Where that becomes a security bug" },
        {
          t: "code",
          label: "vulnerable",
          code: `DAILY_LIMIT = 1000.00

def transfer(amount, spent_today):
    if spent_today + amount > DAILY_LIMIT:
        raise ValueError("daily limit exceeded")
    return spent_today + amount

# 999.99 + 0.01 == 1000.0000000000001 ... or 999.9999999999999,
# depending on how the running total was accumulated.`,
          cap: "A limit check on accumulated floats is a coin flip at the boundary. Attackers find the side that favours them and stay there.",
        },
        {
          t: "code",
          label: "fixed",
          code: `DAILY_LIMIT_CENTS = 100_000          # integers: exact, comparable, loggable

def transfer(amount_cents, spent_today_cents):
    if not isinstance(amount_cents, int) or amount_cents <= 0:
        raise ValueError("amount must be a positive whole number of cents")
    total = spent_today_cents + amount_cents
    if total > DAILY_LIMIT_CENTS:
        raise ValueError("daily limit exceeded")
    return total`,
          cap: "Store money as integer minor units. Every comparison is then exact and every total reproducible.",
        },
        {
          t: "box",
          kind: "good",
          title: "Two correct ways to handle money",
          md: `1. **Integer minor units** — cents, satoshi, mills. Simple, exact, fast, and what payment APIs actually send on the wire (Stripe amounts are integer cents).
2. **\`decimal.Decimal\`** — when you need fractional cents, repeating division, or a specified rounding mode. \`Decimal("0.1") + Decimal("0.2") == Decimal("0.3")\` is \`True\`.

Never \`float\`. Not for money, not for quotas, not for anything someone can transact against.`,
        },
        {
          t: "code",
          label: "example",
          code: `from decimal import Decimal, ROUND_HALF_UP

price = Decimal("19.99")
tax = (price * Decimal("0.0825")).quantize(Decimal("0.01"), rounding=ROUND_HALF_UP)
print(price, tax, price + tax)        # 19.99 1.65 21.64`,
          cap: "Build `Decimal` from a **string**. `Decimal(0.1)` inherits the float's error and defeats the point.",
        },
        { t: "h", text: "The overflow you do not have, and the one you do" },
        {
          t: "p",
          md: `In C, \`int x = 2147483647; x + 1\` wraps to a negative number and the length check two lines later passes. That bug class does not exist in Python: integers grow to fit memory.

What you get instead is **resource exhaustion**. \`2 ** 10_000_000\` does not overflow — it tries to allocate the result, and \`int("9" * 10_000_000)\` tries to parse it. Python 3.11+ caps integer↔string conversion at 4300 digits by default for exactly this reason.`,
        },
        {
          t: "box",
          kind: "warn",
          title: "Bound the size of untrusted numbers",
          md: `An exponent, a repeat count, a page size, a timeout, a retry limit — every number that reaches an allocation or a loop needs an upper bound checked *before* use. "It is only an integer" is how a request body becomes a memory exhaustion.`,
        },
        {
          t: "table",
          head: ["Need", "Use", "Not"],
          rows: [
            ["Counting, indexing, ids", "`int`", "—"],
            ["Money, quotas, billing", "`int` minor units or `Decimal`", "`float`"],
            ["Physical measurement, statistics", "`float`", "—"],
            ["Comparing computed floats", "`math.isclose(a, b)`", "`a == b`"],
            ["Rounding for display", "`f\"{x:.2f}\"`", "`round()` then compare"],
          ],
        },
      ],
      quiz: [
        {
          q: "Why is `if balance - amount >= 0` risky when both are floats?",
          options: [
            "Floats cannot represent negative numbers.",
            "Accumulated binary error can make the comparison true when the exact arithmetic says false.",
            "Subtraction is slower than addition.",
          ],
          answer: 1,
          why:
            "Representation error at the boundary. With integer cents the comparison is exact, and the result is reproducible in an audit.",
        },
        {
          q: "`Decimal(0.1)` vs `Decimal(\"0.1\")` — what is the difference?",
          options: [
            "None.",
            "`Decimal(0.1)` captures the float's error: 0.1000000000000000055511151231257827.",
            "`Decimal(\"0.1\")` raises a TypeError.",
          ],
          answer: 1,
          why: "Constructing from a float imports the error you were trying to avoid. Always construct Decimals from strings or ints.",
        },
        {
          q: "An endpoint accepts `{\"repeat\": n}` and returns `\"x\" * n`. Python ints never overflow, so is a bound needed?",
          options: [
            "No — no overflow means no vulnerability.",
            "Yes — unbounded `n` is a memory exhaustion denial of service.",
            "No, the garbage collector handles it.",
          ],
          answer: 1,
          why:
            "The absence of integer overflow moves the problem to allocation. `n = 10**12` attempts a terabyte string. Bound every untrusted number before it reaches an allocation or a loop.",
        },
      ],
      exercise: {
        title: "An exact spending limiter",
        brief: `Build a limiter that works in integer cents and refuses anything unreasonable.

Define \`charge(spent_cents, amount_cents, limit_cents=100_000)\`:

- Reject non-\`int\` arguments with \`TypeError\` (note: \`bool\` is a subclass of \`int\` — reject \`True\` too).
- Reject \`amount_cents <= 0\` with \`ValueError\`.
- Reject \`amount_cents > 50_000\` (single-transaction cap) with \`ValueError\`.
- Raise \`ValueError\` when \`spent_cents + amount_cents\` would exceed \`limit_cents\`.
- Otherwise return the new total.

Also define \`money(cents)\` returning a display string: \`money(21640)\` → \`"$216.40"\`, \`money(5)\` → \`"$0.05"\`.

Print \`money(charge(99_900, 100))\`.`,
        rubric: [
          "Exact boundary: spending to exactly the limit succeeds; one cent more raises",
          "`charge(0, 50_001)` raises `ValueError` (single-transaction cap)",
          "`charge(0, 0)` and `charge(0, -5)` raise `ValueError`",
          "`charge(0, 10.0)` and `charge(0, True)` raise `TypeError`",
          "`money(21640) == \"$216.40\"`, `money(5) == \"$0.05\"`",
        ],
        starter: `def charge(spent_cents, amount_cents, limit_cents=100_000):
    """Return the new total in cents, or raise."""


def money(cents):
    """Format integer cents as a dollar string."""


print(money(charge(99_900, 100)))
`,
        stdin: [],
        tests: [
          { name: "accepts a normal charge", code: `assert charge(1000, 500) == 1500, f"got {charge(1000, 500)!r}"` },
          {
            name: "the boundary is exact",
            code: `assert charge(99_900, 100) == 100_000, "spending to exactly the limit must succeed"
with raises(ValueError):
    charge(99_900, 101)`,
          },
          {
            name: "single-transaction cap",
            code: `assert charge(0, 50_000) == 50_000
with raises(ValueError):
    charge(0, 50_001)`,
          },
          {
            name: "rejects zero and negative amounts",
            code: `for bad in (0, -1, -5000):
    with raises(ValueError):
        charge(1000, bad)`,
          },
          {
            name: "rejects non-integers, including bool",
            code: `for bad in (10.0, "100", None, True):
    with raises(TypeError):
        charge(1000, bad)`,
          },
          {
            name: "money formats cents exactly",
            code: `assert money(21640) == "$216.40", f"got {money(21640)!r}"
assert money(5) == "$0.05", f"got {money(5)!r}"
assert money(0) == "$0.00", f"got {money(0)!r}"
assert money(100_000) == "$1000.00", f"got {money(100_000)!r}"`,
          },
          { name: "prints the formatted total", code: `assert "$1000.00" in _stdout, "print(money(charge(99_900, 100)))"` },
        ],
        requirements: [
          { kind: "defines", value: "charge" },
          { kind: "defines", value: "money" },
          { kind: "forbids", value: "float\\s*\\(", message: "No `float()` here — money stays in integer cents." },
        ],
        hints: [
          "`isinstance(True, int)` is `True`, so an int check alone lets booleans through. Add `or isinstance(x, bool)` to the rejection condition.",
          "Order the checks: types first (TypeError), then value rules (ValueError), then the limit. Fail on the most basic violation first so error messages stay accurate.",
          "`money`: `f\"${cents // 100}.{cents % 100:02d}\"` — integer division and remainder keep it exact, and `:02d` pads the cents.",
        ],
        solution: `SINGLE_TXN_CAP_CENTS = 50_000


def charge(spent_cents, amount_cents, limit_cents=100_000):
    """Return the new total in cents, or raise."""
    for name, value in (("spent_cents", spent_cents), ("amount_cents", amount_cents),
                        ("limit_cents", limit_cents)):
        if isinstance(value, bool) or not isinstance(value, int):
            raise TypeError(f"{name} must be an int number of cents, got {type(value).__name__}")

    if amount_cents <= 0:
        raise ValueError(f"amount must be positive, got {amount_cents}")
    if amount_cents > SINGLE_TXN_CAP_CENTS:
        raise ValueError(f"single transaction cap is {SINGLE_TXN_CAP_CENTS} cents")

    total = spent_cents + amount_cents
    if total > limit_cents:
        raise ValueError(f"daily limit exceeded: {total} > {limit_cents}")
    return total


def money(cents):
    """Format integer cents as a dollar string."""
    return f"\${cents // 100}.{cents % 100:02d}"


print(money(charge(99_900, 100)))`,
        why: `Everything is an integer, so \`99_900 + 100 > 100_000\` is \`False\` on every machine, every run, forever — no boundary coin flip.

Three separate rules, three separate errors: a type problem is a \`TypeError\`, a value problem is a \`ValueError\`, and the per-transaction cap is stated as a named constant rather than buried in a comparison. The \`bool\` check matters more than it looks: \`charge(1000, True)\` would otherwise charge one cent, and a JSON body of \`{"amount": true}\` is a realistic input.

\`money()\` formats only at the edge, for display. The value itself never becomes a float.`,
      },
      wrapup: `- Python ints are unbounded: no overflow bugs, but unbounded allocation instead. Bound untrusted numbers.
- Floats are binary approximations. Never use them for money, quotas or limits.
- Integer minor units or \`Decimal("...")\` from a string. Format for display at the edge only.
- \`bool\` is an \`int\` — an isinstance check that forgets this lets \`True\` through as 1.`,
      refs: [
        { label: "Floating-point arithmetic: issues and limitations", url: "https://docs.python.org/3/tutorial/floatingpoint.html" },
        { label: "decimal — Decimal fixed-point arithmetic", url: "https://docs.python.org/3/library/decimal.html" },
        { label: "Integer string conversion length limit (CVE-2020-10735)", url: "https://docs.python.org/3/library/stdtypes.html#int-max-str-digits" },
      ],
    },

    /* ------------------------------------------------------------------ 5 */
    {
      id: "m01l05",
      day: 5,
      title: "Capstone: a settings loader that fails closed",
      minutes: 60,
      secure: "fail-closed configuration, no secrets in source",
      cwe: ["CWE-798", "CWE-636"],
      tags: ["capstone", "booleans", "None", "config", "env", "truthiness"],
      lede:
        "Booleans, `None` and truthiness — assembled into the thing every program needs and most get wrong: configuration that refuses to start rather than starting insecurely.",
      blocks: [
        {
          t: "p",
          md: `\`None\` means *no value*. \`False\` means *a value, and it is false*. Conflating them is how a disabled security control ends up looking identical to an unconfigured one.`,
        },
        {
          t: "repl",
          lines: [
            ">>> bool(0), bool(0.0), bool(\"\"), bool([]), bool({}), bool(None)",
            "(False, False, False, False, False, False)",
            '>>> bool("False")   # a non-empty string is truthy!',
            "True",
            '>>> bool("0")',
            "True",
            ">>> None == False",
            "False",
          ],
        },
        {
          t: "box",
          kind: "pitfall",
          title: "The classic: `if os.environ.get(\"TLS_VERIFY\")`",
          md: `Environment variables are strings. \`"false"\`, \`"0\`\`"\` and \`"no"\` are all **truthy**, so the check above enables verification — which is lucky. Now invert it:

\`if os.environ.get("DEBUG"):\` with \`DEBUG=false\` set turns debug **on**. That is how a debug console ends up on a production host.

Parse the string. Never test it for truthiness.`,
        },
        {
          t: "code",
          label: "fixed",
          code: `TRUE = {"1", "true", "yes", "on"}
FALSE = {"0", "false", "no", "off"}

def parse_bool(raw, *, default=None):
    if raw is None:
        if default is None:
            raise ValueError("required boolean setting is missing")
        return default
    text = raw.strip().lower()
    if text in TRUE:
        return True
    if text in FALSE:
        return False
    raise ValueError(f"not a boolean: {raw!r}")`,
          cap: "An allowlist of accepted spellings, and an error for everything else. Note `default=None` meaning *no default* — so a missing required setting is an exception, not a silent `False`.",
        },
        { t: "h", text: "`is` versus `==`" },
        {
          t: "p",
          md: `\`is\` asks whether two names point at the same object. \`==\` asks whether two values are equal. For \`None\` always use \`is\`: \`None\` is a singleton, and a hostile or buggy class can define \`__eq__\` so that \`obj == None\` returns \`True\`.`,
        },
        {
          t: "code",
          label: "vulnerable",
          code: `class Sneaky:
    def __eq__(self, other):
        return True          # equal to everything, including None

user = Sneaky()
if user == None:
    print("no user")         # taken!
if user is None:
    print("unreachable")     # correct: identity cannot be faked`,
        },
        { t: "h", text: "Fail closed" },
        {
          t: "p",
          md: `A {{fail-closed}} system denies access when it cannot determine that access should be granted. A {{fail-open}} system grants it. The difference is usually a single \`else\` branch or a default value.

Applied to configuration: a missing \`SESSION_SECRET\` must stop the process. The alternative — generating a random one at startup, or falling back to \`"dev-secret"\` — produces a server that boots happily and is trivially forgeable.`,
        },
        {
          t: "table",
          head: ["Setting missing", "Fail-open (wrong)", "Fail-closed (right)"],
          rows: [
            ["`SESSION_SECRET`", "`os.environ.get(..., \"dev\")`", "`os.environ[\"SESSION_SECRET\"]` → KeyError, process exits"],
            ["`TLS_VERIFY`", "default `False`", "default `True`"],
            ["`ALLOWED_ORIGINS`", "default `[\"*\"]`", "default `[]` — nothing is allowed until stated"],
            ["`MAX_UPLOAD_MB`", "unlimited", "a conservative number"],
            ["`AUTH_REQUIRED`", "default `False`", "default `True`"],
          ],
        },
        {
          t: "box",
          kind: "rule",
          title: "Rules PY-HARDCODED-SECRET and PY-SECRET-FALLBACK",
          md: `The auditor raises a **high** finding for a string literal assigned to a secret-looking name, and for \`os.environ.get("TOKEN", "some-default")\`. Both ship a working credential inside your source. The second is worse, because it hides the misconfiguration you needed to notice.`,
        },
      ],
      spot: {
        label: "application startup",
        prompt: "Two lines here are dangerous. Click the one that makes every deployment share one forgeable session key.",
        lines: [6],
        why:
          "Line 6. With `SESSION_SECRET` unset — the normal case in a fresh container — every instance uses `\"dev-secret-change-me\"`, so anyone who has read the source can mint a valid session cookie for any user. Line 7 is also wrong (`\"false\"` is truthy, so `DEBUG=false` enables debug), but line 6 is the one that forges sessions.",
        code: `import os

HOST = os.environ.get("HOST", "127.0.0.1")
PORT = int(os.environ.get("PORT", "8000"))
WORKERS = int(os.environ.get("WORKERS", "4"))
SESSION_SECRET = os.environ.get("SESSION_SECRET", "dev-secret-change-me")
DEBUG = bool(os.environ.get("DEBUG", ""))
TLS_VERIFY = os.environ.get("TLS_VERIFY", "1") != "0"`,
      },
      quiz: [
        {
          q: "`os.environ[\"API_KEY\"]` versus `os.environ.get(\"API_KEY\", \"test-key\")` — which is the secure default and why?",
          options: [
            "`.get()` with a default, because the program keeps running.",
            "`[\"API_KEY\"]`, because a missing credential should stop the process rather than silently use a shared one.",
            "They are equivalent.",
          ],
          answer: 1,
          why:
            "Crashing at startup is a loud, immediate, cheap failure. A fallback credential is a quiet one that every deployment shares and that lives in your repository history forever.",
        },
        {
          q: "`DEBUG=false` in the environment, and the code says `if os.environ.get(\"DEBUG\"):`. What happens?",
          options: ["Debug is off.", "Debug is on — `\"false\"` is a non-empty string, which is truthy.", "A ValueError."],
          answer: 1,
          why: "Every non-empty string is truthy. Parse environment strings through an explicit allowlist of spellings.",
        },
        {
          q: "Why `if value is None` rather than `if value == None`?",
          options: [
            "`is` is faster.",
            "`==` can be overridden by a class's `__eq__`, so a non-None object can claim to equal None.",
            "`== None` is a syntax error in Python 3.",
          ],
          answer: 1,
          why:
            "Identity cannot be faked; equality can. It is also faster, but the security reason is the one that matters: never let the object you are inspecting decide the answer.",
        },
      ],
      exercise: {
        title: "load_settings(): refuse to start insecurely",
        brief: `Write \`load_settings(env)\` where \`env\` is a dict of strings (the grader passes one in; do not read the real environment).

Return a dict with these keys, applying these rules:

| key | source | rule |
|---|---|---|
| \`session_secret\` | \`env["SESSION_SECRET"]\` | **required**, at least 16 characters. Missing or short → \`ValueError\`. No default, ever. |
| \`debug\` | \`env.get("DEBUG")\` | parse with an allowlist; **default \`False\`** |
| \`tls_verify\` | \`env.get("TLS_VERIFY")\` | parse with an allowlist; **default \`True\`** |
| \`max_upload_mb\` | \`env.get("MAX_UPLOAD_MB")\` | int, 1–100, **default 10**; out of range → \`ValueError\` |
| \`allowed_origins\` | \`env.get("ALLOWED_ORIGINS")\` | comma-separated list, **default \`[]\`**; \`"*"\` anywhere → \`ValueError\` |

Accept \`"1"/"true"/"yes"/"on"\` and \`"0"/"false"/"no"/"off"\` (case-insensitive, surrounding whitespace allowed) for booleans; any other spelling → \`ValueError\`.

Also write \`describe(settings)\` returning a one-line summary that is safe to log: it must include \`debug=\`, \`tls_verify=\` and \`max_upload_mb=\`, and must **not** contain the session secret.`,
        rubric: [
          "Missing or short `SESSION_SECRET` raises `ValueError`; there is no fallback secret anywhere in the file",
          "`DEBUG=\"false\"` yields `False`; absent yields `False`",
          "`TLS_VERIFY` absent yields `True`",
          "Unknown boolean spellings raise `ValueError`",
          "`MAX_UPLOAD_MB` outside 1–100 raises `ValueError`; absent yields 10",
          "`ALLOWED_ORIGINS` absent yields `[]`; a `*` entry raises `ValueError`",
          "`describe()` never contains the secret",
        ],
        starter: `TRUE_WORDS = {"1", "true", "yes", "on"}
FALSE_WORDS = {"0", "false", "no", "off"}


def parse_bool(raw, default):
    """raw is a string or None. Return True/False or raise ValueError."""


def load_settings(env):
    """Build a settings dict from a mapping of strings, or refuse to start."""


def describe(settings):
    """One safe log line. Must not contain the secret."""


print(describe(load_settings({"SESSION_SECRET": "x" * 24, "DEBUG": "false"})))
`,
        stdin: [],
        tests: [
          {
            name: "secret is required",
            code: `with raises(ValueError):
    load_settings({})
with raises(ValueError):
    load_settings({"SESSION_SECRET": "tooshort"})`,
          },
          {
            name: "secure defaults when nothing is set",
            code: `s = load_settings({"SESSION_SECRET": "a" * 16})
assert s["debug"] is False, "debug must default to False"
assert s["tls_verify"] is True, "tls_verify must default to True"
assert s["max_upload_mb"] == 10, f"got {s['max_upload_mb']!r}"
assert s["allowed_origins"] == [], f"got {s['allowed_origins']!r}"`,
          },
          {
            name: "boolean strings are parsed, not tested for truthiness",
            code: `base = {"SESSION_SECRET": "a" * 16}
assert load_settings({**base, "DEBUG": "false"})["debug"] is False
assert load_settings({**base, "DEBUG": "FALSE"})["debug"] is False
assert load_settings({**base, "DEBUG": " no "})["debug"] is False
assert load_settings({**base, "DEBUG": "1"})["debug"] is True
assert load_settings({**base, "TLS_VERIFY": "off"})["tls_verify"] is False`,
          },
          {
            name: "unknown boolean spellings are rejected",
            code: `base = {"SESSION_SECRET": "a" * 16}
for bad in ("maybe", "", "2", "trueish"):
    with raises(ValueError):
        load_settings({**base, "DEBUG": bad})`,
          },
          {
            name: "upload size is range-checked",
            code: `base = {"SESSION_SECRET": "a" * 16}
assert load_settings({**base, "MAX_UPLOAD_MB": "50"})["max_upload_mb"] == 50
for bad in ("0", "101", "-1", "ten", "10.5"):
    with raises(ValueError):
        load_settings({**base, "MAX_UPLOAD_MB": bad})`,
          },
          {
            name: "origins: explicit list, no wildcard",
            code: `base = {"SESSION_SECRET": "a" * 16}
got = load_settings({**base, "ALLOWED_ORIGINS": "https://a.example, https://b.example"})
assert got["allowed_origins"] == ["https://a.example", "https://b.example"], f"got {got['allowed_origins']!r}"
for bad in ("*", "https://a.example,*"):
    with raises(ValueError):
        load_settings({**base, "ALLOWED_ORIGINS": bad})`,
          },
          {
            name: "describe() is loggable and complete",
            code: `secret = "s3cr3t-value-01234567"
line = describe(load_settings({"SESSION_SECRET": secret, "DEBUG": "no"}))
assert secret not in line, "describe() leaked the session secret"
for needle in ("debug=", "tls_verify=", "max_upload_mb="):
    assert needle in line, f"describe() should report {needle}"`,
          },
          {
            name: "the secret never reaches stdout",
            code: `assert "xxxxxxxxxxxxxxxxxxxxxxxx" not in _stdout, "the secret was printed"`,
          },
        ],
        requirements: [
          { kind: "defines", value: "load_settings" },
          { kind: "defines", value: "describe" },
          { kind: "no_finding", value: "PY-HARDCODED-SECRET" },
          { kind: "no_finding", value: "PY-SECRET-FALLBACK" },
        ],
        hints: [
          "Write `parse_bool(raw, default)` first and use it twice. When `raw is None` return the default; otherwise normalise with `.strip().lower()` and check membership in the two sets.",
          "For the secret: `secret = env.get(\"SESSION_SECRET\")`, then `if not secret or len(secret) < 16: raise ValueError(...)`. Do not put any literal secret in the file — the auditor will flag it.",
          "Origins: `[o.strip() for o in raw.split(\",\") if o.strip()]`, then `if \"*\" in parts: raise ValueError(...)`.",
          "`describe` should interpolate only the non-secret settings. If you want to mention the secret at all, report `len(secret)`.",
        ],
        solution: `TRUE_WORDS = {"1", "true", "yes", "on"}
FALSE_WORDS = {"0", "false", "no", "off"}

MIN_SECRET_LEN = 16
UPLOAD_RANGE = (1, 100)


def parse_bool(raw, default):
    """raw is a string or None. Return True/False or raise ValueError."""
    if raw is None:
        return default
    text = str(raw).strip().lower()
    if text in TRUE_WORDS:
        return True
    if text in FALSE_WORDS:
        return False
    raise ValueError(f"not a boolean: {raw!r} (use one of {sorted(TRUE_WORDS | FALSE_WORDS)})")


def _parse_upload_mb(raw):
    if raw is None:
        return 10
    text = str(raw).strip()
    if not (text.isascii() and text.isdigit()):
        raise ValueError(f"MAX_UPLOAD_MB must be digits, got {raw!r}")
    value = int(text)
    low, high = UPLOAD_RANGE
    if not low <= value <= high:
        raise ValueError(f"MAX_UPLOAD_MB out of range {low}..{high}: {value}")
    return value


def _parse_origins(raw):
    if raw is None:
        return []
    parts = [o.strip() for o in str(raw).split(",") if o.strip()]
    if "*" in parts:
        raise ValueError("wildcard origin '*' is not permitted; list origins explicitly")
    return parts


def load_settings(env):
    """Build a settings dict from a mapping of strings, or refuse to start."""
    secret = env.get("SESSION_SECRET")
    if not secret or len(secret) < MIN_SECRET_LEN:
        raise ValueError(
            f"SESSION_SECRET is required and must be at least {MIN_SECRET_LEN} characters"
        )

    return {
        "session_secret": secret,
        "debug": parse_bool(env.get("DEBUG"), False),
        "tls_verify": parse_bool(env.get("TLS_VERIFY"), True),
        "max_upload_mb": _parse_upload_mb(env.get("MAX_UPLOAD_MB")),
        "allowed_origins": _parse_origins(env.get("ALLOWED_ORIGINS")),
    }


def describe(settings):
    """One safe log line. Must not contain the secret."""
    return (
        f"settings loaded: debug={settings['debug']} "
        f"tls_verify={settings['tls_verify']} "
        f"max_upload_mb={settings['max_upload_mb']} "
        f"origins={len(settings['allowed_origins'])} "
        f"secret_len={len(settings['session_secret'])}"
    )


print(describe(load_settings({"SESSION_SECRET": "x" * 24, "DEBUG": "false"})))`,
        why: `Every default in this loader is the safe one: debug off, TLS verification on, uploads small, origins empty. A deployment that forgets a variable gets the restrictive behaviour, and a deployment that forgets the *secret* does not start at all.

Three details worth keeping:

- \`parse_bool\` takes the default as an argument instead of hard-coding one, so the same parser serves a setting that defaults on and a setting that defaults off.
- The secret is never given a fallback and never interpolated into output — \`describe\` reports its *length*, which is enough to tell "wrong value" from "not set".
- Each parse helper raises with the offending value included, so a misconfiguration is diagnosable from the crash message alone — without printing the one value that must not be printed.`,
      },
      wrapup: `- \`None\` is "unset"; \`False\` is "set to false". Never let them collapse into each other.
- Every non-empty string is truthy. \`DEBUG=false\` enables debug if you test for truthiness.
- Use \`is None\`, never \`== None\`: identity cannot be overridden.
- Fail closed. The default for a security setting is the restrictive one, and a missing secret stops the process.`,
      refs: [
        { label: "Truth value testing", url: "https://docs.python.org/3/library/stdtypes.html#truth-value-testing" },
        { label: "CWE-798: Use of Hard-coded Credentials", url: "https://cwe.mitre.org/data/definitions/798.html" },
        { label: "The Twelve-Factor App — Config", url: "https://12factor.net/config" },
      ],
    },
  ],
};
