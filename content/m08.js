export default {
  id: "m08",
  number: 8,
  title: "Modules, environments and the supply chain",
  focus: "dependencies",
  subtitle:
    "Your code is a minority of what runs in production. This module covers the import system, virtual environments, pinning with hashes, and the attacks that target the packages rather than the program.",
  objectives: [
    "Explain how Python resolves an import and why `sys.path[0]` is a security concern.",
    "Create and use virtual environments, and read a lockfile critically.",
    "Pin dependencies by version and hash, and justify why both are needed.",
    "Recognise typosquatting, dependency confusion and install-time code execution.",
    "Load configuration and secrets from the environment, failing closed when they are absent.",
  ],
  rules: [
    { id: "PY-HARDCODED-SECRET", what: "credentials never live in source or in a repository" },
    { id: "PY-SECRET-FALLBACK", what: "a default credential hides the misconfiguration you needed to see" },
    { id: "PY-IMPORT-PICKLE", what: "importing a deserializer is a dependency on trust" },
  ],
  capstone:
    "Day 46 audits a requirements file: unpinned versions, missing hashes, a typosquatted name and a confusable internal package — reported with severities and a remediation.",

  lessons: [
    /* ----------------------------------------------------------------- 36 */
    {
      id: "m08l01",
      day: 42,
      title: "Imports, sys.path, and the module that shadows the real one",
      minutes: 60,
      secure: "import resolution order",
      cwe: ["CWE-427", "CWE-98"],
      tags: ["import", "sys.path", "modules", "packages", "shadowing"],
      lede:
        "Python searches a list of directories for every import, and the first match wins. The first entry on that list is usually the directory your script lives in.",
      blocks: [
        {
          t: "code",
          label: "example",
          code: `import json                      # a module
from pathlib import Path         # one name from a module
import numpy as np               # aliased
from . import helpers            # relative, inside a package

# at the bottom of a script, not the top:
if __name__ == "__main__":
    main()`,
          cap: "`__name__` is `\"__main__\"` when the file is run directly and the module's name when imported. Code outside that guard runs on *import*, which is why a module with side effects is a liability.",
        },
        {
          t: "p",
          md: `An import resolves by walking \`sys.path\` in order and taking the **first** match:

1. the script's own directory (or the current directory for \`python -c\` and the REPL),
2. \`PYTHONPATH\` entries,
3. the installation's site-packages.

A file named \`json.py\` beside your script therefore replaces the standard library's \`json\` for your entire process.`,
        },
        {
          t: "repl",
          lines: [
            ">>> import sys",
            ">>> sys.path[:3]",
            "['/srv/app', '/usr/lib/python313.zip', '/usr/lib/python3.13']",
            ">>> import secrets",
            ">>> secrets.__file__",
            "'/usr/lib/python3.13/secrets.py'",
          ],
        },
        {
          t: "box",
          kind: "cve",
          title: "Shadowing is an attack, not just a mistake",
          md: `If an attacker can write a file into a directory that appears early on \`sys.path\` — a world-writable deployment directory, a shared \`/tmp\` on the path, a repository where they can land a pull request — they control what \`import requests\` returns.

Historically this included the current working directory being on the path for \`python -c\` and for interactive use, which is why running tooling from inside an untrusted checkout is dangerous. Python 3.11+ offers \`-P\` and \`PYTHONSAFEPATH=1\` to omit the script directory.`,
        },
        { t: "h", text: "Modules run on import" },
        {
          t: "code",
          label: "vulnerable",
          code: `# analytics.py
import requests

requests.post("https://collector.example/ping",      # runs at import time
              json={"host": socket.gethostname()}, timeout=5)

def track(event):
    ...`,
          cap: "Importing this module sends a network request. Anything at module level — a connection, a file write, a `subprocess` call — happens the moment someone types `import analytics`.",
        },
        {
          t: "code",
          label: "fixed",
          code: `# analytics.py
import requests

COLLECTOR = "https://collector.example/ping"

def ping(hostname):
    """Nothing happens until a caller asks for it."""
    return requests.post(COLLECTOR, json={"host": hostname}, timeout=(3, 10))

if __name__ == "__main__":
    ping(socket.gethostname())`,
        },
        {
          t: "box",
          kind: "rule",
          title: "Module level is for definitions",
          md: `Constants, functions, classes, and nothing else. No I/O, no network, no \`subprocess\`, no credential reads.

Beyond the security argument, a module with import-time side effects cannot be tested, cannot be imported by a linter, and turns \`--help\` into a network call.`,
        },
        {
          t: "box",
          kind: "pitfall",
          title: "Circular imports and partial initialisation",
          md: `When \`a\` imports \`b\` and \`b\` imports \`a\`, one of them observes the other **half-initialised** — its constants defined up to the import line and nothing after.

A security module caught in a cycle can expose a partially built allowlist or an unset key. The fix is structural: move shared definitions into a third module that neither imports.`,
        },
      ],
      spot: {
        label: "deployment script",
        prompt: "Click the line that makes this script's behaviour depend on the directory it is run from.",
        lines: [4],
        why:
          "Line 4. Inserting the current working directory at the front of `sys.path` means any `.py` file in that directory shadows a real module — including `json`, `logging` or `requests`. If the directory is attacker-writable, this is code execution. Remove it and use a proper package install.",
        code: `import sys
import os

sys.path.insert(0, os.getcwd())

import config
import requests

def deploy():
    requests.post(config.URL, timeout=10)`,
      },
      quiz: [
        {
          q: "A file named `secrets.py` sits beside your script. What does `import secrets` give you?",
          options: [
            "The standard library module.",
            "Your local file — the script's directory comes first on `sys.path`.",
            "An ImportError about ambiguity.",
          ],
          answer: 1,
          why:
            "First match wins. This is why a file named after a stdlib module is a bug, and why an attacker-writable directory early on the path is code execution.",
        },
        {
          q: "Why keep I/O out of module level?",
          options: [
            "Style.",
            "Module-level code runs on import, so merely importing performs the action — including in tests, linters and `--help`.",
            "Python forbids it.",
          ],
          answer: 1,
          why: "Imports should be free of effects. A module that connects to a database when imported cannot be reasoned about.",
        },
        {
          q: "`if __name__ == \"__main__\":` exists to:",
          options: [
            "Speed up imports.",
            "Separate 'run as a program' from 'imported as a library'.",
            "Define the entry point for the interpreter.",
          ],
          answer: 1,
          why: "Without it, importing the module executes the program.",
        },
      ],
      exercise: {
        title: "An import auditor",
        brief: `Write a static checker that reads Python source text and reports import hygiene problems. Use the \`ast\` module — not regular expressions.

\`audit_imports(source)\` returns a list of dicts \`{"rule": ..., "line": ..., "name": ...}\`, sorted by line, for these rules:

| rule | fires when |
|---|---|
| \`"stdlib-shadow"\` | a module-level assignment or function/class definition uses a name that is also a standard-library module from the provided \`STDLIB\` set (e.g. defining \`json = ...\` or \`def secrets(): ...\`) |
| \`"import-side-effect"\` | a module-level **call** statement appears outside any function, class or \`if __name__\` guard (e.g. a bare \`requests.post(...)\` at top level) |
| \`"star-import"\` | \`from x import *\` |
| \`"path-manipulation"\` | a call to \`sys.path.insert\` or \`sys.path.append\` |

\`name\` is the offending identifier: the shadowed name, the called function's dotted name, the module for a star import, or \`"sys.path"\`.

A call inside \`if __name__ == "__main__":\` is **not** a side effect. A call used as part of an assignment at module level (\`X = compute()\`) is also not reported — only bare expression statements.`,
        rubric: [
          "Detects a module-level bare call, but not one inside a function or the main guard",
          "Detects assignments/definitions shadowing a stdlib name",
          "Detects `import *` and `sys.path` manipulation",
          "Uses `ast`, not regexes",
          "Results are sorted by line and never raise on unusual input",
        ],
        starter: `import ast

STDLIB = frozenset({"json", "secrets", "os", "sys", "re", "hashlib", "hmac",
                    "logging", "random", "socket", "time", "types", "copy"})


def audit_imports(source):
    """Return a sorted list of import-hygiene findings."""


SAMPLE = '''
import sys
sys.path.insert(0, ".")
from os.path import *

json = {"a": 1}

def handler():
    send()

send_telemetry()

if __name__ == "__main__":
    main()
'''
for f in audit_imports(SAMPLE):
    print(f["line"], f["rule"], f["name"])
`,
        stdin: [],
        tests: [
          {
            name: "finds a module-level bare call",
            code: `src = "import requests\\nrequests.post('https://x.example')\\n"
got = audit_imports(src)
assert any(f["rule"] == "import-side-effect" and f["name"] == "requests.post" for f in got), f"got {got!r}"`,
          },
          {
            name: "ignores calls inside functions and the main guard",
            code: `src = ("def f():\\n    send()\\n\\n"
       "class C:\\n    def m(self):\\n        send()\\n\\n"
       "if __name__ == '__main__':\\n    main()\\n")
got = [f for f in audit_imports(src) if f["rule"] == "import-side-effect"]
assert got == [], f"false positives: {got!r}"`,
          },
          {
            name: "ignores calls that produce a value",
            code: `src = "VALUE = compute()\\nITEMS = [build(i) for i in range(3)]\\n"
got = [f for f in audit_imports(src) if f["rule"] == "import-side-effect"]
assert got == [], f"assignments are not side effects: {got!r}"`,
          },
          {
            name: "detects stdlib shadowing by assignment and by def",
            code: `src = "json = {'a': 1}\\n\\ndef secrets():\\n    pass\\n\\nclass logging:\\n    pass\\n"
got = audit_imports(src)
names = {f["name"] for f in got if f["rule"] == "stdlib-shadow"}
assert names == {"json", "secrets", "logging"}, f"got {names!r}"`,
          },
          {
            name: "does not flag a local variable with a stdlib name",
            code: `src = "def f():\\n    json = 1\\n    return json\\n"
got = [f for f in audit_imports(src) if f["rule"] == "stdlib-shadow"]
assert got == [], f"only module level matters: {got!r}"`,
          },
          {
            name: "detects star imports and path manipulation",
            code: `src = "import sys\\nfrom os.path import *\\nsys.path.insert(0, '.')\\nsys.path.append('/tmp')\\n"
got = audit_imports(src)
rules = [(f["rule"], f["name"]) for f in got]
assert ("star-import", "os.path") in rules, f"got {rules!r}"
assert rules.count(("path-manipulation", "sys.path")) == 2, f"got {rules!r}"`,
          },
          {
            name: "results are sorted by line",
            code: `src = "import sys\\njson = 1\\nsys.path.append('.')\\nsend()\\n"
got = audit_imports(src)
lines = [f["line"] for f in got]
assert lines == sorted(lines), f"not sorted: {lines!r}"
assert all(isinstance(f["line"], int) and f["line"] > 0 for f in got)`,
          },
          {
            name: "clean code produces no findings, bad syntax does not crash",
            code: `clean = "import json\\n\\nDEFAULT = 3\\n\\ndef run(x):\\n    return json.dumps(x)\\n\\nif __name__ == '__main__':\\n    run({})\\n"
assert audit_imports(clean) == [], f"false positives: {audit_imports(clean)!r}"
assert audit_imports("def broken(:") == [], "a syntax error should produce no findings, not an exception"`,
          },
        ],
        requirements: [
          { kind: "defines", value: "audit_imports" },
          { kind: "uses_module", value: "ast" },
          { kind: "forbids_module", value: "re", message: "Parse the code with `ast`; regexes cannot tell a string from a statement." },
        ],
        hints: [
          "`tree = ast.parse(source)` inside a `try/except SyntaxError: return []`. Then iterate `tree.body` — that is module level, and nothing nested appears there.",
          "A bare call is `ast.Expr` whose `.value` is an `ast.Call`. An assignment is `ast.Assign`, so iterating only `tree.body` and checking for `Expr` handles the 'produces a value' rule for free.",
          "To skip the main guard, check for `ast.If` nodes at module level and simply do not recurse into them — module-level iteration without recursion gives you that automatically.",
          "`sys.path.insert` as an AST is `Attribute(attr='insert', value=Attribute(attr='path', value=Name(id='sys')))`. Walk the whole tree for these, since they may appear inside a function too.",
        ],
        solution: `import ast

STDLIB = frozenset({"json", "secrets", "os", "sys", "re", "hashlib", "hmac",
                    "logging", "random", "socket", "time", "types", "copy"})


def _dotted(node):
    """Return the dotted name of a Name/Attribute chain, else ''."""
    parts = []
    while isinstance(node, ast.Attribute):
        parts.append(node.attr)
        node = node.value
    if isinstance(node, ast.Name):
        parts.append(node.id)
        return ".".join(reversed(parts))
    return ""


def audit_imports(source):
    """Return a sorted list of import-hygiene findings."""
    try:
        tree = ast.parse(source)
    except SyntaxError:
        return []

    findings = []

    def report(rule, node, name):
        findings.append({"rule": rule, "line": node.lineno, "name": name})

    # --- module level only: shadowing and bare calls ---------------------
    for node in tree.body:
        if isinstance(node, ast.Expr) and isinstance(node.value, ast.Call):
            report("import-side-effect", node, _dotted(node.value.func) or "<call>")

        elif isinstance(node, ast.Assign):
            for target in node.targets:
                if isinstance(target, ast.Name) and target.id in STDLIB:
                    report("stdlib-shadow", node, target.id)

        elif isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef, ast.ClassDef)):
            if node.name in STDLIB:
                report("stdlib-shadow", node, node.name)

    # --- anywhere: star imports and path manipulation --------------------
    for node in ast.walk(tree):
        if isinstance(node, ast.ImportFrom):
            if any(alias.name == "*" for alias in node.names):
                report("star-import", node, node.module or "")

        elif isinstance(node, ast.Call):
            target = _dotted(node.func)
            if target in ("sys.path.insert", "sys.path.append", "sys.path.extend"):
                report("path-manipulation", node, "sys.path")

    findings.sort(key=lambda f: (f["line"], f["rule"]))
    return findings


SAMPLE = '''
import sys
sys.path.insert(0, ".")
from os.path import *

json = {"a": 1}

def handler():
    send()

send_telemetry()

if __name__ == "__main__":
    main()
'''
for f in audit_imports(SAMPLE):
    print(f["line"], f["rule"], f["name"])`,
        why: `Two different traversals, because the two kinds of rule have different scopes.

**Iterating \`tree.body\` directly** is what makes "module level" precise. Nothing inside a function, a class or an \`if\` block appears there, so calls in \`handler()\` and inside the \`__main__\` guard are excluded without a single special case — and a local variable named \`json\` is invisible, which is correct, since shadowing only matters at the scope where imports resolve.

**\`ast.walk\`** is right for star imports and \`sys.path\` manipulation, because those are dangerous wherever they appear. A \`sys.path.insert\` hidden inside a function is *more* suspicious than one at the top, not less.

Parsing rather than pattern-matching is the point of the exercise. A regex for \`sys.path.insert\` matches the string \`"call sys.path.insert to fix imports"\` in a docstring, and misses \`path = sys.path; path.insert(0, x)\`. The AST knows the difference between a statement and a mention, which is the same reason the course's own auditor is built this way.

Returning \`[]\` on a \`SyntaxError\` is a deliberate choice for a linting tool: a file that does not parse is a problem for the compiler to report, not for this checker to crash on. Note the trade-off — a scanner that silently skips unparseable files can be evaded by a file that is valid for a different Python version, so a real tool would surface the skip rather than hide it.`,
      },
      wrapup: `- Imports resolve by first match on \`sys.path\`; the script's directory is usually first.
- A file named after a stdlib module replaces it for the whole process.
- Module level is for definitions only — anything else runs on import.
- Never \`sys.path.insert\` a directory you do not control.`,
      refs: [
        { label: "The import system", url: "https://docs.python.org/3/reference/import.html" },
        { label: "CWE-427: Uncontrolled Search Path Element", url: "https://cwe.mitre.org/data/definitions/427.html" },
      ],
    },

    /* ----------------------------------------------------------------- 37 */
    {
      id: "m08l02",
      day: 43,
      title: "Virtual environments, pinning, and hashes",
      minutes: 60,
      secure: "reproducible installs",
      cwe: ["CWE-1104", "CWE-494"],
      tags: ["venv", "pip", "requirements", "pinning", "hashes", "sbom"],
      lede:
        "A version range says *anything that satisfies this*. A hash says *exactly these bytes*. Only one of them survives a compromised package index.",
      blocks: [
        {
          t: "code",
          label: "example",
          code: `python3 -m venv .venv
source .venv/bin/activate          # Windows: .venv\\Scripts\\activate
python -m pip install --upgrade pip
python -m pip install requests
python -m pip freeze > requirements.txt
deactivate`,
          cap: "A virtual environment isolates dependencies per project. Without it, two projects share one site-packages and an upgrade for one silently changes the other.",
        },
        {
          t: "table",
          head: ["Specifier", "Means", "Reproducible?"],
          rows: [
            ["`requests`", "anything, now or ever", "**No**"],
            ["`requests>=2.0`", "any future version", "**No**"],
            ["`requests~=2.31.0`", "2.31.x", "Partly"],
            ["`requests==2.31.0`", "that version", "Mostly — the *contents* could still change"],
            ["`requests==2.31.0 --hash=sha256:...`", "exactly those bytes", "**Yes**"],
          ],
        },
        {
          t: "box",
          kind: "rule",
          title: "Pin the version in applications, range it in libraries",
          md: `- **An application** you deploy: pin exactly, with hashes. You control the environment, and reproducibility beats convenience.
- **A library** others install: use ranges (\`>=2.0,<3\`), or you force your constraints onto every consumer and cause unresolvable conflicts.

Do not confuse the two. A pinned library is a bad citizen; an unpinned application is a different build every deploy.`,
        },
        {
          t: "code",
          label: "fixed",
          code: `# requirements.txt -- generated by pip-compile --generate-hashes
requests==2.31.0 \\
    --hash=sha256:58cd2187c01e70e6e26505bca751777aa9f2ee0b7f4300988b709f44e013003f \\
    --hash=sha256:942c5a758f98d790eaed1a29cb6eefc7ffb0d1cf7af05c3d2791656dbd6ad1e1
urllib3==2.1.0 \\
    --hash=sha256:55901e917a5896a349ff771be919f8bd99aff186cb2e1ee03b2c2a45b55b63c8`,
          cap: "`pip install --require-hashes -r requirements.txt` then refuses anything whose bytes do not match — including a package the index was tricked into serving.",
        },
        {
          t: "box",
          kind: "cve",
          title: "Why the hash and not just the version",
          md: `PyPI deletes and re-uploads are restricted, but version pinning alone has failed in practice elsewhere: a maintainer account compromise, a mirror serving different bytes, or a transparent proxy injecting content. The hash makes the artifact self-verifying regardless of what the index says.

The 2021 \`ua-parser-js\` and 2018 \`event-stream\` incidents in npm, and the \`ctx\` package takeover on PyPI in 2022, were all *version-satisfying* installs of hostile code.`,
        },
        { t: "h", text: "Packages run code at install time" },
        {
          t: "p",
          md: `\`setup.py\` executes during installation of a source distribution. That is arbitrary code, running with your user's privileges, before a single line of your program has been imported. Wheels (\`.whl\`) do not execute setup code, which is one reason \`--only-binary\` is a hardening measure.`,
        },
        {
          t: "code",
          label: "fixed",
          code: `python -m pip install \\
    --require-hashes \\
    --only-binary :all: \\
    --no-deps \\
    -r requirements.txt`,
          cap: "`--require-hashes` verifies bytes, `--only-binary` avoids executing setup.py, `--no-deps` ensures the lockfile is the complete list rather than a starting point.",
        },
        {
          t: "box",
          kind: "good",
          title: "What a lockfile is for",
          md: `\`requirements.txt\` from \`pip freeze\` captures what you happen to have installed. A **lockfile** produced by \`pip-compile\`, \`uv\`, \`poetry\` or \`pdm\` captures the full resolved graph including transitive dependencies, with hashes.

The practical test: can a colleague reproduce your exact environment from the repository, on a different machine, next year? If the answer involves "it depends what version resolves", you do not have a lockfile.`,
        },
      ],
      quiz: [
        {
          q: "Why add hashes when the version is already pinned?",
          options: [
            "Faster installs.",
            "The hash verifies the bytes, so a compromised index or mirror cannot serve different content for that version.",
            "Hashes are required by pip.",
          ],
          answer: 1,
          why: "A version is a label the index controls; a hash is a property of the artifact. Only the second is tamper-evident.",
        },
        {
          q: "Should a library pin its dependencies exactly?",
          options: [
            "Yes, always.",
            "No — ranges let consumers resolve; pinning in a library causes unresolvable conflicts.",
            "Only for major versions.",
          ],
          answer: 1,
          why: "Applications pin, libraries range. A pinned library forces its constraints on everything else in the environment.",
        },
        {
          q: "What does `--only-binary :all:` protect against?",
          options: [
            "Slow downloads.",
            "`setup.py` from a source distribution executing arbitrary code at install time.",
            "Version conflicts.",
          ],
          answer: 1,
          why: "Wheels are data; sdists run code during installation, with your privileges, before your program starts.",
        },
      ],
      exercise: {
        title: "A requirements-file auditor",
        brief: `Write \`audit_requirements(text)\` returning a list of findings sorted by line number.

Each line of a requirements file is one of: a comment (\`#...\`), blank, a pip option (starts with \`-\`), or a requirement. A requirement may be followed by \`--hash=sha256:...\` entries on the same logical line (continuations with a trailing \`\\\` have already been joined for you — treat each input line as complete).

Report \`{"line": n, "package": name, "rule": ..., "severity": ...}\` for:

| rule | severity | fires when |
|---|---|---|
| \`"unpinned"\` | \`"high"\` | no \`==\` in the specifier (bare name, \`>=\`, \`~=\`, \`<\`) |
| \`"no-hash"\` | \`"medium"\` | pinned with \`==\` but no \`--hash=\` present |
| \`"url-install"\` | \`"high"\` | the line contains \`http://\` or \`https://\` or starts with \`git+\` |
| \`"local-path"\` | \`"medium"\` | the requirement is a path (starts with \`.\` or \`/\`) |

\`package\` is the lower-cased name up to the first of \` <>=!~[;\` characters, or the whole token for URLs/paths.

Also write \`summary(findings)\` returning \`{"high": n, "medium": n}\` counts.`,
        rubric: [
          "Comments, blanks and option lines are ignored",
          "`==` without a hash is medium; no `==` at all is high",
          "URL and local-path installs are reported",
          "Package names are extracted and lower-cased, extras stripped",
          "Findings are sorted by line; `summary` counts by severity",
        ],
        starter: `def audit_requirements(text):
    """Return a sorted list of findings about a requirements file."""


def summary(findings):
    """Return {'high': n, 'medium': n}."""


SAMPLE = """# production deps
requests
flask==3.0.0
urllib3==2.1.0 --hash=sha256:55901e917a5896a349ff771be919f8bd99aff186cb2e1ee03b2c2a45b55b63c8
./vendor/internal-lib
https://example.com/pkg-1.0.tar.gz
-r base.txt
"""
for f in audit_requirements(SAMPLE):
    print(f["line"], f["severity"], f["rule"], f["package"])
print(summary(audit_requirements(SAMPLE)))
`,
        stdin: [],
        tests: [
          {
            name: "ignores comments, blanks and options",
            code: `text = "# a comment\\n\\n-r base.txt\\n--index-url https://pypi.org/simple\\n"
assert audit_requirements(text) == [], f"got {audit_requirements(text)!r}"`,
          },
          {
            name: "unpinned requirements are high",
            code: `text = "requests\\nflask>=2.0\\nurllib3~=2.1.0\\ndjango<5\\n"
got = audit_requirements(text)
assert len(got) == 4, f"got {got!r}"
assert all(f["rule"] == "unpinned" and f["severity"] == "high" for f in got), f"got {got!r}"
assert [f["package"] for f in got] == ["requests", "flask", "urllib3", "django"], f"got {got!r}"`,
          },
          {
            name: "pinned without a hash is medium",
            code: `text = "flask==3.0.0\\n"
got = audit_requirements(text)
assert len(got) == 1 and got[0]["rule"] == "no-hash" and got[0]["severity"] == "medium", f"got {got!r}"`,
          },
          {
            name: "pinned with a hash is clean",
            code: `text = "urllib3==2.1.0 --hash=sha256:55901e917a5896a349ff771be919f8bd99aff186cb2e1ee03b2c2a45b55b63c8\\n"
assert audit_requirements(text) == [], f"got {audit_requirements(text)!r}"`,
          },
          {
            name: "url and git installs are high",
            code: `text = "https://example.com/pkg-1.0.tar.gz\\ngit+https://github.com/x/y.git@main\\nhttp://internal/pkg.whl\\n"
got = audit_requirements(text)
assert len(got) == 3, f"got {got!r}"
assert all(f["rule"] == "url-install" and f["severity"] == "high" for f in got), f"got {got!r}"`,
          },
          {
            name: "local paths are medium",
            code: `text = "./vendor/internal-lib\\n/opt/pkgs/thing\\n"
got = audit_requirements(text)
assert len(got) == 2 and all(f["rule"] == "local-path" for f in got), f"got {got!r}"
assert all(f["severity"] == "medium" for f in got)`,
          },
          {
            name: "names are normalised",
            code: `text = "Requests[security]>=2.0\\nFlask==3.0.0\\nUrlLib3==2.0.0; python_version>'3.8'\\n"
got = audit_requirements(text)
assert [f["package"] for f in got] == ["requests", "flask", "urllib3"], f"got {got!r}"`,
          },
          {
            name: "sorted, and summarised by severity",
            code: `text = "requests\\nflask==3.0.0\\n./local\\nhttps://x.example/p.tar.gz\\n"
got = audit_requirements(text)
assert [f["line"] for f in got] == [1, 2, 3, 4], f"got {[f['line'] for f in got]!r}"
assert summary(got) == {"high": 2, "medium": 2}, f"got {summary(got)!r}"
assert summary([]) == {"high": 0, "medium": 0}`,
          },
        ],
        requirements: [
          { kind: "defines", value: "audit_requirements" },
          { kind: "defines", value: "summary" },
        ],
        hints: [
          "Loop with `enumerate(text.splitlines(), start=1)` so line numbers are 1-based and match what an editor shows.",
          "Order the checks: skip blanks/comments/options first, then URL, then local path, then `==` and hash. The first match wins, so a URL line is never also reported as unpinned.",
          "Extract the name by splitting the first token on the first character in `<>=!~[; `: a small loop or `re.split` both work — but note the requirement forbids nothing here, so plain string work is fine.",
          "A line starting with `-` is a pip option, *except* that `--hash` only ever appears after a requirement on the same line, so checking `line.startswith(\"-\")` on the stripped line is safe.",
        ],
        solution: `SPLIT_CHARS = "<>=!~[; "


def _package_name(token):
    """Take the distribution name off the front of a requirement token."""
    for index, char in enumerate(token):
        if char in SPLIT_CHARS:
            return token[:index].lower()
    return token.lower()


def audit_requirements(text):
    """Return a sorted list of findings about a requirements file."""
    findings = []

    for number, raw in enumerate(text.splitlines(), start=1):
        line = raw.strip()

        if not line or line.startswith("#") or line.startswith("-"):
            continue

        token = line.split()[0]

        if "http://" in line or "https://" in line or token.startswith("git+"):
            rule, severity, name = "url-install", "high", token
        elif token.startswith(".") or token.startswith("/"):
            rule, severity, name = "local-path", "medium", token
        elif "==" not in line:
            rule, severity, name = "unpinned", "high", _package_name(token)
        elif "--hash=" not in line:
            rule, severity, name = "no-hash", "medium", _package_name(token)
        else:
            continue

        findings.append({"line": number, "package": name, "rule": rule, "severity": severity})

    findings.sort(key=lambda f: f["line"])
    return findings


def summary(findings):
    """Return {'high': n, 'medium': n}."""
    counts = {"high": 0, "medium": 0}
    for finding in findings:
        if finding["severity"] in counts:
            counts[finding["severity"]] += 1
    return counts


SAMPLE = """# production deps
requests
flask==3.0.0
urllib3==2.1.0 --hash=sha256:55901e917a5896a349ff771be919f8bd99aff186cb2e1ee03b2c2a45b55b63c8
./vendor/internal-lib
https://example.com/pkg-1.0.tar.gz
-r base.txt
"""
for f in audit_requirements(SAMPLE):
    print(f["line"], f["severity"], f["rule"], f["package"])
print(summary(audit_requirements(SAMPLE)))`,
        why: `The rule order encodes the severity reasoning. A URL install is checked before pinning because \`https://example.com/pkg.tar.gz\` has no version to pin — reporting it as "unpinned" would be true but useless, and would hide the more important fact that the artifact comes from outside the index entirely.

The two severities map to two different threats:

- **high** — the *identity* of the code is not fixed. An unpinned requirement installs whatever exists at build time; a URL install trusts a host that is not the package index and usually has no signature at all.
- **medium** — the identity is fixed but not *verified*. A pinned version without a hash is reproducible as long as nobody tampers with the index or the mirror.

Name normalisation matters more than it looks. PyPI treats names case-insensitively and folds \`-\`/\`_\`/\`.\`, so \`Flask\`, \`flask\` and \`FLASK\` are one package. An auditor that reports them as three makes its own output unusable for deduplication — and the next lesson's typosquatting check depends on comparing normalised names.

What this tool deliberately does not do is resolve the dependency graph. It reports on the file as written, which is the right scope for a pre-commit check: transitive dependencies are the lockfile's job, and a tool that silently needs network access is a tool that gets disabled in CI.`,
      },
      wrapup: `- One virtual environment per project; never install into the system interpreter.
- Applications pin exactly with hashes; libraries declare ranges.
- \`--require-hashes --only-binary :all:\` verifies bytes and avoids install-time code execution.
- A lockfile covers the full transitive graph, not just what you happen to have installed.`,
      refs: [
        { label: "pip — secure installs", url: "https://pip.pypa.io/en/stable/topics/secure-installs/" },
        { label: "Python Packaging User Guide", url: "https://packaging.python.org/en/latest/guides/installing-using-pip-and-virtual-environments/" },
        { label: "CWE-1104: Use of Unmaintained Third Party Components", url: "https://cwe.mitre.org/data/definitions/1104.html" },
      ],
    },

    /* ----------------------------------------------------------------- 38 */
    {
      id: "m08l03",
      day: 44,
      title: "Typosquatting and dependency confusion",
      minutes: 60,
      secure: "package name trust",
      cwe: ["CWE-427", "CWE-1357"],
      tags: ["typosquat", "dependency-confusion", "supply-chain", "index"],
      lede:
        "Two attacks that need no vulnerability in your code: publish a package with a name close to the one you wanted, or with the same name as one of your private ones and a higher version number.",
      blocks: [
        { t: "h", text: "Typosquatting" },
        {
          t: "p",
          md: `The attacker registers a name a developer might type by mistake, then publishes a package that does its advertised job *and* exfiltrates environment variables at import time.

Real PyPI examples have included names differing by a transposition (\`reqeusts\`), a missing or added character (\`python-dateutil\` vs \`python3-dateutil\`), a hyphen/underscore swap, or a plausible-sounding prefix (\`python-\`, \`py-\`).`,
        },
        {
          t: "table",
          head: ["Real package", "Observed squat", "Trick"],
          rows: [
            ["`requests`", "`request`, `reqeusts`", "missing letter, transposition"],
            ["`urllib3`", "`urlib3`", "missing letter"],
            ["`python-dateutil`", "`python3-dateutil`", "plausible prefix"],
            ["`colorama`", "`colourama`", "spelling variant"],
            ["`beautifulsoup4`", "`beautifulsoup`", "dropped suffix"],
          ],
        },
        {
          t: "box",
          kind: "cve",
          title: "`ctx`, 2022",
          md: `The \`ctx\` package on PyPI — a small, popular utility — was taken over through an expired maintainer domain. The new version exfiltrated every environment variable to a remote host. Because it was a legitimate name with a legitimate history, pinning the *name* was no protection; only pinning the version **with a hash** would have been.`,
        },
        { t: "h", text: "Dependency confusion" },
        {
          t: "p",
          md: `Your company has an internal package \`acme-payments\` on a private index. Someone registers \`acme-payments\` on public PyPI with version \`99.0.0\`.

Many installers, when given both a private index and the public one, resolve across **both** and take the highest version. Your build now installs the attacker's package — with no typo and no compromise of your systems.`,
        },
        {
          t: "code",
          label: "vulnerable",
          code: `# pip.conf
[global]
index-url = https://pypi.org/simple
extra-index-url = https://pypi.internal.acme.com/simple`,
          cap: "`extra-index-url` means \"search both and pick the best version\". That is the whole vulnerability.",
        },
        {
          t: "code",
          label: "fixed",
          code: `# pip.conf
[global]
index-url = https://pypi.internal.acme.com/simple   # the ONLY index
# the internal index proxies and caches public packages itself`,
          cap: "One index. Internal names resolve internally; public packages are proxied through it, so there is no second resolver to confuse.",
        },
        {
          t: "box",
          kind: "rule",
          title: "Four mitigations, in order of effectiveness",
          md: `1. **One index.** A single private index that proxies the public one removes the ambiguity entirely.
2. **Hashes.** \`--require-hashes\` fails the build when the bytes differ, whatever the index served.
3. **Namespace your internal names.** Register the prefix publicly (or use a scope) so nobody else can claim it.
4. **Verify names at review time.** Character-level similarity to popular packages is a cheap automated check.`,
        },
        {
          t: "box",
          kind: "good",
          title: "Levenshtein distance in eight lines",
          md: `Edit distance — the number of single-character insertions, deletions or substitutions needed to turn one string into another — catches most squats. A distance of 1 from a very popular package, with a different name, is worth a human look.

The exercise below builds it. It is a classic dynamic-programming routine and worth being able to write from memory.`,
        },
      ],
      quiz: [
        {
          q: "Why is `extra-index-url` dangerous for internal packages?",
          options: [
            "It is slower.",
            "Resolution happens across both indexes and the highest version wins, so a public package can shadow a private one.",
            "It disables TLS.",
          ],
          answer: 1,
          why: "Dependency confusion. Use a single index that proxies the public one.",
        },
        {
          q: "A pinned version of a package whose maintainer account was taken over — are you safe?",
          options: [
            "Yes, the version is pinned.",
            "Only if you also pinned hashes; a new release does not change your pin, but a re-upload or a mirror could change the bytes.",
            "No, pinning is useless.",
          ],
          answer: 1,
          why:
            "Version pinning stops you from picking up the *new* malicious version, which is most of the benefit. Hashes close the remaining gap where the bytes behind your pinned version are not the ones you reviewed.",
        },
        {
          q: "Which single change removes dependency confusion entirely?",
          options: [
            "Pinning versions.",
            "Using one index that proxies the public one.",
            "Reviewing package names.",
          ],
          answer: 1,
          why: "The attack requires two resolvers to disagree. One index means there is nothing to confuse.",
        },
      ],
      exercise: {
        title: "A package-name risk checker",
        brief: `Write a checker that flags names worth a second look before they enter a lockfile.

1. \`edit_distance(a, b)\` — classic Levenshtein distance (insert/delete/substitute, each cost 1). \`edit_distance("", "abc") == 3\`, \`edit_distance("abc", "abc") == 0\`.
2. \`normalise(name)\` — PEP 503 normalisation: lower-case and collapse runs of \`-\`, \`_\` and \`.\` into a single \`-\`.
3. \`check_name(name, popular, internal_prefixes=())\` returning a list of findings sorted by severity (\`"high"\` before \`"medium"\`), each \`{"rule":..., "severity":..., "detail":...}\`:
   - \`"exact-match"\` / severity \`"ok"\`: the normalised name is in \`popular\` → return \`[]\` (no findings at all; it *is* the real package).
   - \`"typosquat"\` / \`"high"\`: edit distance 1 or 2 from any popular name. \`detail\` is the popular name it resembles (choose the smallest distance; ties broken alphabetically).
   - \`"confusable-internal"\` / \`"high"\`: the name starts with one of \`internal_prefixes\` (after normalisation) — such a name must come from the private index, so seeing it in a public requirements file is a confusion risk.
   - \`"unusual-separator"\` / \`"medium"\`: the raw name contains \`_\` or \`.\` (normalisation changes it), which is how \`python_dateutil\` and \`python-dateutil\` end up looking like two packages.`,
        rubric: [
          "`edit_distance` is correct for empty strings, equal strings and real pairs",
          "`normalise` follows PEP 503",
          "An exact popular name returns no findings",
          "Distance 1–2 is flagged with the closest popular name",
          "Internal prefixes and unusual separators are flagged",
          "Findings are ordered high before medium",
        ],
        starter: `POPULAR = frozenset({"requests", "urllib3", "numpy", "flask", "django",
                     "python-dateutil", "colorama", "beautifulsoup4", "pyyaml"})


def edit_distance(a, b):
    """Levenshtein distance between two strings."""


def normalise(name):
    """PEP 503 name normalisation."""


def check_name(name, popular=POPULAR, internal_prefixes=()):
    """Return findings about a package name."""


for candidate in ("requests", "reqeusts", "python_dateutil", "acme-payments"):
    print(candidate, check_name(candidate, internal_prefixes=("acme-",)))
`,
        stdin: [],
        tests: [
          {
            name: "edit distance basics",
            code: `assert edit_distance("", "") == 0
assert edit_distance("abc", "abc") == 0
assert edit_distance("", "abc") == 3
assert edit_distance("abc", "") == 3
assert edit_distance("kitten", "sitting") == 3
assert edit_distance("requests", "reqeusts") == 2
assert edit_distance("urllib3", "urlib3") == 1
assert edit_distance("flask", "flsak") == 2`,
          },
          {
            name: "edit distance is symmetric",
            code: `for a, b in (("abc", "abd"), ("requests", "request"), ("", "x")):
    assert edit_distance(a, b) == edit_distance(b, a), f"asymmetric for {a!r}/{b!r}"`,
          },
          {
            name: "PEP 503 normalisation",
            code: `assert normalise("Flask") == "flask"
assert normalise("python_dateutil") == "python-dateutil"
assert normalise("zope.interface") == "zope-interface"
assert normalise("A__B--C") == "a-b-c"
assert normalise("requests") == "requests"`,
          },
          {
            name: "the real package produces no findings",
            code: `for name in ("requests", "Requests", "python_dateutil", "PyYAML"):
    assert check_name(name) == [], f"{name!r} is legitimate but got {check_name(name)!r}"`,
          },
          {
            name: "near-misses are flagged with the closest match",
            code: `got = check_name("reqeusts")
assert any(f["rule"] == "typosquat" and f["severity"] == "high" for f in got), f"got {got!r}"
assert got[0]["detail"] == "requests", f"got {got!r}"
got = check_name("urlib3")
assert got and got[0]["detail"] == "urllib3", f"got {got!r}"`,
          },
          {
            name: "distant names are not flagged as squats",
            code: `for name in ("tensorflow", "sqlalchemy", "cryptography"):
    rules = [f["rule"] for f in check_name(name)]
    assert "typosquat" not in rules, f"{name!r} should not look like a squat: {rules!r}"`,
          },
          {
            name: "internal prefixes are high",
            code: `got = check_name("acme-payments", internal_prefixes=("acme-", "corp-"))
assert any(f["rule"] == "confusable-internal" and f["severity"] == "high" for f in got), f"got {got!r}"
assert check_name("requests", internal_prefixes=("acme-",)) == []`,
          },
          {
            name: "unusual separators are medium and ordered last",
            code: `got = check_name("colour_ama", internal_prefixes=())
rules = [f["rule"] for f in got]
assert "unusual-separator" in rules, f"got {got!r}"
sevs = [f["severity"] for f in got]
assert sevs == sorted(sevs, key=lambda s: {"high": 0, "medium": 1}[s]), f"not ordered: {sevs!r}"`,
          },
        ],
        requirements: [
          { kind: "defines", value: "edit_distance" },
          { kind: "defines", value: "normalise" },
          { kind: "defines", value: "check_name" },
        ],
        hints: [
          "Levenshtein with two rows: `prev = list(range(len(b) + 1))`, then for each character of `a` build `cur` from `prev`. Memory stays O(len(b)) instead of O(n*m).",
          "Normalisation is one regex in the real spec (`re.sub(r\"[-_.]+\", \"-\", name).lower()`), but a loop works equally well — collapse runs, do not just replace each character.",
          "Check the exact match first and return `[]` immediately: a legitimate package must never be reported, and that early return is what guarantees it.",
          "For the closest popular name, build `(distance, popular_name)` tuples and take `min(...)` — tuple comparison breaks ties alphabetically for free.",
        ],
        solution: `import re

POPULAR = frozenset({"requests", "urllib3", "numpy", "flask", "django",
                     "python-dateutil", "colorama", "beautifulsoup4", "pyyaml"})

SEVERITY_ORDER = {"high": 0, "medium": 1}


def edit_distance(a, b):
    """Levenshtein distance between two strings."""
    if a == b:
        return 0
    if not a:
        return len(b)
    if not b:
        return len(a)

    previous = list(range(len(b) + 1))
    for i, ch_a in enumerate(a, start=1):
        current = [i]
        for j, ch_b in enumerate(b, start=1):
            cost = 0 if ch_a == ch_b else 1
            current.append(min(
                previous[j] + 1,          # deletion
                current[j - 1] + 1,       # insertion
                previous[j - 1] + cost,   # substitution
            ))
        previous = current
    return previous[-1]


def normalise(name):
    """PEP 503 name normalisation."""
    return re.sub(r"[-_.]+", "-", str(name)).lower()


def check_name(name, popular=POPULAR, internal_prefixes=()):
    """Return findings about a package name."""
    canonical = normalise(name)

    # The genuine article: never report it.
    if canonical in popular:
        return []

    findings = []

    closest = min(((edit_distance(canonical, p), p) for p in popular), default=None)
    if closest and 1 <= closest[0] <= 2:
        findings.append({
            "rule": "typosquat",
            "severity": "high",
            "detail": closest[1],
        })

    for prefix in internal_prefixes:
        if canonical.startswith(normalise(prefix)):
            findings.append({
                "rule": "confusable-internal",
                "severity": "high",
                "detail": f"internal prefix {prefix!r} must resolve from the private index",
            })
            break

    if canonical != str(name).lower():
        findings.append({
            "rule": "unusual-separator",
            "severity": "medium",
            "detail": f"{name!r} normalises to {canonical!r}",
        })

    findings.sort(key=lambda f: SEVERITY_ORDER[f["severity"]])
    return findings


for candidate in ("requests", "reqeusts", "python_dateutil", "acme-payments"):
    print(candidate, check_name(candidate, internal_prefixes=("acme-",)))`,
        why: `The early return for an exact match is the most important line. A checker that reports false positives on \`requests\` and \`python-dateutil\` gets switched off within a week, and a switched-off check protects nothing. Normalising first is what makes that early return reliable: \`PyYAML\`, \`pyyaml\` and \`py-yaml\` are the same package to PyPI, and must be the same package here.

The distance window of 1–2 is a deliberate trade. Distance 1 catches \`urlib3\` and \`request\`; distance 2 catches transpositions like \`reqeusts\`, which are two substitutions. Widening it to 3 starts matching genuinely unrelated short names — \`flask\` and \`flask-cors\` are distance 5, but \`numpy\` and \`numba\` are distance 2, which is exactly the kind of case a human should see rather than a build should block. That is why the output is a *finding* rather than a refusal.

\`min()\` over \`(distance, name)\` tuples gives deterministic output for free: when two popular names are equally close, the alphabetically first wins, so the same requirements file produces the same report on every machine. Non-deterministic security tooling is tooling whose diffs nobody can read.

The internal-prefix rule is the dependency-confusion check, and it is the one with real teeth. A name beginning with your organisation's reserved prefix appearing in a *public* requirements file means either a mistake or an attack, and both deserve a build failure.`,
      },
      wrapup: `- Typosquatting exploits typing; dependency confusion exploits resolution across two indexes.
- One index that proxies the public one removes confusion entirely.
- Hashes are the backstop for a compromised maintainer account.
- Normalise names before comparing them, or your own checker becomes noise.`,
      refs: [
        { label: "PEP 503 — Simple Repository API (name normalisation)", url: "https://peps.python.org/pep-0503/#normalized-names" },
        { label: "Dependency confusion (Birsan, 2021)", url: "https://medium.com/@alex.birsan/dependency-confusion-4a5d60fec610" },
        { label: "CWE-1357: Reliance on Insufficiently Trustworthy Component", url: "https://cwe.mitre.org/data/definitions/1357.html" },
      ],
    },

    /* ----------------------------------------------------------------- 39 */
    {
      id: "m08l04",
      day: 45,
      title: "Configuration and secrets at runtime",
      minutes: 60,
      secure: "no credentials in source or image",
      cwe: ["CWE-798", "CWE-526"],
      tags: ["env", "config", "secrets", "dotenv", "12factor"],
      lede:
        "A secret in source is a secret in every clone, every backup, every container layer and every CI log. Getting it out of the code is step one; making its absence fatal is step two.",
      blocks: [
        {
          t: "table",
          head: ["Where the secret lives", "Who can read it", "Verdict"],
          rows: [
            ["A string in `settings.py`", "everyone with repository access, forever", "**Never**"],
            ["A `.env` file committed to git", "the same people", "**Never**"],
            ["A `.env` file, git-ignored, local only", "developers on that machine", "Acceptable for development"],
            ["An environment variable", "the process, anything that can read `/proc`, any crash dump", "Baseline"],
            ["A mounted secret file (`0600`)", "the process user", "Better — not in the environment block"],
            ["A secrets manager with short-lived tokens", "the process, for a bounded time", "Best"],
          ],
        },
        {
          t: "box",
          kind: "warn",
          title: "Environment variables are not private",
          md: `They appear in \`ps e\` output on some systems, in \`/proc/<pid>/environ\`, in crash dumps, in error-tracker payloads that capture the environment, in \`docker inspect\`, and in any subprocess you spawn — including the one running a hostile dependency's build script.

They are *better than source* and *worse than a mounted file*. Know which level you are at.`,
        },
        {
          t: "code",
          label: "vulnerable",
          code: `import os

API_KEY = os.environ.get("API_KEY", "dev-key-do-not-use")    # 1
DATABASE_URL = "postgresql://app:hunter2@db.internal/prod"   # 2
DEBUG = os.environ.get("DEBUG", "")                          # 3`,
          cap: "1: a working fallback credential shared by every deployment that forgets the variable. 2: a password in source. 3: `\"false\"` is truthy, so `DEBUG=false` enables debug.",
        },
        {
          t: "code",
          label: "fixed",
          code: `import os

def required(name):
    """Fail closed: a missing secret stops the process."""
    try:
        value = os.environ[name]
    except KeyError:
        raise RuntimeError(f"{name} is not set") from None
    if not value.strip():
        raise RuntimeError(f"{name} is empty")
    return value

API_KEY = required("API_KEY")
DATABASE_URL = required("DATABASE_URL")
DEBUG = os.environ.get("DEBUG", "0").strip().lower() in {"1", "true", "yes", "on"}`,
          cap: "`from None` suppresses the original `KeyError`, whose message would be the variable name repeated — harmless here, but the habit matters when the chained exception carries more.",
        },
        {
          t: "box",
          kind: "rule",
          title: "Fail closed at startup, not at first use",
          md: `Validate **every** required setting when the process starts. A service that boots successfully and then fails on the first request that touches the payment provider is far harder to diagnose — and in a rolling deploy, it passes the health check and replaces the working instances.

Load, validate, then serve.`,
        },
        { t: "h", text: "Secret files beat environment variables" },
        {
          t: "code",
          label: "fixed",
          code: `from pathlib import Path

def read_secret(name, *, directory="/run/secrets"):
    """Read a mounted secret file, as Docker/Kubernetes provide them."""
    path = Path(directory) / name
    if not path.is_file():
        raise RuntimeError(f"secret {name!r} is not mounted")
    value = path.read_text(encoding="utf-8").strip()
    if not value:
        raise RuntimeError(f"secret {name!r} is empty")
    return value`,
          cap: "A file is not inherited by subprocesses, does not appear in `docker inspect`, and can be rotated by replacing the file without restarting the orchestrator's config.",
        },
        {
          t: "box",
          kind: "cve",
          title: "Scanning works, which is the problem",
          md: `GitHub's secret scanning and tools such as \`trufflehog\` and \`gitleaks\` find live credentials in public repositories continuously, and automated scrapers find them within minutes of a push. Removing the line in a later commit does not help: the object remains in the history and in every clone.

A leaked credential must be **rotated**, not deleted. Treat "it was only in a commit for ten minutes" as "it is compromised".`,
        },
      ],
      spot: {
        label: "settings module",
        prompt: "Click the line that gives every misconfigured deployment a working shared credential.",
        lines: [5],
        why:
          "Line 5. The fallback means a deployment that forgets to set `SIGNING_KEY` starts successfully using a key that is in the source, and therefore known to anyone with repository access. Line 4 is correct — `os.environ[...]` raises when the variable is absent, which is the behaviour you want.",
        code: `import os

DEBUG = os.environ.get("DEBUG", "0") == "1"
DATABASE_URL = os.environ["DATABASE_URL"]
SIGNING_KEY = os.environ.get("SIGNING_KEY", "dev-signing-key-2019")
TIMEOUT = int(os.environ.get("TIMEOUT", "30"))`,
      },
      quiz: [
        {
          q: "Why is `os.environ.get(\"KEY\", \"default-secret\")` worse than `os.environ[\"KEY\"]`?",
          options: [
            "It is slower.",
            "It silently substitutes a credential that is in the source and shared by every deployment that forgets the variable.",
            "`get` is deprecated.",
          ],
          answer: 1,
          why: "The default hides the misconfiguration you needed to notice, and the value itself is in your repository history.",
        },
        {
          q: "A secret was committed and removed in the next commit. What must happen?",
          options: [
            "Nothing, it is removed.",
            "Rotate it — the object is still in the history and in every clone, and scanners are continuous.",
            "Rewrite history and move on.",
          ],
          answer: 1,
          why:
            "History rewriting does not reach forks, clones, CI caches or anyone who already fetched. Rotation is the only control that actually works.",
        },
        {
          q: "Why can a mounted secret file be better than an environment variable?",
          options: [
            "Files are encrypted.",
            "It is not inherited by subprocesses, not in `docker inspect`, and can be permissioned `0600`.",
            "Files are faster to read.",
          ],
          answer: 1,
          why: "The environment block is copied into every child process and shows up in a lot of diagnostic output.",
        },
      ],
      exercise: {
        title: "A settings loader that will not start without its secrets",
        brief: `Write a loader that reads from a mapping (the grader passes one; do not touch the real environment) and from a secrets directory.

1. \`required(env, name)\` — return the stripped value, or raise \`RuntimeError\` naming the variable when it is missing or blank.
2. \`optional_bool(env, name, default)\` — parse \`1/true/yes/on\` and \`0/false/no/off\` case-insensitively; unknown spellings raise \`ValueError\`; missing returns \`default\`.
3. \`optional_int(env, name, default, *, minimum, maximum)\` — parse and clamp into range; a non-numeric value raises \`ValueError\`.
4. \`read_secret_file(path)\` — read a file, strip it, raise \`RuntimeError\` if missing or empty.
5. \`load(env, secrets_dir)\` — return a dict with:
   - \`"database_url"\` from \`required(env, "DATABASE_URL")\`
   - \`"signing_key"\` from the file \`<secrets_dir>/signing_key\` (never from \`env\`)
   - \`"debug"\` from \`DEBUG\`, default \`False\`
   - \`"timeout"\` from \`TIMEOUT\`, default 30, clamped 1–300
   - \`"api_key"\` from \`required(env, "API_KEY")\`
6. \`describe(settings)\` — a one-line summary containing \`debug=\`, \`timeout=\` and \`db_host=\` (the host portion of the database URL, i.e. the text between \`@\` and the next \`/\`), and containing **no** secret values.

Every missing requirement must raise at load time, not later.`,
        rubric: [
          "Missing `DATABASE_URL`, `API_KEY` or the signing-key file each stop the load",
          "No fallback credential appears anywhere in the file",
          "Booleans are parsed from an allowlist, not truthiness",
          "`timeout` is clamped; a non-numeric value raises",
          "`describe` reveals the host but no credential",
        ],
        setup: `import os
os.makedirs("secrets", exist_ok=True)
with open("secrets/signing_key", "w", encoding="utf-8") as _fh:
    _fh.write("  s1gning-key-from-a-mounted-file  \\n")
with open("secrets/empty_key", "w", encoding="utf-8") as _fh:
    _fh.write("   \\n")
`,
        starter: `from pathlib import Path

TRUE_WORDS = {"1", "true", "yes", "on"}
FALSE_WORDS = {"0", "false", "no", "off"}


def required(env, name):
    """Return env[name] stripped, or raise RuntimeError."""


def optional_bool(env, name, default):
    """Parse a boolean spelling, or return the default."""


def optional_int(env, name, default, *, minimum, maximum):
    """Parse an int and clamp it, or return the default."""


def read_secret_file(path):
    """Read a mounted secret, or raise RuntimeError."""


def load(env, secrets_dir):
    """Build the settings dict, or refuse to start."""


def describe(settings):
    """A one-line summary with no secrets in it."""


ENV = {"DATABASE_URL": "postgresql://app:pw@db.internal/prod", "API_KEY": "k" * 20, "DEBUG": "false"}
print(describe(load(ENV, "secrets")))
`,
        stdin: [],
        tests: [
          {
            name: "a complete environment loads",
            code: `env = {"DATABASE_URL": "postgresql://app:pw@db.internal/prod", "API_KEY": "k" * 20}
s = load(env, "secrets")
assert s["database_url"] == "postgresql://app:pw@db.internal/prod"
assert s["signing_key"] == "s1gning-key-from-a-mounted-file", f"got {s['signing_key']!r}"
assert s["debug"] is False and s["timeout"] == 30`,
          },
          {
            name: "missing requirements stop the load",
            code: `base = {"DATABASE_URL": "postgresql://app:pw@db.internal/prod", "API_KEY": "k" * 20}
for missing in ("DATABASE_URL", "API_KEY"):
    env = {k: v for k, v in base.items() if k != missing}
    try:
        load(env, "secrets")
        raise AssertionError(f"missing {missing} should stop the load")
    except RuntimeError as e:
        assert missing in str(e), f"the error should name {missing}: {str(e)!r}"`,
          },
          {
            name: "blank values are treated as missing",
            code: `base = {"DATABASE_URL": "postgresql://app:pw@db.internal/prod", "API_KEY": "k" * 20}
for blank in ("", "   ", "\\t"):
    with raises(RuntimeError):
        load({**base, "API_KEY": blank}, "secrets")`,
          },
          {
            name: "the signing key comes from the file, never the environment",
            code: `base = {"DATABASE_URL": "postgresql://app:pw@db.internal/prod", "API_KEY": "k" * 20}
s = load({**base, "SIGNING_KEY": "from-the-environment"}, "secrets")
assert s["signing_key"] == "s1gning-key-from-a-mounted-file", "the file must win"
with raises(RuntimeError):
    load(base, "secrets/does-not-exist")`,
          },
          {
            name: "an empty secret file is a failure",
            code: `with raises(RuntimeError):
    read_secret_file("secrets/empty_key")
assert read_secret_file("secrets/signing_key") == "s1gning-key-from-a-mounted-file"`,
          },
          {
            name: "booleans are parsed, not tested for truthiness",
            code: `base = {"DATABASE_URL": "postgresql://app:pw@db.internal/prod", "API_KEY": "k" * 20}
assert load({**base, "DEBUG": "false"}, "secrets")["debug"] is False
assert load({**base, "DEBUG": "FALSE"}, "secrets")["debug"] is False
assert load({**base, "DEBUG": " on "}, "secrets")["debug"] is True
for bad in ("maybe", "2", ""):
    with raises(ValueError):
        load({**base, "DEBUG": bad}, "secrets")`,
          },
          {
            name: "timeout is clamped and validated",
            code: `base = {"DATABASE_URL": "postgresql://app:pw@db.internal/prod", "API_KEY": "k" * 20}
assert load({**base, "TIMEOUT": "90"}, "secrets")["timeout"] == 90
assert load({**base, "TIMEOUT": "0"}, "secrets")["timeout"] == 1
assert load({**base, "TIMEOUT": "9999"}, "secrets")["timeout"] == 300
for bad in ("abc", "30.5", ""):
    with raises(ValueError):
        load({**base, "TIMEOUT": bad}, "secrets")`,
          },
          {
            name: "describe reveals the host and nothing else",
            code: `env = {"DATABASE_URL": "postgresql://app:hunter2@db.internal/prod", "API_KEY": "k" * 20}
line = describe(load(env, "secrets"))
assert "db.internal" in line, f"got {line!r}"
for secret in ("hunter2", "k" * 20, "s1gning-key-from-a-mounted-file"):
    assert secret not in line, f"describe leaked a secret: {line!r}"
for needle in ("debug=", "timeout=", "db_host="):
    assert needle in line, f"missing {needle} in {line!r}"`,
          },
          {
            name: "no hardcoded credential anywhere",
            code: `assert "hunter2" not in _stdout, "a credential was printed"`,
          },
        ],
        requirements: [
          { kind: "defines", value: "load" },
          { kind: "defines", value: "describe" },
          { kind: "no_finding", value: "PY-HARDCODED-SECRET" },
          { kind: "no_finding", value: "PY-SECRET-FALLBACK" },
        ],
        hints: [
          "`required` should use `env.get(name)` then check for `None` or blank, raising `RuntimeError(f\"{name} is not set\")` — the variable name in the message is what makes a failed deploy diagnosable.",
          "`optional_int`: reject with `ValueError` when the text is not ASCII digits, then clamp with `max(minimum, min(value, maximum))`. Clamping after parsing keeps the two concerns separate.",
          "The host extraction for `describe`: `url.split(\"@\", 1)[-1].split(\"/\", 1)[0]` — taking the part after the last `@` avoids leaking the credential that precedes it.",
          "Load everything into local variables first and build the dict at the end, so a failure anywhere means no partially-built settings object escapes.",
        ],
        solution: `from pathlib import Path

TRUE_WORDS = {"1", "true", "yes", "on"}
FALSE_WORDS = {"0", "false", "no", "off"}


def required(env, name):
    """Return env[name] stripped, or raise RuntimeError."""
    value = env.get(name)
    if value is None or not str(value).strip():
        raise RuntimeError(f"{name} is not set")
    return str(value).strip()


def optional_bool(env, name, default):
    """Parse a boolean spelling, or return the default."""
    raw = env.get(name)
    if raw is None:
        return default
    text = str(raw).strip().lower()
    if text in TRUE_WORDS:
        return True
    if text in FALSE_WORDS:
        return False
    raise ValueError(f"{name} is not a boolean: {text!r}")


def optional_int(env, name, default, *, minimum, maximum):
    """Parse an int and clamp it, or return the default."""
    raw = env.get(name)
    if raw is None:
        return default
    text = str(raw).strip()
    if not (text.isascii() and text.isdigit()):
        raise ValueError(f"{name} must be digits")
    return max(minimum, min(int(text), maximum))


def read_secret_file(path):
    """Read a mounted secret, or raise RuntimeError."""
    p = Path(path)
    if not p.is_file():
        raise RuntimeError(f"secret file {p} is not mounted")
    value = p.read_text(encoding="utf-8").strip()
    if not value:
        raise RuntimeError(f"secret file {p} is empty")
    return value


def load(env, secrets_dir):
    """Build the settings dict, or refuse to start."""
    database_url = required(env, "DATABASE_URL")
    api_key = required(env, "API_KEY")
    signing_key = read_secret_file(Path(secrets_dir) / "signing_key")
    debug = optional_bool(env, "DEBUG", False)
    timeout = optional_int(env, "TIMEOUT", 30, minimum=1, maximum=300)

    return {
        "database_url": database_url,
        "api_key": api_key,
        "signing_key": signing_key,
        "debug": debug,
        "timeout": timeout,
    }


def describe(settings):
    """A one-line summary with no secrets in it."""
    url = settings["database_url"]
    host = url.split("@")[-1].split("/")[0]
    return (
        f"settings loaded: debug={settings['debug']} "
        f"timeout={settings['timeout']} "
        f"db_host={host} "
        f"api_key_len={len(settings['api_key'])}"
    )


ENV = {"DATABASE_URL": "postgresql://app:pw@db.internal/prod", "API_KEY": "k" * 20, "DEBUG": "false"}
print(describe(load(ENV, "secrets")))`,
        why: `There is no literal credential and no fallback anywhere in the file, so the auditor's two high-severity secret rules have nothing to find — and neither does a scanner reading the repository.

Every required value is fetched before the dict is built. A deployment missing \`API_KEY\` fails during \`load()\`, before the process begins serving, which means the orchestrator's health check never passes and the rolling deploy stops instead of replacing working instances with broken ones. That ordering is the practical difference between "fail closed" as a slogan and as a property.

The signing key comes from a file and only from a file. The test that puts \`SIGNING_KEY\` in the environment and asserts the file still wins encodes a real rule: once a secret has a canonical source, a second source is a bypass. If the environment could override the mount, anyone who can set an environment variable on the pod could substitute their own signing key.

\`describe\` is built from a fixed set of non-secret fields. Taking the text after the **last** \`@\` is deliberate — \`postgresql://app:hunter2@db.internal/prod\` split on the first \`@\` would still be safe here, but a password containing an \`@\` would put a credential fragment into the log line. Reporting \`api_key_len\` rather than a prefix gives operators enough to tell "wrong key" from "no key" while revealing nothing usable.`,
      },
      wrapup: `- No credential in source, in \`.env\` committed to git, or in a default argument.
- \`os.environ[...]\` rather than \`.get(..., "fallback")\` — fail closed at startup.
- Mounted files beat environment variables; environment variables beat source.
- A leaked secret is rotated, never merely deleted.`,
      refs: [
        { label: "The Twelve-Factor App — Config", url: "https://12factor.net/config" },
        { label: "CWE-798: Use of Hard-coded Credentials", url: "https://cwe.mitre.org/data/definitions/798.html" },
      ],
    },

    /* ----------------------------------------------------------------- 40 */
    {
      id: "m08l05",
      day: 46,
      title: "Capstone: audit a dependency manifest",
      minutes: 60,
      secure: "supply-chain review",
      cwe: ["CWE-1104", "CWE-1357"],
      tags: ["capstone", "supply-chain", "audit", "report", "remediation"],
      lede:
        "Combine the three checkers into one review that produces what a security engineer actually delivers: a prioritised list with a remediation for each item.",
      blocks: [
        {
          t: "p",
          md: `A dependency review is not a list of facts; it is a list of *decisions someone has to make*. Three properties separate a report that gets acted on from one that gets closed:

- **Severity**, so the reader knows where to start.
- **A remediation**, so the fix is a copy-paste rather than a research project.
- **Determinism**, so the diff between this week's report and last week's is readable.`,
        },
        {
          t: "table",
          head: ["Finding", "Severity", "Remediation"],
          rows: [
            ["Unpinned requirement", "high", "Pin with `==` and regenerate the lockfile with hashes."],
            ["Name resembles a popular package", "high", "Confirm the intended package; check the project URL and release history."],
            ["Internal prefix in a public manifest", "high", "Move to the private index; reserve the name publicly."],
            ["Pinned without a hash", "medium", "`pip-compile --generate-hashes`."],
            ["URL or VCS install", "high", "Vendor it into the private index with a pinned artifact."],
            ["Local path install", "medium", "Publish to the private index; paths do not reproduce in CI."],
          ],
        },
        {
          t: "box",
          kind: "good",
          title: "Report the highest-leverage fix first",
          md: `Seven findings across five packages usually have one root cause: the manifest was written by hand instead of being generated. The most useful line in the report is not finding #1 — it is *"regenerating this file with \`pip-compile --generate-hashes\` resolves five of the seven"*.

Lead with the change that fixes the most.`,
        },
        {
          t: "box",
          kind: "rule",
          title: "What this check can and cannot see",
          md: `A manifest auditor reads a file. It does not know whether a package is *currently* compromised, whether its maintainer account has MFA, or what the transitive graph pulls in.

State the gap in the report. A tool that implies more coverage than it has is worse than no tool, because it ends an investigation that should have continued — pair it with a vulnerability database check (\`pip-audit\`, \`osv-scanner\`) and a lockfile.`,
        },
      ],
      quiz: [
        {
          q: "What belongs in a dependency finding besides the problem?",
          options: [
            "The CVSS vector.",
            "A severity and a concrete remediation.",
            "The package's download count.",
          ],
          answer: 1,
          why: "A finding without a fix is a chore. Severity sets the order; the remediation makes acting on it cheap.",
        },
        {
          q: "Why must report output be deterministic?",
          options: [
            "It is faster.",
            "So the diff between runs is readable and CI failures are reproducible.",
            "JSON requires it.",
          ],
          answer: 1,
          why: "Non-deterministic ordering makes every run look like a change, and reports nobody can diff get ignored.",
        },
        {
          q: "Your manifest auditor reports zero findings. What does that mean?",
          options: [
            "The dependencies are safe.",
            "The file is well-formed — it says nothing about whether those versions have known vulnerabilities.",
            "The tool failed.",
          ],
          answer: 1,
          why: "Pinning and hashing prove reproducibility, not absence of vulnerabilities. Add a vulnerability-database scan.",
        },
      ],
      exercise: {
        title: "review_manifest(): one prioritised report",
        brief: `Write \`review_manifest(text, *, popular=POPULAR, internal_prefixes=())\` producing a single list of findings, then \`render(findings)\` producing a text report.

For each requirement line (skip blanks, comments and option lines), apply **all** applicable checks:

| rule | severity | remediation |
|---|---|---|
| \`"url-install"\` | high | \`"vendor the artifact into the private index and pin it"\` |
| \`"local-path"\` | medium | \`"publish to the private index; local paths do not reproduce in CI"\` |
| \`"unpinned"\` | high | \`"pin with == and regenerate with --generate-hashes"\` |
| \`"no-hash"\` | medium | \`"regenerate with pip-compile --generate-hashes"\` |
| \`"typosquat"\` | high | \`"confirm the intended package: did you mean <popular>?"\` |
| \`"internal-name"\` | high | \`"must resolve from the private index, not a public manifest"\` |

A URL or local-path line gets only its own finding (no pinning or name checks — there is no package name to check). Otherwise a line may produce several findings: for example an unpinned typosquat yields two.

Each finding is \`{"line", "package", "rule", "severity", "remediation"}\`. Sort by severity (high first) then line then rule.

\`render(findings)\` returns a string: a first line \`"<n> findings: <h> high, <m> medium"\`, then one line per finding formatted \`"[<severity>] line <line>: <package> — <rule>: <remediation>"\`.

Reuse \`edit_distance\` and \`normalise\` (both provided in the starter).`,
        rubric: [
          "A clean, hashed manifest produces zero findings",
          "A single line can produce multiple findings when several rules apply",
          "URL/path lines produce exactly one finding each",
          "Sorting is high-then-line-then-rule and fully deterministic",
          "`render` reports the counts and one line per finding",
        ],
        starter: `import re

POPULAR = frozenset({"requests", "urllib3", "numpy", "flask", "django",
                     "python-dateutil", "colorama", "beautifulsoup4", "pyyaml"})
SEVERITY_ORDER = {"high": 0, "medium": 1}
SPLIT_CHARS = "<>=!~[; "


def normalise(name):
    return re.sub(r"[-_.]+", "-", str(name)).lower()


def edit_distance(a, b):
    if a == b:
        return 0
    if not a or not b:
        return len(a) or len(b)
    previous = list(range(len(b) + 1))
    for i, ch_a in enumerate(a, start=1):
        current = [i]
        for j, ch_b in enumerate(b, start=1):
            cost = 0 if ch_a == ch_b else 1
            current.append(min(previous[j] + 1, current[j - 1] + 1, previous[j - 1] + cost))
        previous = current
    return previous[-1]


def package_name(token):
    for index, char in enumerate(token):
        if char in SPLIT_CHARS:
            return normalise(token[:index])
    return normalise(token)


def review_manifest(text, *, popular=POPULAR, internal_prefixes=()):
    """Return every finding for a requirements manifest."""


def render(findings):
    """Return a human-readable report."""


SAMPLE = """# deps
requests==2.31.0 --hash=sha256:abc
reqeusts
flask==3.0.0
acme-payments==1.2.0 --hash=sha256:def
./vendor/thing
"""
print(render(review_manifest(SAMPLE, internal_prefixes=("acme-",))))
`,
        stdin: [],
        tests: [
          {
            name: "a clean manifest is clean",
            code: `text = "# deps\\n\\n-r base.txt\\nrequests==2.31.0 --hash=sha256:abc\\nflask==3.0.0 --hash=sha256:def\\n"
assert review_manifest(text) == [], f"got {review_manifest(text)!r}"`,
          },
          {
            name: "a pinned package without a hash is one medium finding",
            code: `got = review_manifest("flask==3.0.0\\n")
assert len(got) == 1, f"got {got!r}"
assert got[0]["rule"] == "no-hash" and got[0]["severity"] == "medium"
assert got[0]["package"] == "flask"
assert "generate-hashes" in got[0]["remediation"]`,
          },
          {
            name: "one line can produce several findings",
            code: `got = review_manifest("reqeusts\\n")
rules = sorted(f["rule"] for f in got)
assert rules == ["typosquat", "unpinned"], f"got {rules!r}"
assert all(f["line"] == 1 for f in got)
squat = [f for f in got if f["rule"] == "typosquat"][0]
assert "requests" in squat["remediation"], f"got {squat!r}"`,
          },
          {
            name: "url and path lines produce exactly one finding",
            code: `got = review_manifest("https://example.com/pkg-1.0.tar.gz\\n")
assert len(got) == 1 and got[0]["rule"] == "url-install" and got[0]["severity"] == "high", f"got {got!r}"
got = review_manifest("./vendor/thing\\n")
assert len(got) == 1 and got[0]["rule"] == "local-path" and got[0]["severity"] == "medium", f"got {got!r}"`,
          },
          {
            name: "internal names are caught even when pinned and hashed",
            code: `text = "acme-payments==1.2.0 --hash=sha256:abc\\n"
got = review_manifest(text, internal_prefixes=("acme-",))
assert len(got) == 1 and got[0]["rule"] == "internal-name", f"got {got!r}"
assert got[0]["severity"] == "high"
assert review_manifest(text) == [], "without a configured prefix there is nothing to flag"`,
          },
          {
            name: "sorting is deterministic: severity, then line, then rule",
            code: `text = "flask==3.0.0\\nreqeusts\\n"
runs = {tuple((f["severity"], f["line"], f["rule"]) for f in review_manifest(text)) for _ in range(5)}
assert len(runs) == 1, f"non-deterministic output: {runs!r}"
got = review_manifest(text)
assert got[0]["severity"] == "high", f"high findings must come first: {got!r}"
keys = [(SEVERITY_ORDER[f["severity"]], f["line"], f["rule"]) for f in got]
assert keys == sorted(keys), f"not sorted: {keys!r}"`,
          },
          {
            name: "render reports counts and one line per finding",
            code: `text = "reqeusts\\nflask==3.0.0\\n"
findings = review_manifest(text)
out = render(findings)
lines = out.splitlines()
assert lines[0] == f"{len(findings)} findings: 2 high, 1 medium", f"got {lines[0]!r}"
assert len(lines) == len(findings) + 1, f"got {len(lines)} lines for {len(findings)} findings"
for line in lines[1:]:
    assert line.startswith("[high]") or line.startswith("[medium]"), f"got {line!r}"
assert "reqeusts" in out and "flask" in out`,
          },
          {
            name: "an empty manifest renders cleanly",
            code: `out = render([])
assert out.splitlines()[0] == "0 findings: 0 high, 0 medium", f"got {out!r}"`,
          },
        ],
        requirements: [
          { kind: "defines", value: "review_manifest" },
          { kind: "defines", value: "render" },
        ],
        hints: [
          "Structure the loop as: skip non-requirements → handle URL/path with an early `continue` → then run the pinning and name checks, appending as many findings as apply.",
          "`add(rule, severity, remediation)` as a closure over `number` and `name` keeps the body readable and makes every finding the same shape by construction.",
          "The typosquat check reuses the previous lesson: skip it when the normalised name is already in `popular`, then `min((edit_distance(name, p), p) for p in popular)` and flag a distance of 1 or 2.",
          "Sort with `key=lambda f: (SEVERITY_ORDER[f[\"severity\"]], f[\"line\"], f[\"rule\"])` — one expression gives you all three levels of ordering.",
        ],
        solution: `import re

POPULAR = frozenset({"requests", "urllib3", "numpy", "flask", "django",
                     "python-dateutil", "colorama", "beautifulsoup4", "pyyaml"})
SEVERITY_ORDER = {"high": 0, "medium": 1}
SPLIT_CHARS = "<>=!~[; "

REMEDIATION = {
    "url-install": "vendor the artifact into the private index and pin it",
    "local-path": "publish to the private index; local paths do not reproduce in CI",
    "unpinned": "pin with == and regenerate with --generate-hashes",
    "no-hash": "regenerate with pip-compile --generate-hashes",
    "internal-name": "must resolve from the private index, not a public manifest",
}


def normalise(name):
    return re.sub(r"[-_.]+", "-", str(name)).lower()


def edit_distance(a, b):
    if a == b:
        return 0
    if not a or not b:
        return len(a) or len(b)
    previous = list(range(len(b) + 1))
    for i, ch_a in enumerate(a, start=1):
        current = [i]
        for j, ch_b in enumerate(b, start=1):
            cost = 0 if ch_a == ch_b else 1
            current.append(min(previous[j] + 1, current[j - 1] + 1, previous[j - 1] + cost))
        previous = current
    return previous[-1]


def package_name(token):
    for index, char in enumerate(token):
        if char in SPLIT_CHARS:
            return normalise(token[:index])
    return normalise(token)


def review_manifest(text, *, popular=POPULAR, internal_prefixes=()):
    """Return every finding for a requirements manifest."""
    findings = []

    for number, raw in enumerate(text.splitlines(), start=1):
        line = raw.strip()
        if not line or line.startswith("#") or line.startswith("-"):
            continue

        token = line.split()[0]

        def add(rule, severity, package, remediation=None):
            findings.append({
                "line": number,
                "package": package,
                "rule": rule,
                "severity": severity,
                "remediation": remediation or REMEDIATION[rule],
            })

        # A URL or path has no package name to reason about: one finding, then stop.
        if "http://" in line or "https://" in line or token.startswith("git+"):
            add("url-install", "high", token)
            continue
        if token.startswith(".") or token.startswith("/"):
            add("local-path", "medium", token)
            continue

        name = package_name(token)

        if "==" not in line:
            add("unpinned", "high", name)
        elif "--hash=" not in line:
            add("no-hash", "medium", name)

        if any(name.startswith(normalise(p)) for p in internal_prefixes):
            add("internal-name", "high", name)

        if name not in popular:
            distance, closest = min((edit_distance(name, p), p) for p in popular)
            if 1 <= distance <= 2:
                add("typosquat", "high", name,
                    f"confirm the intended package: did you mean {closest}?")

    findings.sort(key=lambda f: (SEVERITY_ORDER[f["severity"]], f["line"], f["rule"]))
    return findings


def render(findings):
    """Return a human-readable report."""
    high = sum(1 for f in findings if f["severity"] == "high")
    medium = sum(1 for f in findings if f["severity"] == "medium")

    lines = [f"{len(findings)} findings: {high} high, {medium} medium"]
    for f in findings:
        lines.append(
            f"[{f['severity']}] line {f['line']}: {f['package']} — {f['rule']}: {f['remediation']}"
        )
    return "\\n".join(lines)


SAMPLE = """# deps
requests==2.31.0 --hash=sha256:abc
reqeusts
flask==3.0.0
acme-payments==1.2.0 --hash=sha256:def
./vendor/thing
"""
print(render(review_manifest(SAMPLE, internal_prefixes=("acme-",))))`,
        why: `Each line is evaluated against every applicable rule rather than stopping at the first hit, because the rules describe independent risks. \`reqeusts\` is both unpinned *and* a probable squat; reporting only the first would let a reviewer "fix" it by pinning a hostile package to an exact version.

The one place the checks short-circuit is deliberate. A URL or local-path line has no package name, no version specifier and no hash to evaluate, so running the pinning and similarity checks on it would produce three findings that all describe the same problem — and the pinning remediation would be actively wrong advice for a tarball URL.

Sorting on \`(severity, line, rule)\` makes the report a stable artifact. Two runs over the same file produce byte-identical output, so the report can live in CI, be committed, and be diffed: a new line in the diff is a new risk, not a reordering. Reports that shuffle get ignored within two sprints.

The remediation strings carry most of the practical value. \`"regenerate with pip-compile --generate-hashes"\` is a command someone runs; \`"missing hash"\` is a fact someone has to go research. And because \`no-hash\` and \`unpinned\` share one remediation, a reader with seven findings sees immediately that one command resolves most of them — which is the highest-leverage line in any dependency review.

The honest limitation stays visible: this reads a file. It does not know that a pinned, hashed, correctly-named package has a published CVE. Pair it with \`pip-audit\` or \`osv-scanner\`, and say so in the report rather than letting a clean run imply more than it proves.`,
      },
      wrapup: `- Findings need a severity and a remediation, or they are facts rather than work.
- Apply every applicable rule per line; different rules describe different risks.
- Deterministic ordering makes a report diffable, which is what makes it survive in CI.
- Say what the check does not cover — a clean manifest is not an absence of vulnerabilities.`,
      refs: [
        { label: "pip-audit", url: "https://pypi.org/project/pip-audit/" },
        { label: "OSV — open source vulnerability database", url: "https://osv.dev/" },
        { label: "SLSA — supply chain levels", url: "https://slsa.dev/" },
      ],
    },
  ],
};
