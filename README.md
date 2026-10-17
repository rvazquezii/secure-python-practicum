# Secure Python — a 60-day practicum

A self-contained, browser-based course that teaches Python from zero with secure
coding enforced from day one. Real CPython runs in the page (Pyodide/WebAssembly),
so you write code and it executes. Every submission is graded twice: once for
correctness, once by a security auditor that reads your syntax tree.

**Insecure code that produces the right answer does not pass.**

## Run it

```bash
./serve.sh
```

Then open <http://localhost:8800>. A server is required — Python's WebAssembly
runtime and ES modules are both blocked on `file://` URLs. The runtime downloads
once (~10 MB) from a CDN and is cached by the browser afterwards.

```bash
./serve.sh 9000      # a different port
```

## What is in it

| | |
|---|---|
| Modules | 12 |
| Lessons | 60, one per hour-long session |
| Auditor rules | 34, AST-based, each with a CWE reference and a fix |
| Exercises | 60, every reference solution machine-verified |
| Quiz questions | 180, plus 29 spot-the-vulnerability drills |
| Automated tests | 462 across the exercises, plus 130 for the engine itself |

### Curriculum

| Module | Days | Subject | Security focus |
|---|---|---|---|
| 1 | 1–5 | Foundations and the secure mindset | trust boundaries |
| 2 | 6–10 | Control flow and input validation | fail closed |
| 3 | 11–15 | Data structures and data you do not own | lookup tables, minimisation |
| 4 | 16–20 | Functions, scope and failure | error hygiene |
| 5 | 21–25 | Strings, bytes and injection | command and SQL injection |
| 6 | 26–30 | Files, paths and deserialization | path confinement, RCE formats |
| 7 | 31–35 | Objects and secure design | invariants, redaction |
| 8 | 36–40 | Modules, environments and the supply chain | dependencies, secrets |
| 9 | 41–45 | Cryptography you will actually use | tokens, hashing, HMAC |
| 10 | 46–50 | Web and API security | TLS, SSRF, XSS, IDOR |
| 11 | 51–55 | Concurrency, resources and denial of service | availability |
| 12 | 56–60 | Expert practice: types, tests and tooling | proving it |

## How grading works

A lesson is complete when **all three** hold:

1. every automated test passes,
2. the auditor reports no **critical** or **high** finding,
3. the lesson's explicit requirements are met (for example *must use `secrets`,
   must not use `random`*).

Medium and low findings do not block, but are shown with the fix.

## The simulated hostile world

`os.system`, `subprocess`, `requests`, `yaml` and `jwt` are replaced by
instrumented simulations (`py/teachlib.py`). A command injection really parses
shell metacharacters, an SSRF really reaches a fake metadata service, and
`yaml.load` really constructs the object the payload names — and all of it is
harmless. Exploits are recorded in `WORLD.events` and shown in the **Breach**
tab, so exercises can assert *no breach occurred* rather than only checking the
happy path.

`sqlite3` is real, so SQL-injection lessons run against an actual database.

## Interface

| | |
|---|---|
| `⌘/⌃ ↵` | Run |
| `⌘/⌃ ⇧ ↵` | Submit for grading |
| `⌃ \`` | Toggle the Python console (a persistent REPL) |
| `⌥ ←` / `⌥ →` | Previous / next lesson |
| `/` | Search |
| `?` | Shortcuts |

Progress, written code, quiz answers and practice time are stored in
`localStorage`. **Export progress** in the left rail writes a JSON backup;
**Import** restores it. Clearing site data erases everything.

Practice time counts only while the tab is focused and you have interacted in
the last two and a half minutes, so leaving a lesson open overnight does not
report an eight-hour session. A day counts toward the streak at 20 minutes.

## Layout

```
index.html              the shell
css/app.css             design system ("Indigo Lab"), light and dark
js/app.js               routing, workbench, grading, console, search
js/py.js                Pyodide bootstrap and the three entry points
js/editor.js            Python editor: highlighting, auto-indent, brackets
js/render.js            lesson block renderer
js/store.js             progress, practice clock, streak
py/sandbox.py           executor, test harness and AST security auditor
py/teachlib.py          the simulated hostile world
py/test_sandbox.py      130 tests for the engine
content/m01..m12.js     the lessons
tools/verify.mjs        content structure checks
tools/verify_lessons.py runs every reference solution through the real grader
```

## Verifying the content

```bash
python3 py/test_sandbox.py
```

Asserts that every auditor rule fires on vulnerable code and stays quiet on the
fixed version, and that the executor, test harness and REPL behave.

```bash
node tools/verify.mjs && python3 tools/verify_lessons.py
```

Checks every lesson's structure (ids, day numbering, quiz answers, spot-the-bug
line ranges), then runs all 60 reference solutions through the same grader the
browser uses. A solution must be accepted — tests pass, no blocking finding,
requirements met — and no starter may contain a syntax error.

Run both after editing any lesson.

## Adding a lesson

Lessons are plain data. Append to the `lessons` array of a module file:

```js
{
  id: "m01l06", day: 61, title: "...", minutes: 60,
  secure: "one-line security focus", cwe: ["CWE-20"], tags: [],
  lede: "...",
  blocks: [ {t: "p", md: "..."}, {t: "box", kind: "warn", title: "...", md: "..."},
            {t: "code", label: "vulnerable", code: "...", cap: "..."} ],
  spot: {label, prompt, code, lines: [4], why},        // optional
  quiz: [{q, options: [], answer: 0, why}],
  exercise: {title, brief, rubric: [], starter, stdin: [], setup: "",
             tests: [{name, code}], requirements: [], hints: [], solution, why},
  wrapup: "...", refs: [{label, url}],
}
```

Block types: `p`, `h`, `h3`, `list`, `box` (`note`/`rule`/`warn`/`pitfall`/`cve`/`good`/`try`),
`code`, `repl`, `table`.

Inside exercise tests you have the submission's globals plus `_stdout`,
`_lines`, `approx(a, b)`, `raises(Exc)`, and `WORLD`/`SHELL` from the simulated
world.

Requirement kinds: `defines`, `calls`, `uses_module`, `forbids_module`,
`forbids` (regex), `regex`, `no_finding`.

Two authoring traps, both caught by `node tools/verify.mjs`:

- lesson content lives in JS template literals, so Python backticks must be
  escaped (`` \` ``) and a Python f-string containing `${` collides with JS
  interpolation,
- exercises that touch the filesystem must use **relative** paths; the browser's
  in-memory filesystem allows `/work`, a real machine does not.

## Limitations

- The auditor is pattern-based. It sees syntax, not behaviour: aliasing
  (`f = eval`), dynamic dispatch and anything crossing a process boundary are
  invisible to it. A clean audit means *these 34 patterns are absent*, never
  *this code is secure*.
- Exercises run in WebAssembly, so there is no real network, no real shell and
  no real filesystem outside the page.
- Progress is per-browser. Use Export regularly if it matters.

## License

MIT — see [LICENSE](LICENSE). Clone it, fork it, change it, teach from it,
or ship it in something of your own; keep the copyright notice.

The CVE and incident references throughout the lessons describe publicly
documented events and are cited to their primary sources.
