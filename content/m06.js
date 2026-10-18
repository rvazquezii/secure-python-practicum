export default {
  id: "m06",
  number: 6,
  title: "Files, paths and deserialization",
  focus: "path confinement",
  subtitle:
    "Reading and writing files safely: confining paths to a directory, writing atomically, and the two formats that turn a data file into code execution.",
  objectives: [
    "Open, read and write files with explicit encodings and guaranteed cleanup.",
    "Confine a user-influenced path to a base directory with `resolve()` and `is_relative_to()`.",
    "Write files atomically and with restrictive permissions.",
    "Parse untrusted JSON with size and shape limits.",
    "Explain why `pickle.loads` and `yaml.load` are remote code execution, and extract archives safely.",
  ],
  rules: [
    { id: "PY-PATH-TRAVERSAL", what: "paths built from input escape their directory" },
    { id: "PY-INSECURE-DESERIALIZE", what: "`pickle.loads` on untrusted bytes is RCE" },
    { id: "PY-YAML-UNSAFE", what: "`yaml.load` constructs arbitrary Python objects" },
    { id: "PY-ZIP-SLIP", what: "archive members can contain `../`" },
    { id: "PY-INSECURE-TEMP", what: "`mktemp` is a TOCTOU race" },
  ],
  capstone:
    "Day 36 builds a safe archive extractor: every member name validated, every destination confined, totals bounded against zip bombs.",

  lessons: [
    /* ----------------------------------------------------------------- 26 */
    {
      id: "m06l01",
      day: 32,
      title: "open(), with, and the file you forgot to close",
      minutes: 60,
      secure: "explicit encoding, guaranteed cleanup",
      cwe: ["CWE-404", "CWE-772"],
      tags: ["open", "with", "encoding", "modes", "pathlib"],
      lede:
        "Three details decide whether file handling is boring or a bug: the mode, the encoding, and whether the handle is closed when something raises.",
      blocks: [
        {
          t: "code",
          label: "example",
          code: `with open("report.csv", "r", encoding="utf-8") as fh:
    for line in fh:              # streams; never fh.read() on untrusted size
        process(line)
# closed here, even if process() raised`,
        },
        {
          t: "table",
          head: ["Mode", "Means", "If the file exists"],
          rows: [
            ["`\"r\"`", "read text (default)", "must exist, else `FileNotFoundError`"],
            ["`\"w\"`", "write text", "**truncated to empty**"],
            ["`\"a\"`", "append text", "writes at the end"],
            ["`\"x\"`", "exclusive create", "**fails** — the safe way to not clobber"],
            ["`\"rb\"` / `\"wb\"`", "binary", "no encoding, no newline translation"],
          ],
        },
        {
          t: "box",
          kind: "warn",
          title: "`\"w\"` destroys before it writes",
          md: `\`open(path, "w")\` truncates the file the moment it opens — before your program has computed anything to put in it. A crash two lines later leaves an empty file where the data was.

Use \`"x"\` when the file must not already exist, and write to a temporary file then rename when you are replacing content (next lesson).`,
        },
        { t: "h", text: "pathlib is the modern interface" },
        {
          t: "code",
          label: "example",
          code: `from pathlib import Path

base = Path("/srv/reports")
p = base / "q4.csv"              # the / operator joins

p.name          # 'q4.csv'
p.stem          # 'q4'
p.suffix        # '.csv'
p.parent        # PosixPath('/srv/reports')
p.exists(), p.is_file(), p.is_dir()
p.read_text(encoding="utf-8")
p.write_text(data, encoding="utf-8")
sorted(base.glob("*.csv"))`,
          cap: "`Path` objects carry the structure of a path instead of treating it as a string — which is what makes the confinement check in the next lesson possible.",
        },
        {
          t: "box",
          kind: "pitfall",
          title: "`base / user_input` does not confine anything",
          md: `\`\`\`
Path("/srv/reports") / "../../etc/passwd"
# PosixPath('/srv/reports/../../etc/passwd')  -> resolves to /etc/passwd

Path("/srv/reports") / "/etc/shadow"
# PosixPath('/etc/shadow')   <- an absolute right-hand side REPLACES the base
\`\`\`

The second behaviour surprises people: joining an absolute path discards everything to its left. Neither \`/\` nor \`os.path.join\` is a security boundary.`,
        },
        { t: "h", text: "Reading untrusted files" },
        {
          t: "code",
          label: "fixed",
          code: `MAX_BYTES = 5_000_000

def read_report(path):
    """Read a text file with every bound and decision made explicit."""
    if path.stat().st_size > MAX_BYTES:
        raise ValueError(f"file exceeds {MAX_BYTES} bytes")
    with path.open("r", encoding="utf-8", errors="replace", newline="") as fh:
        return fh.read()`,
          cap: "Check the size before reading. `errors=\"replace\"` keeps a mangled byte from killing an import job; `newline=\"\"` stops Python rewriting line endings under you (which matters for CSV and for signatures).",
        },
        {
          t: "box",
          kind: "good",
          title: "Symlinks and the file you did not mean to open",
          md: `\`open()\` follows symbolic links. If an attacker can create a file in the directory you read from, they can point \`report.csv\` at \`/etc/shadow\` or at a named pipe that never returns.

Where it matters: check \`path.is_symlink()\`, compare \`path.resolve()\` with what you expected, and prefer directories only your process can write.`,
        },
      ],
      quiz: [
        {
          q: "Why prefer `with open(...)` over `fh = open(...)` plus `fh.close()`?",
          options: [
            "It is shorter.",
            "The file is closed even when the block raises, so handles and buffers are never leaked.",
            "It is faster.",
          ],
          answer: 1,
          why:
            "An exception between `open` and `close` leaks the handle. In a long-running server that exhausts the file-descriptor limit, which takes down everything, not just the failing request.",
        },
        {
          q: "`Path(\"/srv/data\") / user_value` where `user_value` is `\"/etc/shadow\"` gives:",
          options: [
            "`/srv/data/etc/shadow`",
            "`/etc/shadow` — an absolute right-hand side replaces the base",
            "A `ValueError`",
          ],
          answer: 1,
          why: "Joining is not confinement. The next lesson adds the check that actually constrains the result.",
        },
        {
          q: "Which mode refuses to overwrite an existing file?",
          options: ["`\"w\"`", "`\"a\"`", "`\"x\"`"],
          answer: 2,
          why: "`\"x\"` raises `FileExistsError`, which is the correct behaviour when a collision means something has gone wrong.",
        },
      ],
      exercise: {
        title: "A bounded, explicit file reader",
        brief: `Write \`read_lines(path, *, max_bytes=100_000, max_lines=1000)\` using \`pathlib\`.

- \`path\` may be a \`str\` or \`Path\`; convert to \`Path\`.
- If it does not exist or is not a regular file → \`FileNotFoundError\`.
- If its size exceeds \`max_bytes\` → \`ValueError\` mentioning \`"bytes"\`. Check the size *before* opening.
- Read with \`encoding="utf-8"\`, \`errors="replace"\`, streaming line by line.
- Return a list of at most \`max_lines\` lines with trailing newlines removed.
- The file handle must be closed on every path — use \`with\`.

Also write \`write_once(path, text)\` that creates a new file with mode \`"x"\` and \`encoding="utf-8"\`, returning the number of characters written, and raising \`FileExistsError\` if it is already there.

(The exercise setup creates \`work/sample.txt\` with five lines and \`work/big.txt\`.)`,
        rubric: [
          "Reads and strips newlines, capped at `max_lines`",
          "Oversized files raise before being opened",
          "Missing files and directories raise `FileNotFoundError`",
          "`write_once` refuses to overwrite",
          "`with` is used; no leaked handles",
        ],
        setup: `import os
os.makedirs("work", exist_ok=True)
with open("work/sample.txt", "w", encoding="utf-8") as _fh:
    _fh.write("alpha\\nbravo\\ncharlie\\ndelta\\necho\\n")
with open("work/big.txt", "w", encoding="utf-8") as _fh:
    _fh.write("x" * 200_000)
os.makedirs("work/adir", exist_ok=True)
`,
        starter: `from pathlib import Path


def read_lines(path, *, max_bytes=100_000, max_lines=1000):
    """Return up to max_lines lines, with every bound explicit."""


def write_once(path, text):
    """Create a new file; refuse to overwrite. Return the character count."""


print(read_lines("work/sample.txt"))
`,
        stdin: [],
        tests: [
          {
            name: "reads and strips",
            code: `got = read_lines("work/sample.txt")
assert got == ["alpha", "bravo", "charlie", "delta", "echo"], f"got {got!r}"`,
          },
          {
            name: "accepts Path as well as str",
            code: `from pathlib import Path
assert read_lines(Path("work/sample.txt"))[0] == "alpha"`,
          },
          {
            name: "line cap applies",
            code: `assert read_lines("work/sample.txt", max_lines=2) == ["alpha", "bravo"]
assert read_lines("work/sample.txt", max_lines=0) == []`,
          },
          {
            name: "size is checked before opening",
            code: `try:
    read_lines("work/big.txt", max_bytes=1000)
    raise AssertionError("expected ValueError")
except ValueError as e:
    assert "bytes" in str(e), f"got {str(e)!r}"`,
          },
          {
            name: "missing paths and directories are FileNotFoundError",
            code: `with raises(FileNotFoundError):
    read_lines("work/nope.txt")
with raises(FileNotFoundError):
    read_lines("work/adir")`,
          },
          {
            name: "write_once creates and then refuses",
            code: `import os
target = "work/new-file.txt"
if os.path.exists(target):
    os.remove(target)
assert write_once(target, "hello") == 5
with open(target, encoding="utf-8") as fh:
    assert fh.read() == "hello"
with raises(FileExistsError):
    write_once(target, "again")`,
          },
          {
            name: "handles are not leaked on failure",
            code: `import gc
for _ in range(50):
    try:
        read_lines("work/nope.txt")
    except FileNotFoundError:
        pass
gc.collect()
assert read_lines("work/sample.txt")[0] == "alpha"`,
          },
        ],
        requirements: [
          { kind: "defines", value: "read_lines" },
          { kind: "defines", value: "write_once" },
          { kind: "uses_module", value: "pathlib" },
          { kind: "regex", value: "with\\s+.*open", message: "Use a `with` block so the handle closes on every path." },
        ],
        hints: [
          "`p = Path(path)` accepts both a str and a Path — `Path(Path(x))` is harmless.",
          "`p.is_file()` is False for directories *and* for missing paths, so one check covers both FileNotFoundError cases.",
          "`p.stat().st_size` is the byte size without opening the file.",
          "Cap while iterating rather than after: `for i, line in enumerate(fh): if i >= max_lines: break`. Reading everything and slicing defeats the purpose.",
        ],
        solution: `from pathlib import Path


def read_lines(path, *, max_bytes=100_000, max_lines=1000):
    """Return up to max_lines lines, with every bound explicit."""
    p = Path(path)

    if not p.is_file():
        raise FileNotFoundError(f"no such file: {p}")

    size = p.stat().st_size
    if size > max_bytes:
        raise ValueError(f"file exceeds {max_bytes} bytes (is {size})")

    out = []
    with p.open("r", encoding="utf-8", errors="replace", newline="") as fh:
        for index, line in enumerate(fh):
            if index >= max_lines:
                break
            out.append(line.rstrip("\\n").rstrip("\\r"))
    return out


def write_once(path, text):
    """Create a new file; refuse to overwrite. Return the character count."""
    p = Path(path)
    with p.open("x", encoding="utf-8") as fh:
        fh.write(text)
    return len(text)


print(read_lines("work/sample.txt"))`,
        why: `Every decision that \`open()\` would otherwise make for you is written down: the mode, the encoding, the error policy, the newline handling. On a different machine, with a different locale, this function behaves identically — which is the baseline requirement for anything whose output is hashed, signed, compared or billed.

The ordering is a resource control. \`stat()\` costs one syscall and no memory; opening a 40 GB file and discovering its size afterwards costs you the file descriptor and, if you had called \`.read()\`, the machine. Check cheaply, then act.

The line cap is applied *during* iteration. Written as \`fh.readlines()[:max_lines]\` it would read the whole file first and the bound would protect nothing — the same lazy-versus-eager distinction as \`islice\` in Module 3.

\`write_once\` uses mode \`"x"\` so a name collision is an error rather than silent data loss. When two processes race, exactly one succeeds and the other gets \`FileExistsError\` — the kernel provides that guarantee atomically, which no \`if path.exists()\` check can.`,
      },
      wrapup: `- \`with\` closes the handle even when the block raises.
- Always pass \`encoding="utf-8"\`; add \`errors="replace"\` for input you do not control.
- \`"w"\` truncates immediately; \`"x"\` refuses to clobber.
- \`stat()\` the size before reading, and bound while streaming, not after.`,
      refs: [
        { label: "pathlib", url: "https://docs.python.org/3/library/pathlib.html" },
        { label: "CWE-772: Missing Release of Resource", url: "https://cwe.mitre.org/data/definitions/772.html" },
      ],
    },

    /* ----------------------------------------------------------------- 27 */
    {
      id: "m06l02",
      day: 33,
      title: "Path traversal, and the only check that works",
      minutes: 60,
      secure: "resolve then confine",
      cwe: ["CWE-22"],
      tags: ["traversal", "pathlib", "resolve", "confinement", "symlink"],
      lede:
        "Rejecting `..` is a denylist, and denylists lose. The check that holds is: build the path, resolve it, and verify the *result* is inside the directory you meant.",
      blocks: [
        {
          t: "code",
          label: "vulnerable",
          code: `BASE = "/srv/files/"

def download(name):
    if ".." in name:                       # patch 1
        raise ValueError("no")
    if name.startswith("/"):               # patch 2
        raise ValueError("no")
    return open(BASE + name, "rb").read()`,
          cap: "Two patches already, and still broken: `....//` survives a single `..` removal upstream, URL-encoded forms arrive decoded later, and a symlink inside BASE points anywhere at all.",
        },
        {
          t: "code",
          label: "fixed",
          code: `from pathlib import Path

BASE = Path("/srv/files").resolve()

def safe_path(name):
    """Return a path guaranteed to be inside BASE, or raise."""
    candidate = (BASE / name).resolve()
    if not candidate.is_relative_to(BASE):      # Python 3.9+
        raise ValueError("path escapes the base directory")
    return candidate`,
          cap: "`resolve()` collapses `..`, follows symlinks and makes the path absolute. `is_relative_to` then asks the only question that matters: *did we end up inside?*",
        },
        {
          t: "box",
          kind: "rule",
          title: "Resolve, then compare — never inspect the input",
          md: `The input can be spelled a thousand ways. The *resolved result* has exactly one spelling. Check that.

\`\`\`
candidate = (BASE / untrusted).resolve()
if not candidate.is_relative_to(BASE):
    raise ValueError(...)
\`\`\`

Note that \`BASE\` must itself be resolved once, at import time, or the comparison can fail when \`/srv\` is a symlink.`,
        },
        {
          t: "repl",
          lines: [
            ">>> from pathlib import Path",
            '>>> BASE = Path("/srv/files").resolve()',
            '>>> (BASE / "../../etc/passwd").resolve()',
            "PosixPath('/etc/passwd')",
            '>>> (BASE / "../../etc/passwd").resolve().is_relative_to(BASE)',
            "False",
            '>>> (BASE / "sub/../ok.csv").resolve().is_relative_to(BASE)',
            "True",
          ],
        },
        {
          t: "box",
          kind: "warn",
          title: "String prefix checks are not equivalent",
          md: `\`\`\`
if not str(candidate).startswith(str(BASE)):   # WRONG
\`\`\`

\`/srv/files-backup/secret\` starts with \`/srv/files\`. The classic fix is to append a separator, which then fails on the base directory itself. \`is_relative_to\` compares path *components*, which is what you actually mean.

Before Python 3.9: \`os.path.commonpath([BASE, candidate]) == str(BASE)\`.`,
        },
        { t: "h", text: "Two layers, as usual" },
        {
          t: "code",
          label: "fixed",
          code: `import re
from pathlib import Path

BASE = Path("/srv/files").resolve()
SAFE_NAME = re.compile(r"\\A[A-Za-z0-9_-]{1,64}\\.(csv|json|txt)\\Z")

def open_report(name):
    if not SAFE_NAME.match(name):                 # layer 1: allowlist the input
        raise ValueError("file name not permitted")
    path = (BASE / name).resolve()
    if not path.is_relative_to(BASE):             # layer 2: confine the result
        raise ValueError("path escapes the base directory")
    if path.is_symlink():                         # layer 3: no indirection
        raise ValueError("symlinks are not permitted")
    return path.read_text(encoding="utf-8")`,
          cap: "The allowlist makes traversal unexpressible; the confinement check catches anything the allowlist is loosened to permit later.",
        },
        {
          t: "box",
          kind: "cve",
          title: "Still happening",
          md: `CVE-2021-41773 (Apache) traversed with an encoded \`.%2e/\`. CVE-2022-24706 and the long "zip slip" family write *outside* a directory during extraction. Python's own \`tarfile\` gained a \`filter=\` parameter in 3.12 (and backports) precisely because extracting archives safely by hand proved too error-prone — CVE-2007-4559 sat open for fifteen years.

The constant across all of them: something checked the input instead of checking the resolved result.`,
        },
      ],
      spot: {
        label: "attachment download",
        prompt: "Click the line that is supposed to be the security check but is not one.",
        lines: [7],
        why:
          "Line 7. A prefix comparison on strings passes for `/srv/files-backup/secret.csv`, which is a different directory, and it says nothing about symlinks inside the base. Replace it with `candidate.is_relative_to(BASE)` on the *resolved* path.",
        code: `from pathlib import Path

BASE = Path("/srv/files").resolve()

def download(name):
    candidate = (BASE / name).resolve()
    if not str(candidate).startswith(str(BASE)):
        raise ValueError("escape")
    return candidate.read_bytes()`,
      },
      quiz: [
        {
          q: "Why check the resolved path rather than the input string?",
          options: [
            "Resolving is faster.",
            "The input has many spellings; the resolved result has one, and it answers the real question.",
            "`resolve()` sanitises the string.",
          ],
          answer: 1,
          why:
            "Encodings, double dots, mixed separators and symlinks all collapse during resolution. Checking before resolution is checking a different value from the one you will use.",
        },
        {
          q: "`str(candidate).startswith(str(BASE))` — what does it miss?",
          options: [
            "Nothing.",
            "A sibling directory whose name extends the base, such as `/srv/files-backup`.",
            "Absolute paths.",
          ],
          answer: 1,
          why: "Prefix matching compares characters; `is_relative_to` compares path components, which is the semantic you intend.",
        },
        {
          q: "You already validate names against `\\A[a-z0-9_]+\\.csv\\Z`. Is the confinement check still worth writing?",
          options: [
            "No, it is redundant.",
            "Yes — it is the layer that survives someone relaxing the regex later.",
            "No, regexes are stronger.",
          ],
          answer: 1,
          why:
            "Defence in depth is about the change you have not seen yet. The regex will be loosened the first time a customer needs a dot or a slash in a name.",
        },
      ],
      exercise: {
        title: "A confined file reader",
        brief: `The setup creates \`data/reports/\` (with \`q4.csv\` and \`sub/nested.csv\`) and a sibling \`data/secret.txt\`.

Write:

1. \`safe_path(base, name)\` — join, resolve, and return the result only if it is inside the **resolved** base. Raise \`ValueError("path escapes the base directory")\` otherwise. \`base\` may be a \`str\` or \`Path\`.
2. \`read_report(name)\` — use \`safe_path\` with \`BASE = Path("data/reports")\`, additionally require that the name match \`\\A[A-Za-z0-9_/-]{1,64}\\.csv\\Z\` (note: a forward slash is permitted, so subdirectories work), and return the file's text.

Traversal must fail with \`ValueError\`, and a file that genuinely sits in a subdirectory must succeed.`,
        rubric: [
          "`q4.csv` and `sub/nested.csv` are readable",
          "`../secret.txt` and absolute paths raise `ValueError`, not `FileNotFoundError`",
          "`safe_path` judges the resolved path: `sub/../q4.csv` resolves inside the base and is accepted",
          "A sibling directory sharing the base's prefix is rejected",
          "Non-matching names are rejected before any filesystem access",
        ],
        setup: `import os
os.makedirs("data/reports/sub", exist_ok=True)
os.makedirs("data/reports-backup", exist_ok=True)
with open("data/reports/q4.csv", "w", encoding="utf-8") as _fh:
    _fh.write("region,revenue\\nemea,201885\\n")
with open("data/reports/sub/nested.csv", "w", encoding="utf-8") as _fh:
    _fh.write("nested,1\\n")
with open("data/secret.txt", "w", encoding="utf-8") as _fh:
    _fh.write("TOP SECRET\\n")
with open("data/reports-backup/old.csv", "w", encoding="utf-8") as _fh:
    _fh.write("old,1\\n")
`,
        starter: `import re
from pathlib import Path

BASE = Path("data/reports")
SAFE_NAME = re.compile(r"\\A[A-Za-z0-9_/-]{1,64}\\.csv\\Z")


def safe_path(base, name):
    """Return the resolved path, or raise if it escapes base."""


def read_report(name):
    """Validate the name, confine the path, return the text."""


print(read_report("q4.csv").strip())
`,
        stdin: [],
        tests: [
          {
            name: "reads a report and a nested report",
            code: `assert "emea" in read_report("q4.csv")
assert "nested" in read_report("sub/nested.csv")`,
          },
          {
            name: "traversal is refused as a ValueError",
            code: `for bad in ("../secret.txt", "../../data/secret.txt", "sub/../../secret.txt"):
    try:
        read_report(bad)
        raise AssertionError(f"{bad!r} should have been refused")
    except ValueError:
        pass
    except FileNotFoundError:
        raise AssertionError(f"{bad!r} reached the filesystem; confine before opening")`,
          },
          {
            name: "absolute paths do not replace the base",
            code: `for bad in ("/data/secret.txt", "/etc/passwd"):
    with raises(ValueError):
        read_report(bad)`,
          },
          {
            name: "confinement judges the resolved path, not the spelling",
            code: `got = safe_path("data/reports", "sub/../q4.csv")
assert str(got).endswith("data/reports/q4.csv"), f"a path resolving inside the base must be accepted: {got!r}"
with raises(ValueError):
    read_report("sub/../q4.csv")   # the stricter name allowlist rejects it first`,
          },
          {
            name: "safe_path rejects a prefix-sharing sibling",
            code: `with raises(ValueError):
    safe_path("data/reports", "../reports-backup/old.csv")
got = safe_path("data/reports", "q4.csv")
assert str(got).endswith("data/reports/q4.csv"), f"got {got!r}"`,
          },
          {
            name: "safe_path works on a str or a Path",
            code: `from pathlib import Path
a = safe_path("data/reports", "q4.csv")
b = safe_path(Path("data/reports"), "q4.csv")
assert a == b`,
          },
          {
            name: "the name allowlist is applied",
            code: `for bad in ("q4.txt", "", "a" * 70 + ".csv", "q4.csv\\nrm -rf /", "q4%2ecsv", "q4.csv "):
    with raises(ValueError):
        read_report(bad)`,
          },
        ],
        requirements: [
          { kind: "defines", value: "safe_path" },
          { kind: "defines", value: "read_report" },
          { kind: "calls", value: "is_relative_to", message: "Confine the resolved path with `is_relative_to`." },
        ],
        hints: [
          "`root = Path(base).resolve()` first — resolving the base too is what makes the comparison reliable.",
          "`candidate = (root / name).resolve()`. Remember that an absolute `name` replaces `root` entirely, which is exactly why the check afterwards is required.",
          "`candidate.is_relative_to(root)` returns a bool; raise `ValueError` when it is False.",
          "In `read_report`, match the regex *before* touching the filesystem, so a rejected name never produces a `FileNotFoundError` that leaks whether a path exists.",
        ],
        solution: `import re
from pathlib import Path

BASE = Path("data/reports")
SAFE_NAME = re.compile(r"\\A[A-Za-z0-9_/-]{1,64}\\.csv\\Z")


def safe_path(base, name):
    """Return the resolved path, or raise if it escapes base."""
    root = Path(base).resolve()
    candidate = (root / name).resolve()

    if not candidate.is_relative_to(root):
        raise ValueError("path escapes the base directory")

    return candidate


def read_report(name):
    """Validate the name, confine the path, return the text."""
    if not isinstance(name, str) or not SAFE_NAME.match(name):
        raise ValueError("file name not permitted")

    path = safe_path(BASE, name)
    return path.read_text(encoding="utf-8")


print(read_report("q4.csv").strip())`,
        why: `The confinement check never looks at what the caller typed. It builds the path, resolves it to its single canonical form, and asks whether that form lives inside the base. Every spelling of traversal — \`..\`, \`....//\`, an absolute path, a symlink, a mix of all four — collapses before the question is asked.

\`safe_path\` resolves the *base* as well. Without that, a deployment where \`data\` is a symlink to \`/mnt/vol1/data\` would resolve the candidate to the real location and compare it against the symlinked base, and every legitimate request would be rejected. Resolving both sides keeps the check correct and avoids the "fix" of weakening it.

The two layers do different jobs. The regex makes traversal *unexpressible* for this endpoint, and rejects before any filesystem access — so a probe for \`/etc/shadow\` cannot even learn whether the path exists from the timing or the error type. The confinement check makes traversal *ineffective* regardless of what the regex permits, which is the layer that still stands when someone adds \`.\` to the character class next year.

\`read_report\` deliberately raises \`ValueError\` for both failures rather than letting \`FileNotFoundError\` escape: the caller learns the request was invalid, not whether a given path exists.`,
      },
      wrapup: `- Resolve the candidate and the base, then check \`is_relative_to\`. Never inspect the raw input.
- \`startswith\` on strings is not confinement — \`/srv/files-backup\` shares the prefix.
- Joining an absolute path discards the base entirely.
- Validate the name first so rejected requests never touch the filesystem.`,
      refs: [
        { label: "Path.is_relative_to", url: "https://docs.python.org/3/library/pathlib.html#pathlib.PurePath.is_relative_to" },
        { label: "CWE-22: Path Traversal", url: "https://cwe.mitre.org/data/definitions/22.html" },
      ],
    },

    /* ----------------------------------------------------------------- 28 */
    {
      id: "m06l03",
      day: 34,
      title: "Writing files: atomicity, permissions, and temp-file races",
      minutes: 60,
      secure: "atomic writes, safe temp files",
      cwe: ["CWE-377", "CWE-367", "CWE-732"],
      tags: ["tempfile", "atomic", "rename", "permissions", "toctou"],
      lede:
        "A file that is half-written is a file that will be read half-written. And a temporary file created the obvious way is a race an attacker can win.",
      blocks: [
        {
          t: "code",
          label: "vulnerable",
          code: `def save_config(path, data):
    with open(path, "w", encoding="utf-8") as fh:   # truncates immediately
        fh.write(render(data))                      # crash here -> empty config`,
          cap: "Between truncation and the final flush, the file on disk is wrong. A reader in that window gets a partial file; a crash makes the damage permanent.",
        },
        {
          t: "code",
          label: "fixed",
          code: `import os, tempfile
from pathlib import Path

def save_atomic(path, text, *, mode=0o600):
    """Write to a temp file in the same directory, then rename over the target."""
    path = Path(path)
    fd, tmp = tempfile.mkstemp(dir=path.parent, prefix=f".{path.name}.", suffix=".tmp")
    try:
        with os.fdopen(fd, "w", encoding="utf-8") as fh:
            fh.write(text)
            fh.flush()
            os.fsync(fh.fileno())        # the bytes are on the disk, not just in cache
        os.chmod(tmp, mode)
        os.replace(tmp, path)            # atomic on POSIX and Windows
    except BaseException:
        os.unlink(tmp)                   # never leave the temp file behind
        raise`,
          cap: "`os.replace` is atomic: a reader sees either the entire old file or the entire new one, never a mixture. The temp file must be in the *same directory* so the rename stays within one filesystem.",
        },
        {
          t: "box",
          kind: "rule",
          title: "`mkstemp`, never `mktemp`",
          md: `\`tempfile.mktemp()\` returns a *name* and nothing else. Between its return and your \`open()\`, anyone with write access to that directory can create that path — as a symlink to \`/etc/passwd\`, or to a file they can read afterwards. Your process then writes through it with your privileges.

\`mkstemp()\` creates the file atomically with \`O_CREAT|O_EXCL\` and mode \`0600\`, and hands you the descriptor. There is no window. The auditor flags \`mktemp\` as **medium**; treat it as never.`,
        },
        {
          t: "box",
          kind: "pitfall",
          title: "TOCTOU: the check that expires",
          md: `\`\`\`
if not path.exists():        # time of check
    path.write_text(data)    # time of use -- someone created it in between
\`\`\`

Any gap between checking a filesystem property and acting on it is exploitable when another account can write to that directory. The fix is to make the kernel do both at once: open with \`"x"\` (\`O_EXCL\`), use \`mkstemp\`, or operate on a file descriptor you already hold.`,
        },
        { t: "h", text: "Permissions, and the umask that surprises you" },
        {
          t: "table",
          head: ["Mode", "Meaning", "Use for"],
          rows: [
            ["`0o600`", "owner read/write", "secrets, tokens, private keys"],
            ["`0o644`", "owner write, world read", "public config, static content"],
            ["`0o700`", "owner only, directories", "private directories"],
            ["`0o777`", "everyone writes", "**never** — this is a finding"],
          ],
        },
        {
          t: "code",
          label: "fixed",
          code: `import os

fd = os.open("/etc/app/token", os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
with os.fdopen(fd, "w", encoding="utf-8") as fh:
    fh.write(token)`,
          cap: "`os.open` with an explicit mode and `O_EXCL` creates the file with the right permissions from the first instant — rather than creating it world-readable and chmod-ing a moment later.",
        },
        {
          t: "box",
          kind: "cve",
          title: "The window is real",
          md: `Symlink and TOCTOU races in temp-file handling account for a steady stream of local privilege escalations — frequently in installers, log rotation and backup scripts running as root on a machine where \`/tmp\` is world-writable.

The pattern is always the same: a predictable name, a gap in time, and a directory someone else can write to.`,
        },
      ],
      quiz: [
        {
          q: "Why write to a temp file and `os.replace` instead of writing in place?",
          options: [
            "It is faster.",
            "`os.replace` is atomic, so a concurrent reader never sees a partially written file.",
            "It avoids permissions issues.",
          ],
          answer: 1,
          why:
            "Readers see the old file or the new one. In-place writing exposes an inconsistent window and makes a crash permanent.",
        },
        {
          q: "What is wrong with `tempfile.mktemp()`?",
          options: [
            "It is deprecated but safe.",
            "It returns a name without creating the file, leaving a race where an attacker creates that path first.",
            "It creates the file world-writable.",
          ],
          answer: 1,
          why: "Use `mkstemp()`, which creates the file atomically with mode 0600 and returns a descriptor.",
        },
        {
          q: "Why must the temp file be in the same directory as the target?",
          options: [
            "For tidiness.",
            "`os.replace` is only atomic within one filesystem; across devices it degrades to copy-then-delete.",
            "It is not necessary.",
          ],
          answer: 1,
          why: "A rename across filesystems is not a rename. Creating the temp file beside the target keeps the operation atomic.",
        },
      ],
      exercise: {
        title: "save_atomic(): no partial files, no races",
        brief: `Write \`save_atomic(path, text, *, mode=0o600)\` and \`save_secret(path, text)\`.

\`save_atomic\`:

1. Create the temporary file with \`tempfile.mkstemp(dir=<target's parent>)\` — never \`mktemp\`.
2. Write \`text\` with \`encoding="utf-8"\`, flush, and \`os.fsync\`.
3. \`os.chmod\` the temp file to \`mode\`.
4. \`os.replace\` it onto the target.
5. On **any** exception, remove the temp file and re-raise. No stray \`.tmp\` files may survive a failure.
6. Return the number of characters written.

\`save_secret(path, text)\` calls \`save_atomic\` with mode \`0o600\` and additionally raises \`ValueError\` when \`text\` is empty.

The setup provides \`vault/\` as a working directory.`,
        rubric: [
          "The target contains the complete new text after a successful call",
          "An existing file is replaced, not appended to",
          "A failure during writing leaves the original intact and no temp file behind",
          "The resulting file's mode is `0o600` for secrets",
          "`mkstemp` is used, `mktemp` is not",
        ],
        setup: `import os
os.makedirs("vault", exist_ok=True)
`,
        starter: `import os
import tempfile
from pathlib import Path


def save_atomic(path, text, *, mode=0o600):
    """Write text to path atomically. Return the character count."""


def save_secret(path, text):
    """Write a non-empty secret with owner-only permissions."""


print(save_atomic("vault/config.txt", "key=value\\n"))
`,
        stdin: [],
        tests: [
          {
            name: "writes the file",
            code: `n = save_atomic("vault/a.txt", "hello world")
assert n == 11, f"got {n!r}"
with open("vault/a.txt", encoding="utf-8") as fh:
    assert fh.read() == "hello world"`,
          },
          {
            name: "replaces rather than appends",
            code: `save_atomic("vault/b.txt", "first")
save_atomic("vault/b.txt", "second")
with open("vault/b.txt", encoding="utf-8") as fh:
    assert fh.read() == "second", "the file should be replaced wholesale"`,
          },
          {
            name: "permissions are restrictive",
            code: `import os, stat
save_secret("vault/token.txt", "s3cret-value")
perm = stat.S_IMODE(os.stat("vault/token.txt").st_mode)
assert perm == 0o600, f"expected 0o600, got {oct(perm)}"`,
          },
          {
            name: "failure leaves no temp file and no damage",
            code: `import os
save_atomic("vault/c.txt", "original")
before = set(os.listdir("vault"))

class Boom(Exception):
    pass

class BadStr(str):
    def __len__(self):
        raise Boom("write failed")

try:
    save_atomic("vault/c.txt", BadStr("x" * 10))
except Exception:
    pass

with open("vault/c.txt", encoding="utf-8") as fh:
    content = fh.read()
after = set(os.listdir("vault"))
assert after == before, f"stray files left behind: {sorted(after - before)}"`,
          },
          {
            name: "an unwritable directory does not leave debris",
            code: `import os
before = set(os.listdir("vault"))
try:
    save_atomic("vault/nope/deep.txt", "x")
except Exception:
    pass
assert set(os.listdir("vault")) == before, "a failed write left files behind"`,
          },
          {
            name: "save_secret refuses empty values",
            code: `for bad in ("", None):
    with raises(ValueError):
        save_secret("vault/empty.txt", bad)`,
          },
          {
            name: "mkstemp is used instead of mktemp",
            code: `assert True  # enforced by the exercise requirements below`,
          },
        ],
        requirements: [
          { kind: "defines", value: "save_atomic" },
          { kind: "calls", value: "tempfile.mkstemp", message: "Create the temporary file with `tempfile.mkstemp`." },
          { kind: "calls", value: "os.replace", message: "Move the temp file into place with `os.replace`." },
          { kind: "forbids", value: "mktemp\\s*\\(", message: "`mktemp` is a race condition — use `mkstemp`." },
          { kind: "no_finding", value: "PY-INSECURE-TEMP" },
        ],
        hints: [
          "`fd, tmp = tempfile.mkstemp(dir=Path(path).parent, prefix=\".\", suffix=\".tmp\")` — the `dir` argument is what keeps the later rename atomic.",
          "`os.fdopen(fd, \"w\", encoding=\"utf-8\")` wraps the descriptor you were given. Opening `tmp` by name again would reintroduce a race.",
          "Wrap everything after `mkstemp` in `try/except BaseException:` that calls `os.unlink(tmp)` and re-raises. Catching `BaseException` here is correct — even a `KeyboardInterrupt` must not leave debris.",
          "Compute the length before writing if you want to return it; the test deliberately raises from `__len__` to check your cleanup path.",
        ],
        solution: `import os
import tempfile
from pathlib import Path


def save_atomic(path, text, *, mode=0o600):
    """Write text to path atomically. Return the character count."""
    target = Path(path)

    fd, tmp = tempfile.mkstemp(dir=str(target.parent), prefix=f".{target.name}.", suffix=".tmp")
    try:
        with os.fdopen(fd, "w", encoding="utf-8") as fh:
            fh.write(text)
            fh.flush()
            os.fsync(fh.fileno())
        os.chmod(tmp, mode)
        os.replace(tmp, target)
    except BaseException:
        try:
            os.unlink(tmp)
        except OSError:
            pass
        raise

    return len(text)


def save_secret(path, text):
    """Write a non-empty secret with owner-only permissions."""
    if not isinstance(text, str) or not text:
        raise ValueError("refusing to write an empty secret")
    return save_atomic(path, text, mode=0o600)


print(save_atomic("vault/config.txt", "key=value\\n"))`,
        why: `The target file is never open for writing. It is replaced, in one indivisible operation, by a file that was already complete and already had the right permissions. A reader either sees the previous version or the new one — there is no window in which it sees neither.

Each step closes a specific hole:

- **\`mkstemp\` instead of a chosen name** removes the race entirely. The kernel creates the file with \`O_CREAT|O_EXCL\` at mode 0600 and hands back a descriptor, so there is no interval during which an attacker can substitute a symlink.
- **\`dir=target.parent\`** keeps the temp file on the same filesystem. \`os.replace\` across devices is a copy followed by a delete, which is neither atomic nor crash-safe.
- **\`fsync\` before the rename** means the data is durable before it becomes visible. Without it, a power loss can leave a renamed file whose contents were still in the page cache — a correctly-named empty file, which is worse than no file.
- **\`except BaseException\` on the cleanup path.** This is the one place where catching everything is right: the handler does not swallow anything, it removes the temp file and re-raises immediately. Catching only \`Exception\` would leave debris behind on \`KeyboardInterrupt\` during a long write.

\`save_secret\` refusing an empty value is a small thing that prevents a large class of incident: a credential file truncated to zero bytes by a bug upstream, which then fails open in whatever reads it.`,
      },
      wrapup: `- Write to a temp file in the same directory, fsync, then \`os.replace\`.
- \`mkstemp\` creates atomically at 0600; \`mktemp\` just guesses a name.
- Any check-then-act on the filesystem is a race. Let the kernel do both at once.
- Create secrets at 0600 from the first instant rather than chmod-ing afterwards.`,
      refs: [
        { label: "tempfile", url: "https://docs.python.org/3/library/tempfile.html" },
        { label: "CWE-367: Time-of-check Time-of-use Race Condition", url: "https://cwe.mitre.org/data/definitions/367.html" },
      ],
    },

    /* ----------------------------------------------------------------- 29 */
    {
      id: "m06l04",
      day: 35,
      title: "pickle and yaml: when loading data runs code",
      minutes: 60,
      secure: "never deserialize untrusted data",
      cwe: ["CWE-502"],
      tags: ["pickle", "yaml", "json", "deserialization", "rce"],
      lede:
        "`json.loads` builds dicts and lists. `pickle.loads` calls functions named in the payload. The difference between a parser and an interpreter is the difference between a data format and a shell.",
      blocks: [
        {
          t: "p",
          md: `A pickle is not a data format — it is a small stack language whose instructions include *call this callable with these arguments*. The \`__reduce__\` protocol exists so objects can describe how to rebuild themselves, and it works exactly as well for rebuilding a subprocess.`,
        },
        {
          t: "code",
          label: "vulnerable",
          code: `import pickle

class Exploit:
    def __reduce__(self):
        import os
        return (os.system, ("cat /etc/shadow",))

payload = pickle.dumps(Exploit())      # ~60 bytes
# ... later, somewhere else entirely:
pickle.loads(payload)                  # runs the command`,
          cap: "No bug is being exploited. This is pickle working as designed, which is why the documentation says plainly: never unpickle data from an untrusted source.",
        },
        {
          t: "box",
          kind: "try",
          title: "Watch yaml.load do the same thing",
          md: `The simulated \`yaml\` module in this course implements the real behaviour: \`yaml.load\` honours \`!!python/object/apply:\` tags, \`yaml.safe_load\` refuses them.

\`\`\`
import yaml
yaml.load("hook: !!python/object/apply:os.system ['id']")
\`\`\`

Run that in the console and check the **Breach** tab, then change it to \`safe_load\` and watch it refuse.`,
        },
        {
          t: "table",
          head: ["Format", "Loader", "Can it execute?", "Verdict for untrusted input"],
          rows: [
            ["JSON", "`json.loads`", "No", "**Safe** — add size/depth limits."],
            ["YAML", "`yaml.safe_load`", "No", "**Safe.**"],
            ["YAML", "`yaml.load` (no SafeLoader)", "**Yes**", "Never."],
            ["Pickle", "`pickle.loads`", "**Yes**", "Never."],
            ["Marshal / shelve / dill", "various", "**Yes**", "Never."],
            ["XML", "`xml.etree`", "entity expansion, DTD", "Use `defusedxml`."],
            ["Literals", "`ast.literal_eval`", "No", "Safe for literal structures."],
          ],
        },
        {
          t: "box",
          kind: "rule",
          title: "The rule, and the exception",
          md: `**Rule:** data crossing a trust boundary is parsed by a parser — \`json.loads\`, \`yaml.safe_load\`, \`csv\`, \`ast.literal_eval\`.

**Exception:** pickle is acceptable for data your own process produced and stored where nothing else can write, *and* where you verify an HMAC over the bytes before loading. If you cannot state both conditions in one sentence about your system, the answer is no.

Note that pickle appears in places people forget: \`torch.load\`, \`pandas.read_pickle\`, \`joblib.load\`, Celery's pickle serializer, and any cache or session store configured with it. A downloaded model file is an executable.`,
        },
        { t: "h", text: "JSON is safe to parse, not safe to trust" },
        {
          t: "code",
          label: "fixed",
          code: `import json

MAX_BYTES = 100_000

def parse_event(raw):
    """Parse untrusted JSON into a validated shape."""
    if len(raw) > MAX_BYTES:
        raise ValueError("payload too large")
    try:
        data = json.loads(raw)
    except json.JSONDecodeError as exc:
        raise ValueError("payload is not valid JSON") from exc

    if not isinstance(data, dict):
        raise ValueError("payload must be an object")
    kind = data.get("type")
    if kind not in ("login", "logout"):
        raise ValueError("unsupported event type")
    return {"type": kind, "user_id": int(data.get("user_id", 0))}`,
          cap: "`json.loads` cannot execute anything, but it will happily hand you a 400-level-deep structure or a dict with the keys you did not expect. Parsing is step one; validating the shape is step two.",
        },
        {
          t: "box",
          kind: "warn",
          title: "JSON still has limits worth setting",
          md: `- **Size** — check the byte length before parsing.
- **Depth** — deeply nested arrays can exhaust the C stack during parsing; Python raises \`RecursionError\`, which is a 500 if you do not catch it.
- **Numbers** — \`{"n": 1e9999}\` parses to \`inf\`; a huge integer literal is a memory allocation.
- **Duplicate keys** — \`{"role":"user","role":"admin"}\` is accepted by \`json.loads\`, last value wins. If a proxy or a different language's parser upstream picked the *first*, you have a parser-confusion bug.`,
        },
      ],
      spot: {
        label: "session cache",
        prompt: "Click the line that gives anyone who can write to the cache remote code execution.",
        lines: [8],
        why:
          "Line 8. `pickle.loads` on bytes fetched from a shared cache means anyone who can write a key in that cache — another tenant, a compromised service, an unauthenticated Redis — executes code in this process. `json.loads` plus explicit field validation removes the primitive entirely.",
        code: `import pickle

class SessionStore:
    def __init__(self, cache):
        self.cache = cache

    def load(self, session_id):
        blob = self.cache.get(f"sess:{session_id}")
        return pickle.loads(blob) if blob else {}`,
      },
      quiz: [
        {
          q: "Why can `pickle.loads` execute code?",
          options: [
            "A bug in the module.",
            "The format includes instructions that call callables named in the payload — `__reduce__` by design.",
            "Only when the data is encrypted.",
          ],
          answer: 1,
          why:
            "It is a designed capability, not a defect. That is why no amount of input filtering makes unpickling untrusted bytes safe.",
        },
        {
          q: "`yaml.load(text)` versus `yaml.safe_load(text)`:",
          options: [
            "Identical.",
            "`load` constructs arbitrary Python objects from tags such as `!!python/object/apply`; `safe_load` refuses.",
            "`safe_load` only handles small documents.",
          ],
          answer: 1,
          why: "Use `safe_load` for anything you did not write yourself. The auditor rates the unsafe form critical.",
        },
        {
          q: "You must cache Python objects between requests. What makes pickle acceptable?",
          options: [
            "Nothing ever does.",
            "The bytes never leave your trust boundary, and you verify an HMAC before loading.",
            "Base64-encoding the pickle.",
          ],
          answer: 1,
          why:
            "Authenticity is the requirement: you must know the bytes are the ones you wrote. Encoding is not authentication, and a shared cache is not a trust boundary.",
        },
      ],
      exercise: {
        title: "Replacing a pickle cache with a safe one",
        brief: `A session store currently pickles. Rewrite it with JSON plus an HMAC so that tampering is detected and no deserialization primitive exists.

Write:

1. \`dump_session(data, key)\` — serialise \`data\` (a dict of JSON-safe values) to a string \`"<b64url-payload>.<hex-signature>"\`, where the signature is HMAC-SHA256 of the base64 payload under \`key\`.
2. \`load_session(blob, key, *, max_bytes=10_000)\` — split, verify with \`hmac.compare_digest\`, decode, \`json.loads\`, and return the dict.
   - Oversized blob → \`ValueError("session too large")\`
   - Wrong shape, bad base64, or bad JSON → \`ValueError("malformed session")\`
   - Signature mismatch → \`ValueError("session signature invalid")\`
   - Decoded value that is not a dict → \`ValueError("malformed session")\`
3. Use \`base64.urlsafe_b64encode\`; no padding issues — keep the padding.

Never import \`pickle\`.`,
        rubric: [
          "Round-trips a dict unchanged",
          "A tampered payload is rejected before parsing is trusted",
          "A wrong key is rejected",
          "`hmac.compare_digest` is used",
          "Malformed input raises `ValueError`, never a crash",
          "`pickle` is not imported",
        ],
        starter: `import base64
import hashlib
import hmac
import json


def dump_session(data, key):
    """Return '<payload>.<signature>'."""


def load_session(blob, key, *, max_bytes=10_000):
    """Verify, decode and return the session dict."""


KEY = "k" * 32
blob = dump_session({"user_id": 7, "role": "member"}, KEY)
print(load_session(blob, KEY))
`,
        stdin: [],
        tests: [
          {
            name: "round-trips",
            code: `key = "k" * 32
data = {"user_id": 7, "role": "member", "tags": ["a", "b"], "ok": True, "n": None}
assert load_session(dump_session(data, key), key) == data`,
          },
          {
            name: "the blob has two dot-separated parts",
            code: `key = "k" * 32
blob = dump_session({"a": 1}, key)
assert isinstance(blob, str), f"got {type(blob).__name__}"
assert blob.count(".") == 1, f"got {blob!r}"`,
          },
          {
            name: "tampering with the payload is detected",
            code: `import base64, json
key = "k" * 32
blob = dump_session({"user_id": 7, "role": "member"}, key)
payload, sig = blob.split(".")
forged = base64.urlsafe_b64encode(json.dumps({"user_id": 7, "role": "admin"}).encode()).decode()
try:
    load_session(f"{forged}.{sig}", key)
    raise AssertionError("forged payload was accepted")
except ValueError as e:
    assert "signature" in str(e), f"got {str(e)!r}"`,
          },
          {
            name: "a wrong key is rejected",
            code: `key = "k" * 32
blob = dump_session({"a": 1}, key)
with raises(ValueError):
    load_session(blob, "j" * 32)`,
          },
          {
            name: "malformed input is a ValueError, never a crash",
            code: `key = "k" * 32
for bad in ("", "nodot", "a.b.c", "!!!.aaa", "YWJj.zz", ".", "a.", ".a"):
    try:
        load_session(bad, key)
        raise AssertionError(f"{bad!r} should have been refused")
    except ValueError:
        pass`,
          },
          {
            name: "size is bounded",
            code: `key = "k" * 32
big = dump_session({"blob": "x" * 50_000}, key)
try:
    load_session(big, key)
    raise AssertionError("expected ValueError")
except ValueError as e:
    assert "too large" in str(e), f"got {str(e)!r}"`,
          },
          {
            name: "a signed non-dict is refused",
            code: `import base64, json, hashlib, hmac
key = "k" * 32
payload = base64.urlsafe_b64encode(json.dumps([1, 2, 3]).encode()).decode()
sig = hmac.new(key.encode(), payload.encode(), hashlib.sha256).hexdigest()
try:
    load_session(f"{payload}.{sig}", key)
    raise AssertionError("a signed list was accepted as a session")
except ValueError as e:
    assert "malformed" in str(e), f"got {str(e)!r}"`,
          },
        ],
        requirements: [
          { kind: "defines", value: "dump_session" },
          { kind: "defines", value: "load_session" },
          { kind: "forbids_module", value: "pickle", message: "Do not import `pickle` — that is the primitive this exercise removes." },
          { kind: "calls", value: "hmac.compare_digest" },
          { kind: "no_finding", value: "PY-INSECURE-DESERIALIZE" },
        ],
        hints: [
          "`payload = base64.urlsafe_b64encode(json.dumps(data).encode()).decode()` then sign the *payload string*, not the original JSON — sign exactly what you transmit.",
          "Split defensively: `parts = blob.split(\".\")` and require `len(parts) == 2` and both parts non-empty before using them.",
          "Verify the signature **before** base64-decoding and parsing. The order is the point: nothing untrusted gets parsed until it is proven to be yours.",
          "Wrap the decode and `json.loads` in `try/except (ValueError, TypeError, binascii.Error)` — base64 raises `binascii.Error`, which is a subclass of `ValueError`, so catching `ValueError` is enough.",
        ],
        solution: `import base64
import hashlib
import hmac
import json


def _sign(payload, key):
    return hmac.new(key.encode(), payload.encode(), hashlib.sha256).hexdigest()


def dump_session(data, key):
    """Return '<payload>.<signature>'."""
    payload = base64.urlsafe_b64encode(json.dumps(data).encode()).decode()
    return f"{payload}.{_sign(payload, key)}"


def load_session(blob, key, *, max_bytes=10_000):
    """Verify, decode and return the session dict."""
    if not isinstance(blob, str):
        raise ValueError("malformed session")
    if len(blob) > max_bytes:
        raise ValueError("session too large")

    parts = blob.split(".")
    if len(parts) != 2 or not parts[0] or not parts[1]:
        raise ValueError("malformed session")
    payload, signature = parts

    # Verify first: nothing untrusted is parsed until it is proven to be ours.
    if not hmac.compare_digest(_sign(payload, key), signature):
        raise ValueError("session signature invalid")

    try:
        data = json.loads(base64.urlsafe_b64decode(payload.encode()).decode("utf-8"))
    except (ValueError, UnicodeDecodeError) as exc:
        raise ValueError("malformed session") from exc

    if not isinstance(data, dict):
        raise ValueError("malformed session")
    return data


KEY = "k" * 32
blob = dump_session({"user_id": 7, "role": "member"}, KEY)
print(load_session(blob, KEY))`,
        why: `There is no deserialization primitive left to attack. \`json.loads\` constructs dicts, lists, strings and numbers — nothing else exists in the format — so even a payload that passes the signature check cannot do more than produce a surprising dict, which the final \`isinstance\` and the caller's own validation handle.

The order of operations carries the security:

1. **Size**, because it is the cheapest check and a 50 MB cookie should never reach the HMAC.
2. **Shape**, so the split cannot raise and no index is taken from a string that does not have the parts.
3. **Signature**, before any decoding. Parsing first and verifying afterwards would hand untrusted bytes to the base64 and JSON parsers — a smaller attack surface than pickle, but not zero, and the ordering costs nothing.
4. **Type**, because a signed \`[1,2,3]\` is still not a session. Signatures prove *origin*, never *shape*.

Signing the base64 payload rather than the raw JSON is deliberate: you sign the exact bytes you transmit, so there is no re-encoding step between verification and use where a difference could creep in.

What this does **not** provide is confidentiality — the payload is readable by anyone holding the cookie. If a session must carry something the user may not read, encrypt it or, better, store it server-side and put only an opaque id in the cookie.`,
      },
      wrapup: `- \`pickle.loads\` and \`yaml.load\` execute code by design. Never on untrusted bytes.
- Pickle hides inside \`torch.load\`, \`pandas.read_pickle\`, \`joblib.load\` and cache backends.
- JSON cannot execute, but still needs size, depth and shape limits.
- When you must round-trip your own data, sign it and verify before parsing.`,
      refs: [
        { label: "pickle — security warning", url: "https://docs.python.org/3/library/pickle.html#module-pickle" },
        { label: "CWE-502: Deserialization of Untrusted Data", url: "https://cwe.mitre.org/data/definitions/502.html" },
      ],
    },

    /* ----------------------------------------------------------------- 30 */
    {
      id: "m06l05",
      day: 36,
      title: "Capstone: an archive extractor that cannot escape",
      minutes: 60,
      secure: "zip slip and zip bombs",
      cwe: ["CWE-22", "CWE-409"],
      tags: ["capstone", "zip", "extraction", "traversal", "dos"],
      lede:
        "An uploaded archive is a list of file names chosen by the attacker, each with a size they also chose. Extraction is where path confinement and resource limits meet.",
      blocks: [
        {
          t: "p",
          md: `\`ZipFile.extractall()\` writes every member to the path recorded inside the archive. Those names are data. They can contain \`../\`, absolute paths, or — on some tools — Windows drive letters and backslashes.`,
        },
        {
          t: "code",
          label: "vulnerable",
          code: `import zipfile

def unpack(archive_path, dest):
    with zipfile.ZipFile(archive_path) as zf:
        zf.extractall(dest)          # member names are attacker-controlled`,
          cap: "A member named `../../../../home/app/.ssh/authorized_keys` is written exactly there. This is \"zip slip\", and it has affected archive handling in most languages.",
        },
        { t: "h", text: "The three bounds an extractor needs" },
        {
          t: "table",
          head: ["Threat", "Control"],
          rows: [
            ["Zip slip — member escapes the destination", "Resolve each destination and confine with `is_relative_to`."],
            ["Zip bomb — 42 KB expands to 4.5 PB", "Cap total uncompressed bytes **and** the compression ratio."],
            ["Too many members", "Cap the member count before iterating."],
            ["Symlink members", "Skip anything that is not a regular file."],
            ["Absolute member names", "Rejected by the confinement check; reject explicitly for a clearer error."],
          ],
        },
        {
          t: "code",
          label: "fixed",
          code: `from pathlib import Path
import zipfile

MAX_MEMBERS = 1_000
MAX_TOTAL = 100 * 1024 * 1024          # 100 MB uncompressed
MAX_RATIO = 100                         # per-member compression ratio

def unpack(archive_path, dest):
    dest = Path(dest).resolve()
    written, total = [], 0
    with zipfile.ZipFile(archive_path) as zf:
        infos = zf.infolist()
        if len(infos) > MAX_MEMBERS:
            raise ValueError("archive has too many members")
        for info in infos:
            if info.is_dir():
                continue
            target = (dest / info.filename).resolve()
            if not target.is_relative_to(dest):
                raise ValueError(f"member escapes destination: {info.filename!r}")
            if info.compress_size and info.file_size / info.compress_size > MAX_RATIO:
                raise ValueError("suspicious compression ratio")
            total += info.file_size
            if total > MAX_TOTAL:
                raise ValueError("archive expands beyond the size limit")
            target.parent.mkdir(parents=True, exist_ok=True)
            with zf.open(info) as src, open(target, "wb") as out:
                out.write(src.read())
            written.append(target)
    return written`,
          cap: "Checks happen per member, before writing. The ratio test catches the classic bomb; the running total catches the slow version that uses a thousand modest members.",
        },
        {
          t: "box",
          kind: "cve",
          title: "42.zip and CVE-2007-4559",
          md: `The \`42.zip\` bomb is 42 kilobytes and expands to 4.5 petabytes through nested layers. It has been publicly known since 2001 and still fills disks.

Python's \`tarfile\` carried CVE-2007-4559 — \`extractall\` honouring \`../\` — for **fifteen years**, affecting thousands of downstream projects. Python 3.12 added \`filter="data"\` as the safe default-in-waiting. Where available, use it; where not, write the loop above.`,
        },
        {
          t: "box",
          kind: "good",
          title: "`Path.mkdir(parents=True)` and the parent you did not check",
          md: `Creating the parent directory for each member is necessary — but do it only after the confinement check, or a member named \`../evil/x\` creates \`../evil/\` before you reject it. Check first, then create.`,
        },
      ],
      quiz: [
        {
          q: "Why is `zf.extractall(dest)` unsafe for an uploaded archive?",
          options: [
            "It is slow.",
            "Member names are attacker-controlled and may contain `../` or absolute paths.",
            "It does not create directories.",
          ],
          answer: 1,
          why: "Zip slip. Each destination must be resolved and confined before anything is written.",
        },
        {
          q: "What does a compression-ratio check catch that a total-size check does not?",
          options: [
            "Nothing extra.",
            "A single small member that expands enormously — caught before the write rather than during it.",
            "Encrypted archives.",
          ],
          answer: 1,
          why:
            "The ratio is visible in the member header, so it can be refused before any bytes are written. A running total is the backstop for many modest members.",
        },
        {
          q: "When should the destination directory be created for a member?",
          options: [
            "Before the confinement check, so the path exists.",
            "After the confinement check.",
            "It does not matter.",
          ],
          answer: 1,
          why: "Creating directories first lets a rejected member still create `../evil/` as a side effect. Validate, then act.",
        },
      ],
      exercise: {
        title: "safe_unpack(): confined, bounded, and proven",
        brief: `The setup creates three archives in \`arch/\`: \`good.zip\` (two harmless files, one in a subdirectory), \`slip.zip\` (contains a member named \`../escaped.txt\`), and \`bomb.zip\` (a member whose declared uncompressed size is enormous relative to its compressed size).

Write \`safe_unpack(archive_path, dest, *, max_members=100, max_total=1_000_000, max_ratio=100)\`:

- Resolve \`dest\`; create it if missing.
- Raise \`ValueError\` when the archive has more than \`max_members\` entries.
- For each non-directory member, in order:
  1. resolve the destination and raise \`ValueError\` containing \`"escapes"\` if it is not inside \`dest\`;
  2. raise \`ValueError\` containing \`"ratio"\` when \`file_size / compress_size\` exceeds \`max_ratio\` (treat a zero \`compress_size\` as fine);
  3. add \`file_size\` to a running total and raise \`ValueError\` containing \`"size"\` when it exceeds \`max_total\`;
  4. create the parent directory **after** those checks, then write the member.
- Return the sorted list of written paths as strings.
- Nothing may be written outside \`dest\`, including when the function raises.`,
        rubric: [
          "`good.zip` extracts both members, including the nested one",
          "`slip.zip` raises `ValueError` mentioning `escapes` and writes nothing outside the destination",
          "`bomb.zip` raises before writing the oversized member",
          "Member count and running total are enforced",
          "Parent directories are created only after the checks pass",
        ],
        setup: `import os, zipfile
os.makedirs("arch", exist_ok=True)
os.makedirs("out", exist_ok=True)

with zipfile.ZipFile("arch/good.zip", "w") as _zf:
    _zf.writestr("notes.txt", "hello\\n")
    _zf.writestr("sub/data.csv", "a,b\\n1,2\\n")

with zipfile.ZipFile("arch/slip.zip", "w") as _zf:
    _zf.writestr("ok.txt", "fine\\n")
    _zf.writestr("../escaped.txt", "PWNED\\n")

with zipfile.ZipFile("arch/bomb.zip", "w", zipfile.ZIP_DEFLATED) as _zf:
    _zf.writestr("bomb.txt", "0" * 2_000_000)
`,
        starter: `import zipfile
from pathlib import Path


def safe_unpack(archive_path, dest, *, max_members=100, max_total=1_000_000, max_ratio=100):
    """Extract an archive, confined to dest and bounded in size."""


print(safe_unpack("arch/good.zip", "out/good"))
`,
        stdin: [],
        tests: [
          {
            name: "a harmless archive extracts, including nested members",
            code: `import os
got = safe_unpack("arch/good.zip", "out/a")
assert len(got) == 2, f"got {got!r}"
assert os.path.exists("out/a/notes.txt"), "top-level member missing"
assert os.path.exists("out/a/sub/data.csv"), "nested member missing"
with open("out/a/sub/data.csv", encoding="utf-8") as fh:
    assert fh.read().startswith("a,b")`,
          },
          {
            name: "zip slip is refused",
            code: `try:
    safe_unpack("arch/slip.zip", "out/b")
    raise AssertionError("the slip archive was extracted")
except ValueError as e:
    assert "escapes" in str(e), f"got {str(e)!r}"`,
          },
          {
            name: "nothing is written outside the destination",
            code: `import os
try:
    safe_unpack("arch/slip.zip", "out/c")
except ValueError:
    pass
assert not os.path.exists("out/escaped.txt"), "a member escaped the destination"
assert not os.path.exists("/escaped.txt"), "a member escaped to the filesystem root"`,
          },
          {
            name: "the compression ratio bound fires",
            code: `try:
    safe_unpack("arch/bomb.zip", "out/d", max_ratio=5)
    raise AssertionError("the bomb was extracted")
except ValueError as e:
    assert "ratio" in str(e), f"got {str(e)!r}"`,
          },
          {
            name: "the total size bound fires",
            code: `try:
    safe_unpack("arch/bomb.zip", "out/e", max_ratio=10_000_000, max_total=1000)
    raise AssertionError("expected a size refusal")
except ValueError as e:
    assert "size" in str(e), f"got {str(e)!r}"`,
          },
          {
            name: "the member count bound fires",
            code: `try:
    safe_unpack("arch/good.zip", "out/f", max_members=1)
    raise AssertionError("expected a member-count refusal")
except ValueError:
    pass`,
          },
          {
            name: "no stray directories are created for rejected members",
            code: `import os
before = set(os.listdir("out"))
try:
    safe_unpack("arch/slip.zip", "out/g")
except ValueError:
    pass
after = set(os.listdir("out"))
assert after - before <= {"g"}, f"unexpected directories created: {sorted(after - before)}"`,
          },
        ],
        requirements: [
          { kind: "defines", value: "safe_unpack" },
          { kind: "calls", value: "is_relative_to", message: "Confine each member with `is_relative_to`." },
          { kind: "forbids", value: "extractall", message: "`extractall` is the vulnerability — write the loop yourself." },
          { kind: "no_finding", value: "PY-ZIP-SLIP" },
        ],
        hints: [
          "`dest = Path(dest).resolve()` after `mkdir(parents=True, exist_ok=True)` — resolving a path that does not exist still works, but creating it first keeps the comparison honest on systems with symlinked temp dirs.",
          "`zf.infolist()` gives you `ZipInfo` objects with `.filename`, `.file_size`, `.compress_size` and `.is_dir()` — all the metadata you need to decide *before* reading any content.",
          "The ratio check: `if info.compress_size and info.file_size / info.compress_size > max_ratio`. Guarding on `compress_size` avoids a ZeroDivisionError for empty members.",
          "`with zf.open(info) as src, open(target, \"wb\") as out: out.write(src.read())` — and note `src.read()` is bounded here only because you already checked `file_size`.",
        ],
        solution: `import zipfile
from pathlib import Path


def safe_unpack(archive_path, dest, *, max_members=100, max_total=1_000_000, max_ratio=100):
    """Extract an archive, confined to dest and bounded in size."""
    dest = Path(dest)
    dest.mkdir(parents=True, exist_ok=True)
    dest = dest.resolve()

    written = []
    total = 0

    with zipfile.ZipFile(archive_path) as zf:
        infos = zf.infolist()

        if len(infos) > max_members:
            raise ValueError(f"archive has {len(infos)} members, limit is {max_members}")

        for info in infos:
            if info.is_dir():
                continue

            target = (dest / info.filename).resolve()
            if not target.is_relative_to(dest):
                raise ValueError(f"member escapes destination: {info.filename!r}")

            if info.compress_size and info.file_size / info.compress_size > max_ratio:
                raise ValueError(f"suspicious compression ratio in {info.filename!r}")

            total += info.file_size
            if total > max_total:
                raise ValueError(f"archive expands beyond the size limit of {max_total} bytes")

            # Only now is it safe to create directories and write.
            target.parent.mkdir(parents=True, exist_ok=True)
            with zf.open(info) as src, open(target, "wb") as out:
                out.write(src.read())
            written.append(str(target))

    return sorted(written)


print(safe_unpack("arch/good.zip", "out/good"))`,
        why: `Every decision is made from the archive's *metadata* before a single byte is written. \`ZipInfo\` tells you the declared name, the uncompressed size and the compressed size, which is enough to reject a slip, a bomb or an oversized archive without touching the disk.

The two confinement details that matter:

- **\`resolve()\` on both sides, then \`is_relative_to\`.** The member name \`../escaped.txt\` resolves to a path outside \`dest\`, and the comparison catches it regardless of how the name was spelled. An absolute member name is caught by the same check, for free.
- **\`mkdir\` after the check, not before.** Reversed, the member \`../evil/payload\` would create \`out/../evil/\` as a side effect of preparing to write, and the subsequent rejection would leave an attacker-named directory behind. Validate, then act — the same rule as the TOCTOU lesson, applied to directory creation.

The two resource bounds are deliberately different in kind. The **ratio** check catches the classic bomb: one member, small on disk, enormous when expanded, refused from its header alone. The **running total** catches the version that evades the ratio check by using a thousand members that are each individually reasonable. Either alone leaves a gap.

Note what is absent: \`extractall\`. The entire vulnerability class lives inside that one convenience method, and the loop that replaces it is fifteen lines.`,
      },
      wrapup: `- Member names are attacker data. Resolve and confine every destination.
- Bound the member count, the per-member ratio, and the running total — they catch different attacks.
- Create directories only after a member passes its checks.
- Prefer \`tarfile.extractall(filter="data")\` on 3.12+; otherwise write the loop.`,
      refs: [
        { label: "zipfile", url: "https://docs.python.org/3/library/zipfile.html" },
        { label: "tarfile extraction filters", url: "https://docs.python.org/3/library/tarfile.html#extraction-filters" },
        { label: "CWE-409: Improper Handling of Highly Compressed Data", url: "https://cwe.mitre.org/data/definitions/409.html" },
      ],
    },
  ],
};
