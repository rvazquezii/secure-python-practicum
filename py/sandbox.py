"""Secure Python Trainer -- execution sandbox, test harness and AST security auditor.

This module is plain CPython (stdlib only) so it runs identically under Pyodide in
the browser and under python3 on the command line for unit testing.

Public entry points (all take/return JSON strings so the JS side stays simple):

    SPT_run(payload_json)    -> execute submission, run tests, audit, return verdict
    SPT_audit(payload_json)  -> audit only (fast, used for live linting while typing)
    SPT_repl(payload_json)   -> feed one line/block to a persistent REPL namespace
    SPT_reset_repl()         -> clear the REPL namespace
"""

import ast
import builtins
import codeop
import contextlib
import io
import json
import re
import sys
import traceback

try:
    import teachlib
except ImportError:  # pragma: no cover - teachlib is always shipped alongside
    teachlib = None

SEVERITY_ORDER = {"critical": 0, "high": 1, "medium": 2, "low": 3, "info": 4}
BLOCKING = ("critical", "high")

SECRET_NAME = re.compile(
    # Short tokens are anchored: an unbounded "pin" matches "unpinned",
    # "sig" matches "design", and a noisy auditor is an ignored auditor.
    r"(pass(word|wd|phrase)?|pwd|secret|token|api[_-]?key|apikey|access[_-]?key"
    r"|private[_-]?key|client[_-]?secret|credential|signature|passphrase"
    r"|session[_-]?id|cookie[_-]?value|bearer"
    r"|\bpin\b|\botp\b|\bsig\b|\bcreds?\b|authorization)",
    re.I,
)
PATHY_NAME = re.compile(r"(path|file|filename|fname|dir|folder|name|target|doc|upload)", re.I)
UNTRUSTED_NAME = re.compile(
    r"(user|input|request|param|query|form|body|payload|untrusted|client|remote"
    r"|\breq\b|\bargs?\b|\bargv\b|\braw\b|\braw_|_raw\b|\bcmd\b)",
    re.I,
)
PLACEHOLDER_SECRET = re.compile(r"^(|x+|\.\.\.|<.*>|changeme|todo|replace[_-]?me)$", re.I)


def _looks_like_credential(value):
    """Credentials are opaque tokens. Prose under a secret-ish name is not one."""
    return bool(value) and len(value) >= 4 and not any(c.isspace() for c in value) \
        and not PLACEHOLDER_SECRET.match(value)
NESTED_QUANTIFIER = re.compile(r"(\((?:[^()]*[+*]){1,}[^()]*\)\s*[+*])|(\[[^\]]+\]\+\)\+)")


# --------------------------------------------------------------------------- #
# helpers
# --------------------------------------------------------------------------- #
def _dotted(node):
    """Return the dotted source text of a Name/Attribute chain, else ''."""
    bits = []
    cur = node
    while isinstance(cur, ast.Attribute):
        bits.append(cur.attr)
        cur = cur.value
    if isinstance(cur, ast.Name):
        bits.append(cur.id)
        return ".".join(reversed(bits))
    if isinstance(cur, ast.Call):
        return ""
    return ""


def _kw(call, name):
    for k in call.keywords:
        if k.arg == name:
            return k.value
    return None


def _const_bool(node):
    return isinstance(node, ast.Constant) and node.value is True


def _is_falsy_const(node):
    return isinstance(node, ast.Constant) and node.value is False


def _str_const(node):
    if isinstance(node, ast.Constant) and isinstance(node.value, str):
        return node.value
    return None


def _node_src(src_lines, node):
    try:
        return src_lines[node.lineno - 1].strip()
    except Exception:
        return ""


def _names_in(node):
    out = set()
    for n in ast.walk(node):
        if isinstance(n, ast.Name):
            out.add(n.id)
        elif isinstance(n, ast.Attribute):
            out.add(n.attr)
    return out


def _is_dynamic_string(node):
    """True when a string is assembled at runtime (concat, %, .format, f-string)."""
    if isinstance(node, ast.JoinedStr):
        return any(isinstance(v, ast.FormattedValue) for v in node.values)
    if isinstance(node, ast.BinOp) and isinstance(node.op, (ast.Add, ast.Mod)):
        return True
    if isinstance(node, ast.Call):
        f = node.func
        if isinstance(f, ast.Attribute) and f.attr in ("format", "join", "format_map"):
            return True
    return False


# --------------------------------------------------------------------------- #
# auditor
# --------------------------------------------------------------------------- #
class Auditor(ast.NodeVisitor):
    """AST walk that produces security findings and positive-practice signals."""

    def __init__(self, source):
        self.source = source
        self.lines = source.splitlines()
        self.findings = []
        self.good = []
        self.alias = {}          # local name -> fully qualified module/func
        self.imported = set()    # top-level module names actually imported
        self.func_stack = []
        self.func_nodes = []
        self.seen_ids = set()

    # -- emit ------------------------------------------------------------- #
    def flag(self, node, rule_id, severity, title, detail, fix, cwe=""):
        key = (rule_id, getattr(node, "lineno", 0))
        if key in self.seen_ids:
            return
        self.seen_ids.add(key)
        self.findings.append(
            {
                "id": rule_id,
                "severity": severity,
                "line": getattr(node, "lineno", 0),
                "col": getattr(node, "col_offset", 0),
                "title": title,
                "detail": detail,
                "fix": fix,
                "cwe": cwe,
                "snippet": _node_src(self.lines, node),
            }
        )

    def praise(self, node, title, detail):
        key = ("GOOD:" + title, getattr(node, "lineno", 0))
        if key in self.seen_ids:
            return
        self.seen_ids.add(key)
        self.good.append({"title": title, "detail": detail, "line": getattr(node, "lineno", 0)})

    def enclosing_src(self):
        """Source of the innermost enclosing function, for whole-function heuristics."""
        if not self.func_nodes:
            return self.source
        fn = self.func_nodes[-1]
        end = getattr(fn, "end_lineno", None) or len(self.lines)
        return "\n".join(self.lines[fn.lineno - 1:end])

    def resolve(self, node):
        """Resolve a call target to its canonical dotted path, honouring aliases."""
        raw = _dotted(node)
        if not raw:
            return ""
        head, _, rest = raw.partition(".")
        base = self.alias.get(head, head)
        return base + ("." + rest if rest else "")

    # -- imports ---------------------------------------------------------- #
    def visit_Import(self, node):
        for a in node.names:
            self.alias[a.asname or a.name.split(".")[0]] = a.name
            self.imported.add(a.name.split(".")[0])
            if a.name in ("pickle", "cPickle", "dill", "marshal", "shelve"):
                self.flag(
                    node, "PY-IMPORT-PICKLE", "low",
                    f"`{a.name}` imported",
                    f"`{a.name}` executes arbitrary code during deserialization. Importing it is "
                    "only safe if every byte you load was produced and signed by you.",
                    "Prefer `json` for data you did not create yourself.",
                    "CWE-502",
                )
            if a.name == "secrets":
                self.praise(node, "secrets module", "Cryptographically secure randomness source.")
            if a.name == "hmac":
                self.praise(node, "hmac module", "Enables constant-time comparison of secrets.")
        self.generic_visit(node)

    def visit_ImportFrom(self, node):
        mod = node.module or ""
        self.imported.add(mod.split(".")[0])
        for a in node.names:
            self.alias[a.asname or a.name] = f"{mod}.{a.name}" if mod else a.name
        if mod == "secrets":
            self.praise(node, "secrets module", "Cryptographically secure randomness source.")
        self.generic_visit(node)

    # -- functions -------------------------------------------------------- #
    def visit_FunctionDef(self, node):
        self._function(node)

    def visit_AsyncFunctionDef(self, node):
        self._function(node)

    def _function(self, node):
        pos = node.args.posonlyargs + node.args.args
        pairs = list(zip(pos[len(pos) - len(node.args.defaults):], node.args.defaults))
        pairs += [(a, d) for a, d in zip(node.args.kwonlyargs, node.args.kw_defaults) if d is not None]
        for arg, d in pairs:
            if isinstance(d, (ast.List, ast.Dict, ast.Set)):
                self.flag(
                    node, "PY-MUTABLE-DEFAULT", "low",
                    f"Mutable default for `{arg.arg}`",
                    "Default arguments are evaluated once, at definition time. Every call shares "
                    "the same object, so one caller's data leaks into the next call.",
                    "Use `def f(items=None):` then `items = [] if items is None else items`.",
                    "CWE-1188",
                )
            s = _str_const(d)
            if s and _looks_like_credential(s) and SECRET_NAME.search(arg.arg):
                self.flag(
                    node, "PY-HARDCODED-SECRET", "high",
                    f"Secret as the default for `{arg.arg}`",
                    "A credential baked into a function signature ships with the source, lands "
                    "in version control, and is readable by anyone with the package.",
                    "Default to `None` and load the real value from the environment or a secret manager.",
                    "CWE-798",
                )
        self.func_stack.append(node.name)
        self.func_nodes.append(node)
        self.generic_visit(node)
        self.func_nodes.pop()
        self.func_stack.pop()

    # -- assignments ------------------------------------------------------ #
    def visit_Assign(self, node):
        for t in node.targets:
            nm = t.id if isinstance(t, ast.Name) else (t.attr if isinstance(t, ast.Attribute) else "")
            if nm and SECRET_NAME.search(nm):
                s = _str_const(node.value)
                if s is not None and _looks_like_credential(s):
                    if not re.search(r"(hash|digest|algo|field|label|header|prompt|column|key_name)", nm, re.I):
                        self.flag(
                            node, "PY-HARDCODED-SECRET", "high",
                            f"Hardcoded secret in `{nm}`",
                            "Credentials in source code are copied into every clone, backup, log and "
                            "container image. Rotation becomes a code change, so it never happens.",
                            "Read it at runtime: `os.environ['APP_TOKEN']`, and fail closed when it is missing.",
                            "CWE-798",
                        )
                if isinstance(node.value, ast.Call):
                    tgt = self.resolve(node.value.func)
                    if tgt.startswith("random."):
                        self.flag(
                            node, "PY-WEAK-RANDOM", "high",
                            f"`{tgt}()` used to generate `{nm}`",
                            "`random` is a Mersenne Twister PRNG. Observing ~624 outputs reveals its "
                            "internal state, which makes every past and future value predictable.",
                            "Use `secrets.token_urlsafe(32)` / `secrets.randbelow(n)` for anything a user must not guess.",
                            "CWE-338",
                        )
        self._dict_secret_scan(node.value)
        self.generic_visit(node)

    def _dict_secret_scan(self, value):
        if not isinstance(value, ast.Dict):
            return
        for k, v in zip(value.keys, value.values):
            ks = _str_const(k) or ""
            vs = _str_const(v)
            if ks and SECRET_NAME.search(ks) and vs and _looks_like_credential(vs):
                self.flag(
                    value, "PY-HARDCODED-SECRET", "high",
                    f"Hardcoded secret under key '{ks}'",
                    "A config dict literal is still source code. This value is in your repository history.",
                    "Build the dict from `os.environ` at startup.",
                    "CWE-798",
                )

    # -- comparisons ------------------------------------------------------ #
    def visit_Compare(self, node):
        if any(isinstance(o, (ast.Eq, ast.NotEq)) for o in node.ops):
            names = _names_in(node)
            if any(SECRET_NAME.search(n) for n in names):
                if not any(
                    "compare_digest" in (self.resolve(c.func) if isinstance(c, ast.Call) else "")
                    for c in ast.walk(node) if isinstance(c, ast.Call)
                ):
                    self.flag(
                        node, "PY-TIMING-COMPARE", "medium",
                        "Secret compared with `==`",
                        "`==` on bytes/str short-circuits at the first differing byte. The response-time "
                        "difference is measurable over a network and leaks the value one byte at a time.",
                        "Use `hmac.compare_digest(a, b)`, which always inspects the full length.",
                        "CWE-208",
                    )
        self.generic_visit(node)

    # -- exception handling ----------------------------------------------- #
    def visit_ExceptHandler(self, node):
        body_is_pass = len(node.body) == 1 and isinstance(node.body[0], ast.Pass)
        broad = node.type is None or _dotted(node.type) in ("Exception", "BaseException")
        if body_is_pass:
            self.flag(
                node, "PY-SWALLOWED-ERROR", "medium",
                "Exception silently swallowed",
                "A security control that fails quietly fails open. Signature checks, permission "
                "lookups and parse errors all vanish into this `pass`.",
                "Log the error and re-raise, or return an explicit denial. Never `pass`.",
                "CWE-390",
            )
        elif broad and node.type is None:
            self.flag(
                node, "PY-BARE-EXCEPT", "low",
                "Bare `except:`",
                "A bare except also catches `KeyboardInterrupt` and `SystemExit`, so the process "
                "cannot be stopped cleanly and real bugs hide behind it.",
                "Catch the specific exception you can actually handle: `except ValueError:`.",
                "CWE-396",
            )
        for n in node.body:
            for c in ast.walk(n):
                if isinstance(c, ast.Call) and self.resolve(c.func) in ("print",):
                    for a in c.args:
                        src = _node_src(self.lines, c)
                        if "traceback" in src or "format_exc" in src:
                            self.flag(
                                c, "PY-TRACEBACK-LEAK", "medium",
                                "Traceback printed to the caller",
                                "Stack traces expose file paths, library versions, SQL fragments and "
                                "local variable names -- a free map of your system for an attacker.",
                                "Log the detail server-side; return a generic message with a correlation id.",
                                "CWE-209",
                            )
        self.generic_visit(node)

    def visit_Assert(self, node):
        enclosing = self.func_stack[-1] if self.func_stack else ""
        # Judge the asserted EXPRESSION, not the failure message: an assert whose
        # message happens to mention "authenticated" is not an authorization check.
        try:
            tested = ast.unparse(node.test)
        except Exception:
            tested = _node_src(self.lines, node)
        ctx = enclosing + " " + tested
        if re.search(r"(auth|admin|permission|role|allowed|is_owner|can_|access|valid)", ctx, re.I):
            self.flag(
                node, "PY-ASSERT-AUTH", "high",
                "`assert` used as a security check",
                "`assert` statements are removed entirely when Python runs with `-O` or "
                "`PYTHONOPTIMIZE=1`. The check disappears in production and everyone becomes an admin.",
                "Use an explicit `if not allowed: raise PermissionError(...)`.",
                "CWE-617",
            )
        self.generic_visit(node)

    # -- calls ------------------------------------------------------------ #
    def visit_Call(self, node):
        target = self.resolve(node.func)
        attr = node.func.attr if isinstance(node.func, ast.Attribute) else ""
        first = node.args[0] if node.args else None

        # --- arbitrary code execution ---
        if target in ("eval", "exec", "builtins.eval", "builtins.exec"):
            literal = isinstance(first, ast.Constant)
            self.flag(
                node, "PY-EVAL", "critical" if not literal else "high",
                f"`{target.split('.')[-1]}()` on {'runtime data' if not literal else 'a string literal'}",
                "This hands the Python interpreter to whoever controls the string. "
                "`__import__('os').system('...')` fits in one expression.",
                "Parse instead of execute: `int(x)`, `json.loads(x)`, `ast.literal_eval(x)`, or a dict of allowed operations.",
                "CWE-95",
            )
        if target in ("os.system", "os.popen", "commands.getoutput", "commands.getstatusoutput", "popen2.popen2"):
            self.flag(
                node, "PY-SHELL-EXEC", "critical",
                f"`{target}()` runs a shell",
                "The whole string goes to /bin/sh, where `;`, `&&`, `|`, `$()` and backticks are "
                "operators. One quote in user data becomes command execution.",
                "Use `subprocess.run([prog, arg1, arg2], shell=False, check=True)` -- a list, never a string.",
                "CWE-78",
            )
        if target.startswith("subprocess."):
            sh = _kw(node, "shell")
            if _const_bool(sh):
                self.flag(
                    node, "PY-SHELL-TRUE", "critical",
                    "`shell=True`",
                    "With shell=True the argument is parsed by /bin/sh, so shell metacharacters in "
                    "any interpolated value become commands.",
                    "Drop shell=True and pass a list of arguments; the OS executes the program directly.",
                    "CWE-78",
                )
            elif isinstance(first, ast.List) or _is_falsy_const(sh) or sh is None:
                if isinstance(first, ast.List):
                    self.praise(node, "argument list, no shell",
                                "Passing a list keeps the shell out of the picture entirely.")
            if first is not None and _is_dynamic_string(first) and not isinstance(first, ast.List):
                self.flag(
                    node, "PY-CMD-BUILD", "high",
                    "Command assembled from a formatted string",
                    "Building the command line as text re-introduces quoting bugs even without a shell.",
                    "Keep each argument a separate list element: `[\"grep\", pattern, path]`.",
                    "CWE-78",
                )

        # --- deserialization ---
        if target in ("pickle.load", "pickle.loads", "cPickle.load", "cPickle.loads",
                      "dill.load", "dill.loads", "marshal.loads", "shelve.open",
                      "pandas.read_pickle", "joblib.load", "torch.load"):
            self.flag(
                node, "PY-INSECURE-DESERIALIZE", "critical",
                f"`{target}()` on untrusted bytes is remote code execution",
                "Unpickling calls `__reduce__` on the payload, which can name any callable with any "
                "arguments. A 60-byte blob is enough to spawn a shell.",
                "Use `json.loads()` for data crossing a trust boundary. If you must use pickle, sign it with HMAC and verify first.",
                "CWE-502",
            )
        if target in ("yaml.load", "yaml.load_all"):
            loader = _kw(node, "Loader") or (node.args[1] if len(node.args) > 1 else None)
            ldr = _dotted(loader) if loader is not None else ""
            if "Safe" not in ldr:
                self.flag(
                    node, "PY-YAML-UNSAFE", "critical",
                    "`yaml.load()` without SafeLoader",
                    "The default YAML loader honours `!!python/object/apply:os.system`, which turns a "
                    "config file into an execution primitive.",
                    "Use `yaml.safe_load(stream)`.",
                    "CWE-502",
                )
            else:
                self.praise(node, "SafeLoader specified", "Python object tags are rejected.")
        if target in ("yaml.safe_load", "yaml.safe_load_all"):
            self.praise(node, "yaml.safe_load", "Only plain YAML types are constructed.")
        if target == "json.loads":
            self.praise(node, "json.loads", "JSON parses to inert data -- no code paths.")
        if target == "ast.literal_eval":
            self.praise(node, "ast.literal_eval", "Evaluates literals only; no calls, no imports.")

        # --- SQL ---
        if attr in ("execute", "executemany", "executescript") and first is not None:
            if _is_dynamic_string(first):
                self.flag(
                    node, "PY-SQLI", "critical",
                    "SQL query built by string formatting",
                    "The database receives one blob of text and cannot tell your query from the "
                    "attacker's. `' OR 1=1 --` ends the WHERE clause; `'; DROP TABLE users --` ends the table.",
                    "Use placeholders and let the driver bind: "
                    "`cur.execute(\"SELECT * FROM users WHERE id = ?\", (user_id,))`.",
                    "CWE-89",
                )
            elif isinstance(first, ast.Constant) and len(node.args) > 1:
                self.praise(node, "parameterized query",
                            "Values are bound by the driver, never parsed as SQL.")
            if attr == "executescript":
                self.flag(
                    node, "PY-SQL-MULTI", "medium",
                    "`executescript()` allows statement stacking",
                    "executescript runs every `;`-separated statement, so one injected semicolon "
                    "gets a second query for free.",
                    "Use `execute()` with placeholders for anything containing input.",
                    "CWE-89",
                )

        # --- hashing / crypto ---
        if target in ("hashlib.md5", "hashlib.sha1", "hashlib.new"):
            algo = _str_const(first) if target == "hashlib.new" else target.split(".")[-1]
            ufs = _kw(node, "usedforsecurity")
            if algo and algo.lower() in ("md5", "sha1") and not _is_falsy_const(ufs):
                self.flag(
                    node, "PY-WEAK-HASH", "high",
                    f"`{algo}` is a broken hash",
                    "MD5 and SHA-1 both have practical collision attacks (SHAttered, 2017). They must "
                    "not be used for signatures, integrity checks or password storage.",
                    "Use `hashlib.sha256` for integrity; for passwords use `hashlib.scrypt` or `pbkdf2_hmac`. "
                    "If the hash is a non-security cache key, say so: `hashlib.md5(x, usedforsecurity=False)`.",
                    "CWE-327",
                )
        if target in ("hashlib.sha256", "hashlib.sha512", "hashlib.sha3_256"):
            ctx = _node_src(self.lines, node)
            if re.search(r"(pass(word|wd)?|pwd|credential)", ctx, re.I):
                self.flag(
                    node, "PY-FAST-HASH-PASSWORD", "high",
                    "Password stored with a fast hash",
                    "A GPU computes billions of SHA-256 hashes per second, so a stolen table of "
                    "SHA-256 passwords is cracked at human-password speed. SHA-256 is fast by design.",
                    "Use a deliberately slow KDF: `hashlib.scrypt(pw, salt=salt, n=2**15, r=8, p=1)` "
                    "or `hashlib.pbkdf2_hmac('sha256', pw, salt, 600_000)`. In production: argon2 or bcrypt.",
                    "CWE-916",
                )
        if target in ("hashlib.pbkdf2_hmac", "hashlib.scrypt"):
            self.praise(node, "password KDF", "Slow, salted key derivation -- the right tool for passwords.")
        if target in ("hmac.compare_digest", "secrets.compare_digest"):
            self.praise(node, "constant-time compare", "No timing side channel on secret comparison.")
        if target.startswith("secrets."):
            self.praise(node, f"{target}()", "Unpredictable values from the OS CSPRNG.")
        if target.startswith("random.") and target != "random.SystemRandom":
            ctx = _node_src(self.lines, node)
            if re.search(SECRET_NAME, ctx) or re.search(r"(nonce|iv|salt|reset|invite|coupon|id\b)", ctx, re.I):
                self.flag(
                    node, "PY-WEAK-RANDOM", "high",
                    f"`{target}()` for a security-relevant value",
                    "`random` is seeded predictably and its state is recoverable from its output. "
                    "Password-reset tokens generated this way have been brute-forced in the wild.",
                    "Use the `secrets` module: `secrets.token_urlsafe(32)`, `secrets.randbelow(n)`, `secrets.choice(seq)`.",
                    "CWE-338",
                )

        # --- TLS / network ---
        if target.startswith("requests.") or target in ("httpx.get", "httpx.post", "urllib3.request"):
            v = _kw(node, "verify")
            if _is_falsy_const(v):
                self.flag(
                    node, "PY-TLS-VERIFY-OFF", "critical",
                    "`verify=False` disables certificate validation",
                    "Without verification, TLS encrypts the connection to whoever answered -- including "
                    "the attacker on the path. Confidentiality and authenticity are both gone.",
                    "Remove `verify=False`. For an internal CA, point verify at the CA bundle: `verify='/etc/ssl/corp-ca.pem'`.",
                    "CWE-295",
                )
            if _kw(node, "timeout") is None and target.split(".")[-1] in ("get", "post", "put", "delete", "head", "patch", "request"):
                self.flag(
                    node, "PY-NO-TIMEOUT", "low",
                    "HTTP call with no timeout",
                    "requests waits forever by default. A slow or hostile server pins your worker "
                    "thread indefinitely -- a one-line denial of service.",
                    "Always pass `timeout=(connect, read)`, e.g. `timeout=(3.05, 10)`.",
                    "CWE-400",
                )
            else:
                if _kw(node, "timeout") is not None:
                    self.praise(node, "explicit timeout", "The call cannot hang forever.")
            url = first
            if url is not None and _is_dynamic_string(url) and any(UNTRUSTED_NAME.search(n) for n in _names_in(url)):
                self.flag(
                    node, "PY-SSRF", "high",
                    "URL built from untrusted input",
                    "Server-side request forgery: the attacker chooses the destination, so your server "
                    "fetches `http://169.254.169.254/` (cloud credentials) or an internal admin port for them.",
                    "Validate against an allowlist of exact hosts, resolve the name, and reject private/link-local IPs before connecting.",
                    "CWE-918",
                )
        if target in ("ssl._create_unverified_context",):
            self.flag(
                node, "PY-TLS-VERIFY-OFF", "critical", "Unverified TLS context",
                "This context accepts any certificate, including a self-signed one from an attacker.",
                "Use `ssl.create_default_context()`.", "CWE-295",
            )

        # --- filesystem ---
        if target in ("open", "io.open", "pathlib.Path.open", "codecs.open") or attr == "read_text":
            if first is not None and (_is_dynamic_string(first) or
                                      any(UNTRUSTED_NAME.search(n) for n in _names_in(first))):
                scope = self.enclosing_src()
                if not re.search(r"(is_relative_to|commonpath|safe_join|_safe_path|safe_path)", scope):
                    self.flag(
                        node, "PY-PATH-TRAVERSAL", "high",
                        "File path built from untrusted input",
                        "`../../etc/passwd` and absolute paths both escape the directory you intended. "
                        "On a web server this reads any file the process can read.",
                        "Resolve and confine: `p = (BASE / name).resolve()` then "
                        "`if not p.is_relative_to(BASE.resolve()): raise ValueError`.",
                        "CWE-22",
                    )
        if attr == "is_relative_to":
            self.praise(node, "path confinement check", "Resolved path is verified to stay inside the base directory.")
        if target in ("tempfile.mktemp",):
            self.flag(
                node, "PY-INSECURE-TEMP", "medium",
                "`tempfile.mktemp()` is a race condition",
                "mktemp returns a name, not a file. Between the name and your `open()` an attacker "
                "can create that path as a symlink to something else (TOCTOU).",
                "Use `tempfile.NamedTemporaryFile()` or `tempfile.mkstemp()`, which create the file atomically.",
                "CWE-377",
            )
        if attr == "extractall" or target == "shutil.unpack_archive":
            self.flag(
                node, "PY-ZIP-SLIP", "high",
                "Archive extracted without path checks",
                "Entry names inside a zip/tar can contain `../` or absolute paths, letting the archive "
                "write outside the target directory -- over your code, or into ~/.ssh/authorized_keys.",
                "Inspect every member first and reject names that escape the destination; on 3.12+ use `tar.extractall(filter='data')`.",
                "CWE-22",
            )
        if target == "os.chmod" and len(node.args) > 1:
            m = node.args[1]
            if isinstance(m, ast.Constant) and isinstance(m.value, int) and m.value & 0o022:
                self.flag(
                    node, "PY-WORLD-WRITABLE", "medium",
                    f"World/group-writable permissions ({oct(m.value)})",
                    "Any local account can rewrite this file. If it is code or config, that is privilege escalation.",
                    "Use `0o600` for secrets, `0o644` for public data, `0o700` for private directories.",
                    "CWE-732",
                )

        # --- XML ---
        if target.startswith("xml.") or target in ("ElementTree.parse", "ElementTree.fromstring", "minidom.parse", "minidom.parseString"):
            if attr in ("parse", "fromstring", "parseString"):
                self.flag(
                    node, "PY-XXE", "medium",
                    "Stdlib XML parser on external input",
                    "Python's XML modules are not hardened against entity-expansion ('billion laughs') "
                    "attacks, and older parsers resolve external entities, which reads local files.",
                    "Use `defusedxml` for untrusted XML, or set a hard size limit and disable DTDs.",
                    "CWE-611",
                )

        # --- logging secrets ---
        if target in ("print",) or target.startswith("logging.") or attr in ("info", "debug", "warning", "error", "exception"):
            for a in node.args:
                if any(SECRET_NAME.search(n) for n in _names_in(a)):
                    self.flag(
                        node, "PY-SECRET-IN-LOG", "medium",
                        "Secret written to output/logs",
                        "Logs are replicated to aggregators, retained for years and read by people who "
                        "were never granted access to the credential. This is how tokens leak.",
                        "Log an identifier, not the value: `log.info('auth ok for user=%s', user_id)`, or redact to `***`.",
                        "CWE-532",
                    )

        # --- web ---
        if attr == "run" and isinstance(node.func, ast.Attribute) and _const_bool(_kw(node, "debug")):
            self.flag(
                node, "PY-DEBUG-ON", "critical",
                "Debug mode enabled",
                "The Werkzeug/Flask debugger exposes an interactive Python console on any traceback. "
                "Reachable from the network, it is an unauthenticated remote shell.",
                "Never set debug=True outside your own machine; drive it from an env var that defaults to off.",
                "CWE-489",
            )
        if target in ("flask.render_template_string", "render_template_string", "jinja2.Template"):
            if first is not None and _is_dynamic_string(first):
                self.flag(
                    node, "PY-SSTI", "critical",
                    "Template built from untrusted input",
                    "Server-side template injection: Jinja expressions in the data are evaluated, and "
                    "`{{ ''.__class__.__mro__ }}` walks from a string to arbitrary code.",
                    "Render a fixed template and pass data as context variables: `render_template('p.html', name=name)`.",
                    "CWE-1336",
                )
        if target in ("flask.Markup", "Markup", "markupsafe.Markup"):
            self.flag(
                node, "PY-XSS-MARKUP", "high",
                "`Markup()` marks a string as trusted HTML",
                "Markup switches autoescaping off for that value. If any part of it came from a user, "
                "you just shipped stored XSS.",
                "Escape first (`markupsafe.escape(user)`), or build the HTML from fixed fragments only.",
                "CWE-79",
            )
        if attr in ("escape",) or target in ("html.escape", "markupsafe.escape"):
            self.praise(node, "output escaping", "User data is neutralised before it reaches HTML.")
        if target in ("jwt.decode",):
            v = _kw(node, "verify")
            opts = _kw(node, "options")
            bad = _is_falsy_const(v)
            if isinstance(opts, ast.Dict):
                for k, val in zip(opts.keys, opts.values):
                    if (_str_const(k) or "").startswith("verify") and _is_falsy_const(val):
                        bad = True
            if _kw(node, "algorithms") is None:
                bad = True
            if bad:
                self.flag(
                    node, "PY-JWT-NOVERIFY", "critical",
                    "JWT decoded without verifying the signature",
                    "An unverified token is just attacker-supplied JSON. Flipping `\"role\":\"admin\"` "
                    "costs nothing, and `alg: none` tokens are accepted when algorithms is unset.",
                    "`jwt.decode(tok, key, algorithms=['HS256'])` -- always pin the algorithm list.",
                    "CWE-347",
                )
        if target == "re.compile" or target.startswith("re."):
            pat = _str_const(first)
            if pat and NESTED_QUANTIFIER.search(pat):
                self.flag(
                    node, "PY-REDOS", "medium",
                    "Regex with nested quantifiers",
                    "Patterns like `(a+)+` backtrack exponentially. A 30-character input can pin a CPU "
                    "core for minutes -- denial of service through a single field.",
                    "Flatten the quantifiers, anchor the pattern, and cap input length before matching.",
                    "CWE-1333",
                )

        # --- misc ---
        if target == "os.environ.get" and len(node.args) > 1:
            d = _str_const(node.args[1])
            k = _str_const(first) or ""
            if d and SECRET_NAME.search(k) and not PLACEHOLDER_SECRET.match(d):
                self.flag(
                    node, "PY-SECRET-FALLBACK", "high",
                    "Hardcoded fallback for a secret",
                    "The default silently takes over when the variable is unset -- which is exactly the "
                    "misconfiguration you needed to notice. Everyone running the app shares one credential.",
                    "Fail closed: `os.environ['APP_TOKEN']` raises KeyError, which is the correct behaviour.",
                    "CWE-798",
                )
        if target in ("input", "builtins.input") and self.func_stack:
            pass
        self.generic_visit(node)


def audit_source(source, requirements=None):
    """Return {'findings': [...], 'good': [...], 'syntax': None|{...}, 'unmet': [...]}."""
    try:
        tree = ast.parse(source)
    except SyntaxError as e:
        return {
            "findings": [],
            "good": [],
            "syntax": {"line": e.lineno or 0, "col": e.offset or 0, "msg": e.msg, "text": (e.text or "").rstrip()},
            "unmet": [],
        }
    a = Auditor(source)
    a.visit(tree)
    a.findings.sort(key=lambda f: (SEVERITY_ORDER.get(f["severity"], 9), f["line"]))
    return {
        "findings": a.findings,
        "good": a.good,
        "syntax": None,
        "unmet": check_requirements(source, tree, a, requirements or []),
    }


def check_requirements(source, tree, auditor, reqs):
    """Lesson-specific gates, e.g. 'must use secrets', 'must not use random'."""
    unmet = []
    calls = set()
    for n in ast.walk(tree):
        if isinstance(n, ast.Call):
            t = auditor.resolve(n.func)
            if t:
                calls.add(t)
                calls.add(t.split(".")[-1])
            if isinstance(n.func, ast.Attribute):
                calls.add(n.func.attr)
    defs = {n.name for n in ast.walk(tree) if isinstance(n, (ast.FunctionDef, ast.AsyncFunctionDef, ast.ClassDef))}
    for r in reqs:
        kind, val = r.get("kind"), r.get("value", "")
        msg = r.get("message") or ""
        ok = True
        if kind == "uses_module":
            ok = val in auditor.imported
            msg = msg or f"Your solution must import and use `{val}`."
        elif kind == "calls":
            ok = val in calls or val.split(".")[-1] in calls
            msg = msg or f"Your solution must call `{val}()`."
        elif kind == "defines":
            ok = val in defs
            msg = msg or f"Define `{val}` in your solution."
        elif kind == "forbids_module":
            ok = val not in auditor.imported
            msg = msg or f"`{val}` is not acceptable here -- remove it."
        elif kind == "forbids":
            ok = not re.search(val, source)
            msg = msg or f"Remove `{val}` from your solution."
        elif kind == "regex":
            ok = bool(re.search(val, source, re.M))
            msg = msg or f"Expected to find `{val}` in your code."
        elif kind == "no_finding":
            ok = not any(f["id"] == val for f in auditor.findings)
            msg = msg or f"Resolve the {val} finding."
        if not ok:
            unmet.append({"kind": kind, "value": val, "message": msg})
    return unmet


# --------------------------------------------------------------------------- #
# execution
# --------------------------------------------------------------------------- #
class BudgetExceeded(Exception):
    pass


class _Budget:
    """Cheap line-event counter so a runaway loop cannot freeze the browser tab."""

    def __init__(self, limit):
        self.limit = limit
        self.n = 0

    def trace(self, frame, event, arg):
        if event == "line":
            self.n += 1
            if self.n > self.limit:
                raise BudgetExceeded(
                    f"execution budget exceeded after {self.limit:,} steps -- "
                    "this usually means a loop never ends"
                )
        return self.trace


def _make_input(lines, out):
    it = iter(lines)

    def _input(prompt=""):
        try:
            val = next(it)
        except StopIteration:
            raise EOFError("input() was called more times than this exercise provides input")
        out.write(f"{prompt}{val}\n")
        return val

    return _input


def _fmt_exc(exc, code):
    """Format a traceback with the frames of our own harness removed."""
    tb = exc.__traceback__
    frames = traceback.extract_tb(tb)
    keep = [f for f in frames if f.filename == "<submission>"]
    head = f"{type(exc).__name__}: {exc}"
    if not keep:
        return head
    loc = keep[-1]
    lines = code.splitlines()
    src = lines[loc.lineno - 1].strip() if 0 < loc.lineno <= len(lines) else ""
    return f"{head}\n  line {loc.lineno}: {src}"


TEST_HELPERS_SRC = """
def _approx(a, b, tol=1e-9):
    return abs(a - b) <= tol

class _Raises:
    def __init__(self, exc): self.exc = exc; self.caught = None
    def __enter__(self): return self
    def __exit__(self, t, v, tb):
        self.caught = v
        if t is None:
            raise AssertionError(f"expected {self.exc.__name__} but nothing was raised")
        return issubclass(t, self.exc)
"""


def run_submission(code, stdin_lines, tests, requirements, setup="", budget=400000):
    out = io.StringIO()
    err = io.StringIO()
    audit = audit_source(code, requirements)
    result = {
        "stdout": "",
        "stderr": "",
        "error": None,
        "tests": [],
        "findings": audit["findings"],
        "good": audit["good"],
        "unmet": audit["unmet"],
        "syntax": audit["syntax"],
        "passed": False,
        "steps": 0,
        "breaches": [],
        "transcript": [],
        "blocking": 0,
    }
    if audit["syntax"]:
        s = audit["syntax"]
        result["error"] = f"SyntaxError: {s['msg']} (line {s['line']})"
        return result

    ns = {"__name__": "__main__", "__builtins__": builtins}
    if teachlib is not None:
        teachlib.reset()
        teachlib.install()
        ns["WORLD"] = teachlib.WORLD
        ns["SHELL"] = teachlib.SHELL
    if setup:
        try:
            exec(compile(setup, "<setup>", "exec"), ns)
        except Exception as e:
            result["error"] = f"exercise setup failed: {e}"
            if teachlib is not None:
                teachlib.uninstall()
            return result

    ns["input"] = _make_input(list(stdin_lines or []), out)
    real_input = builtins.input
    builtins.input = ns["input"]
    b = _Budget(budget)
    try:
        obj = compile(code, "<submission>", "exec")
        with contextlib.redirect_stdout(out), contextlib.redirect_stderr(err):
            sys.settrace(b.trace)
            try:
                exec(obj, ns)
            finally:
                sys.settrace(None)
    except BudgetExceeded as e:
        result["error"] = str(e)
    except SystemExit:
        pass
    except BaseException as e:  # noqa: BLE001 - surfaced to the learner verbatim
        result["error"] = _fmt_exc(e, code)
    finally:
        builtins.input = real_input
        sys.settrace(None)
        result["steps"] = b.n
        result["stdout"] = out.getvalue()
        result["stderr"] = err.getvalue()

    if result["error"] is None:
        result["tests"] = _run_tests(tests or [], ns, result["stdout"], code)

    if teachlib is not None:
        result["breaches"] = list(teachlib.WORLD.events)
        result["transcript"] = list(teachlib.WORLD.transcript)
        teachlib.uninstall()

    all_tests_ok = all(t["passed"] for t in result["tests"]) if result["tests"] else result["error"] is None
    blocking = [f for f in result["findings"] if f["severity"] in BLOCKING]
    result["blocking"] = len(blocking)
    result["passed"] = bool(all_tests_ok and not blocking and not result["unmet"] and result["error"] is None)
    return result


def _run_tests(tests, ns, stdout, code):
    rows = []
    for t in tests:
        scope = dict(ns)
        scope["_stdout"] = stdout
        scope["_lines"] = [l for l in stdout.splitlines()]
        exec(TEST_HELPERS_SRC, scope)
        scope["approx"] = scope["_approx"]
        scope["raises"] = scope["_Raises"]
        row = {"name": t.get("name", "test"), "passed": False, "message": "", "hidden": bool(t.get("hidden"))}
        buf = io.StringIO()
        b = _Budget(200000)
        try:
            with contextlib.redirect_stdout(buf):
                sys.settrace(b.trace)
                try:
                    exec(compile(t["code"], "<test>", "exec"), scope)
                finally:
                    sys.settrace(None)
            row["passed"] = True
        except AssertionError as e:
            row["message"] = str(e) or "assertion failed"
        except BudgetExceeded as e:
            row["message"] = str(e)
        except BaseException as e:  # noqa: BLE001
            row["message"] = f"{type(e).__name__}: {e}"
        finally:
            sys.settrace(None)
        rows.append(row)
    return rows


# --------------------------------------------------------------------------- #
# REPL
# --------------------------------------------------------------------------- #
_repl_ns = {"__name__": "__repl__", "__builtins__": builtins}
_repl_compile = codeop.CommandCompiler()
_repl_buffer = []


def repl_feed(line):
    """Feed one physical line to the REPL. Mirrors CPython's interactive loop."""
    global _repl_buffer
    _repl_buffer.append(line)
    source = "\n".join(_repl_buffer)
    out, err, value = io.StringIO(), io.StringIO(), None
    try:
        obj = _repl_compile(source, "<repl>", "single")
    except (SyntaxError, OverflowError, ValueError) as e:
        _repl_buffer = []
        return {"status": "error", "out": "", "err": f"{type(e).__name__}: {e}", "value": None}
    if obj is None:
        return {"status": "more", "out": "", "err": "", "value": None}
    _repl_buffer = []
    b = _Budget(400000)
    if teachlib is not None:
        teachlib.install()
        _repl_ns.setdefault("WORLD", teachlib.WORLD)
        _repl_ns.setdefault("SHELL", teachlib.SHELL)
    try:
        with contextlib.redirect_stdout(out), contextlib.redirect_stderr(err):
            sys.settrace(b.trace)
            try:
                exec(obj, _repl_ns)
            finally:
                sys.settrace(None)
        status = "ok"
    except BudgetExceeded as e:
        err.write(str(e))
        status = "error"
    except SystemExit:
        status = "ok"
    except BaseException as e:  # noqa: BLE001
        err.write(_fmt_exc(e, source).replace("<submission>", "<repl>"))
        status = "error"
    finally:
        sys.settrace(None)
    return {"status": status, "out": out.getvalue(), "err": err.getvalue(), "value": value}


def repl_reset():
    global _repl_ns, _repl_buffer
    _repl_ns = {"__name__": "__repl__", "__builtins__": builtins}
    _repl_buffer = []
    return True


# --------------------------------------------------------------------------- #
# JSON entry points
# --------------------------------------------------------------------------- #
def SPT_run(payload_json):
    p = json.loads(payload_json)
    return json.dumps(
        run_submission(
            p.get("code", ""),
            p.get("stdin", []),
            p.get("tests", []),
            p.get("requirements", []),
            p.get("setup", ""),
            p.get("budget", 400000),
        )
    )


def SPT_audit(payload_json):
    p = json.loads(payload_json)
    return json.dumps(audit_source(p.get("code", ""), p.get("requirements", [])))


def SPT_repl(payload_json):
    p = json.loads(payload_json)
    return json.dumps(repl_feed(p.get("line", "")))


def SPT_reset_repl():
    repl_reset()
    return "{}"
