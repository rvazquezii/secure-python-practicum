"""Unit tests for the trainer sandbox. Run with: python3 py/test_sandbox.py

These assert that every auditor rule fires on vulnerable code and stays quiet on the
fixed version, and that the executor/test-harness behaves. Keep this green: the
auditor is what makes the whole course "secure by default", so a silent rule is a
pedagogical bug.
"""

import json
import os
import sys

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import sandbox  # noqa: E402

PASS = FAIL = 0
FAILURES = []


def check(name, cond, extra=""):
    global PASS, FAIL
    if cond:
        PASS += 1
    else:
        FAIL += 1
        FAILURES.append(f"{name} {extra}")


def ids(code):
    return [f["id"] for f in sandbox.audit_source(code)["findings"]]


def fires(rule, code, label=""):
    got = ids(code)
    check(f"fires {rule} {label}", rule in got, f"-> got {got}")


def quiet(rule, code, label=""):
    got = ids(code)
    check(f"quiet {rule} {label}", rule not in got, f"-> got {got}")


# --------------------------------------------------------------------------- #
# rule coverage: vulnerable form fires, fixed form does not
# --------------------------------------------------------------------------- #
CASES = [
    ("PY-EVAL", "x = input()\nprint(eval(x))", "n = int(input())\nprint(n)"),
    ("PY-SHELL-EXEC", "import os\nos.system('ls ' + input())", "import subprocess\nsubprocess.run(['ls'], check=True)"),
    ("PY-SHELL-TRUE", "import subprocess\nsubprocess.run('ls ' + p, shell=True)",
     "import subprocess\nsubprocess.run(['ls', p], check=True)"),
    ("PY-INSECURE-DESERIALIZE", "import pickle\nd = pickle.loads(blob)", "import json\nd = json.loads(blob)"),
    ("PY-YAML-UNSAFE", "import yaml\nc = yaml.load(text)", "import yaml\nc = yaml.safe_load(text)"),
    ("PY-SQLI", 'cur.execute("SELECT * FROM u WHERE n = \'" + name + "\'")',
     'cur.execute("SELECT * FROM u WHERE n = ?", (name,))'),
    ("PY-SQLI", 'cur.execute(f"SELECT * FROM u WHERE n = {name}")',
     'cur.execute("SELECT * FROM u WHERE n = ?", (name,))'),
    ("PY-WEAK-HASH", "import hashlib\nd = hashlib.md5(data).hexdigest()",
     "import hashlib\nd = hashlib.sha256(data).hexdigest()"),
    ("PY-WEAK-HASH", "import hashlib\nd = hashlib.new('sha1', data)",
     "import hashlib\nd = hashlib.md5(data, usedforsecurity=False)"),
    ("PY-FAST-HASH-PASSWORD", "import hashlib\nh = hashlib.sha256(password.encode()).hexdigest()",
     "import hashlib\nh = hashlib.scrypt(password.encode(), salt=salt, n=16384, r=8, p=1)"),
    ("PY-WEAK-RANDOM", "import random\ntoken = random.choice(alphabet)",
     "import secrets\ntoken = secrets.token_urlsafe(32)"),
    ("PY-TLS-VERIFY-OFF", "import requests\nr = requests.get(u, verify=False, timeout=5)",
     "import requests\nr = requests.get(u, timeout=5)"),
    ("PY-NO-TIMEOUT", "import requests\nr = requests.get('https://a.example')",
     "import requests\nr = requests.get('https://a.example', timeout=(3, 10))"),
    ("PY-HARDCODED-SECRET", 'API_TOKEN = "sk-live-9f2b41ccd8"', "import os\nAPI_TOKEN = os.environ['API_TOKEN']"),
    ("PY-HARDCODED-SECRET", 'CONF = {"api_key": "AKIA7Y3EXAMPLE"}', 'CONF = {"api_key": os.environ["AWS_KEY"]}'),
    ("PY-HARDCODED-SECRET", 'def conn(password="letmein123"):\n    return password',
     "def conn(password=None):\n    return password"),
    ("PY-SECRET-FALLBACK", 'import os\nk = os.environ.get("API_KEY", "dev-key-123")',
     "import os\nk = os.environ['API_KEY']"),
    ("PY-TIMING-COMPARE", "if token == expected:\n    pass",
     "import hmac\nif hmac.compare_digest(token, expected):\n    pass"),
    ("PY-SWALLOWED-ERROR", "try:\n    verify()\nexcept Exception:\n    pass",
     "try:\n    verify()\nexcept ValueError as e:\n    raise"),
    ("PY-BARE-EXCEPT", "try:\n    f()\nexcept:\n    log(1)", "try:\n    f()\nexcept OSError:\n    log(1)"),
    ("PY-ASSERT-AUTH", "def check_admin(u):\n    assert u.is_admin",
     "def check_admin(u):\n    if not u.is_admin:\n        raise PermissionError('nope')"),
    ("PY-PATH-TRAVERSAL", "data = open('/srv/files/' + user_name).read()",
     "p = (BASE / name).resolve()\nif not p.is_relative_to(BASE.resolve()):\n    raise ValueError"),
    ("PY-INSECURE-TEMP", "import tempfile\np = tempfile.mktemp()",
     "import tempfile\nf = tempfile.NamedTemporaryFile()"),
    ("PY-ZIP-SLIP", "import zipfile\nzipfile.ZipFile(p).extractall('/tmp/x')", "import zipfile\nz = zipfile.ZipFile(p)"),
    ("PY-WORLD-WRITABLE", "import os\nos.chmod(p, 0o777)", "import os\nos.chmod(p, 0o600)"),
    ("PY-SECRET-IN-LOG", "print('token is', api_token)", "print('auth ok for', user_id)"),
    ("PY-MUTABLE-DEFAULT", "def add(x, acc=[]):\n    acc.append(x)",
     "def add(x, acc=None):\n    acc = [] if acc is None else acc"),
    ("PY-DEBUG-ON", "app.run(debug=True)", "app.run(debug=False)"),
    ("PY-SSTI", "from flask import render_template_string\nrender_template_string('<p>' + name + '</p>')",
     "from flask import render_template\nrender_template('p.html', name=name)"),
    ("PY-XSS-MARKUP", "from markupsafe import Markup\nh = Markup(comment)",
     "from markupsafe import escape\nh = escape(comment)"),
    ("PY-JWT-NOVERIFY", "import jwt\nclaims = jwt.decode(tok, options={'verify_signature': False})",
     "import jwt\nclaims = jwt.decode(tok, key, algorithms=['HS256'])"),
    ("PY-REDOS", "import re\nre.compile(r'^(a+)+$')", "import re\nre.compile(r'^a+$')"),
    ("PY-SSRF", "import requests\nr = requests.get('http://' + user_host + '/x', timeout=5)",
     "import requests\nr = requests.get(ALLOWED[name], timeout=5)"),
    ("PY-XXE", "from xml.etree import ElementTree\nElementTree.fromstring(body)",
     "import defusedxml.ElementTree as ET\nET.fromstring(body)"),
    ("PY-CMD-BUILD", "import subprocess\nsubprocess.run('grep ' + pat, shell=False)",
     "import subprocess\nsubprocess.run(['grep', pat], check=True)"),
]

for rule, bad, good in CASES:
    fires(rule, bad, f"[{bad.splitlines()[-1][:42]}]")
    quiet(rule, good, f"[{good.splitlines()[-1][:42]}]")

# positive signals
good_signals = sandbox.audit_source(
    "import secrets, hmac, hashlib, json\n"
    "t = secrets.token_urlsafe(32)\n"
    "ok = hmac.compare_digest(a, b)\n"
    "h = hashlib.scrypt(b'pw', salt=b's', n=16384, r=8, p=1)\n"
    "d = json.loads(raw)\n"
)
check("praises secure practice", len(good_signals["good"]) >= 4, f"-> {good_signals['good']}")
check("secure sample is clean", not good_signals["findings"], f"-> {ids('')}")

# severity gating
hi = sandbox.audit_source("import os\nos.system(cmd)")["findings"]
check("shell exec is critical", hi[0]["severity"] == "critical", f"-> {hi[0]['severity']}")
check("finding carries CWE", hi[0]["cwe"] == "CWE-78", f"-> {hi[0]['cwe']}")
check("finding carries fix text", len(hi[0]["fix"]) > 20)

# --------------------------------------------------------------------------- #
# executor
# --------------------------------------------------------------------------- #
r = sandbox.run_submission("print('hi')", [], [], [])
check("stdout captured", r["stdout"] == "hi\n", f"-> {r['stdout']!r}")
check("clean code passes", r["passed"] is True, f"-> {r}")

r = sandbox.run_submission("x = 1/0", [], [], [])
check("runtime error reported", "ZeroDivisionError" in (r["error"] or ""), f"-> {r['error']}")
check("error includes line", "line 1" in (r["error"] or ""), f"-> {r['error']}")

r = sandbox.run_submission("def f(:", [], [], [])
check("syntax error reported", "SyntaxError" in (r["error"] or ""), f"-> {r['error']}")

r = sandbox.run_submission("while True:\n    pass", [], [], [], budget=20000)
check("infinite loop stopped", "budget exceeded" in (r["error"] or ""), f"-> {r['error']}")

r = sandbox.run_submission("name = input('Name: ')\nprint('hello', name)", ["ada"], [], [])
check("stdin fed to input()", r["stdout"] == "Name: ada\nhello ada\n", f"-> {r['stdout']!r}")

r = sandbox.run_submission("x = input()", [], [], [])
check("exhausted stdin is EOFError", "EOFError" in (r["error"] or ""), f"-> {r['error']}")

tests = [
    {"name": "adds", "code": "assert add(2, 3) == 5"},
    {"name": "negatives", "code": "assert add(-1, -1) == -2"},
    {"name": "wrong", "code": "assert add(1, 1) == 3, 'expected 3'"},
]
r = sandbox.run_submission("def add(a, b):\n    return a + b", [], tests, [])
check("tests run against namespace", [t["passed"] for t in r["tests"]] == [True, True, False], f"-> {r['tests']}")
check("assert message surfaced", r["tests"][2]["message"] == "expected 3", f"-> {r['tests'][2]}")
check("failing test blocks pass", r["passed"] is False)

r = sandbox.run_submission("def add(a, b):\n    return a + b", [], tests[:2], [])
check("all tests pass -> passed", r["passed"] is True, f"-> {r}")

# a high finding blocks completion even when tests pass
r = sandbox.run_submission(
    "import os\ndef add(a, b):\n    os.system('echo ' + str(a))\n    return a + b", [], tests[:2], []
)
check("security finding blocks pass", r["passed"] is False and r["blocking"] >= 1, f"-> {r['blocking']}")

# test helpers
r = sandbox.run_submission(
    "def half(x):\n    if x < 0:\n        raise ValueError('neg')\n    return x / 2",
    [],
    [
        {"name": "approx", "code": "assert approx(half(1), 0.5)"},
        {"name": "raises", "code": "with raises(ValueError):\n    half(-1)"},
        {"name": "stdout helper", "code": "assert _stdout == ''"},
    ],
    [],
)
check("helpers available in tests", all(t["passed"] for t in r["tests"]), f"-> {r['tests']}")

# requirements
r = sandbox.run_submission(
    "import random\ntok = random.random()", [], [],
    [{"kind": "uses_module", "value": "secrets"}, {"kind": "forbids_module", "value": "random"}],
)
check("unmet requirements collected", len(r["unmet"]) == 2, f"-> {r['unmet']}")
r = sandbox.run_submission(
    "import secrets\ntok = secrets.token_urlsafe(32)", [], [],
    [{"kind": "uses_module", "value": "secrets"}, {"kind": "calls", "value": "secrets.token_urlsafe"},
     {"kind": "forbids_module", "value": "random"}],
)
check("met requirements empty", r["unmet"] == [], f"-> {r['unmet']}")

# setup code is available to the submission
r = sandbox.run_submission("print(SEEDED)", [], [], [], setup="SEEDED = 'from-setup'")
check("setup namespace shared", r["stdout"].strip() == "from-setup", f"-> {r['stdout']!r}")

# --------------------------------------------------------------------------- #
# REPL
# --------------------------------------------------------------------------- #
sandbox.repl_reset()
check("repl expression", json.loads(sandbox.SPT_repl('{"line": "print(2 ** 10)"}'))["out"].strip() == "1024")
check("repl multiline pending", sandbox.repl_feed("for i in range(2):")["status"] == "more")
check("repl multiline body", sandbox.repl_feed("    print(i)")["status"] == "more")
fin = sandbox.repl_feed("")
check("repl multiline executes", fin["out"] == "0\n1\n", f"-> {fin}")
sandbox.repl_feed("x = 41")
check("repl state persists", sandbox.repl_feed("print(x + 1)")["out"].strip() == "42")
check("repl error captured", "NameError" in sandbox.repl_feed("print(nope)")["err"])
sandbox.repl_reset()
check("repl reset clears state", "NameError" in sandbox.repl_feed("print(x)")["err"])

# JSON entry points round-trip
out = json.loads(sandbox.SPT_run(json.dumps({"code": "print('x')", "tests": [], "stdin": []})))
check("SPT_run returns json", out["stdout"] == "x\n", f"-> {out}")
out = json.loads(sandbox.SPT_audit(json.dumps({"code": "import os\nos.system(c)"})))
check("SPT_audit returns json", out["findings"][0]["id"] == "PY-SHELL-EXEC", f"-> {out}")

# --------------------------------------------------------------------------- #
# simulated world: the exploit must be observable, and the real OS untouched
# --------------------------------------------------------------------------- #
r = sandbox.run_submission(
    "import os\nname = input()\nos.system('echo hello ' + name)", ["ada; cat /etc/shadow"], [], []
)
check("sim shell runs, real shell does not", "hello ada" in r["stdout"], f"-> {r['stdout']!r}")
check("injected command visible", "root:$6$" in r["stdout"], f"-> {r['stdout']!r}")
kinds = [b["kind"] for b in r["breaches"]]
check("metachar breach recorded", "shell-metachar" in kinds, f"-> {kinds}")
check("credential disclosure recorded", "credential-disclosure" in kinds, f"-> {kinds}")
check("shell transcript captured", any("echo hello" in t for t in r["transcript"]), f"-> {r['transcript']}")

r = sandbox.run_submission(
    "import subprocess\nname = input()\nsubprocess.run(['echo', 'hello', name], check=True)",
    ["ada; cat /etc/shadow"], [{"name": "no breach", "code": "assert not WORLD.breached, WORLD.report()"}], [],
)
check("argv form is injection-proof", r["tests"][0]["passed"] is True, f"-> {r['tests']}")
check("metachars stay literal", "ada; cat /etc/shadow" in r["stdout"], f"-> {r['stdout']!r}")
check("safe submission passes", r["passed"] is True, f"-> {r}")

r = sandbox.run_submission(
    "import subprocess\nsubprocess.run('rm -rf / ' , shell=True)", [], [], []
)
check("destructive command simulated", "destructive-command" in [b["kind"] for b in r["breaches"]],
      f"-> {r['breaches']}")
check("real filesystem untouched", os.path.exists("/usr"), "-> /usr vanished, which would be bad")

r = sandbox.run_submission(
    "import requests\nr = requests.get('https://mitm.example.com/account', verify=False, timeout=5)\n"
    "print(r.json()['note'])", [], [], []
)
check("verify=False accepts forged cert", "man-in-the-middle" in r["stdout"], f"-> {r['stdout']!r}")
check("tls breach recorded", "tls-mitm" in [b["kind"] for b in r["breaches"]], f"-> {r['breaches']}")

r = sandbox.run_submission(
    "import requests\ntry:\n    requests.get('https://mitm.example.com/x', timeout=5)\n"
    "except requests.SSLError as e:\n    print('blocked:', e)", [], [], []
)
check("default verify blocks forged cert", "blocked: certificate verify failed" in r["stdout"], f"-> {r['stdout']!r}")

r = sandbox.run_submission(
    "import requests\nhost = input()\nr = requests.get('http://' + host + "
    "'/latest/meta-data/iam/security-credentials/app', timeout=3)\nprint(r.json()['SecretAccessKey'])",
    ["169.254.169.254"], [], [],
)
check("ssrf to metadata simulated", "s3cr3t" in r["stdout"], f"-> {r['stdout']!r} err={r['error']}")
check("ssrf breach recorded", "ssrf" in [b["kind"] for b in r["breaches"]], f"-> {r['breaches']}")

r = sandbox.run_submission(
    "import requests\ntry:\n    requests.get('https://slowloris.example.com/')\nexcept Exception as e:\n"
    "    print('hung:', e)", [], [], []
)
check("missing timeout hangs (simulated)", "hung:" in r["stdout"], f"-> {r['stdout']!r}")

YAML_RCE = "version: 1\nhook: !!python/object/apply:os.system ['id']\n"
r = sandbox.run_submission(f"import yaml\ncfg = yaml.load({YAML_RCE!r})\nprint(cfg)", [], [], [])
check("yaml.load executes payload", "uid=1000" in r["stdout"], f"-> {r['stdout']!r}")
check("deserialization breach recorded",
      "insecure-deserialization" in [b["kind"] for b in r["breaches"]], f"-> {r['breaches']}")

r = sandbox.run_submission(
    f"import yaml\ntry:\n    cfg = yaml.safe_load({YAML_RCE!r})\nexcept yaml.YAMLError as e:\n"
    "    print('refused')", [], [], []
)
check("safe_load refuses python tags", "refused" in r["stdout"], f"-> {r['stdout']!r}")
check("no breach with safe_load", not r["breaches"], f"-> {r['breaches']}")

r = sandbox.run_submission(
    "import yaml\ncfg = yaml.safe_load('name: app\\nport: 8080\\ndebug: false\\n"
    "hosts:\\n  - a.example\\n  - b.example\\n')\nprint(cfg['port'], cfg['debug'], cfg['hosts'][1])",
    [], [], [],
)
check("safe_load parses plain yaml", r["stdout"].strip() == "8080 False b.example", f"-> {r['stdout']!r} err={r['error']}")

r = sandbox.run_submission(
    "import jwt\ntok = jwt.encode({'sub': 'ada', 'role': 'user'}, 'k3y', algorithm='HS256')\n"
    "print(jwt.decode(tok, 'k3y', algorithms=['HS256'])['role'])\n"
    "forged = jwt.encode({'sub': 'ada', 'role': 'admin'}, 'wrong', algorithm='HS256')\n"
    "try:\n    jwt.decode(forged, 'k3y', algorithms=['HS256'])\nexcept jwt.InvalidSignatureError:\n"
    "    print('forgery rejected')", [], [], [],
)
check("jwt roundtrip + forgery rejected",
      "user" in r["stdout"] and "forgery rejected" in r["stdout"], f"-> {r['stdout']!r}")

r = sandbox.run_submission(
    "import jwt\nforged = jwt.encode({'role': 'admin'}, 'anything', algorithm='HS256')\n"
    "claims = jwt.decode(forged, options={'verify_signature': False})\nprint(claims['role'])", [], [], [],
)
check("unverified decode = auth bypass", "auth-bypass" in [b["kind"] for b in r["breaches"]], f"-> {r['breaches']}")

r = sandbox.run_submission(
    "from miniweb import render, escape\n"
    "print(render('<p>{c}</p>', c=\"<script>steal()</script>\"))\n"
    "print(render('<p>{c}</p>', autoescape=False, c=\"<script>steal()</script>\"))", [], [], [],
)
check("autoescape neutralises xss", "&lt;script&gt;" in r["stdout"], f"-> {r['stdout']!r}")
check("xss breach recorded when unescaped", "xss" in [b["kind"] for b in r["breaches"]], f"-> {r['breaches']}")

r = sandbox.run_submission(
    "import sqlite3\ncon = sqlite3.connect(':memory:')\ncon.execute('create table u(name text, role text)')\n"
    "con.execute(\"insert into u values ('ada','user')\")\n"
    "name = input()\n"
    "rows = con.execute(\"select * from u where name = '\" + name + \"'\").fetchall()\n"
    "print(len(rows))", ["x' or '1'='1"], [], [],
)
check("real sqlite3 injection works", r["stdout"].splitlines()[-1] == "1", f"-> {r['stdout']!r} err={r['error']}")

r = sandbox.run_submission(
    "import sqlite3\ncon = sqlite3.connect(':memory:')\ncon.execute('create table u(name text)')\n"
    "con.execute(\"insert into u values ('ada')\")\nname = input()\n"
    "rows = con.execute('select * from u where name = ?', (name,)).fetchall()\nprint(len(rows))",
    ["x' or '1'='1"], [], [],
)
check("parameterized query defeats it", r["stdout"].splitlines()[-1] == "0", f"-> {r['stdout']!r}")

# shims must not leak into the host process after a run
import subprocess as _real_sp  # noqa: E402

check("real subprocess restored", hasattr(_real_sp, "Popen") and _real_sp.__name__ == "subprocess"
      and "simulated" not in (_real_sp.__doc__ or ""), f"-> {_real_sp.__doc__}")
check("real os.system restored", os.system("true") == 0)

print(f"\n{PASS} passed, {FAIL} failed")
for f in FAILURES:
    print("  FAIL:", f)
sys.exit(1 if FAIL else 0)
