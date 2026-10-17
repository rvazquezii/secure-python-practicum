"""Simulated hostile world for the Secure Python Trainer.

Exercises need to *demonstrate* command injection, SSRF, unsafe deserialization and
TLS downgrade. Running the real thing is unacceptable, and stubbing it out with a
`pass` teaches nothing. So this module provides a small simulated universe:

  * SimShell   -- a fake /bin/sh that honours ; && || | $() and records breaches
  * subprocess -- shim routed through SimShell (shell=True vs argv list differ!)
  * requests   -- shim with a route table, real TLS/timeout/SSRF semantics
  * yaml       -- shim where `load` honours !!python/object/apply and `safe_load` does not
  * jwt        -- shim with genuine HS256 signing, plus the `alg: none` flaw
  * miniweb    -- request/response/template objects for the web-security module

Every shim records what an attacker achieved in `WORLD.events`, so an exercise test
can assert "no breach occurred for this malicious input" instead of only checking
the happy path. That is the whole mechanic of the course.

Stdlib only; identical behaviour under Pyodide and CPython.
"""

import base64
import hashlib
import hmac
import io
import json
import re
import shlex
import sys
import types

# --------------------------------------------------------------------------- #
# breach ledger
# --------------------------------------------------------------------------- #
class World:
    def __init__(self):
        self.events = []
        self.transcript = []

    def record(self, kind, detail, source=""):
        self.events.append({"kind": kind, "detail": detail, "source": source})

    def reset(self):
        self.events.clear()
        self.transcript.clear()

    @property
    def breached(self):
        return bool(self.events)

    def kinds(self):
        return [e["kind"] for e in self.events]

    def report(self):
        if not self.events:
            return "no breach recorded"
        return "\n".join(f"[{e['kind']}] {e['detail']}" for e in self.events)


WORLD = World()


# --------------------------------------------------------------------------- #
# simulated shell
# --------------------------------------------------------------------------- #
FS = {
    "/etc/passwd": "root:x:0:0:root:/root:/bin/bash\nstudent:x:1000:1000::/home/student:/bin/bash\n",
    "/etc/shadow": "root:$6$rounds=656000$REDACTED:19000:0:99999:7:::\n",
    "/home/student/notes.txt": "remember to rotate the deploy key\n",
    "/home/student/.aws/credentials": "[default]\naws_access_key_id = AKIA" "IOSFODNN7EXAMPLE\naws_secret_access_key = wJalrXUtnFEMI" "/K7MDENG/bPxRfiCYEXAMPLEKEY\n",
    "/srv/reports/q3.csv": "region,revenue\nemea,184220\napac,99140\n",
    "/srv/reports/q4.csv": "region,revenue\nemea,201885\napac,112700\n",
    "/var/log/app.log": "2026-01-04 INFO login user=ada\n2026-01-04 WARN bad password user=root\n",
}
DIRS = {
    "/": ["etc", "home", "srv", "var"],
    "/etc": ["passwd", "shadow"],
    "/home": ["student"],
    "/home/student": [".aws", "notes.txt"],
    "/srv": ["reports"],
    "/srv/reports": ["q3.csv", "q4.csv"],
    "/var": ["log"],
    "/var/log": ["app.log"],
}

SHELL_META = re.compile(r"[;&|`$><\n]")


class SimShell:
    """A deliberately naive /bin/sh. It is here to be exploited."""

    cwd = "/home/student"

    def __init__(self, world=WORLD):
        self.world = world
        self.out = io.StringIO()

    # -- entry points -------------------------------------------------------
    def run_string(self, command):
        """shell=True path: metacharacters are OPERATORS. This is the hole."""
        self.world.transcript.append(f"$ {command}")
        if SHELL_META.search(command):
            self.world.record(
                "shell-metachar",
                f"the shell parsed operators in {command!r}; everything after the first "
                "operator is a second command the caller never intended",
                command,
            )
        rc = 0
        for part in self._split(command):
            rc = self._exec(part)
        return rc

    def run_argv(self, argv):
        """shell=False path: metacharacters are DATA. Nothing to exploit."""
        argv = [str(a) for a in argv]
        self.world.transcript.append("$ " + " ".join(shlex.quote(a) for a in argv))
        return self._dispatch(argv)

    # -- shell parsing ------------------------------------------------------
    @staticmethod
    def _split(command):
        parts, buf, i = [], "", 0
        while i < len(command):
            c = command[i]
            if c in ";\n":
                parts.append(buf)
                buf = ""
            elif command[i:i + 2] in ("&&", "||"):
                parts.append(buf)
                buf = ""
                i += 1
            elif c == "|":
                parts.append(buf)
                buf = "|PIPE|"
            else:
                buf += c
            i += 1
        parts.append(buf)
        return [p.strip() for p in parts if p.strip()]

    def _exec(self, part):
        piped = part.startswith("|PIPE|")
        if piped:
            part = part[6:].strip()
        if "$(" in part or "`" in part:
            self.world.record("command-substitution",
                              f"the shell executed a nested command inside {part!r}", part)
        try:
            argv = shlex.split(part)
        except ValueError:
            argv = part.split()
        if not argv:
            return 0
        if piped and argv[0] in ("sh", "bash", "python", "python3", "perl"):
            self.world.record("remote-code-execution",
                              f"downloaded content was piped into {argv[0]} -- the attacker's "
                              "script ran with this process's privileges", part)
        return self._dispatch(argv)

    # -- commands -----------------------------------------------------------
    def _dispatch(self, argv):
        cmd, args = argv[0], argv[1:]
        fn = getattr(self, "_cmd_" + cmd.replace("-", "_"), None)
        if fn is None:
            self.out.write(f"sh: {cmd}: command not found\n")
            return 127
        return fn(args) or 0

    def _abs(self, path):
        if path.startswith("/"):
            return re.sub(r"/+", "/", path)
        joined = self.cwd.rstrip("/") + "/" + path
        out = []
        for seg in joined.split("/"):
            if seg in ("", "."):
                continue
            if seg == "..":
                if out:
                    out.pop()
            else:
                out.append(seg)
        return "/" + "/".join(out)

    def _cmd_echo(self, args):
        self.out.write(" ".join(args) + "\n")

    def _cmd_whoami(self, args):
        self.out.write("student\n")

    def _cmd_id(self, args):
        self.out.write("uid=1000(student) gid=1000(student) groups=1000(student)\n")

    def _cmd_uname(self, args):
        self.out.write("Linux trainer 6.1.0 x86_64 GNU/Linux\n")

    def _cmd_pwd(self, args):
        self.out.write(self.cwd + "\n")

    def _cmd_ls(self, args):
        targets = [a for a in args if not a.startswith("-")] or [self.cwd]
        for t in targets:
            p = self._abs(t)
            if p in DIRS:
                self.out.write("  ".join(DIRS[p]) + "\n")
            elif p in FS:
                self.out.write(p.rsplit("/", 1)[-1] + "\n")
            else:
                self.out.write(f"ls: cannot access '{t}': No such file or directory\n")
                return 2

    def _cmd_cat(self, args):
        for t in [a for a in args if not a.startswith("-")]:
            p = self._abs(t)
            if p in ("/etc/shadow",) or ".aws/credentials" in p or "id_rsa" in p:
                self.world.record("credential-disclosure",
                                  f"{p} was read -- password hashes / cloud keys are now in the output", p)
            if p in FS:
                self.out.write(FS[p])
            else:
                self.out.write(f"cat: {t}: No such file or directory\n")
                return 1

    def _cmd_rm(self, args):
        flags = [a for a in args if a.startswith("-")]
        paths = [a for a in args if not a.startswith("-")]
        recursive = any("r" in f for f in flags)
        for t in paths:
            p = self._abs(t)
            if recursive and p in ("/", "/home", "/srv", "/var", "/etc"):
                self.world.record("destructive-command",
                                  f"rm -rf {p} would delete the entire {p} tree", " ".join(args))
            elif recursive:
                self.world.record("destructive-command", f"rm -r removed {p}", " ".join(args))
            else:
                FS.pop(p, None)

    def _cmd_chmod(self, args):
        if args and args[0] in ("777", "0777", "a+w"):
            self.world.record("permission-weakening",
                              f"chmod {args[0]} made {' '.join(args[1:])} world-writable", " ".join(args))

    def _cmd_env(self, args):
        self.world.record("credential-disclosure",
                          "the process environment was dumped, including DEPLOY_TOKEN", "env")
        self.out.write("USER=student\nHOME=/home/student\nDEPLOY_TOKEN=glpat-7x2Qd91ZvKmA\n")

    _cmd_printenv = _cmd_env

    def _cmd_curl(self, args):
        url = next((a for a in args if a.startswith("http")), "")
        self.world.record("egress", f"curl reached out to {url or 'an attacker-chosen host'}", " ".join(args))
        self.out.write("#!/bin/sh\n# attacker payload\n")

    _cmd_wget = _cmd_curl

    def _cmd_nc(self, args):
        self.world.record("reverse-shell",
                          f"nc opened an interactive channel to {' '.join(args)}", " ".join(args))

    def _cmd_sh(self, args):
        self.world.record("remote-code-execution", "a new shell was spawned", " ".join(["sh"] + args))

    _cmd_bash = _cmd_sh

    def _cmd_python(self, args):
        self.world.record("remote-code-execution", "python was invoked with attacker arguments", " ".join(args))

    _cmd_python3 = _cmd_python

    def _cmd_grep(self, args):
        # "--" ends option parsing, exactly as real grep does -- everything after
        # it is data, which is what makes argument injection non-exploitable.
        if "--" in args:
            args = args[args.index("--") + 1:]
        else:
            args = [a for a in args if not a.startswith("-")]
        pat = args[0] if args else ""
        files = [self._abs(a) for a in args[1:]]
        hits = 0
        for p in files:
            for line in FS.get(p, "").splitlines():
                if pat.strip("'\"") in line:
                    self.out.write(f"{p}:{line}\n")
                    hits += 1
        return 0 if hits else 1

    def _cmd_wc(self, args):
        paths = [self._abs(a) for a in args if not a.startswith("-")]
        for p in paths:
            self.out.write(f"{len(FS.get(p, '').splitlines())} {p}\n")

    def _cmd_sleep(self, args):
        self.out.write("")

    def _cmd_true(self, args):
        return 0

    def _cmd_false(self, args):
        return 1

    def drain(self):
        v = self.out.getvalue()
        self.out = io.StringIO()
        return v


SHELL = SimShell()


# --------------------------------------------------------------------------- #
# subprocess / os.system shims
# --------------------------------------------------------------------------- #
class CompletedProcess:
    def __init__(self, args, returncode, stdout="", stderr=""):
        self.args, self.returncode, self.stdout, self.stderr = args, returncode, stdout, stderr

    def __repr__(self):
        return f"CompletedProcess(args={self.args!r}, returncode={self.returncode}, stdout={self.stdout!r})"

    def check_returncode(self):
        if self.returncode:
            raise CalledProcessError(self.returncode, self.args, self.stdout, self.stderr)


class CalledProcessError(Exception):
    def __init__(self, returncode, cmd, output="", stderr=""):
        super().__init__(f"Command {cmd!r} returned non-zero exit status {returncode}.")
        self.returncode, self.cmd, self.output, self.stderr = returncode, cmd, output, stderr


class SubprocessError(Exception):
    pass


def _sp_run(args, shell=False, capture_output=False, check=False, text=True,
            timeout=None, input=None, stdout=None, stderr=None, cwd=None, env=None, **kw):
    if shell:
        if not isinstance(args, str):
            args = " ".join(str(a) for a in args)
        rc = SHELL.run_string(args)
    else:
        if isinstance(args, str):
            rc = SHELL.run_argv(shlex.split(args))
        else:
            rc = SHELL.run_argv(args)
    out = SHELL.drain()
    cp = CompletedProcess(args, rc, out if capture_output or stdout is not None else "", "")
    if not (capture_output or stdout is not None):
        sys.stdout.write(out)
    if check and rc:
        raise CalledProcessError(rc, args, out, "")
    return cp


def _sp_check_output(args, shell=False, text=True, **kw):
    cp = _sp_run(args, shell=shell, capture_output=True, check=True, text=text)
    return cp.stdout


def _sp_call(args, shell=False, **kw):
    return _sp_run(args, shell=shell, capture_output=True).returncode


class Popen:
    def __init__(self, args, shell=False, stdout=None, stderr=None, text=True, **kw):
        self._cp = _sp_run(args, shell=shell, capture_output=True)
        self.args = args
        self.returncode = self._cp.returncode
        self.stdout = io.StringIO(self._cp.stdout)

    def communicate(self, input=None, timeout=None):
        return self._cp.stdout, ""

    def wait(self, timeout=None):
        return self.returncode


def _make_subprocess():
    m = types.ModuleType("subprocess")
    m.run = _sp_run
    m.check_output = _sp_check_output
    m.check_call = _sp_call
    m.call = _sp_call
    m.getoutput = lambda cmd: (SHELL.run_string(cmd), SHELL.drain())[1]
    m.Popen = Popen
    m.PIPE, m.STDOUT, m.DEVNULL = -1, -2, -3
    m.CompletedProcess = CompletedProcess
    m.CalledProcessError = CalledProcessError
    m.SubprocessError = SubprocessError
    m.TimeoutExpired = SubprocessError
    m.list2cmdline = lambda a: " ".join(a)
    m.__doc__ = "simulated subprocess (Secure Python Trainer)"
    return m


# --------------------------------------------------------------------------- #
# requests shim
# --------------------------------------------------------------------------- #
ROUTES = {
    "status.example.com": {"/": {"status": "ok", "region": "emea"}},
    "api.example.com": {
        "/v1/users": [{"id": 1, "name": "ada"}, {"id": 2, "name": "lin"}],
        "/v1/health": {"ok": True},
    },
    "169.254.169.254": {
        "/latest/meta-data/iam/security-credentials/app":
            {"AccessKeyId": "ASIAEXAMPLE", "SecretAccessKey": "s3cr3t", "Token": "FwoGZXIvYXdzE..."}
    },
    "localhost:9200": {"/_cluster/health": {"status": "green", "cluster_name": "internal-logs"}},
    "admin.internal": {"/users": [{"id": 1, "role": "admin"}]},
}
BAD_CERT_HOSTS = {"mitm.example.com", "selfsigned.example.com"}
SLOW_HOSTS = {"slowloris.example.com"}
PRIVATE = re.compile(r"^(127\.|10\.|192\.168\.|172\.(1[6-9]|2\d|3[01])\.|169\.254\.|localhost|\[::1\]|.*\.internal$)")


class RequestException(Exception):
    pass


class SSLError(RequestException):
    pass


class Timeout(RequestException):
    pass


class ConnectionError(RequestException, OSError):  # noqa: A001 - mirrors requests' API
    pass


class HTTPError(RequestException):
    pass


class HttpResponse:
    def __init__(self, url, status_code=200, payload=None, text=None):
        self.url, self.status_code = url, status_code
        self._payload = payload
        self.text = text if text is not None else json.dumps(payload)
        self.content = self.text.encode()
        self.headers = {"Content-Type": "application/json"}
        self.ok = status_code < 400

    def json(self):
        if self._payload is None:
            raise ValueError("response is not JSON")
        return self._payload

    def raise_for_status(self):
        if not self.ok:
            raise HTTPError(f"{self.status_code} for {self.url}")

    def __repr__(self):
        return f"<Response [{self.status_code}]>"


def _http(method, url, verify=True, timeout=None, params=None, data=None,
          json=None, headers=None, allow_redirects=True, **kw):
    m = re.match(r"^(https?)://([^/]+)(/.*)?$", str(url))
    if not m:
        raise RequestException(f"invalid URL {url!r}")
    scheme, host, path = m.group(1), m.group(2), m.group(3) or "/"
    if PRIVATE.match(host):
        WORLD.record(
            "ssrf",
            f"the server was made to request {url} -- an internal address reachable only from "
            "inside the perimeter" + (" (cloud metadata: credential theft)" if "169.254" in host else ""),
            str(url),
        )
    if host in BAD_CERT_HOSTS:
        if verify:
            raise SSLError(
                f"certificate verify failed: self signed certificate for {host} "
                "(this is TLS doing its job)"
            )
        WORLD.record("tls-mitm",
                     f"verify=False accepted a forged certificate for {host}; the response body "
                     "came from the attacker on the path", str(url))
        return HttpResponse(url, 200, {"balance": 0, "note": "injected by man-in-the-middle"})
    if host in SLOW_HOSTS:
        if timeout is None:
            WORLD.record("resource-exhaustion",
                         f"{host} never answers and no timeout was set -- this worker is now "
                         "blocked forever", str(url))
            raise RequestException("hung forever: no timeout was supplied (simulated)")
        raise Timeout(f"read timeout after {timeout}s connecting to {host}")
    table = ROUTES.get(host)
    if table is None:
        raise ConnectionError(f"failed to resolve {host!r}")
    if path not in table:
        return HttpResponse(url, 404, {"error": "not found"})
    return HttpResponse(url, 200, table[path])


def _make_requests():
    m = types.ModuleType("requests")
    for verb in ("get", "post", "put", "delete", "head", "patch", "options"):
        m.__dict__[verb] = (lambda v: (lambda url, **kw: _http(v, url, **kw)))(verb)
    m.request = _http
    m.Response = HttpResponse
    m.exceptions = types.SimpleNamespace(
        RequestException=RequestException, SSLError=SSLError, Timeout=Timeout,
        ConnectionError=ConnectionError, HTTPError=HTTPError,
    )
    for name, exc in (("RequestException", RequestException), ("SSLError", SSLError),
                      ("Timeout", Timeout), ("ConnectionError", ConnectionError), ("HTTPError", HTTPError)):
        setattr(m, name, exc)
    m.__doc__ = "simulated requests (Secure Python Trainer)"
    return m


# --------------------------------------------------------------------------- #
# yaml shim -- tiny parser, plus the python-object tag that makes load() lethal
# --------------------------------------------------------------------------- #
def _scalar(tok):
    t = tok.strip()
    if t in ("true", "True", "yes"):
        return True
    if t in ("false", "False", "no"):
        return False
    if t in ("null", "~", ""):
        return None
    if re.fullmatch(r"-?\d+", t):
        return int(t)
    if re.fullmatch(r"-?\d+\.\d*", t):
        return float(t)
    return t.strip("'\"")


def _parse_block(lines, i, indent):
    """Return (value, next_index) for a mapping or sequence at the given indent."""
    if i >= len(lines):
        return None, i
    stripped = lines[i][1]
    if stripped.startswith("- "):
        out = []
        while i < len(lines) and lines[i][0] == indent and lines[i][1].startswith("- "):
            item = lines[i][1][2:].strip()
            i += 1
            if item == "" and i < len(lines) and lines[i][0] > indent:
                val, i = _parse_block(lines, i, lines[i][0])
                out.append(val)
            elif ":" in item and not item.startswith("{"):
                k, _, v = item.partition(":")
                sub = {k.strip(): _scalar(v)}
                while i < len(lines) and lines[i][0] > indent:
                    k2, _, v2 = lines[i][1].partition(":")
                    sub[k2.strip()] = _scalar(v2)
                    i += 1
                out.append(sub)
            else:
                out.append(_scalar(item))
        return out, i
    out = {}
    while i < len(lines) and lines[i][0] == indent:
        key, _, rest = lines[i][1].partition(":")
        key, rest = key.strip(), rest.strip()
        i += 1
        if rest:
            out[key] = _scalar(rest)
        elif i < len(lines) and lines[i][0] > indent:
            out[key], i = _parse_block(lines, i, lines[i][0])
        else:
            out[key] = None
    return out, i


def _yaml_lines(text):
    rows = []
    for raw in text.splitlines():
        if not raw.strip() or raw.lstrip().startswith("#"):
            continue
        rows.append((len(raw) - len(raw.lstrip()), raw.strip()))
    return rows


PY_TAG = re.compile(r"!!python/(object/apply|object|name|module):([\w.]+)")


def _yaml_safe_load(text):
    if PY_TAG.search(text or ""):
        raise YAMLError(
            "could not determine a constructor for the tag "
            "'tag:yaml.org,2002:python/object/apply' -- SafeLoader refuses to build Python objects"
        )
    rows = _yaml_lines(text or "")
    if not rows:
        return None
    val, _ = _parse_block(rows, 0, rows[0][0])
    return val


def _yaml_load(text, Loader=None):
    name = getattr(Loader, "__name__", "") or ""
    if "Safe" in name:
        return _yaml_safe_load(text)
    m = PY_TAG.search(text or "")
    if m:
        target = m.group(2)
        arg = re.search(r"\[(.*?)\]|\n\s*-\s*(.+)", text)
        payload = (arg.group(1) or arg.group(2) or "").strip().strip("'\"") if arg else ""
        WORLD.record(
            "insecure-deserialization",
            f"yaml.load() constructed {target}({payload!r}) from the document -- the config file "
            "executed code",
            text.strip()[:80],
        )
        if "system" in target or "popen" in target or "subprocess" in target:
            SHELL.run_string(payload)
            sys.stdout.write(SHELL.drain())
        return {"pwned": True}
    return _yaml_safe_load(text)


class YAMLError(Exception):
    pass


def _make_yaml():
    m = types.ModuleType("yaml")
    m.safe_load = _yaml_safe_load
    m.load = _yaml_load
    m.full_load = _yaml_load
    m.safe_load_all = lambda t: [_yaml_safe_load(d) for d in (t or "").split("---") if d.strip()]
    m.YAMLError = YAMLError
    m.SafeLoader = type("SafeLoader", (), {})
    m.FullLoader = type("FullLoader", (), {})
    m.Loader = type("Loader", (), {})
    m.dump = lambda obj, **kw: json.dumps(obj)
    m.__doc__ = "simulated PyYAML (Secure Python Trainer)"
    return m


# --------------------------------------------------------------------------- #
# jwt shim -- real HS256, plus the classic verification holes
# --------------------------------------------------------------------------- #
def _b64e(b):
    return base64.urlsafe_b64encode(b).rstrip(b"=").decode()


def _b64d(s):
    return base64.urlsafe_b64decode(s + "=" * (-len(s) % 4))


class InvalidTokenError(Exception):
    pass


class InvalidSignatureError(InvalidTokenError):
    pass


class ExpiredSignatureError(InvalidTokenError):
    pass


def _jwt_encode(payload, key=None, algorithm="HS256", headers=None):
    head = {"typ": "JWT", "alg": algorithm}
    head.update(headers or {})
    h = _b64e(json.dumps(head, separators=(",", ":")).encode())
    p = _b64e(json.dumps(payload, separators=(",", ":")).encode())
    if algorithm in ("none", "None", None):
        return f"{h}.{p}."
    sig = hmac.new(str(key).encode(), f"{h}.{p}".encode(), hashlib.sha256).digest()
    return f"{h}.{p}.{_b64e(sig)}"


def _jwt_decode(token, key=None, algorithms=None, options=None, **kw):
    try:
        h, p, s = token.split(".")
    except ValueError:
        raise InvalidTokenError("not enough segments")
    header = json.loads(_b64d(h))
    claims = json.loads(_b64d(p))
    opts = options or {}
    verify = opts.get("verify_signature", kw.get("verify", True))
    if not verify or algorithms is None:
        WORLD.record(
            "auth-bypass",
            f"a token was accepted without verifying its signature; claims {claims} came "
            "straight from the client",
            token[:28] + "...",
        )
        return claims
    alg = header.get("alg", "none")
    if alg not in algorithms:
        raise InvalidTokenError(f"the specified alg value is not allowed: {alg}")
    if alg in ("none", "None"):
        WORLD.record("auth-bypass", "alg=none was in the allowed list, so any token validates", token[:28])
        return claims
    expect = _b64e(hmac.new(str(key).encode(), f"{h}.{p}".encode(), hashlib.sha256).digest())
    if not hmac.compare_digest(expect, s):
        raise InvalidSignatureError("Signature verification failed")
    return claims


def _make_jwt():
    m = types.ModuleType("jwt")
    m.encode = _jwt_encode
    m.decode = _jwt_decode
    m.get_unverified_header = lambda t: json.loads(_b64d(t.split(".")[0]))
    m.InvalidTokenError = InvalidTokenError
    m.InvalidSignatureError = InvalidSignatureError
    m.ExpiredSignatureError = ExpiredSignatureError
    m.exceptions = types.SimpleNamespace(
        InvalidTokenError=InvalidTokenError, InvalidSignatureError=InvalidSignatureError,
        ExpiredSignatureError=ExpiredSignatureError, PyJWTError=InvalidTokenError,
    )
    m.__doc__ = "simulated PyJWT (Secure Python Trainer)"
    return m


# --------------------------------------------------------------------------- #
# miniweb -- enough of a web framework to teach XSS, authz and session handling
# --------------------------------------------------------------------------- #
ESCAPES = {"&": "&amp;", "<": "&lt;", ">": "&gt;", '"': "&quot;", "'": "&#x27;"}


def escape(value):
    return "".join(ESCAPES.get(c, c) for c in str(value))


class Request:
    def __init__(self, path="/", method="GET", query=None, form=None, json_body=None,
                 headers=None, cookies=None, remote_addr="203.0.113.9", user=None):
        self.path, self.method = path, method.upper()
        self.query = dict(query or {})
        self.form = dict(form or {})
        self.json = json_body
        self.headers = dict(headers or {})
        self.cookies = dict(cookies or {})
        self.remote_addr = remote_addr
        self.user = user

    def get(self, name, default=None):
        return self.form.get(name, self.query.get(name, default))

    def __repr__(self):
        return f"<Request {self.method} {self.path} query={self.query} form={self.form}>"


class WebResponse:
    def __init__(self, body="", status=200, headers=None):
        self.body, self.status = body, status
        self.headers = {"Content-Type": "text/html; charset=utf-8"}
        self.headers.update(headers or {})

    def __repr__(self):
        return f"<Response {self.status} {self.body[:48]!r}>"


def render(template, autoescape=True, **context):
    """Substitute {name} placeholders, escaping by default."""
    def sub(m):
        val = context.get(m.group(1), "")
        return escape(val) if autoescape else str(val)

    html = re.sub(r"\{(\w+)\}", sub, template)
    if not autoescape and re.search(r"<script|onerror=|javascript:", html, re.I):
        WORLD.record("xss",
                     "unescaped user input reached the HTML response; the browser will execute it",
                     html[:80])
    return html


def is_safe_html(html):
    return not re.search(r"<\s*script|on\w+\s*=|javascript:", html or "", re.I)


def _make_miniweb():
    m = types.ModuleType("miniweb")
    m.Request, m.Response, m.render, m.escape, m.is_safe_html = Request, WebResponse, render, escape, is_safe_html
    m.WORLD = WORLD
    m.__doc__ = "tiny request/response objects for the web-security module"
    return m


# --------------------------------------------------------------------------- #
# installation
# --------------------------------------------------------------------------- #
_SAVED = {}


def install():
    """Register the simulated modules and neuter the real OS escape hatches."""
    import os

    mods = {
        "subprocess": _make_subprocess(),
        "requests": _make_requests(),
        "yaml": _make_yaml(),
        "jwt": _make_jwt(),
        "miniweb": _make_miniweb(),
    }
    for name, mod in mods.items():
        _SAVED.setdefault(name, sys.modules.get(name))
        sys.modules[name] = mod

    if "os.system" not in _SAVED:
        _SAVED["os.system"] = os.system
        _SAVED["os.popen"] = os.popen

    def sim_system(command):
        rc = SHELL.run_string(command)
        sys.stdout.write(SHELL.drain())
        return rc << 8 if rc else 0

    def sim_popen(command, *a, **kw):
        SHELL.run_string(command)
        return io.StringIO(SHELL.drain())

    os.system = sim_system
    os.popen = sim_popen
    return mods


def uninstall():
    import os

    for name, mod in list(_SAVED.items()):
        if name == "os.system":
            os.system = mod
        elif name == "os.popen":
            os.popen = mod
        elif mod is None:
            sys.modules.pop(name, None)
        else:
            sys.modules[name] = mod
    _SAVED.clear()


def reset():
    WORLD.reset()
    SHELL.out = io.StringIO()
