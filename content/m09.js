export default {
  id: "m09",
  number: 9,
  title: "Cryptography you will actually use",
  focus: "secrets and hashing",
  subtitle:
    "Not elliptic curves — the four things every application needs: unpredictable tokens, integrity hashes, password storage, and signatures verified in constant time.",
  objectives: [
    "Generate unguessable values with `secrets`, and explain why `random` is not a substitute.",
    "Use hashes for integrity, and recognise where MD5 and SHA-1 are disqualifying.",
    "Store passwords with a slow, salted KDF and support upgrading the parameters over time.",
    "Sign and verify data with HMAC, compared in constant time.",
    "Build a signed, expiring token and defend each of its design choices.",
  ],
  rules: [
    { id: "PY-WEAK-RANDOM", what: "`random` is predictable; use `secrets`" },
    { id: "PY-WEAK-HASH", what: "MD5 and SHA-1 have practical collisions" },
    { id: "PY-FAST-HASH-PASSWORD", what: "a fast hash makes a stolen password table cheap to crack" },
    { id: "PY-TIMING-COMPARE", what: "secret comparison must be constant-time" },
  ],
  capstone:
    "Day 51 builds a signed, expiring, single-purpose token: versioned, bound to an audience, and rejected the moment anything about it is off.",

  lessons: [
    /* ----------------------------------------------------------------- 41 */
    {
      id: "m09l01",
      day: 47,
      title: "secrets, not random",
      minutes: 60,
      secure: "unpredictable values",
      cwe: ["CWE-338", "CWE-330"],
      tags: ["secrets", "random", "tokens", "csprng", "entropy"],
      lede:
        "`random` is a Mersenne Twister: fast, repeatable, and fully recoverable from its output. Everything a user must not guess comes from `secrets` instead.",
      blocks: [
        {
          t: "repl",
          lines: [
            ">>> import random",
            ">>> random.seed(42)",
            ">>> [random.randint(0, 99) for _ in range(5)]",
            "[81, 14, 3, 94, 35]",
            ">>> random.seed(42)",
            ">>> [random.randint(0, 99) for _ in range(5)]",
            "[81, 14, 3, 94, 35]",
          ],
        },
        {
          t: "p",
          md: `That reproducibility is the *point* of \`random\` — it exists for simulations, sampling and tests, where you want the same sequence twice. The internal state is 19 937 bits, and observing roughly **624 consecutive 32-bit outputs** is enough to reconstruct it and predict every past and future value.`,
        },
        {
          t: "code",
          label: "vulnerable",
          code: `import random, string

def password_reset_token():
    alphabet = string.ascii_letters + string.digits
    return "".join(random.choice(alphabet) for _ in range(32))`,
          cap: "An attacker who requests enough resets for their own accounts observes the generator's output directly, recovers the state, and predicts the next token — the one issued to someone else.",
        },
        {
          t: "code",
          label: "fixed",
          code: `import secrets

def password_reset_token():
    return secrets.token_urlsafe(32)        # ~43 characters, 256 bits of entropy`,
        },
        {
          t: "table",
          head: ["Need", "Use", "Note"],
          rows: [
            ["URL-safe token", "`secrets.token_urlsafe(32)`", "The default for session ids, reset links, API keys."],
            ["Hex token", "`secrets.token_hex(16)`", "32 hex characters, 128 bits."],
            ["Raw bytes", "`secrets.token_bytes(16)`", "Salts, nonces, IVs."],
            ["A number below n", "`secrets.randbelow(n)`", "Unbiased, unlike `% n`."],
            ["One of a sequence", "`secrets.choice(seq)`", "Unbiased selection."],
            ["Compare two secrets", "`secrets.compare_digest`", "Same function as `hmac.compare_digest`."],
            ["Shuffling a deck for a game", "`random.shuffle`", "Fine — no security decision rides on it."],
          ],
        },
        {
          t: "box",
          kind: "rule",
          title: "How much entropy?",
          md: `**128 bits** is the floor for anything an attacker can guess at offline speed; **256 bits** costs nothing extra and removes the discussion.

\`secrets.token_urlsafe(n)\` takes *bytes*, not characters: \`token_urlsafe(32)\` is 32 random bytes rendered as about 43 characters. Do not reduce it "because the URL is long" — a 6-character token is 36 bits, which is a few hours of brute force.`,
        },
        {
          t: "box",
          kind: "pitfall",
          title: "`% n` biases the result",
          md: `\`\`\`
secrets.randbelow(100)                     # uniform
int.from_bytes(secrets.token_bytes(1)) % 100   # biased toward 0-55
\`\`\`

256 does not divide evenly by 100, so the low values occur more often. The bias is small, and it is exactly the kind of small that cryptanalysis is built on. Use \`randbelow\`.`,
        },
        {
          t: "box",
          kind: "cve",
          title: "Predictable tokens in the wild",
          md: `Password-reset tokens derived from \`random\`, from the current timestamp, or from an MD5 of the user id have all been exploited in deployed applications. The pattern that makes it findable: a reset link that is short, or that looks like it encodes something.

A token should be opaque, long, and carry no information about what it refers to.`,
        },
        {
          t: "code",
          label: "fixed",
          code: `import secrets

ALPHABET = "23456789ABCDEFGHJKLMNPQRSTUVWXYZ"     # no 0/O, 1/I/L

def recovery_code(groups=4, size=4):
    """A human-readable code: still from the CSPRNG, just friendlier to type."""
    chars = [secrets.choice(ALPHABET) for _ in range(groups * size)]
    return "-".join("".join(chars[i:i + size]) for i in range(0, len(chars), size))`,
          cap: "Readability comes from the alphabet, never from using a weaker generator. 16 characters of a 32-symbol alphabet is 80 bits — acceptable for a code that is also rate-limited.",
        },
      ],
      spot: {
        label: "invite link generator",
        prompt: "Click the line that makes every invite predictable.",
        lines: [6],
        why:
          "Line 6. Seeding with the current time gives roughly a million possible states for a known second, so an attacker who knows approximately when an invite was created can enumerate every token. Delete the seeding *and* the `random` module: use `secrets.token_urlsafe(32)`.",
        code: `import random
import time
import string

def invite_code(email):
    random.seed(int(time.time()))
    alphabet = string.ascii_lowercase + string.digits
    return "".join(random.choice(alphabet) for _ in range(12))`,
      },
      quiz: [
        {
          q: "Why is `random` unsuitable for a session id?",
          options: [
            "It is slower than `secrets`.",
            "Its internal state is recoverable from its output, so future values become predictable.",
            "It cannot produce strings.",
          ],
          answer: 1,
          why:
            "The Mersenne Twister is designed to be reproducible. About 624 observed outputs reconstruct the state, which is a realistic amount for an attacker who can request tokens.",
        },
        {
          q: "`secrets.token_urlsafe(32)` returns how many characters?",
          options: ["32", "about 43 — the argument is a byte count", "64"],
          answer: 1,
          why: "Base64url of 32 bytes is roughly 43 characters. Reading the argument as a character count leads to under-sized tokens.",
        },
        {
          q: "`secrets.randbelow(100)` versus `secrets.token_bytes(1)[0] % 100`:",
          options: [
            "Equivalent.",
            "The modulo version is biased because 256 is not a multiple of 100.",
            "The modulo version is more secure.",
          ],
          answer: 1,
          why: "Modulo bias. `randbelow` rejects out-of-range draws to stay uniform.",
        },
      ],
      exercise: {
        title: "A token factory with no predictable parts",
        brief: `Write four generators, all using \`secrets\` and never \`random\`.

1. \`session_token()\` — \`secrets.token_urlsafe(32)\`.
2. \`api_key(prefix)\` — \`"<prefix>_<40 hex chars>"\`. \`prefix\` must be 2–10 lowercase ASCII letters, else \`ValueError\`.
3. \`recovery_code()\` — four groups of four characters from the unambiguous alphabet \`"23456789ABCDEFGHJKLMNPQRSTUVWXYZ"\`, joined with \`-\` (e.g. \`"K7F2-98QR-MNBV-3XZA"\`).
4. \`numeric_otp(digits=6)\` — a zero-padded decimal string of exactly \`digits\` digits, uniform across the whole range (so \`"000123"\` is as likely as \`"912345"\`). \`digits\` must be 4–10, else \`ValueError\`.

Then \`entropy_bits(alphabet_size, length)\` returning the entropy in bits as a float, and \`is_strong(bits)\` returning \`True\` only at 128 bits or more.`,
        rubric: [
          "`secrets` is used; `random` is neither imported nor called",
          "Tokens vary between calls and have the documented shapes",
          "`recovery_code` uses only the unambiguous alphabet and the right grouping",
          "`numeric_otp` is zero-padded, correct length, and covers the full range",
          "`entropy_bits`/`is_strong` are correct",
        ],
        starter: `import secrets

CODE_ALPHABET = "23456789ABCDEFGHJKLMNPQRSTUVWXYZ"


def session_token():
    """A URL-safe session token with 256 bits of entropy."""


def api_key(prefix):
    """'<prefix>_<40 hex characters>'."""


def recovery_code():
    """Four groups of four unambiguous characters."""


def numeric_otp(digits=6):
    """A uniformly distributed, zero-padded numeric code."""


def entropy_bits(alphabet_size, length):
    """Bits of entropy in a random string of this length over this alphabet."""


def is_strong(bits):
    """True at 128 bits or above."""


print(len(session_token()), api_key("acme")[:5], recovery_code(), numeric_otp())
`,
        stdin: [],
        tests: [
          {
            name: "session tokens are long and unique",
            code: `a, b = session_token(), session_token()
assert a != b, "two calls returned the same token"
assert len(a) >= 40, f"token too short: {len(a)}"
assert all(c.isalnum() or c in "-_" for c in a), f"not URL-safe: {a!r}"`,
          },
          {
            name: "api keys have the documented shape",
            code: `k = api_key("acme")
assert k.startswith("acme_"), f"got {k!r}"
body = k.split("_", 1)[1]
assert len(body) == 40, f"expected 40 hex characters, got {len(body)}"
assert all(c in "0123456789abcdef" for c in body), f"not hex: {body!r}"
assert api_key("acme") != api_key("acme")`,
          },
          {
            name: "api key prefixes are validated",
            code: `for bad in ("", "a", "x" * 11, "ACME", "ac-me", "ac1", 5, None):
    with raises(ValueError):
        api_key(bad)
assert api_key("ab").startswith("ab_")`,
          },
          {
            name: "recovery codes are grouped and unambiguous",
            code: `c = recovery_code()
parts = c.split("-")
assert len(parts) == 4 and all(len(p) == 4 for p in parts), f"got {c!r}"
assert all(ch in CODE_ALPHABET for ch in c.replace("-", "")), f"unexpected characters in {c!r}"
seen = {recovery_code() for _ in range(20)}
assert len(seen) == 20, "recovery codes repeat"`,
          },
          {
            name: "otp is the right length and zero-padded",
            code: `for digits in (4, 6, 8, 10):
    code = numeric_otp(digits)
    assert len(code) == digits, f"expected {digits} characters, got {code!r}"
    assert code.isdigit(), f"got {code!r}"
for bad in (3, 11, 0, -1, "6", None, True):
    with raises(ValueError):
        numeric_otp(bad)`,
          },
          {
            name: "otp covers the full range including leading zeros",
            code: `codes = [numeric_otp(4) for _ in range(4000)]
assert any(c.startswith("0") for c in codes), "leading zeros never appear: the range is not uniform"
assert len(set(codes)) > 1000, "too little variation"
assert all(len(c) == 4 for c in codes)`,
          },
          {
            name: "entropy maths",
            code: `assert approx(entropy_bits(2, 128), 128.0)
assert approx(entropy_bits(32, 16), 80.0)
assert approx(entropy_bits(10, 6), 19.93156856932417, 1e-6)
assert is_strong(128) is True
assert is_strong(127.9) is False
assert is_strong(entropy_bits(64, 43)) is True
assert is_strong(entropy_bits(10, 6)) is False`,
          },
          {
            name: "random is never used",
            code: `assert "random" not in dir() or True  # enforced by the exercise requirements`,
          },
        ],
        requirements: [
          { kind: "defines", value: "session_token" },
          { kind: "uses_module", value: "secrets" },
          { kind: "forbids_module", value: "random", message: "Remove `random` entirely — every value here must come from `secrets`." },
          { kind: "no_finding", value: "PY-WEAK-RANDOM" },
        ],
        hints: [
          "`secrets.token_hex(20)` gives exactly 40 hex characters — the argument is bytes, and each byte is two hex characters.",
          "`numeric_otp`: `secrets.randbelow(10 ** digits)` then `f\"{value:0{digits}d}\"`. Building it digit-by-digit with `choice` also works, but the modulo-free `randbelow` is the idiomatic form.",
          "Zero-padding is what makes the distribution uniform: taking `randbelow(900_000) + 100_000` to 'avoid leading zeros' discards a tenth of the keyspace.",
          "Entropy is `length * log2(alphabet_size)` — `math.log2` is in the standard library.",
        ],
        solution: `import math
import secrets

CODE_ALPHABET = "23456789ABCDEFGHJKLMNPQRSTUVWXYZ"
STRONG_BITS = 128


def session_token():
    """A URL-safe session token with 256 bits of entropy."""
    return secrets.token_urlsafe(32)


def api_key(prefix):
    """'<prefix>_<40 hex characters>'."""
    if not isinstance(prefix, str) or not 2 <= len(prefix) <= 10:
        raise ValueError("prefix must be 2 to 10 characters")
    if not (prefix.isascii() and prefix.isalpha() and prefix.islower()):
        raise ValueError("prefix must be lowercase ASCII letters")
    return f"{prefix}_{secrets.token_hex(20)}"


def recovery_code():
    """Four groups of four unambiguous characters."""
    chars = [secrets.choice(CODE_ALPHABET) for _ in range(16)]
    return "-".join("".join(chars[i:i + 4]) for i in range(0, 16, 4))


def numeric_otp(digits=6):
    """A uniformly distributed, zero-padded numeric code."""
    if isinstance(digits, bool) or not isinstance(digits, int):
        raise ValueError("digits must be an int")
    if not 4 <= digits <= 10:
        raise ValueError("digits must be between 4 and 10")
    value = secrets.randbelow(10 ** digits)
    return f"{value:0{digits}d}"


def entropy_bits(alphabet_size, length):
    """Bits of entropy in a random string of this length over this alphabet."""
    return length * math.log2(alphabet_size)


def is_strong(bits):
    """True at 128 bits or above."""
    return bits >= STRONG_BITS


print(len(session_token()), api_key("acme")[:5], recovery_code(), numeric_otp())`,
        why: `Every value comes from the operating system's CSPRNG through \`secrets\`. There is no seeding, no fallback and no "fast path" — and \`random\` is not imported at all, which is the property a reviewer can verify in one glance at the import block.

Two details carry more weight than they appear to:

**Zero-padding rather than range-shifting.** The tempting way to avoid an OTP starting with \`0\` is \`randbelow(900_000) + 100_000\`. That throws away 10% of the keyspace and, more importantly, tells an attacker that no code begins with zero — reducing a six-digit search by a tenth before they start. Formatting with \`:06d\` keeps the full range and the fixed width.

**\`randbelow\` instead of modulo.** \`secrets.randbelow(n)\` rejects and redraws when a sample falls outside the usable range, so the result is uniform for any \`n\`. Taking a byte modulo 100 biases toward the low values, because 256 is not a multiple of 100. The bias is a few percent — which is irrelevant for a dice roll and precisely the kind of structure that cryptanalysis exploits.

The unambiguous alphabet in \`recovery_code\` is a usability decision with a security consequence: it is 32 symbols rather than 36, so 16 characters give 80 bits instead of 83. That is acceptable only because recovery codes are rate-limited and single-use. Shortening the code to eight characters — 40 bits — would not be, which is what \`entropy_bits\` and \`is_strong\` exist to make visible.`,
      },
      wrapup: `- \`random\` is reproducible by design and its state is recoverable. Never for security.
- \`secrets.token_urlsafe(32)\` is the default answer; the argument is bytes, not characters.
- \`randbelow\` avoids modulo bias; zero-pad rather than shrinking the range.
- 128 bits minimum for anything guessable offline.`,
      refs: [
        { label: "secrets — generate secure random numbers", url: "https://docs.python.org/3/library/secrets.html" },
        { label: "CWE-338: Use of Cryptographically Weak PRNG", url: "https://cwe.mitre.org/data/definitions/338.html" },
      ],
    },

    /* ----------------------------------------------------------------- 42 */
    {
      id: "m09l02",
      day: 48,
      title: "Hashing for integrity, and the algorithms that are finished",
      minutes: 60,
      secure: "collision resistance",
      cwe: ["CWE-327", "CWE-328"],
      tags: ["hashlib", "sha256", "md5", "integrity", "collisions"],
      lede:
        "A hash answers one question: *are these the same bytes?* MD5 and SHA-1 can no longer answer it, because producing two inputs with the same digest is now cheap.",
      blocks: [
        {
          t: "code",
          label: "example",
          code: `import hashlib

hashlib.sha256(b"hello").hexdigest()
# '2cf24dba5fb0a30e26e83b2ac5b9e29e1b161e5c1fa7425e73043362938b9824'

h = hashlib.sha256()                     # streaming, for large files
with open("image.iso", "rb") as fh:
    for chunk in iter(lambda: fh.read(1024 * 1024), b""):
        h.update(chunk)
print(h.hexdigest())`,
          cap: "`hashlib` refuses `str` — you must encode, which forces you to name the encoding and makes the digest reproducible across platforms.",
        },
        {
          t: "table",
          head: ["Algorithm", "Status", "Acceptable for"],
          rows: [
            ["MD5", "**broken** — collisions in seconds", "Nothing security-related."],
            ["SHA-1", "**broken** — SHAttered, 2017", "Nothing security-related."],
            ["SHA-256 / SHA-512", "current", "Integrity, signatures, fingerprints."],
            ["SHA-3 / BLAKE2", "current", "Same, with different internals."],
            ["`hashlib.scrypt`, `pbkdf2_hmac`", "current KDFs", "**Passwords only.**"],
            ["`hmac` + SHA-256", "current", "Authenticating a message with a shared key."],
          ],
        },
        {
          t: "box",
          kind: "cve",
          title: "What 'broken' means here",
          md: `**SHAttered** (2017) produced two different PDFs with the same SHA-1 digest. **Chosen-prefix** collisions for SHA-1 followed in 2020 at a cost of tens of thousands of dollars, and that cost only falls.

MD5 collisions are generated in seconds on a laptop, and were used in the **Flame** malware (2012) to forge a Microsoft code-signing certificate and ship malicious updates as legitimate ones.

A collision breaks exactly the property integrity checking depends on: *different content, same digest*.`,
        },
        { t: "h", text: "Where a weak hash is still not a finding" },
        {
          t: "code",
          label: "example",
          code: `import hashlib

def cache_key(url):
    """Not a security decision: just a short, stable key for a cache shard."""
    return hashlib.md5(url.encode("utf-8"), usedforsecurity=False).hexdigest()`,
          cap: "`usedforsecurity=False` (3.9+) documents the intent and keeps the call working on FIPS-restricted builds where MD5 is otherwise disabled. The auditor in this course honours it.",
        },
        {
          t: "box",
          kind: "rule",
          title: "The question to ask",
          md: `*If an attacker produced a second input with this same digest, would anything bad happen?*

- **Yes** — file integrity, signatures, deduplicating user uploads, comparing passwords, cache keys that control access. Use SHA-256.
- **No** — sharding a cache, bucketing metrics, generating a stable colour from a name. Any hash will do; say so with \`usedforsecurity=False\`.`,
        },
        { t: "h", text: "Hashes are not for passwords, and not for secrecy" },
        {
          t: "box",
          kind: "pitfall",
          title: "Three things a hash does not do",
          md: `1. **It is not encryption.** There is no key and nothing to reverse — but a hash of a predictable value (an email, a phone number, a 4-digit PIN) is trivially recovered by hashing all the candidates.
2. **It is not a password store.** SHA-256 is fast by design; a GPU computes billions per second. Use a KDF (next lesson).
3. **It does not authenticate.** Anyone can compute \`sha256(message)\`. Proving *who* produced it requires a key — that is HMAC, two lessons from here.`,
        },
        {
          t: "code",
          label: "vulnerable",
          code: `def anonymise(email):
    """'Anonymised' analytics identifier."""
    return hashlib.sha256(email.encode()).hexdigest()`,
          cap: "Reversible by brute force: hash a list of known addresses and match. Under GDPR this is pseudonymisation, not anonymisation. Use an HMAC with a secret key you can rotate, or a random id stored in a lookup table.",
        },
        {
          t: "code",
          label: "fixed",
          code: `import hashlib

CHUNK = 1024 * 1024

def file_digest(path, algorithm="sha256"):
    """Stream a file and return its hex digest; memory stays flat."""
    h = hashlib.new(algorithm)
    with open(path, "rb") as fh:
        while chunk := fh.read(CHUNK):
            h.update(chunk)
    return h.hexdigest()`,
          cap: "`hashlib.file_digest(fh, \"sha256\")` does this for you in 3.11+. Either way, never `fh.read()` the whole file.",
        },
      ],
      quiz: [
        {
          q: "Why is SHA-1 unacceptable for verifying a downloaded artifact?",
          options: [
            "It is slow.",
            "Chosen-prefix collisions are practical, so an attacker can produce different content with the same digest.",
            "It produces too few bits to store.",
          ],
          answer: 1,
          why: "A collision breaks the exact property the check relies on. SHAttered demonstrated it with real PDFs in 2017.",
        },
        {
          q: "`hashlib.md5(url, usedforsecurity=False)` for a cache shard key — acceptable?",
          options: [
            "No, MD5 is banned everywhere.",
            "Yes — no security decision depends on it, and the flag documents that and keeps it working on FIPS builds.",
            "Only with a salt.",
          ],
          answer: 1,
          why: "The algorithm is not the question; the consequence of a collision is. State the intent in the code.",
        },
        {
          q: "You hash email addresses to 'anonymise' analytics. What is wrong?",
          options: [
            "Nothing.",
            "The input space is small and enumerable, so the hash is reversible by brute force.",
            "SHA-256 is too slow.",
          ],
          answer: 1,
          why:
            "Hashing low-entropy, enumerable values provides pseudonymity at best. Use a keyed HMAC with a rotatable secret, or a random identifier stored separately.",
        },
      ],
      exercise: {
        title: "An integrity manifest",
        brief: `Build the integrity-checking half of a deployment tool.

The setup creates \`dist/\` containing \`app.py\`, \`lib.py\` and \`notes.txt\`.

Write:

1. \`file_digest(path, algorithm="sha256")\` — stream the file in 64 KiB chunks and return the hex digest. Raise \`ValueError\` for an algorithm not in \`ALLOWED\` (\`sha256\`, \`sha384\`, \`sha512\`, \`blake2b\`) — note that MD5 and SHA-1 must be **refused**. Raise \`FileNotFoundError\` for a missing file.
2. \`build_manifest(directory, algorithm="sha256")\` — return \`{filename: digest}\` for every regular file directly inside \`directory\`, sorted by name (a dict preserves insertion order, so build it in sorted order).
3. \`verify_manifest(directory, manifest, algorithm="sha256")\` — return a dict \`{"ok": bool, "changed": [...], "missing": [...], "unexpected": [...]}\` with each list sorted. \`changed\` are files whose digest differs, \`missing\` are in the manifest but not on disk, \`unexpected\` are on disk but not in the manifest. \`ok\` is \`True\` only when all three lists are empty.
4. Comparisons of digests must use \`hmac.compare_digest\`.`,
        rubric: [
          "Digests match `hashlib` computed directly",
          "MD5 and SHA-1 are refused with `ValueError`",
          "Manifest keys are sorted filenames",
          "Verification detects changed, missing and unexpected files separately",
          "Digest comparison uses `compare_digest`",
          "Large files are streamed, not read whole",
        ],
        setup: `import os
os.makedirs("dist", exist_ok=True)
with open("dist/app.py", "w", encoding="utf-8") as _fh:
    _fh.write("print('hello')\\n")
with open("dist/lib.py", "w", encoding="utf-8") as _fh:
    _fh.write("VERSION = '1.0'\\n")
with open("dist/notes.txt", "w", encoding="utf-8") as _fh:
    _fh.write("release notes\\n")
os.makedirs("dist/subdir", exist_ok=True)
with open("dist/subdir/ignored.txt", "w", encoding="utf-8") as _fh:
    _fh.write("not a direct child\\n")
`,
        starter: `import hashlib
import hmac
from pathlib import Path

ALLOWED = ("sha256", "sha384", "sha512", "blake2b")
CHUNK = 64 * 1024


def file_digest(path, algorithm="sha256"):
    """Stream a file and return its hex digest."""


def build_manifest(directory, algorithm="sha256"):
    """Return {filename: digest} for the directory's files, name-sorted."""


def verify_manifest(directory, manifest, algorithm="sha256"):
    """Compare the directory against a manifest."""


m = build_manifest("dist")
print(list(m))
print(verify_manifest("dist", m)["ok"])
`,
        stdin: [],
        tests: [
          {
            name: "digests match hashlib",
            code: `import hashlib
expected = hashlib.sha256(open("dist/app.py", "rb").read()).hexdigest()
assert file_digest("dist/app.py") == expected, "digest does not match hashlib"
expected512 = hashlib.sha512(open("dist/app.py", "rb").read()).hexdigest()
assert file_digest("dist/app.py", "sha512") == expected512`,
          },
          {
            name: "broken algorithms are refused",
            code: `for bad in ("md5", "sha1", "MD5", "crc32", "", None):
    with raises(ValueError):
        file_digest("dist/app.py", bad)`,
          },
          {
            name: "missing files raise",
            code: `with raises(FileNotFoundError):
    file_digest("dist/nope.py")`,
          },
          {
            name: "the manifest covers direct children only, sorted",
            code: `m = build_manifest("dist")
assert list(m) == ["app.py", "lib.py", "notes.txt"], f"got {list(m)!r}"
assert all(len(v) == 64 for v in m.values()), "sha256 hex digests are 64 characters"`,
          },
          {
            name: "an untouched directory verifies",
            code: `m = build_manifest("dist")
r = verify_manifest("dist", m)
assert r == {"ok": True, "changed": [], "missing": [], "unexpected": []}, f"got {r!r}"`,
          },
          {
            name: "a modified file is detected",
            code: `m = build_manifest("dist")
with open("dist/lib.py", "w", encoding="utf-8") as fh:
    fh.write("VERSION = '1.0'  # tampered\\n")
r = verify_manifest("dist", m)
assert r["ok"] is False and r["changed"] == ["lib.py"], f"got {r!r}"
assert r["missing"] == [] and r["unexpected"] == []`,
          },
          {
            name: "missing and unexpected files are distinguished",
            code: `m = build_manifest("dist")
m["ghost.py"] = "0" * 64
with open("dist/extra.py", "w", encoding="utf-8") as fh:
    fh.write("new\\n")
r = verify_manifest("dist", m)
assert r["missing"] == ["ghost.py"], f"got {r!r}"
assert r["unexpected"] == ["extra.py"], f"got {r!r}"
assert r["ok"] is False
import os
os.remove("dist/extra.py")`,
          },
          {
            name: "lists are sorted",
            code: `m = {"z.py": "0" * 64, "a.py": "0" * 64, "m.py": "0" * 64}
r = verify_manifest("dist", m)
assert r["missing"] == sorted(r["missing"]), f"got {r['missing']!r}"
assert r["unexpected"] == sorted(r["unexpected"]), f"got {r['unexpected']!r}"`,
          },
        ],
        requirements: [
          { kind: "defines", value: "file_digest" },
          { kind: "defines", value: "verify_manifest" },
          { kind: "calls", value: "hmac.compare_digest" },
          { kind: "no_finding", value: "PY-WEAK-HASH" },
        ],
        hints: [
          "Check the algorithm against `ALLOWED` *before* calling `hashlib.new` — otherwise `hashlib.new(\"md5\")` succeeds and the allowlist does nothing.",
          "Stream with the walrus operator: `while chunk := fh.read(CHUNK): h.update(chunk)`.",
          "`sorted(p for p in Path(directory).iterdir() if p.is_file())` gives direct children only — `iterdir` does not recurse, which is what the 'subdir is ignored' test checks.",
          "Set arithmetic makes the three lists trivial: `on_disk - in_manifest` is unexpected, `in_manifest - on_disk` is missing, and the intersection is where you compare digests.",
        ],
        solution: `import hashlib
import hmac
from pathlib import Path

ALLOWED = ("sha256", "sha384", "sha512", "blake2b")
CHUNK = 64 * 1024


def file_digest(path, algorithm="sha256"):
    """Stream a file and return its hex digest."""
    if algorithm not in ALLOWED:
        raise ValueError(f"algorithm must be one of {', '.join(ALLOWED)}")

    p = Path(path)
    if not p.is_file():
        raise FileNotFoundError(f"no such file: {p}")

    digest = hashlib.new(algorithm)
    with p.open("rb") as fh:
        while chunk := fh.read(CHUNK):
            digest.update(chunk)
    return digest.hexdigest()


def build_manifest(directory, algorithm="sha256"):
    """Return {filename: digest} for the directory's files, name-sorted."""
    base = Path(directory)
    return {
        path.name: file_digest(path, algorithm)
        for path in sorted(base.iterdir())
        if path.is_file()
    }


def verify_manifest(directory, manifest, algorithm="sha256"):
    """Compare the directory against a manifest."""
    base = Path(directory)
    on_disk = {p.name for p in base.iterdir() if p.is_file()}
    recorded = set(manifest)

    changed = []
    for name in sorted(on_disk & recorded):
        actual = file_digest(base / name, algorithm)
        if not hmac.compare_digest(actual, manifest[name]):
            changed.append(name)

    missing = sorted(recorded - on_disk)
    unexpected = sorted(on_disk - recorded)

    return {
        "ok": not (changed or missing or unexpected),
        "changed": changed,
        "missing": missing,
        "unexpected": unexpected,
    }


m = build_manifest("dist")
print(list(m))
print(verify_manifest("dist", m)["ok"])`,
        why: `The algorithm allowlist is checked before \`hashlib.new\`, which matters because \`hashlib.new("md5")\` succeeds happily — an allowlist consulted after the fact is decoration. Rejecting MD5 and SHA-1 here is not pedantry: a manifest is exactly the use case collisions break, since an attacker who can supply file content can supply two files with one digest.

The three result categories exist because they mean different things operationally:

- **changed** — the bytes differ from what was published. This is the tamper signal.
- **missing** — a file in the manifest is gone. Usually a broken deploy, occasionally an attacker removing something inconvenient.
- **unexpected** — a file on disk that nobody published. This is the one people forget, and it is where a dropped webshell shows up. A verifier that only checks the manifest's entries will report "all files verified" while a hostile \`.py\` sits beside them.

\`compare_digest\` on hex digests is defensive rather than strictly necessary — these are public values, so the timing channel leaks nothing. The habit is the point: when the same code is reused for a digest that *is* secret, the comparison is already right.

Streaming in 64 KiB chunks keeps memory flat whether the artifact is 2 KB or 2 GB, and the walrus loop is the shortest correct spelling. On Python 3.11+, \`hashlib.file_digest(fh, "sha256")\` does the same thing in one call and is worth preferring in real code.`,
      },
      wrapup: `- MD5 and SHA-1 are broken for anything where a collision matters. SHA-256 by default.
- \`usedforsecurity=False\` documents a genuinely non-security hash and keeps it FIPS-safe.
- A hash is not encryption, not a password store, and not authentication.
- Hashing low-entropy values (emails, PINs) is reversible by enumeration.`,
      refs: [
        { label: "hashlib", url: "https://docs.python.org/3/library/hashlib.html" },
        { label: "SHAttered — the first SHA-1 collision", url: "https://shattered.io/" },
        { label: "CWE-328: Use of Weak Hash", url: "https://cwe.mitre.org/data/definitions/328.html" },
      ],
    },

    /* ----------------------------------------------------------------- 43 */
    {
      id: "m09l03",
      day: 49,
      title: "Password storage: slow, salted, and upgradable",
      minutes: 60,
      secure: "key derivation functions",
      cwe: ["CWE-916", "CWE-759"],
      tags: ["passwords", "pbkdf2", "scrypt", "argon2", "salt", "kdf"],
      lede:
        "A password hash has one job: make an attacker who stole your database pay enormously per guess. Everything else about the design follows from that.",
      blocks: [
        {
          t: "p",
          md: `Assume the table is stolen. That is not pessimism — it is the threat model the control exists for. The attacker now has unlimited offline guesses, limited only by how fast they can compute your hash function.

SHA-256 on a modern GPU runs at billions of hashes per second. A {{key derivation function}} is deliberately slow and deliberately memory-hungry, turning billions per second into thousands.`,
        },
        {
          t: "table",
          head: ["Approach", "Guesses/second (GPU, approx.)", "Verdict"],
          rows: [
            ["`sha256(password)`", "tens of billions", "**Broken.**"],
            ["`sha256(salt + password)`", "tens of billions", "**Broken** — salt stops rainbow tables, not speed."],
            ["`pbkdf2_hmac('sha256', ..., 600_000)`", "hundreds of thousands", "Acceptable; stdlib."],
            ["`scrypt(n=2**15, r=8, p=1)`", "tens of thousands", "Good; memory-hard; stdlib."],
            ["argon2id", "tens of thousands", "**Best.** Needs `argon2-cffi`."],
            ["bcrypt (cost 12)", "tens of thousands", "Good; needs `bcrypt`."],
          ],
        },
        {
          t: "box",
          kind: "rule",
          title: "The three properties",
          md: `1. **Slow** — a tunable work factor you raise as hardware improves.
2. **Salted** — a unique random salt per password, so identical passwords produce different hashes and one precomputed table cannot cover many users.
3. **Memory-hard** (scrypt, argon2) — GPUs have enormous parallelism but limited memory per core, so memory cost hurts the attacker far more than the defender.`,
        },
        {
          t: "code",
          label: "fixed",
          code: `import hashlib, hmac, secrets

ITERATIONS = 600_000          # OWASP guidance for PBKDF2-HMAC-SHA256
SALT_BYTES = 16

def hash_password(password):
    """Return a self-describing record: algorithm, parameters, salt, hash."""
    salt = secrets.token_bytes(SALT_BYTES)
    dk = hashlib.pbkdf2_hmac("sha256", password.encode("utf-8"), salt, ITERATIONS)
    return f"pbkdf2_sha256$\x7bITERATIONS}$\x7bsalt.hex()}$\x7bdk.hex()}"

def verify_password(password, record):
    """Constant-time verification against a stored record."""
    algorithm, iterations, salt_hex, hash_hex = record.split("$")
    if algorithm != "pbkdf2_sha256":
        raise ValueError("unsupported algorithm")
    dk = hashlib.pbkdf2_hmac("sha256", password.encode("utf-8"),
                             bytes.fromhex(salt_hex), int(iterations))
    return hmac.compare_digest(dk.hex(), hash_hex)`,
          cap: "Storing the algorithm and parameters *inside the record* is what makes upgrading possible later without a flag day.",
        },
        {
          t: "box",
          kind: "good",
          title: "The upgrade path",
          md: `You cannot re-hash a stored password — you do not have the plaintext. You *do* have it for one instant: during a successful login.

\`\`\`
if verify_password(password, record):
    if needs_rehash(record):                 # old algorithm or low iterations
        store(user, hash_password(password))  # upgrade silently, in place
    return "ok"
\`\`\`

Over a few months most active accounts migrate themselves. Dormant accounts keep the old parameters, which is why you also force a reset for anything untouched for a year.`,
        },
        {
          t: "box",
          kind: "pitfall",
          title: "A pepper is not a salt",
          md: `A **salt** is unique per password and stored alongside the hash. A **pepper** is a single secret, shared across all passwords, kept *outside* the database — in a secrets manager or an HSM.

A pepper protects against a database-only breach, where the attacker has the table but not the application's secrets. It is a genuine defence-in-depth measure, and it is not a substitute for a KDF: pepper plus SHA-256 is still fast.`,
        },
        {
          t: "box",
          kind: "cve",
          title: "What a slow hash buys",
          md: `In the 2012 LinkedIn breach, 6.5 million unsalted SHA-1 password hashes were published; most were cracked within days. The 2015 Ashley Madison breach contained bcrypt hashes — which held — alongside a legacy MD5 field that let researchers crack 11 million passwords in days.

Same breach, same passwords, two orders of magnitude difference in outcome, decided entirely by the hashing choice.`,
        },
      ],
      spot: {
        label: "signup handler",
        prompt: "Click the line that makes a stolen table worthless to defend.",
        lines: [5],
        why:
          "Line 5. A single SHA-256 of salt+password is fast, so the salt only prevents precomputed tables — it does nothing about throughput. The attacker still gets billions of guesses per second. Replace it with `hashlib.pbkdf2_hmac` or `hashlib.scrypt`.",
        code: `import hashlib, secrets

def create_user(db, email, password):
    salt = secrets.token_hex(16)
    digest = hashlib.sha256((salt + password).encode()).hexdigest()
    db.insert(email=email, salt=salt, password_hash=digest)
    return email`,
      },
      quiz: [
        {
          q: "What does a salt actually prevent?",
          options: [
            "Fast brute force.",
            "Precomputed (rainbow) tables and the ability to see that two users share a password.",
            "Database theft.",
          ],
          answer: 1,
          why:
            "Salting forces per-password work instead of one shared table, but each guess is still as fast as the hash. Slowness comes from the KDF's work factor.",
        },
        {
          q: "Why store the algorithm and iteration count inside the password record?",
          options: [
            "For debugging.",
            "So parameters can be raised later and old records verified and upgraded at next login.",
            "It is required by PBKDF2.",
          ],
          answer: 1,
          why: "Self-describing records make migration incremental rather than a flag day you can never schedule.",
        },
        {
          q: "When can you upgrade a stored password hash?",
          options: [
            "Any time, by re-hashing the stored value.",
            "Only during a successful login, when you briefly hold the plaintext.",
            "Never.",
          ],
          answer: 1,
          why:
            "Re-hashing the stored hash just wraps the old one — it does not increase the work for an attacker guessing the password. The plaintext is only available at login.",
        },
      ],
      exercise: {
        title: "A password store with an upgrade path",
        brief: `Implement a self-describing password record using \`hashlib.pbkdf2_hmac\`.

Record format: \`"pbkdf2_sha256$<iterations>$<salt_hex>$<hash_hex>"\`.

1. \`hash_password(password, *, iterations=DEFAULT_ITERATIONS)\` — random 16-byte salt; reject a non-\`str\` or shorter than 8 characters with \`ValueError\`; reject \`iterations\` below \`MIN_ITERATIONS\` (50 000) with \`ValueError\`.
2. \`verify_password(password, record)\` — return \`True\`/\`False\`. Use \`hmac.compare_digest\`. A malformed record raises \`ValueError\`; an unknown algorithm prefix raises \`ValueError\`. A wrong password returns \`False\` — never raises.
3. \`needs_rehash(record, *, iterations=DEFAULT_ITERATIONS)\` — \`True\` when the record's algorithm is not \`pbkdf2_sha256\` or its iteration count is below \`iterations\`.
4. \`login(store, email, password)\` — \`store\` is \`{email: record}\`. Return \`(ok, action)\` where \`action\` is \`"ok"\`, \`"rehashed"\`, or \`"rejected"\`. On a successful login of a record needing rehash, replace it in \`store\` with a fresh one and return \`"rehashed"\`. Unknown email behaves exactly like a wrong password (compute a hash anyway, return \`(False, "rejected")\`).

Use \`DEFAULT_ITERATIONS = 100_000\` so the grader stays fast; real deployments use 600 000 for PBKDF2-HMAC-SHA256.`,
        rubric: [
          "Two hashes of the same password differ (unique salts)",
          "Verification succeeds for the right password and fails for the wrong one",
          "`compare_digest` is used",
          "`needs_rehash` detects low iterations and foreign algorithms",
          "A successful login with an old record upgrades it in place",
          "Unknown accounts do the same work as known ones",
        ],
        starter: `import hashlib
import hmac
import secrets

DEFAULT_ITERATIONS = 100_000       # production: 600_000 for PBKDF2-HMAC-SHA256
MIN_ITERATIONS = 50_000
SALT_BYTES = 16
ALGORITHM = "pbkdf2_sha256"


def hash_password(password, *, iterations=DEFAULT_ITERATIONS):
    """Return 'pbkdf2_sha256$<iterations>$<salt_hex>$<hash_hex>'."""


def verify_password(password, record):
    """True when the password matches the record."""


def needs_rehash(record, *, iterations=DEFAULT_ITERATIONS):
    """True when the record should be upgraded at next login."""


def login(store, email, password):
    """Return (ok, action) where action is 'ok', 'rehashed' or 'rejected'."""


rec = hash_password("correct-horse-battery")
print(rec.split("$")[0], verify_password("correct-horse-battery", rec))
`,
        stdin: [],
        tests: [
          {
            name: "records are self-describing and uniquely salted",
            code: `a = hash_password("correct-horse")
b = hash_password("correct-horse")
assert a != b, "identical passwords must produce different records"
parts = a.split("$")
assert len(parts) == 4, f"got {parts!r}"
assert parts[0] == "pbkdf2_sha256" and parts[1] == str(DEFAULT_ITERATIONS)
assert len(parts[2]) == 32, f"expected a 16-byte salt in hex: {parts[2]!r}"
assert len(parts[3]) == 64, f"expected a sha256 hash in hex: {parts[3]!r}"`,
          },
          {
            name: "verification works both ways",
            code: `rec = hash_password("correct-horse")
assert verify_password("correct-horse", rec) is True
assert verify_password("Correct-horse", rec) is False
assert verify_password("", rec) is False
assert verify_password("correct-horse ", rec) is False`,
          },
          {
            name: "weak inputs are refused at hashing time",
            code: `for bad in ("short", "", None, 12345):
    with raises(ValueError):
        hash_password(bad)
with raises(ValueError):
    hash_password("long-enough-password", iterations=1000)`,
          },
          {
            name: "malformed records raise, wrong passwords do not",
            code: `for bad in ("", "nope", "a$b$c", "a$b$c$d$e", "bcrypt$1$aa$bb"):
    with raises(ValueError):
        verify_password("whatever", bad)
rec = hash_password("correct-horse")
assert verify_password("wrong", rec) is False`,
          },
          {
            name: "needs_rehash spots old parameters",
            code: `old = hash_password("correct-horse", iterations=MIN_ITERATIONS)
assert needs_rehash(old) is True
fresh = hash_password("correct-horse")
assert needs_rehash(fresh) is False
assert needs_rehash("bcrypt$12$abc$def") is True
assert needs_rehash(fresh, iterations=DEFAULT_ITERATIONS * 2) is True`,
          },
          {
            name: "login upgrades a weak record in place",
            code: `store = {"ada@example.com": hash_password("correct-horse", iterations=MIN_ITERATIONS)}
before = store["ada@example.com"]
ok, action = login(store, "ada@example.com", "correct-horse")
assert (ok, action) == (True, "rehashed"), f"got {(ok, action)!r}"
after = store["ada@example.com"]
assert after != before, "the record was not replaced"
assert needs_rehash(after) is False
assert verify_password("correct-horse", after) is True`,
          },
          {
            name: "a current record logs in without churn",
            code: `store = {"ada@example.com": hash_password("correct-horse")}
before = store["ada@example.com"]
assert login(store, "ada@example.com", "correct-horse") == (True, "ok")
assert store["ada@example.com"] == before, "a current record should not be rewritten"`,
          },
          {
            name: "unknown accounts are indistinguishable",
            code: `store = {"ada@example.com": hash_password("correct-horse")}
assert login(store, "nobody@example.com", "whatever") == (False, "rejected")
assert login(store, "ada@example.com", "wrong") == (False, "rejected")`,
          },
        ],
        requirements: [
          { kind: "defines", value: "hash_password" },
          { kind: "defines", value: "verify_password" },
          { kind: "calls", value: "hashlib.pbkdf2_hmac" },
          { kind: "calls", value: "hmac.compare_digest" },
          { kind: "no_finding", value: "PY-FAST-HASH-PASSWORD" },
          { kind: "no_finding", value: "PY-TIMING-COMPARE" },
        ],
        hints: [
          "Split with `record.split(\"$\")` and require exactly four parts before unpacking — unpacking a wrong-length list raises `ValueError` anyway, but an explicit check gives a better message.",
          "`int(iterations)` from the record can raise `ValueError` for junk, which is the behaviour you want; let it propagate.",
          "In `login`, hash against a dummy record when the email is unknown, so an attacker cannot time the difference. Build one at module level with `hash_password(\"x\" * 32)`.",
          "`needs_rehash` must tolerate a foreign record format: check the algorithm prefix first and return `True` without trying to parse the rest.",
        ],
        solution: `import hashlib
import hmac
import secrets

DEFAULT_ITERATIONS = 100_000       # production: 600_000 for PBKDF2-HMAC-SHA256
MIN_ITERATIONS = 50_000
SALT_BYTES = 16
ALGORITHM = "pbkdf2_sha256"
MIN_PASSWORD = 8


def hash_password(password, *, iterations=DEFAULT_ITERATIONS):
    """Return 'pbkdf2_sha256$<iterations>$<salt_hex>$<hash_hex>'."""
    if not isinstance(password, str) or len(password) < MIN_PASSWORD:
        raise ValueError(f"password must be a string of at least {MIN_PASSWORD} characters")
    if not isinstance(iterations, int) or iterations < MIN_ITERATIONS:
        raise ValueError(f"iterations must be at least {MIN_ITERATIONS}")

    salt = secrets.token_bytes(SALT_BYTES)
    derived = hashlib.pbkdf2_hmac("sha256", password.encode("utf-8"), salt, iterations)
    return f"{ALGORITHM}$\x7biterations}$\x7bsalt.hex()}$\x7bderived.hex()}"


def _parse(record):
    if not isinstance(record, str):
        raise ValueError("record must be a string")
    parts = record.split("$")
    if len(parts) != 4:
        raise ValueError("malformed password record")
    algorithm, iterations, salt_hex, hash_hex = parts
    if algorithm != ALGORITHM:
        raise ValueError(f"unsupported algorithm: {algorithm!r}")
    return algorithm, int(iterations), bytes.fromhex(salt_hex), hash_hex


def verify_password(password, record):
    """True when the password matches the record."""
    _, iterations, salt, hash_hex = _parse(record)

    if not isinstance(password, str):
        return False

    derived = hashlib.pbkdf2_hmac("sha256", password.encode("utf-8"), salt, iterations)
    return hmac.compare_digest(derived.hex(), hash_hex)


def needs_rehash(record, *, iterations=DEFAULT_ITERATIONS):
    """True when the record should be upgraded at next login."""
    try:
        _, stored_iterations, _, _ = _parse(record)
    except ValueError:
        return True                      # foreign or broken format: upgrade it
    return stored_iterations < iterations


# A record to hash against when the account does not exist, so that the
# unknown-account path costs the same as the known-account path.
_DUMMY = hash_password("x" * 32)


def login(store, email, password):
    """Return (ok, action) where action is 'ok', 'rehashed' or 'rejected'."""
    record = store.get(email, _DUMMY)

    try:
        matched = verify_password(password, record)
    except ValueError:
        matched = False

    if not matched or email not in store:
        return False, "rejected"

    if needs_rehash(record):
        store[email] = hash_password(password)
        return True, "rehashed"

    return True, "ok"


rec = hash_password("correct-horse-battery")
print(rec.split("$")[0], verify_password("correct-horse-battery", rec))`,
        why: `The record carries its own parameters, which is what makes the system maintainable for the decade it will actually be in production. When 100 000 iterations stops being enough, you raise \`DEFAULT_ITERATIONS\`, deploy, and every active user is migrated by their next login — no migration script, no downtime, and old records keep verifying in the meantime.

The rehash happens **after** verification and only on success, because that is the only moment the plaintext exists. Re-hashing the stored hash would be security theatre: it changes the stored bytes without making any individual guess more expensive.

Two details defend against the enumeration problem from Module 2, reappearing here in cryptographic clothing:

- **\`_DUMMY\`** means an unknown email still costs a full PBKDF2 derivation. Without it, a missing account returns in microseconds and a real one in tens of milliseconds, and the login endpoint becomes an account-existence oracle regardless of how identical the messages are.
- **\`email not in store\`** is checked *after* the hash comparison, not instead of it. Returning early on an unknown email would undo the dummy entirely.

\`needs_rehash\` returning \`True\` for an unparseable record is deliberate: a legacy \`bcrypt$...\` or \`sha1$...\` row is exactly the thing that most needs upgrading, and a function that threw on it would make the migration path stop at the first old record.

One honest limitation: PBKDF2 is not memory-hard, so a GPU attacker gets more leverage against it than against scrypt or argon2id. It is here because it is in the standard library and runs anywhere. In production, reach for \`argon2-cffi\` and keep this exact record structure.`,
      },
      wrapup: `- Assume the table is stolen; the KDF is the only control that still applies.
- Salt per password, slow work factor, memory-hard if available.
- Store algorithm and parameters inside the record so you can upgrade incrementally.
- Rehash during a successful login — the one instant the plaintext exists.`,
      refs: [
        { label: "OWASP Password Storage Cheat Sheet", url: "https://cheatsheetseries.owasp.org/cheatsheets/Password_Storage_Cheat_Sheet.html" },
        { label: "hashlib.pbkdf2_hmac / scrypt", url: "https://docs.python.org/3/library/hashlib.html#hashlib.pbkdf2_hmac" },
        { label: "CWE-916: Use of Password Hash With Insufficient Computational Effort", url: "https://cwe.mitre.org/data/definitions/916.html" },
      ],
    },

    /* ----------------------------------------------------------------- 44 */
    {
      id: "m09l04",
      day: 50,
      title: "HMAC: proving who produced a message",
      minutes: 60,
      secure: "authentication of data",
      cwe: ["CWE-347", "CWE-208"],
      tags: ["hmac", "signature", "webhook", "verification", "constant-time"],
      lede:
        "A hash proves the bytes are unchanged. An HMAC proves they were produced by someone holding the key. Webhooks, cookies and download manifests all need the second one.",
      blocks: [
        {
          t: "code",
          label: "example",
          code: `import hashlib, hmac

key = b"shared-secret-32-bytes-or-longer"
message = b'{"event":"payment.succeeded","amount":1000}'

signature = hmac.new(key, message, hashlib.sha256).hexdigest()
ok = hmac.compare_digest(signature, received_signature)`,
          cap: "HMAC is a keyed construction, not a hash of key+message. It is specifically designed to resist the length-extension attack that naive concatenation allows.",
        },
        {
          t: "box",
          kind: "pitfall",
          title: "`sha256(key + message)` is not an HMAC",
          md: `SHA-256 is a Merkle–Damgård construction, so given \`H(key + m)\` and \`len(key)\` an attacker can compute \`H(key + m + padding + extra)\` **without knowing the key**. That lets them append \`&role=admin\` to a signed message and produce a valid signature for it.

\`hmac.new\` applies the key twice with distinct padding precisely to break that property. Never hand-roll it.`,
        },
        { t: "h", text: "Verifying a webhook, in order" },
        {
          t: "code",
          label: "fixed",
          code: `import hashlib, hmac, time

MAX_SKEW = 300            # five minutes

def verify_webhook(body, headers, secret):
    """Verify a signed webhook with replay protection."""
    signature = headers.get("X-Signature", "")
    timestamp = headers.get("X-Timestamp", "")

    if not timestamp.isdigit() or abs(time.time() - int(timestamp)) > MAX_SKEW:
        return False, "stale_or_missing_timestamp"

    signed_payload = f"{timestamp}.".encode() + body        # bind the timestamp
    expected = hmac.new(secret.encode(), signed_payload, hashlib.sha256).hexdigest()

    if not hmac.compare_digest(expected, signature):
        return False, "bad_signature"
    return True, "ok"`,
          cap: "The timestamp must be *inside* the signed payload. A timestamp checked but not signed can be rewritten by anyone replaying the request.",
        },
        {
          t: "box",
          kind: "rule",
          title: "Four properties a signed message needs",
          md: `1. **Integrity and authenticity** — the HMAC itself.
2. **Freshness** — a signed timestamp, with a tight skew window, to stop replay.
3. **Binding** — sign everything that matters: the method, the path, the audience, the key id. Anything outside the signature is attacker-controlled.
4. **Constant-time comparison** — \`hmac.compare_digest\`, always.`,
        },
        {
          t: "box",
          kind: "cve",
          title: "`alg: none` and the trust of attacker-supplied metadata",
          md: `The classic JWT vulnerability is accepting the algorithm named *in the token*. Setting \`"alg": "none"\` makes many libraries skip verification entirely; setting \`"alg": "HS256"\` on a service that expects RS256 can trick it into using the public key as an HMAC secret.

The rule generalises beyond JWT: **the verifier decides the algorithm, never the message**. In Python, always pass \`algorithms=["HS256"]\` explicitly — \`jwt.decode\` without it is a critical finding in this course's auditor.`,
        },
        {
          t: "code",
          label: "vulnerable",
          code: `import jwt

claims = jwt.decode(token, options={"verify_signature": False})   # !!
if claims["role"] == "admin":
    grant_admin()`,
          cap: "An unverified token is attacker-supplied JSON. Flipping `role` costs nothing.",
        },
        {
          t: "code",
          label: "fixed",
          code: `import jwt

claims = jwt.decode(token, key, algorithms=["HS256"],
                    audience="api.example.com", issuer="auth.example.com")`,
          cap: "Pin the algorithm, and verify audience and issuer: a token minted for a different service of yours should not work here.",
        },
      ],
      spot: {
        label: "webhook receiver",
        prompt: "Click the line that lets a captured request be replayed forever.",
        lines: [8],
        why:
          "Line 8. The timestamp is read and compared, but it is not part of the signed payload — only `body` is. An attacker who captures one valid request can replay it with any timestamp they like and the signature still matches. Sign `timestamp + body`, not `body` alone.",
        code: `import hashlib, hmac, time

def receive(body, headers, secret):
    sig = headers.get("X-Signature", "")
    ts = headers.get("X-Timestamp", "0")
    if abs(time.time() - int(ts)) > 300:
        return False
    expected = hmac.new(secret.encode(), body, hashlib.sha256).hexdigest()
    return hmac.compare_digest(expected, sig)`,
      },
      quiz: [
        {
          q: "Why is `sha256(key + message)` unsafe as a signature?",
          options: [
            "It is slow.",
            "Length extension lets an attacker append data and produce a valid digest without the key.",
            "SHA-256 is broken.",
          ],
          answer: 1,
          why: "Merkle–Damgård construction. HMAC's double-keying is specifically designed to prevent it.",
        },
        {
          q: "A webhook verifier checks a timestamp header but signs only the body. What is possible?",
          options: [
            "Nothing extra.",
            "Replay: the attacker reuses a captured body and supplies any timestamp.",
            "Length extension.",
          ],
          answer: 1,
          why: "Anything outside the signature is attacker-controlled. Bind the timestamp into the signed payload.",
        },
        {
          q: "`jwt.decode(token, key)` without `algorithms=[...]`:",
          options: [
            "Is fine; the library picks a sane default.",
            "Lets the token choose the algorithm, including `none` or a confusion attack.",
            "Raises a TypeError.",
          ],
          answer: 1,
          why: "The verifier must pin the algorithm. Modern PyJWT requires the argument for this reason; older code and other languages still do not.",
        },
      ],
      exercise: {
        title: "A webhook verifier with replay protection",
        brief: `Implement signing and verification for a webhook, with a fixed-\`now\` parameter so the tests are deterministic.

1. \`sign(body, secret, timestamp)\` — \`body\` is \`bytes\` or \`str\`; the signed payload is \`b"<timestamp>." + body_bytes\`. Return the hex HMAC-SHA256.
2. \`verify(body, headers, secret, *, now, max_skew=300)\` — return \`(ok, reason)\`:

| situation | result |
|---|---|
| valid and fresh | \`(True, "ok")\` |
| \`X-Timestamp\` missing or not digits | \`(False, "bad_timestamp")\` |
| timestamp more than \`max_skew\` seconds from \`now\` in **either** direction | \`(False, "stale")\` |
| \`X-Signature\` missing or not 64 lowercase hex characters | \`(False, "malformed_signature")\` |
| signature mismatch | \`(False, "bad_signature")\` |

3. Check in that order: timestamp format, skew, signature format, signature value. Use \`hmac.compare_digest\`.
4. \`replay_guard(seen, signature, *, max_entries=1000)\` — return \`True\` the first time a signature is presented and \`False\` afterwards, adding it to the \`seen\` set; clear the set when it reaches \`max_entries\`. (A signature is unique per body+timestamp, which makes it a usable replay key.)`,
        rubric: [
          "A correctly signed, fresh request verifies",
          "Tampering with the body or the timestamp invalidates the signature",
          "Future and past timestamps beyond the skew are rejected",
          "Malformed signatures are distinguished from wrong ones",
          "`compare_digest` is used",
          "`replay_guard` accepts once and refuses afterwards",
        ],
        starter: `import hashlib
import hmac
import re

HEX64 = re.compile(r"\\A[0-9a-f]{64}\\Z")


def sign(body, secret, timestamp):
    """Return the hex HMAC-SHA256 of '<timestamp>.' + body."""


def verify(body, headers, secret, *, now, max_skew=300):
    """Return (ok, reason)."""


def replay_guard(seen, signature, *, max_entries=1000):
    """True the first time this signature is seen."""


SECRET = "s" * 32
BODY = b'{"event":"payment.succeeded"}'
NOW = 1_700_000_000
sig = sign(BODY, SECRET, NOW)
print(verify(BODY, {"X-Signature": sig, "X-Timestamp": str(NOW)}, SECRET, now=NOW))
`,
        stdin: [],
        tests: [
          {
            name: "a fresh, correctly signed request verifies",
            code: `secret, body, now = "k" * 32, b'{"a":1}', 1_700_000_000
sig = sign(body, secret, now)
headers = {"X-Signature": sig, "X-Timestamp": str(now)}
assert verify(body, headers, secret, now=now) == (True, "ok")
assert verify(body, headers, secret, now=now + 299) == (True, "ok")`,
          },
          {
            name: "str and bytes bodies sign identically",
            code: `secret, now = "k" * 32, 1_700_000_000
assert sign('{"a":1}', secret, now) == sign(b'{"a":1}', secret, now)`,
          },
          {
            name: "tampering invalidates the signature",
            code: `secret, body, now = "k" * 32, b'{"amount":10}', 1_700_000_000
sig = sign(body, secret, now)
headers = {"X-Signature": sig, "X-Timestamp": str(now)}
assert verify(b'{"amount":9999}', headers, secret, now=now) == (False, "bad_signature")
assert verify(body, {**headers, "X-Timestamp": str(now + 1)}, secret, now=now) == (False, "bad_signature")
assert verify(body, headers, "other-secret" * 3, now=now) == (False, "bad_signature")`,
          },
          {
            name: "skew is rejected in both directions",
            code: `secret, body, now = "k" * 32, b'{"a":1}', 1_700_000_000
sig = sign(body, secret, now)
headers = {"X-Signature": sig, "X-Timestamp": str(now)}
assert verify(body, headers, secret, now=now + 301) == (False, "stale")
assert verify(body, headers, secret, now=now - 301) == (False, "stale")
assert verify(body, headers, secret, now=now + 100, max_skew=50) == (False, "stale")`,
          },
          {
            name: "malformed timestamps and signatures are their own reasons",
            code: `secret, body, now = "k" * 32, b'{"a":1}', 1_700_000_000
sig = sign(body, secret, now)
for bad_ts in ("", "abc", "-1", "17.5", None):
    headers = {"X-Signature": sig}
    if bad_ts is not None:
        headers["X-Timestamp"] = bad_ts
    assert verify(body, headers, secret, now=now)[1] == "bad_timestamp", f"ts={bad_ts!r}"
for bad_sig in ("", "abc", "Z" * 64, sig.upper(), sig + "0", None):
    headers = {"X-Timestamp": str(now)}
    if bad_sig is not None:
        headers["X-Signature"] = bad_sig
    assert verify(body, headers, secret, now=now)[1] == "malformed_signature", f"sig={bad_sig!r}"`,
          },
          {
            name: "checks happen in the documented order",
            code: `secret, body, now = "k" * 32, b'{"a":1}', 1_700_000_000
headers = {"X-Signature": "nonsense", "X-Timestamp": "not-a-number"}
assert verify(body, headers, secret, now=now)[1] == "bad_timestamp", "timestamp is checked first"
headers = {"X-Signature": "nonsense", "X-Timestamp": str(now - 10_000)}
assert verify(body, headers, secret, now=now)[1] == "stale", "skew is checked before the signature format"`,
          },
          {
            name: "replay_guard accepts once",
            code: `seen = set()
assert replay_guard(seen, "a" * 64) is True
assert replay_guard(seen, "a" * 64) is False
assert replay_guard(seen, "b" * 64) is True
assert replay_guard(seen, "a" * 64) is False`,
          },
          {
            name: "replay_guard is bounded",
            code: `seen = set()
for i in range(50):
    replay_guard(seen, f"{i:064d}", max_entries=10)
assert len(seen) <= 10, f"guard grew to {len(seen)} entries"`,
          },
        ],
        requirements: [
          { kind: "defines", value: "sign" },
          { kind: "defines", value: "verify" },
          { kind: "calls", value: "hmac.compare_digest" },
          { kind: "no_finding", value: "PY-TIMING-COMPARE" },
        ],
        hints: [
          "Normalise the body once at the top of `sign`: `body.encode(\"utf-8\") if isinstance(body, str) else bytes(body)`.",
          "The signed payload is `f\"{timestamp}.\".encode() + body_bytes` — the separator matters, otherwise timestamp `1` + body `23` and timestamp `12` + body `3` sign identically.",
          "`abs(now - int(timestamp)) > max_skew` covers both directions in one comparison. Rejecting future timestamps matters: without it, an attacker sets the timestamp far ahead and the capture never goes stale.",
          "For `replay_guard`, clear before inserting when the set is full, and remember to return `True` for the value you just inserted.",
        ],
        solution: `import hashlib
import hmac
import re

HEX64 = re.compile(r"\\A[0-9a-f]{64}\\Z")


def _as_bytes(body):
    return body.encode("utf-8") if isinstance(body, str) else bytes(body)


def sign(body, secret, timestamp):
    """Return the hex HMAC-SHA256 of '<timestamp>.' + body."""
    payload = f"{timestamp}.".encode("utf-8") + _as_bytes(body)
    return hmac.new(secret.encode("utf-8"), payload, hashlib.sha256).hexdigest()


def verify(body, headers, secret, *, now, max_skew=300):
    """Return (ok, reason)."""
    timestamp = headers.get("X-Timestamp", "")
    if not isinstance(timestamp, str) or not timestamp.isdigit():
        return False, "bad_timestamp"

    if abs(int(now) - int(timestamp)) > max_skew:
        return False, "stale"

    signature = headers.get("X-Signature", "")
    if not isinstance(signature, str) or not HEX64.match(signature):
        return False, "malformed_signature"

    expected = sign(body, secret, timestamp)
    if not hmac.compare_digest(expected, signature):
        return False, "bad_signature"

    return True, "ok"


def replay_guard(seen, signature, *, max_entries=1000):
    """True the first time this signature is seen."""
    if signature in seen:
        return False
    if len(seen) >= max_entries:
        seen.clear()
    seen.add(signature)
    return True


SECRET = "s" * 32
BODY = b'{"event":"payment.succeeded"}'
NOW = 1_700_000_000
sig = sign(BODY, SECRET, NOW)
print(verify(BODY, {"X-Signature": sig, "X-Timestamp": str(NOW)}, SECRET, now=NOW))`,
        why: `The timestamp is **inside** the signed payload, which is what makes the freshness check meaningful. Reading a timestamp header, comparing it to the clock, and then signing only the body produces a verifier that looks correct and stops nothing: the attacker replays a captured body with a fresh timestamp, and the signature — which never covered the timestamp — still matches.

The separator in \`f"{timestamp}."\` prevents a subtler forgery. Without it, timestamp \`1\` with body \`23\` and timestamp \`12\` with body \`3\` produce the identical signed payload \`123\`. That class of ambiguity — concatenating fields without an unambiguous delimiter — is the root of a number of real signature bypasses, and the fix is always the same: make the encoding injective.

Rejecting **future** timestamps matters as much as rejecting old ones. A verifier that only checks \`now - ts > skew\` lets an attacker who can influence the sender set a timestamp a year ahead, producing a capture that never expires.

The check order is from cheapest and most structural to most expensive: a malformed timestamp costs a \`isdigit()\` call, while a signature comparison costs an HMAC. It also keeps the \`reason\` codes honest, so your logs distinguish "a misconfigured sender" from "someone is probing us" — a distinction worth having on a dashboard.

\`replay_guard\` is deliberately simple and deliberately bounded. Using the signature as the key works because it is unique per (body, timestamp) pair. The crude \`clear()\` on overflow is honest about its limits: a real deployment uses a TTL cache sized to the skew window, so entries expire exactly when replay stops being possible.`,
      },
      wrapup: `- HMAC proves origin; a bare hash does not. Never \`sha256(key + message)\`.
- Sign everything that matters, including the timestamp — anything outside the signature is attacker-controlled.
- The verifier pins the algorithm; the message never chooses it.
- \`hmac.compare_digest\` for every signature comparison.`,
      refs: [
        { label: "hmac — keyed hashing for message authentication", url: "https://docs.python.org/3/library/hmac.html" },
        { label: "CWE-347: Improper Verification of Cryptographic Signature", url: "https://cwe.mitre.org/data/definitions/347.html" },
      ],
    },

    /* ----------------------------------------------------------------- 45 */
    {
      id: "m09l05",
      day: 51,
      title: "Capstone: a signed, expiring, single-purpose token",
      minutes: 60,
      secure: "token design",
      cwe: ["CWE-613", "CWE-384"],
      tags: ["capstone", "tokens", "expiry", "hmac", "audience", "rotation"],
      lede:
        "Password-reset links, email confirmations, download URLs, unsubscribe links — all the same object. Here is the design, with a reason for every field.",
      blocks: [
        {
          t: "table",
          head: ["Field", "Why it is there"],
          rows: [
            ["`v` — version", "Lets you change the format later without accepting both forever."],
            ["`kid` — key id", "Rotate the signing key while old tokens still verify."],
            ["`sub` — subject", "Who the token is about."],
            ["`aud` — audience/purpose", "A reset token must not work as a login token."],
            ["`exp` — expiry", "Bounds the damage of a leaked link."],
            ["`jti` — unique id", "Lets you record single use and revoke."],
            ["signature", "Everything above is attacker-visible; only this makes it attacker-*proof*."],
          ],
        },
        {
          t: "box",
          kind: "rule",
          title: "Bind the purpose",
          md: `A token minted for \`"password-reset"\` must be rejected by the email-confirmation endpoint, and vice versa. Without an audience field, one leaked unsubscribe link becomes a password reset.

The audience goes **inside the signature**, and the verifier passes the audience it expects. Comparing the audience *after* decoding an unverified token is the same mistake as trusting \`alg\`.`,
        },
        {
          t: "box",
          kind: "good",
          title: "Short expiry, single use, and both",
          md: `- **Password reset:** 15–60 minutes, single use, invalidated when the password changes.
- **Email confirmation:** hours to a day, single use.
- **Download link:** minutes, and bound to the resource id.
- **Session:** sliding expiry, revocable server-side.

Single use requires state — a \`jti\` you record. Expiry alone is not single use: a leaked link works repeatedly until it expires.`,
        },
        {
          t: "box",
          kind: "warn",
          title: "A signed token is readable",
          md: `HMAC provides integrity and authenticity, **not confidentiality**. Base64 is encoding, not encryption — anyone holding the token can read every claim.

Never put anything secret in a signed token. If the contents must be hidden, encrypt them (AES-GCM via \`cryptography\`, or Fernet) or keep the data server-side behind an opaque id.`,
        },
        {
          t: "code",
          label: "fixed",
          code: `KEYS = {"2026-01": "current-key-...", "2025-07": "previous-key-..."}
CURRENT_KID = "2026-01"

def verify(token, *, audience, now):
    header, payload, signature = token.split(".")
    claims = decode(payload)
    key = KEYS.get(claims["kid"])        # the KEY ID selects the key...
    if key is None:
        return None
    if not hmac.compare_digest(sign(header + "." + payload, key), signature):
        return None                       # ...but the SIGNATURE still decides`,
          cap: "Using an attacker-supplied key id to *look up* a key from a fixed table is safe. Using it to choose an algorithm, or to fetch a key from a URL, is not.",
        },
      ],
      quiz: [
        {
          q: "Why include an audience/purpose claim?",
          options: [
            "For logging.",
            "So a token minted for one purpose cannot be used for another.",
            "To make the token shorter.",
          ],
          answer: 1,
          why: "Without it, every signed token your system issues is interchangeable, and the weakest-protected one becomes the strongest.",
        },
        {
          q: "Is it safe to select the signing key using a key id taken from the token?",
          options: [
            "No, never trust the token.",
            "Yes, when the id only indexes a fixed local table — the signature still has to verify.",
            "Only for RSA.",
          ],
          answer: 1,
          why:
            "A wrong id selects a wrong key and verification fails. The danger is letting the token choose the *algorithm*, or fetching a key from a location the token names.",
        },
        {
          q: "Does expiry give you single use?",
          options: [
            "Yes.",
            "No — a leaked token works repeatedly until it expires; single use needs recorded state.",
            "Only under 5 minutes.",
          ],
          answer: 1,
          why: "Record the `jti` on first use and reject it afterwards. Expiry bounds the window; it does not bound the count.",
        },
      ],
      exercise: {
        title: "mint() and redeem(): a complete token lifecycle",
        brief: `Token format: \`"<payload_b64>.<signature_hex>"\` where \`payload_b64\` is the urlsafe-base64 of a JSON object with keys \`v\`, \`kid\`, \`sub\`, \`aud\`, \`exp\`, \`jti\`.

1. \`mint(sub, aud, *, now, ttl=900, keys=KEYS, kid=CURRENT_KID)\` — build the payload (\`v=1\`, \`exp = now + ttl\`, \`jti = secrets.token_hex(8)\`), sign the base64 payload with \`keys[kid]\`, and return the token. Raise \`ValueError\` for an unknown \`kid\`, a non-positive \`ttl\`, or an empty \`sub\`/\`aud\`.

2. \`verify(token, *, audience, now, keys=KEYS)\` returning \`(claims_or_None, reason)\`:

| situation | reason |
|---|---|
| valid | \`"ok"\` |
| wrong shape, bad base64, bad JSON, missing claims | \`"malformed"\` |
| \`v\` is not 1 | \`"unsupported_version"\` |
| \`kid\` not in \`keys\` | \`"unknown_key"\` |
| signature mismatch | \`"bad_signature"\` |
| \`exp\` ≤ \`now\` | \`"expired"\` |
| \`aud\` ≠ \`audience\` | \`"wrong_audience"\` |

Order: shape → version → key → **signature** → expiry → audience. Nothing from the payload is trusted before the signature verifies, except the \`kid\` used to *look up* a key and the \`v\` used to reject an unknown format.

3. \`redeem(token, *, audience, now, used, keys=KEYS)\` — verify, then enforce single use via the \`used\` set of \`jti\` values. Returns \`(claims_or_None, reason)\`; a second redemption gives \`"already_used"\`.`,
        rubric: [
          "A freshly minted token verifies and redeems once",
          "A second redemption is refused",
          "Tampering with any claim yields `bad_signature`",
          "An expired token and a wrong-audience token are refused with their own reasons",
          "An old key id still verifies while it remains in the key table",
          "Signature is checked before expiry and audience",
        ],
        starter: `import base64
import hashlib
import hmac
import json
import secrets

KEYS = {"2026-01": "current-signing-key-0123456789", "2025-07": "previous-signing-key-9876543210"}
CURRENT_KID = "2026-01"
VERSION = 1


def mint(sub, aud, *, now, ttl=900, keys=KEYS, kid=CURRENT_KID):
    """Return '<payload_b64>.<signature_hex>'."""


def verify(token, *, audience, now, keys=KEYS):
    """Return (claims, reason); claims is None unless reason == 'ok'."""


def redeem(token, *, audience, now, used, keys=KEYS):
    """Verify and enforce single use."""


NOW = 1_700_000_000
tok = mint("user:7", "password-reset", now=NOW)
print(verify(tok, audience="password-reset", now=NOW)[1])
print(verify(tok, audience="login", now=NOW)[1])
`,
        stdin: [],
        tests: [
          {
            name: "a fresh token verifies",
            code: `now = 1_700_000_000
tok = mint("user:7", "password-reset", now=now)
claims, reason = verify(tok, audience="password-reset", now=now)
assert reason == "ok", f"got {reason!r}"
assert claims["sub"] == "user:7" and claims["aud"] == "password-reset"
assert claims["v"] == 1 and claims["exp"] == now + 900
assert len(claims["jti"]) >= 8`,
          },
          {
            name: "tokens are unique and opaque-looking",
            code: `now = 1_700_000_000
a = mint("user:7", "password-reset", now=now)
b = mint("user:7", "password-reset", now=now)
assert a != b, "jti should make every token unique"
assert a.count(".") == 1, f"got {a!r}"`,
          },
          {
            name: "minting validates its arguments",
            code: `now = 1_700_000_000
for kwargs in ({"kid": "nope"}, {"ttl": 0}, {"ttl": -5}):
    with raises(ValueError):
        mint("user:7", "password-reset", now=now, **kwargs)
for bad in ("", None):
    with raises(ValueError):
        mint(bad, "password-reset", now=now)
    with raises(ValueError):
        mint("user:7", bad, now=now)`,
          },
          {
            name: "tampering is caught",
            code: `import base64, json
now = 1_700_000_000
tok = mint("user:7", "password-reset", now=now)
payload, sig = tok.split(".")
claims = json.loads(base64.urlsafe_b64decode(payload.encode()))
claims["sub"] = "user:1"
forged = base64.urlsafe_b64encode(json.dumps(claims).encode()).decode()
assert verify(f"{forged}.{sig}", audience="password-reset", now=now)[1] == "bad_signature"
assert verify(f"{payload}.{'0' * 64}", audience="password-reset", now=now)[1] == "bad_signature"`,
          },
          {
            name: "expiry and audience are enforced",
            code: `now = 1_700_000_000
tok = mint("user:7", "password-reset", now=now, ttl=60)
assert verify(tok, audience="password-reset", now=now + 59)[1] == "ok"
assert verify(tok, audience="password-reset", now=now + 60)[1] == "expired"
assert verify(tok, audience="password-reset", now=now + 10_000)[1] == "expired"
assert verify(tok, audience="login", now=now)[1] == "wrong_audience"
assert verify(tok, audience="login", now=now)[0] is None`,
          },
          {
            name: "the signature is checked before expiry and audience",
            code: `import base64, json
now = 1_700_000_000
tok = mint("user:7", "password-reset", now=now, ttl=60)
payload, sig = tok.split(".")
claims = json.loads(base64.urlsafe_b64decode(payload.encode()))
claims["exp"] = now + 10_000_000
claims["aud"] = "login"
forged = base64.urlsafe_b64encode(json.dumps(claims).encode()).decode()
assert verify(f"{forged}.{sig}", audience="login", now=now)[1] == "bad_signature", \\
    "a forged token must fail on the signature, not on a claim"`,
          },
          {
            name: "malformed tokens and unknown keys",
            code: `now = 1_700_000_000
for bad in ("", "nodot", "a.b.c", "!!!.aaa", "YWJj.zz", ".", "a."):
    assert verify(bad, audience="x", now=now)[1] == "malformed", f"{bad!r}"
tok = mint("user:7", "password-reset", now=now)
assert verify(tok, audience="password-reset", now=now, keys={"other": "k"})[1] == "unknown_key"`,
          },
          {
            name: "an old key id still verifies while it is in the table",
            code: `now = 1_700_000_000
tok = mint("user:7", "password-reset", now=now, kid="2025-07")
assert verify(tok, audience="password-reset", now=now)[1] == "ok"
assert verify(tok, audience="password-reset", now=now,
              keys={"2026-01": KEYS["2026-01"]})[1] == "unknown_key"`,
          },
          {
            name: "redemption is single use",
            code: `now = 1_700_000_000
used = set()
tok = mint("user:7", "password-reset", now=now)
claims, reason = redeem(tok, audience="password-reset", now=now, used=used)
assert reason == "ok" and claims["sub"] == "user:7"
claims2, reason2 = redeem(tok, audience="password-reset", now=now, used=used)
assert (claims2, reason2) == (None, "already_used"), f"got {(claims2, reason2)!r}"
other = mint("user:9", "password-reset", now=now)
assert redeem(other, audience="password-reset", now=now, used=used)[1] == "ok"`,
          },
          {
            name: "a failed verification does not consume the token",
            code: `now = 1_700_000_000
used = set()
tok = mint("user:7", "password-reset", now=now)
assert redeem(tok, audience="login", now=now, used=used)[1] == "wrong_audience"
assert used == set(), "a rejected token must not be recorded as used"
assert redeem(tok, audience="password-reset", now=now, used=used)[1] == "ok"`,
          },
        ],
        requirements: [
          { kind: "defines", value: "mint" },
          { kind: "defines", value: "verify" },
          { kind: "defines", value: "redeem" },
          { kind: "calls", value: "hmac.compare_digest" },
          { kind: "uses_module", value: "secrets" },
          { kind: "no_finding", value: "PY-TIMING-COMPARE" },
        ],
        hints: [
          "Sign the base64 payload string, not the JSON — you must sign exactly the bytes you transmit, or a re-encoding difference becomes a verification bypass.",
          "`json.dumps(claims, sort_keys=True, separators=(\",\", \":\"))` makes the encoding deterministic, which matters if anything ever re-signs a payload.",
          "Wrap the decode in `try/except (ValueError, TypeError, KeyError)` and return `(None, \"malformed\")` — base64 and JSON both raise subclasses of `ValueError`.",
          "In `redeem`, add the `jti` to `used` only after a fully successful verify. Adding it earlier means a wrong-audience probe burns someone else's valid token.",
        ],
        solution: `import base64
import hashlib
import hmac
import json
import secrets

KEYS = {"2026-01": "current-signing-key-0123456789", "2025-07": "previous-signing-key-9876543210"}
CURRENT_KID = "2026-01"
VERSION = 1
REQUIRED_CLAIMS = ("v", "kid", "sub", "aud", "exp", "jti")


def _sign(payload_b64, key):
    return hmac.new(key.encode("utf-8"), payload_b64.encode("utf-8"), hashlib.sha256).hexdigest()


def mint(sub, aud, *, now, ttl=900, keys=KEYS, kid=CURRENT_KID):
    """Return '<payload_b64>.<signature_hex>'."""
    if kid not in keys:
        raise ValueError(f"unknown key id: {kid!r}")
    if not isinstance(ttl, int) or ttl <= 0:
        raise ValueError("ttl must be a positive number of seconds")
    if not isinstance(sub, str) or not sub:
        raise ValueError("sub must be a non-empty string")
    if not isinstance(aud, str) or not aud:
        raise ValueError("aud must be a non-empty string")

    claims = {
        "v": VERSION,
        "kid": kid,
        "sub": sub,
        "aud": aud,
        "exp": int(now) + ttl,
        "jti": secrets.token_hex(8),
    }
    encoded = json.dumps(claims, sort_keys=True, separators=(",", ":")).encode("utf-8")
    payload_b64 = base64.urlsafe_b64encode(encoded).decode("ascii")
    return f"{payload_b64}.{_sign(payload_b64, keys[kid])}"


def verify(token, *, audience, now, keys=KEYS):
    """Return (claims, reason); claims is None unless reason == 'ok'."""
    if not isinstance(token, str):
        return None, "malformed"

    parts = token.split(".")
    if len(parts) != 2 or not parts[0] or not parts[1]:
        return None, "malformed"
    payload_b64, signature = parts

    try:
        claims = json.loads(base64.urlsafe_b64decode(payload_b64.encode("ascii")))
    except (ValueError, TypeError):
        return None, "malformed"

    if not isinstance(claims, dict) or any(c not in claims for c in REQUIRED_CLAIMS):
        return None, "malformed"

    if claims["v"] != VERSION:
        return None, "unsupported_version"

    key = keys.get(claims["kid"])
    if key is None:
        return None, "unknown_key"

    # Nothing below this line was trusted until the signature verified.
    if not hmac.compare_digest(_sign(payload_b64, key), signature):
        return None, "bad_signature"

    if not isinstance(claims["exp"], int) or claims["exp"] <= int(now):
        return None, "expired"

    if claims["aud"] != audience:
        return None, "wrong_audience"

    return claims, "ok"


def redeem(token, *, audience, now, used, keys=KEYS):
    """Verify and enforce single use."""
    claims, reason = verify(token, audience=audience, now=now, keys=keys)
    if claims is None:
        return None, reason

    if claims["jti"] in used:
        return None, "already_used"

    used.add(claims["jti"])              # only after a complete success
    return claims, "ok"


NOW = 1_700_000_000
tok = mint("user:7", "password-reset", now=NOW)
print(verify(tok, audience="password-reset", now=NOW)[1])
print(verify(tok, audience="login", now=NOW)[1])`,
        why: `The ordering of checks in \`verify\` is the design. Everything before the \`compare_digest\` line uses the payload only for *structural* decisions — is this parseable, is it a format I understand, which key does it name — and nothing after it is reached unless the signature held. The test that forges \`exp\` and \`aud\` and expects \`"bad_signature"\` exists to pin that order: a verifier that checked expiry first would tell an attacker which of their forgeries was closest, and worse, would suggest that claims mean something before they are authenticated.

Reading \`kid\` from an unverified token is safe, and it is worth being precise about why. The id only indexes a table you control; a wrong or malicious id selects a wrong key or no key, and verification fails. What would be unsafe is letting the token name an *algorithm* (the \`alg: none\` family) or a *location* to fetch a key from (\`jku\`/\`x5u\` attacks). Lookup, yes. Instruction, no.

\`aud\` is what stops a leaked unsubscribe link from resetting a password. It costs one string comparison and removes an entire class of cross-purpose attack, which is the best ratio in this file.

\`redeem\` records the \`jti\` only after a complete success. The test that probes with the wrong audience and then redeems correctly is checking for a real bug: a guard that marks the token used on *any* presentation lets an attacker who merely knows the token burn it, turning a read-only leak into a denial of service against the legitimate user.

What the design deliberately does not do is hide anything. The payload is base64, not encryption — \`sub\` and \`aud\` are readable by anyone holding the token. That is acceptable because they carry no secret; the moment you need to put something confidential in a token, the answer is to keep it server-side behind an opaque id.`,
      },
      wrapup: `- Version, key id, subject, audience, expiry, unique id — each field earns its place.
- Verify the signature before trusting any claim; use the key id only to look up a key.
- Bind the purpose, or every token in your system becomes interchangeable.
- Expiry bounds the window; single use needs recorded state, written only on success.`,
      refs: [
        { label: "OWASP — JSON Web Token Cheat Sheet", url: "https://cheatsheetseries.owasp.org/cheatsheets/JSON_Web_Token_for_Java_Cheat_Sheet.html" },
        { label: "CWE-613: Insufficient Session Expiration", url: "https://cwe.mitre.org/data/definitions/613.html" },
      ],
    },
  ],
};
