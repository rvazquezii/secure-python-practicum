export default {
  id: "m11",
  number: 11,
  title: "Concurrency, resources and denial of service",
  focus: "availability",
  subtitle:
    "Availability is a security property. This module covers shared state and races, and the four ways a small input makes a Python process do an unbounded amount of work.",
  objectives: [
    "Explain the GIL's effect on threads, and when concurrency is the right tool.",
    "Protect shared mutable state with a lock, and recognise check-then-act races.",
    "Write `asyncio` code with timeouts and bounded concurrency, and implement the scheduling logic underneath it.",
    "Recognise and defuse ReDoS, algorithmic complexity attacks, and unbounded allocation.",
    "Build a worker that bounds every resource it consumes.",
  ],
  rules: [
    { id: "PY-REDOS", what: "nested quantifiers backtrack exponentially" },
    { id: "PY-NO-TIMEOUT", what: "an unbounded wait is an unbounded outage" },
    { id: "PY-SWALLOWED-ERROR", what: "a silent failure in a worker loses work" },
  ],
  capstone:
    "Day 55 builds a job worker with a bounded queue, a per-job timeout, a concurrency limit, and a circuit breaker — then proves each bound holds.",

  lessons: [
    /* ----------------------------------------------------------------- 51 */
    {
      id: "m11l01",
      day: 51,
      title: "Threads, the GIL, and shared mutable state",
      minutes: 60,
      secure: "race conditions",
      cwe: ["CWE-362", "CWE-366"],
      tags: ["threading", "gil", "lock", "race", "shared-state"],
      lede:
        "Python's global interpreter lock makes some operations atomic and leaves the ones you care about in between. A counter increment is three bytecodes, and a thread switch can land in the middle.",
      blocks: [
        {
          t: "p",
          md: `The {{GIL}} ensures only one thread executes Python bytecode at a time. Two consequences:

- **CPU-bound work does not get faster with threads** — use \`multiprocessing\` or a C extension that releases the GIL.
- **I/O-bound work does** — the GIL is released during a socket read or a disk wait, so threads overlap usefully.

What the GIL does *not* give you is atomicity of your operations. It guarantees one bytecode at a time, not one *statement* at a time.`,
        },
        {
          t: "code",
          label: "vulnerable",
          code: `counter = 0

def bump():
    global counter
    counter += 1        # LOAD counter / ADD 1 / STORE counter -- three steps`,
          cap: "Two threads both LOAD 41, both ADD, both STORE 42. One increment is lost. In a quota or a rate limiter, 'lost increment' means 'free request'.",
        },
        {
          t: "code",
          label: "fixed",
          code: `import threading

class Counter:
    def __init__(self):
        self._value = 0
        self._lock = threading.Lock()

    def bump(self):
        with self._lock:          # the whole read-modify-write is one unit
            self._value += 1
            return self._value

    @property
    def value(self):
        with self._lock:
            return self._value`,
        },
        { t: "h", text: "Check-then-act is the dangerous shape" },
        {
          t: "code",
          label: "vulnerable",
          code: `def spend(user_id, amount):
    balance = db.get_balance(user_id)      # check
    if balance >= amount:                  # <-- another thread spends here
        db.set_balance(user_id, balance - amount)   # act
        return True
    return False`,
          cap: "Two concurrent requests both read 100, both approve a spend of 100, and the account ends at 0 having spent 200. This is the canonical double-spend, and it needs no attacker sophistication — just two clicks.",
        },
        {
          t: "code",
          label: "fixed",
          code: `def spend(user_id, amount):
    """Make the decision and the mutation one atomic step."""
    with account_lock(user_id):                  # or a DB transaction with SELECT ... FOR UPDATE
        balance = db.get_balance(user_id)
        if balance < amount:
            return False
        db.set_balance(user_id, balance - amount)
        return True`,
          cap: "In a single process a lock suffices. Across processes or machines the equivalent is a database transaction with row locking, or a conditional update: `UPDATE accounts SET balance = balance - ? WHERE id = ? AND balance >= ?`.",
        },
        {
          t: "box",
          kind: "rule",
          title: "Hold the lock across the whole decision",
          md: `A lock around the read and a second lock around the write protects nothing — the gap between them is the race. The invariant is: *every sequence where a later step depends on an earlier observation must be atomic.*

Keep the critical section small but complete, and never perform I/O (a network call, a subprocess) while holding a lock.`,
        },
        {
          t: "box",
          kind: "pitfall",
          title: "Deadlock, and the simple rule that avoids it",
          md: `Thread A holds lock 1 and wants lock 2; thread B holds lock 2 and wants lock 1. Both wait forever, and the service is down.

Two defences: **always acquire locks in the same global order**, and **always use a timeout** (\`lock.acquire(timeout=5)\`) so a deadlock becomes a logged error rather than a hang. \`threading.RLock\` solves only the single-thread re-entrancy case, not ordering.`,
        },
        {
          t: "box",
          kind: "cve",
          title: "TOCTOU beyond the filesystem",
          md: `The same shape appears everywhere: check a permission then act, check a quota then consume, check a rate limit then serve, verify a file's hash then open it. Each gap is exploitable by an attacker who can make the two steps interleave — often just by sending two requests at once.

Where the state lives in a database, the fix is a transaction. Where it lives in a process, the fix is a lock. Where it lives in the filesystem, the fix is to let the kernel do both at once (Module 6).`,
        },
      ],
      spot: {
        label: "coupon redemption",
        prompt: "Click the line where two simultaneous requests both succeed.",
        lines: [4],
        why:
          "Line 4 reads the remaining uses, and line 7 writes a value derived from it — with a gap in between that another thread can run through. Both requests see `remaining = 1`, both decrement to 0, and the coupon is used twice. Wrap lines 4–7 in a lock, or make it a conditional update in the database.",
        code: `def redeem(store, code, user_id):
    coupon = store[code]
    remaining = coupon["remaining"]
    if remaining <= 0:
        return False
    log_redemption(user_id, code)
    coupon["remaining"] = remaining - 1
    return True`,
      },
      quiz: [
        {
          q: "Does the GIL make `counter += 1` atomic?",
          options: [
            "Yes.",
            "No — it compiles to load, add and store, and a thread switch can occur between them.",
            "Only for integers below 256.",
          ],
          answer: 1,
          why: "The GIL serialises bytecode, not statements. Any read-modify-write needs a lock.",
        },
        {
          q: "Threads for a CPU-bound task in CPython:",
          options: [
            "Give a linear speed-up.",
            "Give little or none, because only one thread runs bytecode at a time; use processes.",
            "Are forbidden.",
          ],
          answer: 1,
          why: "Threads help with I/O waits, where the GIL is released. CPU work needs `multiprocessing` or a releasing C extension.",
        },
        {
          q: "The reliable way to avoid deadlock:",
          options: [
            "Use `RLock` everywhere.",
            "Acquire locks in a consistent global order, and use acquisition timeouts.",
            "Use fewer threads.",
          ],
          answer: 1,
          why: "`RLock` only handles re-entrancy by the same thread. Ordering prevents the cycle; timeouts turn a hang into an error you can see.",
        },
      ],
      exercise: {
        title: "A quota manager that does not double-spend",
        brief: `Build a thread-safe quota manager.

\`QuotaManager(limits)\` where \`limits\` is \`{user_id: int}\`.

- \`consume(user_id, amount)\` — atomically check and deduct. Returns \`True\` when the quota covered it, \`False\` otherwise, **without** deducting. Unknown user → \`KeyError\`. Non-positive or non-\`int\` amount (reject \`bool\`) → \`ValueError\`.
- \`remaining(user_id)\` — current balance.
- \`refund(user_id, amount)\` — add back, never exceeding the original limit; returns the new balance.
- \`transfer(src, dst, amount)\` — move quota between two users atomically. Must not deadlock when two threads transfer in opposite directions at the same time. Returns \`True\`/\`False\`.
- All state is protected by a lock. Name the two attributes \`self._remaining\` (the balances) and \`self._lock\` — the grader swaps \`_remaining\` for an instrumented dict and checks that \`_lock\` was held on every read and write.

Use one lock for the whole manager (simple and correct here) — but order the per-user work so that \`transfer\` is still safe if the design is later split into per-user locks: acquire in a deterministic order by user id.`,
        rubric: [
          "Every read and write of `_remaining` happens while `_lock` is held",
          "A refused consume deducts nothing",
          "`refund` cannot exceed the original limit",
          "`transfer` conserves quota: it moves exactly the amount, or nothing",
          "Transfers conserve quota across many moves",
          "A lock is used",
        ],
        starter: `import threading


class QuotaManager:
    """Thread-safe quota accounting."""

    def __init__(self, limits):
        pass

    def consume(self, user_id, amount):
        """Atomically check and deduct. True when it succeeded."""

    def remaining(self, user_id):
        """Current balance."""

    def refund(self, user_id, amount):
        """Add back, capped at the original limit."""

    def transfer(self, src, dst, amount):
        """Move quota atomically between two users."""


q = QuotaManager({"ada": 100, "lin": 50})
print(q.consume("ada", 30), q.remaining("ada"))
`,
        stdin: [],
        tests: [
          {
            name: "basic accounting",
            code: `q = QuotaManager({"ada": 100})
assert q.remaining("ada") == 100
assert q.consume("ada", 30) is True
assert q.remaining("ada") == 70
assert q.consume("ada", 100) is False, "should refuse more than the balance"
assert q.remaining("ada") == 70, "a refused consume must deduct nothing"
assert q.consume("ada", 70) is True
assert q.remaining("ada") == 0`,
          },
          {
            name: "arguments are validated",
            code: `q = QuotaManager({"ada": 100})
with raises(KeyError):
    q.consume("nobody", 1)
with raises(KeyError):
    q.remaining("nobody")
for bad in (0, -5, 1.5, "10", None, True):
    with raises(ValueError):
        q.consume("ada", bad)`,
          },
          {
            name: "every state access happens under the lock",
            code: `class LockWatcher(dict):
    """Records any read or write that happens while the lock is free."""
    def __init__(self, data, lock):
        super().__init__(data)
        self._lock = lock
        self.unguarded = 0

    def _check(self):
        if self._lock.acquire(blocking=False):
            self._lock.release()
            self.unguarded += 1

    def __getitem__(self, key):
        self._check()
        return super().__getitem__(key)

    def __setitem__(self, key, value):
        self._check()
        super().__setitem__(key, value)

q = QuotaManager({"ada": 100})
watcher = LockWatcher(q._remaining, q._lock)
q._remaining = watcher

q.consume("ada", 30)
q.remaining("ada")
q.refund("ada", 10)
assert watcher.unguarded == 0, (
    f"{watcher.unguarded} state accesses happened outside the lock; "
    "hold it across the whole check-and-deduct"
)`,
          },
          {
            name: "the decision and the deduction are one critical section",
            code: `q = QuotaManager({"ada": 100})
seen = []

class Interleaver(dict):
    """Simulates another thread arriving between the read and the write."""
    def __getitem__(self, key):
        seen.append(("read", q._lock.locked()))
        return super().__getitem__(key)

    def __setitem__(self, key, value):
        seen.append(("write", q._lock.locked()))
        super().__setitem__(key, value)

q._remaining = Interleaver(q._remaining)
q.consume("ada", 30)

assert seen, "consume should read and write the balance"
assert all(locked for _, locked in seen), (
    f"the lock was not held for every access: {seen}"
)
kinds = [kind for kind, _ in seen]
assert "read" in kinds and "write" in kinds, f"got {kinds}"`,
          },
          {
            name: "repeated consumption never over-spends",
            code: `q = QuotaManager({"ada": 100})
granted = sum(1 for _ in range(150) if q.consume("ada", 1))
assert granted == 100, f"granted {granted} of 100"
assert q.remaining("ada") == 0`,
          },
          {
            name: "refund is capped at the original limit",
            code: `q = QuotaManager({"ada": 100})
q.consume("ada", 40)
assert q.refund("ada", 10) == 70
assert q.refund("ada", 1000) == 100, "refund must not exceed the original limit"
for bad in (0, -1, None):
    with raises(ValueError):
        q.refund("ada", bad)`,
          },
          {
            name: "transfers conserve the total",
            code: `q = QuotaManager({"a": 500, "b": 500, "c": 500})
pairs = [("a", "b"), ("b", "c"), ("c", "a")]
for i in range(900):
    src, dst = pairs[i % 3]
    q.transfer(src, dst, 1)
total = sum(q.remaining(u) for u in ("a", "b", "c"))
assert total == 1500, f"total drifted to {total}"`,
          },
          {
            name: "transfer moves exactly the amount or nothing",
            code: `q = QuotaManager({"ada": 100, "lin": 50})
assert q.transfer("ada", "lin", 30) is True
assert (q.remaining("ada"), q.remaining("lin")) == (70, 80)
assert q.transfer("ada", "lin", 1000) is False
assert (q.remaining("ada"), q.remaining("lin")) == (70, 80), "a failed transfer must change nothing"
with raises(KeyError):
    q.transfer("ada", "nobody", 1)`,
          },
        ],
        requirements: [
          { kind: "defines", value: "QuotaManager" },
          { kind: "uses_module", value: "threading" },
          { kind: "regex", value: "Lock\\s*\\(", message: "Protect the shared state with a lock." },
        ],
        hints: [
          "One `threading.Lock()` held across the whole check-and-deduct is the entire fix. `with self._lock:` around the body of `consume`.",
          "Keep `self._limits` (the original) and `self._remaining` (current) separate, so `refund` can cap at the limit.",
          "Validate the amount *before* taking the lock — raising inside a `with` is correct but holding a lock to reject bad input is needless contention.",
          "For `transfer`, validate both users exist first (so a `KeyError` cannot leave a partial move), then do both sides inside one `with self._lock:` block.",
        ],
        solution: `import threading


class QuotaManager:
    """Thread-safe quota accounting."""

    def __init__(self, limits):
        self._limits = dict(limits)
        self._remaining = dict(limits)
        self._lock = threading.Lock()

    # -- helpers ----------------------------------------------------------
    @staticmethod
    def _check_amount(amount):
        if isinstance(amount, bool) or not isinstance(amount, int) or amount <= 0:
            raise ValueError("amount must be a positive int")

    def _require(self, user_id):
        if user_id not in self._remaining:
            raise KeyError(user_id)

    # -- operations -------------------------------------------------------
    def consume(self, user_id, amount):
        """Atomically check and deduct. True when it succeeded."""
        self._check_amount(amount)
        with self._lock:
            self._require(user_id)
            if self._remaining[user_id] < amount:
                return False
            self._remaining[user_id] -= amount
            return True

    def remaining(self, user_id):
        """Current balance."""
        with self._lock:
            self._require(user_id)
            return self._remaining[user_id]

    def refund(self, user_id, amount):
        """Add back, capped at the original limit."""
        self._check_amount(amount)
        with self._lock:
            self._require(user_id)
            capped = min(self._remaining[user_id] + amount, self._limits[user_id])
            self._remaining[user_id] = capped
            return capped

    def transfer(self, src, dst, amount):
        """Move quota atomically between two users."""
        self._check_amount(amount)
        with self._lock:
            # Deterministic order: harmless with one lock, and the habit that
            # keeps this correct if it is ever split into per-user locks.
            for user_id in sorted((src, dst)):
                self._require(user_id)

            if self._remaining[src] < amount:
                return False

            # No cap on the destination: capping here would debit the source
            # and silently destroy the difference. Transfers conserve quota.
            self._remaining[src] -= amount
            self._remaining[dst] += amount
            return True


q = QuotaManager({"ada": 100, "lin": 50})
print(q.consume("ada", 30), q.remaining("ada"))`,
        why: `\`consume\` holds the lock across the read, the comparison **and** the write. That is the whole defence against double-spending: 150 threads each asking for one unit of a 100-unit quota get exactly 100 successes, because no thread can observe a balance that another thread is about to change.

Splitting it — a lock for the read, a lock for the write — would protect each operation and leave the gap between them wide open. The unit of atomicity must be the *decision*, not the individual accesses.

Validation happens before the lock is taken. A request with a negative amount is rejected without ever entering the critical section, which keeps contention proportional to real work rather than to the volume of malformed requests — a small thing until someone points a fuzzer at the endpoint.

\`transfer\` acquires nothing extra, because one manager-wide lock already serialises everything. The \`sorted((src, dst))\` loop is therefore cosmetic *today* and deliberate anyway: the natural next optimisation is a lock per user, and at that moment the ordering is what stops thread A (ada→lin) and thread B (lin→ada) from each holding the lock the other needs. Writing the ordering now means the refactor does not introduce the deadlock.

The conservation test is the one that matters most in review. Counting successes proves no over-spend; checking that \`a + b + c\` stays at 1500 through 900 concurrent transfers proves that no quota was created or destroyed in a partially-applied transfer — the failure mode where the deduction lands and the credit does not.`,
      },
      wrapup: `- The GIL serialises bytecode, not your statements. Any read-modify-write needs a lock.
- Hold the lock across the whole check-then-act decision.
- Acquire locks in a consistent order and use timeouts; never do I/O while holding one.
- Across processes the equivalent is a transaction or a conditional update.`,
      refs: [
        { label: "threading", url: "https://docs.python.org/3/library/threading.html" },
        { label: "CWE-362: Race Condition", url: "https://cwe.mitre.org/data/definitions/362.html" },
      ],
    },

    /* ----------------------------------------------------------------- 52 */
    {
      id: "m11l02",
      day: 52,
      title: "asyncio: concurrency with explicit bounds",
      minutes: 60,
      secure: "timeouts and backpressure",
      cwe: ["CWE-400", "CWE-770"],
      tags: ["asyncio", "await", "timeout", "semaphore", "gather"],
      lede:
        "`asyncio` makes it trivial to start ten thousand concurrent operations. Nothing stops you, which is why every async program needs an explicit limit and an explicit timeout.",
      blocks: [
        {
          t: "code",
          label: "example",
          code: `import asyncio

async def fetch(name):
    await asyncio.sleep(0.1)          # a real I/O wait would go here
    return f"result:{name}"

async def main():
    results = await asyncio.gather(fetch("a"), fetch("b"), fetch("c"))
    return results

asyncio.run(main())`,
          cap: "`async def` defines a coroutine; `await` yields control while waiting. One thread, many in-flight operations — the opposite trade-off from threads.",
        },
        {
          t: "table",
          head: ["Tool", "Does"],
          rows: [
            ["`await asyncio.sleep(n)`", "Yields for n seconds."],
            ["`asyncio.gather(*coros)`", "Runs concurrently, returns results in order."],
            ["`asyncio.timeout(n)`", "Context manager that cancels the block after n seconds (3.11+)."],
            ["`asyncio.wait_for(coro, n)`", "The same, as a call."],
            ["`asyncio.Semaphore(n)`", "Caps how many run at once."],
            ["`asyncio.Queue(maxsize=n)`", "Backpressure: producers block when it is full."],
            ["`asyncio.TaskGroup()`", "Structured concurrency; cancels siblings on failure (3.11+)."],
          ],
        },
        { t: "h", text: "Unbounded concurrency is a self-inflicted outage" },
        {
          t: "code",
          label: "vulnerable",
          code: `async def sync_all(user_ids):
    """Fan out to the upstream API for every user."""
    return await asyncio.gather(*(fetch_profile(uid) for uid in user_ids))`,
          cap: "With 50 000 ids this opens 50 000 sockets at once: your file-descriptor limit, your memory, and the upstream's rate limiter all fail together.",
        },
        {
          t: "code",
          label: "fixed",
          code: `MAX_CONCURRENCY = 20
PER_ITEM_TIMEOUT = 10

async def sync_all(user_ids, *, limit=MAX_CONCURRENCY):
    sem = asyncio.Semaphore(limit)

    async def one(uid):
        async with sem:                                   # at most 'limit' at a time
            async with asyncio.timeout(PER_ITEM_TIMEOUT): # and none runs forever
                return await fetch_profile(uid)

    return await asyncio.gather(*(one(uid) for uid in user_ids),
                                return_exceptions=True)`,
          cap: "`return_exceptions=True` means one failure does not cancel the rest — but you must then inspect the results, because exceptions arrive as values.",
        },
        {
          t: "box",
          kind: "rule",
          title: "Every await that can block needs a timeout",
          md: `A network read, a lock acquisition, a queue get, a subprocess wait. Without a timeout, one stuck operation holds a task forever; with ten thousand tasks, "forever" is also your memory.

\`async with asyncio.timeout(n):\` is the modern form. It raises \`TimeoutError\` and cancels the inner operation properly.`,
        },
        {
          t: "box",
          kind: "pitfall",
          title: "Blocking calls poison the event loop",
          md: `\`\`\`
async def handler(request):
    data = requests.get(url, timeout=10)     # BLOCKS the whole loop
    time.sleep(1)                            # so does this
    result = hashlib.scrypt(pw, ...)         # and this (CPU-bound)
\`\`\`

A synchronous call inside a coroutine stops **every** task in the process, not just this one. One ten-second blocking call in a 5 000-connection server is a ten-second outage.

Use an async client (\`httpx.AsyncClient\`, \`aiohttp\`), \`await asyncio.sleep\`, and \`await asyncio.to_thread(cpu_work)\` for CPU-bound work.`,
        },
        {
          t: "box",
          kind: "note",
          title: "Why this exercise simulates the scheduler",
          md: `Python in the browser has no OS threads and cannot block on an event loop, so \`asyncio.run()\` does not work here — try it in the console and read the error.

The exercise below therefore implements the *same three controls* — a concurrency cap, a per-item timeout and failure isolation — over a deterministic discrete-event scheduler you write yourself. You get the scheduling logic without the runtime, and a bug in it is reproducible rather than intermittent, which is worth something on its own.

Everything above applies unchanged to real \`asyncio\` on a server.`,
        },
        {
          t: "box",
          kind: "warn",
          title: "Fire-and-forget loses work and hides errors",
          md: `\`asyncio.create_task(coro)\` without keeping a reference lets the garbage collector cancel the task mid-flight, and an exception inside it is reported only when the task is destroyed — often never.

Keep references (\`tasks.add(t)\`), or use \`asyncio.TaskGroup\`, which waits for its children and propagates their failures.`,
        },
      ],
      quiz: [
        {
          q: "`asyncio.gather` over 50 000 coroutines that each open a socket:",
          options: [
            "Is handled automatically.",
            "Opens all 50 000 at once — bound it with a `Semaphore`.",
            "Runs them sequentially.",
          ],
          answer: 1,
          why: "`gather` starts everything immediately. Concurrency limits are yours to impose.",
        },
        {
          q: "`requests.get()` inside an `async def` handler:",
          options: [
            "Works fine.",
            "Blocks the entire event loop, stalling every other task in the process.",
            "Raises a RuntimeError.",
          ],
          answer: 1,
          why: "One thread runs the loop. A synchronous call occupies it completely. Use an async client or `asyncio.to_thread`.",
        },
        {
          q: "Why keep a reference to a task from `create_task`?",
          options: [
            "For debugging.",
            "Otherwise it can be garbage-collected mid-execution and its exceptions are never surfaced.",
            "It is not necessary.",
          ],
          answer: 1,
          why: "The loop holds only a weak reference. `TaskGroup` avoids the problem by owning its children.",
        },
      ],
      exercise: {
        title: "A bounded scheduler you can single-step",
        brief: `Implement \`schedule(tasks, *, limit=3, timeout=10)\`, a discrete-event scheduler with the same three controls a real \`asyncio\` fan-out needs.

Each task is a dict: \`{"name": str, "duration": int, "fails": bool}\` — \`duration\` is how many ticks of work it needs, \`fails\` means it raises at the end of its work.

Rules:

1. Tasks start in list order. At most \`limit\` run at once; the rest wait.
2. Time advances in ticks. A running task finishes at \`start + duration\`.
3. A task still running after \`timeout\` ticks **of its own runtime** is abandoned at \`start + timeout\`, frees its slot, and is recorded as \`"timeout"\`.
4. A task whose \`fails\` is true completes normally (freeing its slot at \`start + duration\`) but is recorded as \`f"error: {name} failed"\`.
5. One task's timeout or failure must never prevent another from running.

Return:

\`\`\`
{"ok": {name: finish_tick}, "failed": {name: reason},
 "elapsed": <tick when everything was done>, "peak": <max concurrent>}
\`\`\`

Validate: \`limit\` and \`timeout\` must be positive \`int\`s (reject \`bool\`) → \`ValueError\`; each task needs a non-empty \`name\` and a non-negative \`int\` \`duration\` → \`ValueError\`. Duplicate names → \`ValueError\`.`,
        rubric: [
          "Concurrency never exceeds `limit`, and `peak` reports it",
          "A long task is abandoned at exactly `timeout` ticks of its own runtime",
          "A timed-out or failing task frees its slot and does not block the queue",
          "`ok` records finish ticks; `failed` records reasons",
          "`elapsed` is the tick at which the last task left",
          "Arguments and tasks are validated",
        ],
        starter: `def schedule(tasks, *, limit=3, timeout=10):
    """Run tasks with a concurrency cap and a per-task timeout."""


work = [
    {"name": "a", "duration": 2, "fails": False},
    {"name": "b", "duration": 5, "fails": False},
    {"name": "c", "duration": 1, "fails": True},
    {"name": "d", "duration": 99, "fails": False},
]
print(schedule(work, limit=2, timeout=4))
`,
        stdin: [],
        tests: [
          {
            name: "a simple batch runs in order within the limit",
            code: `tasks = [{"name": n, "duration": 2, "fails": False} for n in "abcd"]
got = schedule(tasks, limit=2, timeout=10)
assert got["ok"] == {"a": 2, "b": 2, "c": 4, "d": 4}, f"got {got['ok']!r}"
assert got["failed"] == {}
assert got["peak"] == 2, f"got {got['peak']!r}"
assert got["elapsed"] == 4, f"got {got['elapsed']!r}"`,
          },
          {
            name: "the concurrency cap is never exceeded",
            code: `tasks = [{"name": f"t{i}", "duration": 3, "fails": False} for i in range(20)]
for limit in (1, 3, 7):
    got = schedule(tasks, limit=limit, timeout=100)
    assert got["peak"] <= limit, f"limit {limit}: peak was {got['peak']}"
    assert got["peak"] == min(limit, 20), f"limit {limit}: expected full use, got {got['peak']}"
    assert len(got["ok"]) == 20`,
          },
          {
            name: "a slow task is abandoned at its own timeout",
            code: `tasks = [{"name": "slow", "duration": 100, "fails": False},
         {"name": "quick", "duration": 1, "fails": False}]
got = schedule(tasks, limit=2, timeout=5)
assert got["failed"] == {"slow": "timeout"}, f"got {got['failed']!r}"
assert got["ok"] == {"quick": 1}, f"got {got['ok']!r}"
assert got["elapsed"] == 5, f"got {got['elapsed']!r}"`,
          },
          {
            name: "a timed-out task frees its slot for the queue",
            code: `tasks = [{"name": "slow", "duration": 100, "fails": False},
         {"name": "next", "duration": 2, "fails": False}]
got = schedule(tasks, limit=1, timeout=4)
assert got["failed"] == {"slow": "timeout"}, f"got {got['failed']!r}"
assert got["ok"] == {"next": 6}, f"'next' should start at tick 4 and finish at 6: {got['ok']!r}"
assert got["elapsed"] == 6`,
          },
          {
            name: "failures are isolated and recorded with a reason",
            code: `tasks = [{"name": "a", "duration": 1, "fails": True},
         {"name": "b", "duration": 1, "fails": False},
         {"name": "c", "duration": 1, "fails": True}]
got = schedule(tasks, limit=3, timeout=10)
assert got["ok"] == {"b": 1}, f"got {got['ok']!r}"
assert set(got["failed"]) == {"a", "c"}, f"got {got['failed']!r}"
assert got["failed"]["a"].startswith("error:"), f"got {got['failed']!r}"
assert "a failed" in got["failed"]["a"], f"got {got['failed']!r}"`,
          },
          {
            name: "a failing task still frees its slot",
            code: `tasks = [{"name": "boom", "duration": 2, "fails": True},
         {"name": "after", "duration": 1, "fails": False}]
got = schedule(tasks, limit=1, timeout=10)
assert got["ok"] == {"after": 3}, f"'after' should start once 'boom' ends at 2: {got['ok']!r}"
assert got["elapsed"] == 3`,
          },
          {
            name: "zero-duration and empty inputs behave",
            code: `got = schedule([], limit=2, timeout=5)
assert got == {"ok": {}, "failed": {}, "elapsed": 0, "peak": 0}, f"got {got!r}"
got = schedule([{"name": "instant", "duration": 0, "fails": False}], limit=1, timeout=5)
assert got["ok"] == {"instant": 0}, f"got {got['ok']!r}"
assert got["elapsed"] == 0`,
          },
          {
            name: "arguments and tasks are validated",
            code: `ok = [{"name": "a", "duration": 1, "fails": False}]
for bad in (0, -1, 1.5, "2", None, True):
    with raises(ValueError):
        schedule(ok, limit=bad)
    with raises(ValueError):
        schedule(ok, timeout=bad)
for bad_task in ({"duration": 1}, {"name": "", "duration": 1}, {"name": "a", "duration": -1},
                 {"name": "a", "duration": 1.5}, {"name": "a"}, {"name": "a", "duration": True}):
    with raises(ValueError):
        schedule([bad_task])
with raises(ValueError):
    schedule([{"name": "dup", "duration": 1, "fails": False},
              {"name": "dup", "duration": 1, "fails": False}])`,
          },
          {
            name: "a long queue with mixed outcomes schedules correctly",
            code: `tasks = ([{"name": f"fast{i}", "duration": 1, "fails": False} for i in range(5)]
         + [{"name": "hang", "duration": 1000, "fails": False}]
         + [{"name": f"slow{i}", "duration": 3, "fails": i == 0} for i in range(3)])
got = schedule(tasks, limit=2, timeout=4)
assert got["failed"]["hang"] == "timeout", f"got {got['failed']!r}"
assert got["failed"]["slow0"].startswith("error:"), f"got {got['failed']!r}"
assert len(got["ok"]) == 7, f"got {sorted(got['ok'])}"
assert got["peak"] == 2`,
          },
        ],
        requirements: [
          { kind: "defines", value: "schedule" },
          { kind: "forbids_module", value: "asyncio", message: "This exercise is the scheduler itself — implement it, do not delegate to asyncio." },
          { kind: "no_finding", value: "PY-SWALLOWED-ERROR" },
        ],
        hints: [
          "Keep three structures: a queue of pending tasks, a dict of running tasks (`name -> (start, end_tick, reason_if_abandoned)`), and the results. Loop while either is non-empty.",
          "A running task's end tick is `start + min(duration, timeout)`, and it is a timeout exactly when `duration > timeout`. Computing that at start time removes all the special cases from the loop.",
          "Each iteration: fill free slots from the queue, then advance `now` to the smallest end tick among running tasks, then retire everything that ends at that tick.",
          "Track `peak` right after filling slots — that is the moment concurrency is at its highest.",
          "Advance time only to the *next* event, never one tick at a time: a 1000-tick task must not cost 1000 iterations of the loop.",
        ],
        solution: `def _validate(tasks, limit, timeout):
    if isinstance(limit, bool) or not isinstance(limit, int) or limit < 1:
        raise ValueError("limit must be a positive int")
    if isinstance(timeout, bool) or not isinstance(timeout, int) or timeout < 1:
        raise ValueError("timeout must be a positive int")

    seen = set()
    for task in tasks:
        if not isinstance(task, dict):
            raise ValueError("each task must be an object")
        name = task.get("name")
        duration = task.get("duration")
        if not isinstance(name, str) or not name:
            raise ValueError("each task needs a non-empty name")
        if isinstance(duration, bool) or not isinstance(duration, int) or duration < 0:
            raise ValueError(f"{name}: duration must be a non-negative int")
        if name in seen:
            raise ValueError(f"duplicate task name: {name!r}")
        seen.add(name)


def schedule(tasks, *, limit=3, timeout=10):
    """Run tasks with a concurrency cap and a per-task timeout."""
    tasks = list(tasks)
    _validate(tasks, limit, timeout)

    pending = list(tasks)
    running = {}                     # name -> (end_tick, reason or None)
    ok, failed = {}, {}
    now, peak = 0, 0

    while pending or running:
        # 1. fill every free slot
        while pending and len(running) < limit:
            task = pending.pop(0)
            duration = task["duration"]
            if duration > timeout:
                end, reason = now + timeout, "timeout"
            elif task.get("fails"):
                end, reason = now + duration, f"error: {task['name']} failed"
            else:
                end, reason = now + duration, None
            running[task["name"]] = (end, reason)

        peak = max(peak, len(running))

        # 2. jump straight to the next event -- never tick by tick
        now = min(end for end, _ in running.values())

        # 3. retire everything that ends now; each one frees its slot
        for name in [n for n, (end, _) in running.items() if end == now]:
            _, reason = running.pop(name)
            if reason is None:
                ok[name] = now
            else:
                failed[name] = reason

    return {"ok": ok, "failed": failed, "elapsed": now, "peak": peak}


work = [
    {"name": "a", "duration": 2, "fails": False},
    {"name": "b", "duration": 5, "fails": False},
    {"name": "c", "duration": 1, "fails": True},
    {"name": "d", "duration": 99, "fails": False},
]
print(schedule(work, limit=2, timeout=4))`,
        why: `The scheduler is an event loop with the mechanics made visible. Three structures and three steps per iteration: fill the free slots, jump to the next event, retire what finished. Real \`asyncio\` does the same thing with the operating system supplying the events.

**The outcome is decided at start time.** \`end, reason = now + timeout, "timeout"\` when \`duration > timeout\` collapses what would otherwise be a tangle of special cases later in the loop: by the time a task is retired, whether it succeeded, timed out or failed is already known, and retirement is three lines. Deciding late — checking at each tick whether something has overrun — is where off-by-one bugs live.

**Time jumps to the next event.** \`now = min(end for end, _ in running.values())\` is what makes a 1000-tick task cost one iteration rather than a thousand. A tick-by-tick loop would pass the tests and then take minutes on realistic durations, which is the same unbounded-work mistake the module is about — committed by the thing meant to bound it.

**Every exit frees a slot.** A timed-out task and a failed task both leave \`running\` exactly like a successful one, which is the isolation property: the test where \`slow\` times out at tick 4 and \`next\` then runs to tick 6 fails for any implementation that lets an abandoned task keep its slot. That is the single most common real bug in bounded fan-out code — the semaphore is released on the success path only.

**\`peak\` is sampled after filling.** Measuring anywhere else understates concurrency and would let a broken limit pass unnoticed.

The same three controls appear in the \`asyncio\` version at the top of this lesson: \`Semaphore(limit)\` is the slot, \`asyncio.timeout\` is the per-task bound, and catching inside each task is the isolation. Here you wrote them; there the library does.`,
      },
      wrapup: `- \`gather\` starts everything at once; a \`Semaphore\` is how you say "not that much".
- Every await that can block needs \`asyncio.timeout\`.
- A synchronous call inside a coroutine stalls every task in the process.
- Convert per-item failures into values so one bad item cannot end the batch.
- Whatever supplies the events, the three controls are the same: a slot, a deadline, and per-item isolation.`,
      refs: [
        { label: "asyncio", url: "https://docs.python.org/3/library/asyncio.html" },
        { label: "CWE-770: Allocation of Resources Without Limits", url: "https://cwe.mitre.org/data/definitions/770.html" },
      ],
    },

    /* ----------------------------------------------------------------- 53 */
    {
      id: "m11l03",
      day: 53,
      title: "ReDoS: when a regex becomes the outage",
      minutes: 60,
      secure: "catastrophic backtracking",
      cwe: ["CWE-1333"],
      tags: ["redos", "regex", "backtracking", "dos", "validation"],
      lede:
        "`^(a+)+$` against thirty characters of input can run for longer than the universe has existed. The pattern looks reasonable, and it is in validation code everywhere.",
      blocks: [
        {
          t: "p",
          md: `Python's \`re\` is a **backtracking** engine. When a match fails, it returns to the last choice point and tries the next possibility. With nested quantifiers, the number of ways to split the input grows exponentially, and the engine tries all of them before concluding failure.`,
        },
        {
          t: "code",
          label: "vulnerable",
          code: `import re

EMAIL = re.compile(r"^([a-zA-Z0-9_.+-]+)+@[a-zA-Z0-9-]+\\.[a-zA-Z0-9-.]+$")

EMAIL.match("a" * 30 + "!")      # no '@': the engine explores 2^30 splits`,
          cap: "The payload does not even have to be long. Thirty characters and one invalid byte at the end is enough, because the cost is in proving that *no* split works.",
        },
        {
          t: "table",
          head: ["Dangerous shape", "Example", "Safe rewrite"],
          rows: [
            ["Nested quantifier", "`(a+)+`", "`a+`"],
            ["Quantified alternation with overlap", "`(a|aa)+`", "`a+`"],
            ["Quantified optional group", "`(a*)*`", "`a*`"],
            ["Adjacent overlapping quantifiers", "`\\d+\\d+`", "`\\d+`"],
            ["Unanchored scan over a long string", "`.*foo.*`", "anchor, or use `in`"],
          ],
        },
        {
          t: "box",
          kind: "rule",
          title: "Three defences, applied together",
          md: `1. **Bound the input before matching.** \`if len(value) > 254: reject\` costs nothing and caps the exponent.
2. **Flatten the pattern.** Remove nesting and overlapping alternatives. Most ReDoS patterns have a simple equivalent.
3. **Prefer non-regex parsing** where the grammar is simple. \`local, _, domain = value.partition("@")\` and a few checks is faster, clearer and cannot backtrack.

Python has no regex timeout. There is no fourth option that lets you keep the bad pattern.`,
        },
        {
          t: "code",
          label: "fixed",
          code: `import re

# Flat: one quantifier per segment, anchored, with a length bound outside.
EMAIL = re.compile(r"\\A[A-Za-z0-9_.+-]{1,64}@[A-Za-z0-9-]{1,63}\\.[A-Za-z0-9.-]{1,63}\\Z")

def is_email(value):
    if not isinstance(value, str) or len(value) > 254:
        return False
    return EMAIL.match(value) is not None`,
          cap: "`{1,64}` bounds the work explicitly, and no group is quantified, so there is nothing to backtrack between.",
        },
        {
          t: "box",
          kind: "cve",
          title: "Cloudflare, 2 July 2019",
          md: `A single regular expression containing \`.*.*=.*\` was deployed to the global WAF. CPU usage hit 100% on every machine, and Cloudflare's network — a significant fraction of the web — was down for 27 minutes.

Stack Exchange had a comparable outage in 2016 from a trailing-whitespace regex. These are not exotic bugs; they are ordinary patterns meeting unusual input.`,
        },
        { t: "h", text: "Beyond regex: algorithmic complexity attacks" },
        {
          t: "box",
          kind: "warn",
          title: "The same idea, different mechanism",
          md: `- **Hash collisions** — thousands of keys that hash to one bucket turn a dict into a linked list. Python randomises string hashing by default, which closes this.
- **Quadratic string building** — \`s += chunk\` in a loop copies the whole string each time. Use \`"".join(parts)\`.
- **\`in\` on a list** — O(n) per check inside a loop over n items is O(n²). Use a set.
- **Unbounded sort keys** — sorting by a function that itself scans the item.
- **Zip bombs and billion laughs** — small input, enormous expansion (Module 6).

The pattern to recognise: *input size the attacker chooses, work that grows faster than linearly*.`,
        },
      ],
      spot: {
        label: "log parser",
        prompt: "Click the pattern that can be made to run for hours.",
        lines: [4],
        why:
          "Line 4. `(\\s*\\w+\\s*)+` is a quantified group whose body can match the empty string and whose parts overlap — the classic catastrophic shape. A line of 30 word characters followed by one `!` forces the engine through an exponential number of splits. Flatten it to `[\\w\\s]+` and bound the line length first.",
        code: `import re

LINE = re.compile(r"\\A(\\d{4}-\\d{2}-\\d{2})\\s+(\\w+)\\s+(\\s*\\w+\\s*)+\\Z")

def parse(line):
    m = LINE.match(line)
    return m.groups() if m else None`,
      },
      quiz: [
        {
          q: "Why does `^(a+)+$` blow up on `\"aaaa...!\"`?",
          options: [
            "The string is too long.",
            "The engine must try every way of splitting the a's before concluding failure — exponentially many.",
            "`^` and `$` are slow.",
          ],
          answer: 1,
          why: "Catastrophic backtracking. The cost is in proving no match exists, which is why a *failing* input is the payload.",
        },
        {
          q: "Can you set a timeout on a Python regex match?",
          options: [
            "Yes, `re.match(..., timeout=1)`.",
            "No — bound the input length and flatten the pattern instead.",
            "Yes, with a signal handler on any platform.",
          ],
          answer: 1,
          why:
            "`re` has no timeout parameter. Signal-based timeouts are main-thread and Unix-only, and leave the CPU already burned. Fix the pattern.",
        },
        {
          q: "Which is an algorithmic complexity attack that is *not* ReDoS?",
          options: [
            "`s += chunk` inside a loop over attacker-controlled chunks.",
            "A missing database index.",
            "A slow network.",
          ],
          answer: 0,
          why: "Repeated concatenation is quadratic: each `+=` copies the whole accumulated string. `\"\".join(parts)` is linear.",
        },
      ],
      exercise: {
        title: "Find and fix the backtracking patterns",
        brief: `Write a regex-safety checker and a safe validator.

1. \`is_dangerous(pattern)\` — \`True\` when the pattern contains a {{nested quantifier}}: a group \`(...)\` whose body contains \`+\`, \`*\` or \`{n,}\` and which is itself immediately followed by \`+\`, \`*\` or \`{n,}\`. Also \`True\` for an alternation group with a quantifier where the branches overlap in the simple case \`(x|xx)+\` — detect this as *any* alternation group followed by a quantifier. Otherwise \`False\`.
2. \`audit_patterns(patterns)\` — return the sorted list of names from a \`{name: pattern}\` dict whose patterns are dangerous.
3. \`safe_email(value, *, max_length=254)\` — validate an email **without** a regex: reject non-strings, anything longer than \`max_length\`, anything with whitespace, anything without exactly one \`@\`, an empty local part, a local part over 64 characters, a domain without a dot, a domain starting or ending with a dot or hyphen. Return \`True\`/\`False\`, never raise.
4. \`join_lines(parts)\` — concatenate a list of strings in **linear** time (use \`"".join\`), capped at 10 000 total characters, raising \`ValueError\` beyond that.`,
        rubric: [
          "Nested and alternation-quantifier patterns are flagged; flat ones are not",
          "`audit_patterns` returns sorted names",
          "`safe_email` accepts valid addresses and rejects the malformed cases",
          "`safe_email` never raises and is not regex-based",
          "`join_lines` is linear and bounded",
        ],
        starter: `def is_dangerous(pattern):
    """True when the pattern can backtrack catastrophically."""


def audit_patterns(patterns):
    """Return the sorted names of dangerous patterns."""


def safe_email(value, *, max_length=254):
    """Validate an email address without a regular expression."""


def join_lines(parts):
    """Join strings in linear time, bounded in total length."""


PATTERNS = {
    "email_bad": r"^([a-zA-Z0-9_.+-]+)+@example\\.com$",
    "email_ok": r"\\A[A-Za-z0-9_.+-]{1,64}@example\\.com\\Z",
    "words_bad": r"(\\s*\\w+\\s*)+",
    "digits_ok": r"\\A\\d{1,10}\\Z",
}
print(audit_patterns(PATTERNS))
print(safe_email("ada@example.com"), safe_email("a" * 300))
`,
        stdin: [],
        tests: [
          {
            name: "nested quantifiers are flagged",
            code: `for bad in (r"^(a+)+$", r"(a*)*", r"([a-z]+)+@x", r"(\\\\w+\\\\s*)+", r"(\\\\d{1,3}+)*"):
    assert is_dangerous(bad) is True, f"{bad!r} should be flagged"`,
          },
          {
            name: "quantified alternations are flagged",
            code: `for bad in (r"(a|aa)+", r"(x|xy)*", r"(foo|foobar)+"):
    assert is_dangerous(bad) is True, f"{bad!r} should be flagged"`,
          },
          {
            name: "flat patterns are not flagged",
            code: `for ok in (r"\\\\A[a-z]+\\\\Z", r"\\\\d{1,10}", r"\\\\A[A-Za-z0-9_.+-]{1,64}@example\\\\.com\\\\Z",
           r"(abc)", r"(abc)|(def)", r"^foo$", r""):
    assert is_dangerous(ok) is False, f"{ok!r} should be clean"`,
          },
          {
            name: "audit returns sorted names",
            code: `got = audit_patterns(PATTERNS)
assert got == ["email_bad", "words_bad"], f"got {got!r}"
assert audit_patterns({}) == []`,
          },
          {
            name: "valid emails are accepted",
            code: `for ok in ("ada@example.com", "a.b+c@sub.example.co.uk", "x@y.zz", "a_b-c@example.com"):
    assert safe_email(ok) is True, f"{ok!r} should be valid"`,
          },
          {
            name: "malformed emails are rejected",
            code: `for bad in ("", "nope", "a@@b.com", "@example.com", "ada@", "ada@example",
            "ada example@x.com", "ada@.com", "ada@example.", "ada@-example.com",
            "ada@example.com ", "a" * 65 + "@example.com", None, 42):
    assert safe_email(bad) is False, f"{bad!r} should be invalid"`,
          },
          {
            name: "safe_email is bounded and never raises",
            code: `assert safe_email("a" * 300 + "@example.com") is False
assert safe_email("a" * 60 + "@example.com", max_length=10) is False
for weird in ("\\x00@example.com", "a@" + "b" * 1000 + ".com"):
    got = safe_email(weird)
    assert got in (True, False), f"returned {got!r}"`,
          },
          {
            name: "join_lines is bounded",
            code: `assert join_lines(["a", "b", "c"]) == "abc"
assert join_lines([]) == ""
with raises(ValueError):
    join_lines(["x" * 1000] * 20)
assert len(join_lines(["x" * 1000] * 10)) == 10_000`,
          },
        ],
        requirements: [
          { kind: "defines", value: "is_dangerous" },
          { kind: "defines", value: "safe_email" },
          { kind: "forbids", value: "re\\.(match|search|compile|fullmatch)\\s*\\(\\s*[\"'r]", message: "`safe_email` must not use a regular expression." },
        ],
        hints: [
          "Scan the pattern for `)` and look at the next character: if it is `+`, `*`, or `{`, inspect the group's body for a quantifier or a `|`.",
          "Track nesting with a small stack of opening-paren indices so you can slice out the exact group body when you hit its `)`.",
          "Ignore escaped parentheses (`\\\\(`) by checking whether the preceding character is a backslash.",
          "`safe_email`: `local, sep, domain = value.partition(\"@\")`, then a sequence of plain string checks. `any(ch.isspace() for ch in value)` handles the whitespace rule.",
        ],
        solution: `QUANTIFIERS = "+*{"


def is_dangerous(pattern):
    """True when the pattern can backtrack catastrophically."""
    if not isinstance(pattern, str):
        return False

    stack = []
    for index, char in enumerate(pattern):
        escaped = index > 0 and pattern[index - 1] == "\\\\"
        if escaped:
            continue

        if char == "(":
            stack.append(index)
        elif char == ")" and stack:
            start = stack.pop()
            body = pattern[start + 1:index]
            following = pattern[index + 1:index + 2]

            if following in QUANTIFIERS:
                # A quantified group whose body also repeats, or which offers
                # overlapping alternatives, is the catastrophic shape.
                if "|" in body:
                    return True
                for pos, ch in enumerate(body):
                    if ch in "+*" and not (pos and body[pos - 1] == "\\\\"):
                        return True
                    if ch == "{" and not (pos and body[pos - 1] == "\\\\"):
                        return True
    return False


def audit_patterns(patterns):
    """Return the sorted names of dangerous patterns."""
    return sorted(name for name, pattern in patterns.items() if is_dangerous(pattern))


def safe_email(value, *, max_length=254):
    """Validate an email address without a regular expression."""
    if not isinstance(value, str):
        return False
    if not value or len(value) > max_length:
        return False
    if any(ch.isspace() or ord(ch) < 32 for ch in value):
        return False

    local, sep, domain = value.partition("@")
    if not sep or "@" in domain:
        return False
    if not local or len(local) > 64:
        return False
    if not domain or len(domain) > 253:
        return False
    if "." not in domain:
        return False
    if domain[0] in ".-" or domain[-1] in ".-":
        return False
    if ".." in domain:
        return False

    return True


MAX_JOINED = 10_000


def join_lines(parts):
    """Join strings in linear time, bounded in total length."""
    total = 0
    for part in parts:
        total += len(part)
        if total > MAX_JOINED:
            raise ValueError(f"joined output would exceed {MAX_JOINED} characters")
    return "".join(parts)          # linear; "+=" in a loop would be quadratic


PATTERNS = {
    "email_bad": r"^([a-zA-Z0-9_.+-]+)+@example\\.com$",
    "email_ok": r"\\A[A-Za-z0-9_.+-]{1,64}@example\\.com\\Z",
    "words_bad": r"(\\s*\\w+\\s*)+",
    "digits_ok": r"\\A\\d{1,10}\\Z",
}
print(audit_patterns(PATTERNS))
print(safe_email("ada@example.com"), safe_email("a" * 300))`,
        why: `\`safe_email\` is the lesson's real argument. Email validation is the canonical home of catastrophic regexes, and the non-regex version is *shorter*, more readable, and cannot backtrack because there is nothing to backtrack over — every check is a single linear pass or an O(1) index.

It also fails safe in a way the regex version does not: it returns \`False\` for a non-string, for a control character, for a 10 MB input, and it never raises. A validator that throws on unexpected input turns a malformed address into a 500, which is its own availability problem.

The length check comes before everything else, which is the single most valuable line in any validator exposed to user input. Even if the rest of the function were a dangerous regex, bounding the input to 254 characters would cap the damage — the exponent has a ceiling.

\`is_dangerous\` is a heuristic and should be described as one. It catches the two shapes that cause almost all real incidents — a quantified group containing a quantifier, and a quantified alternation — and it will miss patterns whose danger depends on how the character classes overlap. That is an acceptable trade for a pre-commit check: it has a very low false-positive rate on flat patterns, which is what keeps it switched on. For deeper analysis the right tool is a dedicated one (\`regexploit\`, or an engine without backtracking such as RE2).

\`join_lines\` demonstrates the non-regex half of the module. \`s += chunk\` in a loop is quadratic because each concatenation copies everything accumulated so far; with attacker-chosen chunk sizes that is a complexity attack with no regex in sight. Counting first and joining once is linear, and the count doubles as the bound.`,
      },
      wrapup: `- Backtracking engines explore every split; a *failing* input is the payload.
- Bound input length, flatten the pattern, or skip the regex entirely.
- Python regexes have no timeout — the fix is the pattern, not a watchdog.
- Watch for the same shape without regex: quadratic concatenation, \`in\` on lists, unbounded expansion.`,
      refs: [
        { label: "Cloudflare outage postmortem, 2019-07-02", url: "https://blog.cloudflare.com/details-of-the-cloudflare-outage-on-july-2-2019/" },
        { label: "CWE-1333: Inefficient Regular Expression Complexity", url: "https://cwe.mitre.org/data/definitions/1333.html" },
      ],
    },

    /* ----------------------------------------------------------------- 54 */
    {
      id: "m11l04",
      day: 54,
      title: "Rate limiting and backpressure",
      minutes: 60,
      secure: "bounded intake",
      cwe: ["CWE-770", "CWE-307"],
      tags: ["rate-limit", "token-bucket", "backpressure", "queue", "circuit-breaker"],
      lede:
        "A system that accepts work faster than it completes it has only one failure mode. Rate limiting decides what to reject; backpressure decides when to stop accepting at all.",
      blocks: [
        {
          t: "p",
          md: `Two distinct controls that are often confused:

- **Rate limiting** is a *policy*: this client may do 100 requests per minute. It is about fairness and abuse.
- **Backpressure** is a *mechanic*: when the queue is full, stop accepting. It is about survival.

A service needs both. Rate limiting without backpressure still falls over when every client stays exactly at their limit.`,
        },
        { t: "h", text: "The token bucket" },
        {
          t: "code",
          label: "fixed",
          code: `class TokenBucket:
    """capacity tokens, refilled at rate-per-second; one token per request."""

    def __init__(self, capacity, rate, *, now):
        self.capacity = capacity
        self.rate = rate
        self.tokens = float(capacity)
        self.updated = now

    def allow(self, *, now, cost=1):
        elapsed = max(0.0, now - self.updated)
        self.tokens = min(self.capacity, self.tokens + elapsed * self.rate)
        self.updated = now

        if self.tokens < cost:
            return False
        self.tokens -= cost
        return True`,
          cap: "Tokens accumulate up to `capacity`, which permits a burst, and refill at a steady `rate`, which caps the sustained average. Two parameters express both policies.",
        },
        {
          t: "table",
          head: ["Algorithm", "Behaviour", "Trade-off"],
          rows: [
            ["Fixed window", "Count per calendar minute", "Allows 2× the limit across a boundary."],
            ["Sliding window", "Count over the last 60s", "Accurate; needs per-request timestamps."],
            ["**Token bucket**", "Burst then steady rate", "Two numbers, O(1) state. **Usually the right default.**"],
            ["Leaky bucket", "Constant output rate", "Smooths output; adds latency."],
            ["Concurrency limit", "N in flight at once", "Bounds *resources* rather than rate."],
          ],
        },
        {
          t: "box",
          kind: "rule",
          title: "Limit the right key",
          md: `Per **IP** is easy and wrong on its own — NAT puts a thousand users behind one address, and an attacker has thousands of addresses.

Limit by the most specific identity available, and layer: per API key, per account, per IP, and globally. Apply the login limiter per *account* as well as per IP, or credential stuffing simply rotates addresses.`,
        },
        { t: "h", text: "Backpressure" },
        {
          t: "code",
          label: "vulnerable",
          code: `queue = []

def enqueue(job):
    queue.append(job)         # unbounded: the queue grows until memory runs out
    return {"accepted": True}`,
          cap: "Accepting work you cannot complete converts a slowdown into an out-of-memory crash — and the crash loses everything in the queue.",
        },
        {
          t: "code",
          label: "fixed",
          code: `MAX_QUEUE = 1000

def enqueue(queue, job):
    if len(queue) >= MAX_QUEUE:
        raise Overloaded("queue is full")        # 503 + Retry-After
    queue.append(job)
    return {"accepted": True, "depth": len(queue)}`,
          cap: "Rejecting early is a *feature*: the client learns immediately and can retry, rather than waiting for a timeout on work that was never going to run.",
        },
        {
          t: "box",
          kind: "good",
          title: "The circuit breaker",
          md: `When a dependency is failing, calling it repeatedly makes things worse for both sides. A breaker has three states:

- **closed** — calls pass through; count failures.
- **open** — after N consecutive failures, fail immediately without calling, for a cool-down period.
- **half-open** — after the cool-down, let one call through; success closes the breaker, failure re-opens it.

The win is removing load from a struggling dependency, and returning fast to your own callers instead of holding their connections while timeouts expire.`,
        },
        {
          t: "box",
          kind: "warn",
          title: "Retries amplify outages",
          md: `Three retries per client turns a partial outage into 4× load at exactly the moment the system cannot take it. If you retry: use exponential backoff **with jitter**, cap the attempts, and never retry a non-idempotent operation blindly.

Retry storms are a leading cause of a brief degradation becoming a long outage.`,
        },
      ],
      quiz: [
        {
          q: "Why is a fixed-minute window a weaker limiter than a token bucket?",
          options: [
            "It uses more memory.",
            "A client can send a full limit at the end of one window and again at the start of the next — 2× in a short span.",
            "It cannot handle bursts.",
          ],
          answer: 1,
          why: "The boundary effect. A token bucket has no boundary: refill is continuous.",
        },
        {
          q: "Rate limiting logins per IP only. What does it miss?",
          options: [
            "Nothing.",
            "Credential stuffing from many IPs against one account — limit per account as well.",
            "Slow brute force.",
          ],
          answer: 1,
          why: "Attackers rotate addresses cheaply. Layer the limits, with the account as a key.",
        },
        {
          q: "An unbounded in-memory queue under sustained overload:",
          options: [
            "Smooths the load.",
            "Grows until the process is killed, losing every queued job.",
            "Applies backpressure automatically.",
          ],
          answer: 1,
          why: "Bound the queue and reject with 503 + Retry-After. Fast rejection beats a crash that loses the backlog.",
        },
      ],
      exercise: {
        title: "A limiter, a bounded queue and a breaker",
        brief: `All time is passed in explicitly as \`now\` so the tests are deterministic.

1. \`TokenBucket(capacity, rate, *, now)\` with \`allow(*, now, cost=1)\` as described in the lesson. \`capacity\` and \`rate\` must be positive numbers, else \`ValueError\`. Tokens never exceed \`capacity\`, never go below 0, and time must not run backwards (clamp a negative elapsed to 0).

2. \`RateLimiter(capacity, rate)\` managing buckets per key: \`allow(key, *, now)\` returns \`True\`/\`False\`; \`keys()\` returns the sorted keys currently tracked; at most \`max_keys=1000\` buckets are kept (clear all when exceeded — a crude bound, but a bound).

3. \`BoundedQueue(maxsize)\` with \`put(item)\` raising \`Overloaded\` when full, \`get()\` raising \`IndexError\` when empty, \`__len__\`, and FIFO order. \`Overloaded\` subclasses \`RuntimeError\`.

4. \`CircuitBreaker(threshold, cooldown)\` with \`call(fn, *, now)\`:
   - **closed**: call \`fn()\`; on success reset the failure count; on exception increment it and re-raise; at \`threshold\` consecutive failures, open.
   - **open**: raise \`Overloaded("circuit open")\` without calling, until \`cooldown\` seconds have passed since it opened.
   - **half-open** (first call after cooldown): call \`fn()\`; success closes and resets; failure re-opens with the clock restarted.
   - \`state(now)\` returns \`"closed"\`, \`"open"\` or \`"half_open"\`.`,
        rubric: [
          "The bucket allows a burst then settles to the refill rate",
          "Tokens are capped at capacity and never negative",
          "The limiter keeps buckets per key and is bounded",
          "The queue is FIFO and rejects when full",
          "The breaker opens, blocks, half-opens after cooldown, and closes on success",
        ],
        starter: `class Overloaded(RuntimeError):
    pass


class TokenBucket:
    """capacity tokens, refilled at rate per second."""

    def __init__(self, capacity, rate, *, now):
        pass

    def allow(self, *, now, cost=1):
        pass


class RateLimiter:
    """A token bucket per key."""

    def __init__(self, capacity, rate, *, max_keys=1000):
        pass


class BoundedQueue:
    """FIFO with a hard depth limit."""

    def __init__(self, maxsize):
        pass


class CircuitBreaker:
    """closed -> open -> half_open -> closed."""

    def __init__(self, threshold, cooldown):
        pass


b = TokenBucket(3, 1, now=0)
print([b.allow(now=0) for _ in range(5)])
`,
        stdin: [],
        tests: [
          {
            name: "the bucket allows a burst then refills",
            code: `b = TokenBucket(3, 1, now=0.0)
assert [b.allow(now=0.0) for _ in range(5)] == [True, True, True, False, False]
assert b.allow(now=1.0) is True, "one second should refill one token"
assert b.allow(now=1.0) is False
assert [b.allow(now=5.0) for _ in range(4)] == [True, True, True, False], "capacity caps the refill"`,
          },
          {
            name: "cost and validation",
            code: `b = TokenBucket(10, 1, now=0.0)
assert b.allow(now=0.0, cost=7) is True
assert b.allow(now=0.0, cost=7) is False
assert b.allow(now=0.0, cost=3) is True
for bad in (0, -1, "3"):
    with raises(ValueError):
        TokenBucket(bad, 1, now=0.0)
    with raises(ValueError):
        TokenBucket(3, bad, now=0.0)`,
          },
          {
            name: "time cannot run backwards into extra tokens",
            code: `b = TokenBucket(5, 1, now=100.0)
for _ in range(5):
    b.allow(now=100.0)
assert b.allow(now=50.0) is False, "a clock going backwards must not grant tokens"
assert b.allow(now=100.0) is False`,
          },
          {
            name: "the limiter is per key and bounded",
            code: `rl = RateLimiter(2, 1, max_keys=3)
assert rl.allow("a", now=0.0) is True
assert rl.allow("a", now=0.0) is True
assert rl.allow("a", now=0.0) is False
assert rl.allow("b", now=0.0) is True, "a separate key has its own bucket"
assert sorted(rl.keys()) == ["a", "b"]
for key in ("c", "d", "e"):
    rl.allow(key, now=0.0)
assert len(rl.keys()) <= 3, f"tracked {len(rl.keys())} keys"`,
          },
          {
            name: "the queue is FIFO and bounded",
            code: `q = BoundedQueue(3)
for i in range(3):
    q.put(i)
assert len(q) == 3
try:
    q.put(99)
    raise AssertionError("expected Overloaded")
except Overloaded:
    pass
assert [q.get() for _ in range(3)] == [0, 1, 2]
with raises(IndexError):
    q.get()
assert issubclass(Overloaded, RuntimeError)`,
          },
          {
            name: "the breaker opens after consecutive failures",
            code: `cb = CircuitBreaker(threshold=3, cooldown=10)
def boom():
    raise ValueError("upstream down")
for i in range(3):
    try:
        cb.call(boom, now=float(i))
    except ValueError:
        pass
assert cb.state(now=3.0) == "open", f"got {cb.state(now=3.0)!r}"
try:
    cb.call(boom, now=3.0)
    raise AssertionError("an open breaker must not call through")
except Overloaded as e:
    assert "open" in str(e)`,
          },
          {
            name: "success resets the failure count",
            code: `cb = CircuitBreaker(threshold=3, cooldown=10)
def boom():
    raise ValueError("x")
def fine():
    return "ok"
for i in range(2):
    try:
        cb.call(boom, now=float(i))
    except ValueError:
        pass
assert cb.call(fine, now=2.0) == "ok"
assert cb.state(now=2.0) == "closed"
for i in range(2):
    try:
        cb.call(boom, now=float(3 + i))
    except ValueError:
        pass
assert cb.state(now=5.0) == "closed", "the counter should have been reset"`,
          },
          {
            name: "half-open closes on success and re-opens on failure",
            code: `cb = CircuitBreaker(threshold=2, cooldown=10)
def boom():
    raise ValueError("x")
def fine():
    return "ok"
for i in range(2):
    try:
        cb.call(boom, now=float(i))
    except ValueError:
        pass
assert cb.state(now=5.0) == "open"
assert cb.state(now=12.0) == "half_open", f"got {cb.state(now=12.0)!r}"
assert cb.call(fine, now=12.0) == "ok"
assert cb.state(now=12.0) == "closed"

cb2 = CircuitBreaker(threshold=1, cooldown=10)
try:
    cb2.call(boom, now=0.0)
except ValueError:
    pass
assert cb2.state(now=20.0) == "half_open"
try:
    cb2.call(boom, now=20.0)
except ValueError:
    pass
assert cb2.state(now=21.0) == "open", "a failed probe must re-open the breaker"`,
          },
        ],
        requirements: [
          { kind: "defines", value: "TokenBucket" },
          { kind: "defines", value: "CircuitBreaker" },
          { kind: "defines", value: "BoundedQueue" },
        ],
        hints: [
          "`elapsed = max(0.0, now - self.updated)` is the clock-skew guard. Always update `self.updated` afterwards, even when the request is refused.",
          "Refill before deciding: `self.tokens = min(capacity, tokens + elapsed * rate)`. Capping at `capacity` is what stops an idle hour from granting an hour's burst.",
          "For the breaker, store `self._opened_at` and compute the state from `now`: open until `now - opened_at >= cooldown`, then half-open. Deriving the state rather than storing it avoids a stale-state bug.",
          "In half-open, a successful call sets failures to 0 and clears `_opened_at`; a failure sets `_opened_at = now` again.",
        ],
        solution: `class Overloaded(RuntimeError):
    pass


class TokenBucket:
    """capacity tokens, refilled at rate per second."""

    def __init__(self, capacity, rate, *, now):
        if isinstance(capacity, bool) or not isinstance(capacity, (int, float)) or capacity <= 0:
            raise ValueError("capacity must be a positive number")
        if isinstance(rate, bool) or not isinstance(rate, (int, float)) or rate <= 0:
            raise ValueError("rate must be a positive number")

        self.capacity = float(capacity)
        self.rate = float(rate)
        self.tokens = float(capacity)
        self.updated = float(now)

    def allow(self, *, now, cost=1):
        elapsed = max(0.0, float(now) - self.updated)     # a backwards clock adds nothing
        self.tokens = min(self.capacity, self.tokens + elapsed * self.rate)
        self.updated = max(self.updated, float(now))

        if self.tokens < cost:
            return False
        self.tokens -= cost
        return True


class RateLimiter:
    """A token bucket per key."""

    def __init__(self, capacity, rate, *, max_keys=1000):
        self.capacity = capacity
        self.rate = rate
        self.max_keys = max_keys
        self._buckets = {}

    def allow(self, key, *, now):
        if key not in self._buckets:
            if len(self._buckets) >= self.max_keys:
                self._buckets.clear()                      # crude, but bounded
            self._buckets[key] = TokenBucket(self.capacity, self.rate, now=now)
        return self._buckets[key].allow(now=now)

    def keys(self):
        return sorted(self._buckets)


class BoundedQueue:
    """FIFO with a hard depth limit."""

    def __init__(self, maxsize):
        if isinstance(maxsize, bool) or not isinstance(maxsize, int) or maxsize < 1:
            raise ValueError("maxsize must be a positive int")
        self.maxsize = maxsize
        self._items = []

    def put(self, item):
        if len(self._items) >= self.maxsize:
            raise Overloaded("queue is full")
        self._items.append(item)
        return len(self._items)

    def get(self):
        if not self._items:
            raise IndexError("queue is empty")
        return self._items.pop(0)

    def __len__(self):
        return len(self._items)


class CircuitBreaker:
    """closed -> open -> half_open -> closed."""

    def __init__(self, threshold, cooldown):
        self.threshold = threshold
        self.cooldown = cooldown
        self._failures = 0
        self._opened_at = None

    def state(self, now):
        if self._opened_at is None:
            return "closed"
        if float(now) - self._opened_at >= self.cooldown:
            return "half_open"
        return "open"

    def call(self, fn, *, now):
        current = self.state(now)

        if current == "open":
            raise Overloaded("circuit open")

        try:
            result = fn()
        except Exception:
            self._failures += 1
            if current == "half_open" or self._failures >= self.threshold:
                self._opened_at = float(now)               # (re-)open, clock restarted
            raise

        self._failures = 0
        self._opened_at = None
        return result


b = TokenBucket(3, 1, now=0)
print([b.allow(now=0) for _ in range(5)])`,
        why: `Time is a parameter everywhere, which is why these tests are deterministic and fast. A limiter that calls \`time.time()\` internally can only be tested with \`sleep\`, so in practice it is tested badly or not at all — and rate limiters are exactly the code where an off-by-one is invisible until an incident.

**The bucket.** Refilling before deciding, and capping at \`capacity\`, are the two lines that define the policy: burst up to \`capacity\`, sustain at \`rate\`. The clock guard matters more than it looks — NTP steps, container migrations and leap-second handling all move clocks backwards, and without \`max(0.0, ...)\` a backwards jump would compute a negative elapsed and *remove* tokens, or with a naive \`abs()\` would grant them. Updating \`self.updated\` with \`max\` keeps the bucket monotonic.

**The breaker** derives its state from \`now\` instead of storing it. A stored state needs something to fire a transition when the cooldown expires — a timer, a background task, or a check someone forgets — and a breaker stuck open because nothing reset it is an outage of your own making. Deriving it means the transition happens exactly when it should, with no scheduler involved.

The half-open path is the subtle one: it lets precisely one call through, and that call's outcome decides everything. The test that re-opens on a failed probe exists because the obvious implementation increments the failure count and compares it to the threshold, which lets a half-open failure pass if the counter was reset — so the breaker closes while the dependency is still down, and the next burst of traffic hits it unprotected.

**The queue's** rejection is an \`Overloaded\` exception rather than a silent drop or an unbounded append. The caller must handle it, which is the point: that is where the 503 and the \`Retry-After\` header come from, and a client that learns immediately is one that can back off instead of waiting on a timeout for work that was never scheduled.`,
      },
      wrapup: `- Rate limiting is policy; backpressure is survival. Ship both.
- Token bucket: two numbers, O(1) state, no window boundary to exploit.
- Limit by account as well as IP, or credential stuffing just rotates addresses.
- Pass time in as a parameter so limiters and breakers can be tested without sleeping.`,
      refs: [
        { label: "CWE-770: Allocation of Resources Without Limits or Throttling", url: "https://cwe.mitre.org/data/definitions/770.html" },
        { label: "AWS — timeouts, retries and backoff with jitter", url: "https://aws.amazon.com/builders-library/timeouts-retries-and-backoff-with-jitter/" },
      ],
    },

    /* ----------------------------------------------------------------- 55 */
    {
      id: "m11l05",
      day: 55,
      title: "Capstone: a worker that bounds everything",
      minutes: 60,
      secure: "resource budgets end to end",
      cwe: ["CWE-400", "CWE-770", "CWE-833"],
      tags: ["capstone", "worker", "limits", "queue", "breaker"],
      lede:
        "Assemble the module: a job processor where every resource an attacker could influence has a number attached to it, and the numbers are enforced.",
      blocks: [
        {
          t: "table",
          head: ["Resource", "Bound", "What happens at the limit"],
          rows: [
            ["Queue depth", "`max_queue`", "Reject with `Overloaded` (503 + Retry-After)."],
            ["Payload size", "`max_payload`", "Reject the job at submission."],
            ["Per-job work", "`max_steps`", "Abandon that job, record a failure."],
            ["Jobs per client", "token bucket", "Reject, fairly, per account."],
            ["Consecutive upstream failures", "circuit breaker", "Stop calling; fail fast."],
            ["Total batch size", "`max_batch`", "Process a prefix; report what was skipped."],
          ],
        },
        {
          t: "box",
          kind: "rule",
          title: "Every bound needs a visible consequence",
          md: `A limit that silently drops work is worse than no limit, because the system now lies about what it did. Each bound must produce either an error the caller can act on, or a counter someone can see on a dashboard.

"Processed 980 of 1000, 20 skipped: payload too large" is operable. "Processed 980" is a mystery.`,
        },
        {
          t: "box",
          kind: "good",
          title: "Report the shape of the failure",
          md: `Group outcomes by *reason*, not just by success and failure. \`{"too_large": 12, "timeout": 3, "rejected_rate_limit": 40}\` tells you immediately whether you are under attack, under-provisioned or misconfigured — three very different responses to what looks like one incident.`,
        },
      ],
      quiz: [
        {
          q: "A worker silently drops jobs beyond its queue limit. What is wrong?",
          options: [
            "Nothing, the limit is enforced.",
            "The caller believes the work was accepted; the bound needs a visible consequence.",
            "Queues should be unbounded.",
          ],
          answer: 1,
          why: "Rejection must be observable — an error to the caller and a counter for the operator.",
        },
        {
          q: "Why group failures by reason?",
          options: [
            "It looks thorough.",
            "Attack, overload and misconfiguration look identical in a single failure count, and need different responses.",
            "It is required for retries.",
          ],
          answer: 1,
          why: "The reason distribution is the diagnosis.",
        },
        {
          q: "Which bound protects you from a single malicious job, rather than from volume?",
          options: [
            "Queue depth.",
            "A per-job work/step budget.",
            "Rate limiting.",
          ],
          answer: 1,
          why: "Volume controls do not help against one job that never finishes. Bound the work a single item may perform.",
        },
      ],
      exercise: {
        title: "process_batch(): every resource bounded",
        brief: `Build \`Worker\` using the pieces you wrote on day 54 (re-declared in the starter).

\`Worker(handler, *, max_queue=100, max_payload=1000, max_batch=50, rate_capacity=10, rate_per_second=5, breaker_threshold=3, breaker_cooldown=30)\`

- \`submit(job, *, now)\` where \`job\` is \`{"id": str, "client": str, "payload": str}\`:
  - malformed job (not a dict, missing keys, wrong types) → \`ValueError("malformed job")\`
  - \`payload\` longer than \`max_payload\` → \`ValueError("payload too large")\`
  - the client's token bucket refuses → \`Overloaded("rate limited")\`
  - queue full → \`Overloaded("queue is full")\`
  - otherwise enqueue and return the new depth.
- \`process(*, now)\` — drain at most \`max_batch\` jobs, calling \`self.handler(job)\` through the circuit breaker. Returns \`{"done": [ids], "failed": {id: reason}, "remaining": n}\` where \`reason\` is \`"circuit_open"\` when the breaker refused, otherwise \`f"error: {exc}"\`. A handler failure must not stop the batch.
- \`stats()\` — cumulative counters: \`{"accepted", "rejected_rate", "rejected_full", "rejected_payload", "done", "failed"}\`.

The breaker wraps the handler, so a failing dependency stops being called after \`breaker_threshold\` consecutive failures.`,
        rubric: [
          "Each rejection path raises its own error and increments its own counter",
          "The queue is FIFO and bounded; `max_batch` limits one drain",
          "A failing handler trips the breaker and later jobs fail fast with `circuit_open`",
          "One job's failure does not stop the batch",
          "`stats()` accounts for every submitted job",
        ],
        starter: `class Overloaded(RuntimeError):
    pass


class TokenBucket:
    def __init__(self, capacity, rate, *, now):
        self.capacity = float(capacity)
        self.rate = float(rate)
        self.tokens = float(capacity)
        self.updated = float(now)

    def allow(self, *, now, cost=1):
        elapsed = max(0.0, float(now) - self.updated)
        self.tokens = min(self.capacity, self.tokens + elapsed * self.rate)
        self.updated = max(self.updated, float(now))
        if self.tokens < cost:
            return False
        self.tokens -= cost
        return True


class CircuitBreaker:
    def __init__(self, threshold, cooldown):
        self.threshold = threshold
        self.cooldown = cooldown
        self._failures = 0
        self._opened_at = None

    def state(self, now):
        if self._opened_at is None:
            return "closed"
        if float(now) - self._opened_at >= self.cooldown:
            return "half_open"
        return "open"

    def call(self, fn, *, now):
        current = self.state(now)
        if current == "open":
            raise Overloaded("circuit open")
        try:
            result = fn()
        except Exception:
            self._failures += 1
            if current == "half_open" or self._failures >= self.threshold:
                self._opened_at = float(now)
            raise
        self._failures = 0
        self._opened_at = None
        return result


class Worker:
    """A job worker where every resource has a number attached to it."""

    def __init__(self, handler, *, max_queue=100, max_payload=1000, max_batch=50,
                 rate_capacity=10, rate_per_second=5,
                 breaker_threshold=3, breaker_cooldown=30):
        pass

    def submit(self, job, *, now):
        pass

    def process(self, *, now):
        pass

    def stats(self):
        pass


w = Worker(lambda job: job["payload"].upper())
w.submit({"id": "j1", "client": "ada", "payload": "hello"}, now=0.0)
print(w.process(now=0.0))
`,
        stdin: [],
        tests: [
          {
            name: "a normal batch is processed",
            code: `seen = []
w = Worker(lambda job: seen.append(job["id"]))
for i in range(3):
    w.submit({"id": f"j{i}", "client": "ada", "payload": "x"}, now=0.0)
got = w.process(now=0.0)
assert got["done"] == ["j0", "j1", "j2"], f"got {got!r}"
assert got["failed"] == {} and got["remaining"] == 0
assert seen == ["j0", "j1", "j2"], "jobs must run in FIFO order"`,
          },
          {
            name: "malformed jobs and oversized payloads are refused",
            code: `w = Worker(lambda job: None, max_payload=10)
for bad in (None, [], {"id": "a"}, {"id": 1, "client": "a", "payload": "x"},
            {"id": "a", "client": "a"}, {"id": "a", "client": "a", "payload": 5}):
    with raises(ValueError):
        w.submit(bad, now=0.0)
try:
    w.submit({"id": "a", "client": "a", "payload": "x" * 50}, now=0.0)
    raise AssertionError("expected ValueError")
except ValueError as e:
    assert "too large" in str(e), f"got {str(e)!r}"
assert w.stats()["rejected_payload"] == 1, f"got {w.stats()!r}"`,
          },
          {
            name: "rate limiting is per client",
            code: `w = Worker(lambda job: None, rate_capacity=2, rate_per_second=1, max_queue=100)
assert w.submit({"id": "a1", "client": "ada", "payload": "x"}, now=0.0) == 1
assert w.submit({"id": "a2", "client": "ada", "payload": "x"}, now=0.0) == 2
try:
    w.submit({"id": "a3", "client": "ada", "payload": "x"}, now=0.0)
    raise AssertionError("expected Overloaded")
except Overloaded as e:
    assert "rate" in str(e), f"got {str(e)!r}"
assert w.submit({"id": "b1", "client": "lin", "payload": "x"}, now=0.0) == 3, "another client has its own budget"
assert w.stats()["rejected_rate"] == 1`,
          },
          {
            name: "the queue is bounded",
            code: `w = Worker(lambda job: None, max_queue=2, rate_capacity=100, rate_per_second=100)
w.submit({"id": "a", "client": "c", "payload": "x"}, now=0.0)
w.submit({"id": "b", "client": "c", "payload": "x"}, now=0.0)
try:
    w.submit({"id": "c", "client": "c", "payload": "x"}, now=0.0)
    raise AssertionError("expected Overloaded")
except Overloaded as e:
    assert "full" in str(e), f"got {str(e)!r}"
assert w.stats()["rejected_full"] == 1`,
          },
          {
            name: "max_batch limits one drain",
            code: `w = Worker(lambda job: None, max_batch=2, rate_capacity=100, rate_per_second=100)
for i in range(5):
    w.submit({"id": f"j{i}", "client": "c", "payload": "x"}, now=0.0)
got = w.process(now=0.0)
assert got["done"] == ["j0", "j1"], f"got {got!r}"
assert got["remaining"] == 3, f"got {got!r}"
assert w.process(now=0.0)["done"] == ["j2", "j3"]`,
          },
          {
            name: "one failure does not stop the batch",
            code: `def handler(job):
    if job["id"] == "j1":
        raise ValueError("bad job")
    return "ok"
w = Worker(handler, rate_capacity=100, rate_per_second=100, breaker_threshold=10)
for i in range(3):
    w.submit({"id": f"j{i}", "client": "c", "payload": "x"}, now=0.0)
got = w.process(now=0.0)
assert got["done"] == ["j0", "j2"], f"got {got!r}"
assert "bad job" in got["failed"]["j1"], f"got {got['failed']!r}"`,
          },
          {
            name: "the breaker trips and later jobs fail fast",
            code: `calls = []
def handler(job):
    calls.append(job["id"])
    raise ValueError("upstream down")
w = Worker(handler, rate_capacity=100, rate_per_second=100, breaker_threshold=2, breaker_cooldown=30)
for i in range(5):
    w.submit({"id": f"j{i}", "client": "c", "payload": "x"}, now=0.0)
got = w.process(now=0.0)
assert got["done"] == [], f"got {got!r}"
assert len(calls) == 2, f"the handler was called {len(calls)} times; the breaker should have opened"
assert got["failed"]["j2"] == "circuit_open", f"got {got['failed']!r}"
assert got["failed"]["j4"] == "circuit_open"`,
          },
          {
            name: "stats account for everything",
            code: `w = Worker(lambda job: None, max_queue=2, max_payload=5,
           rate_capacity=3, rate_per_second=0.001)
w.submit({"id": "a", "client": "c", "payload": "x"}, now=0.0)
w.submit({"id": "b", "client": "c", "payload": "x"}, now=0.0)
try:
    w.submit({"id": "c", "client": "c", "payload": "x"}, now=0.0)
except Overloaded:
    pass
try:
    w.submit({"id": "d", "client": "c", "payload": "x" * 50}, now=0.0)
except ValueError:
    pass
w.process(now=0.0)
s = w.stats()
assert s["accepted"] == 2, f"got {s!r}"
assert s["rejected_full"] == 1 and s["rejected_payload"] == 1, f"got {s!r}"
assert s["done"] == 2 and s["failed"] == 0, f"got {s!r}"`,
          },
        ],
        requirements: [
          { kind: "defines", value: "Worker" },
          { kind: "no_finding", value: "PY-SWALLOWED-ERROR" },
          { kind: "no_finding", value: "PY-BARE-EXCEPT" },
        ],
        hints: [
          "Order the submit checks from cheapest to most stateful: shape → payload size → rate limit → queue depth. Checking the rate limit before the queue means a rate-limited client does not consume a queue slot.",
          "Keep one `TokenBucket` per client in a dict, created on first sight with the current `now`.",
          "In `process`, wrap each handler call in `self._breaker.call(lambda: self.handler(job), now=now)` and catch `Overloaded` separately from `Exception` so the reason is accurate.",
          "Increment the counters in exactly one place per outcome — the same discipline as the single `_fail` helper in Module 2.",
        ],
        solution: `class Overloaded(RuntimeError):
    pass


class TokenBucket:
    def __init__(self, capacity, rate, *, now):
        self.capacity = float(capacity)
        self.rate = float(rate)
        self.tokens = float(capacity)
        self.updated = float(now)

    def allow(self, *, now, cost=1):
        elapsed = max(0.0, float(now) - self.updated)
        self.tokens = min(self.capacity, self.tokens + elapsed * self.rate)
        self.updated = max(self.updated, float(now))
        if self.tokens < cost:
            return False
        self.tokens -= cost
        return True


class CircuitBreaker:
    def __init__(self, threshold, cooldown):
        self.threshold = threshold
        self.cooldown = cooldown
        self._failures = 0
        self._opened_at = None

    def state(self, now):
        if self._opened_at is None:
            return "closed"
        if float(now) - self._opened_at >= self.cooldown:
            return "half_open"
        return "open"

    def call(self, fn, *, now):
        current = self.state(now)
        if current == "open":
            raise Overloaded("circuit open")
        try:
            result = fn()
        except Exception:
            self._failures += 1
            if current == "half_open" or self._failures >= self.threshold:
                self._opened_at = float(now)
            raise
        self._failures = 0
        self._opened_at = None
        return result


REQUIRED_JOB_KEYS = ("id", "client", "payload")


class Worker:
    """A job worker where every resource has a number attached to it."""

    def __init__(self, handler, *, max_queue=100, max_payload=1000, max_batch=50,
                 rate_capacity=10, rate_per_second=5,
                 breaker_threshold=3, breaker_cooldown=30):
        self.handler = handler
        self.max_queue = max_queue
        self.max_payload = max_payload
        self.max_batch = max_batch
        self.rate_capacity = rate_capacity
        self.rate_per_second = rate_per_second

        self._queue = []
        self._buckets = {}
        self._breaker = CircuitBreaker(breaker_threshold, breaker_cooldown)
        self._stats = {
            "accepted": 0, "rejected_rate": 0, "rejected_full": 0,
            "rejected_payload": 0, "done": 0, "failed": 0,
        }

    # -- intake -----------------------------------------------------------
    def _validate(self, job):
        if not isinstance(job, dict) or any(k not in job for k in REQUIRED_JOB_KEYS):
            raise ValueError("malformed job")
        if not all(isinstance(job[k], str) for k in REQUIRED_JOB_KEYS):
            raise ValueError("malformed job")

    def submit(self, job, *, now):
        self._validate(job)

        if len(job["payload"]) > self.max_payload:
            self._stats["rejected_payload"] += 1
            raise ValueError("payload too large")

        bucket = self._buckets.get(job["client"])
        if bucket is None:
            bucket = TokenBucket(self.rate_capacity, self.rate_per_second, now=now)
            self._buckets[job["client"]] = bucket

        # Rate limit before the queue: a throttled client must not hold a slot.
        if not bucket.allow(now=now):
            self._stats["rejected_rate"] += 1
            raise Overloaded("rate limited")

        if len(self._queue) >= self.max_queue:
            self._stats["rejected_full"] += 1
            raise Overloaded("queue is full")

        self._queue.append(job)
        self._stats["accepted"] += 1
        return len(self._queue)

    # -- draining ---------------------------------------------------------
    def process(self, *, now):
        done, failed = [], {}

        for _ in range(min(self.max_batch, len(self._queue))):
            job = self._queue.pop(0)
            try:
                self._breaker.call(lambda j=job: self.handler(j), now=now)
            except Overloaded:
                failed[job["id"]] = "circuit_open"
                self._stats["failed"] += 1
            except Exception as exc:                 # recorded, never swallowed
                failed[job["id"]] = f"error: {exc}"
                self._stats["failed"] += 1
            else:
                done.append(job["id"])
                self._stats["done"] += 1

        return {"done": done, "failed": failed, "remaining": len(self._queue)}

    def stats(self):
        return dict(self._stats)


w = Worker(lambda job: job["payload"].upper())
w.submit({"id": "j1", "client": "ada", "payload": "hello"}, now=0.0)
print(w.process(now=0.0))`,
        why: `Six resources, six numbers, and every one of them produces either an exception the caller can act on or a counter an operator can graph. Nothing is dropped silently, which means the worker's own reports are trustworthy — the property that makes an incident diagnosable at 3 a.m.

The check order in \`submit\` is a resource decision. Shape and payload size are rejected first because they cost nothing to evaluate. The rate limit comes *before* the queue depth so that a throttled client never occupies a queue slot: reversed, one abusive client could fill the queue with jobs that were going to be rejected anyway, starving everyone else — a limiter that creates the contention it was meant to prevent.

In \`process\`, the breaker wraps the handler rather than the loop. A dependency that has failed \`threshold\` times in a row stops being called at all, and the remaining jobs in the batch fail fast with \`circuit_open\` instead of each waiting for its own timeout. The test asserting the handler was called exactly twice out of five jobs is the proof: load is actually removed from the struggling dependency, which is the only reason a breaker exists.

\`lambda j=job: self.handler(j)\` binds the job as a default argument. Writing \`lambda: self.handler(job)\` would capture the *variable*, and in a loop that is the classic late-binding bug — though here each call happens before the next iteration, so it would work by accident. Binding explicitly makes it work by construction.

The \`except Exception\` in the drain loop is broad on purpose and is not a swallowed error: the exception text goes into \`failed\`, the counter increments, and the caller receives both. It stops at \`Exception\` rather than \`BaseException\`, so \`KeyboardInterrupt\` still stops the process — the distinction from Module 4 that makes the difference between a worker you can deploy and one you have to \`kill -9\`.`,
      },
      wrapup: `- Name every resource an attacker can influence and attach a number to it.
- Reject early and visibly: an error for the caller, a counter for the operator.
- Group failures by reason — attack, overload and misconfiguration need different responses.
- A circuit breaker removes load from a failing dependency and returns fast to your own callers.`,
      refs: [
        { label: "CWE-400: Uncontrolled Resource Consumption", url: "https://cwe.mitre.org/data/definitions/400.html" },
        { label: "Release It! — stability patterns (Nygard)", url: "https://pragprog.com/titles/mnee2/release-it-second-edition/" },
      ],
    },
  ],
};
