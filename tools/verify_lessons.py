"""Run every lesson's reference solution through the real grader.

    node tools/verify.mjs && python3 tools/verify_lessons.py

A solution must be accepted (tests pass, no blocking finding, requirements met).
A starter must not crash the harness in a way that looks like a bug in the course
(a NameError from an unimplemented function is expected and fine; a SyntaxError is
not -- the learner should never open a lesson on broken code).
"""

import json
import os
import sys

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, os.path.join(ROOT, "py"))
import sandbox  # noqa: E402

JOBS = os.path.join(ROOT, ".verify-jobs.json")

with open(JOBS, encoding="utf-8") as fh:
    jobs = json.load(fh)

# Lessons that touch the filesystem write under the working directory, exactly as
# they do in the browser's in-memory filesystem. Run them in a scratch directory.
import tempfile

os.chdir(tempfile.mkdtemp(prefix="spt-verify-"))

sol_fail, start_fail, ok = [], [], 0

for job in jobs:
    r = sandbox.run_submission(
        job["code"], job["stdin"], job["tests"], job["requirements"], job.get("setup", "")
    )
    label = f"day {job['day']:>2} {job['id']} — {job['title']}"

    if job["kind"] == "solution":
        if r["passed"]:
            ok += 1
            continue
        why = []
        if r["error"]:
            why.append(f"error: {r['error']}")
        for t in r["tests"]:
            if not t["passed"]:
                why.append(f"test '{t['name']}' failed: {t['message']}")
        for f in r["findings"]:
            if f["severity"] in ("critical", "high"):
                why.append(f"auditor {f['id']} ({f['severity']}) line {f['line']}: {f['title']}")
        for u in r["unmet"]:
            why.append(f"requirement unmet: {u['message']}")
        sol_fail.append((label, why))
    else:
        if r["syntax"]:
            start_fail.append((label, [f"starter has a syntax error: {r['error']}"]))
        else:
            ok += 1

print(f"\n{ok}/{len(jobs)} jobs clean")

for title, rows in sol_fail:
    print(f"\nSOLUTION REJECTED — {title}")
    for row in rows:
        print("   ", row)
for title, rows in start_fail:
    print(f"\nSTARTER BROKEN — {title}")
    for row in rows:
        print("   ", row)

sys.exit(1 if (sol_fail or start_fail) else 0)
