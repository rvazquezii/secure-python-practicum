/* Content integrity check.
   Usage: node tools/verify.mjs [outfile.json]

   Validates the structure of every lesson, then writes a JSON job file that
   py/verify_lessons.py executes: each reference solution must pass its own tests
   and the auditor, and each starter must not crash the harness.             */

import { readdir, writeFile } from "node:fs/promises";
import { fileURLToPath } from "node:url";
import { dirname, join } from "node:path";

const here = dirname(fileURLToPath(import.meta.url));
const contentDir = join(here, "..", "content");
const out = process.argv[2] || join(here, "..", ".verify-jobs.json");

const problems = [];
const bad = (where, msg) => problems.push(`${where}: ${msg}`);

const files = (await readdir(contentDir)).filter((f) => /^m\d\d\.js$/.test(f)).sort();
if (!files.length) {
  console.error("no content modules found");
  process.exit(1);
}

const modules = [];
for (const f of files) {
  const mod = (await import(join(contentDir, f))).default;
  modules.push({ file: f, ...mod });
}

const ids = new Set();
const days = [];
const jobs = [];

for (const m of modules) {
  const where = m.file;
  for (const field of ["id", "number", "title", "subtitle", "focus", "objectives", "rules", "capstone", "lessons"]) {
    if (m[field] === undefined) bad(where, `module is missing "${field}"`);
  }
  if (!Array.isArray(m.lessons) || m.lessons.length === 0) {
    bad(where, "module has no lessons");
    continue;
  }

  for (const l of m.lessons) {
    const w = `${m.file} ${l.id}`;
    for (const field of ["id", "day", "title", "secure", "lede", "blocks", "quiz", "exercise", "wrapup"]) {
      if (l[field] === undefined) bad(w, `lesson is missing "${field}"`);
    }
    if (ids.has(l.id)) bad(w, "duplicate lesson id");
    ids.add(l.id);
    if (!l.id?.startsWith(m.id)) bad(w, `lesson id should start with module id "${m.id}"`);
    days.push({ day: l.day, id: l.id });

    for (const b of l.blocks || []) {
      if (!b.t) bad(w, "block without a type");
      if (b.t === "p" && !b.md) bad(w, "prose block without md");
      if (b.t === "code" && !b.code) bad(w, "code block without code");
      if (b.t === "table" && (!b.head || !b.rows)) bad(w, "table block needs head and rows");
      if (b.t === "box" && !b.kind) bad(w, "box block without kind");
      if (b.t === "box" && !["note", "rule", "warn", "pitfall", "cve", "good", "try"].includes(b.kind)) {
        bad(w, `unknown box kind "${b.kind}"`);
      }
    }

    (l.quiz || []).forEach((q, i) => {
      if (!q.q || !q.options || q.why === undefined) bad(w, `quiz ${i} incomplete`);
      if (!(q.answer >= 0 && q.answer < (q.options?.length ?? 0))) bad(w, `quiz ${i} answer out of range`);
      if ((q.options?.length ?? 0) < 2) bad(w, `quiz ${i} needs at least two options`);
    });

    if (l.spot) {
      const n = l.spot.code?.split("\n").length ?? 0;
      if (!l.spot.lines?.length) bad(w, "spot drill without lines");
      for (const ln of l.spot.lines || []) {
        if (ln < 1 || ln > n) bad(w, `spot line ${ln} outside the 1..${n} snippet`);
      }
      if (!l.spot.why) bad(w, "spot drill without an explanation");
    }

    const ex = l.exercise;
    if (ex) {
      for (const field of ["title", "brief", "starter", "tests", "solution", "hints", "rubric", "why"]) {
        if (ex[field] === undefined) bad(w, `exercise is missing "${field}"`);
      }
      if (!ex.tests?.length) bad(w, "exercise has no tests");
      (ex.tests || []).forEach((t, i) => {
        if (!t.name || !t.code) bad(w, `test ${i} needs a name and code`);
      });
      jobs.push({
        id: l.id,
        day: l.day,
        title: l.title,
        kind: "solution",
        code: ex.solution,
        stdin: ex.stdin || [],
        tests: ex.tests || [],
        requirements: ex.requirements || [],
        setup: ex.setup || "",
      });
      jobs.push({
        id: l.id,
        day: l.day,
        title: l.title,
        kind: "starter",
        code: ex.starter,
        stdin: ex.stdin || [],
        tests: [],
        requirements: [],
        setup: ex.setup || "",
      });
    }
  }
}

days.sort((a, b) => a.day - b.day);
days.forEach((d, i) => {
  if (d.day !== i + 1) bad(d.id, `day numbering gap: expected day ${i + 1}, found ${d.day}`);
});

await writeFile(out, JSON.stringify(jobs, null, 1));

console.log(`modules: ${modules.length}  lessons: ${ids.size}  jobs: ${jobs.length}`);
if (problems.length) {
  console.error(`\n${problems.length} structural problem(s):`);
  problems.forEach((p) => console.error("  " + p));
  process.exit(1);
}
console.log("structure OK");
