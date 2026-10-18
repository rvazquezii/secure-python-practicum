/* Application shell: routing, the lesson workbench, grading, console, search. */

import { MODULES, LESSON_INDEX, COURSE } from "../content/curriculum.js";
import { store, startClock, today } from "./store.js";
import * as py from "./py.js";
import { Editor } from "./editor.js";
import { blocks, quizHTML, spotHTML, md, inline, esc } from "./render.js";

const $ = (sel, root = document) => root.querySelector(sel);
const $$ = (sel, root = document) => [...root.querySelectorAll(sel)];
const SEV_RANK = { critical: 0, high: 1, medium: 2, low: 3, info: 4 };

let editor = null;
let current = null; // {module, lesson, index}
let lastResult = null;
let activeTab = "output";
let auditTimer = null;
let scratchStdin = null;   // stdin of the snippet currently loaded as scratch

/* ======================================================================== */
/* boot                                                                      */
/* ======================================================================== */
(async function main() {
  applyTheme(store.get("theme") || "auto");
  if (store.get("railOpen") === false) document.querySelector(".shell").classList.add("shell--norail");
  buildRail();
  wireChrome();
  renderMeters();
  window.addEventListener("hashchange", route);

  try {
    await py.boot((text, frac) => {
      $("#bootStatus").textContent = text;
      $("#bootFill").style.width = `${Math.round(frac * 100)}%`;
    });
    $("#boot").classList.add("boot--gone");
    setTimeout(() => $("#boot").setAttribute("hidden", ""), 500);
    $("#replLed").classList.add("led--on");
    replPrint("note", `CPython ${py.version()} ready. The OS is simulated: os.system, subprocess, requests,\nyaml and jwt are instrumented so attacks are visible and harmless.`);
  } catch (e) {
    const msg = String(e.message || e);
    $("#bootStatus").textContent = "could not start the interpreter";
    $("#bootNote").innerHTML = msg.startsWith("FILE_PROTOCOL")
      ? `This page is open as a file. Python needs an HTTP origin.<br><br>
         <code>cd "${esc(location.pathname.replace(/\/index\.html$/, ""))}"</code><br>
         <code>./serve.sh</code><br><br>then open <strong>http://localhost:8800</strong>`
      : `${esc(msg)}<br><br>The lesson text works offline, but running code needs the Python runtime
         (downloaded once from a CDN, then cached by your browser).`;
    $("#boot").querySelector(".boot__bar").style.display = "none";
    setTimeout(() => $("#boot").classList.add("boot--gone"), 6000);
    setTimeout(() => $("#boot").setAttribute("hidden", ""), 6500);
  }

  route();
  startClock(renderMeters);
})();

/* ======================================================================== */
/* chrome                                                                    */
/* ======================================================================== */
function applyTheme(mode) {
  document.documentElement.setAttribute("data-theme", mode === "auto" ? "auto" : mode);
  if (mode === "auto") document.documentElement.removeAttribute("data-theme");
  store.set("theme", mode);
}

function wireChrome() {
  $("#themeToggle").addEventListener("click", () => {
    const order = ["auto", "light", "dark"];
    const next = order[(order.indexOf(store.get("theme") || "auto") + 1) % 3];
    applyTheme(next);
    toast(`Theme: ${next}`);
  });

  $("#railToggle").addEventListener("click", () => {
    const shell = document.querySelector(".shell");
    if (window.matchMedia("(max-width: 860px)").matches) {
      shell.classList.toggle("shell--railopen");
      return;
    }
    const closed = shell.classList.toggle("shell--norail");
    store.set("railOpen", !closed);
    $("#railToggle").setAttribute("aria-expanded", String(!closed));
  });

  // wrap it: passing the listener directly hands the click Event in as `force`,
  // which is truthy, so the drawer would open and never close.
  $("#drawerToggle").addEventListener("click", () => toggleDrawer());
  $("#replClear").addEventListener("click", () => {
    $("#replOut").innerHTML = "";
  });
  $("#replReset").addEventListener("click", () => {
    py.replReset();
    replPrint("note", "namespace cleared");
  });
  $("#replInput").addEventListener("keydown", replKey);

  $("#helpToggle").addEventListener("click", () => $("#helpModal").removeAttribute("hidden"));
  $("#helpClose").addEventListener("click", () => $("#helpModal").setAttribute("hidden", ""));
  $("#helpModal").addEventListener("click", (e) => {
    if (e.target.id === "helpModal") $("#helpModal").setAttribute("hidden", "");
  });

  $("#exportBtn").addEventListener("click", () => {
    const blob = new Blob([store.exportJSON()], { type: "application/json" });
    const a = document.createElement("a");
    a.href = URL.createObjectURL(blob);
    a.download = `secure-python-progress-${today()}.json`;
    a.click();
    URL.revokeObjectURL(a.href);
  });
  $("#importBtn").addEventListener("click", () => $("#importFile").click());
  $("#importFile").addEventListener("change", async (e) => {
    const file = e.target.files?.[0];
    if (!file) return;
    try {
      store.importJSON(await file.text());
      buildRail();
      renderMeters();
      route();
      toast("Progress imported");
    } catch (err) {
      toast(`Import failed: ${err.message}`);
    }
  });

  wireSearch();
  document.addEventListener("keydown", globalKeys);

  // "send to editor" buttons inside lesson prose
  $("#main").addEventListener("click", (e) => {
    const btn = e.target.closest("[data-load-code]");
    if (!btn || !editor) return;
    const code = btn.closest(".snippet").querySelector("pre").textContent.replace(/\n$/, "");
    // Deliberately not saved: an example is scratch material, and overwriting the
    // learner's stored exercise answer with it would lose their work. Leaving the
    // lesson and returning restores whatever they had written.
    editor.value = code;
    clearResults();
    // after clearResults, which resets it: an example brings its own stdin so it
    // never silently consumes the exercise's fixture
    try {
      scratchStdin = JSON.parse(btn.dataset.stdin || "[]");
    } catch {
      scratchStdin = [];
    }
    scheduleAudit();
    revealEditor();
    toast("Loaded as scratch — Run it; Submit still grades your exercise");
    editor.focus();
  });
}

function globalKeys(e) {
  const typing = /^(INPUT|TEXTAREA)$/.test(e.target.tagName);
  if (e.key === "Escape") {
    $("#helpModal").setAttribute("hidden", "");
    $("#searchResults").hidden = true;
  }
  if (e.ctrlKey && e.key === "`") {
    e.preventDefault();
    toggleDrawer();
    return;
  }
  if (typing) return;
  if (e.key === "/") {
    e.preventDefault();
    $("#search").focus();
  }
  if (e.key === "?") {
    e.preventDefault();
    $("#helpModal").removeAttribute("hidden");
  }
  if (e.altKey && e.key === "ArrowRight" && current?.next) location.hash = `#/${current.next.id}`;
  if (e.altKey && e.key === "ArrowLeft" && current?.prev) location.hash = `#/${current.prev.id}`;
}

/* The workbench sits in the right column on a wide window and at the foot of the
   page on a narrow one, where the open console also covers the bottom of the
   screen. Loading code into it is useless if it stays off-screen -- and aligning
   its BOTTOM to the free space needs less scroll room than aligning its top,
   which matters because the page may not be tall enough for the latter. */
function revealEditor() {
  const panel = $(".panel");
  const host = $("#editorHost");
  if (!panel || !host) return;

  const drawer = $("#drawer");
  const floor = drawer?.classList.contains("drawer--open")
    ? drawer.getBoundingClientRect().top
    : window.innerHeight;

  const box = host.getBoundingClientRect();
  if (box.top >= 0 && box.bottom <= floor) return;   // already usable

  const panelBox = panel.getBoundingClientRect();
  const gap = 8;
  const delta = panelBox.height <= floor - gap
    ? panelBox.bottom - (floor - gap)                // whole panel fits: show the footer
    : panelBox.top - gap;                            // taller than the space: show the top

  // A smooth scroll across thousands of pixels is slow and disorienting; only
  // animate short hops.
  const behavior = Math.abs(delta) > window.innerHeight * 1.5 ? "auto" : "smooth";
  window.scrollBy({ top: delta, behavior });
}

function toast(msg) {
  let el = $(".toast");
  if (!el) {
    el = document.createElement("div");
    el.className = "toast";
    document.body.appendChild(el);
  }
  el.textContent = msg;
  requestAnimationFrame(() => el.classList.add("toast--on"));
  clearTimeout(el._t);
  el._t = setTimeout(() => el.classList.remove("toast--on"), 2200);
}

/* ======================================================================== */
/* meters & rail                                                             */
/* ======================================================================== */
function renderMeters() {
  const mins = store.minutesToday();
  const frac = Math.min(mins / store.goal, 1);
  const ring = $("#todayRing");
  ring.style.strokeDashoffset = String(100.5 * (1 - frac));
  ring.classList.toggle("ring__fill--full", frac >= 1);
  $("#todayMin").textContent = mins;
  $("#streakVal").textContent = store.streak();
  $("#doneVal").textContent = store.doneCount();
  $("#totalVal").textContent = LESSON_INDEX.length;
  $("#railProgress").style.width = `${(store.doneCount() / LESSON_INDEX.length) * 100}%`;
}

function buildRail() {
  const body = $("#railBody");
  body.innerHTML = MODULES.map((m) => {
    const done = m.lessons.filter((l) => store.isDone(l.id)).length;
    return `<div class="mod" data-mod="${m.id}">
      <button class="mod__btn" aria-expanded="false" data-modbtn="${m.id}">
        <span class="mod__n">M${String(m.number).padStart(2, "0")}</span>
        <span class="mod__t">${esc(m.title)}</span>
        <span class="mod__meta num">${done}/${m.lessons.length}</span>
      </button>
      <ul class="mod__list" data-modlist="${m.id}">
        ${m.lessons
          .map(
            (l) => `<li><a href="#/${l.id}" data-lesson="${l.id}">
              <span class="day num">${l.day}</span>
              <span>${store.isDone(l.id) ? '<span class="tick">✓</span> ' : ""}${esc(l.title)}</span>
            </a></li>`
          )
          .join("")}
      </ul>
    </div>`;
  }).join("");

  $$("[data-modbtn]", body).forEach((btn) =>
    btn.addEventListener("click", () => {
      const list = $(`[data-modlist="${btn.dataset.modbtn}"]`);
      const open = list.classList.toggle("mod__list--open");
      btn.setAttribute("aria-expanded", String(open));
    })
  );
  body.addEventListener("click", (e) => {
    if (e.target.closest("a") && window.matchMedia("(max-width: 860px)").matches) {
      document.querySelector(".shell").classList.remove("shell--railopen");
    }
  });
}

function highlightRail(lessonId, modId) {
  $$("[data-lesson]").forEach((a) => a.removeAttribute("aria-current"));
  const a = $(`[data-lesson="${lessonId}"]`);
  if (a) {
    a.setAttribute("aria-current", "page");
    const list = $(`[data-modlist="${modId}"]`);
    if (list && !list.classList.contains("mod__list--open")) {
      list.classList.add("mod__list--open");
      $(`[data-modbtn="${modId}"]`)?.setAttribute("aria-expanded", "true");
    }
    a.scrollIntoView({ block: "nearest" });
  }
}

/* ======================================================================== */
/* routing                                                                   */
/* ======================================================================== */
function route() {
  const hash = location.hash.replace(/^#\/?/, "");
  window.scrollTo({ top: 0 });
  if (!hash) return renderOverview();
  const lesson = LESSON_INDEX.find((l) => l.id === hash);
  if (lesson) return renderLesson(lesson.id);
  const mod = MODULES.find((m) => m.id === hash);
  if (mod) return renderModule(mod);
  renderOverview();
}

function nextUnfinished() {
  return LESSON_INDEX.find((l) => !store.isDone(l.id)) || LESSON_INDEX[0];
}

/* ------------------------------------------------------------- overview --- */
function renderOverview() {
  current = null;
  editor = null;
  const nxt = nextUnfinished();
  const hist = store.history(28);
  const totalMin = Object.values(store.all.minutes).reduce((a, b) => a + b, 0);

  $("#main").innerHTML = `<div class="wrap">
    <section class="hero">
      <div class="hero__top">
        <span class="pill pill--accent">${COURSE.lessons} lessons · ${COURSE.modules} modules</span>
        <span class="pill">${COURSE.hours} hours at one hour a day</span>
        <span class="pill pill--brass">${COURSE.rules} auditor rules</span>
      </div>
      <h1 class="h1">Write Python that does not become someone else's attack surface.</h1>
      <p class="lede hero__lede">${inline(COURSE.lede)}</p>
      <div class="hero__stats">
        <div class="stat"><span class="stat__v num">${store.doneCount()}/${LESSON_INDEX.length}</span><span class="stat__l">Lessons complete</span></div>
        <div class="stat"><span class="stat__v num">${store.streak()}</span><span class="stat__l">Day streak</span></div>
        <div class="stat"><span class="stat__v num">${Math.round(totalMin / 60)}h</span><span class="stat__l">Time at the keyboard</span></div>
        <div class="stat"><span class="stat__v num">${store.minutesToday()}/60</span><span class="stat__l">Today</span></div>
      </div>
      <div style="display:flex;gap:.6rem;flex-wrap:wrap;align-items:center">
        <a class="btn" href="#/${nxt.id}">${store.doneCount() ? "Resume" : "Start"} — Day ${nxt.day}: ${esc(nxt.title)}</a>
        <button class="btn btn--ghost" id="openConsole">Open the Python console</button>
      </div>
    </section>

    <section class="contract">
      <span class="eyebrow">How the grading works</span>
      ${md(COURSE.contract)}
    </section>

    <section style="padding:1.6rem 0 0">
      <span class="eyebrow">Last 28 days</span>
      <div class="heat" style="margin-top:.5rem" role="img" aria-label="Practice history, last 28 days">
        ${hist
          .map((d) => {
            const cls = d.minutes >= 60 ? "heat__cell--done" : d.minutes >= 20 ? "heat__cell--try" : "";
            const glyph = d.minutes >= 60 ? "✓" : d.minutes >= 20 ? "·" : "";
            return `<span class="heat__cell ${cls}" title="${d.date}: ${d.minutes} min">${glyph}</span>`;
          })
          .join("")}
      </div>
      <p style="font-size:.84rem;color:var(--ink-2);margin:.5rem 0 0">
        <span class="pill pill--pass">✓ 60+ min</span> <span class="pill pill--brass">· 20+ min</span>
        <span class="pill">empty</span> — a streak needs 20 minutes minimum, which is the floor that keeps the habit alive on a bad day.
      </p>
    </section>

    <section class="modgrid">
      ${MODULES.map((m) => {
        const done = m.lessons.filter((l) => store.isDone(l.id)).length;
        return `<a class="modcard" href="#/${m.id}">
          <div class="modcard__head">
            <span class="eyebrow">Module ${String(m.number).padStart(2, "0")}</span>
            <span class="pill">Days ${m.lessons[0].day}–${m.lessons[m.lessons.length - 1].day}</span>
          </div>
          <h3>${esc(m.title)}</h3>
          <p>${inline(m.subtitle)}</p>
          <div class="modcard__bar"><div class="modcard__barfill" style="width:${(done / m.lessons.length) * 100}%"></div></div>
          <div class="modcard__foot"><span>${done}/${m.lessons.length} complete</span><span>${esc(m.focus)}</span></div>
        </a>`;
      }).join("")}
    </section>
  </div>`;

  $("#openConsole")?.addEventListener("click", () => toggleDrawer(true));
  renderMeters();
}

/* --------------------------------------------------------------- module --- */
function renderModule(m) {
  current = null;
  editor = null;
  const done = m.lessons.filter((l) => store.isDone(l.id)).length;
  $("#main").innerHTML = `<div class="wrap">
    <nav class="crumbs"><a href="#/">Course</a> › <span>Module ${String(m.number).padStart(2, "0")}</span></nav>
    <section class="hero" style="padding-top:.4rem">
      <div class="hero__top">
        <span class="pill pill--accent">Module ${String(m.number).padStart(2, "0")}</span>
        <span class="pill">Days ${m.lessons[0].day}–${m.lessons[m.lessons.length - 1].day}</span>
        <span class="pill">${m.lessons.length} lessons · ~${m.lessons.length} hours</span>
        <span class="pill ${done === m.lessons.length ? "pill--pass" : ""}">${done}/${m.lessons.length} complete</span>
      </div>
      <h1 class="h1" style="font-size:var(--step-3)">${esc(m.title)}</h1>
      <p class="lede hero__lede">${inline(m.subtitle)}</p>
    </section>

    <div class="lesson" style="grid-template-columns:minmax(0,1fr) minmax(300px,.6fr)">
      <div class="prose">
        <h2>What you will be able to do</h2>
        ${md(m.objectives.map((o) => `- ${o}`).join("\n"))}
        <h2>Lessons</h2>
        <div class="tablewrap"><table class="data"><thead><tr><th>Day</th><th>Lesson</th><th>Secure focus</th><th>Status</th></tr></thead><tbody>
        ${m.lessons
          .map(
            (l) => `<tr>
            <td class="num">${l.day}</td>
            <td><a href="#/${l.id}">${esc(l.title)}</a></td>
            <td>${inline(l.secure)}</td>
            <td>${store.isDone(l.id) ? '<span class="pill pill--pass">✓ done</span>' : store.lesson(l.id).attempts ? '<span class="pill pill--brass">in progress</span>' : '<span class="pill">not started</span>'}</td>
          </tr>`
          )
          .join("")}
        </tbody></table></div>
      </div>
      <aside>
        <div class="box box--rule" style="margin-top:0">
          <div class="box__head"><span class="box__glyph">§</span><span>Rules enforced here</span></div>
          <div class="box__body">${md(m.rules.map((r) => `- \`${r.id}\` — ${r.what}`).join("\n"))}</div>
        </div>
        <div class="box box--try">
          <div class="box__head"><span class="box__glyph">›</span><span>Capstone</span></div>
          <div class="box__body">${md(m.capstone)}</div>
        </div>
      </aside>
    </div>
  </div>`;
}

/* --------------------------------------------------------------- lesson --- */
function renderLesson(id) {
  const idx = LESSON_INDEX.findIndex((l) => l.id === id);
  const meta = LESSON_INDEX[idx];
  const mod = MODULES.find((m) => m.id === meta.moduleId);
  const lesson = mod.lessons.find((l) => l.id === id);
  current = {
    module: mod,
    lesson,
    prev: LESSON_INDEX[idx - 1] || null,
    next: LESSON_INDEX[idx + 1] || null,
  };
  lastResult = null;
  activeTab = "output";
  store.set("last", id);

  const saved = store.lesson(id);
  const ex = lesson.exercise;

  $("#main").innerHTML = `<div class="wrap">
    <div class="lesson">
      <article class="lesson__read">
        <nav class="crumbs">
          <a href="#/">Course</a> › <a href="#/${mod.id}">M${String(mod.number).padStart(2, "0")} ${esc(mod.title)}</a> › <span>Day ${lesson.day}</span>
        </nav>
        <header class="lesson__head">
          <span class="eyebrow">Day ${lesson.day} · ${lesson.minutes || 60} minutes</span>
          <h1 class="lesson__title">${esc(lesson.title)}</h1>
          <div class="lesson__facts">
            ${store.isDone(id) ? '<span class="pill pill--pass">✓ completed</span>' : ""}
            <span class="pill pill--accent">${esc(lesson.secure)}</span>
            ${(lesson.cwe || []).map((c) => `<span class="pill">${esc(c)}</span>`).join("")}
          </div>
          <p class="lede">${inline(lesson.lede)}</p>
        </header>

        <div class="prose">${blocks(lesson.blocks)}</div>
        ${spotHTML(lesson.spot)}
        ${quizHTML(lesson.quiz)}

        <div class="prose">
          <h2>Exercise — ${esc(ex.title)}</h2>
          ${md(ex.brief)}
          ${ex.rubric ? `<div class="box box--rule"><div class="box__head"><span class="box__glyph">§</span><span>The grader checks</span></div><div class="box__body"><ol class="rubric">${ex.rubric.map((r) => `<li>${inline(r)}</li>`).join("")}</ol></div></div>` : ""}
        </div>

        ${lesson.wrapup ? `<div class="prose wrapup"><h2>Takeaways</h2>${md(lesson.wrapup)}</div>` : ""}
        ${
          lesson.refs?.length
            ? `<div class="prose"><h3>Primary sources</h3>${md(
                lesson.refs.map((r) => `- [${r.label}](${r.url})`).join("\n")
              )}</div>`
            : ""
        }

        <nav class="lessonnav">
          ${
            current.prev
              ? `<a href="#/${current.prev.id}"><span class="eyebrow">← Day ${current.prev.day}</span><strong>${esc(current.prev.title)}</strong></a>`
              : `<a href="#/" ><span class="eyebrow">←</span><strong>Course overview</strong></a>`
          }
          ${
            current.next
              ? `<a href="#/${current.next.id}"><span class="eyebrow">Day ${current.next.day} →</span><strong>${esc(current.next.title)}</strong></a>`
              : `<a href="#/"><span class="eyebrow">→</span><strong>You reached the end. Review.</strong></a>`
          }
        </nav>
      </article>

      <aside class="panel">
        <div class="panel__head">
          <span class="panel__title">Workbench</span>
          <div class="panel__leds">
            <span class="ledlabel">run</span><span class="led" id="ledRun"></span>
            <span class="ledlabel">tests</span><span class="led" id="ledTests"></span>
            <span class="ledlabel">audit</span><span class="led" id="ledAudit"></span>
          </div>
        </div>
        <div id="editorHost"></div>
        <div>
          <div class="tabs" role="tablist">
            <button class="tab" role="tab" data-tab="output" aria-selected="true">Output</button>
            <button class="tab" role="tab" data-tab="tests" aria-selected="false">Tests <span class="tab__n" id="nTests">${ex.tests.length}</span></button>
            <button class="tab" role="tab" data-tab="audit" aria-selected="false">Audit <span class="tab__n" id="nAudit">0</span></button>
            <button class="tab" role="tab" data-tab="breach" aria-selected="false">Breach <span class="tab__n" id="nBreach">0</span></button>
            <button class="tab" role="tab" data-tab="help" aria-selected="false">Help</button>
          </div>
          <div class="panel__body" id="panelBody"></div>
        </div>
        <div class="panel__foot">
          <button class="btn" id="runBtn">Run <span class="btn__kbd">⌘↵</span></button>
          <button class="btn btn--ghost" id="submitBtn">Submit <span class="btn__kbd">⌘⇧↵</span></button>
          <span class="spacer"></span>
          <button class="btn btn--quiet" id="resetBtn">Reset</button>
          <button class="btn btn--quiet" id="solutionBtn">Solution</button>
        </div>
      </aside>
    </div>
  </div>`;

  editor = new Editor($("#editorHost"), {
    value: saved.code ?? ex.starter,
    onChange: (code) => {
      store.saveCode(id, code);
      scheduleAudit();
    },
    onRun: doRun,
    onSubmit: doSubmit,
  });

  $("#runBtn").addEventListener("click", doRun);
  $("#submitBtn").addEventListener("click", doSubmit);
  $("#resetBtn").addEventListener("click", () => {
    editor.value = ex.starter;
    store.saveCode(id, ex.starter);
    clearResults();
    scheduleAudit();
    revealEditor();
    toast("Starter code restored");
  });
  $("#solutionBtn").addEventListener("click", showSolution);
  $$(".tab").forEach((t) => t.addEventListener("click", () => selectTab(t.dataset.tab)));

  wireQuiz(lesson);
  wireSpot(lesson);
  highlightRail(id, mod.id);
  clearResults();
  scheduleAudit();
}

/* Results belong to the code that produced them. Leaving a verdict on screen
   after the editor changes is the false assurance this whole course is about. */
function clearResults() {
  lastResult = null;
  scratchStdin = null;
  const total = (current?.lesson.exercise.tests || []).length;

  ["#ledRun", "#ledTests", "#ledAudit"].forEach((id) => led(id, ""));
  $("#nTests").textContent = String(total);
  $("#nTests").className = "tab__n";
  $("#nAudit").textContent = "0";
  $("#nAudit").className = "tab__n";
  $("#nBreach").textContent = "0";
  $("#nBreach").className = "tab__n";

  selectTab("output");
  setPanel(
    `<p class="out__meta">no run yet</p><p class="empty">Write code, then press Run (⌘↵ / ⌃↵) to execute it.
     Submit (⌘⇧↵) grades correctness and security together.</p>`
  );
}

/* ======================================================================== */
/* workbench                                                                 */
/* ======================================================================== */
function selectTab(name) {
  activeTab = name;
  $$(".tab").forEach((t) => t.setAttribute("aria-selected", String(t.dataset.tab === name)));
  paintPanel();
}

function setPanel(html) {
  $("#panelBody").innerHTML = html;
}

function led(id, cls) {
  const el = $(id);
  if (!el) return;
  el.className = "led" + (cls ? ` led--${cls}` : "");
}

function scheduleAudit() {
  clearTimeout(auditTimer);
  auditTimer = setTimeout(() => {
    if (!current || !py.ready()) return;
    const a = py.audit(editor.value, current.lesson.exercise.requirements || []);
    const flags = a.findings.map((f) => f.line);
    editor.setFlags(flags);
    const worst = a.findings[0]?.severity;
    $("#nAudit").textContent = a.findings.length;
    $("#nAudit").className = `tab__n${a.findings.length ? (SEV_RANK[worst] <= 1 ? " tab__n--bad" : " tab__n--warn") : " tab__n--good"}`;
    led("#ledAudit", a.findings.length ? (SEV_RANK[worst] <= 1 ? "bad" : "warn") : "on");
    if (!lastResult) lastResult = { findings: a.findings, good: a.good, unmet: a.unmet, tests: [], breaches: [] };
    else Object.assign(lastResult, { findings: a.findings, good: a.good, unmet: a.unmet });
    if (activeTab === "audit") paintPanel();
  }, 420);
}

/* Deliberately setTimeout and not requestAnimationFrame: rAF is paused in a
   background tab, which would make Run silently do nothing after a tab switch.
   The delay exists only so the "busy" LED paints before CPython blocks the thread. */
function execute(grading) {
  if (!py.ready()) return toast("The interpreter is still loading");
  const ex = current.lesson.exercise;
  led("#ledRun", "busy");
  if (grading) {
    store.attempt(current.lesson.id);
    scratchStdin = null;
  }
  setTimeout(() => {
    try {
      // Run executes; only Submit grades. Checking a four-line example from the
      // lesson against the exercise's test suite reports failure for code that
      // was never meant to satisfy it.
      lastResult = py.run({
        code: editor.value,
        stdin: grading ? ex.stdin || [] : scratchStdin ?? ex.stdin ?? [],
        tests: grading ? ex.tests || [] : [],
        requirements: grading ? ex.requirements || [] : [],
        setup: ex.setup || "",
      });
      lastResult.graded = grading;
    } catch (e) {
      led("#ledRun", "bad");
      selectTab("output");
      setPanel(`<p class="out__meta">interpreter error</p><pre class="out out--err">${esc(String(e.message || e))}</pre>`);
      return;
    }
    afterRun(grading);
  }, 16);
}

const doRun = () => execute(false);
const doSubmit = () => execute(true);

function afterRun(grading) {
  const r = lastResult;
  led("#ledRun", r.error ? "bad" : "on");
  const failed = r.tests.filter((t) => !t.passed).length;
  led("#ledTests", grading && r.tests.length ? (failed ? "bad" : "on") : "");
  const worst = r.findings[0]?.severity;
  led("#ledAudit", r.findings.length ? (SEV_RANK[worst] <= 1 ? "bad" : "warn") : "on");

  const total = (current.lesson.exercise.tests || []).length;
  $("#nTests").textContent = grading ? `${r.tests.filter((t) => t.passed).length}/${r.tests.length}` : `${total}`;
  $("#nTests").className = `tab__n${grading && r.tests.length ? (failed ? " tab__n--bad" : " tab__n--good") : ""}`;
  $("#nAudit").textContent = r.findings.length;
  $("#nAudit").className = `tab__n${r.findings.length ? (SEV_RANK[worst] <= 1 ? " tab__n--bad" : " tab__n--warn") : " tab__n--good"}`;
  $("#nBreach").textContent = (r.breaches || []).length;
  $("#nBreach").className = `tab__n${(r.breaches || []).length ? " tab__n--bad" : ""}`;
  editor.setFlags(r.findings.map((f) => f.line));

  if (grading) {
    if (r.passed) {
      const fresh = store.complete(current.lesson.id);
      buildRail();
      highlightRail(current.lesson.id, current.module.id);
      renderMeters();
      toast(fresh ? "Lesson complete — correct and clean" : "Still passing");
    }
    selectTab(r.error ? "output" : failed ? "tests" : r.findings.length || r.unmet.length ? "audit" : "output");
  } else {
    selectTab(r.error ? "output" : activeTab);
  }
  paintPanel();
}

function paintPanel() {
  const r = lastResult;
  if (!r) return;
  if (activeTab === "output") return setPanel(outputHTML(r));
  if (activeTab === "tests") return setPanel(testsHTML(r));
  if (activeTab === "audit") return setPanel(auditHTML(r));
  if (activeTab === "breach") return setPanel(breachHTML(r));
  if (activeTab === "help") return setPanel(helpHTML());
}

function verdictHTML(r) {
  if (!r.graded || r.passed === undefined) return "";
  if (r.passed) {
    return `<div class="verdict verdict--pass">
      <span class="verdict__t">✓ Accepted — correct and clean</span>
      <span style="font-size:.86rem">All tests pass, no blocking findings, every requirement met.
      ${current.next ? `Next: <a href="#/${current.next.id}">Day ${current.next.day}</a>.` : ""}</span></div>`;
  }
  const reasons = [];
  if (r.error) reasons.push(`the program raised <code>${esc(r.error.split("\n")[0])}</code>`);
  const failed = r.tests.filter((t) => !t.passed);
  if (failed.length) reasons.push(`${failed.length} of ${r.tests.length} tests fail`);
  const blocking = r.findings.filter((f) => f.severity === "critical" || f.severity === "high");
  if (blocking.length) reasons.push(`${blocking.length} blocking security finding${blocking.length > 1 ? "s" : ""}`);
  if (r.unmet?.length) reasons.push(`${r.unmet.length} requirement${r.unmet.length > 1 ? "s" : ""} unmet`);
  return `<div class="verdict verdict--fail">
    <span class="verdict__t">Not accepted yet</span>
    <ul>${reasons.map((x) => `<li>${x}</li>`).join("")}</ul></div>`;
}

function outputHTML(r) {
  const parts = [verdictHTML(r)];
  if (r.transcript?.length) {
    parts.push(
      `<p class="out__meta">simulated shell</p><pre class="out">${esc(r.transcript.join("\n"))}</pre>`
    );
  }
  parts.push(`<p class="out__meta">stdout</p>`);
  parts.push(r.stdout ? `<pre class="out">${esc(r.stdout)}</pre>` : `<p class="empty">(nothing printed)</p>`);
  if (r.stderr) parts.push(`<p class="out__meta">stderr</p><pre class="out out--err">${esc(r.stderr)}</pre>`);
  if (r.error) parts.push(`<p class="out__meta">error</p><pre class="out out--err">${esc(r.error)}</pre>`);
  if (r.steps) parts.push(`<p class="out__meta" style="margin-top:.6rem">${r.steps.toLocaleString()} interpreter steps</p>`);
  return parts.join("");
}

function testsHTML(r) {
  if (!r.graded) {
    const n = (current.lesson.exercise.tests || []).length;
    return `<p class="empty">Run executes your code. ${n} test${n === 1 ? "" : "s"} for this
      exercise run when you press <strong>Submit</strong> (⌘⇧↵), which grades correctness
      and security together.</p>`;
  }
  if (!r.tests.length) return `${verdictHTML(r)}<p class="empty">This exercise has no automated tests — read the brief and check the output.</p>`;
  return (
    verdictHTML(r) +
    r.tests
      .map(
        (t) => `<div class="tcase tcase--${t.passed ? "ok" : "no"}">
      <span class="tcase__ic">${t.passed ? "✓" : "✗"}</span>
      <div><span class="tcase__n">${esc(t.name)}</span>
      ${t.message ? `<div class="tcase__m">${esc(t.message)}</div>` : ""}</div></div>`
      )
      .join("")
  );
}

function auditHTML(r) {
  const unmet = r.unmet?.length
    ? `<div class="verdict verdict--fail"><span class="verdict__t">Exercise requirements</span>
       <ul>${r.unmet.map((u) => `<li>${inline(u.message)}</li>`).join("")}</ul></div>`
    : "";
  const findings = r.findings.length
    ? r.findings
        .map(
          (f) => `<div class="finding" data-sev="${f.severity}">
        <div class="finding__head">
          <span class="finding__sev">${f.severity}</span>
          <span class="finding__t">${esc(f.title)}</span>
          <span class="finding__loc">line ${f.line}</span>
        </div>
        ${f.snippet ? `<pre class="finding__snip">${esc(f.snippet)}</pre>` : ""}
        <p class="finding__d">${inline(f.detail)}</p>
        <p class="finding__fix"><b>Fix</b>${inline(f.fix)}</p>
        ${f.cwe ? `<span class="finding__cwe">${esc(f.id)} · ${esc(f.cwe)}</span>` : `<span class="finding__cwe">${esc(f.id)}</span>`}
      </div>`
        )
        .join("")
    : `<p class="empty">No findings. ${r.good?.length ? "" : "Nothing flagged — but an empty audit is not the same as a secure design."}</p>`;
  const good = r.good?.length
    ? `<p class="out__meta" style="margin-top:.7rem">secure practices detected</p>` +
      r.good.map((g) => `<div class="goodrow"><span>✓</span><div><strong>${esc(g.title)}</strong> — ${inline(g.detail)}</div></div>`).join("")
    : "";
  return unmet + findings + good;
}

function breachHTML(r) {
  const b = r.breaches || [];
  if (!b.length) {
    return `<p class="empty">The simulated world recorded no breach during that run.
      When an exercise asks you to exploit something, successful attacks show up here —
      and when you harden the code, this list must go empty.</p>`;
  }
  return (
    `<p class="out__meta">what an attacker achieved</p>` +
    b
      .map(
        (e) => `<div class="breach"><span class="breach__k">${esc(e.kind)}</span>
      <p class="breach__d">${esc(e.detail)}</p>
      ${e.source ? `<pre class="finding__snip">${esc(e.source)}</pre>` : ""}</div>`
      )
      .join("")
  );
}

let hintsShown = 0;
function helpHTML() {
  const ex = current.lesson.exercise;
  const hints = ex.hints || [];
  const shown = hints
    .slice(0, hintsShown)
    .map((h, i) => `<div class="hint"><b>Hint ${i + 1}</b>${inline(h)}</div>`)
    .join("");
  const more =
    hintsShown < hints.length
      ? `<button class="btn btn--ghost" id="hintBtn" style="margin-top:.6rem">Reveal hint ${hintsShown + 1} of ${hints.length}</button>`
      : hints.length
        ? `<p class="empty" style="margin-top:.6rem">All hints shown. The Solution button is next to Reset.</p>`
        : `<p class="empty">No hints for this one.</p>`;
  setTimeout(() => {
    $("#hintBtn")?.addEventListener("click", () => {
      hintsShown += 1;
      setPanel(helpHTML());
    });
  });
  const activeStdin = scratchStdin ?? ex.stdin ?? [];
  const label = scratchStdin ? "stdin fed to input() — from the loaded example" : "stdin fed to input()";
  return `<p class="out__meta">${label}</p>
    ${activeStdin.length ? `<pre class="out">${esc(activeStdin.join("\n"))}</pre>` : `<p class="empty">none</p>`}
    <p class="out__meta" style="margin-top:.7rem">hints</p>${shown}${more}`;
}

function showSolution() {
  const ex = current.lesson.exercise;
  const attempts = store.lesson(current.lesson.id).attempts;
  if (attempts < 1 && !confirm("Submit at least once before reading the solution — struggle is where the learning happens. Show it anyway?")) {
    return;
  }
  selectTab("help");
  setPanel(`<p class="out__meta">reference solution</p>
    <div class="snippet" style="margin:.2rem 0"><div class="snippet__bar"><strong>fixed</strong>
    <button class="linkbtn" id="useSolution">load into editor</button></div>
    <pre><code>${esc(ex.solution)}</code></pre></div>
    ${ex.why ? `<div class="box box--good" style="margin:.6rem 0 0"><div class="box__head"><span class="box__glyph">✓</span><span>Why this is the secure form</span></div><div class="box__body">${md(ex.why)}</div></div>` : ""}`);
  $("#useSolution").addEventListener("click", () => {
    editor.value = ex.solution;
    store.saveCode(current.lesson.id, ex.solution);
    scheduleAudit();
    revealEditor();
    toast("Solution loaded — run it, then rewrite it from memory");
  });
}

/* ======================================================================== */
/* quiz + spot drills                                                        */
/* ======================================================================== */
function wireQuiz(lesson) {
  if (!lesson.quiz?.length) return;
  const saved = store.lesson(lesson.id).quiz || {};
  $$(".quiz__opt").forEach((btn) => {
    const qi = Number(btn.dataset.q);
    const oi = Number(btn.dataset.o);
    if (saved[qi] !== undefined) markQuiz(lesson, qi, saved[qi]);
    btn.addEventListener("click", () => {
      const q = store.lesson(lesson.id).quiz || {};
      q[qi] = oi;
      store.setLesson(lesson.id, { quiz: q });
      markQuiz(lesson, qi, oi);
    });
  });
}

function markQuiz(lesson, qi, picked) {
  const item = lesson.quiz[qi];
  $$(`.quiz__opt[data-q="${qi}"]`).forEach((b) => {
    const oi = Number(b.dataset.o);
    b.classList.toggle("quiz__opt--right", oi === item.answer);
    b.classList.toggle("quiz__opt--wrong", oi === picked && oi !== item.answer);
  });
  const why = $(`[data-why="${qi}"]`);
  if (why) why.hidden = false;
}

function wireSpot(lesson) {
  if (!lesson.spot) return;
  const reveal = (picked) => {
    $$(".spot__line").forEach((b) => {
      const n = Number(b.dataset.line);
      const vuln = lesson.spot.lines.includes(n);
      b.classList.toggle("spot__line--hit", vuln);
      b.classList.toggle("spot__line--miss", !vuln && n === picked);
    });
    $("[data-spotwhy]").hidden = false;
  };
  const prior = store.lesson(lesson.id).spot;
  if (prior) reveal(prior);
  $$(".spot__line").forEach((btn) =>
    btn.addEventListener("click", () => {
      const n = Number(btn.dataset.line);
      store.setLesson(lesson.id, { spot: n });
      reveal(n);
      toast(lesson.spot.lines.includes(n) ? "That is the line." : "Not that line — the highlighted one is the defect.");
    })
  );
}

/* ======================================================================== */
/* console drawer                                                            */
/* ======================================================================== */
let replHistory = [];
let replPos = -1;
let replPending = false;

function toggleDrawer(force) {
  const d = $("#drawer");
  const open = force === undefined ? !d.classList.contains("drawer--open") : force;
  d.classList.toggle("drawer--open", open);
  document.body.classList.toggle("drawer-open", open);
  $("#drawerToggle").setAttribute("aria-expanded", String(open));
  if (open) $("#replInput").focus();
}

function replPrint(cls, text) {
  const out = $("#replOut");
  const span = document.createElement("div");
  span.className = `repl__${cls}`;
  if (cls === "in") span.innerHTML = `<b>${replPending ? "..." : "&gt;&gt;&gt;"}</b> ${esc(text)}`;
  else span.textContent = text;
  out.appendChild(span);
  out.scrollTop = out.scrollHeight;
}

function replKey(e) {
  const ta = $("#replInput");
  if (e.key === "Enter" && !e.shiftKey) {
    e.preventDefault();
    const line = ta.value;
    if (!py.ready()) {
      replPrint("err", "the interpreter is not ready yet");
      return;
    }
    replPrint("in", line);
    if (line.trim()) {
      replHistory.unshift(line);
      replPos = -1;
    }
    ta.value = "";
    let res;
    try {
      res = py.replFeed(line);
    } catch (err) {
      replPrint("err", String(err.message || err));
      return;
    }
    replPending = res.status === "more";
    $("#replPrompt").textContent = replPending ? "..." : ">>>";
    if (res.out) replPrint("out", res.out.replace(/\n$/, ""));
    if (res.err) replPrint("err", res.err.replace(/\n$/, ""));
    return;
  }
  if (e.key === "ArrowUp" && !ta.value.includes("\n")) {
    e.preventDefault();
    if (replPos + 1 < replHistory.length) {
      replPos += 1;
      ta.value = replHistory[replPos];
    }
  }
  if (e.key === "ArrowDown" && !ta.value.includes("\n")) {
    e.preventDefault();
    replPos = Math.max(replPos - 1, -1);
    ta.value = replPos === -1 ? "" : replHistory[replPos];
  }
  if (e.key === "Tab") {
    e.preventDefault();
    const s = ta.selectionStart;
    ta.value = `${ta.value.slice(0, s)}    ${ta.value.slice(ta.selectionEnd)}`;
    ta.setSelectionRange(s + 4, s + 4);
  }
}

/* ======================================================================== */
/* search                                                                    */
/* ======================================================================== */
function searchIndex() {
  return LESSON_INDEX.map((l) => {
    const mod = MODULES.find((m) => m.id === l.moduleId);
    const lesson = mod.lessons.find((x) => x.id === l.id);
    const text = [
      lesson.title,
      lesson.lede,
      lesson.secure,
      (lesson.cwe || []).join(" "),
      (lesson.tags || []).join(" "),
      lesson.blocks.map((b) => b.md || b.text || b.code || "").join(" "),
    ]
      .join(" ")
      .toLowerCase();
    return { id: l.id, day: l.day, title: lesson.title, mod: mod.title, text };
  });
}
let INDEX = null;

function wireSearch() {
  const input = $("#search");
  const box = $("#searchResults");
  input.addEventListener("input", () => {
    const q = input.value.trim().toLowerCase();
    if (q.length < 2) {
      box.hidden = true;
      return;
    }
    INDEX = INDEX || searchIndex();
    const terms = q.split(/\s+/);
    const hits = INDEX.filter((r) => terms.every((t) => r.text.includes(t))).slice(0, 12);
    box.hidden = false;
    box.innerHTML = hits.length
      ? hits
          .map(
            (h) => `<button class="sr__item" data-go="${h.id}">${esc(h.title)}
          <small>Day ${h.day} · ${esc(h.mod)}</small></button>`
          )
          .join("")
      : `<p class="sr__empty">Nothing matches “${esc(q)}”.</p>`;
    $$(".sr__item", box).forEach((b) =>
      b.addEventListener("click", () => {
        location.hash = `#/${b.dataset.go}`;
        box.hidden = true;
        input.value = "";
      })
    );
  });
  input.addEventListener("keydown", (e) => {
    if (e.key === "Enter") $(".sr__item", box)?.click();
    if (e.key === "Escape") {
      box.hidden = true;
      input.blur();
    }
  });
  document.addEventListener("click", (e) => {
    if (!e.target.closest(".search")) box.hidden = true;
  });
}
