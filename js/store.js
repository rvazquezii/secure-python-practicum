/* Progress, practice time and streak tracking. Everything lives in localStorage;
   there is no server and no account. Export/import is the backup story. */

const KEY = "securepython.v1";
const GOAL_MIN = 60;

const blank = () => ({
  version: 1,
  created: new Date().toISOString(),
  lessons: {},          // id -> {status, code, attempts, completed, quiz, spot}
  minutes: {},          // YYYY-MM-DD -> minutes of focused practice
  last: null,           // last lesson visited
  theme: "auto",
  railOpen: true,
});

function load() {
  try {
    const raw = localStorage.getItem(KEY);
    if (!raw) return blank();
    const data = JSON.parse(raw);
    return { ...blank(), ...data };
  } catch {
    return blank();
  }
}

let state = load();
let saveTimer = null;

function persist() {
  clearTimeout(saveTimer);
  saveTimer = setTimeout(() => {
    try {
      localStorage.setItem(KEY, JSON.stringify(state));
    } catch (e) {
      console.warn("progress not saved:", e);
    }
  }, 180);
}

export const today = () => new Date().toISOString().slice(0, 10);

export const store = {
  get all() {
    return state;
  },

  lesson(id) {
    return state.lessons[id] || { status: "new", code: null, attempts: 0, completed: null, quiz: {}, spot: null };
  },

  setLesson(id, patch) {
    state.lessons[id] = { ...this.lesson(id), ...patch };
    persist();
  },

  saveCode(id, code) {
    const cur = this.lesson(id);
    if (cur.code === code) return;
    this.setLesson(id, { code, status: cur.status === "done" ? "done" : "started" });
  },

  complete(id) {
    const cur = this.lesson(id);
    if (cur.status === "done") return false;
    this.setLesson(id, { status: "done", completed: new Date().toISOString() });
    return true;
  },

  attempt(id) {
    const cur = this.lesson(id);
    this.setLesson(id, { attempts: cur.attempts + 1, status: cur.status === "done" ? "done" : "started" });
    return cur.attempts + 1;
  },

  isDone(id) {
    return this.lesson(id).status === "done";
  },

  doneCount() {
    return Object.values(state.lessons).filter((l) => l.status === "done").length;
  },

  /* ---- practice clock ------------------------------------------------- */
  addMinutes(mins) {
    const d = today();
    state.minutes[d] = Math.round(((state.minutes[d] || 0) + mins) * 100) / 100;
    persist();
  },

  minutesToday() {
    return Math.floor(state.minutes[today()] || 0);
  },

  goal: GOAL_MIN,

  /** Consecutive days (ending today or yesterday) with at least 20 minutes logged. */
  streak() {
    const days = Object.keys(state.minutes).filter((d) => (state.minutes[d] || 0) >= 20).sort();
    if (!days.length) return 0;
    const set = new Set(days);
    let n = 0;
    const cursor = new Date();
    if (!set.has(today())) cursor.setDate(cursor.getDate() - 1);
    for (;;) {
      const key = cursor.toISOString().slice(0, 10);
      if (!set.has(key)) break;
      n += 1;
      cursor.setDate(cursor.getDate() - 1);
    }
    return n;
  },

  history(days = 28) {
    const out = [];
    const c = new Date();
    for (let i = days - 1; i >= 0; i -= 1) {
      const d = new Date(c);
      d.setDate(c.getDate() - i);
      const key = d.toISOString().slice(0, 10);
      out.push({ date: key, minutes: Math.floor(state.minutes[key] || 0) });
    }
    return out;
  },

  /* ---- misc ----------------------------------------------------------- */
  set(key, value) {
    state[key] = value;
    persist();
  },
  get(key) {
    return state[key];
  },

  exportJSON() {
    return JSON.stringify(state, null, 2);
  },

  importJSON(text) {
    const data = JSON.parse(text);
    if (typeof data !== "object" || !data.lessons) throw new Error("not a Secure Python progress file");
    state = { ...blank(), ...data };
    persist();
  },

  reset() {
    state = blank();
    persist();
  },
};

/* Counts only time the tab is focused and the learner has interacted recently --
   leaving a lesson open overnight should not report an eight-hour study session. */
export function startClock(onTick) {
  const STEP = 10; // seconds
  let lastInput = Date.now();
  const bump = () => {
    lastInput = Date.now();
  };
  ["keydown", "pointerdown", "wheel", "focus"].forEach((ev) =>
    window.addEventListener(ev, bump, { passive: true })
  );
  setInterval(() => {
    const active = document.hasFocus() && Date.now() - lastInput < 150000 && !document.hidden;
    if (active) {
      store.addMinutes(STEP / 60);
      onTick?.();
    }
  }, STEP * 1000);
}
