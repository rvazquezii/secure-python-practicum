/* Pyodide bootstrap. Runs real CPython compiled to WebAssembly, loads the
   trainer's sandbox + simulated-OS modules into its filesystem, and exposes the
   three entry points the UI needs: run, audit, repl. */

const VERSIONS = ["0.28.3", "0.27.7", "0.26.4"];
const MIRRORS = [
  (v) => `https://cdn.jsdelivr.net/pyodide/v${v}/full/`,
  (v) => `https://unpkg.com/pyodide@${v}/`,
];

let pyodide = null;
let sandbox = null;
let bootPromise = null;

function loadScript(src) {
  return new Promise((resolve, reject) => {
    const s = document.createElement("script");
    s.src = src;
    s.onload = resolve;
    s.onerror = () => reject(new Error(`could not load ${src}`));
    document.head.appendChild(s);
  });
}

async function fetchText(path) {
  const r = await fetch(path, { cache: "no-cache" });
  if (!r.ok) throw new Error(`${path}: HTTP ${r.status}`);
  return r.text();
}

/** Boot the interpreter. `onStatus(text, fraction)` drives the splash screen. */
export function boot(onStatus = () => {}) {
  if (bootPromise) return bootPromise;
  bootPromise = (async () => {
    if (location.protocol === "file:") {
      throw new Error(
        "FILE_PROTOCOL: open this course over HTTP. Run ./serve.sh in the course folder, " +
          "then visit http://localhost:8800"
      );
    }

    onStatus("fetching course sandbox…", 0.08);
    const [sandboxSrc, teachSrc] = await Promise.all([
      fetchText("py/sandbox.py"),
      fetchText("py/teachlib.py"),
    ]);

    let lastErr = null;
    for (const v of VERSIONS) {
      for (const mirror of MIRRORS) {
        const indexURL = mirror(v);
        try {
          onStatus(`loading CPython ${v}…`, 0.2);
          await loadScript(`${indexURL}pyodide.js`);
          pyodide = await globalThis.loadPyodide({
            indexURL,
            stdout: (t) => console.debug("py:", t),
            stderr: (t) => console.debug("py!", t),
          });
          lastErr = null;
          break;
        } catch (e) {
          lastErr = e;
          delete globalThis.loadPyodide;
        }
      }
      if (pyodide) break;
    }
    if (!pyodide) throw new Error(`OFFLINE: ${lastErr?.message || "no Pyodide mirror reachable"}`);

    // Pyodide ships parts of the stdlib as separate packages: sqlite3 (module 5's
    // SQL-injection lessons use a real database) and the OpenSSL-backed hashlib
    // (pbkdf2_hmac/scrypt, which modules 2 and 9 need).
    onStatus("loading sqlite3 and hashlib…", 0.7);
    for (const pkg of ["sqlite3", "hashlib"]) {
      try {
        await pyodide.loadPackage(pkg);
      } catch (e) {
        console.warn(`package "${pkg}" unavailable; it may already be built in:`, e?.message || e);
      }
    }

    onStatus("installing the simulated OS…", 0.78);
    pyodide.FS.mkdirTree("/trainer");
    pyodide.FS.writeFile("/trainer/sandbox.py", sandboxSrc, { encoding: "utf8" });
    pyodide.FS.writeFile("/trainer/teachlib.py", teachSrc, { encoding: "utf8" });
    pyodide.runPython("import sys\nsys.path.insert(0, '/trainer')\nsys.setrecursionlimit(300)");
    sandbox = pyodide.pyimport("sandbox");

    onStatus("checking the harness…", 0.94);
    const probe = JSON.parse(sandbox.SPT_run(JSON.stringify({ code: "print(1 + 1)" })));
    if (probe.stdout.trim() !== "2") throw new Error("harness self-check failed");

    onStatus("ready", 1);
    return pyodide;
  })();
  return bootPromise;
}

export const ready = () => Boolean(sandbox);

export function version() {
  if (!pyodide) return "";
  try {
    return pyodide.runPython("import sys; '.'.join(map(str, sys.version_info[:3]))");
  } catch {
    return "";
  }
}

/** Execute a submission, run its tests, audit it. Returns the verdict object. */
export function run({ code, stdin = [], tests = [], requirements = [], setup = "", budget = 400000 }) {
  if (!sandbox) throw new Error("interpreter not ready");
  return JSON.parse(sandbox.SPT_run(JSON.stringify({ code, stdin, tests, requirements, setup, budget })));
}

/** Audit only -- fast enough to run while the learner types. */
export function audit(code, requirements = []) {
  if (!sandbox) return { findings: [], good: [], syntax: null, unmet: [] };
  return JSON.parse(sandbox.SPT_audit(JSON.stringify({ code, requirements })));
}

/** Feed one line to the persistent console namespace. */
export function replFeed(line) {
  if (!sandbox) throw new Error("interpreter not ready");
  return JSON.parse(sandbox.SPT_repl(JSON.stringify({ line })));
}

export function replReset() {
  if (sandbox) sandbox.SPT_reset_repl();
}
