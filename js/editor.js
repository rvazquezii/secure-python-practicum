/* A small Python editor: a transparent textarea over a highlighted layer, plus
   the behaviours that make writing Python by hand bearable (four-space tab,
   auto-indent after a colon, bracket pairing, block indent/dedent). */

const KEYWORDS = new Set(
  ("False None True and as assert async await break class continue def del elif else except finally " +
    "for from global if import in is lambda nonlocal not or pass raise return try while with yield match case")
    .split(" ")
);
const BUILTINS = new Set(
  ("abs aiter all any anext ascii bin bool breakpoint bytearray bytes callable chr classmethod compile " +
    "complex delattr dict dir divmod enumerate eval exec filter float format frozenset getattr globals " +
    "hasattr hash help hex id input int isinstance issubclass iter len list locals map max memoryview min " +
    "next object oct open ord pow print property range repr reversed round set setattr slice sorted " +
    "staticmethod str sum super tuple type vars zip __import__ self cls Exception ValueError TypeError " +
    "KeyError IndexError OSError RuntimeError PermissionError NotImplementedError AssertionError " +
    "ZeroDivisionError AttributeError StopIteration EOFError FileNotFoundError UnicodeDecodeError")
    .split(" ")
);

const esc = (s) => s.replace(/[&<>]/g, (c) => ({ "&": "&amp;", "<": "&lt;", ">": "&gt;" }[c]));

/** Tokenise Python into highlighted HTML. Handles triple quotes, prefixes, f-strings. */
export function highlight(src) {
  let out = "";
  let i = 0;
  const n = src.length;
  while (i < n) {
    const c = src[i];

    // comment
    if (c === "#") {
      const j = src.indexOf("\n", i);
      const end = j === -1 ? n : j;
      out += `<span class="t-com">${esc(src.slice(i, end))}</span>`;
      i = end;
      continue;
    }

    // string (with optional prefix)
    const pm = /^([rRbBuUfF]{0,2})("""|'''|"|')/.exec(src.slice(i, i + 5));
    if (pm && (pm[1] === "" || /^[rbufRBUF]+$/.test(pm[1]))) {
      const prefix = pm[1];
      const q = pm[2];
      let j = i + prefix.length + q.length;
      while (j < n) {
        if (src[j] === "\\" && q.length === 1) {
          j += 2;
          continue;
        }
        if (src.startsWith(q, j)) {
          j += q.length;
          break;
        }
        if (q.length === 1 && src[j] === "\n") break;
        j += 1;
      }
      out += `<span class="t-str">${esc(src.slice(i, j))}</span>`;
      i = j;
      continue;
    }

    // decorator
    if (c === "@" && /[A-Za-z_]/.test(src[i + 1] || "")) {
      const m = /^@[\w.]+/.exec(src.slice(i));
      out += `<span class="t-dec">${esc(m[0])}</span>`;
      i += m[0].length;
      continue;
    }

    // number
    if (/[0-9]/.test(c) && !/[\w.]/.test(src[i - 1] || " ")) {
      const m = /^(0[xXbBoO][0-9a-fA-F_]+|\d[\d_]*\.?[\d_]*([eE][+-]?\d+)?j?)/.exec(src.slice(i));
      if (m) {
        out += `<span class="t-num">${esc(m[0])}</span>`;
        i += m[0].length;
        continue;
      }
    }

    // identifier
    if (/[A-Za-z_]/.test(c)) {
      const m = /^\w+/.exec(src.slice(i));
      const word = m[0];
      const after = src.slice(i + word.length);
      const prev = src.slice(0, i).match(/(\w+)\s+$/);
      let cls = "";
      if (KEYWORDS.has(word)) cls = "t-kw";
      else if (prev && (prev[1] === "def" || prev[1] === "class")) cls = "t-fn";
      else if (/^\s*\(/.test(after)) cls = BUILTINS.has(word) ? "t-bi" : "t-fn";
      else if (BUILTINS.has(word)) cls = "t-bi";
      out += cls ? `<span class="${cls}">${esc(word)}</span>` : esc(word);
      i += word.length;
      continue;
    }

    // operators & punctuation
    if (/[+\-*/%=<>!&|^~:,.()[\]{}]/.test(c)) {
      out += `<span class="t-op">${esc(c)}</span>`;
      i += 1;
      continue;
    }

    out += esc(c);
    i += 1;
  }
  return out;
}

const OPEN = { "(": ")", "[": "]", "{": "}" };
const QUOTES = new Set(["'", '"']);

export class Editor {
  constructor(host, { value = "", onChange = () => {}, onRun = () => {}, onSubmit = () => {} } = {}) {
    host.classList.add("editor");
    host.innerHTML = `
      <div class="editor__scroll">
        <div class="editor__gutter" aria-hidden="true"></div>
        <pre class="editor__layer" aria-hidden="true"></pre>
        <textarea class="editor__input" spellcheck="false" autocapitalize="off" autocomplete="off"
                  wrap="off" aria-label="Python editor"></textarea>
      </div>`;
    this.scroll = host.querySelector(".editor__scroll");
    this.gutter = host.querySelector(".editor__gutter");
    this.layer = host.querySelector(".editor__layer");
    this.ta = host.querySelector(".editor__input");
    this.onChange = onChange;
    this.onRun = onRun;
    this.onSubmit = onSubmit;
    this.flags = new Set();

    this.ta.value = value;
    this.paint();

    this.ta.addEventListener("input", () => {
      this.paint();
      this.onChange(this.ta.value);
    });
    this.ta.addEventListener("scroll", () => {
      this.layer.style.transform = `translate(${-this.ta.scrollLeft}px, 0)`;
    });
    this.ta.addEventListener("keydown", (e) => this.keydown(e));
  }

  get value() {
    return this.ta.value;
  }

  set value(v) {
    this.ta.value = v;
    this.paint();
  }

  focus() {
    this.ta.focus();
  }

  /** Mark gutter line numbers that carry a security finding. */
  setFlags(lines) {
    this.flags = new Set(lines);
    this.paintGutter();
  }

  paint() {
    const v = this.ta.value;
    this.layer.innerHTML = highlight(v) + "\n";
    this.paintGutter();
    // grow the textarea so the browser scrolls the container, not the textarea
    const lines = v.split("\n").length;
    const h = Math.max(lines * 1.6 * 0.8 * 16 + 20, 176);
    this.ta.style.height = `${h}px`;
    this.layer.style.minHeight = `${h}px`;
  }

  paintGutter() {
    const count = this.ta.value.split("\n").length;
    let html = "";
    for (let i = 1; i <= count; i += 1) {
      html += this.flags.has(i) ? `<b class="flag" title="security finding">${i}</b>` : `<b>${i}</b>`;
    }
    this.gutter.innerHTML = html;
  }

  replace(start, end, text, caret) {
    const v = this.ta.value;
    this.ta.value = v.slice(0, start) + text + v.slice(end);
    const pos = caret === undefined ? start + text.length : caret;
    this.ta.setSelectionRange(pos, pos);
    this.paint();
    this.onChange(this.ta.value);
  }

  keydown(e) {
    const { selectionStart: s, selectionEnd: t, value: v } = this.ta;
    const mod = e.metaKey || e.ctrlKey;

    if (mod && e.key === "Enter") {
      e.preventDefault();
      if (e.shiftKey) this.onSubmit();
      else this.onRun();
      return;
    }
    if (mod && e.key === "/") {
      e.preventDefault();
      this.toggleComment();
      return;
    }

    if (e.key === "Tab") {
      e.preventDefault();
      if (s !== t || e.shiftKey) {
        this.indentBlock(e.shiftKey ? -1 : 1);
      } else {
        const col = s - (v.lastIndexOf("\n", s - 1) + 1);
        this.replace(s, t, " ".repeat(4 - (col % 4)));
      }
      return;
    }

    if (e.key === "Enter") {
      e.preventDefault();
      const lineStart = v.lastIndexOf("\n", s - 1) + 1;
      const line = v.slice(lineStart, s);
      let indent = (line.match(/^[ \t]*/) || [""])[0];
      const stripped = line.trim();
      if (stripped.endsWith(":")) indent += "    ";
      if (/^(return|pass|break|continue|raise)\b/.test(stripped) && indent.length >= 4) {
        indent = indent.slice(0, -4);
      }
      this.replace(s, t, `\n${indent}`);
      return;
    }

    if (e.key === "Backspace" && s === t) {
      const lineStart = v.lastIndexOf("\n", s - 1) + 1;
      const before = v.slice(lineStart, s);
      if (before.length && /^ +$/.test(before)) {
        e.preventDefault();
        const back = before.length % 4 === 0 ? 4 : before.length % 4;
        this.replace(s - back, t, "");
        return;
      }
      if (OPEN[v[s - 1]] === v[s] || (QUOTES.has(v[s - 1]) && v[s - 1] === v[s])) {
        e.preventDefault();
        this.replace(s - 1, s + 1, "");
        return;
      }
    }

    if (OPEN[e.key]) {
      e.preventDefault();
      const sel = v.slice(s, t);
      this.replace(s, t, e.key + sel + OPEN[e.key], s + 1 + sel.length);
      return;
    }
    if (QUOTES.has(e.key) && s === t && !/\w/.test(v[s] || "")) {
      e.preventDefault();
      this.replace(s, t, e.key + e.key, s + 1);
      return;
    }
    if ([")", "]", "}"].includes(e.key) && v[s] === e.key && s === t) {
      e.preventDefault();
      this.ta.setSelectionRange(s + 1, s + 1);
    }
  }

  indentBlock(dir) {
    const { selectionStart: s, selectionEnd: t, value: v } = this.ta;
    const from = v.lastIndexOf("\n", s - 1) + 1;
    const toEnd = v.indexOf("\n", t) === -1 ? v.length : v.indexOf("\n", t);
    const block = v.slice(from, toEnd);
    const next = block
      .split("\n")
      .map((l) => (dir > 0 ? `    ${l}` : l.replace(/^ {1,4}/, "")))
      .join("\n");
    this.ta.value = v.slice(0, from) + next + v.slice(toEnd);
    this.ta.setSelectionRange(from, from + next.length);
    this.paint();
    this.onChange(this.ta.value);
  }

  toggleComment() {
    const { selectionStart: s, selectionEnd: t, value: v } = this.ta;
    const from = v.lastIndexOf("\n", s - 1) + 1;
    const toEnd = v.indexOf("\n", t) === -1 ? v.length : v.indexOf("\n", t);
    const lines = v.slice(from, toEnd).split("\n");
    const allCommented = lines.every((l) => !l.trim() || l.trimStart().startsWith("# "));
    const next = lines
      .map((l) => {
        if (!l.trim()) return l;
        if (allCommented) return l.replace(/^(\s*)# /, "$1");
        const ind = (l.match(/^\s*/) || [""])[0];
        return `${ind}# ${l.slice(ind.length)}`;
      })
      .join("\n");
    this.ta.value = v.slice(0, from) + next + v.slice(toEnd);
    this.ta.setSelectionRange(from, from + next.length);
    this.paint();
    this.onChange(this.ta.value);
  }
}
