/* Content renderer. Lesson blocks are plain data; this turns them into the
   reading column. Inline markup is deliberately tiny: `code`, **bold**, *italic*,
   [label](url). Everything is escaped before markup is applied. */

import { highlight } from "./editor.js";

export const esc = (s = "") =>
  String(s).replace(/[&<>"]/g, (c) => ({ "&": "&amp;", "<": "&lt;", ">": "&gt;", '"': "&quot;" }[c]));

export function inline(text = "") {
  return esc(text)
    .replace(/`([^`]+)`/g, "<code>$1</code>")
    .replace(/\*\*([^*]+)\*\*/g, "<strong>$1</strong>")
    .replace(/(^|[\s(])\*([^*\n]+)\*/g, "$1<em>$2</em>")
    .replace(/\[([^\]]+)\]\(([^)]+)\)/g, '<a href="$2" target="_blank" rel="noopener noreferrer">$1</a>')
    .replace(/\{\{([^}]+)\}\}/g, '<dfn>$1</dfn>');
}

/** Block-level mini markdown: blank-line paragraphs, "- " and "1. " lists. */
export function md(text = "") {
  const chunks = String(text).trim().split(/\n\s*\n/);
  return chunks
    .map((chunk) => {
      const lines = chunk.split("\n").map((l) => l.trim()).filter(Boolean);
      if (lines.every((l) => l.startsWith("- "))) {
        return `<ul>${lines.map((l) => `<li>${inline(l.slice(2))}</li>`).join("")}</ul>`;
      }
      if (lines.every((l) => /^\d+\.\s/.test(l))) {
        return `<ol>${lines.map((l) => `<li>${inline(l.replace(/^\d+\.\s/, ""))}</li>`).join("")}</ol>`;
      }
      return `<p>${inline(lines.join(" "))}</p>`;
    })
    .join("");
}

const BOX_META = {
  note: { label: "Note", glyph: "i" },
  rule: { label: "Rule", glyph: "§" },
  warn: { label: "Watch out", glyph: "!" },
  pitfall: { label: "Common mistake", glyph: "✗" },
  cve: { label: "From the field", glyph: "⚑" },
  good: { label: "Do this", glyph: "✓" },
  try: { label: "Try it", glyph: "›" },
};

function codeBlock(b) {
  const kind = b.label === "vulnerable" ? "vuln" : b.label === "fixed" ? "fix" : "neutral";
  const label = b.label ? esc(b.label) : "python";
  const load = b.load === false ? "" : `<button class="linkbtn" data-load-code="1">send to Workbench →</button>`;
  return `<figure class="snippet snippet--${kind}">
    <div class="snippet__bar"><strong>${label}</strong>${load}</div>
    <pre><code>${highlight(b.code)}</code></pre>
    ${b.cap ? `<figcaption class="snippet__cap">${inline(b.cap)}</figcaption>` : ""}
  </figure>`;
}

function replBlock(b) {
  const body = b.lines
    .map((l) =>
      l.startsWith(">>>") || l.startsWith("...")
        ? `<span class="p">${esc(l)}</span>`
        : `<span class="o">${esc(l)}</span>`
    )
    .join("\n");
  return `<div class="transcript">${body}</div>`;
}

function tableBlock(b) {
  const head = `<tr>${b.head.map((h) => `<th>${inline(h)}</th>`).join("")}</tr>`;
  const rows = b.rows.map((r) => `<tr>${r.map((c) => `<td>${inline(c)}</td>`).join("")}</tr>`).join("");
  return `<div class="tablewrap"><table class="data"><thead>${head}</thead><tbody>${rows}</tbody></table></div>`;
}

export function block(b) {
  switch (b.t) {
    case "p":
      return md(b.md);
    case "h":
      return `<h2>${inline(b.text)}</h2>`;
    case "h3":
      return `<h3>${inline(b.text)}</h3>`;
    case "list":
      return md(b.items.map((i) => `- ${i}`).join("\n"));
    case "box": {
      const meta = BOX_META[b.kind] || BOX_META.note;
      return `<aside class="box box--${b.kind}">
        <div class="box__head"><span class="box__glyph" aria-hidden="true">${meta.glyph}</span>
        <span>${esc(b.title || meta.label)}</span></div>
        <div class="box__body">${md(b.md)}</div></aside>`;
    }
    case "code":
      return codeBlock(b);
    case "repl":
      return replBlock(b);
    case "table":
      return tableBlock(b);
    default:
      return "";
  }
}

export const blocks = (list = []) => list.map(block).join("");

/* ------------------------------------------------------------------ quiz --- */
export function quizHTML(items = []) {
  if (!items.length) return "";
  return `<section class="quiz">
    <span class="eyebrow">Check yourself</span>
    ${items
      .map(
        (q, qi) => `<div class="quiz__q" data-q="${qi}">
          <p class="quiz__stem">${inline(q.q)}</p>
          <div class="quiz__opts">
            ${q.options
              .map(
                (o, oi) =>
                  `<button class="quiz__opt" data-q="${qi}" data-o="${oi}"><b>${String.fromCharCode(
                    65 + oi
                  )}</b><span>${inline(o)}</span></button>`
              )
              .join("")}
          </div>
          <p class="quiz__why" data-why="${qi}" hidden>${inline(q.why)}</p>
        </div>`
      )
      .join("")}
  </section>`;
}

/* ------------------------------------------------------- spot-the-bug ----- */
export function spotHTML(spot) {
  if (!spot) return "";
  const lines = spot.code.split("\n");
  return `<section class="spot">
    <span class="eyebrow">Spot the vulnerability</span>
    <p>${inline(spot.prompt || "Click the line where the security defect lives.")}</p>
    <div class="snippet"><div class="snippet__bar"><strong>${esc(spot.label || "under review")}</strong></div>
      <div class="spot__code" style="padding:.5rem 0;background:var(--surface);border:1px solid var(--rule);border-top:0;border-radius:0 0 var(--radius) var(--radius)">
      ${lines
        .map(
          (l, i) =>
            `<button class="spot__line" data-line="${i + 1}"><span>${i + 1}</span><span>${highlight(
              l || " "
            )}</span></button>`
        )
        .join("")}
      </div>
    </div>
    <p class="quiz__why" data-spotwhy hidden>${inline(spot.why)}</p>
  </section>`;
}
