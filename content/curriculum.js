/* Course assembly. Each module file owns its five lessons; this file derives the
   flat lesson index (day order) that routing, search and the rail depend on. */

import m01 from "./m01.js";
import m02 from "./m02.js";
import m03 from "./m03.js";
import m04 from "./m04.js";
import m05 from "./m05.js";
import m06 from "./m06.js";
import m07 from "./m07.js";
import m08 from "./m08.js";
import m09 from "./m09.js";
import m10 from "./m10.js";
import m11 from "./m11.js";
import m12 from "./m12.js";

export const MODULES = [m01, m02, m03, m04, m05, m06, m07, m08, m09, m10, m11, m12];

export const LESSON_INDEX = MODULES.flatMap((m) =>
  m.lessons.map((l) => ({
    id: l.id,
    day: l.day,
    title: l.title,
    secure: l.secure,
    moduleId: m.id,
    moduleNumber: m.number,
  }))
).sort((a, b) => a.day - b.day);

export const COURSE = {
  modules: MODULES.length,
  lessons: LESSON_INDEX.length,
  hours: LESSON_INDEX.length,
  rules: 34,
  lede:
    "Sixty one-hour sessions. Real CPython runs in this page, so you type code and it executes. " +
    "Every submission is graded twice: once for correctness, once by a security auditor that " +
    "reads your syntax tree. Insecure code that produces the right answer does not pass.",
  contract: `A lesson is complete when **all three** hold:

- every automated test passes,
- the auditor reports no **critical** or **high** finding,
- the lesson's explicit requirements are met (for example "must use \`secrets\`, must not use \`random\`").

Medium and low findings do not block you, but they are shown with the fix so you learn the habit.
The operating system is simulated: \`os.system\`, \`subprocess\`, \`requests\`, \`yaml\` and \`jwt\` are
instrumented, so a successful injection is *visible* in the Breach tab and still completely harmless.`,
};
