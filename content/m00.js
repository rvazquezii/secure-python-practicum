export default {
  id: "m00",
  number: 0,
  title: "Before day one: the Python you need",
  focus: "syntax",
  subtitle:
    "A standing start. Six sessions covering what the rest of this course assumes you already have: running code, reading an error, naming things, text, numbers, blocks and functions.",
  objectives: [
    "Run Python two ways and know which one echoes a value and which one does not.",
    "Read a syntax error and a traceback, and find the line that is actually wrong.",
    "Name values, and say what type one is without guessing.",
    "Build and reshape text with f-strings, slicing and the common string methods.",
    "Write a block — colon, indent, body — and an `if`, a `for` and a `while` that do what you meant.",
    "Write a function that returns a value, and call it with the right arguments.",
  ],
  rules: [
    { id: "PY-EVAL", what: "even in week zero, text is parsed — never executed" },
  ],
  capstone:
    "Day 6 closes with a receipt printer: variables, text, integer arithmetic, a loop and three functions working together — the shape of every exercise from Module 1 onward.",

  lessons: [
    /* ------------------------------------------------------------------ 1 */
    {
      id: "m00l01",
      day: 1,
      title: "Hello, world — and your first error",
      minutes: 60,
      secure: "reading errors precisely",
      tags: ["print", "repl", "errors", "traceback", "syntax"],
      lede:
        "Two things to learn today: how to make Python say something, and how to read what it says when you get it wrong. The second one matters more, because you will see far more errors than output.",
      blocks: [
        {
          t: "p",
          md: `Python is an {{interpreter}}. You give it a line, it does the line, immediately. There is no "build" step and no waiting.

Open the **Python console** at the bottom of this page — click it, or press \`⌃\`\` — and type \`2 + 3\` then Enter.`,
        },
        {
          t: "repl",
          lines: [">>> 2 + 3", "5", ">>> 10 - 4", "6"],
        },
        {
          t: "p",
          md: `The console *echoes* the value of whatever you type. That is a convenience of the console only.

In a **script** — the Workbench on the right — the same line computes 5 and throws it away. Nothing appears. To see a value in a script you must ask for it with \`print()\`.`,
        },
        {
          t: "code",
          label: "example",
          code: `2 + 3
print(2 + 3)`,
          cap: "The first line computes 5 and discards it. Only the second line puts anything on screen. Send this to the Workbench and run it — you will see one `5`, not two.",
        },
        { t: "h", text: "print() in more detail" },
        {
          t: "code",
          label: "example",
          code: `print("Hello, world")
print("checks:", 12, "failures:", 0)
print("a", "b", "c", sep="-")
print("no newline here: ", end="")
print("...same line")`,
          cap: "`print` takes any number of values, puts a space between them, and ends with a newline. `sep=` changes the separator, `end=` changes the ending.",
        },
        {
          t: "box",
          kind: "note",
          title: "Those names in the parentheses",
          md: `\`sep\` and \`end\` are {{keyword arguments}} — you name the thing you are setting. You will meet many of these. The pattern is always \`name=value\`, inside the parentheses of a call.`,
        },
        { t: "h", text: "Errors are messages, not failures" },
        {
          t: "p",
          md: `You will write broken code constantly. Everyone does. The skill is reading what Python tells you, and it tells you a lot.

There are two families.`,
        },
        {
          t: "code",
          label: "vulnerable",
          code: `print("Hello)`,
          cap: "A **SyntaxError**: Python could not even understand the line. Here the string is never closed. Nothing ran at all.",
          load: false,
        },
        {
          t: "repl",
          lines: [
            '>>> print("Hello)',
            '  File "<stdin>", line 1',
            '    print("Hello)',
            "          ^",
            "SyntaxError: unterminated string literal (detected at line 1)",
          ],
        },
        {
          t: "p",
          md: `Read it bottom-up:

1. **\`SyntaxError\`** — the *kind* of problem.
2. **\`unterminated string literal\`** — the detail. A quote was opened and never closed.
3. **\`line 1\`** and the \`^\` marker — *where*.

The caret points at where Python gave up, which is often slightly *after* the real mistake. The missing quote belongs at the end; the caret sits at the opening one.`,
        },
        {
          t: "box",
          kind: "pitfall",
          title: "The error is often on the line before",
          md: `An unclosed \`(\` or \`"\` makes Python keep reading onto the next line, so it reports the error *there*. If line 7 looks perfectly fine, check line 6 for a missing bracket or quote.`,
        },
        { t: "h", text: "The second family: it ran, then broke" },
        {
          t: "code",
          label: "vulnerable",
          code: `print("starting")
print(nmae)`,
          cap: "A **NameError** — a typo. `starting` prints first, proving the program ran up to the bad line.",
          load: false,
        },
        {
          t: "repl",
          lines: [
            ">>> print(nmae)",
            "Traceback (most recent call last):",
            '  File "<stdin>", line 1, in <module>',
            "NameError: name 'nmae' is not defined. Did you mean: 'name'?",
          ],
        },
        {
          t: "table",
          head: ["What you see", "What it means", "Usual cause"],
          rows: [
            ["`SyntaxError`", "Python could not read your code", "missing quote, bracket or colon"],
            ["`IndentationError`", "the spacing at the start of a line is wrong", "mixed or missing indentation"],
            ["`NameError`", "you used a name that does not exist", "typo, or used before assigning"],
            ["`TypeError`", "wrong kind of value for the operation", "`\"3\" + 4`"],
            ["`ValueError`", "right kind, impossible value", "`int(\"abc\")`"],
            ["`ZeroDivisionError`", "you divided by zero", "`10 / 0`"],
          ],
        },
        {
          t: "box",
          kind: "rule",
          title: "Read the last line first",
          md: `A traceback is printed oldest-call-first, so the **last line is the actual error** and the line above it is where it happened. Start at the bottom and work up only if you need to.

This habit pays off for the whole course. In Module 4 you will learn to write error messages for *other* people, and reading them well is what teaches you which ones are useful.`,
        },
      ],
      quiz: [
        {
          q: "You put `2 + 3` on a line of a script and run it. What appears on screen?",
          options: ["`5`", "Nothing", "An error"],
          answer: 1,
          why:
            "Nothing. The console echoes values as a convenience; a script computes and discards unless you call `print()`. This trips up almost everyone once.",
        },
        {
          q: "Which part of a traceback tells you what went wrong?",
          options: ["The first line", "The last line", "The file name"],
          answer: 1,
          why: "The last line names the error type and the detail. Read bottom-up.",
        },
        {
          q: "`print(\"Hello)` produces a SyntaxError. Why did nothing print?",
          options: [
            "`print` is broken.",
            "Python could not parse the line, so no part of the program ran.",
            "The text was too short.",
          ],
          answer: 1,
          why:
            "A SyntaxError happens before execution. That is the difference from a NameError, where earlier lines do run — which is why `starting` appeared in the second example.",
        },
      ],
      exercise: {
        title: "Say hello, properly",
        brief: `Write a program that prints exactly four lines:

\`\`\`
Hello, world
Learning: Python
Day 1 of 66
ready
\`\`\`

Requirements:

- Line 2 must be produced by **one** \`print\` call with **two** values — \`"Learning:"\` and \`"Python"\` — letting \`print\` put the space between them.
- Line 3 must use \`print\` with \`sep\`, called as \`print("Day", 1, "of", 66)\` — the default separator already gives you the spaces, so just call it that way.
- Line 4 is \`ready\`, lower case.

Type it rather than pasting. The muscle memory for quotes and parentheses is the point of this exercise.`,
        rubric: [
          "Exactly four lines, in order",
          "Line 2 is one `print` with two separate values",
          "No syntax errors — the program runs to completion",
        ],
        starter: `print("Hello, world")
# add the other three lines
`,
        stdin: [],
        tests: [
          {
            name: "prints four lines in the right order",
            code: `expected = ["Hello, world", "Learning: Python", "Day 1 of 66", "ready"]
assert _lines == expected, f"expected {expected}, got {_lines}"`,
          },
          {
            name: "line 2 uses one print with two values",
            code: `assert "Learning: Python" in _stdout, "expected 'Learning: Python' on its own line"
assert "Learning:Python" not in _stdout, "let print add the space -- pass two values, do not join them"`,
          },
          {
            name: "the program runs without error",
            code: `assert len(_lines) == 4, f"expected exactly 4 lines, got {len(_lines)}"`,
          },
        ],
        requirements: [],
        hints: [
          "One `print(...)` per line of output. Four lines of output, four calls.",
          'For line 2: `print("Learning:", "Python")` — two values separated by a comma, and print inserts the space.',
          'For line 3: `print("Day", 1, "of", 66)`. Note `1` and `66` have no quotes — they are numbers, not text.',
          "If you get a SyntaxError, count your quotes and your parentheses. Every `(` needs a `)`, every `\\\"` needs a partner.",
        ],
        solution: `print("Hello, world")
print("Learning:", "Python")
print("Day", 1, "of", 66)
print("ready")`,
        why: `Four calls, four lines. The detail worth keeping is on line 2: \`print("Learning:", "Python")\` passes **two values**, and \`print\` joins them with a space. Writing \`print("Learning:" + " " + "Python")\` produces the same output with more ways to go wrong.

On line 3, \`1\` and \`66\` are numbers and \`"Day"\` is text. \`print\` is happy to mix them; the \`+\` operator would not be, and that is the \`TypeError\` you will meet tomorrow.`,
      },
      wrapup: `- The console echoes values; a script needs \`print()\`.
- \`print\` takes several values, separates them with a space, and ends with a newline.
- A **SyntaxError** means nothing ran. A **NameError** or **TypeError** means it ran until that line.
- Read tracebacks from the bottom. The last line is the error.`,
      refs: [
        { label: "Python tutorial — using the interpreter", url: "https://docs.python.org/3/tutorial/interpreter.html" },
        { label: "Built-in exceptions", url: "https://docs.python.org/3/library/exceptions.html" },
      ],
    },

    /* ------------------------------------------------------------------ 2 */
    {
      id: "m00l02",
      day: 2,
      title: "Names, values and types",
      minutes: 60,
      secure: "knowing what you are holding",
      tags: ["variables", "assignment", "naming", "type", "comments"],
      lede:
        "A variable is a name pointing at a value. That is the whole idea — but three details about it cause most beginner confusion, and all three come back as security problems later.",
      blocks: [
        {
          t: "code",
          label: "example",
          code: `port = 8080
name = "ada"
ready = True

print(port, name, ready)`,
          cap: "`=` means *put this value in this name*. It is not a claim that the two sides are equal.",
        },
        {
          t: "box",
          kind: "pitfall",
          title: "`=` assigns, `==` compares",
          md: `\`\`\`
count = 5      # assignment: put 5 in count
count == 5     # comparison: is count 5? -> True
\`\`\`

Reading \`=\` aloud as "gets" helps: *count gets five*. You will meet \`==\` properly on Day 4.`,
        },
        { t: "h", text: "Names are labels, not boxes" },
        {
          t: "repl",
          lines: [
            ">>> x = 10",
            ">>> y = x",
            ">>> x = 99",
            ">>> y",
            "10",
          ],
        },
        {
          t: "p",
          md: `\`y = x\` copied the *value* that \`x\` pointed at, at that moment. Re-pointing \`x\` later does not drag \`y\` along.`,
        },
        { t: "h", text: "Naming rules, and naming taste" },
        {
          t: "table",
          head: ["Rule", "Good", "Not allowed"],
          rows: [
            ["Letters, digits, underscore only", "`user_id`", "`user-id`, `user id`"],
            ["Cannot start with a digit", "`port2`", "`2port`"],
            ["Case matters", "`Name` and `name` are different", "—"],
            ["Not a Python keyword", "`class_name`", "`class`, `if`, `return`"],
            ["Convention: lower_snake_case", "`max_retries`", "`MaxRetries` (used for classes)"],
            ["Convention: ALL_CAPS for constants", "`MAX_RETRIES = 3`", "—"],
          ],
        },
        {
          t: "box",
          kind: "warn",
          title: "Do not name a variable after something you need",
          md: `\`\`\`
print = "hello"      # now print is text
print("anything")    # TypeError: 'str' object is not callable
\`\`\`

You have replaced the \`print\` function with a string. The same applies to \`list\`, \`str\`, \`input\`, \`sum\`, \`type\`. If a built-in suddenly stops working, check whether you named something after it.

This has a bigger version. In Module 8 you will see a *file* named after a standard library module replacing it for an entire program — the same mistake, with a security impact.`,
        },
        { t: "h", text: "What type is it?" },
        {
          t: "repl",
          lines: [
            ">>> type(8080)",
            "<class 'int'>",
            '>>> type("8080")',
            "<class 'str'>",
            ">>> type(80.5)",
            "<class 'float'>",
            ">>> type(True)",
            "<class 'bool'>",
            ">>> type(None)",
            "<class 'NoneType'>",
          ],
        },
        {
          t: "table",
          head: ["Type", "Looks like", "Is for"],
          rows: [
            ["`int`", "`8080`, `-4`, `1_000_000`", "whole numbers"],
            ["`float`", "`80.5`, `2.0`", "numbers with a decimal point"],
            ["`str`", "`\"ada\"`, `'8080'`", "text, always in quotes"],
            ["`bool`", "`True`, `False`", "yes/no — capital first letter"],
            ["`NoneType`", "`None`", "\"no value at all\""],
          ],
        },
        {
          t: "box",
          kind: "rule",
          title: "`8080` and `\"8080\"` are different things",
          md: `One is a number you can do arithmetic with. The other is text that happens to contain digits.

\`\`\`
8080 + 1        # 8081
"8080" + 1      # TypeError
"8080" + "1"    # "80801"  -- joined, not added
\`\`\`

Confusing these is the single most common beginner bug, and in Module 1 it becomes a security one: everything typed by a user arrives as \`str\`, including things that look like numbers.`,
        },
        { t: "h", text: "Comments" },
        {
          t: "code",
          label: "example",
          code: `# a whole-line comment: Python ignores everything after the #
MAX_RETRIES = 3        # an end-of-line comment

# Good comments say WHY.
# Bad comments say what the code already says:
MAX_RETRIES = 3        # set MAX_RETRIES to 3`,
        },
      ],
      quiz: [
        {
          q: "`x = 5` then `y = x` then `x = 9`. What is `y`?",
          options: ["`9`", "`5`", "`None`"],
          answer: 1,
          why: "`y` took the value 5 at the moment of assignment. Re-pointing `x` afterwards does not change `y`.",
        },
        {
          q: "What does `\"5\" + 3` do?",
          options: ["`8`", "`\"53\"`", "Raises a TypeError"],
          answer: 2,
          why:
            "Python refuses to guess whether you meant addition or joining. `\"5\" + \"3\"` would give `\"53\"`, and `5 + 3` gives `8` — but mixing the two is an error, which is Python protecting you.",
        },
        {
          q: "You write `list = [1, 2, 3]`. What have you broken?",
          options: [
            "Nothing.",
            "The built-in `list` function, for the rest of the program.",
            "The variable `list` cannot hold numbers.",
          ],
          answer: 1,
          why: "You replaced a built-in with your own value. Use `items` or `numbers` instead.",
        },
      ],
      exercise: {
        title: "A profile card",
        brief: `Create four variables with exactly these names and values, then print one line per value.

| name | value | type |
|---|---|---|
| \`username\` | \`"ada"\` | str |
| \`port\` | \`8080\` | int |
| \`ratio\` | \`0.75\` | float |
| \`active\` | \`True\` | bool |

Then print exactly these four lines using the variables (not the literal text):

\`\`\`
username = ada (str)
port = 8080 (int)
ratio = 0.75 (float)
active = True (bool)
\`\`\`

Get the type name with \`type(value).__name__\`, which gives \`"str"\` rather than \`<class 'str'>\`.`,
        rubric: [
          "All four variables exist with the right values **and** the right types",
          "`port` is the number 8080, not the text `\"8080\"`",
          "Output lines match exactly, built from the variables",
        ],
        starter: `username = "ada"
# create port, ratio and active

print("username =", username, "(" + type(username).__name__ + ")")
# print the other three the same way
`,
        stdin: [],
        tests: [
          {
            name: "the four variables exist",
            code: `for n in ("username", "port", "ratio", "active"):
    assert n in dir(), f"no variable named {n}"`,
          },
          {
            name: "values are correct",
            code: `assert username == "ada", f"username is {username!r}"
assert port == 8080, f"port is {port!r}"
assert ratio == 0.75, f"ratio is {ratio!r}"
assert active is True, f"active is {active!r}"`,
          },
          {
            name: "types are correct — 8080 is a number, not text",
            code: `assert type(username) is str, f"username should be str, got {type(username).__name__}"
assert type(port) is int, f"port should be int (8080, no quotes), got {type(port).__name__}"
assert type(ratio) is float, f"ratio should be float, got {type(ratio).__name__}"
assert type(active) is bool, f"active should be bool (True, no quotes), got {type(active).__name__}"`,
          },
          {
            name: "prints the four lines exactly",
            code: `expected = ["username = ada (str)", "port = 8080 (int)",
            "ratio = 0.75 (float)", "active = True (bool)"]
assert _lines == expected, f"expected {expected}, got {_lines}"`,
          },
        ],
        requirements: [],
        hints: [
          'Numbers have no quotes: `port = 8080`. With quotes you would get the string `"8080"`, and the type test will tell you so.',
          "`True` is capitalised and has no quotes. `\"True\"` is text; `true` is a NameError.",
          'The print pattern is `print("port =", port, "(" + type(port).__name__ + ")")`.',
          "If a line comes out with a space before the bracket, remember `print` adds a space between each value it is given — build the bracketed part as one value with `+`.",
        ],
        solution: `username = "ada"
port = 8080
ratio = 0.75
active = True

print("username =", username, "(" + type(username).__name__ + ")")
print("port =", port, "(" + type(port).__name__ + ")")
print("ratio =", ratio, "(" + type(ratio).__name__ + ")")
print("active =", active, "(" + type(active).__name__ + ")")`,
        why: `The test that matters is the third one. \`port = "8080"\` would print an identical line and still fail, because the value is text pretending to be a number.

That distinction is not pedantry. From Module 1 onward, everything arriving from outside your program is text, and the first job is always to turn it into the type you actually need — deliberately, in one place, where you can also check it is sensible.

\`type(x).__name__\` gives the short name. \`type(x)\` alone prints \`<class 'int'>\`, which is why the exercise asks for the attribute.`,
      },
      wrapup: `- \`=\` assigns, \`==\` compares.
- A name holds a value; copying a name copies the value it pointed at then.
- \`8080\` and \`"8080"\` are different types, and Python will not silently convert between them.
- Never name a variable \`print\`, \`list\`, \`str\`, \`input\` or \`type\`.`,
      refs: [
        { label: "Python tutorial — an informal introduction", url: "https://docs.python.org/3/tutorial/introduction.html" },
        { label: "Built-in functions", url: "https://docs.python.org/3/library/functions.html" },
      ],
    },

    /* ------------------------------------------------------------------ 3 */
    {
      id: "m00l03",
      day: 3,
      title: "Text: quotes, f-strings and slicing",
      minutes: 60,
      secure: "text is data",
      tags: ["strings", "fstring", "slicing", "methods", "escapes"],
      lede:
        "Most of what a program handles is text, and most of what an attacker sends is text. Today is the mechanics: how to write it, join it, cut it up and reshape it.",
      blocks: [
        {
          t: "code",
          label: "example",
          code: `single = 'works fine'
double = "also fine"
apostrophe = "it's easier with double quotes"
quoted = 'she said "hello"'
long = """three quotes
span several
lines"""`,
          cap: "Single and double quotes are identical in Python. Choose whichever avoids escaping.",
        },
        { t: "h", text: "Escapes" },
        {
          t: "table",
          head: ["You write", "You get"],
          rows: [
            ["`\\n`", "a new line"],
            ["`\\t`", "a tab"],
            ["`\\\\`", "one backslash"],
            ["`\\\"`", "a double quote inside double quotes"],
            ["`r\"C:\\new\"`", "a *raw* string — backslashes stay literal"],
          ],
        },
        {
          t: "box",
          kind: "note",
          title: "Raw strings matter later",
          md: `\`"C:\\new"\` contains a newline, because \`\\n\` is an escape. \`r"C:\\new"\` is the five characters you expected.

You will use \`r"..."\` constantly from Module 2 onward, when writing the patterns that validate input.`,
        },
        { t: "h", text: "Joining text" },
        {
          t: "code",
          label: "example",
          code: `first = "ada"
last = "lovelace"

joined = first + " " + last          # concatenation
shout = "ha" * 3                     # repetition -> "hahaha"
greeting = f"Hello, {first}!"        # f-string -- the one to use`,
          cap: "An f-string is a string with `f` in front. Anything inside `{ }` is evaluated and dropped in.",
        },
        {
          t: "code",
          label: "example",
          code: `name = "ada"
count = 7
ratio = 2 / 3

print(f"user {name} has {count} items")
print(f"ratio: {ratio:.2f}")          # 2 decimal places
print(f"{count:>5}|")                 # right-aligned in 5 columns
print(f"{name!r}")                    # with quotes, as Python would show it
print(f"{count=}")                    # prints  count=7`,
          cap: "The bits after `:` are formatting; `!r` shows the value the way the console would. `{count=}` is a debugging shortcut.",
        },
        {
          t: "box",
          kind: "pitfall",
          title: "Forgetting the `f`",
          md: `\`\`\`
print("Hello, {name}")     # prints the braces literally
print(f"Hello, {name}")    # prints Hello, ada
\`\`\`

If you see \`{name}\` in your output, the \`f\` is missing.`,
        },
        { t: "h", text: "Looking inside a string" },
        {
          t: "repl",
          lines: [
            '>>> word = "security"',
            ">>> len(word)",
            "8",
            ">>> word[0]",
            "'s'",
            ">>> word[-1]",
            "'y'",
            ">>> word[0:3]",
            "'sec'",
            ">>> word[:3]",
            "'sec'",
            ">>> word[3:]",
            "'urity'",
            ">>> word[-3:]",
            "'ity'",
          ],
        },
        {
          t: "box",
          kind: "rule",
          title: "Counting starts at 0, and the end is excluded",
          md: `\`word[0]\` is the **first** character. \`word[0:3]\` gives characters 0, 1 and 2 — **not** 3.

Read \`word[0:3]\` as "from 0, up to but not including 3". It takes practice; everyone gets it wrong for a week.

Negative numbers count from the right: \`-1\` is the last character.`,
        },
        {
          t: "box",
          kind: "note",
          title: "Indexing raises, slicing does not",
          md: `\`word[99]\` raises \`IndexError\`. \`word[0:99]\` quietly gives you whatever exists.

That difference is useful: slicing is the simple way to cut something down to a maximum length without checking it first. You will use \`value[:200]\` throughout the course to bound text you did not write.`,
        },
        { t: "h", text: "The methods you will actually use" },
        {
          t: "code",
          label: "example",
          code: `raw = "  Ada Lovelace  "

raw.strip()                  # "Ada Lovelace"  -- removes surrounding whitespace
raw.strip().lower()          # "ada lovelace"
raw.strip().upper()          # "ADA LOVELACE"
raw.strip().replace(" ", "-")  # "Ada-Lovelace"
"a,b,c".split(",")           # ["a", "b", "c"]
"-".join(["a", "b", "c"])    # "a-b-c"
"ada@example.com".startswith("ada")   # True
"ada@example.com".endswith(".com")    # True
"hello".isdigit()            # False
"8080".isdigit()             # True`,
          cap: "Methods are called with a dot on the value itself. They can be chained left to right.",
        },
        {
          t: "box",
          kind: "warn",
          title: "Strings never change",
          md: `\`\`\`
name = "ada"
name.upper()        # produces "ADA" -- and throws it away
print(name)         # still "ada"

name = name.upper() # this is how you keep it
\`\`\`

Every string method *returns a new string*. Nothing you call on a string modifies it. Forgetting to assign the result is a top-three beginner bug.`,
        },
      ],
      spot: {
        label: "a greeting that does not work",
        prompt: "One line here does not do what the author intended. Click it.",
        lines: [3],
        why:
          "Line 3. `name.strip()` builds a stripped copy and discards it — strings never change in place. It needs `name = name.strip()`. Line 4's f-string is fine, and line 2 is fine.",
        code: `def greet(raw):
    name = raw
    name.strip()
    return f"Hello, {name}!"`,
      },
      quiz: [
        {
          q: "`word = \"python\"`. What is `word[1:4]`?",
          options: ["`\"pyt\"`", "`\"yth\"`", "`\"ytho\"`"],
          answer: 1,
          why: "Start at index 1 (`y`), stop *before* index 4. That gives characters 1, 2 and 3: `yth`.",
        },
        {
          q: "`name = \"ada\"` then `name.upper()` then `print(name)`. What prints?",
          options: ["`ADA`", "`ada`", "Nothing"],
          answer: 1,
          why: "String methods return a new string and never modify the original. You need `name = name.upper()`.",
        },
        {
          q: "`print(\"Total: {amount}\")` prints the braces literally. Why?",
          options: [
            "`amount` does not exist.",
            "The `f` prefix is missing — it is a plain string.",
            "Braces must be doubled.",
          ],
          answer: 1,
          why: "Only an f-string evaluates `{...}`. Write `f\"Total: {amount}\"`.",
        },
      ],
      exercise: {
        title: "Clean up a name",
        brief: `Users type messily. Write code that tidies one name and builds a few things from it.

Starting from \`raw = "   Ada  LOVELACE  "\`, create these variables:

| name | value | how |
|---|---|---|
| \`clean\` | \`"Ada  LOVELACE"\` | strip the surrounding whitespace |
| \`lower\` | \`"ada  lovelace"\` | lower-case of \`clean\` |
| \`parts\` | \`["ada", "lovelace"]\` | \`lower\` split on whitespace |
| \`slug\` | \`"ada-lovelace"\` | the parts joined with a hyphen |
| \`initials\` | \`"AL"\` | first letter of each part, upper-cased |

Then print exactly:

\`\`\`
slug: ada-lovelace
initials: AL
length: 12
\`\`\`

where \`length\` is the number of characters in \`slug\`.

Hint for \`parts\`: calling \`.split()\` with **no argument** splits on any run of whitespace, which handles the double space for you.`,
        rubric: [
          "All five variables exist with exactly the listed values",
          "`parts` is a list of two lower-case words",
          "`.split()` is called with no argument, so the double space collapses",
          "The three output lines match exactly",
        ],
        starter: `raw = "   Ada  LOVELACE  "

clean = raw.strip()
# build lower, parts, slug and initials

# then print the three lines
`,
        stdin: [],
        tests: [
          {
            name: "clean and lower",
            code: `assert clean == "Ada  LOVELACE", f"clean is {clean!r}"
assert lower == "ada  lovelace", f"lower is {lower!r}"`,
          },
          {
            name: "parts splits on whitespace, collapsing the double space",
            code: `assert parts == ["ada", "lovelace"], f"parts is {parts!r} -- call .split() with no argument"`,
          },
          {
            name: "slug and initials",
            code: `assert slug == "ada-lovelace", f"slug is {slug!r}"
assert initials == "AL", f"initials is {initials!r}"`,
          },
          {
            name: "prints the three lines exactly",
            code: `expected = ["slug: ada-lovelace", "initials: AL", "length: 12"]
assert _lines == expected, f"expected {expected}, got {_lines}"`,
          },
          {
            name: "length is computed, not typed",
            code: `assert "length: " + str(len(slug)) in _stdout, "print len(slug), do not hard-code 12"`,
          },
        ],
        requirements: [{ kind: "calls", value: "split" }],
        hints: [
          "`lower = clean.lower()` — remember to assign the result; methods never change the original.",
          '`parts = lower.split()` with empty parentheses. `lower.split(" ")` would give you `["ada", "", "lovelace"]` because of the double space.',
          '`slug = "-".join(parts)` — the separator goes on the left, and you call `.join` on it.',
          "`initials`: take `parts[0][0]` and `parts[1][0]`, join them, and `.upper()` the result.",
          'For the output, f-strings are easiest: `print(f"slug: {slug}")`.',
        ],
        solution: `raw = "   Ada  LOVELACE  "

clean = raw.strip()
lower = clean.lower()
parts = lower.split()
slug = "-".join(parts)
initials = (parts[0][0] + parts[1][0]).upper()

print(f"slug: {slug}")
print(f"initials: {initials}")
print(f"length: {len(slug)}")`,
        why: `Every line takes the result of the previous one and names it. That is the normal shape of text handling: a short chain of small, obvious steps, each with a name you can print when something goes wrong.

\`.split()\` with no argument is the detail worth remembering. It splits on *any run* of whitespace and discards empties, so the double space and the stray tab a user pasted both vanish. \`.split(" ")\` splits on exactly one space and would hand you an empty string in the middle.

\`parts[0][0]\` reads as "the first part, then its first character" — two index operations in a row, left to right. That stacking works on anything you can index.

From Module 1 you will do this same tidying on values that came from outside the program, and the course's name for it is *normalisation*: reduce a value to one predictable form before you make any decision with it.`,
      },
      wrapup: `- Single and double quotes are the same; pick the one that avoids escapes.
- f-strings (\`f"..."\`) are how you build text from values.
- Indexing starts at 0; a slice excludes its end; negatives count from the right.
- String methods return new strings — assign the result or it is lost.`,
      refs: [
        { label: "String methods", url: "https://docs.python.org/3/library/stdtypes.html#string-methods" },
        { label: "PEP 498 — f-strings", url: "https://peps.python.org/pep-0498/" },
      ],
    },

    /* ------------------------------------------------------------------ 4 */
    {
      id: "m00l04",
      day: 4,
      title: "Numbers, comparisons and True/False",
      minutes: 60,
      secure: "exact arithmetic",
      tags: ["int", "float", "operators", "comparison", "bool"],
      lede:
        "Arithmetic, the two kinds of division, and the comparisons that produce `True` and `False` — which is what every decision in every program is built from.",
      blocks: [
        {
          t: "code",
          label: "example",
          code: `7 + 2       # 9
7 - 2       # 5
7 * 2       # 14
7 / 2       # 3.5     <- always a float
7 // 2      # 3       <- floor division: whole part only
7 % 2       # 1       <- remainder
7 ** 2      # 49      <- power`,
          cap: "`/` always gives a float, even for `4 / 2` which is `2.0`. `//` keeps the whole part.",
        },
        {
          t: "box",
          kind: "note",
          title: "`%` is more useful than it looks",
          md: `The remainder tells you things no other operator does:

\`\`\`
n % 2 == 0      # is n even?
n % 5 == 0      # is n a multiple of 5?
total % 100     # the cents part of an amount in pence
\`\`\``,
        },
        { t: "h", text: "Order of operations" },
        {
          t: "repl",
          lines: [
            ">>> 2 + 3 * 4",
            "14",
            ">>> (2 + 3) * 4",
            "20",
            ">>> 10 - 2 - 3",
            "5",
            ">>> 2 ** 3 ** 2",
            "512",
          ],
        },
        {
          t: "p",
          md: `Multiplication and division happen before addition and subtraction, as in school maths. \`**\` binds tightest and groups right-to-left, so \`2 ** 3 ** 2\` is \`2 ** 9\`.

Use parentheses whenever there is any doubt. Nobody has ever complained that an expression had too many brackets.`,
        },
        { t: "h", text: "Converting between types" },
        {
          t: "code",
          label: "example",
          code: `int("42")        # 42      text -> number
int(3.9)         # 3       float -> int, truncates (does NOT round)
float("3.5")     # 3.5
str(42)          # "42"    number -> text
round(3.7)       # 4       this is how you round`,
          cap: "`int()` on a float chops the decimal part off. `int(\"3.9\")` is a `ValueError` — it only accepts whole numbers as text.",
        },
        {
          t: "box",
          kind: "warn",
          title: "Floats are not exact",
          md: `\`\`\`
0.1 + 0.2        # 0.30000000000000004
\`\`\`

That is not a Python bug; it is how computers store decimals in binary. It is harmless for measurements and dangerous for money.

Module 1, Day 10 covers what to do about it. For now: be unsurprised when a float has a long tail.`,
        },
        { t: "h", text: "Comparisons produce True or False" },
        {
          t: "code",
          label: "example",
          code: `5 > 3        # True
5 < 3        # False
5 >= 5       # True
5 == 5       # True    <- two equals signs
5 != 3       # True    <- "not equal"
"a" == "A"   # False   <- text comparison is case-sensitive

1 <= port <= 65535     # chained: reads like maths, and works`,
          cap: "A comparison is an expression whose value is `True` or `False`. You can print one, store it in a variable, or use it in an `if`.",
        },
        {
          t: "code",
          label: "example",
          code: `age = 20
has_ticket = True

age >= 18 and has_ticket      # True   -- both must hold
age >= 18 or has_ticket       # True   -- at least one
not has_ticket                # False  -- flips it`,
          cap: "`and`, `or` and `not` are spelled as words in Python, not as symbols.",
        },
        {
          t: "box",
          kind: "pitfall",
          title: "`=` in an `if` is a SyntaxError",
          md: `\`\`\`
if count = 5:      # SyntaxError: invalid syntax
if count == 5:     # correct
\`\`\`

Python refuses to let you assign inside a condition by accident. In some languages this is a silent, notorious bug; here it simply will not run.`,
        },
        {
          t: "box",
          kind: "note",
          title: "A number is not a truth value — but Python will treat it as one",
          md: `\`0\`, \`""\`, \`[]\` and \`None\` all count as false in a condition; almost everything else counts as true. That shortcut is convenient and occasionally disastrous — \`"False"\` is a *non-empty string*, so it counts as **true**.

Module 1, Day 11 is entirely about that trap. For now, compare explicitly and you cannot be caught by it.`,
        },
      ],
      quiz: [
        {
          q: "What is `7 // 2`?",
          options: ["`3.5`", "`3`", "`4`"],
          answer: 1,
          why: "`//` is floor division — the whole part, decimal discarded. `7 / 2` would give `3.5`.",
        },
        {
          q: "What is `int(3.9)`?",
          options: ["`4`", "`3`", "`3.9`"],
          answer: 1,
          why: "`int()` truncates toward zero; it does not round. Use `round(3.9)` for 4.",
        },
        {
          q: "`2 + 3 * 4` evaluates to:",
          options: ["`20`", "`14`", "`24`"],
          answer: 1,
          why: "Multiplication first: `3 * 4` is 12, plus 2 is 14. Use `(2 + 3) * 4` if you meant 20.",
        },
      ],
      exercise: {
        title: "A receipt line",
        brief: `Work in **whole pence**, never floats — Module 1 explains why in detail, and the habit starts now.

Given these variables (already in the starter):

\`\`\`
unit_price_pence = 1299      # £12.99
quantity = 3
discount_percent = 10
\`\`\`

Compute, in this order:

| name | meaning |
|---|---|
| \`subtotal\` | \`unit_price_pence * quantity\` |
| \`discount\` | \`discount_percent\` percent of \`subtotal\`, as a **whole number of pence** using \`//\` |
| \`total\` | \`subtotal\` minus \`discount\` |
| \`pounds\` | the whole pounds in \`total\` |
| \`pence\` | the leftover pence in \`total\` |

Then print exactly:

\`\`\`
subtotal: 3897
discount: 389
total: 3508
payable: £35.08
\`\`\`

The last line needs the pence padded to two digits — \`f"{pence:02d}"\` does that.`,
        rubric: [
          "All five values computed with integer arithmetic (`*`, `//`, `%`, `-`)",
          "`discount` uses `//` so it stays a whole number of pence",
          "`pounds` and `pence` come from `//` and `%`",
          "The payable line shows `£35.08`, with the pence padded",
        ],
        starter: `unit_price_pence = 1299
quantity = 3
discount_percent = 10

subtotal = unit_price_pence * quantity
# compute discount, total, pounds and pence

# then print the four lines
`,
        stdin: [],
        tests: [
          {
            name: "the arithmetic is right",
            code: `assert subtotal == 3897, f"subtotal is {subtotal!r}"
assert discount == 389, f"discount is {discount!r} -- use // so it stays whole"
assert total == 3508, f"total is {total!r}"
assert pounds == 35, f"pounds is {pounds!r}"
assert pence == 8, f"pence is {pence!r}"`,
          },
          {
            name: "everything stays a whole number",
            code: `for n in ("subtotal", "discount", "total", "pounds", "pence"):
    v = globals()[n] if n in globals() else eval(n)
    assert type(v) is int, f"{n} should be an int, got {type(v).__name__} -- use // not /"`,
          },
          {
            name: "prints the four lines exactly",
            code: `expected = ["subtotal: 3897", "discount: 389", "total: 3508", "payable: £35.08"]
assert _lines == expected, f"expected {expected}, got {_lines}"`,
          },
          {
            name: "the pence are padded to two digits",
            code: `assert "£35.08" in _stdout, "pence need two digits -- use f\\"{pence:02d}\\""
assert "£35.8" not in _stdout, "that is £35.80, not £35.08"`,
          },
        ],
        requirements: [
          { kind: "forbids", value: "float\\s*\\(", message: "Stay in whole pence — no `float()`." },
        ],
        hints: [
          "`discount = subtotal * discount_percent // 100`. Multiply first, then divide, or you lose precision.",
          "`//` gives a whole number; `/` gives a float. If you see " +
            "`Unknown format code 'd' for object of type 'float'`, that is this mistake — " +
            "something upstream used `/` and the `:02d` cannot format a float.",
          "`pounds = total // 100` and `pence = total % 100`.",
          'The last line: `print(f"payable: £{pounds}.{pence:02d}")`. The `02d` means "at least 2 digits, padded with zeros".',
        ],
        solution: `unit_price_pence = 1299
quantity = 3
discount_percent = 10

subtotal = unit_price_pence * quantity
discount = subtotal * discount_percent // 100
total = subtotal - discount
pounds = total // 100
pence = total % 100

print(f"subtotal: {subtotal}")
print(f"discount: {discount}")
print(f"total: {total}")
print(f"payable: £{pounds}.{pence:02d}")`,
        why: `Every value is a whole number of pence, so every result is exact and reproducible. There is no \`0.30000000000000004\` hiding anywhere, because no float is ever created.

\`subtotal * discount_percent // 100\` multiplies before dividing. The other order — \`subtotal * (discount_percent // 100)\` — computes \`10 // 100\`, which is \`0\`, and gives a discount of nothing. Operator order is not a style question here; it is the difference between a correct bill and a free one.

\`//\` and \`%\` are a pair: one gives you the pounds, the other the pence left over. You will reach for that pair constantly — splitting seconds into minutes, bytes into kilobytes, items into pages.

\`{pence:02d}\` is formatting, not arithmetic. Without it, 8 pence prints as \`£35.8\`, which reads as 80 pence. Money is the classic example of a value that must be *computed* exactly and *displayed* carefully, and they are two separate jobs.`,
      },
      wrapup: `- \`/\` always gives a float; \`//\` gives the whole part; \`%\` gives the remainder.
- \`int()\` truncates, \`round()\` rounds.
- Comparisons produce \`True\`/\`False\`; combine them with the words \`and\`, \`or\`, \`not\`.
- Floats carry small errors. Whole numbers do not — which is why money lives in pence.`,
      refs: [
        { label: "Numeric types", url: "https://docs.python.org/3/library/stdtypes.html#numeric-types-int-float-complex" },
        { label: "Format specification mini-language", url: "https://docs.python.org/3/library/string.html#format-specification-mini-language" },
      ],
    },

    /* ------------------------------------------------------------------ 5 */
    {
      id: "m00l05",
      day: 5,
      title: "Blocks: indentation, if and loops",
      minutes: 60,
      secure: "blocks and control",
      tags: ["indentation", "if", "for", "while", "range", "lists"],
      lede:
        "Python uses indentation where other languages use braces. That is the single biggest change in how your code looks — and the source of the error message beginners see most.",
      blocks: [
        {
          t: "p",
          md: `A {{block}} is a group of lines that belong together. The rule has two halves:

1. the line that opens a block ends with a **colon**,
2. the lines inside it are **indented** — by four spaces, consistently.`,
        },
        {
          t: "code",
          label: "example",
          code: `temperature = 30

if temperature > 25:
    print("warm")
    print("still inside the if")
print("always runs -- back at the outer level")`,
          cap: "The indented lines run only when the condition is true. The unindented line always runs. Nothing but indentation says so.",
        },
        {
          t: "box",
          kind: "pitfall",
          title: "The two errors you will see most",
          md: `**\`IndentationError: expected an indented block\`** — you wrote the colon but left the next line flush left. A block cannot be empty.

**\`IndentationError: unexpected indent\`** — a line is indented when nothing opened a block above it.

Both are fixed by looking at the colon on the line above and the spaces on the line below. The editor here indents for you after a colon.`,
        },
        {
          t: "box",
          kind: "warn",
          title: "Never mix tabs and spaces",
          md: `They can look identical on screen and Python will reject the file with \`TabError\`. Use spaces — four of them. The editor in this course inserts spaces when you press Tab, so you are safe here.`,
        },
        { t: "h", text: "Making decisions" },
        {
          t: "code",
          label: "example",
          code: `score = 72

if score >= 90:
    grade = "A"
elif score >= 80:
    grade = "B"
elif score >= 70:
    grade = "C"
else:
    grade = "F"

print(grade)      # C`,
          cap: "`elif` is \"else if\". Python checks each in order and takes the **first** one that is true, then skips the rest.",
        },
        {
          t: "box",
          kind: "rule",
          title: "Order matters in an if/elif chain",
          md: `If you put \`score >= 70\` first, a score of 95 would be graded \`C\` — because the first true branch wins and nothing after it is examined.

Put the most specific or highest condition first. Getting this backwards is a logic bug, not a syntax error, so Python will not warn you.`,
        },
        { t: "h", text: "Lists, briefly" },
        {
          t: "code",
          label: "example",
          code: `names = ["ada", "lin", "mo"]

names[0]           # "ada"
len(names)         # 3
names.append("jo") # adds to the end
"ada" in names     # True`,
          cap: "A list holds several values in order. Module 3 covers them properly; today you need just enough to loop over one.",
        },
        { t: "h", text: "Repeating things" },
        {
          t: "code",
          label: "example",
          code: `for name in ["ada", "lin", "mo"]:
    print(name)

for letter in "abc":
    print(letter)

for i in range(3):
    print(i)              # 0, 1, 2

for i in range(1, 4):
    print(i)              # 1, 2, 3`,
          cap: "`for` takes each item in turn. `range(3)` counts 0, 1, 2 — it stops *before* the number you give it, exactly like slicing.",
        },
        {
          t: "code",
          label: "example",
          code: `total = 0
for price in [100, 250, 75]:
    total = total + price      # or: total += price
print(total)                   # 425`,
          cap: "The accumulator pattern: start at zero outside the loop, add inside it, use it after. Starting it *inside* the loop resets it every pass — a classic bug.",
        },
        {
          t: "code",
          label: "example",
          code: `countdown = 3
while countdown > 0:
    print(countdown)
    countdown = countdown - 1
print("go")`,
          cap: "`while` repeats as long as its condition holds. Something inside **must** change the condition, or it never stops.",
        },
        {
          t: "box",
          kind: "warn",
          title: "A `while` that never ends",
          md: `Forget the \`countdown = countdown - 1\` line and the loop runs forever. In this course the interpreter stops you with *"execution budget exceeded — this usually means a loop never ends"*, so you can simply fix it and run again.

Module 11 is about this failure deliberately: a loop whose stopping condition is controlled by someone else is a way to take a server down.`,
        },
        {
          t: "code",
          label: "example",
          code: `for n in [1, 2, 3, 4, 5]:
    if n == 3:
        continue          # skip just this one
    if n == 5:
        break             # stop the loop entirely
    print(n)              # 1, 2, 4`,
        },
      ],
      spot: {
        label: "a total that is always wrong",
        prompt: "This should print 425 but prints 75. Click the line that causes it.",
        lines: [3],
        why:
          "Line 3. `total = 0` is *inside* the loop, so it resets on every pass and only the last price survives. Move it above the `for` line. The indentation is what puts it inside — nothing else.",
        code: `prices = [100, 250, 75]
for price in prices:
    total = 0
    total += price
print(total)`,
      },
      quiz: [
        {
          q: "How many numbers does `range(4)` produce, and what are they?",
          options: ["4: 1, 2, 3, 4", "4: 0, 1, 2, 3", "5: 0, 1, 2, 3, 4"],
          answer: 1,
          why: "It starts at 0 and stops *before* 4 — the same \"end excluded\" rule as slicing.",
        },
        {
          q: "In an `if`/`elif` chain where two conditions are both true, what happens?",
          options: [
            "Both blocks run.",
            "Only the first true one runs; the rest are skipped.",
            "Python raises an error.",
          ],
          answer: 1,
          why: "First match wins. That is why ordering the conditions correctly is a real design decision.",
        },
        {
          q: "You write a `while` loop and nothing inside it changes the condition. What happens?",
          options: [
            "It runs once.",
            "It runs forever — here, until the interpreter's step budget stops it.",
            "Python refuses to run it.",
          ],
          answer: 1,
          why:
            "Nothing detects it in advance. This course caps the number of steps so you get a clear message instead of a frozen page.",
        },
      ],
      exercise: {
        title: "Summarise an order",
        brief: `You are given a list of prices in pence (in the starter):

\`\`\`
prices = [1299, 450, 2500, 99, 1750]
\`\`\`

Using a loop, compute:

| name | meaning |
|---|---|
| \`total\` | the sum of every price |
| \`count\` | how many prices there are |
| \`expensive\` | how many prices are **1000 or more** |
| \`biggest\` | the largest single price |

Then print one line per price in this form, numbered from 1:

\`\`\`
1. 1299
2. 450
3. 2500
4. 99
5. 1750
\`\`\`

followed by exactly:

\`\`\`
count: 5
total: 6098
expensive: 3
biggest: 2500
\`\`\`

Do not use \`sum()\`, \`len()\` or \`max()\` — the point is to write the loop. Use \`enumerate(prices, start=1)\` for the numbering, or count manually.`,
        rubric: [
          "A `for` loop computes all four values",
          "`sum`, `len` and `max` are not used",
          "Lines are numbered from 1",
          "All four summary lines match exactly",
        ],
        starter: `prices = [1299, 450, 2500, 99, 1750]

total = 0
count = 0
expensive = 0
biggest = 0

# loop over prices: print each numbered line and update the four values

# then print the four summary lines
`,
        stdin: [],
        tests: [
          {
            name: "the four values are right",
            code: `assert total == 6098, f"total is {total!r}"
assert count == 5, f"count is {count!r}"
assert expensive == 3, f"expensive is {expensive!r}"
assert biggest == 2500, f"biggest is {biggest!r}"`,
          },
          {
            name: "each price is printed, numbered from 1",
            code: `for i, p in enumerate([1299, 450, 2500, 99, 1750], start=1):
    assert f"{i}. {p}" in _stdout, f"missing line '{i}. {p}'"`,
          },
          {
            name: "the summary lines match exactly",
            code: `assert _lines[-4:] == ["count: 5", "total: 6098", "expensive: 3", "biggest: 2500"], \\
    f"last four lines are {_lines[-4:]}"`,
          },
          {
            name: "the loop does the work",
            code: `assert len(_lines) == 9, f"expected 5 price lines + 4 summary lines, got {len(_lines)}"`,
          },
        ],
        requirements: [
          { kind: "regex", value: "for\\s+\\w+", message: "Use a `for` loop." },
          { kind: "forbids", value: "\\bsum\\s*\\(", message: "Write the loop instead of using sum()." },
          { kind: "forbids", value: "\\bmax\\s*\\(", message: "Write the loop instead of using max()." },
          { kind: "forbids", value: "\\blen\\s*\\(", message: "Count in the loop instead of using len()." },
        ],
        hints: [
          "`for position, price in enumerate(prices, start=1):` gives you the number and the value together.",
          "Inside the loop: print the numbered line, add to `total`, add 1 to `count`, and check the two conditions.",
          "`if price >= 1000:` then `expensive += 1`. `+=` is shorthand for `expensive = expensive + 1`.",
          "For `biggest`: `if price > biggest:` then `biggest = price`. Starting it at 0 works because every price is positive.",
          "Keep the four starting values **above** the loop, or they reset on every pass.",
        ],
        solution: `prices = [1299, 450, 2500, 99, 1750]

total = 0
count = 0
expensive = 0
biggest = 0

for position, price in enumerate(prices, start=1):
    print(f"{position}. {price}")
    total += price
    count += 1
    if price >= 1000:
        expensive += 1
    if price > biggest:
        biggest = price

print(f"count: {count}")
print(f"total: {total}")
print(f"expensive: {expensive}")
print(f"biggest: {biggest}")`,
        why: `Four accumulators, all initialised **above** the loop and updated inside it. That placement is the whole exercise: move any of those four lines in by four spaces and it resets on every pass, which is the bug in today's spot-the-problem drill.

\`enumerate(prices, start=1)\` hands you the position and the value at once. The alternative — keeping your own counter, or using \`prices[i]\` with a \`range\` — works, but has two places to make an off-by-one mistake instead of none.

\`biggest\` starting at \`0\` is safe only because prices cannot be negative. With temperatures or balances you would start at the first element instead. It is worth noticing *why* a starting value is safe rather than copying one that happened to work.

The two \`if\` statements inside the loop are independent, not \`elif\` — a price can be both the biggest and over 1000, and both counters must see it.`,
      },
      wrapup: `- Colon opens a block; four spaces of indentation define it.
- \`if\`/\`elif\`/\`else\` takes the first true branch and skips the rest.
- \`range(n)\` counts from 0 and stops before \`n\`.
- Initialise accumulators *outside* the loop, or they reset every pass.
- A \`while\` needs something inside it that changes the condition.`,
      refs: [
        { label: "Python tutorial — control flow", url: "https://docs.python.org/3/tutorial/controlflow.html" },
        { label: "PEP 8 — indentation", url: "https://peps.python.org/pep-0008/#indentation" },
      ],
    },

    /* ------------------------------------------------------------------ 6 */
    {
      id: "m00l06",
      day: 6,
      title: "Capstone: functions, and your first real program",
      minutes: 60,
      secure: "functions as contracts",
      tags: ["capstone", "functions", "def", "return", "arguments", "import"],
      lede:
        "A function is a named piece of code you can run whenever you like. Everything from Module 1 onward is written as functions, so this is the last thing you need before starting.",
      blocks: [
        {
          t: "code",
          label: "example",
          code: `def greet(name):
    return f"Hello, {name}!"

message = greet("ada")
print(message)              # Hello, ada!`,
          cap: "`def` names it. `name` is a parameter — a placeholder filled in when you call. `return` hands a value back to whoever called.",
        },
        {
          t: "box",
          kind: "rule",
          title: "`return` and `print` are not the same thing",
          md: `\`print\` puts text on the screen and gives nothing back. \`return\` hands a **value** back to the caller and puts nothing on screen.

\`\`\`
def double(n):
    print(n * 2)       # shows it; the caller gets None

def double(n):
    return n * 2       # the caller gets the number, and can use it
\`\`\`

\`result = double(5)\` with the first version leaves \`result\` as \`None\`. Prefer \`return\` — a function that returns a value can be tested, reused and combined. This matters immediately: every graded exercise in this course checks what your functions **return**.`,
        },
        { t: "h", text: "Arguments" },
        {
          t: "code",
          label: "example",
          code: `def describe(name, role="member", active=True):
    return f"{name} ({role}) active={active}"

describe("ada")                          # ada (member) active=True
describe("lin", "admin")                 # lin (admin) active=True
describe("mo", role="editor")            # mo (editor) active=True
describe("jo", active=False)             # jo (member) active=False`,
          cap: "Parameters with an `=` have a default and may be omitted. Naming an argument at the call site lets you skip over the ones in between — and makes the call readable.",
        },
        {
          t: "box",
          kind: "note",
          title: "A function with no `return` gives back `None`",
          md: `\`\`\`
def shout(text):
    print(text.upper())

value = shout("hi")     # prints HI
print(value)            # None
\`\`\`

That is not an error — it is Python telling you the function had no answer to give.`,
        },
        { t: "h", text: "Names inside a function stay inside it" },
        {
          t: "code",
          label: "example",
          code: `def compute():
    temp = 42        # exists only while compute() runs
    return temp

print(compute())     # 42
print(temp)          # NameError: name 'temp' is not defined`,
          cap: "A variable created inside a function is *local* to it. This is a feature: two functions can both use `i` or `total` without colliding.",
        },
        { t: "h", text: "Using code other people wrote" },
        {
          t: "code",
          label: "example",
          code: `import math

print(math.sqrt(16))        # 4.0
print(math.floor(3.7))      # 3

from math import sqrt
print(sqrt(25))             # 5.0`,
          cap: "`import x` then `x.thing()`. Or `from x import thing` to use `thing()` directly. Put imports at the top of the file.",
        },
        {
          t: "box",
          kind: "good",
          title: "What a good small function looks like",
          md: `- **One job**, describable in a short sentence.
- A **name that says what it returns** — \`total_pence\`, \`is_valid\`, \`clean_name\`.
- Takes what it needs as **parameters** rather than reaching for outside variables.
- **Returns** a value instead of printing one.

Hold on to the last two. From Module 1 they stop being style advice: a function that takes its input as a parameter and returns a result is one you can test, and testing is how you find out whether your security checks actually work.`,
        },
      ],
      quiz: [
        {
          q: "`def double(n): print(n * 2)` — what is `result` after `result = double(5)`?",
          options: ["`10`", "`None`", "`5`"],
          answer: 1,
          why: "It printed 10 but returned nothing, so `result` is `None`. Use `return n * 2`.",
        },
        {
          q: "A variable created inside a function, after the function finishes:",
          options: [
            "is still available outside",
            "no longer exists — it was local to that call",
            "becomes None",
          ],
          answer: 1,
          why: "Local names live only for the duration of the call. That isolation is what lets every function use `total` without interfering.",
        },
        {
          q: "`def describe(name, role=\"member\")`. Which call is wrong?",
          options: [
            "`describe(\"ada\")`",
            "`describe(\"ada\", \"admin\")`",
            "`describe(role=\"admin\")`",
          ],
          answer: 2,
          why: "`name` has no default, so it must always be supplied. The others are fine.",
        },
      ],
      exercise: {
        title: "A receipt printer",
        brief: `Put the whole module together. Write three functions and then use them.

1. \`line_total(unit_pence, quantity)\` — returns \`unit_pence * quantity\`.

2. \`money(pence)\` — returns the amount as text: \`money(3508)\` → \`"£35.08"\`. Pad the pence to two digits.

3. \`receipt(items)\` — \`items\` is a list of \`(name, unit_pence, quantity)\` tuples. It must:
   - print one line per item as \`"<name> x<quantity> = <money>"\`, e.g. \`"widget x3 = £38.97"\`
   - print \`"total: <money>"\` as the last line
   - **return** the total in pence as an \`int\`

Then call \`receipt\` with the \`ITEMS\` list in the starter and print nothing else.

Expected output:

\`\`\`
widget x3 = £38.97
gadget x1 = £4.50
cable x2 = £35.00
total: £78.47
\`\`\``,
        rubric: [
          "`line_total` and `money` return values rather than printing",
          "`money(5)` is `\"£0.05\"` — pence padded to two digits",
          "`receipt` prints one line per item plus a total line",
          "`receipt` **returns** the total in pence as an int",
          "The three functions are used together, not reimplemented inline",
        ],
        starter: `ITEMS = [
    ("widget", 1299, 3),
    ("gadget", 450, 1),
    ("cable", 1750, 2),
]


def line_total(unit_pence, quantity):
    """Return the cost of this line, in pence."""


def money(pence):
    """Return pence as text, e.g. 3508 -> '£35.08'."""


def receipt(items):
    """Print a line per item and a total; return the total in pence."""


receipt(ITEMS)
`,
        stdin: [],
        tests: [
          {
            name: "line_total returns, it does not print",
            code: `assert line_total(1299, 3) == 3897, f"got {line_total(1299, 3)!r}"
assert line_total(100, 0) == 0
assert line_total(5, 1) == 5`,
          },
          {
            name: "money formats correctly, including small amounts",
            code: `assert money(3508) == "£35.08", f"got {money(3508)!r}"
assert money(5) == "£0.05", f"got {money(5)!r} -- pad the pence to two digits"
assert money(100) == "£1.00", f"got {money(100)!r}"
assert money(0) == "£0.00", f"got {money(0)!r}"
assert money(123456) == "£1234.56", f"got {money(123456)!r}"`,
          },
          {
            name: "receipt returns the total as an int",
            code: `got = receipt([("a", 100, 2), ("b", 50, 1)])
assert got == 250, f"receipt should return 250, got {got!r}"
assert type(got) is int, f"return an int, got {type(got).__name__}"`,
          },
          {
            name: "receipt prints a line per item and a total",
            code: `expected = ["widget x3 = £38.97", "gadget x1 = £4.50",
            "cable x2 = £35.00", "total: £78.47"]
assert _lines == expected, f"expected {expected}, got {_lines}"`,
          },
          {
            name: "the functions are used together",
            code: `import io, contextlib

buf = io.StringIO()
with contextlib.redirect_stdout(buf):
    got = receipt([("x", 1000, 1), ("y", 250, 4)])
out = buf.getvalue().strip().split("\\n")

assert got == 2000, f"receipt should return 2000 for that list, got {got!r}"
assert out == ["x x1 = £10.00", "y x4 = £10.00", "total: £20.00"], \\
    f"receipt printed {out} -- build each line with line_total() and money()"`,
          },
        ],
        requirements: [
          { kind: "defines", value: "line_total" },
          { kind: "defines", value: "money" },
          { kind: "defines", value: "receipt" },
        ],
        hints: [
          "`line_total` is one line: `return unit_pence * quantity`.",
          '`money`: `return f"£{pence // 100}.{pence % 100:02d}"` — the `//` gives pounds, `%` the pence, `02d` pads.',
          "In `receipt`, start `total = 0` **before** the loop, then `for name, unit, qty in items:` unpacks each tuple into three names at once.",
          'Inside the loop: `cost = line_total(unit, qty)`, print `f"{name} x{qty} = {money(cost)}"`, then `total += cost`.',
          "After the loop, print the total line and then `return total`. The `return` goes last and is not indented inside the loop.",
        ],
        solution: `ITEMS = [
    ("widget", 1299, 3),
    ("gadget", 450, 1),
    ("cable", 1750, 2),
]


def line_total(unit_pence, quantity):
    """Return the cost of this line, in pence."""
    return unit_pence * quantity


def money(pence):
    """Return pence as text, e.g. 3508 -> '£35.08'."""
    return f"£{pence // 100}.{pence % 100:02d}"


def receipt(items):
    """Print a line per item and a total; return the total in pence."""
    total = 0
    for name, unit_pence, quantity in items:
        cost = line_total(unit_pence, quantity)
        print(f"{name} x{quantity} = {money(cost)}")
        total += cost

    print(f"total: {money(total)}")
    return total


receipt(ITEMS)`,
        why: `Three functions, each with one job, and the third built out of the other two. That is the shape of nearly every program: small pieces that return values, and one piece that arranges them.

\`line_total\` and \`money\` **return** rather than print, which is what makes them testable — the grader calls \`money(5)\` directly and checks it gives \`"£0.05"\`. A version that printed instead would be untestable and unusable inside \`receipt\`. Every graded exercise from Module 1 onward works this way.

\`receipt\` does both: it prints, because a receipt is for a human, *and* it returns the total, because the caller may need the number. Doing one without the other would make it half a function.

\`for name, unit_pence, quantity in items:\` unpacks each tuple into three names in one step. You will see that pattern everywhere.

Finally, note \`total = 0\` sits above the loop and \`return total\` sits below it, both at the function's own indentation level. Indent the \`return\` by four more spaces and it would fire on the first item, returning the first line's cost and ignoring the rest — a bug with no error message, which is exactly the kind Module 12 teaches you to catch with tests.

You are ready for Module 1.`,
      },
      wrapup: `- \`def name(parameters):\` then an indented body; \`return\` hands a value back.
- \`return\` gives a value to the caller; \`print\` shows text to a human. They are different jobs.
- A function with no \`return\` gives \`None\`.
- Names inside a function are local to it.
- Small functions that take parameters and return values are what the rest of this course is built from.`,
      refs: [
        { label: "Python tutorial — defining functions", url: "https://docs.python.org/3/tutorial/controlflow.html#defining-functions" },
        { label: "PEP 8 — style guide", url: "https://peps.python.org/pep-0008/" },
      ],
    },
  ],
};
