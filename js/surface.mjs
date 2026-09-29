// The function names each port's dispatcher answers to, read out of its source.
//
// Both were read with a regex that knew the INDENTATION: eight spaces before a Rust arm, one tab before
// a Go key. rustfmt or gofmt moving the table one level, or a reviewer wrapping it in a block, would
// have read zero names — and a guard for that (`size < 20`) stood in for knowing. These read the
// STRUCTURE instead: find the dispatcher (`fn dispatch` and its `match name { … }` in Rust, the
// `functions` map literal in Go), take its braces, and collect the string literals at its top level
// that are a match arm's pattern (`"a" | "b" =>`) or a map key (`"a":`). Strings, raw strings, rune
// and char literals and comments are stepped over, so nothing inside an arm's body is read as a name.
// A dispatcher that cannot be found is an error, not an empty set.

/** The text between the braces of the first `{` at or after `from`, balanced, skipping literals. */
function block(src, from, what) {
  const open = src.indexOf('{', from);
  if (from < 0 || open < 0) throw new Error(`surface: ${what} was not found`);
  let depth = 0;
  for (let i = open; i < src.length; i++) {
    const skip = literalEnd(src, i);
    if (skip > i) { i = skip - 1; continue; }
    const c = src[i];
    if (c === '{') depth++;
    else if (c === '}' && --depth === 0) return src.slice(open + 1, i);
  }
  throw new Error(`surface: ${what} never closes`);
}

/**
 * If a literal or comment starts at `i`, the index just past it; otherwise `i`.
 * Covers "…" with escapes, Rust raw strings (r"…", r#"…"#), Go back-quoted strings, line and block
 * comments, and char or rune literals.
 */
function literalEnd(s, i) {
  const c = s[i];
  if (c === '/' && s[i + 1] === '/') { const n = s.indexOf('\n', i); return n < 0 ? s.length : n; }
  if (c === '/' && s[i + 1] === '*') { const n = s.indexOf('*/', i + 2); return n < 0 ? s.length : n + 2; }
  if (c === 'r' && /[#"]/.test(s[i + 1] ?? '') && !/[A-Za-z0-9_]/.test(s[i - 1] ?? '')) {
    const m = /^r(#*)"/.exec(s.slice(i));
    if (m) { const close = '"' + m[1]; const n = s.indexOf(close, i + m[0].length); return n < 0 ? s.length : n + close.length; }
  }
  if (c === '"') {
    for (let j = i + 1; j < s.length; j++) { if (s[j] === '\\') j++; else if (s[j] === '"') return j + 1; }
    return s.length;
  }
  if (c === '`') { const n = s.indexOf('`', i + 1); return n < 0 ? s.length : n + 1; }
  if (c === "'") { const m = /^'(?:\\.[^']*|[^'\\])'/.exec(s.slice(i)); if (m) return i + m[0].length; }
  return i;
}

/** The tokens at the top level of a block: string literals (by value) and the punctuation around them. */
function topLevel(body) {
  const out = [];
  let depth = 0;
  for (let i = 0; i < body.length; i++) {
    const c = body[i];
    if (c === '"' && depth === 0) {
      const end = literalEnd(body, i);
      out.push({ str: body.slice(i + 1, end - 1) });
      i = end - 1;
      continue;
    }
    const skip = literalEnd(body, i);
    if (skip > i) { i = skip - 1; continue; }
    if ('([{'.includes(c)) depth++;
    else if (')]}'.includes(c)) depth--;
    else if (depth === 0 && /\S/.test(c)) {
      if (c === '=' && body[i + 1] === '>') { out.push({ p: '=>' }); i++; } else out.push({ p: c });
    }
  }
  return out;
}

/** The names `crates/pact-identity/src/api.rs` dispatches: the string patterns of `match name` in `fn dispatch`. */
export function rustDispatch(src) {
  const fn = src.search(/\bfn\s+dispatch\s*\(/);
  if (fn < 0) throw new Error('surface: fn dispatch was not found in the Rust source');
  const match = src.slice(fn).search(/\bmatch\s+name\s*\{/);
  if (match < 0) throw new Error('surface: `match name` was not found in fn dispatch');
  const t = topLevel(block(src, fn + match, 'the match in fn dispatch'));
  const names = new Set();
  for (let i = 0; i < t.length; i++) {
    if (t[i].str === undefined || t[i - 1]?.p === '|') continue; // a later alternative of a pattern already read
    const pattern = [t[i].str];
    let j = i + 1;
    while (t[j]?.p === '|' && t[j + 1]?.str !== undefined) { pattern.push(t[j + 1].str); j += 2; }
    if (t[j]?.p === '=>') for (const n of pattern) names.add(n);
  }
  return names;
}

/** The names `go/api.go` dispatches: the keys of its `functions` map literal. */
export function goDispatch(src) {
  const at = src.search(/\bvar\s+functions\s*=\s*map\[string\]/);
  if (at < 0) throw new Error('surface: the functions map was not found in the Go source');
  // The map's own brace is the first after `map[string]`: its value type is a named type (`function`,
  // api.go), which has none.
  const t = topLevel(block(src, at, 'the functions map literal'));
  const names = new Set();
  for (let i = 0; i < t.length; i++) if (t[i].str !== undefined && t[i + 1]?.p === ':') names.add(t[i].str);
  return names;
}
