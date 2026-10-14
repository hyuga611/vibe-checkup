// Small helpers shared by the SQL and rules readers.

export function lineIndex(text) {
  const starts = [0];
  for (let i = text.indexOf('\n'); i !== -1; i = text.indexOf('\n', i + 1)) starts.push(i + 1);
  return (index) => {
    let lo = 0;
    let hi = starts.length - 1;
    while (lo < hi) {
      const mid = (lo + hi + 1) >> 1;
      if (starts[mid] <= index) lo = mid;
      else hi = mid - 1;
    }
    return lo + 1;
  };
}

// A doubled quote ('it''s') closes and reopens the run, so stopping at the next quote is enough.
function skipQuoted(s, i) {
  const end = s.indexOf(s[i], i + 1);
  return end === -1 ? s.length : end + 1;
}

const CLOSE = { '(': ')', '[': ']', '{': '}' };

export function balanced(s, open) {
  const close = CLOSE[s[open]];
  let depth = 0;
  for (let i = open; i < s.length; ) {
    const c = s[i];
    if (c === "'" || c === '"') {
      i = skipQuoted(s, i);
      continue;
    }
    if (c === s[open]) depth++;
    else if (c === close && --depth === 0) return { inner: s.slice(open + 1, i), end: i + 1 };
    i++;
  }
  return { inner: s.slice(open + 1), end: s.length };
}

// Splits `s` wherever the sticky regex `sep` matches outside brackets and quotes.
export function splitTop(s, sep) {
  const parts = [];
  let depth = 0;
  let from = 0;
  for (let i = 0; i < s.length; ) {
    const c = s[i];
    if (c === "'" || c === '"') {
      i = skipQuoted(s, i);
      continue;
    }
    if (c in CLOSE) depth++;
    else if (c === ')' || c === ']' || c === '}') depth--;
    else if (depth === 0) {
      sep.lastIndex = i;
      if (sep.test(s)) {
        parts.push(s.slice(from, i));
        i = from = sep.lastIndex;
        continue;
      }
    }
    i++;
  }
  parts.push(s.slice(from));
  return parts.map((p) => p.trim()).filter(Boolean);
}

export function unwrap(s) {
  let e = s.trim();
  while (e.startsWith('(') && balanced(e, 0).end === e.length) e = e.slice(1, -1).trim();
  return e;
}

// Blanks out // and /* */ comments but keeps every newline, so offsets still map to lines.
export function blankComments(text) {
  let out = '';
  for (let i = 0; i < text.length; ) {
    const c = text[i];
    if (c === "'" || c === '"') {
      const end = skipQuoted(text, i);
      out += text.slice(i, end);
      i = end;
    } else if (c === '/' && text[i + 1] === '/') {
      const end = text.indexOf('\n', i);
      const stop = end === -1 ? text.length : end;
      out += ' '.repeat(stop - i);
      i = stop;
    } else if (c === '/' && text[i + 1] === '*') {
      const end = text.indexOf('*/', i + 2);
      const stop = end === -1 ? text.length : end + 2;
      out += text.slice(i, stop).replace(/[^\n]/g, ' ');
      i = stop;
    } else {
      out += c;
      i++;
    }
  }
  return out;
}
