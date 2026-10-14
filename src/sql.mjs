// Just enough SQL reading for migrations: statements, names and clauses. Not a parser.

export const ID = String.raw`(?:"(?:[^"]|"")+"|[A-Za-z_][A-Za-z0-9_$]*)`;
export const QNAME = String.raw`${ID}(?:\s*\.\s*${ID})?`;

const unquote = (id) => (id.startsWith('"') ? id.slice(1, -1).replace(/""/g, '"') : id.toLowerCase());

export function parseName(text) {
  const parts = text.match(new RegExp(ID, 'g')).map(unquote);
  return parts.length > 1 ? { schema: parts[0], name: parts[1] } : { schema: 'public', name: parts[0] };
}

export const nameKey = ({ schema, name }) => `${schema}.${name}`;

export function parseRoles(text) {
  return text.split(',').map((r) => unquote(r.trim().replace(/^group\s+/i, ''))).filter(Boolean);
}

const newlines = (s) => (s.match(/\n/g) ?? []).length;

// Comments are dropped; quoted strings and dollar-quoted bodies are kept whole, so a ';'
// inside a function body does not end the statement.
export function splitStatements(sql) {
  const out = [];
  let text = '';
  let line = 1;
  let start = 0;
  const take = (s) => {
    if (!start && /\S/.test(s)) start = line + newlines(s.slice(0, s.search(/\S/)));
    text += s;
    line += newlines(s);
  };
  const end = () => {
    if (text.trim()) out.push({ text: text.trim(), line: start });
    text = '';
    start = 0;
  };
  for (let i = 0; i < sql.length; ) {
    const c = sql[i];
    const next = sql[i + 1];
    let stop = i + 1;
    if (c === '-' && next === '-') {
      const nl = sql.indexOf('\n', i);
      i = nl === -1 ? sql.length : nl;
      continue;
    }
    if (c === '/' && next === '*') {
      const close = sql.indexOf('*/', i + 2);
      stop = close === -1 ? sql.length : close + 2;
      line += newlines(sql.slice(i, stop));
      text += ' ';
      i = stop;
      continue;
    }
    if (c === "'" || c === '"') {
      const close = sql.indexOf(c, i + 1);
      stop = close === -1 ? sql.length : close + 1;
    } else if (c === '$') {
      const tag = /^\$(?:[A-Za-z_][A-Za-z0-9_]*)?\$/.exec(sql.slice(i, i + 64))?.[0];
      if (tag) {
        const close = sql.indexOf(tag, i + tag.length);
        stop = close === -1 ? sql.length : close + tag.length;
      }
    } else if (c === ';') {
      end();
      i++;
      continue;
    }
    take(sql.slice(i, stop));
    i = stop;
  }
  end();
  return out;
}

export const collapse = (s) => s.replace(/\s+/g, ' ').trim();
