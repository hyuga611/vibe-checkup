import { MESSAGES } from './messages.mjs';
import { SEVERITY_ORDER } from './scan.mjs';

const WIDTH = 80;
const MAX_LOCATIONS = 5;

export function counts(findings) {
  const c = Object.fromEntries(SEVERITY_ORDER.map((s) => [s, 0]));
  for (const f of findings) c[f.severity]++;
  return c;
}

// Lines in the same file are listed together: "a.sql:7,15".
function places(locations) {
  const out = [];
  for (const l of locations) {
    const last = out.at(-1);
    if (last && last.file === l.file && !last.name && !l.name && l.line) last.lines.push(l.line);
    else out.push({ file: l.file, name: l.name, lines: l.line ? [l.line] : [] });
  }
  return out.map((p) => `${p.file}${p.lines.length ? `:${p.lines.join(',')}` : ''}${p.name ? ` (${p.name})` : ''}`);
}

function wrap(text, indent, lang) {
  const pad = ' '.repeat(indent);
  if (lang === 'ja') return text.split(/(?<=。)(?![」）])/).map((s) => s.trim()).filter(Boolean).map((s) => pad + s);
  const lines = [];
  let line = '';
  for (const word of text.split(/(?<=\s)(?=\S)/)) {
    if (line && indent + (line + word).trimEnd().length > WIDTH) {
      lines.push(pad + line.trimEnd());
      line = '';
    }
    line += word;
  }
  if (line.trim()) lines.push(pad + line.trimEnd());
  return lines;
}

export function describe(finding, lang) {
  return MESSAGES[lang].finding[finding.id](finding.params);
}

function renderFinding(f, m, lang) {
  const d = describe(f, lang);
  const out = [`${m.severity[f.severity]}${lang === 'ja' ? '' : '  '}${d.title}`];
  const all = places(f.locations);
  const where = all.slice(0, MAX_LOCATIONS);
  if (all.length > MAX_LOCATIONS) where.push(lang === 'ja' ? `ほか ${all.length - MAX_LOCATIONS} か所` : `and ${all.length - MAX_LOCATIONS} more`);
  if (where.length) out.push(`  ${m.label.where}: ${where.join(', ')}`);
  out.push(`  ${m.label.impact}:`, ...wrap(d.impact, 4, lang));
  out.push(`  ${m.label.fix}:`);
  d.fix.forEach((step, i) => {
    const [first, ...rest] = wrap(step, 7, lang);
    out.push(`    ${i + 1}. ${first.trimStart()}`, ...rest);
  });
  if (d.code) out.push('', ...d.code.split('\n').map((l) => `       ${l}`), '');
  if (d.ask) out.push(`  ${m.label.ask}:`, ...wrap(lang === 'ja' ? `「${d.ask.replace(/。$/, '')}」` : `"${d.ask}"`, 4, lang));
  return out.join('\n');
}

export function renderText(result, lang) {
  const m = MESSAGES[lang];
  const sections = [m.header(result.root, result.stack, result.files)];
  for (const f of result.findings) sections.push(renderFinding(f, m, lang));
  if (result.live?.length) {
    const width = Math.max(...result.live.map((r) => r.table.length));
    sections.push([`${m.label.live}:`, ...result.live.map((r) => `  ${r.table.padEnd(width)}  ${m.live[r.status](r)}`)].join('\n'));
  }
  if (result.ok.length) {
    sections.push([`${m.label.ok}:`, ...result.ok.flatMap((o) => wrap(m.ok[o.id](o.params), 4, lang).map((l, i) => (i ? l : `  - ${l.trimStart()}`)))].join('\n'));
  }
  if (result.notes.length) {
    sections.push([`${m.label.notes}:`, ...result.notes.flatMap((n) => wrap(m.note[n.id](n.params ?? {}), 4, lang).map((l, i) => (i ? l : `  - ${l.trimStart()}`)))].join('\n'));
  }
  if (result.problems.length) sections.push([`${m.label.problems}:`, ...result.problems.map((p) => `  - ${p}`)].join('\n'));
  sections.push(m.summary(counts(result.findings)));
  return `${sections.join('\n\n')}\n`;
}

export function renderJson(result, lang) {
  const m = MESSAGES[lang];
  return `${JSON.stringify(
    {
      root: result.root,
      stack: result.stack,
      files: result.files,
      counts: counts(result.findings),
      findings: result.findings.map((f) => ({ ...f, ...describe(f, lang) })),
      ok: result.ok.map((o) => ({ ...o, message: m.ok[o.id](o.params) })),
      notes: result.notes.map((n) => ({ ...n, message: m.note[n.id](n.params ?? {}) })),
      live: result.live,
      problems: result.problems,
    },
    null,
    2,
  )}\n`;
}
