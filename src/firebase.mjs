import { EVERYONE, NOBODY, SIGNED_IN, openness, until } from './access.mjs';
import { personalName, sensitiveFiles } from './names.mjs';
import { balanced, blankComments, lineIndex, splitTop } from './text.mjs';

const DEFAULT_FILES = { firestore: 'firestore.rules', storage: 'storage.rules', database: 'database.rules.json' };

function rulesFiles(project) {
  const out = [];
  for (const [service, fallback] of Object.entries(DEFAULT_FILES)) {
    const config = project.firebase?.[service];
    const listed = (Array.isArray(config) ? config : config ? [config] : []).map((c) => c?.rules).filter((p) => typeof p === 'string');
    const files = listed.length ? listed : [fallback];
    for (const file of files.map((f) => f.replace(/^\.\//, ''))) if (project.has(file)) out.push({ service, file });
  }
  return out;
}

const VERBS = { read: ['read'], get: ['read'], list: ['read'], write: ['add', 'change', 'delete'], create: ['add'], update: ['change'], delete: ['delete'] };
const OPS = { or: /\s*\|\|\s*/y, and: /\s*&&\s*/y };
const SIGNED_IN_ATOM = /^(?:request\.)?auth(?:\.uid)?\s*!==?\s*null$|^null\s*!==?\s*(?:request\.)?auth(?:\.uid)?$/;
const TEST_MODE = /^request\.time\s*<=?\s*timestamp\.date\(\s*(\d{4})\s*,\s*(\d{1,2})\s*,\s*(\d{1,2})\s*\)$/;
const RTDB_TEST_MODE = /^now\s*<=?\s*(\d{10,})$/;

function atom(now) {
  return (e) => {
    if (e === 'true') return { level: EVERYONE };
    if (e === 'false') return { level: NOBODY };
    if (SIGNED_IN_ATOM.test(e)) return { level: SIGNED_IN };
    const date = TEST_MODE.exec(e);
    if (date) return until(Date.UTC(+date[1], +date[2] - 1, +date[3]), now);
    const ms = RTDB_TEST_MODE.exec(e);
    return ms ? until(Number(ms[1]), now) : null;
  };
}

const escape = (s) => s.replace(/[.*+?^${}()|[\]\\]/g, '\\$&');
const substitute = (expr, name, value) => expr.replace(new RegExp(`(?<![.\\w$])${escape(name)}(?![\\w$])`, 'g'), () => `(${value})`);

// `{ let a = x; return a && b; }` becomes `(x) && b`.
function functionBody(inner) {
  let result = 'false';
  const lets = [];
  for (const part of splitTop(inner, /;/y)) {
    const binding = /^let\s+(\w+)\s*=\s*([\s\S]+)$/.exec(part);
    if (binding) lets.push([binding[1], binding[2]]);
    const ret = /^return\s+([\s\S]+)$/.exec(part);
    if (ret) result = ret[1];
  }
  for (const [name, value] of lets.reverse()) result = substitute(result, name, value);
  return result;
}

// Helper functions are written into the condition so the condition can be judged on its own.
function inline(expr, lookup, depth = 0) {
  if (depth > 8) return expr;
  const call = /(?<![.\w$])([A-Za-z_]\w*)\s*\(/g;
  let out = '';
  let from = 0;
  for (let m; (m = call.exec(expr)); ) {
    const fn = lookup(m[1]);
    if (!fn) continue;
    const { inner, end } = balanced(expr, m.index + m[0].length - 1);
    const args = splitTop(inner, /,/y);
    const body = fn.params.reduce((b, p, i) => substitute(b, p, args[i] ?? 'null'), fn.body);
    out += `${expr.slice(from, m.index)}(${inline(body, lookup, depth + 1)})`;
    from = call.lastIndex = end;
  }
  return out + expr.slice(from);
}

// An allow condition ends at ';', at a brace, or where the next statement starts.
function conditionEnd(src, from) {
  let depth = 0;
  for (let i = from; i < src.length; i++) {
    const c = src[i];
    if (c === "'" || c === '"') {
      const close = src.indexOf(c, i + 1);
      i = close === -1 ? src.length : close;
    } else if (c === '(' || c === '[') depth++;
    else if (c === ')' || c === ']') depth--;
    else if (depth <= 0 && (c === ';' || c === '{' || c === '}')) return i;
    else if (depth <= 0 && c === '\n' && /^\s*(?:allow|match|function)\b/.test(src.slice(i + 1, i + 40))) return i;
  }
  return src.length;
}

const TOKEN = /\bmatch\s+((?:[^\s{]|\{[^\s{}]*\})+)\s*\{|\bfunction\s+(\w+)\s*\(([^)]*)\)\s*\{|\ballow\s+([a-z]+(?:\s*,\s*[a-z]+)*)\s*(:\s*if\b)?|[{}]|(['"])/g;

export function parseRules(text) {
  const src = blankComments(text);
  const line = lineIndex(src);
  const scopes = [{ path: '', fns: new Map() }];
  const rules = [];
  const token = new RegExp(TOKEN);
  for (let m; (m = token.exec(src)); ) {
    const top = scopes.at(-1);
    if (m[6]) {
      const close = src.indexOf(m[6], m.index + 1);
      token.lastIndex = close === -1 ? src.length : close + 1;
    } else if (m[1]) {
      scopes.push({ path: `${top.path}/${m[1].replace(/^\//, '')}`, fns: new Map() });
    } else if (m[2]) {
      const { inner, end } = balanced(src, token.lastIndex - 1);
      top.fns.set(m[2], { params: m[3].split(',').map((p) => p.trim()).filter(Boolean), body: functionBody(inner) });
      token.lastIndex = end;
    } else if (m[4]) {
      const end = m[5] ? conditionEnd(src, token.lastIndex) : token.lastIndex;
      const chain = scopes.slice().reverse();
      const lookup = (name) => chain.find((s) => s.fns.has(name))?.fns.get(name);
      const condition = m[5] ? src.slice(token.lastIndex, end).trim() : 'true';
      rules.push({ path: top.path, methods: m[4].split(/\s*,\s*/), condition, lookup, line: line(m.index) });
      token.lastIndex = src[end] === ';' ? end + 1 : end;
    } else if (m[0] === '{') {
      scopes.push({ path: top.path, fns: new Map() });
    } else if (scopes.length > 1) {
      scopes.pop();
    }
  }
  return rules.map(({ lookup, condition, ...rule }) => ({ ...rule, condition: inline(condition, lookup) }));
}

function parseDatabaseRules(text) {
  const rules = [];
  const tree = JSON.parse(blankComments(text));
  const line = lineIndex(text);
  const visit = (node, path, cursor) => {
    for (const [key, value] of Object.entries(node ?? {})) {
      const at = Math.max(text.indexOf(JSON.stringify(key), cursor), cursor);
      if (key === '.read' || key === '.write') {
        rules.push({ path, methods: [key.slice(1)], condition: typeof value === 'string' ? value : String(value), line: line(at) });
      } else if (!key.startsWith('.') && value && typeof value === 'object') {
        visit(value, `${path}/${key}`, at);
      }
    }
  };
  visit(tree.rules, '', 0);
  return rules;
}

const ROOT = { firestore: /^\/databases\/\{[^}]+\}\/documents/, storage: /^\/b\/\{[^}]+\}\/o/, database: /^/ };
const segments = (path) => path.split('/').filter((s) => s && !/^[{$]/.test(s));
const isWhole = (path) => /^(?:\/\{[^}=]+=\*\*\})?$/.test(path);
const isPersonal = (service, path) => segments(path).some((s) => personalName(s) || (service === 'storage' && sensitiveFiles(s)));

export function scanFirebase(project, { now = Date.now() } = {}) {
  const files = rulesFiles(project);
  const findings = [];
  const ok = [];
  const notes = [];
  const problems = [];

  for (const { service, file } of files) {
    let rules;
    try {
      rules = service === 'database' ? parseDatabaseRules(project.read(file) ?? '') : parseRules(project.read(file) ?? '');
    } catch (e) {
      problems.push(`${file}: ${e.message}`);
      continue;
    }
    const groups = new Map();
    let expired;
    for (const rule of rules) {
      const result = openness(rule.condition, { ...OPS, atom: atom(now) });
      if (result.level < SIGNED_IN) {
        if (result.expired !== undefined) expired = Math.max(expired ?? 0, result.expired);
        continue;
      }
      const path = rule.path.replace(ROOT[service], '') || '/';
      const key = `${path}|${result.level}`;
      if (!groups.has(key)) groups.set(key, { path, level: result.level, verbs: new Set(), locations: [], until: undefined });
      const g = groups.get(key);
      for (const method of rule.methods) for (const verb of VERBS[method] ?? []) g.verbs.add(verb);
      g.locations.push({ file, line: rule.line });
      if (result.until !== undefined) g.until = Math.min(g.until ?? Infinity, result.until);
    }

    for (const g of groups.values()) {
      const verbs = [...g.verbs].filter((v) => v !== 'add');
      if (!verbs.length) continue;
      const whole = isWhole(g.path === '/' ? '' : g.path);
      const personal = isPersonal(service, g.path);
      const everyone = g.level === EVERYONE;
      const writes = verbs.includes('change') || verbs.includes('delete');
      const exposed = writes || whole || personal;
      const params = { service, file, path: g.path, scope: everyone ? 'everyone' : 'signed-in', verbs, whole, until: g.until && new Date(g.until).toISOString().slice(0, 10) };
      if (exposed) findings.push({ id: 'rules-open', severity: everyone ? 'critical' : 'high', params, locations: g.locations });
      else if (everyone) ok.push({ id: 'rules-public-read', params: { service, path: g.path }, locations: g.locations });
    }
    if (expired !== undefined && !groups.size) {
      notes.push({ id: 'test-mode-expired', params: { service, date: new Date(expired).toISOString().slice(0, 10) }, locations: [{ file }] });
    }
  }

  if (project.stack.firebase && !files.length) notes.push({ id: 'no-rules' });
  return { findings, ok, notes, problems, checked: files.length > 0 };
}
