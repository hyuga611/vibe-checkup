import { EVERYONE, NOBODY, SIGNED_IN, openness } from './access.mjs';
import { ownerColumn, personalColumn, personalName, publicFiles, sensitiveFiles } from './names.mjs';
import { ID, QNAME, collapse, nameKey, parseName, parseRoles, splitStatements } from './sql.mjs';
import { balanced, splitTop } from './text.mjs';

const r = (src) => new RegExp(src, 'i');
const RE = {
  createTable: r(String.raw`^create\s+(?:(?:global|local)\s+)?(?:(?:temp|temporary|unlogged)\s+)?table\s+(?:if\s+not\s+exists\s+)?(${QNAME})\s*\(`),
  alterTable: r(String.raw`^alter\s+table\s+(?:if\s+exists\s+)?(?:only\s+)?(${QNAME})\s+(.*)$`),
  dropTable: /^drop\s+table\s+(?:if\s+exists\s+)?(.+?)(?:\s+(?:cascade|restrict))?$/i,
  createPolicy: r(String.raw`^create\s+policy\s+(${ID})\s+on\s+(${QNAME})(.*)$`),
  alterPolicy: r(String.raw`^alter\s+policy\s+(${ID})\s+on\s+(${QNAME})\s+(.*)$`),
  dropPolicy: r(String.raw`^drop\s+policy\s+(?:if\s+exists\s+)?(${ID})\s+on\s+(${QNAME})`),
  createFunction: r(String.raw`^create\s+(?:or\s+replace\s+)?function\s+(${QNAME})\s*\(`),
  dropFunction: r(String.raw`^drop\s+function\s+(?:if\s+exists\s+)?(${QNAME})`),
  createView: r(String.raw`^create\s+(?:or\s+replace\s+)?(?:(?:temp|temporary|recursive)\s+)*view\s+(${QNAME})\s*(?:\([^)]*\)\s*)?(?:with\s*\(([^)]*)\)\s*)?as\s+(.*)$`),
  alterView: r(String.raw`^alter\s+view\s+(?:if\s+exists\s+)?(${QNAME})\s+set\s*\(([^)]*)\)`),
  dropView: r(String.raw`^drop\s+view\s+(?:if\s+exists\s+)?(${QNAME})`),
  grantOn: /^grant\s+(.+?)\s+on\s+(.+?)\s+to\s+(.+?)(?:\s+with\s+grant\s+option)?(?:\s+granted\s+by\s+\S+)?$/i,
  grantRole: /^grant\s+([\w\s,"]+?)\s+to\s+([\w\s,"]+?)(?:\s+with\s+\w+\s+\w+)?$/i,
  revokeOn: /^revoke\s+(?:grant\s+option\s+for\s+)?(.+?)\s+on\s+(.+?)\s+from\s+(.+?)(?:\s+(?:cascade|restrict))?$/i,
  defaultRevoke: /^alter\s+default\s+privileges\s+(?:for\s+(?:role|user)\s+\S+\s+)?in\s+schema\s+(\S+)\s+revoke\s+(.+?)\s+on\s+functions\s+from\s+(.+?)(?:\s+(?:cascade|restrict))?$/i,
  alterRole: /^alter\s+role\s+(\S+)\s+(?:with\s+)?(.*)$/i,
  insertBucket: /^insert\s+into\s+storage\s*\.\s*buckets\s*\(([^)]*)\)\s*values\s*(.*)$/i,
  updateBucket: /^update\s+storage\s*\.\s*buckets\s+set\s+(.+?)\s+where\s+(.+)$/i,
};

const CLIENT_ROLES = new Set(['anon', 'authenticated', 'public']);
const ADMIN_ROLES = new Set(['service_role', 'postgres', 'supabase_admin']);
const isClient = (roles) => roles.some((role) => CLIENT_ROLES.has(role));
const isAll = (privileges) => /^all(?:\s+privileges)?$/i.test(privileges.trim());
const unquoteValue = (v) => v.trim().replace(/^'(.*)'$/, '$1').replace(/''/g, "'");

function createDb() {
  return { tables: new Map(), policies: [], functions: new Map(), views: new Map(), buckets: new Map(), defaultRevoked: new Map(), escalations: [] };
}

function columnsOf(defs) {
  return splitTop(defs, /,/y)
    .filter((d) => !/^(?:constraint|primary|foreign|unique|check|exclude|like)\b/i.test(d))
    .map((d) => ({ name: parseName(new RegExp(`^${ID}`).exec(d)[0]).name, ownerRef: /\breferences\s+auth\s*\.\s*users\b/i.test(d) }));
}

function policyParts(rest) {
  const clause = /\busing\s*\(|\bwith\s+check\s*\(/i.exec(rest);
  const head = clause ? rest.slice(0, clause.index) : rest;
  const body = (re) => {
    const m = re.exec(rest);
    return m ? balanced(rest, m.index + m[0].length - 1).inner.trim() : undefined;
  };
  const as = /\bas\s+(permissive|restrictive)\b/i.exec(head);
  const cmd = /\bfor\s+(all|select|insert|update|delete)\b/i.exec(head);
  const to = /\bto\s+(.+)$/i.exec(head);
  return {
    permissive: as ? as[1].toLowerCase() === 'permissive' : undefined,
    cmd: cmd?.[1].toLowerCase(),
    roles: to ? parseRoles(to[1]) : undefined,
    using: body(/\busing\s*\(/i),
    check: body(/\bwith\s+check\s*\(/i),
  };
}

const defined = (o) => Object.fromEntries(Object.entries(o).filter(([, v]) => v !== undefined));

// Objects named by GRANT/REVOKE: "table a, b", "all tables in schema public", "function f(uuid)".
function objectsOf(text, db) {
  const all = /^all\s+(tables|functions)\s+in\s+schema\s+(.+)$/i.exec(text);
  if (all) {
    const schemas = new Set(parseRoles(all[2]));
    const pool = all[1].toLowerCase() === 'tables' ? db.tables : db.functions;
    return { kind: all[1].toLowerCase(), items: [...pool.values()].filter((o) => schemas.has(o.schema)) };
  }
  const fn = r(String.raw`^(?:function|procedure|routine)\s+(${QNAME})`).exec(text);
  if (fn) return { kind: 'functions', items: [db.functions.get(nameKey(parseName(fn[1])))].filter(Boolean) };
  const names = text.replace(/^table\s+/i, '');
  if (/^(?:schema|sequence|database|type|domain|all\s+sequences)\b/i.test(names)) return { kind: 'other', items: [] };
  return { kind: 'tables', items: splitTop(names, /,/y).map((n) => db.tables.get(nameKey(parseName(n)))).filter(Boolean) };
}

function apply(db, s, at) {
  let m;
  if ((m = RE.createTable.exec(s))) {
    const table = parseName(m[1]);
    const key = nameKey(table);
    if (!db.tables.has(key)) {
      const { inner } = balanced(s, m.index + m[0].length - 1);
      db.tables.set(key, { ...table, ...at, columns: columnsOf(inner), rls: false, revoked: new Set() });
    }
  } else if ((m = RE.alterTable.exec(s))) {
    const key = nameKey(parseName(m[1]));
    const table = db.tables.get(key);
    if (!table) return;
    for (const action of splitTop(m[2], /,/y)) {
      let a;
      if (/^enable\s+row\s+level\s+security$/i.test(action)) table.rls = true;
      else if (/^disable\s+row\s+level\s+security$/i.test(action)) table.rls = false;
      else if ((a = r(String.raw`^rename\s+to\s+(${ID})$`).exec(action))) {
        table.name = parseName(a[1]).name;
        const renamed = nameKey(table);
        db.tables.delete(key);
        db.tables.set(renamed, table);
        for (const p of db.policies) if (p.table === key) p.table = renamed;
      } else if ((a = r(String.raw`^add\s+(?:column\s+)?(?:if\s+not\s+exists\s+)?(${ID})\s`).exec(action))) {
        if (!/^(?:constraint|primary|foreign|unique|check|exclude)$/i.test(a[1])) table.columns.push(...columnsOf(action.replace(/^add\s+(?:column\s+)?(?:if\s+not\s+exists\s+)?/i, '')));
      }
    }
  } else if ((m = RE.dropTable.exec(s))) {
    for (const n of splitTop(m[1], /,/y)) {
      const key = nameKey(parseName(n));
      db.tables.delete(key);
      db.policies = db.policies.filter((p) => p.table !== key);
    }
  } else if ((m = RE.createPolicy.exec(s))) {
    const name = parseName(m[1]).name;
    const table = nameKey(parseName(m[2]));
    db.policies = db.policies.filter((p) => !(p.table === table && p.name === name));
    db.policies.push({ name, table, permissive: true, cmd: 'all', roles: ['public'], ...defined(policyParts(m[3])), ...at });
  } else if ((m = RE.alterPolicy.exec(s))) {
    const name = parseName(m[1]).name;
    const table = nameKey(parseName(m[2]));
    const policy = db.policies.find((p) => p.table === table && p.name === name);
    if (!policy) return;
    const rename = r(String.raw`^rename\s+to\s+(${ID})`).exec(m[3]);
    if (rename) policy.name = parseName(rename[1]).name;
    else Object.assign(policy, defined(policyParts(m[3])), at);
  } else if ((m = RE.dropPolicy.exec(s))) {
    const name = parseName(m[1]).name;
    const table = nameKey(parseName(m[2]));
    db.policies = db.policies.filter((p) => !(p.table === table && p.name === name));
  } else if ((m = RE.createFunction.exec(s))) {
    const fn = parseName(m[1]);
    const key = nameKey(fn);
    const rest = s.slice(balanced(s, m.index + m[0].length - 1).end);
    const dollar = /\$([A-Za-z_]\w*)?\$([\s\S]*?)\$\1\$/.exec(rest);
    const quoted = dollar ? null : /\bas\s+'((?:[^']|'')*)'/i.exec(rest);
    const attrs = dollar ? rest.replace(dollar[0], ' ') : rest;
    const returns = /\breturns\s+(setof\s+)?(table\b|[\w."]+)/i.exec(attrs);
    const revoked = db.functions.get(key)?.revoked ?? new Set(db.defaultRevoked.get(fn.schema));
    db.functions.set(key, {
      ...fn,
      ...at,
      definer: /\bsecurity\s+definer\b/i.test(attrs),
      returns: returns ? (returns[1] ? 'setof' : returns[2].toLowerCase()) : 'void',
      body: dollar?.[2] ?? quoted?.[1] ?? '',
      revoked,
    });
  } else if ((m = RE.dropFunction.exec(s))) {
    db.functions.delete(nameKey(parseName(m[1])));
  } else if ((m = RE.createView.exec(s))) {
    const view = parseName(m[1]);
    const refs = [...m[3].matchAll(new RegExp(String.raw`\b(?:from|join)\s+(${QNAME})`, 'gi'))].map((x) => parseName(x[1]));
    db.views.set(nameKey(view), { ...view, ...at, invoker: invokerOption(m[2]) ?? false, refs });
  } else if ((m = RE.alterView.exec(s))) {
    const view = db.views.get(nameKey(parseName(m[1])));
    const invoker = invokerOption(m[2]);
    if (view && invoker !== undefined) view.invoker = invoker;
  } else if ((m = RE.dropView.exec(s))) {
    db.views.delete(nameKey(parseName(m[1])));
  } else if ((m = RE.grantOn.exec(s))) {
    const grantees = parseRoles(m[3]);
    if (isClient(grantees) && /\b(?:auth|vault)\s*\.|\bschema\s+(?:auth|vault)\b/i.test(m[2])) {
      db.escalations.push({ kind: 'schema', object: m[2], grantees, ...at });
    }
    for (const o of objectsOf(m[2], db).items) for (const g of grantees) o.revoked.delete(g);
  } else if (!/\son\s/i.test(s) && (m = RE.grantRole.exec(s))) {
    const roles = parseRoles(m[1]);
    const grantees = parseRoles(m[2]);
    const admin = roles.find((role) => ADMIN_ROLES.has(role));
    if (admin && isClient(grantees)) db.escalations.push({ kind: 'role', object: admin, grantees, ...at });
  } else if ((m = RE.revokeOn.exec(s))) {
    const { kind, items } = objectsOf(m[2], db);
    const counts = kind === 'functions' ? /\b(?:all|execute)\b/i.test(m[1]) : isAll(m[1]);
    if (counts) for (const o of items) for (const g of parseRoles(m[3])) o.revoked.add(g);
  } else if ((m = RE.defaultRevoke.exec(s))) {
    if (/\b(?:all|execute)\b/i.test(m[2])) {
      const schema = parseName(m[1]).name;
      const roles = db.defaultRevoked.get(schema) ?? new Set();
      for (const g of parseRoles(m[3])) roles.add(g);
      db.defaultRevoked.set(schema, roles);
    }
  } else if ((m = RE.alterRole.exec(s))) {
    const role = parseName(m[1]).name;
    if (CLIENT_ROLES.has(role) && /(?<!no)bypassrls\b/i.test(m[2])) db.escalations.push({ kind: 'bypassrls', object: role, grantees: [role], ...at });
  } else if ((m = RE.insertBucket.exec(s))) {
    const columns = m[1].split(',').map((c) => c.trim().replace(/"/g, '').toLowerCase());
    const publicAt = columns.indexOf('public');
    const idAt = columns.includes('id') ? columns.indexOf('id') : columns.indexOf('name');
    const rows = m[2];
    for (let i = rows.indexOf('('); i !== -1 && idAt !== -1; i = rows.indexOf('(', i)) {
      const tuple = balanced(rows, i);
      const values = splitTop(tuple.inner, /,/y);
      const id = unquoteValue(values[idAt] ?? '');
      db.buckets.set(id, { id, public: publicAt !== -1 && /^(?:true|'t'|'true')$/i.test(values[publicAt] ?? ''), ...at });
      i = tuple.end;
      if (!/^\s*,/.test(rows.slice(i))) break;
    }
  } else if ((m = RE.updateBucket.exec(s))) {
    const pub = /\bpublic\s*=\s*(true|false)\b/i.exec(m[1]);
    const id = /\b(?:id|name)\s*=\s*'([^']+)'/i.exec(m[2]);
    const bucket = id && db.buckets.get(id[1]);
    if (pub && bucket) Object.assign(bucket, { public: pub[1].toLowerCase() === 'true' }, at);
  }
}

function invokerOption(options) {
  const m = options && /\bsecurity_invoker\b\s*(?:=\s*'?(\w+)'?)?/i.exec(options);
  if (!m) return undefined;
  return m[1] === undefined || /^(?:true|on|1|yes|t)$/i.test(m[1]);
}

const sensitiveColumns = (t) => t.columns.map((c) => c.name).filter(personalColumn);
const ownerOf = (t) => t.columns.find((c) => ownerColumn(c.name))?.name ?? t.columns.find((c) => c.ownerRef)?.name;
const isPersonal = (t) => personalName(t.name) || sensitiveColumns(t).length > 0 || ownerOf(t) !== undefined;

const authCall = (fn) => String.raw`(?:\(\s*select\s+auth\.${fn}\(\)\s*\)|auth\.${fn}\(\))`;
const SIGNED_IN_ATOMS = [
  r(String.raw`^${authCall('uid')}\s+is\s+not\s+null$`),
  r(String.raw`^${authCall('jwt')}\s+is\s+not\s+null$`),
  r(String.raw`^${authCall('role')}\s*=\s*'authenticated'$`),
];
const SQL_OPS = { or: /\s+or\s+/iy, and: /\s+and\s+/iy };

// `buckets` collects bucket_id = '…' conditions, which narrow storage.objects to a bucket
// but not to the person who owns the file.
function sqlAtom(expr, buckets) {
  const e = expr.replace(/::\s*[a-z_][\w.]*(?:\[\])?/gi, '').trim();
  if (/^(?:true|1\s*=\s*1|'t(?:rue)?')$/i.test(e)) return { level: EVERYONE };
  if (/^false$/i.test(e)) return { level: NOBODY };
  if (SIGNED_IN_ATOMS.some((re) => re.test(e))) return { level: SIGNED_IN };
  const bucket = buckets && (/^bucket_id\s*=\s*'([^']*)'$/i.exec(e) ?? /^'([^']*)'\s*=\s*bucket_id$/i.exec(e));
  if (bucket) {
    buckets.push(bucket[1]);
    return { level: EVERYONE };
  }
  return null;
}

const VERBS = { select: ['read'], insert: ['add'], update: ['change'], delete: ['delete'], all: ['read', 'add', 'change', 'delete'] };

function roleCap(roles) {
  if (roles.some((role) => role === 'public' || role === 'anon')) return EVERYONE;
  return roles.includes('authenticated') ? SIGNED_IN : NOBODY;
}

// Each way a policy lets everyone, or every signed-in user, past it. Restrictive policies are
// ANDed with the permissive ones, so they cap what those can open.
function openings(policies, storage) {
  const levelOf = (p, verb) => {
    const expr = verb === 'add' ? (p.check ?? p.using) : p.using;
    if (!expr) return { level: NOBODY, buckets: [] };
    const buckets = [];
    const { level } = openness(expr, { ...SQL_OPS, atom: (e) => sqlAtom(e, storage ? buckets : null) });
    return { level, buckets };
  };
  const cap = { read: EVERYONE, add: EVERYONE, change: EVERYONE, delete: EVERYONE };
  for (const p of policies.filter((x) => !x.permissive)) {
    for (const verb of VERBS[p.cmd]) cap[verb] = Math.min(cap[verb], levelOf(p, verb).level);
  }
  const out = [];
  for (const p of policies.filter((x) => x.permissive)) {
    for (const verb of VERBS[p.cmd]) {
      const { level, buckets } = levelOf(p, verb);
      const open = Math.min(level, roleCap(p.roles), cap[verb]);
      if (open >= SIGNED_IN) out.push({ verb, level: open, policy: p, buckets });
    }
  }
  return out;
}

function grouped(items, keyOf) {
  const groups = new Map();
  for (const item of items) {
    const key = keyOf(item);
    if (!groups.has(key)) groups.set(key, []);
    groups.get(key).push(item);
  }
  return [...groups.values()];
}

const scopeName = (level) => (level === EVERYONE ? 'everyone' : 'signed-in');
const locationsOf = (items) => [...new Map(items.map((i) => [`${i.file}:${i.line}`, { file: i.file, line: i.line }])).values()];

function evaluate(db) {
  const findings = [];
  const ok = [];

  for (const [key, t] of db.tables) {
    if (t.schema !== 'public' || (t.revoked.has('anon') && t.revoked.has('authenticated'))) continue;
    const policies = db.policies.filter((p) => p.table === key);
    const params = { table: t.name, columns: sensitiveColumns(t), owner: ownerOf(t) };
    if (!t.rls) {
      findings.push({ id: 'rls-disabled', severity: 'critical', params: { ...params, policies: policies.length }, locations: [{ file: t.file, line: t.line }] });
      continue;
    }
    const personal = isPersonal(t);
    for (const group of grouped(openings(policies, false), (o) => o.level)) {
      const verbs = [...new Set(group.map((o) => o.verb))].filter((v) => v !== 'add');
      if (!verbs.length) continue;
      const level = group[0].level;
      const writes = verbs.includes('change') || verbs.includes('delete');
      const names = [...new Set(group.map((o) => o.policy.name))];
      const locations = locationsOf(group.map((o) => o.policy));
      if (writes || personal) {
        findings.push({ id: 'policy-open', severity: level === EVERYONE ? 'critical' : 'high', params: { ...params, personal, scope: scopeName(level), verbs, policies: names }, locations });
      } else if (level === EVERYONE) {
        ok.push({ id: 'public-read', params: { table: t.name, policies: names }, locations });
      }
    }
  }

  const storage = db.policies.filter((p) => p.table === 'storage.objects');
  for (const group of grouped(openings(storage, true), (o) => `${o.level}|${[...new Set(o.buckets)].sort().join(',')}`)) {
    const level = group[0].level;
    const buckets = [...new Set(group[0].buckets)].sort();
    const verbs = [...new Set(group.map((o) => o.verb))];
    const sensitive = !buckets.length || buckets.some(sensitiveFiles);
    const writes = verbs.includes('change') || verbs.includes('delete');
    const reads = verbs.includes('read');
    const everyone = level === EVERYONE;
    const severity = writes || (reads && sensitive) ? (everyone ? 'critical' : 'high') : everyone && verbs.includes('add') ? 'medium' : null;
    const names = [...new Set(group.map((o) => o.policy.name))];
    const locations = locationsOf(group.map((o) => o.policy));
    if (severity) {
      findings.push({ id: 'storage-policy-open', severity, params: { buckets, scope: scopeName(level), verbs: severity === 'medium' ? ['add'] : verbs.filter((v) => v !== 'add' || everyone), policies: names }, locations });
    } else if (everyone && reads) {
      ok.push({ id: 'public-files', params: { buckets, policies: names }, locations });
    }
  }

  for (const b of db.buckets.values()) {
    if (!b.public) continue;
    const loc = [{ file: b.file, line: b.line }];
    if (publicFiles(b.id)) ok.push({ id: 'public-bucket', params: { bucket: b.id }, locations: loc });
    else findings.push({ id: 'bucket-public', severity: sensitiveFiles(b.id) ? 'high' : 'medium', params: { bucket: b.id, sensitive: sensitiveFiles(b.id) }, locations: loc });
  }

  for (const f of db.functions.values()) {
    if (f.schema !== 'public' || !f.definer || /^(?:trigger|event_trigger)$/.test(f.returns)) continue;
    // Postgres grants EXECUTE to PUBLIC by default, so revoking from anon alone is not enough.
    const callable = (role) => !(f.revoked.has(role) && f.revoked.has('public'));
    const anyone = callable('anon');
    if (!anyone && !callable('authenticated')) continue;
    const writes = /\b(?:insert\s+into|update\s+[\w."]+\s+set|delete\s+from|truncate|drop\s+\w|alter\s+\w|grant\s|execute\s)/i.test(f.body);
    if (!writes && f.returns === 'boolean') continue;
    const rank = (writes ? 1 : 0) + (anyone ? 1 : 0) - (/\bauth\.(?:uid|jwt)\(\)/i.test(f.body) ? 1 : 0);
    if (rank <= 0) continue;
    findings.push({ id: 'definer-function', severity: rank === 2 ? 'high' : 'medium', params: { fn: f.name, scope: anyone ? 'everyone' : 'signed-in', writes }, locations: [{ file: f.file, line: f.line }] });
  }

  for (const v of db.views.values()) {
    if (v.schema !== 'public' || v.invoker) continue;
    const loc = [{ file: v.file, line: v.line }];
    if (v.refs.some((ref) => ref.schema === 'auth' && ref.name === 'users')) {
      findings.push({ id: 'view-exposes-users', severity: 'critical', params: { view: v.name }, locations: loc });
      continue;
    }
    const guarded = v.refs.map((ref) => db.tables.get(nameKey(ref))).filter((t) => t?.rls).map((t) => t.name);
    if (guarded.length) findings.push({ id: 'view-bypasses-rls', severity: 'high', params: { view: v.name, tables: [...new Set(guarded)] }, locations: loc });
  }

  for (const e of db.escalations) {
    findings.push({ id: 'grant-too-broad', severity: 'critical', params: { kind: e.kind, object: e.object, grantees: e.grantees }, locations: [{ file: e.file, line: e.line }] });
  }

  return { findings, ok };
}

export function migrationFiles(project) {
  const migrations = project.files.filter((f) => /(?:^|\/)supabase\/migrations\/[^/]+\.sql$/i.test(f));
  return migrations.length ? migrations : project.files.filter((f) => /(?:^|\/)supabase\/schemas\/.+\.sql$/i.test(f));
}

export function readMigrations(project) {
  const db = createDb();
  for (const file of migrationFiles(project)) {
    for (const st of splitStatements(project.read(file) ?? '')) apply(db, collapse(st.text), { file, line: st.line });
  }
  return db;
}

export function scanSupabase(project) {
  const files = migrationFiles(project);
  const db = readMigrations(project);
  const { findings, ok } = evaluate(db);
  const notes = project.stack.supabase && !files.length ? [{ id: 'no-migrations' }] : [];
  const tables = [...db.tables.values()].filter((t) => t.schema === 'public').map((t) => t.name);
  return { findings, ok, notes, tables, checked: files.length > 0 };
}
