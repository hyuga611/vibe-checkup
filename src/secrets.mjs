import { isExampleEnv } from './project.mjs';
import { lineIndex } from './text.mjs';

const LOCAL_HOST = /^(?:localhost|127\.0\.0\.1|0\.0\.0\.0|db|postgres|host\.docker\.internal|\[::1\])$/i;
export const PLACEHOLDER = /^$|^(?:x+|\*+|\.+|0+)$|your[-_ ]|<[^>]*>|\$\{|^\[.*\]$|changeme|change[-_]me|placeholder|replace[-_ ]?me|^todo$|^example$|^xxx/i;

const SECRET_KEYS = [
  { kind: 'supabase-secret', re: /\bsb_secret_[A-Za-z0-9_-]{20,}/g },
  { kind: 'stripe', re: /\b[rs]k_(live|test)_[0-9a-zA-Z]{10,}/g, test: (m) => m[1] === 'test' },
  { kind: 'openai', re: /\bsk-(?:proj|svcacct|admin)-[A-Za-z0-9_-]{20,}|\bsk-[A-Za-z0-9]{20}T3BlbkFJ[A-Za-z0-9]{20}/g },
  { kind: 'anthropic', re: /\bsk-ant-(?:api|admin)\d\d-[A-Za-z0-9_-]{20,}/g },
  { kind: 'resend', re: /\bre_[A-Za-z0-9]{8,}_[A-Za-z0-9]{16,}/g },
  { kind: 'sendgrid', re: /\bSG\.[A-Za-z0-9_-]{22}\.[A-Za-z0-9_-]{43}/g },
  { kind: 'aws', re: /\b(?:AKIA|ASIA)[0-9A-Z]{16}\b/g },
  { kind: 'github', re: /\b(?:gh[pousr]_[A-Za-z0-9]{36,}|github_pat_[A-Za-z0-9_]{50,})/g },
  { kind: 'private-key', re: /-----BEGIN (?:RSA |EC |DSA |OPENSSH |ENCRYPTED )?PRIVATE KEY-----/g },
  {
    kind: 'database-url',
    re: /\bpostgres(?:ql)?:\/\/[^\s:@'"`/]+:([^\s@'"`]+)@([^\s:/'"`]+)/g,
    real: (m) => !LOCAL_HOST.test(m[2]) && !PLACEHOLDER.test(m[1]),
  },
];

// Keys that are made to be public. They are reported as fine, never as problems.
const PUBLIC_KEYS = [
  { kind: 'supabase-publishable', re: /\bsb_publishable_[A-Za-z0-9_-]{10,}/g },
  { kind: 'google-api-key', re: /\bAIza[0-9A-Za-z_-]{35}/g },
  { kind: 'stripe-publishable', re: /\bpk_(?:live|test)_[0-9a-zA-Z]{10,}/g },
];

const JWT = /\beyJ[A-Za-z0-9_-]{8,}\.eyJ[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{8,}/g;

export function jwtClaims(token) {
  try {
    return JSON.parse(Buffer.from(token.split('.')[1], 'base64url').toString('utf8'));
  } catch {
    return null;
  }
}

export function findKeys(text) {
  const keys = [];
  for (const { kind, re, test, real } of SECRET_KEYS) {
    for (const m of text.matchAll(re)) {
      if (!real || real(m)) keys.push({ kind, value: m[0], secret: true, test: test?.(m) ?? false, index: m.index });
    }
  }
  // Supabase's legacy keys are JWTs: the role claim is what tells the admin key from the public one.
  for (const m of text.matchAll(JWT)) {
    const claims = jwtClaims(m[0]);
    if (claims?.role === 'service_role') keys.push({ kind: 'supabase-service-role', value: m[0], secret: true, test: false, index: m.index });
    else if (claims?.role === 'anon') keys.push({ kind: 'supabase-anon', value: m[0], secret: false, ref: claims.ref, index: m.index });
  }
  for (const { kind, re } of PUBLIC_KEYS) {
    for (const m of text.matchAll(re)) keys.push({ kind, value: m[0], secret: false, index: m.index });
  }
  return keys;
}

const SHOWN_PREFIX = /^(?:sb_secret_|sb_publishable_|[rsp]k_(?:live|test)_|sk-(?:proj|svcacct|admin)-|sk-ant-[a-z]+\d\d-|sk-|re_|SG\.|AKIA|ASIA|gh[pousr]_|github_pat_|AIza|eyJ|postgres(?:ql)?:\/\/|-----BEGIN [A-Z ]*PRIVATE KEY-----)/;

// Only the well-known prefix is ever printed, never a character of the secret itself.
export const mask = (value) => `${SHOWN_PREFIX.exec(value)?.[0] ?? value.slice(0, 3)}…`;

export function parseEnv(text) {
  const vars = [];
  text.split(/\r?\n/).forEach((raw, i) => {
    const m = /^\s*(?:export\s+)?([A-Za-z_][A-Za-z0-9_]*)\s*=\s*(.*)$/.exec(raw);
    if (!m) return;
    const quoted = /^(['"`])(.*)\1/.exec(m[2].trim());
    vars.push({ name: m[1], value: quoted ? quoted[2] : m[2].replace(/\s+#.*$/, '').trim(), line: i + 1 });
  });
  return vars;
}

const SECRET_WORDS = new Set([
  'SECRET', 'PRIVATE', 'PASSWORD', 'PASSWD', 'OPENAI', 'ANTHROPIC', 'CLAUDE', 'GEMINI', 'GROQ', 'MISTRAL',
  'DEEPSEEK', 'PERPLEXITY', 'XAI', 'GROK', 'REPLICATE', 'ELEVENLABS', 'COHERE', 'HUGGINGFACE', 'HF',
  'RESEND', 'SENDGRID', 'MAILGUN', 'POSTMARK', 'BREVO', 'TWILIO',
]);
const SECRET_PHRASES = /SERVICE_ROLE|SERVICE_KEY|DATABASE_URL|DB_URL|AWS_SECRET|AWS_ACCESS_KEY|GOOGLE_AI|GENAI/;
const PUBLIC_WORDS = new Set(['PUBLISHABLE', 'ANON', 'PUBLIC', 'SITE', 'FIREBASE', 'MEASUREMENT']);

// Whether a variable's name says it holds something only a server should know.
export function secretName(name, prefix) {
  const rest = name.slice(prefix.length);
  const words = rest.split('_');
  if (words.some((w) => PUBLIC_WORDS.has(w))) return false;
  return words.some((w) => SECRET_WORDS.has(w)) || SECRET_PHRASES.test(rest);
}

const ENV_REF = /\b(?:import\.meta\.env|process\.env)(?:\.([A-Za-z_]\w*)|\[\s*['"]([A-Za-z_]\w*)['"]\s*\])/g;
const BROWSER_AI = /dangerouslyAllowBrowser\s*:\s*true|anthropic-dangerous-direct-browser-access['"]?\s*[:,]\s*['"]?true/g;
const SUPABASE_URLS = [
  /\bhttps:\/\/[a-z0-9-]+\.supabase\.(?:co|in)\b/g,
  /SUPABASE_URL['"]?\s*[:=]\s*['"`](https?:\/\/[^'"`\s]+)['"`]/g,
  /\bcreateClient\s*(?:<[^>()]*>)?\(\s*['"`](https?:\/\/[^'"`\s]+)['"`]/g,
];

export function projectUrl(value) {
  try {
    const url = new URL(value);
    if (!/^https?:$/.test(url.protocol) || /your|xxx|example|<|\{|\$/i.test(url.hostname)) return null;
    return url.origin;
  } catch {
    return null;
  }
}

function nameBefore(text, index) {
  const start = Math.max(text.lastIndexOf('\n', index - 1) + 1, index - 120);
  const name = /([A-Za-z_$][\w$]*)['"]?\s*[:=]\s*['"`]?$/.exec(text.slice(start, index))?.[1];
  return name && name.length > 2 ? name : undefined;
}

const lineText = (text, index) => text.slice(text.lastIndexOf('\n', index - 1) + 1, index + 1);

const PLACE_RANK = { repo: 0, server: 0, mixed: 1, browser: 2 };
const LEAK_IDS = ['secret-in-code', 'secret-maybe-in-browser', 'secret-in-browser'];
const SEVERITIES = ['medium', 'high', 'critical'];

function addTo(map, key, init, entry) {
  if (!map.has(key)) map.set(key, { ...init, entries: [] });
  const group = map.get(key);
  if (!group.entries.some((e) => e.file === entry.file && e.line === entry.line)) group.entries.push(entry);
}

export function scanSecrets(project) {
  const leaks = new Map();
  const names = new Map();
  const browserAi = [];
  const publicKeys = new Map();
  const supabase = { urls: new Set(), keys: new Map() };

  const leak = (k, place, loc, context) => {
    const kind = k.kind === 'stripe' && /clerk/i.test(`${loc.name ?? ''} ${context}`) ? 'clerk' : k.kind;
    addTo(leaks, k.value, { kind, test: k.test, value: k.value }, { place, ...loc });
  };
  const seenPublic = (k, loc) => {
    if (!publicKeys.has(k.kind)) publicKeys.set(k.kind, loc);
    if (k.kind === 'supabase-anon' || k.kind === 'supabase-publishable') supabase.keys.set(k.value, { kind: k.kind, ref: k.ref });
  };
  const prefixOf = (name) => project.publicPrefixes.find((p) => name.startsWith(p));

  for (const file of project.files) {
    const text = project.read(file);
    if (text == null) continue;
    const place = project.locate(file);

    if (place === 'env') {
      const example = isExampleEnv(file);
      for (const v of parseEnv(text)) {
        const prefix = prefixOf(v.name);
        const loc = { file, line: v.line, name: v.name };
        const keys = findKeys(v.value);
        // VITE_GEMINI_API_KEY holds an AIza… key, the same shape as Firebase's public one:
        // the name is what gives it away.
        const secretVar = prefix && secretName(v.name, prefix) && !PLACEHOLDER.test(v.value);
        for (const k of keys) {
          if (k.secret) {
            if (prefix) leak(k, 'browser', loc, v.name);
            else if (example) leak(k, 'repo', loc, v.name);
          } else if (!example && !secretVar) seenPublic(k, loc);
        }
        if (secretVar && !keys.some((k) => k.secret)) {
          addTo(names, v.name, { name: v.name, prefix }, { place: 'browser', ...loc });
        }
        const url = !example && /SUPABASE_URL$/.test(v.name) && projectUrl(v.value);
        if (url) supabase.urls.add(url);
      }
      continue;
    }

    const lines = lineIndex(text);
    for (const k of findKeys(text)) {
      const loc = { file, line: lines(k.index), name: nameBefore(text, k.index) };
      if (!k.secret) {
        if (place !== 'server') seenPublic(k, loc);
      } else leak(k, place, loc, lineText(text, k.index));
    }
    if (place === 'browser' || place === 'mixed') {
      for (const m of text.matchAll(ENV_REF)) {
        const name = m[1] ?? m[2];
        const prefix = prefixOf(name);
        if (prefix && secretName(name, prefix)) addTo(names, name, { name, prefix }, { place, file, line: lines(m.index), name });
      }
      for (const m of text.matchAll(BROWSER_AI)) browserAi.push({ file, line: lines(m.index) });
    }
    if (place !== 'server') {
      for (const re of SUPABASE_URLS) {
        for (const m of text.matchAll(re)) {
          const url = projectUrl(m[1] ?? m[0]);
          if (url) supabase.urls.add(url);
        }
      }
    }
  }

  // A variable that also holds a recognised key is reported once, as that key.
  for (const [name, group] of names) {
    const owner = [...leaks.values()].find((l) => l.entries.some((e) => e.name === name));
    if (owner) {
      for (const e of group.entries) addTo(leaks, owner.value, owner, e);
      names.delete(name);
    }
  }

  const findings = [];
  for (const g of leaks.values()) {
    const rank = Math.max(...g.entries.map((e) => PLACE_RANK[e.place]));
    const entries = [...g.entries].sort((a, b) => PLACE_RANK[b.place] - PLACE_RANK[a.place]);
    findings.push({
      id: LEAK_IDS[rank],
      severity: SEVERITIES[Math.max(0, rank - (g.test ? 1 : 0))],
      params: { kind: g.kind, test: g.test, masked: mask(g.value) },
      locations: entries.map(({ file, line, name }) => ({ file, line, name })),
    });
  }
  for (const g of names.values()) {
    findings.push({
      id: 'secret-name-in-public-env',
      severity: 'high',
      params: { name: g.name, prefix: g.prefix },
      locations: g.entries.map(({ file, line, name }) => ({ file, line, name })),
    });
  }
  if (browserAi.length) findings.push({ id: 'ai-sdk-in-browser', severity: 'high', params: {}, locations: browserAi });

  const ok = [...publicKeys].map(([kind, loc]) => ({ id: 'public-key', params: { kind }, locations: [loc] }));
  return { findings, ok, supabase: { urls: [...supabase.urls], keys: [...supabase.keys].map(([value, k]) => ({ value, ...k })) } };
}
