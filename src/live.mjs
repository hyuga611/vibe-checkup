import { jwtClaims } from './secrets.mjs';

const TIMEOUT_MS = 10_000;
const MAX_TABLES = 50;

const PUBLIC_KINDS = new Set(['supabase-anon', 'supabase-publishable']);

// A request only goes to a URL the project itself names, with a public key that belongs to it:
// a legacy anon key carries its project ref, and a key without one is used only when the project
// has exactly one URL and one key.
export function targets({ urls, keys }) {
  const usable = keys.filter((k) => PUBLIC_KINDS.has(k.kind) && jwtClaims(k.value)?.role !== 'service_role');
  const single = urls.length === 1 && usable.length === 1 ? usable[0] : undefined;
  return urls.flatMap((url) => {
    const ref = /^([a-z0-9]+)\.supabase\.(?:co|in)$/.exec(new URL(url).hostname)?.[1];
    const key = usable.find((k) => ref && k.ref === ref) ?? (single && (!ref || !single.ref) ? single : undefined);
    return key ? [{ url, key: key.value }] : [];
  });
}

const totalFrom = (range) => {
  const total = range && /\/(\d+)$/.exec(range)?.[1];
  return total === undefined ? undefined : Number(total);
};

// Only the row count and the column names leave this function; the row itself is dropped here.
export async function probe(url, key, table) {
  const target = new URL(`/rest/v1/${encodeURIComponent(table)}`, url);
  target.search = 'select=*&limit=1';
  const headers = { apikey: key, Accept: 'application/json', Prefer: 'count=estimated' };
  if (key.startsWith('eyJ')) headers.Authorization = `Bearer ${key}`;
  try {
    const res = await fetch(target, { method: 'GET', headers, redirect: 'manual', signal: AbortSignal.timeout(TIMEOUT_MS) });
    const body = await res.text();
    if (res.status === 401 || res.status === 403) return { table, status: 'denied' };
    if (res.status === 404) return { table, status: 'missing' };
    if (res.status !== 200 && res.status !== 206) return { table, status: 'error', detail: `HTTP ${res.status}` };
    let rows;
    try {
      rows = JSON.parse(body);
    } catch {
      return { table, status: 'error', detail: 'not JSON' };
    }
    if (!Array.isArray(rows)) return { table, status: 'error', detail: 'not a list' };
    if (!rows.length) return { table, status: 'empty' };
    return { table, status: 'readable', columns: Object.keys(rows[0] ?? {}), total: totalFrom(res.headers.get('content-range')) };
  } catch (e) {
    return { table, status: 'error', detail: e.name === 'TimeoutError' ? 'timed out' : e.cause?.code ?? e.message };
  }
}

export async function scanLive(supabase, tables) {
  const notes = [];
  const findings = [];
  const results = [];
  const to = targets(supabase);
  if (!to.length) notes.push({ id: 'live-no-target' });
  else if (!tables.length) notes.push({ id: 'live-no-tables' });
  for (const { url, key } of to) {
    for (const table of tables.slice(0, MAX_TABLES)) {
      const result = { url, ...(await probe(url, key, table)) };
      results.push(result);
      if (result.status === 'readable') {
        findings.push({ id: 'live-readable', severity: 'critical', params: { table, url, columns: result.columns, total: result.total }, locations: [] });
      }
    }
  }
  return { findings, notes, results };
}
