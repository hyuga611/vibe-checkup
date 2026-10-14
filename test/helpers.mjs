import { mkdirSync, mkdtempSync, rmSync, writeFileSync } from 'node:fs';
import { createServer } from 'node:http';
import { tmpdir } from 'node:os';
import { dirname, join } from 'node:path';
import { loadProject } from '../src/project.mjs';

// Lays out a project in a fresh temp directory and removes it afterwards.
export async function withFiles(files, fn) {
  const root = mkdtempSync(join(tmpdir(), 'vibe-checkup-'));
  for (const [name, body] of Object.entries(files)) {
    const file = join(root, name);
    mkdirSync(dirname(file), { recursive: true });
    writeFileSync(file, typeof body === 'string' ? body : JSON.stringify(body));
  }
  try {
    return await fn(root);
  } finally {
    rmSync(root, { recursive: true, force: true });
  }
}

export const inProject = (files, fn) => withFiles(files, (root) => fn(loadProject(root), root));

// Fake keys are assembled at run time so that no secret-shaped string sits in this repository's
// test files, and each one says FAKE.
const b64 = (obj) => Buffer.from(JSON.stringify(obj)).toString('base64url');
export const jwt = (claims) => [b64({ alg: 'HS256', typ: 'JWT' }), b64(claims), 'FAKE-signature-not-valid'].join('.');
export const serviceRole = (ref = 'fakeprojectref0000001') => jwt({ iss: 'supabase', ref, role: 'service_role', note: 'FAKE' });
export const anon = (ref = 'fakeprojectref0000001') => jwt({ iss: 'supabase', ref, role: 'anon', note: 'FAKE' });
export const stripeLive = () => ['sk', 'live', 'FAKE0000000000000000000000'].join('_');
export const stripeTest = () => ['sk', 'test', 'FAKE0000000000000000000000'].join('_');
export const openai = () => ['sk', 'proj', 'FAKE000000000000000000000000000000'].join('-');
export const googleKey = () => 'AIza' + 'FAKE'.padEnd(35, '0');
export const dbUrl = (password, host) => ['postgresql://postgres', `${password}@${host}:5432/postgres`].join(':');

export const ids = (findings) => findings.map((f) => f.id);
export const byId = (findings, id) => findings.filter((f) => f.id === id);

export const SECRET_ROW = { id: 1, email: 'FAKE-person@example.invalid', password_hash: 'FAKE-hash-must-not-be-printed' };

// A stand-in for PostgREST: profiles leaks a row, todos is hidden by RLS, secrets refuses,
// anything else does not exist.
export async function withMockSupabase(fn) {
  const requests = [];
  const server = createServer((req, res) => {
    requests.push({ method: req.method, url: req.url, apikey: req.headers.apikey, authorization: req.headers.authorization });
    const table = new URL(req.url, 'http://x').pathname.split('/').pop();
    const send = (status, body, headers = {}) => {
      res.writeHead(status, { 'content-type': 'application/json', ...headers });
      res.end(JSON.stringify(body));
    };
    if (table === 'profiles') send(206, [SECRET_ROW], { 'content-range': '0-0/42' });
    else if (table === 'todos') send(200, [], { 'content-range': '*/0' });
    else if (table === 'secrets') send(401, { code: '42501', message: 'permission denied' });
    else send(404, { code: 'PGRST205', message: 'not found' });
  });
  await new Promise((resolve) => server.listen(0, '127.0.0.1', resolve));
  const url = `http://127.0.0.1:${server.address().port}`;
  try {
    return await fn(url, requests);
  } finally {
    server.close();
  }
}
