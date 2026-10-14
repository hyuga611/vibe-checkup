import { test } from 'node:test';
import assert from 'node:assert/strict';
import { findKeys, mask, scanSecrets, secretName } from '../src/secrets.mjs';
import { anon, byId, dbUrl, googleKey, ids, inProject, openai, serviceRole, stripeLive, stripeTest } from './helpers.mjs';

const VITE = { 'package.json': { dependencies: { react: '18', '@supabase/supabase-js': '2' }, devDependencies: { vite: '5' } } };
const NEXT = { 'package.json': { dependencies: { next: '14', react: '18' } } };

test('a service_role key in a VITE_ variable is critical; the anon key next to it is fine', () =>
  inProject({ ...VITE, '.env': `VITE_SUPABASE_URL=https://fakeprojectref0000001.supabase.co\nVITE_SUPABASE_ANON_KEY=${anon()}\nVITE_SUPABASE_SERVICE_ROLE_KEY=${serviceRole()}\n` }, (project) => {
    const r = scanSecrets(project);
    assert.deepEqual(ids(r.findings), ['secret-in-browser']);
    assert.equal(r.findings[0].severity, 'critical');
    assert.equal(r.findings[0].params.kind, 'supabase-service-role');
    assert.deepEqual(r.findings[0].locations, [{ file: '.env', line: 3, name: 'VITE_SUPABASE_SERVICE_ROLE_KEY' }]);
    assert.deepEqual(r.ok.map((o) => o.params.kind), ['supabase-anon']);
    assert.deepEqual(r.supabase.urls, ['https://fakeprojectref0000001.supabase.co']);
    assert.deepEqual(r.supabase.keys.map((k) => [k.kind, k.ref]), [['supabase-anon', 'fakeprojectref0000001']]);
  }));

test('the same variable without a public prefix stays on the server and is not reported', () =>
  inProject({ ...VITE, '.env': `SUPABASE_SERVICE_ROLE_KEY=${serviceRole()}\nOPENAI_API_KEY=${openai()}\n` }, (project) => {
    assert.deepEqual(scanSecrets(project).findings, []);
  }));

test('a key written into browser code is critical, and the variable that holds it is named', () =>
  inProject({ ...VITE, 'src/lib/pay.ts': `export const stripeKey = "${stripeLive()}";\n` }, (project) => {
    const [f] = scanSecrets(project).findings;
    assert.equal(f.id, 'secret-in-browser');
    assert.equal(f.severity, 'critical');
    assert.deepEqual(f.locations, [{ file: 'src/lib/pay.ts', line: 1, name: 'stripeKey' }]);
  }));

test('a Stripe test key is one step lower', () =>
  inProject({ ...VITE, 'src/pay.ts': `const k = "${stripeTest()}";` }, (project) => {
    const [f] = scanSecrets(project).findings;
    assert.equal(f.severity, 'high');
    assert.equal(f.params.test, true);
  }));

test('a built bundle in dist/ counts as browser code, and one key found twice is one finding', () =>
  inProject({ ...VITE, 'src/a.ts': `const k = "${stripeLive()}";`, 'dist/assets/index-abc.js': `var a="${stripeLive()}";` }, (project) => {
    const f = scanSecrets(project).findings;
    assert.equal(f.length, 1);
    assert.deepEqual(f[0].locations.map((l) => l.file).sort(), ['dist/assets/index-abc.js', 'src/a.ts']);
  }));

test('server code holds keys without leaking them to visitors', () =>
  inProject({ ...VITE, 'supabase/functions/chat/index.ts': `const key = "${openai()}";` }, (project) => {
    const [f] = scanSecrets(project).findings;
    assert.equal(f.id, 'secret-in-code');
    assert.equal(f.severity, 'medium');
  }));

test('Next.js: a file without "use client" may reach the browser, one with it does', () =>
  inProject({ ...NEXT, 'lib/stripe.ts': `const k = "${stripeLive()}";`, 'app/pay/page.tsx': `'use client';\nconst k2 = "${stripeTest()}";`, 'app/api/pay/route.ts': `const k3 = "${openai()}";` }, (project) => {
    const r = scanSecrets(project).findings;
    assert.deepEqual(r.map((f) => [f.id, f.locations[0].file]).sort(), [
      ['secret-in-browser', 'app/pay/page.tsx'],
      ['secret-in-code', 'app/api/pay/route.ts'],
      ['secret-maybe-in-browser', 'lib/stripe.ts'],
    ]);
  }));

test('a secret name behind a public prefix is reported even when the value looks like a public key', () =>
  inProject({ ...VITE, '.env': `VITE_GEMINI_API_KEY=${googleKey()}\nVITE_FIREBASE_API_KEY=${googleKey()}\n`, 'src/ai.ts': 'const k = import.meta.env.VITE_GEMINI_API_KEY;' }, (project) => {
    const r = scanSecrets(project);
    assert.deepEqual(ids(r.findings), ['secret-name-in-public-env']);
    assert.deepEqual(r.findings[0].locations.map((l) => l.file), ['.env', 'src/ai.ts']);
    assert.deepEqual(r.ok.map((o) => o.params.kind), ['google-api-key']);
  }));

test('a secret name that also holds a known key is reported once, as that key', () =>
  inProject({ ...VITE, '.env': `VITE_OPENAI_API_KEY=${openai()}\n`, 'src/ai.ts': 'const k = import.meta.env.VITE_OPENAI_API_KEY;' }, (project) => {
    const r = scanSecrets(project).findings;
    assert.deepEqual(ids(r), ['secret-in-browser']);
    assert.deepEqual(r[0].locations.map((l) => l.file), ['.env', 'src/ai.ts']);
  }));

test('envPrefix in vite.config widens what counts as public', () =>
  inProject({ ...VITE, 'vite.config.ts': "export default { envPrefix: ['VITE_', 'APP_'] };", '.env': `APP_STRIPE_SECRET=${stripeLive()}\n` }, (project) => {
    assert.deepEqual(ids(scanSecrets(project).findings), ['secret-in-browser']);
  }));

test('dangerouslyAllowBrowser is reported', () =>
  inProject({ ...VITE, 'src/ai.ts': 'new OpenAI({ apiKey: k, dangerouslyAllowBrowser: true });' }, (project) => {
    assert.deepEqual(ids(scanSecrets(project).findings), ['ai-sdk-in-browser']);
  }));

test('placeholders, example files and local database URLs are not secrets', () =>
  inProject({
    ...VITE,
    '.env': `VITE_OPENAI_API_KEY=your-openai-key\nDATABASE_URL=${dbUrl('postgres', '127.0.0.1')}\n`,
    '.env.example': 'VITE_SUPABASE_URL=https://your-project.supabase.co\nVITE_SUPABASE_ANON_KEY=<anon key>\n',
  }, (project) => {
    const r = scanSecrets(project);
    assert.deepEqual(r.findings, []);
    assert.deepEqual(r.supabase.urls, []);
  }));

test('a real-looking key in .env.example is still a leak, because that file is shared', () =>
  inProject({ ...VITE, '.env.example': `STRIPE_SECRET_KEY=${stripeLive()}\n` }, (project) => {
    assert.deepEqual(ids(scanSecrets(project).findings), ['secret-in-code']);
  }));

test('a password in a database URL is found unless the host is local', () => {
  assert.equal(findKeys(dbUrl('FAKEpassword', 'db.fakeprojectref0000001.supabase.co'))[0].kind, 'database-url');
  assert.deepEqual(findKeys(dbUrl('postgres', 'localhost')), []);
  assert.deepEqual(findKeys(dbUrl('your-password', 'db.fakeprojectref0000001.supabase.co')), []);
});

test('mask prints only the well-known prefix', () => {
  assert.equal(mask(stripeLive()), 'sk_live_…');
  assert.equal(mask(serviceRole()), 'eyJ…');
  assert.equal(mask(openai()), 'sk-proj-…');
  assert.ok(!mask(stripeLive()).includes('FAKE'));
});

test('secretName reads the words of a variable name', () => {
  assert.equal(secretName('VITE_OPENAI_API_KEY', 'VITE_'), true);
  assert.equal(secretName('VITE_SUPABASE_SERVICE_ROLE_KEY', 'VITE_'), true);
  assert.equal(secretName('NEXT_PUBLIC_STRIPE_PUBLISHABLE_KEY', 'NEXT_PUBLIC_'), false);
  assert.equal(secretName('VITE_SUPABASE_ANON_KEY', 'VITE_'), false);
  assert.equal(secretName('VITE_RECAPTCHA_SITE_KEY', 'VITE_'), false);
  assert.equal(secretName('VITE_FIREBASE_API_KEY', 'VITE_'), false);
});

test('the service_role key and the anon key are told apart by the role inside the JWT', () => {
  assert.deepEqual(findKeys(`a=${serviceRole()} b=${anon()}`).map((k) => [k.kind, k.secret]), [['supabase-service-role', true], ['supabase-anon', false]]);
  assert.equal(byId([{ id: 'x' }], 'x').length, 1);
});
