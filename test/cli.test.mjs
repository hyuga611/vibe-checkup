import { test } from 'node:test';
import assert from 'node:assert/strict';
import { spawnSync } from 'node:child_process';
import { dirname, join } from 'node:path';
import { fileURLToPath } from 'node:url';
import { langFromEnv, main, parseArgs } from '../src/cli.mjs';
import { renderJson, renderText } from '../src/report.mjs';
import { scan } from '../src/scan.mjs';
import { anon, stripeLive, withFiles, withMockSupabase as withMock } from './helpers.mjs';

const HERE = dirname(fileURLToPath(import.meta.url));
const CLI = join(HERE, '..', 'src', 'cli.mjs');
const BAD = join(HERE, '..', 'examples', 'bad');
const GOOD = join(HERE, '..', 'examples', 'good');
const run = (...args) => spawnSync(process.execPath, [CLI, ...args], { encoding: 'utf8', env: { ...process.env, LANG: 'C', LC_ALL: '', LC_MESSAGES: '' } });

test('examples/bad exits 1 and leads with the critical findings', () => {
  const r = run(BAD);
  assert.equal(r.status, 1, r.stderr);
  assert.match(r.stdout, /^CRITICAL {2}Supabase service_role key is in code sent to the browser$/m);
  assert.match(r.stdout, /^CRITICAL {2}Table "profiles" has row-level security \(RLS\) turned off$/m);
  assert.match(r.stdout, /^CRITICAL {2}Firestore: anyone can read, change and delete all data$/m);
  assert.ok(r.stdout.indexOf('CRITICAL') < r.stdout.indexOf('HIGH'));
});

test('examples/good exits 0 and says why the public key is fine', () => {
  const r = run(GOOD);
  assert.equal(r.status, 0, r.stdout);
  assert.match(r.stdout, /Supabase anon key: made to be public/);
  assert.match(r.stdout, /No problems found/);
});

test('no key from the examples is ever printed in full', () => {
  for (const args of [[BAD], [BAD, '--lang', 'ja'], [BAD, '--json']]) {
    const out = run(...args).stdout;
    assert.ok(!/eyJ[\w-]{10,}/.test(out), 'a JWT was printed');
    assert.ok(!/sk_live_\w/.test(out) && !/sk-proj-\w/.test(out), 'a secret key was printed');
  }
});

test('--lang ja writes the report in Japanese', () => {
  const r = run(BAD, '--lang', 'ja');
  assert.equal(r.status, 1);
  assert.match(r.stdout, /【重大】テーブル「profiles」の RLS（行ごとの権限）が切れています/);
  assert.match(r.stdout, /何が起きるか:/);
  assert.match(r.stdout, /直し方:/);
});

test('LANG=ja_JP.UTF-8 picks Japanese, and LC_ALL wins over LANG', () => {
  assert.equal(langFromEnv({ LANG: 'ja_JP.UTF-8' }), 'ja');
  assert.equal(langFromEnv({ LANG: 'ja_JP.UTF-8', LC_ALL: 'en_US.UTF-8' }), 'en');
  assert.equal(langFromEnv({}), 'en');
  assert.equal(parseArgs([], { LANG: 'ja' }).lang, 'ja');
});

test('--json is machine-readable and carries the explanation', () => {
  const r = run(BAD, '--json');
  const out = JSON.parse(r.stdout);
  assert.equal(r.status, 1);
  assert.equal(out.counts.critical, out.findings.filter((f) => f.severity === 'critical').length);
  assert.ok(out.findings.every((f) => f.title && f.impact && f.fix.length));
});

test('usage errors exit 2', () => {
  for (const [args, message] of [[['--zzz'], /unknown option --zzz/], [['--lang', 'fr'], /--lang must be ja or en/], [['--lang'], /needs a value/]]) {
    const r = run(...args);
    assert.equal(r.status, 2);
    assert.match(r.stderr, message);
  }
});

test('a folder that does not exist exits 2', () => {
  const r = run(join(HERE, 'no-such-folder'));
  assert.equal(r.status, 2);
  assert.match(r.stderr, /could not read/);
});

test('a broken package.json exits 2 instead of passing', () =>
  withFiles({ 'package.json': '{ "dependencies": ' }, (root) => {
    const r = run(root);
    assert.equal(r.status, 2);
    assert.match(r.stdout, /package\.json/);
  }));

test('an empty folder passes with a note that there was nothing to check', () =>
  withFiles({ 'README.md': 'hello' }, async (root) => {
    const out = [];
    const code = await main([root, '--lang', 'en'], { log: (s) => out.push(s), error: (s) => out.push(s) });
    assert.equal(code, 0);
    assert.match(out.join(''), /No Supabase or Firebase/);
  }));

test('a project with only a leaked key in a public variable fails', () =>
  withFiles({ 'package.json': { devDependencies: { vite: '5' } }, '.env.production': `VITE_STRIPE_SECRET_KEY=${stripeLive()}\n` }, (root) => {
    assert.equal(run(root).status, 1);
  }));

test('--help and --version exit 0', () => {
  assert.match(run('--help').stdout, /Usage: vibe-checkup \[dir\] \[options\]/);
  assert.match(run('-v').stdout, /^\d+\.\d+\.\d+\n$/);
});

test('--live end to end: the row itself never reaches the report', () =>
  withMock((url) =>
    withFiles(
      {
        'package.json': { dependencies: { '@supabase/supabase-js': '2' } },
        '.env': `VITE_SUPABASE_URL=${url}\nVITE_SUPABASE_ANON_KEY=${anon()}\n`,
        'supabase/migrations/1_init.sql': 'create table profiles (id int, email text); alter table profiles enable row level security;\ncreate table todos (id int); alter table todos enable row level security;',
      },
      async (root) => {
        const result = await scan(root, { live: true, git: false });
        for (const out of [renderText(result, 'en'), renderText(result, 'ja'), renderJson(result, 'en')]) {
          assert.ok(!out.includes('FAKE-person'), 'row value printed');
          assert.ok(!out.includes('FAKE-hash'), 'row value printed');
          assert.ok(!out.includes(anon()), 'key printed');
        }
        assert.match(renderText(result, 'en'), /anyone can read table "profiles" right now/);
        assert.deepEqual(result.live.map((l) => l.status), ['readable', 'empty']);
      },
    ),
  ));

test('without --live nothing is sent', () =>
  withMock((url, requests) =>
    withFiles({ '.env': `VITE_SUPABASE_URL=${url}\nVITE_SUPABASE_ANON_KEY=${anon()}\n`, 'supabase/migrations/1.sql': 'create table profiles (id int);' }, async (root) => {
      await scan(root, { git: false });
      assert.equal(requests.length, 0);
    }),
  ));
