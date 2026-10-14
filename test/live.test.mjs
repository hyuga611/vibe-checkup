import { test } from 'node:test';
import assert from 'node:assert/strict';
import { probe, scanLive, targets } from '../src/live.mjs';
import { anon, serviceRole, withMockSupabase as withMock } from './helpers.mjs';

test('probe sends one read-only request for one row and keeps only the column names', () =>
  withMock(async (url, requests) => {
    const key = anon();
    const r = await probe(url, key, 'profiles');
    assert.deepEqual(r, { table: 'profiles', status: 'readable', columns: ['id', 'email', 'password_hash'], total: 42 });
    assert.equal(requests.length, 1);
    assert.equal(requests[0].method, 'GET');
    assert.equal(requests[0].url, '/rest/v1/profiles?select=*&limit=1');
    assert.equal(requests[0].apikey, key);
    assert.equal(requests[0].authorization, `Bearer ${key}`);
  }));

test('a publishable key goes only in the apikey header', () =>
  withMock(async (url, requests) => {
    await probe(url, 'sb_publishable_FAKE000000000000', 'todos');
    assert.equal(requests[0].authorization, undefined);
  }));

test('empty, refused and missing tables are told apart', () =>
  withMock(async (url) => {
    const statuses = await Promise.all(['todos', 'secrets', 'nope'].map((t) => probe(url, anon(), t)));
    assert.deepEqual(statuses.map((s) => s.status), ['empty', 'denied', 'missing']);
  }));

test('an unreachable server is an error, not a pass', async () => {
  const r = await probe('http://127.0.0.1:9', anon(), 'profiles');
  assert.equal(r.status, 'error');
});

test('targets: a JWT key goes only to its own project, and never the service_role key', () => {
  const mine = { value: anon('aaaa1111'), kind: 'supabase-anon', ref: 'aaaa1111' };
  const other = { value: anon('bbbb2222'), kind: 'supabase-anon', ref: 'bbbb2222' };
  const admin = { value: serviceRole('aaaa1111'), kind: 'supabase-service-role', ref: 'aaaa1111' };
  assert.deepEqual(targets({ urls: ['https://aaaa1111.supabase.co'], keys: [other, admin, mine] }), [{ url: 'https://aaaa1111.supabase.co', key: mine.value }]);
  assert.deepEqual(targets({ urls: ['https://cccc3333.supabase.co'], keys: [mine] }), []);
  assert.deepEqual(targets({ urls: ['https://aaaa1111.supabase.co'], keys: [admin] }), []);
});

test('targets: a key without a project ref is used only when there is one URL and one key', () => {
  const pub = { value: 'sb_publishable_FAKE000000000000', kind: 'supabase-publishable' };
  assert.equal(targets({ urls: ['https://aaaa1111.supabase.co'], keys: [pub] }).length, 1);
  assert.deepEqual(targets({ urls: ['https://aaaa1111.supabase.co', 'https://app.supabase.co'], keys: [pub] }), []);
});

test('scanLive reports a readable table as critical and makes no request without a target', () =>
  withMock(async (url, requests) => {
    const r = await scanLive({ urls: [url], keys: [{ value: anon(), kind: 'supabase-anon', ref: 'fakeprojectref0000001' }] }, ['profiles', 'todos']);
    assert.deepEqual(r.findings.map((f) => [f.id, f.severity, f.params.table]), [['live-readable', 'critical', 'profiles']]);
    const none = await scanLive({ urls: [], keys: [] }, ['profiles']);
    assert.deepEqual(none.notes, [{ id: 'live-no-target' }]);
    assert.equal(requests.length, 2);
  }));
