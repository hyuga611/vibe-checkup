import { test } from 'node:test';
import assert from 'node:assert/strict';
import { parseName, splitStatements } from '../src/sql.mjs';
import { scanSupabase } from '../src/supabase.mjs';
import { byId, ids, inProject } from './helpers.mjs';

const migrations = (...files) => Object.fromEntries(files.map((sql, i) => [`supabase/migrations/2025010100000${i}_m.sql`, sql]));
const scanSql = (...files) => inProject(migrations(...files), (project) => scanSupabase(project));

test('splitStatements keeps function bodies whole and drops comments', () => {
  const st = splitStatements(`-- a comment; with a semicolon
create table a (id int); /* block; comment */
create function f() returns void language plpgsql as $$ begin delete from a; end; $$;
insert into t values ('x;y');`);
  assert.deepEqual(st.map((s) => s.line), [2, 3, 4]);
  assert.match(st[1].text, /delete from a; end; \$\$$/);
  assert.equal(st[2].text, "insert into t values ('x;y')");
});

test('parseName lower-cases bare names, keeps quoted ones and defaults to public', () => {
  assert.deepEqual(parseName('Profiles'), { schema: 'public', name: 'profiles' });
  assert.deepEqual(parseName('"public"."UserData"'), { schema: 'public', name: 'UserData' });
  assert.deepEqual(parseName('storage . objects'), { schema: 'storage', name: 'objects' });
});

test('a table without RLS is critical and names its personal columns', async () => {
  const r = await scanSql('create table public.profiles (id uuid references auth.users primary key, email text, bio text);');
  assert.deepEqual(ids(r.findings), ['rls-disabled']);
  assert.equal(r.findings[0].severity, 'critical');
  assert.deepEqual(r.findings[0].params.columns, ['email']);
  assert.equal(r.findings[0].params.owner, 'id');
  assert.deepEqual(r.tables, ['profiles']);
});

test('RLS turned on in a later migration counts', async () => {
  const r = await scanSql('create table todos (id int, user_id uuid);', 'alter table todos enable row level security;');
  assert.deepEqual(r.findings, []);
});

test('RLS turned off again, or a renamed table, is followed', async () => {
  const r = await scanSql('create table a (id int); alter table a enable row level security;', 'alter table a disable row level security; alter table a rename to b;');
  assert.deepEqual(r.findings.map((f) => f.params.table), ['b']);
});

test('tables outside public, and tables the API roles cannot reach, are not reported', async () => {
  const r = await scanSql('create table private.secrets (v text);', 'create table jobs (id int); revoke all on table jobs from anon, authenticated;');
  assert.deepEqual(r.findings, []);
});

test('using (true) on a table with personal data is critical', async () => {
  const r = await scanSql(`create table profiles (id uuid, email text);
alter table profiles enable row level security;
create policy "Public profiles" on profiles for select using (true);`);
  const [f] = r.findings;
  assert.equal(f.id, 'policy-open');
  assert.equal(f.severity, 'critical');
  assert.deepEqual(f.params.verbs, ['read']);
  assert.equal(f.params.scope, 'everyone');
});

test('using (true) for reading a non-personal table is listed as fine, not as a problem', async () => {
  const r = await scanSql(`create table products (id int, name text, price int);
alter table products enable row level security;
create policy "Anyone can read products" on products for select to anon, authenticated using (true);`);
  assert.deepEqual(r.findings, []);
  assert.deepEqual(r.ok.map((o) => o.id), ['public-read']);
});

test('anyone may change or delete every row: critical even for a non-personal table', async () => {
  const r = await scanSql(`create table products (id int);
alter table products enable row level security;
create policy "edit" on products for all using (true) with check (true);`);
  assert.deepEqual(r.findings[0].params.verbs, ['read', 'change', 'delete']);
  assert.equal(r.findings[0].severity, 'critical');
});

test('any signed-in user may change every row: high', async () => {
  const r = await scanSql(`create table notes (id int, user_id uuid);
alter table notes enable row level security;
create policy "upd" on notes for update to authenticated using (true);`);
  assert.equal(r.findings[0].severity, 'high');
  assert.equal(r.findings[0].params.scope, 'signed-in');
});

test('auth.uid() is not null only proves someone is logged in', async () => {
  const r = await scanSql(`create table orders (id int, user_id uuid);
alter table orders enable row level security;
create policy "read" on orders for select using ((select auth.uid()) is not null);`);
  assert.equal(r.findings[0].severity, 'high');
});

test('an owner check is not reported', async () => {
  const r = await scanSql(`create table orders (id int, user_id uuid references auth.users);
alter table orders enable row level security;
create policy "own" on orders for all to authenticated using ((select auth.uid()) = user_id) with check ((select auth.uid()) = user_id);
create policy "admin or own" on orders for select using (auth.uid() = user_id or is_admin());`);
  assert.deepEqual(r.findings, []);
});

test('an or with true opens the whole policy, an and with an owner check closes it', async () => {
  const r = await scanSql(`create table messages (id int, user_id uuid);
alter table messages enable row level security;
create policy "a" on messages for select using (auth.uid() = user_id or true);
create policy "b" on messages for delete using (true and auth.uid() = user_id);`);
  assert.deepEqual(r.findings.map((f) => f.params.verbs), [['read']]);
});

test('a restrictive policy caps what a permissive one opens', async () => {
  const r = await scanSql(`create table docs (id int, user_id uuid);
alter table docs enable row level security;
create policy "all" on docs for select using (true);
create policy "only own" on docs as restrictive for select using (auth.uid() = user_id);`);
  assert.deepEqual(r.findings, []);
});

test('a dropped policy no longer counts', async () => {
  const r = await scanSql(`create table docs (id int, user_id uuid);
alter table docs enable row level security;
create policy "all" on docs for select using (true);`, 'drop policy if exists "all" on docs;');
  assert.deepEqual(r.findings, []);
});

test('policies that only add rows are not reported', async () => {
  const r = await scanSql(`create table feedback (id int, email text);
alter table feedback enable row level security;
create policy "anyone can send" on feedback for insert with check (true);`);
  assert.deepEqual(r.findings, []);
});

test('public buckets: pictures are fine, documents are not', async () => {
  const r = await scanSql(`insert into storage.buckets (id, name, public) values ('avatars', 'avatars', true);
insert into storage.buckets (id, name, public) values ('invoices', 'invoices', true), ('misc', 'misc', true);
insert into storage.buckets (id, name) values ('private-docs', 'private-docs');`);
  assert.deepEqual(r.findings.map((f) => [f.params.bucket, f.severity]), [['invoices', 'high'], ['misc', 'medium']]);
  assert.deepEqual(r.ok.map((o) => o.params.bucket), ['avatars']);
});

test('a storage policy that only checks the bucket lets anyone at every file in it', async () => {
  const r = await scanSql(`create policy "read docs" on storage.objects for select using (bucket_id = 'documents');
create policy "upload avatar" on storage.objects for insert to authenticated with check (bucket_id = 'avatars');
create policy "read avatars" on storage.objects for select using (bucket_id = 'avatars');
create policy "own files" on storage.objects for delete using (bucket_id = 'documents' and (storage.foldername(name))[1] = auth.uid()::text);`);
  assert.deepEqual(r.findings.map((f) => [f.id, f.params.buckets, f.severity]), [['storage-policy-open', ['documents'], 'critical']]);
  assert.deepEqual(r.ok.map((o) => o.id), ['public-files']);
});

test('a security definer function anyone can call is reported, one step lower when it checks auth.uid()', async () => {
  const fn = (name, body) => `create or replace function public.${name}() returns void language plpgsql security definer set search_path = '' as $$ begin ${body}; end; $$;`;
  const r = await scanSql(
    fn('wipe', 'delete from public.posts'),
    fn('wipe_own', 'delete from public.posts where user_id = auth.uid()'),
    fn('internal', 'delete from public.posts'),
    'revoke execute on function public.internal() from public, anon, authenticated;',
    `create function public.handle_new_user() returns trigger language plpgsql security definer as $$ begin insert into public.profiles (id) values (new.id); return new; end; $$;`,
  );
  assert.deepEqual(r.findings.map((f) => [f.params.fn, f.severity]), [['wipe', 'high'], ['wipe_own', 'medium']]);
});

test('a definer function that returns data to anyone is medium; one that returns a boolean is not reported', async () => {
  const r = await scanSql(
    'create function public.all_emails() returns setof text language sql security definer as $$ select email from auth.users $$;',
    'create function public.is_admin() returns boolean language sql security definer as $$ select true $$;',
  );
  assert.deepEqual(r.findings.map((f) => [f.params.fn, f.severity]), [['all_emails', 'medium']]);
});

test('views: one over auth.users is critical, one over an RLS table without security_invoker is high', async () => {
  const r = await scanSql(`create table posts (id int, user_id uuid); alter table posts enable row level security;
create view public.user_list as select id, email from auth.users;
create view public.post_list as select * from posts;
create view public.safe_posts with (security_invoker = true) as select * from posts;`);
  assert.deepEqual(r.findings.map((f) => [f.id, f.severity]), [['view-exposes-users', 'critical'], ['view-bypasses-rls', 'high']]);
});

test('grants that hand the API roles admin powers are critical', async () => {
  const r = await scanSql(`grant usage on schema auth to anon;
grant select on auth.users to authenticated;
grant service_role to authenticated;
alter role anon bypassrls;
grant select on public.products to anon;`);
  assert.deepEqual(byId(r.findings, 'grant-too-broad').map((f) => f.params.kind), ['schema', 'schema', 'role', 'bypassrls']);
});

test('a Supabase project without migrations gets a note, not a pass', () =>
  inProject({ 'package.json': { dependencies: { '@supabase/supabase-js': '2' } } }, (project) => {
    const r = scanSupabase(project);
    assert.deepEqual(r.notes, [{ id: 'no-migrations' }]);
    assert.equal(r.checked, false);
  }));
