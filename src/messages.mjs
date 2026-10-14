// Every finding explained twice, for people who did not write the code themselves.

const q = (name) => `"${String(name).replace(/"/g, '""')}"`;
const listEn = (items) => (items.length < 2 ? items.join('') : `${items.slice(0, -1).join(', ')} and ${items.at(-1)}`);
const listJa = (items) => items.join('・');

const ADMIN_KINDS = new Set(['supabase-service-role', 'supabase-secret', 'database-url']);

function ownerPolicySql(table, owner, verbs = ['read', 'change', 'delete']) {
  const col = owner ?? 'user_id';
  const cmd = verbs.length === 1 && verbs[0] === 'read' ? 'select' : 'all';
  const check = cmd === 'all' ? `\n  with check ((select auth.uid()) = ${col})` : '';
  return `create policy "Owner only" on public.${table}\n  for ${cmd} to authenticated\n  using ((select auth.uid()) = ${col})${check};`;
}

const keepsRead = (p) => !p.personal && p.scope === 'everyone' && p.verbs.includes('read');

function policySql(p) {
  const drops = p.policies.map((name) => `drop policy ${q(name)} on public.${p.table};`);
  const keepRead = keepsRead(p);
  const owner = ownerPolicySql(p.table, p.owner, keepRead ? p.verbs.filter((v) => v !== 'read') : p.verbs);
  const read = keepRead ? [`create policy "Anyone can read" on public.${p.table}\n  for select using (true);`] : [];
  return [...drops, owner, ...read].join('\n');
}

function storageSql(buckets, policies) {
  const bucket = buckets[0] ?? 'your-bucket';
  const cond = `bucket_id = '${bucket}' and (storage.foldername(name))[1] = (select auth.uid())::text`;
  return [
    ...policies.map((p) => `drop policy ${q(p)} on storage.objects;`),
    `create policy "Own folder only" on storage.objects\n  for all to authenticated\n  using (${cond})\n  with check (${cond});`,
  ].join('\n');
}

const RULES_EXAMPLE = {
  firestore: 'match /users/{userId} {\n  allow read, write: if request.auth != null && request.auth.uid == userId;\n}',
  storage: 'match /b/{bucket}/o {\n  match /users/{userId}/{allPaths=**} {\n    allow read, write: if request.auth != null && request.auth.uid == userId;\n  }\n}',
  database: '{\n  "rules": {\n    "users": {\n      "$uid": {\n        ".read": "$uid === auth.uid",\n        ".write": "$uid === auth.uid"\n      }\n    }\n  }\n}',
};

const en = {
  severity: { critical: 'CRITICAL', high: 'HIGH', medium: 'MEDIUM' },
  label: { where: 'Where', impact: 'What can happen', fix: 'How to fix', ask: 'Or ask your AI', ok: 'Checked and fine', notes: 'Notes', live: 'Live check (read-only, 1 row per table)', problems: 'Could not read' },
  header: (root, stack, files) => `vibe-checkup — ${root}${stack.length ? ` (${stack.join(', ')})` : ''}, ${files} files read`,
  summary: (c) => {
    const total = c.critical + c.high + c.medium;
    if (!total) return 'No problems found. Read "What it does not check" in the README before you rely on this.';
    const parts = [c.critical && `${c.critical} critical`, c.high && `${c.high} high`, c.medium && `${c.medium} medium`].filter(Boolean);
    return `${total} problem${total === 1 ? '' : 's'} found: ${parts.join(', ')}. Fix the critical ones before you share the link with anyone.`;
  },
  scope: { everyone: 'anyone — even people who are not logged in —', 'signed-in': 'any logged-in user' },
  verbs: { read: 'read', add: 'add', change: 'change', delete: 'delete' },
  signup: 'Anyone can sign up for your app, so "logged in" does not mean "trusted".',
  kind: {
    'supabase-service-role': 'Supabase service_role key',
    'supabase-secret': 'Supabase secret key',
    stripe: 'Stripe secret key',
    clerk: 'Clerk secret key',
    openai: 'OpenAI API key',
    anthropic: 'Anthropic (Claude) API key',
    resend: 'Resend API key',
    sendgrid: 'SendGrid API key',
    aws: 'AWS access key',
    github: 'GitHub token',
    'private-key': 'private key',
    'database-url': 'database password',
    'supabase-anon': 'Supabase anon key',
    'supabase-publishable': 'Supabase publishable key',
    'google-api-key': 'Firebase / Google API key',
    'stripe-publishable': 'Stripe publishable key',
  },
  power: {
    'supabase-service-role': 'This key skips every RLS rule. With it, a stranger can read, change and delete every row in your database: all users, all emails, all orders.',
    'supabase-secret': 'This key skips every RLS rule. With it, a stranger can read, change and delete every row in your database: all users, all emails, all orders.',
    'database-url': 'With it, a stranger can connect straight to your database with full rights and skip every RLS rule.',
    stripe: 'With it, a stranger can use your Stripe account: list your customers and payments, refund charges and create new ones.',
    clerk: "With it, a stranger can use Clerk's admin API: list, change and delete your users.",
    openai: 'With it, a stranger can use the AI on your bill. Bots look for leaked AI keys and use them until your limit runs out.',
    anthropic: 'With it, a stranger can use the AI on your bill. Bots look for leaked AI keys and use them until your limit runs out.',
    resend: 'With it, a stranger can send email in your name, for example phishing mail from your domain.',
    sendgrid: 'With it, a stranger can send email in your name, for example phishing mail from your domain.',
    aws: 'With it, a stranger can use your AWS account with whatever rights this key has. Leaked AWS keys are often used to mine crypto on your bill.',
    github: 'With it, a stranger can act as you on GitHub, including reading private code.',
    'private-key': 'With it, a stranger can sign or decrypt anything this key protects.',
  },
  rotate: {
    'supabase-service-role': 'In the Supabase dashboard open Project Settings → API Keys. Create a new secret key for your server code, then disable the legacy keys so the leaked service_role key stops working (the app then uses the new publishable key instead of the anon key).',
    'supabase-secret': 'In the Supabase dashboard open Project Settings → API Keys, create a new secret key and delete the leaked one.',
    'database-url': 'Change the database password (Supabase: Project Settings → Database → Reset database password).',
    stripe: 'In the Stripe Dashboard open Developers → API keys and roll this key.',
    clerk: 'In the Clerk Dashboard open API Keys, create a new secret key and delete this one.',
    openai: 'On platform.openai.com open API keys, revoke this key and create a new one.',
    anthropic: 'In the Anthropic Console open API Keys, disable this key and create a new one.',
    resend: 'In the Resend dashboard open API Keys, delete this key and create a new one.',
    sendgrid: 'In SendGrid open Settings → API Keys, delete this key and create a new one.',
    aws: "In the AWS console open IAM → the user's Security credentials, deactivate and delete this access key, then create a new one.",
    github: 'On GitHub open Settings → Developer settings → Personal access tokens and delete this token.',
    'private-key': 'Make a new key pair wherever this key is used and remove the old one there.',
  },
  where: {
    browser: 'It is in code that every visitor\'s browser downloads, so anyone can open the browser\'s developer tools and copy it.',
    mixed: 'It is in a file that ends up in the browser as soon as a page component imports it.',
    repo: 'It is written into the project files, so anyone who can see the code — or any past version of it in git — has it.',
  },
  finding: {
    'secret-in-browser': (p) => leak(en, p, 'browser'),
    'secret-maybe-in-browser': (p) => leak(en, p, 'mixed'),
    'secret-in-code': (p) => leak(en, p, 'repo'),
    'secret-name-in-public-env': (p) => ({
      title: `${p.name} is a secret, but its name starts with ${p.prefix}`,
      impact: `Every variable that starts with ${p.prefix} is copied into the JavaScript that every visitor downloads. The name says this one is a secret, so anyone can copy it and use the service on your bill.`,
      fix: [
        `Rename it so it does not start with ${p.prefix}, and use it only in server code: a Supabase Edge Function, a Next.js route handler or server action, or a serverless function.`,
        'If the site has already been online with this value, treat the key as leaked: create a new one at the service and turn the old one off.',
      ],
      ask: `Move every use of ${p.name} into a Supabase Edge Function (or a server route), store the key as a server-side secret without the ${p.prefix} prefix, and have the page call that function instead.`,
    }),
    'ai-sdk-in-browser': () => ({
      title: 'The AI library is told to run in the browser',
      impact: 'dangerouslyAllowBrowser (or anthropic-dangerous-direct-browser-access) lets the OpenAI or Anthropic library run in the page. That only works when the API key is in the page too, so any visitor can copy it and use the AI on your bill.',
      fix: ['Call the AI from server code instead (a Supabase Edge Function or a server route), keep the key there, and have the page call your function.'],
      ask: 'Move the AI calls out of the browser into a Supabase Edge Function, keep the API key as an Edge Function secret, and remove dangerouslyAllowBrowser.',
    }),
    'env-tracked': (p) => ({
      title: `${p.file} is saved in git`,
      impact: p.secrets
        ? `It holds secret keys, and git keeps every past version: anyone who can see this repository, now or later, can read them even after you delete the file.`
        : `It holds settings that are not meant to be public (${listEn(p.names)}). Git keeps every past version, so they stay readable even after you delete the file.`,
      fix: [
        `Stop tracking it: run \`git rm --cached ${p.file}\` and add \`.env*\` (and \`!.env.example\`) to .gitignore.`,
        'If the repository has ever been pushed or shared, treat the keys in it as leaked: create new ones and turn the old ones off.',
      ],
      ask: `Remove ${p.file} from git without deleting it, add .env files to .gitignore, and tell me which keys in it I need to replace.`,
    }),
    'rls-disabled': (p) => ({
      title: `Table "${p.table}" has row-level security (RLS) turned off`,
      impact: `Your app sends the Supabase URL and public key to every visitor. With RLS off, ${en.scope.everyone} can use them to read, change and delete every row in "${p.table}"${p.columns.length ? `, including ${listEn(p.columns)}` : ''}.${p.policies ? ` The ${p.policies} polic${p.policies === 1 ? 'y' : 'ies'} written for this table do nothing until RLS is on.` : ''}`,
      fix: [
        `In the Supabase dashboard open Table Editor → ${p.table} and turn on RLS. (Authentication → Policies lists every table and can turn it on too.)`,
        'Then add a policy that lets each user reach only their own rows. Until there is a policy, the app cannot read the table at all.',
        p.owner ? `The SQL below assumes "${p.owner}" holds the owner's user id.` : 'Replace user_id below with the column that stores who owns the row.',
        'If everyone really may read this table (a product list, say), use `for select using (true)` for reading and keep writing to the owner.',
      ],
      code: `alter table public.${p.table} enable row level security;\n${ownerPolicySql(p.table, p.owner)}`,
      ask: `Turn on RLS for the ${p.table} table and add policies so each user can only read and change their own rows.`,
    }),
    'policy-open': (p) => ({
      title: `Table "${p.table}": ${p.scope === 'everyone' ? 'anyone' : 'any logged-in user'} can ${listEn(p.verbs.map((v) => en.verbs[v]))} every row`,
      impact: `The polic${p.policies.length === 1 ? 'y' : 'ies'} ${listEn(p.policies.map(q))} let${p.policies.length === 1 ? 's' : ''} ${en.scope[p.scope]} ${listEn(p.verbs.map((v) => en.verbs[v]))} every row in "${p.table}"${p.columns.length ? `, including ${listEn(p.columns)}` : ''}. ${p.scope === 'signed-in' ? `The policy only checks that someone is logged in, not whose row it is. ${en.signup}` : 'A rule like using (true) means "no check at all".'}`,
      fix: [
        `Replace the policy with one that checks the row belongs to the person asking: using ((select auth.uid()) = ${p.owner ?? 'user_id'}).`,
        p.owner ? `The SQL below assumes "${p.owner}" holds the owner's user id.` : 'Replace user_id below with the column that stores who owns the row.',
        ...(keepsRead(p) ? ['The last statement keeps the table readable by everyone, which looks intended here. Leave it out if the rows are private.'] : []),
      ],
      code: policySql(p),
      ask: `Rewrite the RLS policies on ${p.table} so each user can only ${listEn(p.verbs.map((v) => en.verbs[v]))} their own rows.`,
    }),
    'storage-policy-open': (p) => ({
      title: `Files${p.buckets.length ? ` in ${listEn(p.buckets.map((b) => `"${b}"`))}` : ' in every bucket'}: ${p.scope === 'everyone' ? 'anyone' : 'any logged-in user'} can ${listEn(p.verbs.map((v) => en.verbs[v]))} them`,
      impact: `The storage polic${p.policies.length === 1 ? 'y' : 'ies'} ${listEn(p.policies.map(q))} only check${p.policies.length === 1 ? 's' : ''} which bucket a file is in, not who uploaded it. So ${en.scope[p.scope]} can ${listEn(p.verbs.map((v) => en.verbs[v]))} everyone's files.${p.scope === 'signed-in' ? ` ${en.signup}` : ''}`,
      fix: [
        'Save each user\'s files in a folder named after their user id (for example `<user id>/invoice.pdf`) and let people reach only their own folder.',
        'In the Supabase dashboard: Storage → Policies, or run the SQL below.',
      ],
      code: storageSql(p.buckets, p.policies),
      ask: 'Change the storage policies so users can only read and write files in a folder named after their own user id.',
    }),
    'bucket-public': (p) => ({
      title: `Storage bucket "${p.bucket}" is public`,
      impact: `Anyone who has a file's link can download it without logging in, and links get shared, logged and guessed.${p.sensitive ? ' The name suggests it holds private files.' : ''}`,
      fix: [
        `In the Supabase dashboard open Storage → ${p.bucket} → Edit bucket and turn off "Public bucket".`,
        'Show files with short-lived signed links instead (supabase.storage.from(...).createSignedUrl).',
      ],
      ask: `Make the ${p.bucket} storage bucket private and show its files with signed URLs.`,
    }),
    'definer-function': (p) => ({
      title: `Database function "${p.fn}" runs with full rights and ${p.scope === 'everyone' ? 'anyone' : 'any logged-in user'} can call it`,
      impact: `It is marked security definer, so it skips RLS, and ${en.scope[p.scope]} can call it through your API (/rest/v1/rpc/${p.fn}).${p.writes ? ' It changes data.' : ' It returns data.'}`,
      fix: [
        'If only your server or other database code calls it, take away the right to call it from the API (SQL below).',
        'If logged-in users need it, keep it callable by authenticated only and make it check auth.uid() inside, or switch it to security invoker.',
      ],
      code: `revoke execute on function public.${p.fn} from public, anon${p.scope === 'signed-in' ? ', authenticated' : ''};`,
      ask: `Make the ${p.fn} database function impossible to call for people who are not logged in, and make it check auth.uid() so users can only affect their own data.`,
    }),
    'view-exposes-users': (p) => ({
      title: `View "${p.view}" shows the auth.users table to anyone`,
      impact: 'auth.users holds every account: emails, phone numbers, sign-in data. The view runs with its creator\'s rights, so anyone can read it through your API.',
      fix: ['Drop the view, or move it out of the public schema. If the app needs names, keep them in a profiles table protected by RLS.'],
      code: `drop view public.${p.view};`,
      ask: `Remove the ${p.view} view that exposes auth.users and use a profiles table with RLS instead.`,
    }),
    'view-bypasses-rls': (p) => ({
      title: `View "${p.view}" skips the RLS rules of ${listEn(p.tables.map((t) => `"${t}"`))}`,
      impact: 'A view runs with its creator\'s rights unless it is told otherwise, so anyone can read through it the rows that RLS was hiding.',
      fix: ['Make the view use the rights of the person asking (needs Postgres 15 or newer, which Supabase has).'],
      code: `alter view public.${p.view} set (security_invoker = true);`,
      ask: `Set security_invoker = true on the ${p.view} view so it respects RLS.`,
    }),
    'grant-too-broad': (p) => ({
      title: {
        schema: `${listEn(p.grantees)} got access to ${p.object}`,
        role: `${listEn(p.grantees)} got the ${p.object} role`,
        bypassrls: `${p.object} is allowed to skip RLS`,
      }[p.kind],
      impact: {
        schema: 'The auth schema and vault hold every account and secret. Giving the public roles access lets visitors read them.',
        role: `Every request from ${listEn(p.grantees)} now has admin rights and skips RLS.`,
        bypassrls: `Every request from ${p.object} skips every RLS rule.`,
      }[p.kind],
      fix: ['Remove that line from the migration and undo it in the database (SQL below).'],
      code: {
        schema: `revoke all on ${p.object} from ${p.grantees.join(', ')};`,
        role: `revoke ${p.object} from ${p.grantees.join(', ')};`,
        bypassrls: `alter role ${p.object} nobypassrls;`,
      }[p.kind],
      ask: 'Undo this grant in a new migration and explain why it was there.',
    }),
    'rules-open': (p) => rulesOpen(en, p),
    'live-readable': (p) => ({
      title: `Live check: anyone can read table "${p.table}" right now`,
      impact: `With only the public key from your app, the database returned a row from "${p.table}"${p.total !== undefined ? ` (about ${p.total} rows in total)` : ''}. Columns: ${p.columns.join(', ') || '(none)'}. The row itself was not shown or saved.`,
      fix: ['Make sure RLS is on for this table and that its policies let people read only their own rows (see the items above, or Supabase dashboard → Authentication → Policies).'],
      ask: `Turn on RLS for the ${p.table} table and add policies so each user can only read their own rows.`,
    }),
  },
  ok: {
    'public-key': (p) => `${en.kind[p.kind]}: made to be public, so it is fine in the browser. What it can reach is decided by your ${p.kind === 'google-api-key' ? 'Firebase security rules' : p.kind === 'stripe-publishable' ? 'Stripe account' : 'RLS policies'}, which this tool checks separately.`,
    'public-read': (p) => `Table "${p.table}": everyone can read it (${listEn(p.policies.map(q))}). No personal columns found, so this looks intended.`,
    'public-files': (p) => `Files in ${listEn(p.buckets.map((b) => `"${b}"`))}: everyone can download them. Looks intended for this kind of bucket.`,
    'public-bucket': (p) => `Bucket "${p.bucket}" is public. Normal for pictures shown on the site.`,
    'rules-public-read': (p) => `${SERVICE_EN[p.service]} ${p.path}: everyone can read it. No personal data in the name, so this looks intended.`,
  },
  note: {
    'no-migrations': () => 'This project uses Supabase but has no supabase/migrations folder, so the database rules were not checked. Save them with `supabase db pull`, run the Security Advisor in the Supabase dashboard, or try `--live`.',
    'no-rules': () => 'This project uses Firebase but has no firestore.rules, storage.rules or database.rules.json. Copy the rules from the Firebase console into the project (`firebase init`) so they can be checked.',
    'test-mode-expired': (p) => `${SERVICE_EN[p.service]}: the test-mode rules ended on ${p.date}, so nobody can read or write now and the app is probably broken. Write real rules instead of moving the date.`,
    'secrets-only': () => 'No Supabase or Firebase files were found, so only secret keys and git were checked.',
    'live-no-target': () => '--live: no Supabase URL with a matching public key was found in the project, so nothing was sent.',
    'live-no-tables': () => '--live: no tables were found in supabase/migrations, so nothing was sent.',
  },
  live: {
    readable: (r) => `readable by anyone — ${r.columns.length} columns`,
    empty: () => 'no rows returned (RLS is hiding them, or the table is empty)',
    denied: () => 'refused (good)',
    missing: () => 'not found or not exposed through the API',
    error: (r) => `could not check (${r.detail})`,
  },
};

const SERVICE_EN = { firestore: 'Firestore', storage: 'Cloud Storage', database: 'Realtime Database' };
const SERVICE_JA = { firestore: 'Firestore', storage: 'Cloud Storage（ファイル置き場）', database: 'Realtime Database' };
const RULES_PLACE = {
  firestore: { console: 'Firestore Database', deploy: 'firestore:rules' },
  storage: { console: 'Storage', deploy: 'storage' },
  database: { console: 'Realtime Database', deploy: 'database' },
};
const CATCH_ALL = {
  firestore: { en: 'the catch-all `match /{document=**}` block', ja: '全部に当てはまる `match /{document=**}` のブロック' },
  storage: { en: 'the catch-all `match /{allPaths=**}` block', ja: '全部に当てはまる `match /{allPaths=**}` のブロック' },
  database: { en: 'the ".read" / ".write" right under "rules"', ja: '"rules" の直下にある ".read" / ".write"' },
};

function rulesOpen(t, p) {
  const japanese = t === ja;
  const service = (japanese ? SERVICE_JA : SERVICE_EN)[p.service];
  const verbs = p.verbs.map((v) => t.verbs[v]);
  const target = japanese ? (p.whole ? 'すべてのデータ' : `「${p.path}」のデータ`) : p.whole ? 'all of its data' : `everything under ${p.path}`;
  if (japanese) {
    return {
      title: `${service}：${p.scope === 'everyone' ? '誰でも' : 'ログインした人なら誰でも'}${p.whole ? '全部の' : `「${p.path}」の`}データを${listJa(verbs)}ことができます`,
      impact: `セキュリティルールが、${t.scope[p.scope]}${target}を${listJa(verbs)}ことを許しています。${p.until ? `これは「テストモード」のルールで、${p.until} まで開きっぱなしです。` : ''}${p.scope === 'signed-in' ? t.signup : ''}`,
      fix: [
        `Firebase コンソールの「${RULES_PLACE[p.service].console}」→「ルール」で、データの持ち主だけが読み書きできるルールに書き換えます。プロジェクトの ${p.file} を直した場合は \`firebase deploy --only ${RULES_PLACE[p.service].deploy}\` で反映します。`,
        p.whole ? `${CATCH_ALL[p.service].ja}は消し、コレクションごとにルールを書きます。` : '下の例の users は、実際のコレクション名に合わせてください。',
      ],
      code: RULES_EXAMPLE[p.service],
      ask: `${service} のセキュリティルールを、ログインした本人のデータだけを読み書きできる形に書き直して。`,
    };
  }
  return {
    title: `${service}: ${p.scope === 'everyone' ? 'anyone' : 'any logged-in user'} can ${listEn(verbs)} ${p.whole ? 'all data' : p.path}`,
    impact: `The security rules let ${t.scope[p.scope]} ${listEn(verbs)} ${target}.${p.until ? ` These are "test mode" rules and stay open until ${p.until}.` : ''}${p.scope === 'signed-in' ? ` ${t.signup}` : ''}`,
    fix: [
      `In the Firebase console open ${RULES_PLACE[p.service].console} → Rules and write rules that let people reach only their own data. If you edit ${p.file} in the project instead, publish it with \`firebase deploy --only ${RULES_PLACE[p.service].deploy}\`.`,
      p.whole ? `Remove ${CATCH_ALL[p.service].en} and write rules for each collection.` : 'Change users in the example to your own collection.',
    ],
    code: RULES_EXAMPLE[p.service],
    ask: `Rewrite the ${service} security rules so each signed-in user can only read and write their own data.`,
  };
}

function leak(t, p, place) {
  const japanese = t === ja;
  const kind = t.kind[p.kind] ?? p.kind;
  const server = ADMIN_KINDS.has(p.kind) ? (japanese ? 'Supabase の Edge Function など、サーバー側' : 'server code, such as a Supabase Edge Function') : japanese ? 'サーバー側（Supabase の Edge Function・Next.js の route handler など）' : 'server code (a Supabase Edge Function, a Next.js route handler)';
  const titles = japanese
    ? { browser: `${kind}が、ブラウザに届くコードに入っています`, mixed: `${kind}が、ブラウザに届くかもしれないコードに入っています`, repo: `${kind}が、コードに直接書かれています` }
    : { browser: `${kind} is in code sent to the browser`, mixed: `${kind} may end up in the browser`, repo: `${kind} is written in the code` };
  const testNote = p.test ? (japanese ? 'テスト用の鍵なので実際のお金は動きませんが、本番の鍵に替える前に直してください。' : 'It is a test-mode key, so no real money moves, but fix this before you switch to live keys.') : '';
  const steps = japanese
    ? [
        `この鍵は漏れたものとして扱い、作り直して古い鍵を止めます。コードから消すだけでは足りません（すでにサイトを開いた人や、git の履歴に残っています）。${t.rotate[p.kind] ?? ''}`,
        `新しい鍵は VITE_ や NEXT_PUBLIC_ の付かない名前で、${server}だけに置きます。`,
        ADMIN_KINDS.has(p.kind) ? '画面側からは公開用の鍵（anon / publishable）だけを使い、必要な読み書きは RLS のポリシーで許可します。' : '画面からは、その鍵を使う自分のサーバー側の処理を呼ぶようにします。',
      ]
    : [
        `Treat the key as leaked: make a new one and turn the old one off. Deleting it from the code is not enough — anyone who opened the site, and your git history, still has it. ${t.rotate[p.kind] ?? ''}`,
        `Keep the new key only in ${server}, in a variable without the VITE_ or NEXT_PUBLIC_ prefix.`,
        ADMIN_KINDS.has(p.kind) ? 'The page itself should use only the public key (anon / publishable) and let RLS policies decide what each user can do.' : 'Have the page call your own server code, which uses the key.',
      ];
  const ask = japanese
    ? `${kind}を使っている処理を Supabase の Edge Function（またはサーバー側の route）に移し、鍵はサーバー側の secret に置いて、画面からはその関数を呼ぶようにして。`
    : `Move everything that uses the ${kind} into a Supabase Edge Function (or a server route), keep the key as a server-side secret, and have the page call that function.`;
  return {
    title: titles[place],
    impact: [t.where[place], t.power[p.kind], testNote, japanese ? `（見つけた鍵：${p.masked}）` : `(Found: ${p.masked})`].filter(Boolean).join(japanese ? '' : ' '),
    fix: steps,
    ask,
  };
}

const ja = {
  severity: { critical: '【重大】', high: '【高】', medium: '【中】' },
  label: { where: '場所', impact: '何が起きるか', fix: '直し方', ask: 'AI にこう頼む', ok: '確認して問題にしなかったもの', notes: 'お知らせ', live: '実際の問い合わせ（読むだけ・各テーブル1行）', problems: '読めなかったもの' },
  header: (root, stack, files) => `vibe-checkup — ${root}${stack.length ? `（${stack.join('・')}）` : ''}・${files} ファイルを読みました`,
  summary: (c) => {
    const total = c.critical + c.high + c.medium;
    if (!total) return '問題は見つかりませんでした。ただし、このツールが見ないもの（README の「見ないもの」）は別に確かめてください。';
    const parts = [c.critical && `重大 ${c.critical}`, c.high && `高 ${c.high}`, c.medium && `中 ${c.medium}`].filter(Boolean);
    return `${total} 件の問題が見つかりました（${parts.join('・')}）。【重大】は、リンクを誰かに教える前に直してください。`;
  },
  scope: { everyone: '誰でも（ログインしていなくても）', 'signed-in': 'ログインした人なら誰でも' },
  verbs: { read: '読む', add: '追加する', change: '書き換える', delete: '消す' },
  signup: 'アプリには誰でも登録できるので、「ログインしている」は「信用できる人」という意味になりません。',
  kind: {
    'supabase-service-role': 'Supabase の service_role キー（管理者用の鍵）',
    'supabase-secret': 'Supabase の secret キー（管理者用の鍵）',
    stripe: 'Stripe の秘密鍵',
    clerk: 'Clerk の秘密鍵',
    openai: 'OpenAI の API キー',
    anthropic: 'Anthropic（Claude）の API キー',
    resend: 'Resend の API キー',
    sendgrid: 'SendGrid の API キー',
    aws: 'AWS のアクセスキー',
    github: 'GitHub のトークン',
    'private-key': '秘密鍵（private key）',
    'database-url': 'データベースのパスワード',
    'supabase-anon': 'Supabase の anon キー',
    'supabase-publishable': 'Supabase の publishable キー',
    'google-api-key': 'Firebase（Google）の API キー',
    'stripe-publishable': 'Stripe の公開鍵（pk_）',
  },
  power: {
    'supabase-service-role': 'この鍵は RLS（行ごとの権限）をすべて素通りします。手に入れた人は、データベースの全部の行を読み・書き換え・消せます。全会員のメールアドレスも、注文も、全部です。',
    'supabase-secret': 'この鍵は RLS（行ごとの権限）をすべて素通りします。手に入れた人は、データベースの全部の行を読み・書き換え・消せます。全会員のメールアドレスも、注文も、全部です。',
    'database-url': '手に入れた人は、データベースに直接つないで、RLS を無視して何でもできます。',
    stripe: '手に入れた人は、あなたの Stripe アカウントを使えます。顧客や決済の一覧を見る・返金する・新しい請求を作る、などです。',
    clerk: '手に入れた人は、Clerk の管理用 API で会員の一覧を見たり、書き換えたり、消したりできます。',
    openai: '手に入れた人は、あなたの支払いで AI を使えます。漏れた AI の鍵は自動で探されていて、上限まで使われます。',
    anthropic: '手に入れた人は、あなたの支払いで AI を使えます。漏れた AI の鍵は自動で探されていて、上限まで使われます。',
    resend: '手に入れた人は、あなたの名前でメールを送れます（あなたのドメインからの詐欺メールなど）。',
    sendgrid: '手に入れた人は、あなたの名前でメールを送れます（あなたのドメインからの詐欺メールなど）。',
    aws: '手に入れた人は、この鍵の権限であなたの AWS を使えます。漏れた AWS の鍵は、あなたの支払いで暗号資産の採掘に使われることがよくあります。',
    github: '手に入れた人は、GitHub であなたとして振る舞えます。非公開のコードも読めます。',
    'private-key': '手に入れた人は、この鍵が守っているものに署名したり、復号したりできます。',
  },
  rotate: {
    'supabase-service-role': 'Supabase の管理画面で「Project Settings」→「API Keys」を開き、サーバー用に新しい secret キーを作ってから、古い形式の鍵（legacy keys）を無効にします。これで漏れた service_role キーは使えなくなります（画面側は anon キーの代わりに新しい publishable キーを使います）。',
    'supabase-secret': 'Supabase の管理画面で「Project Settings」→「API Keys」を開き、新しい secret キーを作って、漏れた鍵を消します。',
    'database-url': 'データベースのパスワードを変えます（Supabase なら「Project Settings」→「Database」→「Reset database password」）。',
    stripe: 'Stripe のダッシュボードで「開発者」→「API キー」を開き、この鍵を作り直します（ロール）。',
    clerk: 'Clerk のダッシュボードで「API Keys」を開き、新しい secret キーを作って、この鍵を消します。',
    openai: 'platform.openai.com の「API keys」で、この鍵を無効にして新しい鍵を作ります。',
    anthropic: 'Anthropic の Console の「API Keys」で、この鍵を無効にして新しい鍵を作ります。',
    resend: 'Resend の管理画面の「API Keys」で、この鍵を消して新しい鍵を作ります。',
    sendgrid: 'SendGrid の「Settings」→「API Keys」で、この鍵を消して新しい鍵を作ります。',
    aws: 'AWS コンソールの「IAM」→ そのユーザーの「認証情報」で、このアクセスキーを無効にして削除し、新しいキーを作ります。',
    github: 'GitHub の「Settings」→「Developer settings」→「Personal access tokens」で、このトークンを消します。',
    'private-key': 'この鍵を使っている場所で新しい鍵の組を作り、古い鍵を外します。',
  },
  where: {
    browser: 'サイトを開いた人のブラウザに届くコードに入っているので、誰でもブラウザの開発者ツールを開けば取り出せます。',
    mixed: '画面の部品がこのファイルを読み込んだ時点で、ブラウザに届くコードに混ざります。',
    repo: 'プロジェクトのファイルに直接書かれているので、コードを見られる人（git の過去の版も含めて）は誰でも手に入れられます。',
  },
  finding: {
    'secret-in-browser': (p) => leak(ja, p, 'browser'),
    'secret-maybe-in-browser': (p) => leak(ja, p, 'mixed'),
    'secret-in-code': (p) => leak(ja, p, 'repo'),
    'secret-name-in-public-env': (p) => ({
      title: `${p.name} は秘密のはずなのに、名前が ${p.prefix} で始まっています`,
      impact: `${p.prefix} で始まる変数は、サイトを開いた人全員に届くコードに、そのまま書き込まれます。名前からするとこれは秘密の鍵なので、誰でも取り出して、あなたの支払いでそのサービスを使えます。`,
      fix: [
        `${p.prefix} の付かない名前に変え、サーバー側（Supabase の Edge Function、Next.js の route handler など）だけで使います。`,
        'この値のままサイトを公開したことがあるなら、鍵は漏れたものとして扱い、サービスの管理画面で作り直して古い鍵を止めます。',
      ],
      ask: `${p.name} を使っている処理を Supabase の Edge Function（またはサーバー側の route）に移し、鍵は ${p.prefix} の付かない名前でサーバー側の secret に置いて、画面からはその関数を呼ぶようにして。`,
    }),
    'ai-sdk-in-browser': () => ({
      title: 'AI のライブラリを、ブラウザで動かす設定になっています',
      impact: 'dangerouslyAllowBrowser（または anthropic-dangerous-direct-browser-access）は、OpenAI や Anthropic のライブラリを画面の中で動かす設定です。これが動くのは API キーも画面に入っているときだけなので、サイトを開いた人は誰でも鍵を取り出して、あなたの支払いで AI を使えます。',
      fix: ['AI の呼び出しはサーバー側（Supabase の Edge Function など）に移し、鍵もそこに置きます。画面からは自分の関数を呼ぶだけにします。'],
      ask: 'AI の呼び出しをブラウザから Supabase の Edge Function に移し、API キーは Edge Function の secret に置いて、dangerouslyAllowBrowser を消して。',
    }),
    'env-tracked': (p) => ({
      title: `${p.file} が git に保存されています`,
      impact: p.secrets
        ? '中に秘密の鍵が入っています。git は過去の版を全部残すので、ファイルを消したあとでも、このリポジトリを見られる人は誰でも読めます。'
        : `公開する前提ではない設定（${listJa(p.names)}）が入っています。git は過去の版を全部残すので、ファイルを消したあとでも読めます。`,
      fix: [
        `git の管理から外します：\`git rm --cached ${p.file}\` を打ち、.gitignore に \`.env*\` と \`!.env.example\` を足します。`,
        'このリポジトリを GitHub などに上げたこと・人に渡したことがあるなら、中の鍵は漏れたものとして扱い、作り直して古い鍵を止めます。',
      ],
      ask: `${p.file} をファイルは残したまま git の管理から外し、.env を .gitignore に入れて、中のどの鍵を作り直すべきか教えて。`,
    }),
    'rls-disabled': (p) => ({
      title: `テーブル「${p.table}」の RLS（行ごとの権限）が切れています`,
      impact: `アプリは Supabase の URL と公開用の鍵を、サイトを開いた人全員に渡しています。RLS が切れていると、それを使って${ja.scope.everyone}「${p.table}」の全部の行を読み・書き換え・消せます${p.columns.length ? `（${listJa(p.columns)} も含めて）` : ''}。${p.policies ? `このテーブル用に書かれた ${p.policies} 個のポリシーは、RLS を入れるまで何もしていません。` : ''}`,
      fix: [
        `Supabase の管理画面で「Table Editor」→「${p.table}」を開き、RLS をオンにします（「Authentication」→「Policies」でも、テーブルごとにオンにできます）。`,
        'そのうえで、自分の行だけに届くポリシーを足します。ポリシーが1つも無いと、アプリからもこのテーブルが読めなくなります。',
        p.owner ? `下の SQL は「${p.owner}」列に持ち主のユーザー ID が入っている前提です。` : '下の SQL の user_id は、行の持ち主を入れている列の名前に置き換えてください。',
        '商品一覧のように誰が読んでもよいテーブルなら、読むのは `for select using (true)` で全員に許し、書くのは持ち主だけにします。',
      ],
      code: `alter table public.${p.table} enable row level security;\n${ownerPolicySql(p.table, p.owner)}`,
      ask: `${p.table} テーブルの RLS をオンにして、各ユーザーが自分の行だけを読み書きできるポリシーを足して。`,
    }),
    'policy-open': (p) => ({
      title: `テーブル「${p.table}」：${p.scope === 'everyone' ? '誰でも' : 'ログインした人なら誰でも'}全部の行を${listJa(p.verbs.map((v) => ja.verbs[v]))}ことができます`,
      impact: `ポリシー${listJa(p.policies.map((n) => `「${n}」`))}が、${ja.scope[p.scope]}「${p.table}」の全部の行を${listJa(p.verbs.map((v) => ja.verbs[v]))}ことを許しています${p.columns.length ? `（${listJa(p.columns)} も含めて）` : ''}。${p.scope === 'signed-in' ? `このポリシーは「ログインしているか」しか確かめず、「誰の行か」を確かめていません。${ja.signup}` : 'using (true) は「何も確かめない」という意味です。'}`,
      fix: [
        `ポリシーを、行の持ち主かどうかを確かめる形に書き換えます：using ((select auth.uid()) = ${p.owner ?? 'user_id'})`,
        p.owner ? `下の SQL は「${p.owner}」列に持ち主のユーザー ID が入っている前提です。` : '下の SQL の user_id は、行の持ち主を入れている列の名前に置き換えてください。',
        ...(keepsRead(p) ? ['最後の1文で、読むことだけは全員に残しています（このテーブルはそれが意図に見えるため）。人に見せない行なら、この1文は外してください。'] : []),
      ],
      code: policySql(p),
      ask: `${p.table} テーブルの RLS ポリシーを、各ユーザーが自分の行だけを${listJa(p.verbs.map((v) => ja.verbs[v]))}形に書き直して。`,
    }),
    'storage-policy-open': (p) => ({
      title: `${p.buckets.length ? `バケット${listJa(p.buckets.map((b) => `「${b}」`))}` : '全部のバケット'}のファイルを、${p.scope === 'everyone' ? '誰でも' : 'ログインした人なら誰でも'}${listJa(p.verbs.map((v) => ja.verbs[v]))}ことができます`,
      impact: `ストレージのポリシー${listJa(p.policies.map((n) => `「${n}」`))}は、ファイルがどのバケットにあるかだけを見て、誰が上げたかを見ていません。そのため${ja.scope[p.scope]}全員分のファイルを${listJa(p.verbs.map((v) => ja.verbs[v]))}ことができます。${p.scope === 'signed-in' ? ja.signup : ''}`,
      fix: [
        '各ユーザーのファイルは、そのユーザー ID の名前のフォルダに置き（例：`<ユーザーID>/invoice.pdf`）、自分のフォルダにだけ届くようにします。',
        'Supabase の管理画面「Storage」→「Policies」で直すか、下の SQL を流します。',
      ],
      code: storageSql(p.buckets, p.policies),
      ask: 'ストレージのポリシーを、各ユーザーが自分のユーザー ID のフォルダの中だけを読み書きできる形に変えて。',
    }),
    'bucket-public': (p) => ({
      title: `ストレージのバケット「${p.bucket}」が公開になっています`,
      impact: `ファイルのリンクを知っている人は、ログインしなくてもダウンロードできます。リンクは転送され、記録に残り、推測されます。${p.sensitive ? '名前からすると、人に見せない書類を置く場所のようです。' : ''}`,
      fix: [
        `Supabase の管理画面で「Storage」→「${p.bucket}」→「Edit bucket」を開き、「Public bucket」をオフにします。`,
        'ファイルを見せるときは、期限付きのリンク（createSignedUrl）を使います。',
      ],
      ask: `ストレージの ${p.bucket} バケットを非公開にして、ファイルは期限付きの signed URL で見せるようにして。`,
    }),
    'definer-function': (p) => ({
      title: `データベースの関数「${p.fn}」は全権で動き、${p.scope === 'everyone' ? '誰でも' : 'ログインした人なら誰でも'}呼べます`,
      impact: `security definer が付いているので RLS を素通りし、しかも${ja.scope[p.scope]}API（/rest/v1/rpc/${p.fn}）から呼べます。${p.writes ? 'この関数はデータを書き換えます。' : 'この関数はデータを返します。'}`,
      fix: [
        'サーバーや他のデータベースの処理からしか呼ばないなら、API から呼ぶ権利を取り上げます（下の SQL）。',
        'ログインした人が使う必要があるなら、authenticated だけが呼べるようにし、関数の中で auth.uid() を確かめるか、security invoker に変えます。',
      ],
      code: `revoke execute on function public.${p.fn} from public, anon${p.scope === 'signed-in' ? ', authenticated' : ''};`,
      ask: `${p.fn} 関数を、ログインしていない人には呼べないようにし、中で auth.uid() を確かめて、本人のデータにしか触れないようにして。`,
    }),
    'view-exposes-users': (p) => ({
      title: `ビュー「${p.view}」が auth.users を誰にでも見せています`,
      impact: 'auth.users には全アカウントのメールアドレス・電話番号・ログイン情報が入っています。このビューは作った人の権限で動くので、誰でも API から読めます。',
      fix: ['ビューを消すか、public 以外のスキーマに移します。名前などを画面で使うなら、RLS で守った profiles テーブルに置きます。'],
      code: `drop view public.${p.view};`,
      ask: `auth.users を見せている ${p.view} ビューを消し、代わりに RLS 付きの profiles テーブルを使うようにして。`,
    }),
    'view-bypasses-rls': (p) => ({
      title: `ビュー「${p.view}」が${listJa(p.tables.map((t) => `「${t}」`))}の RLS を素通りしています`,
      impact: 'ビューは、指定しないかぎり作った人の権限で動きます。そのため RLS で隠していた行も、ビュー経由なら誰でも読めます。',
      fix: ['ビューが「問い合わせた人の権限」で動くようにします（Postgres 15 以降。Supabase は対応済み）。'],
      code: `alter view public.${p.view} set (security_invoker = true);`,
      ask: `${p.view} ビューに security_invoker = true を付けて、RLS が効くようにして。`,
    }),
    'grant-too-broad': (p) => ({
      title: {
        schema: `${listJa(p.grantees)} に ${p.object} への権限が与えられています`,
        role: `${listJa(p.grantees)} に ${p.object} の役割が与えられています`,
        bypassrls: `${p.object} が RLS を素通りできる設定になっています`,
      }[p.kind],
      impact: {
        schema: 'auth スキーマや vault には、全アカウントの情報や秘密が入っています。公開用の役割に権限を与えると、サイトを開いた人が読めてしまいます。',
        role: `${listJa(p.grantees)} からの問い合わせが、すべて管理者の権限になり、RLS を素通りします。`,
        bypassrls: `${p.object} からの問い合わせが、すべて RLS を素通りします。`,
      }[p.kind],
      fix: ['その行を migration から消し、データベース側でも取り消します（下の SQL）。'],
      code: {
        schema: `revoke all on ${p.object} from ${p.grantees.join(', ')};`,
        role: `revoke ${p.object} from ${p.grantees.join(', ')};`,
        bypassrls: `alter role ${p.object} nobypassrls;`,
      }[p.kind],
      ask: 'この権限を新しい migration で取り消して、なぜ入っていたのか説明して。',
    }),
    'rules-open': (p) => rulesOpen(ja, p),
    'live-readable': (p) => ({
      title: `実際に確かめました：テーブル「${p.table}」はいま誰でも読めます`,
      impact: `アプリに入っている公開用の鍵だけで、データベースが「${p.table}」の行を返しました${p.total !== undefined ? `（全部でおよそ ${p.total} 行）` : ''}。列：${p.columns.join('、') || '（なし）'}。行の中身は表示も保存もしていません。`,
      fix: ['このテーブルの RLS がオンになっているかを確かめ、ポリシーを「持ち主だけが読める」形にします（上の項目、または Supabase の管理画面「Authentication」→「Policies」）。'],
      ask: `${p.table} テーブルの RLS をオンにして、各ユーザーが自分の行だけを読めるポリシーを足して。`,
    }),
  },
  ok: {
    'public-key': (p) => `${ja.kind[p.kind]}：公開して使う前提の鍵なので、ブラウザにあって問題ありません。この鍵で何に届くかは ${p.kind === 'google-api-key' ? 'Firebase のセキュリティルール' : p.kind === 'stripe-publishable' ? 'Stripe 側の設定' : 'RLS のポリシー'}が決めます（それは別に確かめています）。`,
    'public-read': (p) => `テーブル「${p.table}」：誰でも読めます（${listJa(p.policies.map((n) => `「${n}」`))}）。個人情報らしい列は無いので、意図どおりと見ました。`,
    'public-files': (p) => `バケット${listJa(p.buckets.map((b) => `「${b}」`))}のファイル：誰でもダウンロードできます。この種類のバケットなら意図どおりと見ました。`,
    'public-bucket': (p) => `バケット「${p.bucket}」は公開です。サイトに表示する画像の置き場なら普通です。`,
    'rules-public-read': (p) => `${SERVICE_JA[p.service]} ${p.path}：誰でも読めます。名前に個人情報らしさは無いので、意図どおりと見ました。`,
  },
  note: {
    'no-migrations': () => 'Supabase を使っていますが supabase/migrations フォルダが無いので、データベースの権限は確かめていません。`supabase db pull` で保存するか、Supabase の管理画面の Security Advisor を使うか、`--live` を試してください。',
    'no-rules': () => 'Firebase を使っていますが firestore.rules・storage.rules・database.rules.json が無いので、ルールは確かめていません。Firebase コンソールのルールをプロジェクトに写すと（firebase init）確かめられます。',
    'test-mode-expired': (p) => `${SERVICE_JA[p.service]}：テストモードのルールは ${p.date} で切れていて、いまは誰も読み書きできません。アプリは動いていないはずです。日付を延ばすのではなく、ちゃんとしたルールを書いてください。`,
    'secrets-only': () => 'Supabase と Firebase のファイルが見つからなかったので、秘密の鍵と git だけを確かめました。',
    'live-no-target': () => '--live：プロジェクトの中に、Supabase の URL とそれに合う公開用の鍵が見つからなかったので、何も送っていません。',
    'live-no-tables': () => '--live：supabase/migrations にテーブルが見つからなかったので、何も送っていません。',
  },
  live: {
    readable: (r) => `誰でも読める（列 ${r.columns.length} 個）`,
    empty: () => '行は返らなかった（RLS が隠しているか、空のテーブル）',
    denied: () => '断られた（安全）',
    missing: () => '見つからない、または API に出していない',
    error: (r) => `確かめられなかった（${r.detail}）`,
  },
};

export const MESSAGES = { en, ja: ja };
