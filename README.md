# vibe-checkup

[日本語](README.ja.md)

Open an app built with Lovable or Bolt, press F12 and watch the Network tab. The page talks
straight to its database: a request to `https://<project>.supabase.co/rest/v1/profiles`, with
the project's key in the `apikey` header. That key is meant to be public. The only thing that
stops a visitor from copying it and asking for every row of `profiles` is row-level security
(RLS), and when the AI that wrote the app leaves RLS off, nothing does. A researcher who
checked 1,645 Lovable apps in 2025 found 303 such open endpoints across 170 of them
([CVE-2025-48757][cve]).

The other common leak runs the opposite way: a key that must stay secret — Supabase's
`service_role` key, a Stripe secret key, an OpenAI key — is put in a `VITE_` or `NEXT_PUBLIC_`
variable, and the build copies it into the JavaScript that every visitor downloads.

`vibe-checkup` reads your project folder, finds both before you share the link, and explains
each finding so that someone who did not write the code can fix it. It reads files only.
Nothing is sent anywhere unless you pass `--live`.

```console
$ npx vibe-checkup examples/bad
vibe-checkup — examples/bad (Vite + React, Supabase, Firebase), 10 files read

CRITICAL  Supabase service_role key is in code sent to the browser
  Where: .env:4 (VITE_SUPABASE_SERVICE_ROLE_KEY), dist/assets/index-FAKE0001.js:1, src/integrations/supabase/client.ts:4 (VITE_SUPABASE_SERVICE_ROLE_KEY)
  What can happen:
    It is in code that every visitor's browser downloads, so anyone can open the
    browser's developer tools and copy it. This key skips every RLS rule. With
    it, a stranger can read, change and delete every row in your database: all
    users, all emails, all orders. (Found: eyJ…)
  How to fix:
    1. Treat the key as leaked: make a new one and turn the old one off.
       Deleting it from the code is not enough — anyone who opened the site, and
       your git history, still has it. In the Supabase dashboard open Project
       Settings → API Keys. Create a new secret key for your server code, then
       disable the legacy keys so the leaked service_role key stops working (the
       app then uses the new publishable key instead of the anon key).
    2. Keep the new key only in server code, such as a Supabase Edge Function,
       in a variable without the VITE_ or NEXT_PUBLIC_ prefix.
    3. The page itself should use only the public key (anon / publishable) and
       let RLS policies decide what each user can do.
  Or ask your AI:
    "Move everything that uses the Supabase service_role key into a Supabase
    Edge Function (or a server route), keep the key as a server-side secret, and
    have the page call that function."

CRITICAL  OpenAI API key is in code sent to the browser
  …

CRITICAL  Stripe secret key is in code sent to the browser
  …

CRITICAL  .env is saved in git
  …

CRITICAL  Table "profiles" has row-level security (RLS) turned off
  Where: supabase/migrations/20250101000000_init.sql:1
  What can happen:
    Your app sends the Supabase URL and public key to every visitor. With RLS
    off, anyone — even people who are not logged in — can use them to read,
    change and delete every row in "profiles", including full_name, email and
    phone.
  How to fix:
    1. In the Supabase dashboard open Table Editor → profiles and turn on RLS.
       (Authentication → Policies lists every table and can turn it on too.)
    2. Then add a policy that lets each user reach only their own rows. Until
       there is a policy, the app cannot read the table at all.
    3. The SQL below assumes "id" holds the owner's user id.
    4. If everyone really may read this table (a product list, say), use `for
       select using (true)` for reading and keep writing to the owner.

       alter table public.profiles enable row level security;
       create policy "Owner only" on public.profiles
         for all to authenticated
         using ((select auth.uid()) = id)
         with check ((select auth.uid()) = id);

  Or ask your AI:
    "Turn on RLS for the profiles table and add policies so each user can only
    read and change their own rows."

CRITICAL  Table "orders": anyone can read, change and delete every row
  …

CRITICAL  Firestore: anyone can read, change and delete all data
  …

HIGH  The AI library is told to run in the browser
  …

HIGH  Table "messages": any logged-in user can read every row
  …

HIGH  Storage bucket "documents" is public
  …

HIGH  Database function "delete_user" runs with full rights and anyone can call it
  …

Checked and fine:
  - Supabase anon key: made to be public, so it is fine in the browser. What it
    can reach is decided by your RLS policies, which this tool checks
    separately.

11 problems found: 7 critical, 4 high. Fix the critical ones before you share the link with anyone.
```

`examples/bad` is a small Lovable-style Vite + React + Supabase app with the usual mistakes;
[`examples/good`](examples/good) is the same app done right, and passes. Every key in them is
fake and says `FAKE`.

## Usage

```sh
npx vibe-checkup                 # the current folder
npx vibe-checkup path/to/app     # another folder
npx vibe-checkup --lang ja       # the report in Japanese (default: from LANG, otherwise English)
npx vibe-checkup --json          # the same report as JSON, for CI
```

Exit codes: `0` no problems found, `1` problems found, `2` the folder or one of its config
files could not be read. A `package.json` or `database.rules.json` that does not parse is a
`2`, not a pass.

## What it checks

**Keys that reach the browser.** It reads front-end source (`src/`, `app/`, `components/` …),
build output (`dist/`, `build/`, `out/`, `public/`, `.next/static/`, the Firebase hosting
folder) and `.env*` files, where a variable starting with `VITE_`, `NEXT_PUBLIC_`,
`REACT_APP_` or `EXPO_PUBLIC_` (or a Vite `envPrefix`) is built into the page.

- Secret keys: Supabase `service_role` (read from the `role` inside the JWT) and `sb_secret_`,
  Stripe `sk_` and `rk_`, OpenAI, Anthropic, Resend, SendGrid, AWS access keys, GitHub tokens,
  private keys, and database URLs with a password.
- A public-prefixed variable whose name says it is secret (`VITE_STRIPE_SECRET_KEY`), whatever
  its value; `dangerouslyAllowBrowser: true` on the OpenAI or Anthropic SDK; `.env` files
  tracked by git.
- The place sets the severity. Browser code and public variables are critical. In Next.js, a
  file without `'use client'` reaches the browser only if a client component imports it, so
  it is high. Server code (`supabase/functions/`, `pages/api/`, route handlers) is medium.
- Not reported, on purpose: the Supabase anon and `sb_publishable_` keys, which Supabase calls
  safe to expose ([docs][sb-keys]); Firebase `AIza…` keys, which "do not need to be treated as
  secrets" when restricted to Firebase services ([docs][fb-keys]); Stripe `pk_` keys. The
  report lists them under "Checked and fine" with that reason, so a reader does not go and
  rotate the wrong key.

**Supabase** (`supabase/migrations/*.sql`, replayed in order, so a later `alter table … enable
row level security` or `drop policy` counts):

- tables in `public` without RLS;
- policies that let everyone, or every signed-in user, read, change or delete every row:
  `using (true)`, `1 = 1`, `auth.uid() is not null`, `auth.role() = 'authenticated'`, also
  inside `or`. Restrictive policies are taken into account. Policies that only add rows are
  not reported;
- public storage buckets, and `storage.objects` policies that check only the bucket;
- `security definer` functions that `anon` or `authenticated` can call through
  `/rest/v1/rpc/…` (trigger functions are skipped);
- views in `public` without `security_invoker`, which bypass RLS, and views over `auth.users`;
- grants of the `auth` schema or `service_role` to `anon` / `authenticated`, and `bypassrls`.

**Firebase** (`firestore.rules`, `storage.rules`, `database.rules.json`, or the paths in
`firebase.json`): `allow …: if true`, a lone `request.auth != null`, helper functions that
amount to the same, and test-mode dates that have not passed yet.

Severity depends on what the data looks like. A table, collection or bucket whose name or
columns look personal (`users`, `profiles`, `orders`, `messages`, `email`, `phone`,
`address` …) is critical when everyone can read it and high when every signed-in user can. A
table that everyone may read and that has no personal-looking names, such as `products` or
`posts`, is listed as fine rather than reported. Writing or deleting every row is reported
whatever the table.

## `--live`: ask your own database

```sh
npx vibe-checkup --live
```

Static reading cannot see changes made in the Supabase dashboard. With `--live`, for each table
in the migrations it sends one `GET /rest/v1/<table>?select=*&limit=1` to the Supabase URL
found in the project, with the public key found in the project, and reports a table that
answers.

- Read-only, one row per table. The row is dropped as soon as it arrives: the report shows
  only the column names and the row count.
- It sends only to the Supabase URL written in the project. On a `*.supabase.co` URL it uses
  only the key issued for that project (the anon key names its project); on any other URL,
  only when the project has exactly one URL and one public key. The `service_role` key is
  never sent.
- **Use it only on projects you own.**

```console
$ npx vibe-checkup --live
vibe-checkup — . (Vite + React, Supabase, Firebase), 9 files read

CRITICAL  Live check: anyone can read table "profiles" right now
  What can happen:
    With only the public key from your app, the database returned a row from
    "profiles" (about 1280 rows in total). Columns: id, full_name, email, phone.
    The row itself was not shown or saved.
  How to fix:
    1. Make sure RLS is on for this table and that its policies let people read
       only their own rows (see the items above, or Supabase dashboard →
       Authentication → Policies).
  Or ask your AI:
    "Turn on RLS for the profiles table and add policies so each user can only
    read their own rows."

CRITICAL  Live check: anyone can read table "orders" right now
  What can happen:
    With only the public key from your app, the database returned a row from
    "orders" (about 310 rows in total). Columns: id, user_id, total,
    shipping_address. The row itself was not shown or saved.
  How to fix:
    1. Make sure RLS is on for this table and that its policies let people read
       only their own rows (see the items above, or Supabase dashboard →
       Authentication → Policies).
  Or ask your AI:
    "Turn on RLS for the orders table and add policies so each user can only
    read their own rows."

…

Live check (read-only, 1 row per table):
  profiles  readable by anyone — 4 columns
  orders    readable by anyone — 4 columns
  messages  no rows returned (RLS is hiding them, or the table is empty)

12 problems found: 8 critical, 4 high. Fix the critical ones before you share the link with anyone.
```

That run was against a local mock server; the same test runs in `npm test`.

## What it does not check

- It reads files. A table, policy or bucket created in the Supabase dashboard and never written
  to `supabase/migrations` is invisible; run `supabase db pull` first, or use `--live` and
  Supabase's own Security Advisor.
- A policy condition it does not recognise is taken as a real restriction. `using (true)`
  is caught; `using (user_id = user_id)`, which is just as open, is not. Rules that call
  `get()` or `exists()` are taken as restrictions too.
- Which tables hold personal data is guessed from names. A public `items` table full of private
  notes would be listed as fine.
- Firebase and Gemini keys share the `AIza` shape. A Gemini key is caught only when its variable
  name says so (`VITE_GEMINI_API_KEY`).
- A secret with no known shape is caught only through its variable name.
- It reads the build output in the folder, not the deployed site.
- Out of scope: sign-up and email settings, the code inside Edge Functions and API routes,
  XSS, CORS, rate limits, vulnerable dependencies.

## How it compares

- **Supabase Security Advisor** ([database linter][sb-lint], [splinter][splinter]) runs SQL
  against your live database. Its lints include `rls_disabled_in_public` and
  `permissive_rls_policy` (`using (true)`), and it sees what you changed in the dashboard. It
  does not read your front-end code or keys. `vibe-checkup` works from files, before deploy and
  in CI without database credentials, and adds the browser side. Run both.
- **Lovable's security scan** ([docs][lovable]) runs a quick scan when you publish (database
  access rules, vulnerable npm packages, MCP servers without auth) and a deep scan on request
  (the whole code, including leaked secrets). It covers Lovable projects. The researcher behind
  CVE-2025-48757 wrote that, at the time, the scanner checked whether a policy existed, not
  whether it was correct ([statement][cve]).
- **Bolt** has a Security Audit in its database settings, based on Supabase's advisor; it looks
  at the database ([docs][bolt]). **Replit** scans with around 200 Semgrep Community rules plus
  secret detection ([Semgrep][replit]). For **v0 / Vercel** we found no built-in check that
  warns about a secret in a `NEXT_PUBLIC_` variable.
- **gitleaks and trufflehog** find key shapes anywhere. gitleaks' default rules cover Stripe,
  OpenAI, Anthropic and SendGrid but not Supabase or Resend keys ([config][gitleaks]);
  trufflehog's Supabase detector looks only for `sbp_` access tokens ([source][trufflehog]).
  Neither reads RLS policies or security rules.
- **Others for vibe-coded apps**: [RLSGuard][rlsguard] reads migrations and code locally
  (Python); [supabase-rls-audit-kit][auditkit] needs a `DATABASE_URL` to the live database;
  [VibeAppScanner][vas] and [VibeScan][vibescan] probe a deployed app from outside.

## Use in CI

```yaml
- run: npx --yes vibe-checkup
```

It exits 1 when it finds a problem. `--json` prints the findings, with the same explanations,
for a bot to post.

[cve]: https://mattpalmer.io/posts/statement-on-CVE-2025-48757/
[sb-keys]: https://supabase.com/docs/guides/api/api-keys
[fb-keys]: https://firebase.google.com/docs/projects/api-keys
[sb-lint]: https://supabase.com/docs/guides/database/database-linter
[splinter]: https://github.com/supabase/splinter
[lovable]: https://docs.lovable.dev/features/security
[bolt]: https://support.bolt.new/cloud/database/security
[replit]: https://semgrep.dev/blog/2025/replit-and-semgrep-secure-vibe-coding
[gitleaks]: https://github.com/gitleaks/gitleaks/blob/master/config/gitleaks.toml
[trufflehog]: https://github.com/trufflesecurity/trufflehog/blob/main/pkg/detectors/supabasetoken/supabasetoken.go
[rlsguard]: https://github.com/Sezman/RLSGaurd
[auditkit]: https://github.com/sharwin-dev/supabase-rls-audit-kit
[vas]: https://vibeappscanner.com/supabase-security
[vibescan]: https://replit.discourse.group/t/i-built-an-open-source-tool-to-check-if-your-vibe-coded-apps-are-accidentally-exposing-data/12215
