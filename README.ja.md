# vibe-checkup

[English](README.md)

Lovable や Bolt で作られたアプリを開き、F12 を押して「ネットワーク」タブを見てください。画面は
データベースと直接やりとりしています。`https://<プロジェクト>.supabase.co/rest/v1/profiles` への
通信があり、`apikey` という欄にプロジェクトの鍵が入っています。この鍵は、もともと公開して使うものです。
見た人がこの鍵を写して「profiles の行を全部ください」と頼むのを止めているのは、RLS（行ごとの権限）
だけです。アプリを書いた AI が RLS を付け忘れていると、止めるものは何もありません。2025 年に
Lovable 製のアプリ 1,645 個を調べた研究者は、そのうち 170 個で、このように開いている入口を合わせて
303 か所見つけました（[CVE-2025-48757][cve]）。

もう一つのよくある事故は逆向きです。隠しておくべき鍵（Supabase の `service_role` キー、Stripe の
秘密鍵、OpenAI の鍵など）が `VITE_` や `NEXT_PUBLIC_` で始まる名前の変数に入っていて、ビルドの
ときに、サイトを開いた人全員に届く JavaScript の中へ書き込まれてしまうことです。

`vibe-checkup` は、プロジェクトのフォルダを読んで、リンクを人に教える前にこの2つを見つけます。
見つけたものには、コードを書いていない人でも直せるように「何が起きるか」と「直し方」を付けます。
読むのはファイルだけです。`--live` を付けない限り、どこにも何も送りません。

```console
$ npx vibe-checkup examples/bad --lang ja
vibe-checkup — examples/bad（Vite + React・Supabase・Firebase）・10 ファイルを読みました

【重大】Supabase の service_role キー（管理者用の鍵）が、ブラウザに届くコードに入っています
  場所: .env:4 (VITE_SUPABASE_SERVICE_ROLE_KEY), dist/assets/index-FAKE0001.js:1, src/integrations/supabase/client.ts:4 (VITE_SUPABASE_SERVICE_ROLE_KEY)
  何が起きるか:
    サイトを開いた人のブラウザに届くコードに入っているので、誰でもブラウザの開発者ツールを開けば取り出せます。
    この鍵は RLS（行ごとの権限）をすべて素通りします。
    手に入れた人は、データベースの全部の行を読み・書き換え・消せます。
    全会員のメールアドレスも、注文も、全部です。
    （見つけた鍵：eyJ…）
  直し方:
    1. この鍵は漏れたものとして扱い、作り直して古い鍵を止めます。
       コードから消すだけでは足りません（すでにサイトを開いた人や、git の履歴に残っています）。
       Supabase の管理画面で「Project Settings」→「API Keys」を開き、サーバー用に新しい secret キーを作ってから、古い形式の鍵（legacy keys）を無効にします。
       これで漏れた service_role キーは使えなくなります（画面側は anon キーの代わりに新しい publishable キーを使います）。
    2. 新しい鍵は VITE_ や NEXT_PUBLIC_ の付かない名前で、Supabase の Edge Function など、サーバー側だけに置きます。
    3. 画面側からは公開用の鍵（anon / publishable）だけを使い、必要な読み書きは RLS のポリシーで許可します。
  AI にこう頼む:
    「Supabase の service_role キー（管理者用の鍵）を使っている処理を Supabase の Edge Function（またはサーバー側の route）に移し、鍵はサーバー側の secret に置いて、画面からはその関数を呼ぶようにして」

【重大】OpenAI の API キーが、ブラウザに届くコードに入っています
  …

【重大】Stripe の秘密鍵が、ブラウザに届くコードに入っています
  …

【重大】.env が git に保存されています
  …

【重大】テーブル「profiles」の RLS（行ごとの権限）が切れています
  場所: supabase/migrations/20250101000000_init.sql:1
  何が起きるか:
    アプリは Supabase の URL と公開用の鍵を、サイトを開いた人全員に渡しています。
    RLS が切れていると、それを使って誰でも（ログインしていなくても）「profiles」の全部の行を読み・書き換え・消せます（full_name・email・phone も含めて）。
  直し方:
    1. Supabase の管理画面で「Table Editor」→「profiles」を開き、RLS をオンにします（「Authentication」→「Policies」でも、テーブルごとにオンにできます）。
    2. そのうえで、自分の行だけに届くポリシーを足します。
       ポリシーが1つも無いと、アプリからもこのテーブルが読めなくなります。
    3. 下の SQL は「id」列に持ち主のユーザー ID が入っている前提です。
    4. 商品一覧のように誰が読んでもよいテーブルなら、読むのは `for select using (true)` で全員に許し、書くのは持ち主だけにします。

       alter table public.profiles enable row level security;
       create policy "Owner only" on public.profiles
         for all to authenticated
         using ((select auth.uid()) = id)
         with check ((select auth.uid()) = id);

  AI にこう頼む:
    「profiles テーブルの RLS をオンにして、各ユーザーが自分の行だけを読み書きできるポリシーを足して」

【重大】テーブル「orders」：誰でも全部の行を読む・書き換える・消すことができます
  …

【重大】Firestore：誰でも全部のデータを読む・書き換える・消すことができます
  …

【高】AI のライブラリを、ブラウザで動かす設定になっています
  …

【高】テーブル「messages」：ログインした人なら誰でも全部の行を読むことができます
  …

【高】ストレージのバケット「documents」が公開になっています
  …

【高】データベースの関数「delete_user」は全権で動き、誰でも呼べます
  …

確認して問題にしなかったもの:
  - Supabase の anon キー：公開して使う前提の鍵なので、ブラウザにあって問題ありません。
    この鍵で何に届くかは RLS のポリシーが決めます（それは別に確かめています）。

11 件の問題が見つかりました（重大 7・高 4）。【重大】は、リンクを誰かに教える前に直してください。
```

`examples/bad` は、Lovable 風の Vite + React + Supabase の小さなアプリに、よくある間違いを入れたものです。
[`examples/good`](examples/good) は同じアプリを正しく作ったもので、問題なしになります。どちらに入っている
鍵もすべて偽物で、`FAKE` と書いてあります。

## 使い方

```sh
npx vibe-checkup                 # いまいるフォルダを調べる
npx vibe-checkup path/to/app     # 別のフォルダを調べる
npx vibe-checkup --lang ja       # 日本語で出す（指定しなければ LANG から決め、無ければ英語）
npx vibe-checkup --json          # 同じ結果を JSON で出す（CI 用）
```

終わったときの番号（終了コード）は、`0` が問題なし、`1` が問題あり、`2` がフォルダや設定ファイルを
読めなかったときです。`package.json` や `database.rules.json` が壊れていて読めないときは、「問題なし」
ではなく `2` になります。

## 何を調べるか

**ブラウザに届く鍵。** 画面側のコード（`src/`・`app/`・`components/` など）、ビルドしてできたファイル
（`dist/`・`build/`・`out/`・`public/`・`.next/static/`・Firebase Hosting のフォルダ）、`.env` ファイルを
読みます。`.env` では、`VITE_`・`NEXT_PUBLIC_`・`REACT_APP_`・`EXPO_PUBLIC_`（と Vite の `envPrefix`）で
始まる変数がページに書き込まれます。

- 秘密の鍵：Supabase の `service_role`（JWT の中の `role` を読んで見分けます）と `sb_secret_`、Stripe の
  `sk_` と `rk_`、OpenAI、Anthropic、Resend、SendGrid、AWS のアクセスキー、GitHub のトークン、秘密鍵の
  ファイル、パスワード入りのデータベース URL。
- 公開用の名前なのに名前が「秘密」と言っている変数（`VITE_STRIPE_SECRET_KEY` など。中身は問いません）。
  OpenAI や Anthropic のライブラリをブラウザで動かす `dangerouslyAllowBrowser: true`。git に保存された `.env`。
- 重さは置き場所で決まります。画面のコードと公開用の変数に入っていれば【重大】。Next.js で
  `'use client'` の無いファイルは、画面側から読み込まれたときだけブラウザに届くので【高】。サーバー側の
  コード（`supabase/functions/`・`pages/api/`・route handler）は【中】です。
- わざと鳴らさないもの：Supabase の anon キーと `sb_publishable_` キー（Supabase は公開してよいと
  書いています。[公式][sb-keys]）、Firebase の `AIza…` キー（Firebase のサービスに限った鍵は秘密として
  扱わなくてよい、と書いています。[公式][fb-keys]）、Stripe の `pk_` キー。これらは結果の
  「確認して問題にしなかったもの」に理由と一緒に出ます。間違った鍵を作り直さずに済むようにです。

**Supabase**（`supabase/migrations/*.sql` を古い順に読みます。後のファイルで RLS をオンにしたり、
ポリシーを消したりしていれば、それも反映します）

- RLS が切れている `public` のテーブル
- 誰でも、またはログインした人なら誰でも、全部の行を読む・書き換える・消すことができるポリシー。
  `using (true)`・`1 = 1`・`auth.uid() is not null`・`auth.role() = 'authenticated'` を、`or` の中に
  あるものも含めて見ます。restrictive なポリシーで絞っていれば考えに入れます。行を足すだけのポリシーは
  鳴らしません
- 公開になっているストレージのバケットと、バケットの名前しか確かめていない `storage.objects` のポリシー
- `anon` や `authenticated` が `/rest/v1/rpc/…` から呼べる `security definer` の関数（トリガー用は除きます）
- `security_invoker` の無い `public` のビュー（RLS を素通りします）と、`auth.users` を見せるビュー
- `auth` スキーマや `service_role` を `anon` / `authenticated` に渡す grant と `bypassrls`

**Firebase**（`firestore.rules`・`storage.rules`・`database.rules.json`、または `firebase.json` に書かれた
ファイル）：`allow …: if true`、`request.auth != null` だけの条件、同じ意味になる自作の関数、まだ期限が
来ていないテストモードの日付。

重さはデータの中身の見当で変わります。テーブル・コレクション・バケットの名前や列の名前が個人情報
らしいとき（`users`・`profiles`・`orders`・`messages`・`email`・`phone`・`address` など）、誰でも
読めれば【重大】、ログインした人なら誰でも読めれば【高】です。`products` や `posts` のように誰でも
読めて個人情報らしい名前が無いテーブルは、問題ではなく「確認して問題にしなかったもの」に出します。
全部の行を書き換えられる・消せるものは、どのテーブルでも鳴らします。

## `--live`：自分のデータベースに実際に聞く

```sh
npx vibe-checkup --live
```

ファイルを読むだけでは、Supabase の管理画面で直接変えたことは見えません。`--live` を付けると、
migrations に出てくるテーブルごとに、プロジェクトの中で見つけた Supabase の URL へ、プロジェクトの
中で見つけた公開用の鍵で `GET /rest/v1/<テーブル>?select=*&limit=1` を1回ずつ送り、答えが返ってきた
テーブルを知らせます。

- 読むだけで、1テーブルにつき1行だけです。返ってきた行はその場で捨て、結果には列の名前と行数しか
  出しません。
- 送り先は、プロジェクトに書かれている Supabase の URL だけです。`*.supabase.co` の URL には、その
  プロジェクト用の鍵しか使いません（anon キーには自分のプロジェクト名が入っています）。それ以外の URL
  には、URL と公開用の鍵がちょうど1つずつのときだけ送ります。`service_role` キーは決して送りません。
- **自分のプロジェクトにだけ使ってください。**

```console
$ npx vibe-checkup --live --lang ja
vibe-checkup — .（Vite + React・Supabase・Firebase）・9 ファイルを読みました

【重大】実際に確かめました：テーブル「profiles」はいま誰でも読めます
  何が起きるか:
    アプリに入っている公開用の鍵だけで、データベースが「profiles」の行を返しました（全部でおよそ 1280 行）。
    列：id、full_name、email、phone。
    行の中身は表示も保存もしていません。
  直し方:
    1. このテーブルの RLS がオンになっているかを確かめ、ポリシーを「持ち主だけが読める」形にします（上の項目、または Supabase の管理画面「Authentication」→「Policies」）。
  AI にこう頼む:
    「profiles テーブルの RLS をオンにして、各ユーザーが自分の行だけを読めるポリシーを足して」

【重大】実際に確かめました：テーブル「orders」はいま誰でも読めます
  何が起きるか:
    アプリに入っている公開用の鍵だけで、データベースが「orders」の行を返しました（全部でおよそ 310 行）。
    列：id、user_id、total、shipping_address。
    行の中身は表示も保存もしていません。
  直し方:
    1. このテーブルの RLS がオンになっているかを確かめ、ポリシーを「持ち主だけが読める」形にします（上の項目、または Supabase の管理画面「Authentication」→「Policies」）。
  AI にこう頼む:
    「orders テーブルの RLS をオンにして、各ユーザーが自分の行だけを読めるポリシーを足して」

…

実際の問い合わせ（読むだけ・各テーブル1行）:
  profiles  誰でも読める（列 4 個）
  orders    誰でも読める（列 4 個）
  messages  行は返らなかった（RLS が隠しているか、空のテーブル）

12 件の問題が見つかりました（重大 8・高 4）。【重大】は、リンクを誰かに教える前に直してください。
```

上の結果は、手元で立てた偽のサーバーに向けて走らせたものです。同じ確かめを `npm test` でも行っています。

## 調べないこと

- 読むのはファイルだけです。Supabase の管理画面で作ったテーブル・ポリシー・バケットで、
  `supabase/migrations` に書かれていないものは見えません。先に `supabase db pull` を打つか、
  `--live` と Supabase 自身の Security Advisor を使ってください。
- 知らない形の条件は「ちゃんと絞っている」と受け取ります。`using (true)` は見つけますが、同じくらい
  開いている `using (user_id = user_id)` は見つけません。Firebase の `get()`・`exists()` を使う条件も、
  絞っているものとして扱います。
- どのテーブルに個人情報があるかは名前からの見当です。誰でも読める `items` テーブルに人の書いたメモが
  入っていても、「問題にしなかったもの」に出ます。
- Firebase の鍵と Gemini の鍵は、どちらも `AIza` で始まる同じ形です。Gemini の鍵は、変数の名前が
  そう言っているとき（`VITE_GEMINI_API_KEY` など）だけ見つけます。
- 決まった形の無い秘密は、変数の名前からしか見つけません。
- 読むのはフォルダの中のビルド結果で、公開中のサイトそのものではありません。
- 対象外：会員登録やメール確認の設定、Edge Function や API route の中身、XSS、CORS、回数制限、
  脆弱性のあるライブラリ。

## ほかの道具との違い

- **Supabase の Security Advisor**（[database linter][sb-lint]・[splinter][splinter]）は、動いている
  データベースに SQL を当てて調べます。`rls_disabled_in_public`（RLS が切れている）や
  `permissive_rls_policy`（`using (true)`）などがあり、管理画面で変えたことも見えます。画面側のコードや
  鍵は見ません。`vibe-checkup` はファイルから調べるので、公開前に、データベースのパスワード無しで CI でも
  走り、画面側の鍵も見ます。両方使うのがおすすめです。
- **Lovable のセキュリティスキャン**（[公式][lovable]）は、公開のときに軽いスキャン（データベースの
  アクセスルール、npm の脆弱性、認証の無い MCP サーバー）を、頼めば詳しいスキャン（コード全体。秘密の
  漏れを含む）を行います。Lovable のプロジェクトが対象です。CVE-2025-48757 を見つけた研究者は、当時の
  スキャナが「ポリシーがあるか」だけを見て「正しいか」は見ていなかった、と書いています（[声明][cve]）。
- **Bolt** には、データベースの設定に Supabase の Advisor をもとにした Security Audit があり、見るのは
  データベースです（[公式][bolt]）。**Replit** は約 200 の Semgrep Community のルールと秘密の検出で
  調べます（[Semgrep][replit]）。**v0 / Vercel** には、`NEXT_PUBLIC_` の変数に入った秘密を知らせる
  仕組みは見つかりませんでした。
- **gitleaks と trufflehog** は、どこにあっても鍵の形を見つけます。gitleaks の標準のルールには Stripe・
  OpenAI・Anthropic・SendGrid はありますが、Supabase と Resend の鍵はありません（[設定][gitleaks]）。
  trufflehog の Supabase 用の検出は `sbp_` で始まるアクセストークンだけです（[ソース][trufflehog]）。
  どちらも RLS のポリシーや Firebase のルールは読みません。
- **ほかの vibe coding 向けの道具**：[RLSGuard][rlsguard] は migrations とコードを手元で読みます
  （Python）。[supabase-rls-audit-kit][auditkit] は動いているデータベースへの `DATABASE_URL` が要ります。
  [VibeAppScanner][vas] と [VibeScan][vibescan] は、公開中のアプリを外から調べます。

## CI で使う

```yaml
- run: npx --yes vibe-checkup
```

問題があれば 1 で終わります。`--json` を付けると、説明も含めた結果を JSON で出すので、ボットに
書き込ませることもできます。

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
