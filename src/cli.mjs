#!/usr/bin/env node
import { readFileSync, realpathSync } from 'node:fs';
import { pathToFileURL } from 'node:url';
import { renderJson, renderText } from './report.mjs';
import { scan } from './scan.mjs';

const VERSION = JSON.parse(readFileSync(new URL('../package.json', import.meta.url), 'utf8')).version;

const HELP = `vibe-checkup ${VERSION} — before you share your AI-built app, check who can read its data.

Usage: vibe-checkup [dir] [options]

Reads the project folder (default: the current one) and looks for the two mistakes that leak
data most often in apps built with Lovable, Bolt, v0, Replit and similar tools:
  - secret keys in code that reaches the browser (service_role, Stripe, OpenAI, ...)
  - database rules that let anyone read or change everyone's data
    (Supabase RLS in supabase/migrations, Firebase security rules)
Nothing is sent anywhere unless you pass --live.

Options:
  --live          also ask your own Supabase project, with the public key found in the
                  project, whether each table hands out a row to anyone. Read-only, one row
                  per table, and only the row count and column names are shown.
                  Use it only on projects you own.
  --lang <ja|en>  language of the report (default: from LANG, otherwise en)
  --json          print the result as JSON
  -h, --help      show this help
  -v, --version   show the version

Exit codes: 0 no problems found, 1 problems found, 2 usage error or the project could not be read.`;

export function parseArgs(argv, env = process.env) {
  const opts = { root: '.', live: false, json: false, lang: undefined };
  for (let i = 0; i < argv.length; i++) {
    const a = argv[i];
    const value = () => {
      if (i + 1 >= argv.length) throw new Error(`${a} needs a value`);
      return argv[++i];
    };
    if (a === '-h' || a === '--help') opts.help = true;
    else if (a === '-v' || a === '--version') opts.version = true;
    else if (a === '--live') opts.live = true;
    else if (a === '--json') opts.json = true;
    else if (a === '--lang') opts.lang = value();
    else if (a.startsWith('--lang=')) opts.lang = a.slice('--lang='.length);
    else if (a.startsWith('-')) throw new Error(`unknown option ${a}`);
    else opts.root = a;
  }
  if (opts.lang !== undefined && !['ja', 'en'].includes(opts.lang)) throw new Error(`--lang must be ja or en (got "${opts.lang}")`);
  opts.lang ??= langFromEnv(env);
  return opts;
}

// The first locale variable that is set wins, the same order gettext uses.
export function langFromEnv(env) {
  const locale = env.LC_ALL || env.LC_MESSAGES || env.LANG || '';
  return /^ja\b|^ja[_-]/i.test(locale) ? 'ja' : 'en';
}

export async function main(argv, io = { log: (s) => process.stdout.write(s), error: console.error }, env = process.env) {
  let opts;
  try {
    opts = parseArgs(argv, env);
  } catch (e) {
    io.error(`vibe-checkup: ${e.message}\nRun vibe-checkup --help for usage.`);
    return 2;
  }
  if (opts.help || opts.version) {
    io.log(`${opts.help ? HELP : VERSION}\n`);
    return 0;
  }

  let result;
  try {
    result = await scan(opts.root, { live: opts.live });
  } catch (e) {
    io.error(`vibe-checkup: could not read ${opts.root}: ${e.message}`);
    return 2;
  }
  io.log(opts.json ? renderJson(result, opts.lang) : renderText(result, opts.lang));
  if (result.problems.length) return 2;
  return result.findings.length ? 1 : 0;
}

function runDirectly() {
  const arg = process.argv[1];
  if (!arg) return false;
  try {
    return import.meta.url === pathToFileURL(realpathSync(arg)).href;
  } catch {
    return false;
  }
}

// exitCode rather than exit(): a long report written to a pipe must finish flushing first.
if (runDirectly()) main(process.argv.slice(2)).then((code) => {
  process.exitCode = code;
});
