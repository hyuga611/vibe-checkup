import { readFileSync, readdirSync, statSync } from 'node:fs';
import { basename, join } from 'node:path';

const SKIP_DIRS = new Set([
  'node_modules', '.git', '.hg', '.svn', '.turbo', '.vercel', '.netlify', '.firebase', '.cache',
  '.parcel-cache', '.svelte-kit', '.expo', 'coverage', '.venv', 'venv', '__pycache__', 'Pods',
]);
const SKIP_PATHS = new Set(['.next/cache']);
const LOCKFILES = new Set(['package-lock.json', 'npm-shrinkwrap.json', 'pnpm-lock.yaml', 'yarn.lock', 'bun.lock', 'deno.lock']);
const TEXT_FILE = /\.(?:[cm]?[jt]sx?|vue|svelte|astro|html?|json|ya?ml|toml|sql|rules)$/i;
const ENV_FILE = /^\.env(?:\..+)?$/;
const EXAMPLE_ENV = /\.(?:example|sample|template|dist|defaults)$/i;
const MAX_BYTES = 10 * 1024 * 1024;

export const PUBLIC_PREFIXES = ['VITE_', 'NEXT_PUBLIC_', 'REACT_APP_', 'EXPO_PUBLIC_'];

export const isEnvFile = (rel) => ENV_FILE.test(basename(rel));
export const isExampleEnv = (rel) => isEnvFile(rel) && EXAMPLE_ENV.test(rel);

// Where a file's contents end up. `browser`: sent to every visitor. `mixed`: Next.js code
// that reaches the browser when a client component imports it. `server`: runs on a server
// only. `env`: an environment file. `repo`: only people who can read the code see it.
const BUILD_OUTPUT = /^(?:dist|build|out|public|\.next\/static)\//;
const SERVER_CODE = /^(?:supabase\/functions|functions|api|server|backend|netlify\/functions|scripts|\.next)\//;
const NEXT_SERVER_FILE = /(?:^|\/)(?:pages|app)\/api\/|(?:^|\/)route\.[cm]?[jt]sx?$|(?:^|\/)middleware\.[cm]?[jt]s$|\.server\.[cm]?[jt]sx?$/;
const CLIENT_SOURCE = /^(?:src|app|components|lib|hooks|pages|utils|contexts?|store|services|features)\//;
const BUILD_CONFIG = /^(?:vite|next)\.config\.[cm]?[jt]s$/;
const USE_CLIENT = /^(?:\s|\/\/[^\n]*\n|\/\*[\s\S]*?\*\/)*(['"])use client\1/;

function walk(root) {
  const files = [];
  const visit = (dir, rel) => {
    let entries;
    try {
      entries = readdirSync(dir, { withFileTypes: true });
    } catch (e) {
      if (!rel) throw e;
      return;
    }
    for (const entry of entries) {
      const path = rel ? `${rel}/${entry.name}` : entry.name;
      if (entry.isDirectory()) {
        if (!SKIP_DIRS.has(entry.name) && !SKIP_PATHS.has(path)) visit(join(dir, entry.name), path);
      } else if (entry.isFile() && (ENV_FILE.test(entry.name) || (TEXT_FILE.test(entry.name) && !LOCKFILES.has(entry.name)))) {
        files.push(path);
      }
    }
  };
  visit(root, '');
  return files.sort();
}

function hostingDirs(firebase) {
  const hosting = firebase?.hosting;
  const sites = Array.isArray(hosting) ? hosting : hosting ? [hosting] : [];
  return sites.map((s) => s.public).filter((p) => typeof p === 'string').map((p) => p.replace(/^\.\/|\/$/g, ''));
}

// Vite only inlines variables that start with an allowed prefix, and envPrefix widens the list.
function vitePrefixes(text) {
  const m = text && /envPrefix\s*:\s*(\[[^\]]*\]|(['"`])[^'"`]*\2)/.exec(text);
  return m ? [...m[1].matchAll(/['"`]([^'"`]+)['"`]/g)].map((x) => x[1]) : [];
}

export function loadProject(root) {
  if (!statSync(root).isDirectory()) throw new Error(`${root} is not a folder`);
  const files = walk(root);
  const fileSet = new Set(files);
  const cache = new Map();
  const problems = [];

  const read = (rel) => {
    if (!cache.has(rel)) {
      let text = null;
      try {
        const abs = join(root, rel);
        if (statSync(abs).size <= MAX_BYTES) text = readFileSync(abs, 'utf8').replace(/^﻿/, '');
      } catch {
        text = null;
      }
      cache.set(rel, text);
    }
    return cache.get(rel);
  };
  const json = (rel) => {
    if (!fileSet.has(rel)) return null;
    try {
      return JSON.parse(read(rel));
    } catch (e) {
      problems.push(`${rel}: ${e.message}`);
      return null;
    }
  };

  const pkg = json('package.json');
  const firebase = json('firebase.json');
  const deps = { ...pkg?.dependencies, ...pkg?.devDependencies };
  const has = (re) => files.some((f) => re.test(f));
  const stack = {
    next: 'next' in deps || has(/^next\.config\.[cm]?[jt]s$/),
    vite: 'vite' in deps || has(/^vite\.config\.[cm]?[jt]s$/),
    cra: 'react-scripts' in deps,
    expo: 'expo' in deps,
    react: 'react' in deps,
    supabase: '@supabase/supabase-js' in deps || '@supabase/ssr' in deps || has(/^supabase\//),
    firebase: 'firebase' in deps || firebase !== null || has(/^(?:firestore|storage)\.rules$|^database\.rules\.json$/),
  };
  const frontend = stack.next || stack.vite || stack.cra || stack.expo || stack.react || 'vue' in deps || 'svelte' in deps || fileSet.has('index.html');
  const viteConfig = files.find((f) => /^vite\.config\.[cm]?[jt]s$/.test(f));
  const publicPrefixes = [...new Set([...PUBLIC_PREFIXES, ...vitePrefixes(viteConfig && read(viteConfig))])];
  const hosting = hostingDirs(firebase);

  const locate = (rel) => {
    if (isEnvFile(rel)) return 'env';
    if (BUILD_OUTPUT.test(rel) || hosting.some((d) => rel.startsWith(`${d}/`))) return 'browser';
    if (SERVER_CODE.test(rel)) return 'server';
    if (BUILD_CONFIG.test(rel)) return 'mixed';
    if (/^[^/]+\.html?$/.test(rel)) return 'browser';
    if (!frontend || !CLIENT_SOURCE.test(rel)) return 'repo';
    if (!stack.next) return 'browser';
    if (NEXT_SERVER_FILE.test(rel)) return 'server';
    return USE_CLIENT.test(read(rel) ?? '') ? 'browser' : 'mixed';
  };

  return { root, files, has: (rel) => fileSet.has(rel), read, locate, stack, firebase, publicPrefixes, problems };
}

export function stackLabel(stack) {
  const app = stack.next ? 'Next.js' : stack.expo ? 'Expo' : stack.cra ? 'Create React App' : stack.vite ? (stack.react ? 'Vite + React' : 'Vite') : stack.react ? 'React' : null;
  return [app, stack.supabase && 'Supabase', stack.firebase && 'Firebase'].filter(Boolean);
}
