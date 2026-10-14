import { test } from 'node:test';
import assert from 'node:assert/strict';
import { spawnSync } from 'node:child_process';
import { scanGit } from '../src/git.mjs';
import { loadProject } from '../src/project.mjs';
import { stripeLive, withFiles } from './helpers.mjs';

const git = (root, ...args) => spawnSync('git', args, { cwd: root, encoding: 'utf8', windowsHide: true });
const hasGit = !git('.', '--version').error;

const inRepo = (files, tracked, fn) =>
  withFiles(files, (root) => {
    git(root, 'init', '-q');
    git(root, 'add', '-f', ...tracked);
    return fn(scanGit(loadProject(root)));
  });

test('a tracked .env with a secret is critical; an untracked one is not reported', { skip: !hasGit }, () =>
  inRepo({ '.env': `STRIPE_SECRET_KEY=${stripeLive()}\n`, '.env.local': `STRIPE_SECRET_KEY=${stripeLive()}\n` }, ['.env'], (r) => {
    assert.equal(r.checked, true);
    assert.deepEqual(r.findings.map((f) => [f.id, f.severity, f.params.file]), [['env-tracked', 'critical', '.env']]);
  }));

test('a tracked .env with only public values, or an .env.example, is fine', { skip: !hasGit }, () =>
  inRepo({ '.env': 'VITE_SUPABASE_URL=https://fakeprojectref0000001.supabase.co\n', '.env.example': 'STRIPE_SECRET_KEY=your-key\n' }, ['.env', '.env.example'], (r) => {
    assert.deepEqual(r.findings, []);
  }));

test('a tracked .env with private settings but no known key is medium', { skip: !hasGit }, () =>
  inRepo({ '.env': 'ADMIN_PASSWORD=FAKE-not-a-real-password\n' }, ['.env'], (r) => {
    assert.deepEqual(r.findings.map((f) => [f.severity, f.params.names]), [['medium', ['ADMIN_PASSWORD']]]);
  }));

test('outside a git repository the check is skipped', () =>
  withFiles({ '.env': `STRIPE_SECRET_KEY=${stripeLive()}\n` }, (root) => {
    const r = scanGit(loadProject(root));
    assert.equal(r.findings.length, 0);
  }));
