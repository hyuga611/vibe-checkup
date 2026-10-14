import { spawnSync } from 'node:child_process';
import { readFileSync } from 'node:fs';
import { join } from 'node:path';
import { isEnvFile, isExampleEnv } from './project.mjs';
import { PLACEHOLDER, findKeys, parseEnv } from './secrets.mjs';

function trackedFiles(root) {
  const run = spawnSync('git', ['ls-files', '-z'], { cwd: root, encoding: 'utf8', windowsHide: true });
  if (run.error || run.status !== 0) return null;
  return run.stdout.split('\0').filter(Boolean);
}

// A committed .env stays in the history even after it is deleted, so it is reported on its own.
export function scanGit(project) {
  const tracked = trackedFiles(project.root);
  if (!tracked) return { findings: [], checked: false };
  const findings = [];
  for (const file of tracked.filter((f) => isEnvFile(f) && !isExampleEnv(f))) {
    let text;
    try {
      text = readFileSync(join(project.root, file), 'utf8');
    } catch {
      continue;
    }
    const vars = parseEnv(text);
    const secrets = vars.some((v) => findKeys(v.value).some((k) => k.secret));
    const privateVars = vars.filter((v) => !project.publicPrefixes.some((p) => v.name.startsWith(p)) && !PLACEHOLDER.test(v.value));
    if (!secrets && !privateVars.length) continue;
    findings.push({
      id: 'env-tracked',
      severity: secrets ? 'critical' : 'medium',
      params: { file, secrets, names: privateVars.map((v) => v.name) },
      locations: [{ file }],
    });
  }
  return { findings, checked: true };
}
