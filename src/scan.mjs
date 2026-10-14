import { scanFirebase } from './firebase.mjs';
import { scanGit } from './git.mjs';
import { scanLive } from './live.mjs';
import { loadProject, stackLabel } from './project.mjs';
import { scanSecrets } from './secrets.mjs';
import { scanSupabase } from './supabase.mjs';

export const SEVERITY_ORDER = ['critical', 'high', 'medium'];

const bySeverity = (a, b) => SEVERITY_ORDER.indexOf(a.severity) - SEVERITY_ORDER.indexOf(b.severity);

export async function scan(root, { live = false, now = Date.now(), git = true } = {}) {
  const project = loadProject(root);
  const secrets = scanSecrets(project);
  const supabase = scanSupabase(project);
  const firebase = scanFirebase(project, { now });
  const repo = git ? scanGit(project) : { findings: [], checked: false };
  const online = live ? await scanLive(secrets.supabase, supabase.tables) : null;

  const notes = [...supabase.notes, ...firebase.notes, ...(online?.notes ?? [])];
  if (!supabase.checked && !firebase.checked && !project.stack.supabase && !project.stack.firebase) notes.push({ id: 'secrets-only' });

  return {
    root,
    stack: stackLabel(project.stack),
    files: project.files.length,
    findings: [...(online?.findings ?? []), ...secrets.findings, ...repo.findings, ...supabase.findings, ...firebase.findings].sort(bySeverity),
    ok: [...secrets.ok, ...supabase.ok, ...firebase.ok],
    notes,
    live: online?.results ?? null,
    problems: [...project.problems, ...firebase.problems],
  };
}
