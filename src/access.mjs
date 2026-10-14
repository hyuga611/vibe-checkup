import { splitTop, unwrap } from './text.mjs';

// Who an access condition lets in, from most to least open.
export const EVERYONE = 3;
export const SIGNED_IN = 2;
export const LIMITED = 1;
export const NOBODY = 0;

const earlier = (a, b) => (a === undefined ? b : b === undefined ? a : Math.min(a, b));

function both(a, b) {
  return { level: Math.min(a.level, b.level), until: earlier(a.until, b.until), expired: earlier(a.expired, b.expired) };
}

// The most open `or` branch decides, and inside a branch the most closed `and` part does.
// `atom` recognises conditions that let everyone or every signed-in user through; anything
// it does not recognise is taken as a real restriction.
export function openness(expr, ops) {
  const e = unwrap(expr);
  const branches = splitTop(e, ops.or);
  if (branches.length > 1) {
    return branches.map((b) => openness(b, ops)).reduce((a, b) => (b.level > a.level ? b : a));
  }
  const parts = splitTop(e, ops.and);
  if (parts.length > 1) return parts.map((p) => openness(p, ops)).reduce(both);
  return ops.atom(e) ?? { level: LIMITED };
}

// A test-mode condition such as request.time < timestamp.date(2025, 1, 1).
export const until = (ms, now) => (now < ms ? { level: EVERYONE, until: ms } : { level: NOBODY, expired: ms });
