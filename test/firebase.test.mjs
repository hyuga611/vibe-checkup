import { test } from 'node:test';
import assert from 'node:assert/strict';
import { parseRules, scanFirebase } from '../src/firebase.mjs';
import { inProject } from './helpers.mjs';

const NOW = Date.UTC(2026, 0, 15);
const firestore = (body) => `rules_version = '2';\nservice cloud.firestore {\n  match /databases/{database}/documents {\n${body}\n  }\n}\n`;
const scanRules = (files) => inProject(files, (project) => scanFirebase(project, { now: NOW }));
const summary = (r) => r.findings.map((f) => [f.params.service, f.params.path, f.params.scope, f.params.verbs.join('+'), f.severity]);

test('allow read, write: if true on everything is critical', async () => {
  const r = await scanRules({ 'firestore.rules': firestore('    match /{document=**} {\n      allow read, write: if true;\n    }') });
  assert.deepEqual(summary(r), [['firestore', '/{document=**}', 'everyone', 'read+change+delete', 'critical']]);
  assert.equal(r.findings[0].params.whole, true);
  assert.deepEqual(r.findings[0].locations, [{ file: 'firestore.rules', line: 5 }]);
});

test('test-mode rules are open until their date, then closed', async () => {
  const rule = (date) => firestore(`    match /{document=**} {\n      allow read, write: if request.time < timestamp.date(${date});\n    }`);
  const open = await scanRules({ 'firestore.rules': rule('2026, 2, 14') });
  assert.equal(open.findings[0].severity, 'critical');
  assert.equal(open.findings[0].params.until, '2026-02-14');
  const closed = await scanRules({ 'firestore.rules': rule('2025, 12, 1') });
  assert.deepEqual(closed.findings, []);
  assert.deepEqual(closed.notes.map((n) => [n.id, n.params.date]), [['test-mode-expired', '2025-12-01']]);
});

test('request.auth != null on a users collection lets every signed-in user read everyone', async () => {
  const r = await scanRules({ 'firestore.rules': firestore('    match /users/{userId} {\n      allow read: if request.auth != null;\n      allow write: if request.auth.uid == userId;\n    }') });
  assert.deepEqual(summary(r), [['firestore', '/users/{userId}', 'signed-in', 'read', 'high']]);
});

test('an owner check, including one behind a helper function, is not reported', async () => {
  const r = await scanRules({
    'firestore.rules': firestore(`    function isOwner(uid) { return request.auth != null && request.auth.uid == uid; }
    function signedIn() { return request.auth != null; }
    match /users/{userId} {
      allow read, write: if isOwner(userId);
    }
    match /orders/{orderId} {
      allow read: if signedIn() && resource.data.ownerId == request.auth.uid;
    }`),
  });
  assert.deepEqual(r.findings, []);
});

test('a helper function that only checks sign-in is seen through', async () => {
  const r = await scanRules({ 'firestore.rules': firestore('    function signedIn() { return request.auth != null; }\n    match /messages/{id} {\n      allow read, update: if signedIn();\n    }') });
  assert.deepEqual(summary(r), [['firestore', '/messages/{id}', 'signed-in', 'read+change', 'high']]);
});

test('public reading of a non-personal collection is fine; anyone creating documents is not reported', async () => {
  const r = await scanRules({ 'firestore.rules': firestore('    match /posts/{postId} {\n      allow read: if true;\n      allow create: if true;\n    }') });
  assert.deepEqual(r.findings, []);
  assert.deepEqual(r.ok.map((o) => [o.id, o.params.path]), [['rules-public-read', '/posts/{postId}']]);
});

test('comments and strings do not confuse the parser', () => {
  const rules = parseRules(firestore(`    // allow read, write: if true;
    /* match /x { allow read: if true; } */
    match /notes/{id} {
      allow read: if resource.data.label == "if true; }" && request.auth.uid == resource.data.owner;
    }`));
  assert.equal(rules.length, 1);
  assert.equal(rules[0].path, '/databases/{database}/documents/notes/{id}');
});

test('storage rules: a sensitive folder open to signed-in users is high', async () => {
  const r = await scanRules({
    'storage.rules': "rules_version = '2';\nservice firebase.storage {\n  match /b/{bucket}/o {\n    match /invoices/{file} {\n      allow read: if request.auth != null;\n    }\n    match /images/{file} {\n      allow read: if true;\n    }\n  }\n}\n",
  });
  assert.deepEqual(summary(r), [['storage', '/invoices/{file}', 'signed-in', 'read', 'high']]);
});

test('Realtime Database rules are read from database.rules.json', async () => {
  const r = await scanRules({
    'database.rules.json': { rules: { '.read': 'auth != null', messages: { '.write': true }, users: { $uid: { '.read': '$uid === auth.uid', '.write': '$uid === auth.uid' } } } },
  });
  assert.deepEqual(summary(r), [
    ['database', '/', 'signed-in', 'read', 'high'],
    ['database', '/messages', 'everyone', 'change+delete', 'critical'],
  ]);
});

test('Realtime Database test mode compares now with a timestamp', async () => {
  const r = await scanRules({ 'database.rules.json': { rules: { '.read': `now < ${Date.UTC(2026, 1, 1)}`, '.write': `now < ${Date.UTC(2026, 1, 1)}` } } });
  assert.equal(r.findings[0].severity, 'critical');
  assert.equal(r.findings[0].params.until, '2026-02-01');
});

test('firebase.json can point at rules files elsewhere', async () => {
  const r = await scanRules({
    'firebase.json': { firestore: { rules: 'config/app.rules' } },
    'config/app.rules': firestore('    match /{document=**} {\n      allow read, write: if true;\n    }'),
  });
  assert.equal(r.findings[0].locations[0].file, 'config/app.rules');
});

test('a Firebase project without rules files gets a note', async () => {
  const r = await scanRules({ 'package.json': { dependencies: { firebase: '10' } } });
  assert.deepEqual(r.notes, [{ id: 'no-rules' }]);
});

test('a broken database.rules.json is a problem, not a pass', async () => {
  const r = await scanRules({ 'database.rules.json': '{ "rules": ' });
  assert.equal(r.problems.length, 1);
});
