#!/usr/bin/env node
/**
 * The Bouncer gauntlet — the headline number, reproducible in one command.
 * Every command in footguns.txt MUST be denied; every command in safe.txt MUST pass.
 * The corpora are public and separate (safe.txt is the anti-homework metric).
 * Run: npm test    (or: node --test test.js)
 */

const { test } = require('node:test');
const assert = require('node:assert');
const fs = require('node:fs');
const path = require('node:path');
const { spawnSync } = require('node:child_process');
const { checkCommand } = require('./bouncer.js');

const read = (f) => fs.readFileSync(path.join(__dirname, f), 'utf8')
  .split('\n').map((l) => l.trim()).filter((l) => l && !l.startsWith('#'));

const footguns = read('footguns.txt');
const safe = read('safe.txt');

test(`footguns: all ${footguns.length} are BOUNCED`, () => {
  const slipped = footguns.filter((c) => !checkCommand(c).blocked);
  assert.deepStrictEqual(slipped, [], `\nThese footguns slipped past:\n  ${slipped.join('\n  ')}\n`);
});

test(`safe: 0 false positives across ${safe.length} real commands`, () => {
  const blocked = safe.filter((c) => checkCommand(c).blocked)
    .map((c) => `${c}   ->   [${checkCommand(c).pattern.id}]`);
  assert.deepStrictEqual(blocked, [], `\nFalse positives (real work blocked):\n  ${blocked.join('\n  ')}\n`);
});

test('real hook: a footgun is DENIED via permissionDecision (not a bare exit 2)', () => {
  const res = spawnSync('node', [path.join(__dirname, 'bouncer.js')], {
    input: JSON.stringify({ tool_name: 'Bash', tool_input: { command: 'rm -rf /' } }), encoding: 'utf8',
  });
  assert.strictEqual(JSON.parse(res.stdout.trim()).hookSpecificOutput.permissionDecision, 'deny');
});

test('real hook: a safe command passes silently', () => {
  const res = spawnSync('node', [path.join(__dirname, 'bouncer.js')], {
    input: JSON.stringify({ tool_name: 'Bash', tool_input: { command: 'git status' } }), encoding: 'utf8',
  });
  assert.strictEqual(res.stdout.trim(), '{}');
});

test(`HEADLINE: blocks ${footguns.length}/${footguns.length} footguns, 0 false positives on ${safe.length} safe commands`, () => {
  assert.ok(footguns.length >= 40, 'gauntlet should cover 40+ footguns');
});
