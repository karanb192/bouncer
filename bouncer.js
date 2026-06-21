#!/usr/bin/env node
/**
 * Bouncer — a one-file PreToolUse door-guard for coding agents.
 * Reads every Bash command at the door; the dangerous ones don't get in.
 *
 * Engine extracted from karanb192/claude-code-hooks (block-dangerous-commands.js,
 * 262 passing tests) and extended with database / exfil / device footguns.
 * https://github.com/karanb192/claude-code-hooks
 *
 * Two enforcement modes — same engine, different door:
 *   claude (default) — reads the PreToolUse tool-call JSON on stdin and emits the
 *                      permissionDecision:"deny" contract. Enforced on Claude Code.
 *   exit  (BOUNCER_MODE=exit) — reads the command from argv (or raw stdin) and
 *                      exits 2 to BLOCK / 0 to ALLOW, reason on stderr. Wire this
 *                      as the pre-exec command hook of ANY agent that blocks on a
 *                      non-zero exit.   e.g.  BOUNCER_MODE=exit node bouncer.js "rm -rf ~"
 *
 * Tune:  BOUNCER_LEVEL=critical|high|strict   Disable:  BOUNCER_OFF=1
 *   critical - catastrophic only: rm -rf ~, dd to disk, fork bombs, DROP TABLE
 *   high     - + data loss / secrets / RCE  (default)
 *   strict   - + cautionary: any force push, sudo rm, docker prune
 *
 * Setup (Claude Code) — merge settings.snippet.json into .claude/settings.json:
 *   PreToolUse -> matcher "Bash" -> command "node /abs/path/bouncer.js"
 * Limits: a regex filter, not a sandbox — see KNOWN-BYPASSES.md.
 */

const fs = require('fs');
const path = require('path');

const SAFETY_LEVEL = process.env.BOUNCER_LEVEL || 'high';

const PATTERNS = [
  // ── CRITICAL — catastrophic, unrecoverable ──  [base: claude-code-hooks]
  { level: 'critical', id: 'rm-home',          regex: /\brm\s+(-.+\s+)*["']?~\/?["']?(\s|$|[;&|])/,                              reason: 'rm targeting home directory' },
  { level: 'critical', id: 'rm-home-var',      regex: /\brm\s+(-.+\s+)*["']?\$HOME["']?(\s|$|[;&|])/,                            reason: 'rm targeting $HOME' },
  { level: 'critical', id: 'rm-home-trailing', regex: /\brm\s+.+\s+["']?(~\/?|\$HOME)["']?(\s*$|[;&|])/,                         reason: 'rm with trailing ~/ or $HOME' },
  { level: 'critical', id: 'rm-root',          regex: /\brm\s+(-.+\s+)*\/(\*|\s|$|[;&|])/,                                       reason: 'rm targeting root filesystem' },
  { level: 'critical', id: 'rm-system',        regex: /\brm\s+(-.+\s+)*\/(etc|usr|var|bin|sbin|lib|boot|dev|proc|sys)(\/|\s|$)/, reason: 'rm targeting system directory' },
  { level: 'critical', id: 'rm-cwd',           regex: /\brm\s+(-.+\s+)*(\.\/?|\*|\.\/\*)(\s|$|[;&|])/,                           reason: 'rm deleting current directory contents' },
  { level: 'critical', id: 'dd-disk',          regex: /\bdd\b.+of=\/dev\/(sd[a-z]|nvme|hd[a-z]|vd[a-z]|xvd[a-z])/,               reason: 'dd writing to disk device' },
  { level: 'critical', id: 'mkfs',             regex: /\bmkfs(\.\w+)?\s+\/dev\/(sd[a-z]|nvme|hd[a-z]|vd[a-z])/,                  reason: 'mkfs formatting disk' },
  { level: 'critical', id: 'fork-bomb',        regex: /:\(\)\s*\{.*:\s*\|\s*:.*&/,                                               reason: 'fork bomb detected' },
  // ── CRITICAL — Bouncer additions ──
  { level: 'critical', id: 'db-drop',          regex: /\b(DROP\s+(TABLE|DATABASE|SCHEMA|INDEX)|TRUNCATE\s+(TABLE\s+)?\w+)\b/i,   reason: 'destructive SQL (DROP / TRUNCATE)' },
  { level: 'critical', id: 'wipefs',           regex: /\bwipefs\b[^|;&]*\/dev\//,                                                reason: 'wipefs erasing a device' },
  { level: 'critical', id: 'dev-overwrite',    regex: /(>|of=)\s*\/dev\/(sd|nvme|hd|vd|disk|mmcblk)/i,                           reason: 'writing directly to a disk device' },
  { level: 'critical', id: 'etc-write',        regex: /(>|>>|\btee\b)\s*\/etc\/(passwd|shadow|sudoers|hosts)\b/i,                reason: 'overwriting a protected system file' },

  // ── HIGH — data loss / secrets / RCE ──  [base: claude-code-hooks]
  { level: 'high', id: 'curl-pipe-sh',   regex: /\b(curl|wget)\b.+\|\s*(ba)?sh\b/,                                              reason: 'piping a URL straight to the shell (RCE)' },
  { level: 'high', id: 'git-force-main', regex: /\bgit\s+push\b(?!.+--force-with-lease).+(--force|-f)\b.+\b(main|master)\b/,     reason: 'force push to main/master' },
  { level: 'high', id: 'git-reset-hard', regex: /\bgit\s+reset\s+--hard/,                                                       reason: 'git reset --hard loses uncommitted work' },
  { level: 'high', id: 'git-clean-f',    regex: /\bgit\s+clean\s+(-\w*f|-f)/,                                                   reason: 'git clean -f deletes untracked files' },
  { level: 'high', id: 'chmod-777',      regex: /\bchmod\b.+\b777\b/,                                                           reason: 'chmod 777 is a security risk' },
  { level: 'high', id: 'cat-env',        regex: /\b(cat|less|head|tail|more)\s+\.env\b/,                                        reason: 'reading .env exposes secrets' },
  { level: 'high', id: 'cat-secrets',    regex: /\b(cat|less|head|tail|more)\b.+(credentials|secrets?|\.pem|\.key|id_rsa|id_ed25519)/i, reason: 'reading a secrets file' },
  { level: 'high', id: 'env-dump',       regex: /\b(printenv|^env)\s*([;&|]|$)/,                                                reason: 'env dump may expose secrets' },
  { level: 'high', id: 'echo-secret',    regex: /\becho\b.+\$\w*(SECRET|KEY|TOKEN|PASSWORD|API_|PRIVATE)/i,                     reason: 'echoing a secret variable' },
  { level: 'high', id: 'docker-vol-rm',  regex: /\bdocker\s+volume\s+(rm|prune)/,                                              reason: 'docker volume deletion loses data' },
  { level: 'high', id: 'rm-ssh',         regex: /\brm\b.+\.ssh\/(id_|authorized_keys|known_hosts)/,                            reason: 'deleting SSH keys' },
  // ── HIGH — Bouncer additions ──
  { level: 'high', id: 'db-no-where',    regex: /\b(DELETE\s+FROM|UPDATE\s+\S+\s+SET)\b(?![\s\S]*\bWHERE\b)/i,                  reason: 'unscoped DELETE/UPDATE (no WHERE)' },
  { level: 'high', id: 'redis-flush',    regex: /\bredis-cli\b[^|;&]*\bflush(all|db)\b/i,                                       reason: 'redis flushall/flushdb wipes the store' },
  { level: 'high', id: 'dropdb',         regex: /\bdropdb\b\s+\S/,                                                              reason: 'dropping a database' },
  { level: 'high', id: 'curl-exfil',     regex: /\b(curl|wget)\b[^|;&]*(pastebin\.com|paste\.[a-z]+|transfer\.sh|0x0\.st|termbin\.com|webhook\.site|requestbin|ngrok)/i, reason: 'curl/wget to a paste / exfil host' },
  { level: 'high', id: 'curl-upload',    regex: /\bcurl\b[^|;&]*(-d\s*@|-T\s+|-F\s+\S*=@|--data[^|;&]*@)[^|;&]*(\.env|id_rsa|id_ed25519|\.pem|\.key|credentials|secrets)/i, reason: 'uploading secrets via curl' },
  { level: 'high', id: 'rm-parent-glob', regex: /\brm\s+(-\S+\s+)*[^|;&]*(\.\.\/|\*)(\s|$|[;&|])/,                             reason: 'rm with parent-traversal or glob target' },
  { level: 'high', id: 'kill-init',      regex: /\bkill\s+-9\s+1\b/,                                                            reason: 'killing PID 1 (init)' },
  { level: 'high', id: 'chown-root',     regex: /\bchown\b[^|;&]*\s\/(\s|$|[;&|])/,                                             reason: 'chown on the root filesystem' },
  { level: 'high', id: 'npm-publish',    regex: /\bnpm\s+publish\b/,                                                           reason: 'npm publish is an irreversible release' },

  // ── STRICT — cautionary, context-dependent ──  [base: claude-code-hooks]
  { level: 'strict', id: 'git-force-any',    regex: /\bgit\s+push\b(?!.+--force-with-lease).+(--force|-f)\b/,                   reason: 'force push (use --force-with-lease)' },
  { level: 'strict', id: 'git-checkout-dot', regex: /\bgit\s+checkout\s+\./,                                                   reason: 'git checkout . discards changes' },
  { level: 'strict', id: 'sudo-rm',          regex: /\bsudo\s+rm\b/,                                                           reason: 'sudo rm has elevated privileges' },
  { level: 'strict', id: 'docker-prune',     regex: /\bdocker\s+(system|image)\s+prune/,                                       reason: 'docker prune removes images' },
  { level: 'strict', id: 'crontab-r',        regex: /\bcrontab\s+-r/,                                                          reason: 'crontab -r removes all cron jobs' },
];

const LEVELS = { critical: 1, high: 2, strict: 3 };
const EMOJIS = { critical: '🚨', high: '⛔', strict: '⚠️' };
const LOG_DIR = path.join(process.env.HOME || '.', '.claude', 'hooks-logs');

function log(data) {
  try {
    if (!fs.existsSync(LOG_DIR)) fs.mkdirSync(LOG_DIR, { recursive: true });
    const file = path.join(LOG_DIR, `${new Date().toISOString().slice(0, 10)}.jsonl`);
    fs.appendFileSync(file, JSON.stringify({ ts: new Date().toISOString(), hook: 'bouncer', ...data }) + '\n');
  } catch {}
}

function checkCommand(cmd, safetyLevel = SAFETY_LEVEL) {
  const threshold = LEVELS[safetyLevel] || 2;
  for (const p of PATTERNS) {
    if (LEVELS[p.level] <= threshold && p.regex.test(cmd)) {
      return { blocked: true, pattern: p };
    }
  }
  return { blocked: false, pattern: null };
}

// Where's the command coming from? argv (generic CLI) > Claude JSON > raw stdin.
function resolve(stdin) {
  if (process.argv.length > 2) return { cmd: process.argv.slice(2).join(' '), ctx: {} };
  if (!stdin) return { cmd: '', ctx: {} };
  try {
    const d = JSON.parse(stdin);                         // tool-call JSON
    // GitHub Copilot CLI preToolUse: camelCase {toolName, toolArgs}. toolArgs may
    // be an object OR a stringified JSON (double-encoded), so parse it again if so.
    if (d.toolName) {
      const shellTools = ['bash', 'shell', 'powershell'];
      if (!shellTools.includes(String(d.toolName).toLowerCase())) return { skip: true };
      let args = d.toolArgs;
      if (typeof args === 'string') { try { args = JSON.parse(args); } catch {} }
      return { cmd: (args && args.command) || '',
               ctx: { session_id: d.sessionId, cwd: d.cwd } };
    }
    if (d.tool_name && d.tool_name !== 'Bash') return { skip: true };   // Claude Code
    return { cmd: (d.tool_input && d.tool_input.command) || '',
             ctx: { session_id: d.session_id, cwd: d.cwd, permission_mode: d.permission_mode } };
  } catch {
    return { cmd: stdin.trim(), ctx: {} };               // raw command piped on stdin
  }
}

function allow(mode) {
  if (mode === 'exit') return process.exit(0);
  console.log('{}');
}

function deny(mode, p) {
  const msg = `${EMOJIS[p.level]} Bouncer: name's not on the list — [${p.id}] ${p.reason}`;
  if (mode === 'exit') { process.stderr.write(msg + '\n'); return process.exit(2); }
  console.log(JSON.stringify({
    hookSpecificOutput: { hookEventName: 'PreToolUse', permissionDecision: 'deny', permissionDecisionReason: msg },
  }));
}

async function main() {
  const mode = process.env.BOUNCER_MODE || 'claude';
  if (process.env.BOUNCER_OFF) return allow(mode);

  let input = '';
  if (process.argv.length <= 2) { for await (const chunk of process.stdin) input += chunk; }

  try {
    const r = resolve(input);
    if (r.skip) return allow(mode);
    const result = checkCommand(r.cmd);
    if (result.blocked) {
      const p = result.pattern;
      log({ level: 'BLOCKED', id: p.id, priority: p.level, cmd: r.cmd, ...r.ctx });
      return deny(mode, p);
    }
    allow(mode);
  } catch (e) {
    log({ level: 'ERROR', error: e.message });
    allow(mode);
  }
}

if (require.main === module) {
  main();
} else {
  module.exports = { PATTERNS, LEVELS, SAFETY_LEVEL, checkCommand };
}
