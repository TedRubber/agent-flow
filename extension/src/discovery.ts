/**
 * Discovery-file-based service discovery for hook forwarding.
 *
 * Each VS Code instance writes a discovery file containing its hook server
 * port and PID. The hook forwarding script reads these at invocation time
 * to find live instances — no port numbers in settings.json, no races.
 *
 * Discovery dir: ~/.claude/agent-flow/
 * Discovery file: {workspace-hash}-{pid}.json
 * Hook script:   ~/.claude/agent-flow/hook.js
 */

import * as fs from 'fs'
import * as path from 'path'
import * as os from 'os'
import * as crypto from 'crypto'
import { HOOK_TIMEOUT_S, HOOK_SAFETY_MARGIN_MS, HOOK_FORWARD_TIMEOUT_MS, WORKSPACE_HASH_LENGTH } from './constants'
import { createLogger } from './logger'

const log = createLogger('Discovery')

const DISCOVERY_DIR = path.join(os.homedir(), '.claude', 'agent-flow')
const HOOK_SCRIPT_PATH = path.join(DISCOVERY_DIR, 'hook.js')
const WORKSPACES_MANIFEST_PATH = path.join(DISCOVERY_DIR, 'workspaces.json')

/** Identifier substring used to detect our command hooks in settings.json */
export const HOOK_COMMAND_MARKER = 'agent-flow/hook.js'

export function getHookCommand(): string { return `node "${HOOK_SCRIPT_PATH}"` }

export function hashWorkspace(workspace: string): string {
  // Normalize path before hashing so Windows and Unix paths hash consistently.
  // Claude Code sends cwd with backslashes and mixed casing on Windows —
  // normalize to lowercase forward-slash paths to ensure the hash matches
  // regardless of whether it comes from the extension or the hook script.
  const normalized = path.resolve(workspace)
    .replace(/\\/g, '/')   // backslashes → forward slashes
    .replace(/\/$/, '')     // remove trailing slash
    .toLowerCase()           // lowercase for case-insensitive matching on Windows
  return crypto.createHash('sha256').update(normalized).digest('hex').slice(0, WORKSPACE_HASH_LENGTH)
}

// ─── Discovery Files ──────────────────────────────────────────────────────────

export function writeDiscoveryFile(port: number, workspace: string): void {
  ensureDir()
  const hash = hashWorkspace(workspace)
  const filePath = path.join(DISCOVERY_DIR, `${hash}-${process.pid}.json`)
  fs.writeFileSync(filePath, JSON.stringify({
    port,
    pid: process.pid,
    workspace: path.resolve(workspace),
  }, null, 2) + '\n')
  log.info(`Wrote ${filePath}`)
}

export function removeDiscoveryFile(workspace: string): void {
  const hash = hashWorkspace(workspace)
  const filePath = path.join(DISCOVERY_DIR, `${hash}-${process.pid}.json`)
  try {
    fs.unlinkSync(filePath)
    log.info(`Removed ${filePath}`)
  } catch { /* expected if file was already removed */ }
}

// ─── Workspace Manifest ──────────────────────────────────────────────────────
// Tracks every workspace where hooks have been written to settings.local.json.
// Survives crashes and discovery-file cleanup — the uninstall script reads this
// to find all project-level settings files that need cleaning.

export function addWorkspaceToManifest(workspace: string): void {
  ensureDir()
  const resolved = path.resolve(workspace)
  const workspaces = readManifest()
  if (workspaces.includes(resolved)) { return }
  workspaces.push(resolved)
  fs.writeFileSync(WORKSPACES_MANIFEST_PATH, JSON.stringify(workspaces, null, 2) + '\n')
}

function readManifest(): string[] {
  try {
    if (!fs.existsSync(WORKSPACES_MANIFEST_PATH)) { return [] }
    const data = JSON.parse(fs.readFileSync(WORKSPACES_MANIFEST_PATH, 'utf-8'))
    return Array.isArray(data) ? data : []
  } catch (err) {
    log.debug('Failed to read workspaces manifest:', err)
    return []
  }
}

// ─── Hook Script ──────────────────────────────────────────────────────────────

export function ensureHookScript(): void {
  ensureDir()
  const script = getHookScriptContent()
  try {
    if (fs.existsSync(HOOK_SCRIPT_PATH) && fs.readFileSync(HOOK_SCRIPT_PATH, 'utf8') === script) {
      return // already up to date
    }
  } catch { /* failed to read existing script — rewrite it */ }
  // Atomic write: write to temp file then rename, so a concurrent
  // `node hook.js` never reads a truncated/empty file during updates.
  const tmpPath = HOOK_SCRIPT_PATH + `.${process.pid}.tmp`
  fs.writeFileSync(tmpPath, script, { mode: 0o755 })
  fs.renameSync(tmpPath, HOOK_SCRIPT_PATH)
  log.info(`Installed hook script → ${HOOK_SCRIPT_PATH}`)
}

// ─── Helpers ──────────────────────────────────────────────────────────────────

function ensureDir(): void {
  if (!fs.existsSync(DISCOVERY_DIR)) {
    fs.mkdirSync(DISCOVERY_DIR, { recursive: true })
  }
}

function getHookScriptContent(): string {
  return `#!/usr/bin/env node
// Agent Flow hook forwarder v2 — installed by the Agent Flow VS Code extension.
// Claude Code invokes this as a command hook. It reads a discovery directory to
// find live extension instances, checks their PIDs, and forwards the event via
// HTTP POST. Dead instances are cleaned up automatically.
//
// Discovery dir: ~/.claude/agent-flow/
// Discovery file: {workspace-hash}-{pid}.json  →  { port, pid, workspace }
'use strict';
const fs = require('fs');
const path = require('path');
const crypto = require('crypto');
const http = require('http');
const os = require('os');

// Hard safety deadline — guarantees exit well before Claude Code's
// ${HOOK_TIMEOUT_S}s kill timeout (500ms margin). Prevents ANY hanging scenario
// (stdin stall, HTTP hang, unexpected blocking) from blocking Claude Code.
setTimeout(() => process.exit(0), ${HOOK_TIMEOUT_S * 1000 - HOOK_SAFETY_MARGIN_MS});

const DIR = path.join(os.homedir(), '.claude', 'agent-flow');

let input = '';
process.stdin.setEncoding('utf8');
process.stdin.on('data', c => { input += c; });
process.stdin.on('end', () => {
  let cwd;
  try { cwd = JSON.parse(input).cwd; } catch { process.exit(0); }
  if (!cwd) process.exit(0);

  const normalized = path.resolve(cwd).replace(/\\\\/g, '/').replace(/\/$/, '').toLowerCase();
  const hash = crypto.createHash('sha256').update(normalized).digest('hex').slice(0, ${WORKSPACE_HASH_LENGTH});

  let files;
  try {
    files = fs.readdirSync(DIR).filter(f => f.startsWith(hash + '-') && f.endsWith('.json'));
  } catch { process.exit(0); }
  if (!files.length) process.exit(0);

  let pending = 0;
  for (const file of files) {
    let d;
    try { d = JSON.parse(fs.readFileSync(path.join(DIR, file), 'utf8')); } catch { continue; }

    // Check PID is alive
    try { process.kill(d.pid, 0); } catch {
      try { fs.unlinkSync(path.join(DIR, file)); } catch {}
      continue;
    }

    pending++;
    let settled = false;
    const finish = () => { if (settled) return; settled = true; done(); };
    const req = http.request({
      hostname: '127.0.0.1', port: d.port, method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      timeout: ${HOOK_FORWARD_TIMEOUT_MS},
    }, res => { res.resume(); res.on('end', finish); });
    req.on('error', finish);
    req.on('timeout', () => { req.destroy(); });
    req.write(input);
    req.end();
  }

  if (!pending) process.exit(0);
  function done() { if (--pending <= 0) process.exit(0); }
});
`
}
