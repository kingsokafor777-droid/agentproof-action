'use strict';

const fs = require('node:fs');
const path = require('node:path');

const MAX_INPUT_BYTES = 1_000_000;

/** @param {string} workspace @param {string} supplied @param {string} label @param {boolean} allowMissing */
function workspacePath(workspace, supplied, label, allowMissing = false) {
  if (typeof supplied !== 'string' || supplied.length === 0 || supplied.length > 512) {
    throw new Error(`${label} must be a bounded workspace-relative path.`);
  }
  const root = fs.realpathSync(workspace);
  const candidate = path.resolve(root, supplied);
  if (
    path.relative(root, candidate).startsWith(`..${path.sep}`) ||
    path.relative(root, candidate) === '..'
  ) {
    throw new Error(`${label} must remain below GITHUB_WORKSPACE.`);
  }
  if (allowMissing) return candidate;
  let resolved;
  try {
    resolved = fs.realpathSync(candidate);
  } catch {
    throw new Error(`${label} must be an existing local file.`);
  }
  if (
    path.relative(root, resolved).startsWith(`..${path.sep}`) ||
    path.relative(root, resolved) === '..'
  ) {
    throw new Error(`${label} must remain below GITHUB_WORKSPACE after symlink resolution.`);
  }
  if (!fs.statSync(resolved).isFile()) throw new Error(`${label} must be a regular file.`);
  return resolved;
}

/** @param {string} file @param {string} label */
function readJson(file, label) {
  if (fs.statSync(file).size > MAX_INPUT_BYTES)
    throw new Error(`${label} exceeds ${MAX_INPUT_BYTES} bytes.`);
  let text;
  try {
    text = fs.readFileSync(file, 'utf8');
  } catch {
    throw new Error(`${label} must be readable UTF-8 text.`);
  }
  try {
    return JSON.parse(text);
  } catch {
    throw new Error(`${label} must contain JSON.`);
  }
}

/** @param {string} workspace @param {string} supplied */
function outputDirectory(workspace, supplied) {
  const directory = workspacePath(workspace, supplied, 'output-dir', true);
  fs.mkdirSync(directory, { recursive: true });
  const root = fs.realpathSync(workspace);
  const resolved = fs.realpathSync(directory);
  if (
    path.relative(root, resolved).startsWith(`..${path.sep}`) ||
    path.relative(root, resolved) === '..'
  ) {
    throw new Error('output-dir must remain below GITHUB_WORKSPACE after symlink resolution.');
  }
  return resolved;
}

/** @param {string} workspace @param {string} directory @param {string} name @param {string} content */
function writeOutput(workspace, directory, name, content) {
  const target = path.join(directory, name);
  fs.writeFileSync(target, content, { encoding: 'utf8', mode: 0o600 });
  const relative = path.relative(fs.realpathSync(workspace), target).split(path.sep).join('/');
  if (relative.startsWith('../') || relative === '..')
    throw new Error('Output escaped GITHUB_WORKSPACE.');
  return relative;
}

module.exports = { outputDirectory, readJson, workspacePath, writeOutput };
