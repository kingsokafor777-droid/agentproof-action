'use strict';

const assert = require('node:assert/strict');
const fs = require('node:fs');
const os = require('node:os');
const path = require('node:path');
const test = require('node:test');

const { commentPullRequest, runAction } = require('../src/index');

function mockCore(inputs) {
  const outputs = new Map();
  const failures = [];
  return {
    outputs,
    failures,
    getInput(name, options = {}) {
      if (options.required && !inputs[name]) throw new Error(`missing ${name}`);
      return inputs[name] || '';
    },
    setOutput(name, value) {
      outputs.set(name, value);
    },
    setFailed(message) {
      failures.push(message);
    },
    summary: {
      addRaw() {
        return this;
      },
      async write() {}
    }
  };
}

function workspace() {
  const root = fs.mkdtempSync(path.join(os.tmpdir(), 'agentproof-action-'));
  fs.copyFileSync(
    path.join(__dirname, '../fixtures/policy-result.fail.json'),
    path.join(root, 'result.json')
  );
  fs.copyFileSync(
    path.join(__dirname, '../fixtures/baseline.existing.json'),
    path.join(root, 'baseline.json')
  );
  return root;
}

function unusedGitHub() {
  return {
    client() {
      throw new Error('not used');
    }
  };
}

test('writes deterministic local artifacts and preserves a baseline-existing finding', async () => {
  const root = workspace();
  const core = mockCore({
    'policy-result': 'result.json',
    baseline: 'baseline.json',
    'output-dir': 'evidence',
    'fail-on': 'new',
    'comment-pr': 'false'
  });
  const outcome = await runAction({
    core,
    github: unusedGitHub(),
    env: { GITHUB_WORKSPACE: root }
  });
  assert.equal(outcome.gatePassed, true);
  assert.equal(core.outputs.get('existing-findings'), '1');
  assert.equal(core.failures.length, 0);
  assert.equal(fs.existsSync(path.join(root, 'evidence/agentproof.sarif')), true);
  assert.doesNotMatch(
    fs.readFileSync(path.join(root, 'evidence/agentproof.evidence.json'), 'utf8'),
    /Synthetic fixture prose/
  );
});

test('fails a new-finding gate and rejects workspace traversal without writing artifacts', async () => {
  const root = workspace();
  const core = mockCore({
    'policy-result': 'result.json',
    baseline: '',
    'output-dir': 'evidence',
    'fail-on': 'new',
    'comment-pr': 'false'
  });
  const outcome = await runAction({
    core,
    github: unusedGitHub(),
    env: { GITHUB_WORKSPACE: root }
  });
  assert.equal(outcome.gatePassed, false);
  assert.match(core.failures[0], /gate did not pass/);

  const unsafeCore = mockCore({
    'policy-result': '../result.json',
    baseline: '',
    'output-dir': 'evidence',
    'fail-on': 'new',
    'comment-pr': 'false'
  });
  await runAction({ core: unsafeCore, github: unusedGitHub(), env: { GITHUB_WORKSPACE: root } });
  assert.match(unsafeCore.failures[0], /remain below/);
});

test('refuses fork pull-request commenting before any API request', async () => {
  const root = workspace();
  const eventPath = path.join(root, 'event.json');
  fs.writeFileSync(
    eventPath,
    JSON.stringify({ pull_request: { number: 4, head: { repo: { fork: true } } } })
  );
  await assert.rejects(
    commentPullRequest(
      {
        eventName: 'pull_request',
        eventPath,
        token: 'token',
        repository: 'owner/repo',
        client() {
          throw new Error('not used');
        }
      },
      'body'
    ),
    /refuses forked/
  );
});
