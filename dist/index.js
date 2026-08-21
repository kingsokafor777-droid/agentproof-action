require('./sourcemap-register.js');/******/ (() => { // webpackBootstrap
/******/ 	"use strict";
/******/ 	var __webpack_modules__ = ({

/***/ 791:
/***/ ((module, __unused_webpack_exports, __nccwpck_require__) => {



const fs = __nccwpck_require__(24);

/** @param {NodeJS.ProcessEnv} env */
function createCore(env) {
  let summary = '';
  return {
    /** @param {string} name @param {{required?: boolean}} [options] */
    getInput(name, options = {}) {
      const key = `INPUT_${name.replace(/ /g, '_').toUpperCase()}`;
      const value = (env[key] || '').trim();
      if (options.required && !value) throw new Error(`Input required and not supplied: ${name}.`);
      return value;
    },
    /** @param {string} name @param {string | number | boolean} value */
    setOutput(name, value) {
      const line = `${name}=${String(value).replace(/[\r\n]/g, '')}\n`;
      if (env.GITHUB_OUTPUT)
        fs.appendFileSync(env.GITHUB_OUTPUT, line, { encoding: 'utf8', mode: 0o600 });
    },
    /** @param {string} message */
    setFailed(message) {
      process.exitCode = 1;
      process.stderr.write(`::error::${String(message).replace(/[\r\n]/g, ' ')}\n`);
    },
    summary: {
      /** @param {string} markdown */
      addRaw(markdown) {
        summary += String(markdown);
        return this;
      },
      async write() {
        if (env.GITHUB_STEP_SUMMARY) {
          fs.appendFileSync(env.GITHUB_STEP_SUMMARY, summary, { encoding: 'utf8', mode: 0o600 });
        }
      }
    }
  };
}

module.exports = { createCore };


/***/ }),

/***/ 378:
/***/ ((module, __unused_webpack_exports, __nccwpck_require__) => {



const crypto = __nccwpck_require__(598);

const IDENTIFIER = /^[A-Za-z0-9][A-Za-z0-9._:-]{0,127}$/;
const SHA256 = /^[a-f0-9]{64}$/;
const MAX_FINDINGS = 5000;
const SEVERITIES = new Set(['critical', 'high', 'medium', 'low', 'info']);
const DECISIONS = new Set(['pass', 'fail', 'error', 'not_applicable']);

/** @param {unknown} value @param {string} label */
function object(value, label) {
  if (value === null || Array.isArray(value) || typeof value !== 'object') {
    throw new Error(`${label} must be an object.`);
  }
  return /** @type {Record<string, unknown>} */ (value);
}

/** @param {Record<string, unknown>} value @param {string[]} allowed @param {string[]} required @param {string} label */
function keys(value, allowed, required, label) {
  for (const key of Object.keys(value)) {
    if (!allowed.includes(key)) throw new Error(`${label} contains unsupported field ${key}.`);
  }
  for (const key of required) {
    if (!(key in value)) throw new Error(`${label} is missing required field ${key}.`);
  }
}

/** @param {unknown} value @param {string} label */
function identifier(value, label) {
  if (typeof value !== 'string' || !IDENTIFIER.test(value)) {
    throw new Error(`${label} must be a stable non-secret identifier.`);
  }
  return value;
}

/** @param {unknown} value @param {string} label */
function string(value, label) {
  if (typeof value !== 'string' || value.trim().length === 0)
    throw new Error(`${label} must be a string.`);
  return value;
}

/** @param {unknown} value @param {string} label */
function timestamp(value, label) {
  const text = string(value, label);
  if (!/(Z|[+-]\d\d:\d\d)$/.test(text) || Number.isNaN(Date.parse(text))) {
    throw new Error(`${label} must be an ISO-8601 timestamp with an explicit UTC offset.`);
  }
  return text;
}

/** @param {unknown} value @param {string} label */
function eventIds(value, label) {
  if (!Array.isArray(value) || value.length === 0 || value.length > 128) {
    throw new Error(`${label} must be a bounded non-empty event identifier array.`);
  }
  const ids = value.map((item) => identifier(item, `${label} value`));
  if (new Set(ids).size !== ids.length) throw new Error(`${label} may not contain duplicates.`);
  return ids;
}

/** @param {unknown} value */
function parsePolicyResult(value) {
  const result = object(value, 'policy result');
  keys(
    result,
    [
      'schema_version',
      'trace_id',
      'trace_fingerprint',
      'policy',
      'decision',
      'evaluated_at',
      'findings',
      'error_code',
      'summary'
    ],
    [
      'schema_version',
      'trace_id',
      'trace_fingerprint',
      'policy',
      'decision',
      'evaluated_at',
      'findings'
    ],
    'policy result'
  );
  if (result.schema_version !== '1.0') throw new Error('policy result schema_version must be 1.0.');
  const traceId = identifier(result.trace_id, 'policy result trace_id');
  if (typeof result.trace_fingerprint !== 'string' || !SHA256.test(result.trace_fingerprint)) {
    throw new Error('policy result trace_fingerprint must be a lower-case SHA-256 digest.');
  }
  const policy = object(result.policy, 'policy result policy');
  keys(policy, ['policy_id', 'version'], ['policy_id', 'version'], 'policy result policy');
  const policyId = identifier(policy.policy_id, 'policy result policy_id');
  const policyVersion = string(policy.version, 'policy result policy version');
  const decisionValue = string(result.decision, 'policy result decision');
  if (!DECISIONS.has(decisionValue)) throw new Error('policy result decision is unsupported.');
  const decision = /** @type {'pass'|'fail'|'error'|'not_applicable'} */ (decisionValue);
  const evaluatedAt = timestamp(result.evaluated_at, 'policy result evaluated_at');
  if (!Array.isArray(result.findings) || result.findings.length > MAX_FINDINGS) {
    throw new Error(`policy result findings must be an array of at most ${MAX_FINDINGS}.`);
  }
  const findings = result.findings.map((finding, index) =>
    parseFinding(finding, index, traceId, policyId, policyVersion)
  );
  if (decision === 'fail' && findings.length === 0)
    throw new Error('A fail result requires findings.');
  if ((decision === 'pass' || decision === 'not_applicable') && findings.length !== 0) {
    throw new Error('Pass and not_applicable results may not contain findings.');
  }
  if (decision === 'error' && typeof result.error_code !== 'string') {
    throw new Error('An error result requires error_code.');
  }
  if (decision !== 'error' && result.error_code != null) {
    throw new Error('error_code is allowed only for an error result.');
  }
  return {
    traceId,
    traceFingerprint: result.trace_fingerprint,
    policyId,
    policyVersion,
    decision,
    evaluatedAt,
    findings
  };
}

/** @param {unknown} value @param {number} index @param {string} traceId @param {string} policyId @param {string} policyVersion */
function parseFinding(value, index, traceId, policyId, policyVersion) {
  const finding = object(value, `finding ${index}`);
  keys(
    finding,
    [
      'schema_version',
      'finding_id',
      'evidence_id',
      'trace_id',
      'policy',
      'rule_id',
      'severity',
      'title',
      'description',
      'event_ids',
      'remediation'
    ],
    [
      'schema_version',
      'finding_id',
      'evidence_id',
      'trace_id',
      'policy',
      'rule_id',
      'severity',
      'title',
      'description',
      'event_ids'
    ],
    `finding ${index}`
  );
  if (finding.schema_version !== '1.0')
    throw new Error(`finding ${index} schema_version must be 1.0.`);
  const policy = object(finding.policy, `finding ${index} policy`);
  keys(policy, ['policy_id', 'version'], ['policy_id', 'version'], `finding ${index} policy`);
  if (
    finding.trace_id !== traceId ||
    policy.policy_id !== policyId ||
    policy.version !== policyVersion
  ) {
    throw new Error(`finding ${index} must match the result trace and policy identity.`);
  }
  const findingId = identifier(finding.finding_id, `finding ${index} finding_id`);
  const evidenceId = identifier(finding.evidence_id, `finding ${index} evidence_id`);
  const ruleId = identifier(finding.rule_id, `finding ${index} rule_id`);
  const severityValue = string(finding.severity, `finding ${index} severity`);
  if (!SEVERITIES.has(severityValue)) throw new Error(`finding ${index} severity is unsupported.`);
  return {
    findingId,
    evidenceId,
    ruleId,
    severity: /** @type {'critical'|'high'|'medium'|'low'|'info'} */ (severityValue),
    title: string(finding.title, `finding ${index} title`),
    eventIds: eventIds(finding.event_ids, `finding ${index} event_ids`)
  };
}

/** @param {unknown} value */
function parseBaseline(value) {
  const baseline = object(value, 'baseline');
  keys(
    baseline,
    ['schema_version', 'kind', 'findings'],
    ['schema_version', 'kind', 'findings'],
    'baseline'
  );
  if (baseline.schema_version !== '1.0' || baseline.kind !== 'agentproof-action-baseline') {
    throw new Error('baseline must use schema_version 1.0 and kind agentproof-action-baseline.');
  }
  if (!Array.isArray(baseline.findings) || baseline.findings.length > MAX_FINDINGS) {
    throw new Error(`baseline findings must be an array of at most ${MAX_FINDINGS}.`);
  }
  const findings = baseline.findings.map((item, index) => {
    const finding = object(item, `baseline finding ${index}`);
    keys(
      finding,
      ['finding_id', 'evidence_id', 'rule_id', 'severity', 'event_ids'],
      ['finding_id', 'evidence_id', 'rule_id', 'severity', 'event_ids'],
      `baseline finding ${index}`
    );
    const severityValue = string(finding.severity, `baseline finding ${index} severity`);
    if (!SEVERITIES.has(severityValue))
      throw new Error(`baseline finding ${index} severity is unsupported.`);
    return {
      findingId: identifier(finding.finding_id, `baseline finding ${index} finding_id`),
      evidenceId: identifier(finding.evidence_id, `baseline finding ${index} evidence_id`),
      ruleId: identifier(finding.rule_id, `baseline finding ${index} rule_id`),
      severity: /** @type {'critical'|'high'|'medium'|'low'|'info'} */ (severityValue),
      eventIds: eventIds(finding.event_ids, `baseline finding ${index} event_ids`)
    };
  });
  const ids = findings.map((finding) => finding.findingId);
  if (new Set(ids).size !== ids.length)
    throw new Error('baseline may not contain duplicate finding_id values.');
  return findings;
}

/** @param {{findingId:string,evidenceId:string,ruleId:string,severity:string,eventIds:string[]}} finding */
function identity(finding) {
  return JSON.stringify([
    finding.findingId,
    finding.evidenceId,
    finding.ruleId,
    finding.severity,
    finding.eventIds
  ]);
}

/** @param {unknown} value */
function stableJson(value) {
  return JSON.stringify(value, Object.keys(/** @type {object} */ (value)).sort(), 0);
}

/** @param {unknown} value */
function sha256(value) {
  return crypto
    .createHash('sha256')
    .update(typeof value === 'string' ? value : stableJson(value))
    .digest('hex');
}

module.exports = { identity, parseBaseline, parsePolicyResult, sha256 };


/***/ }),

/***/ 416:
/***/ ((module) => {



/** @param {string} token */
function createGitHubClient(token) {
  if (!token) throw new Error('github-token is required when comment-pr is true.');
  /** @param {string} method @param {string} endpoint @param {object} [body] */
  async function request(method, endpoint, body = undefined) {
    const response = await fetch(`https://api.github.com${endpoint}`, {
      method,
      headers: {
        accept: 'application/vnd.github+json',
        authorization: `Bearer ${token}`,
        'content-type': 'application/json',
        'x-github-api-version': '2022-11-28'
      },
      body: body ? JSON.stringify(body) : undefined
    });
    if (!response.ok)
      throw new Error(`GitHub PR evidence request failed with HTTP ${response.status}.`);
    return response.status === 204 ? null : response.json();
  }
  return {
    /** @param {string} owner @param {string} repo @param {number} issueNumber */
    listComments(owner, repo, issueNumber) {
      return request(
        'GET',
        `/repos/${encodeURIComponent(owner)}/${encodeURIComponent(repo)}/issues/${issueNumber}/comments?per_page=100`
      );
    },
    /** @param {string} owner @param {string} repo @param {number} commentId @param {string} body */
    updateComment(owner, repo, commentId, body) {
      return request(
        'PATCH',
        `/repos/${encodeURIComponent(owner)}/${encodeURIComponent(repo)}/issues/comments/${commentId}`,
        { body }
      );
    },
    /** @param {string} owner @param {string} repo @param {number} issueNumber @param {string} body */
    createComment(owner, repo, issueNumber, body) {
      return request(
        'POST',
        `/repos/${encodeURIComponent(owner)}/${encodeURIComponent(repo)}/issues/${issueNumber}/comments`,
        { body }
      );
    }
  };
}

module.exports = { createGitHubClient };


/***/ }),

/***/ 105:
/***/ ((module, __unused_webpack_exports, __nccwpck_require__) => {



const { createCore } = __nccwpck_require__(791);
const { parseBaseline, parsePolicyResult } = __nccwpck_require__(378);
const { createGitHubClient } = __nccwpck_require__(416);
const { outputDirectory, readJson, workspacePath, writeOutput } = __nccwpck_require__(597);
const { classify, evidence, gate, junit, markdown, sarif } = __nccwpck_require__(121);

/** @param {string} value */
function failOn(value) {
  if (!['none', 'new', 'all'].includes(value))
    throw new Error('fail-on must be none, new, or all.');
  return /** @type {'none'|'new'|'all'} */ (value);
}

/** @param {string} value */
function boolean(value) {
  if (value === 'true') return true;
  if (value === 'false') return false;
  throw new Error('comment-pr must be true or false.');
}

/** @param {ReturnType<typeof parsePolicyResult>} policyResult @param {ReturnType<typeof parseBaseline>} baseline @param {'none'|'new'|'all'} mode */
function evaluate(policyResult, baseline, mode) {
  const findings = classify(policyResult, baseline);
  const result = { ...policyResult, findings };
  const gatePassed = gate(findings, policyResult.decision, mode);
  return {
    result,
    gatePassed,
    newCount: findings.filter((finding) => finding.baselineState === 'new').length,
    existingCount: findings.filter((finding) => finding.baselineState === 'existing').length
  };
}

/** @param {{eventName:string, eventPath:string|undefined, token:string, repository:string, client: typeof createGitHubClient}} options @param {string} body */
async function commentPullRequest(options, body) {
  if (!options.eventPath || options.eventName !== 'pull_request') {
    throw new Error('PR commenting requires the unprivileged pull_request event.');
  }
  const event = readJson(options.eventPath, 'GitHub event payload');
  const pr = /** @type {any} */ (event).pull_request;
  if (!pr || pr.head?.repo?.fork !== false || !Number.isInteger(pr.number)) {
    throw new Error('PR commenting refuses forked or malformed pull-request contexts.');
  }
  if (!options.token) throw new Error('github-token is required when comment-pr is true.');
  const [owner, repo] = options.repository.split('/');
  if (!owner || !repo) throw new Error('GITHUB_REPOSITORY must be owner/repo for PR commenting.');
  const api = options.client(options.token);
  const comments = await api.listComments(owner, repo, pr.number);
  if (!Array.isArray(comments))
    throw new Error('GitHub PR evidence response must be a comment array.');
  const existing = comments.find((comment) =>
    comment.body?.includes('<!-- agentproof-action-evidence -->')
  );
  if (existing) {
    await api.updateComment(owner, repo, existing.id, body);
  } else {
    await api.createComment(owner, repo, pr.number, body);
  }
}

/** @param {{core: ReturnType<typeof createCore>, github: {client: typeof createGitHubClient}, env: NodeJS.ProcessEnv}} dependencies */
async function runAction(
  dependencies = {
    core: createCore(process.env),
    github: { client: createGitHubClient },
    env: process.env
  }
) {
  const actionCore = dependencies.core;
  try {
    const workspace = dependencies.env.GITHUB_WORKSPACE;
    if (!workspace) throw new Error('GITHUB_WORKSPACE is required.');
    const policyFile = workspacePath(
      workspace,
      actionCore.getInput('policy-result', { required: true }),
      'policy-result'
    );
    const baselineInput = actionCore.getInput('baseline').trim();
    const baseline = baselineInput
      ? parseBaseline(readJson(workspacePath(workspace, baselineInput, 'baseline'), 'baseline'))
      : [];
    const policyResult = parsePolicyResult(readJson(policyFile, 'policy-result'));
    const outputDir = outputDirectory(workspace, actionCore.getInput('output-dir'));
    const outcome = evaluate(policyResult, baseline, failOn(actionCore.getInput('fail-on')));
    const reviewMarkdown = markdown(outcome.result, outcome.gatePassed);
    const sarifFile = writeOutput(
      workspace,
      outputDir,
      'agentproof.sarif',
      `${JSON.stringify(sarif(outcome.result), null, 2)}\n`
    );
    const junitFile = writeOutput(
      workspace,
      outputDir,
      'agentproof.junit.xml',
      junit(outcome.result)
    );
    const evidenceFile = writeOutput(
      workspace,
      outputDir,
      'agentproof.evidence.json',
      `${JSON.stringify(evidence(outcome.result, outcome.gatePassed), null, 2)}\n`
    );
    writeOutput(workspace, outputDir, 'agentproof.pr.md', reviewMarkdown);
    actionCore.setOutput('decision', policyResult.decision);
    actionCore.setOutput('gate-passed', String(outcome.gatePassed));
    actionCore.setOutput('new-findings', String(outcome.newCount));
    actionCore.setOutput('existing-findings', String(outcome.existingCount));
    actionCore.setOutput('sarif-file', sarifFile);
    actionCore.setOutput('junit-file', junitFile);
    actionCore.setOutput('evidence-file', evidenceFile);
    await actionCore.summary.addRaw(reviewMarkdown).write();
    if (boolean(actionCore.getInput('comment-pr'))) {
      await commentPullRequest(
        {
          eventName: dependencies.env.GITHUB_EVENT_NAME || '',
          eventPath: dependencies.env.GITHUB_EVENT_PATH,
          token: actionCore.getInput('github-token'),
          repository: dependencies.env.GITHUB_REPOSITORY || '',
          client: dependencies.github.client
        },
        reviewMarkdown
      );
    }
    if (!outcome.gatePassed) actionCore.setFailed('AgentProof evidence gate did not pass.');
    return outcome;
  } catch (error) {
    actionCore.setFailed(error instanceof Error ? error.message : 'AgentProof Action failed.');
    return null;
  }
}

if (require.main === require.cache[eval('__filename')]) void runAction();

module.exports = { boolean, commentPullRequest, evaluate, failOn, runAction };


/***/ }),

/***/ 597:
/***/ ((module, __unused_webpack_exports, __nccwpck_require__) => {



const fs = __nccwpck_require__(24);
const path = __nccwpck_require__(760);

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


/***/ }),

/***/ 121:
/***/ ((module, __unused_webpack_exports, __nccwpck_require__) => {



const { identity, sha256 } = __nccwpck_require__(378);

/** @type {Record<string, string>} */
const SARIF_LEVEL = {
  critical: 'error',
  high: 'error',
  medium: 'warning',
  low: 'note',
  info: 'note'
};

/** @param {string} text */
function xml(text) {
  return text.replace(/[<>&"']/g, (character) => {
    if (character === '<') return '&lt;';
    if (character === '>') return '&gt;';
    if (character === '&') return '&amp;';
    if (character === '"') return '&quot;';
    return '&apos;';
  });
}

/** @param {{findings: Array<{findingId:string,evidenceId:string,ruleId:string,severity:string,eventIds:string[]}>, decision:string, policyId:string, policyVersion:string, traceId:string, traceFingerprint:string}} result @param {Array<{findingId:string,evidenceId:string,ruleId:string,severity:string,eventIds:string[]}>} baseline */
function classify(result, baseline) {
  const baselineIdentities = new Set(baseline.map(identity));
  return result.findings.map((finding) => ({
    ...finding,
    baselineState: baselineIdentities.has(identity(finding)) ? 'existing' : 'new'
  }));
}

/** @param {Array<{baselineState:string}>} findings @param {string} decision @param {'none'|'new'|'all'} failOn */
function gate(findings, decision, failOn) {
  if (decision === 'error') return false;
  if (failOn === 'none') return true;
  if (failOn === 'all') return findings.length === 0;
  return findings.every((finding) => finding.baselineState === 'existing');
}

/** @param {{findings:Array<{ruleId:string,evidenceId:string,severity:string,eventIds:string[]}>, policyId:string, policyVersion:string, traceId:string}} result */
function sarif(result) {
  const ruleIds = [...new Set(result.findings.map((finding) => finding.ruleId))];
  return {
    version: '2.1.0',
    $schema: 'https://json.schemastore.org/sarif-2.1.0.json',
    runs: [
      {
        tool: {
          driver: {
            name: 'AgentProof',
            version: '0.1.0',
            informationUri: 'https://github.com/kingsokafor777-droid/agentproof-action',
            rules: ruleIds.map((id) => ({
              id,
              name: id,
              shortDescription: { text: `AgentProof policy rule ${id}` }
            }))
          }
        },
        automationDetails: { id: `agentproof/${result.policyId}/${result.policyVersion}` },
        results: result.findings.map((finding) => ({
          ruleId: finding.ruleId,
          level: SARIF_LEVEL[finding.severity] || 'warning',
          message: { text: `AgentProof policy evidence: ${finding.ruleId}` },
          partialFingerprints: { agentproofEvidenceId: finding.evidenceId },
          properties: {
            agentproofTraceId: result.traceId,
            agentproofSeverity: finding.severity,
            agentproofEventIds: finding.eventIds
          }
        }))
      }
    ]
  };
}

/** @param {{decision:string, policyId:string, policyVersion:string, findings:Array<{ruleId:string,severity:string,baselineState:string}>}} result */
function junit(result) {
  const tests =
    result.findings.length === 0
      ? [{ ruleId: result.policyId, severity: 'info', baselineState: 'existing' }]
      : result.findings;
  const failures = result.findings.length;
  const cases = tests
    .map((finding) => {
      const name = `agentproof:${result.policyId}:${finding.ruleId}`;
      if (result.findings.length === 0)
        return `<testcase classname="agentproof.policy" name="${xml(name)}"/>`;
      const message = `severity=${finding.severity}; baseline=${finding.baselineState}`;
      return `<testcase classname="agentproof.policy" name="${xml(name)}"><failure type="AgentProofFinding" message="${xml(message)}"/></testcase>`;
    })
    .join('');
  return `<?xml version="1.0" encoding="UTF-8"?><testsuite name="agentproof" tests="${tests.length}" failures="${failures}" errors="${result.decision === 'error' ? 1 : 0}">${cases}</testsuite>\n`;
}

/** @param {{decision:string, policyId:string, policyVersion:string, traceId:string, traceFingerprint:string, findings:Array<{findingId:string,evidenceId:string,ruleId:string,severity:string,eventIds:string[],baselineState:string}>} } result @param {boolean} gatePassed */
function evidence(result, gatePassed) {
  const findings = result.findings.map((finding) => ({
    finding_id: finding.findingId,
    evidence_id: finding.evidenceId,
    rule_id: finding.ruleId,
    severity: finding.severity,
    event_ids: finding.eventIds,
    baseline_state: finding.baselineState
  }));
  return {
    schema_version: '1.0',
    kind: 'agentproof-action-evidence',
    trace_id: result.traceId,
    trace_fingerprint: result.traceFingerprint,
    policy: { policy_id: result.policyId, version: result.policyVersion },
    decision: result.decision,
    gate_passed: gatePassed,
    findings,
    evidence_fingerprint: sha256(findings)
  };
}

/** @param {{decision:string, policyId:string, policyVersion:string, findings:Array<{baselineState:string}>}} result @param {boolean} gatePassed */
function markdown(result, gatePassed) {
  const newCount = result.findings.filter((finding) => finding.baselineState === 'new').length;
  const existingCount = result.findings.length - newCount;
  return [
    '<!-- agentproof-action-evidence -->',
    '## AgentProof evidence',
    '',
    `| Field | Value |`,
    `|---|---|`,
    `| Policy | \`${result.policyId}@${result.policyVersion}\` |`,
    `| Decision | \`${result.decision}\` |`,
    `| Gate | ${gatePassed ? 'passed' : 'failed'} |`,
    `| New findings | ${newCount} |`,
    `| Existing findings | ${existingCount} |`,
    '',
    '_Evidence is derived from the validated local AgentProof policy result. No raw trace payload is included._',
    ''
  ].join('\n');
}

module.exports = { classify, evidence, gate, junit, markdown, sarif };


/***/ }),

/***/ 598:
/***/ ((module) => {

module.exports = require("node:crypto");

/***/ }),

/***/ 24:
/***/ ((module) => {

module.exports = require("node:fs");

/***/ }),

/***/ 760:
/***/ ((module) => {

module.exports = require("node:path");

/***/ })

/******/ 	});
/************************************************************************/
/******/ 	// The module cache
/******/ 	var __webpack_module_cache__ = {};
/******/ 	
/******/ 	// The require function
/******/ 	function __nccwpck_require__(moduleId) {
/******/ 		// Check if module is in cache
/******/ 		var cachedModule = __webpack_module_cache__[moduleId];
/******/ 		if (cachedModule !== undefined) {
/******/ 			return cachedModule.exports;
/******/ 		}
/******/ 		// Create a new module (and put it into the cache)
/******/ 		var module = __webpack_module_cache__[moduleId] = {
/******/ 			// no module.id needed
/******/ 			// no module.loaded needed
/******/ 			exports: {}
/******/ 		};
/******/ 	
/******/ 		// Execute the module function
/******/ 		var threw = true;
/******/ 		try {
/******/ 			__webpack_modules__[moduleId](module, module.exports, __nccwpck_require__);
/******/ 			threw = false;
/******/ 		} finally {
/******/ 			if(threw) delete __webpack_module_cache__[moduleId];
/******/ 		}
/******/ 	
/******/ 		// Return the exports of the module
/******/ 		return module.exports;
/******/ 	}
/******/ 	
/************************************************************************/
/******/ 	/* webpack/runtime/compat */
/******/ 	
/******/ 	if (typeof __nccwpck_require__ !== 'undefined') __nccwpck_require__.ab = __dirname + "/";
/******/ 	
/************************************************************************/
/******/ 	
/******/ 	// startup
/******/ 	// Load entry module and return exports
/******/ 	// This entry module is referenced by other modules so it can't be inlined
/******/ 	var __webpack_exports__ = __nccwpck_require__(105);
/******/ 	module.exports = __webpack_exports__;
/******/ 	
/******/ })()
;
//# sourceMappingURL=index.js.map