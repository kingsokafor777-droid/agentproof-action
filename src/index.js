'use strict';

const { createCore } = require('./actions-runtime');
const { parseBaseline, parsePolicyResult } = require('./contracts');
const { createGitHubClient } = require('./github-client');
const { outputDirectory, readJson, workspacePath, writeOutput } = require('./io');
const { classify, evidence, gate, junit, markdown, sarif } = require('./render');

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

if (require.main === module) void runAction();

module.exports = { boolean, commentPullRequest, evaluate, failOn, runAction };
