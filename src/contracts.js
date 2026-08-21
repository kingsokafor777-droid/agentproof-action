'use strict';

const crypto = require('node:crypto');

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
