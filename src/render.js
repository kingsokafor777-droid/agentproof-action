'use strict';

const { identity, sha256 } = require('./contracts');

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
