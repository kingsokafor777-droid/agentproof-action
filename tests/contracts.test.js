'use strict';

const assert = require('node:assert/strict');
const fs = require('node:fs');
const path = require('node:path');
const test = require('node:test');

const { parseBaseline, parsePolicyResult } = require('../src/contracts');
const { classify, evidence, gate, junit, markdown, sarif } = require('../src/render');

const fixture = JSON.parse(
  fs.readFileSync(path.join(__dirname, '../fixtures/policy-result.fail.json'), 'utf8')
);
const baseline = JSON.parse(
  fs.readFileSync(path.join(__dirname, '../fixtures/baseline.existing.json'), 'utf8')
);

test('strictly parses and classifies a Core v1 result against an exact baseline identity', () => {
  const result = parsePolicyResult(fixture);
  const classified = classify(result, parseBaseline(baseline));
  assert.equal(classified[0].baselineState, 'existing');
  assert.equal(gate(classified, result.decision, 'new'), true);
  assert.equal(gate(classified, result.decision, 'all'), false);
});

test('rejects unknown Core fields, invalid decision consistency, and duplicate baseline identities', () => {
  assert.throws(() => parsePolicyResult({ ...fixture, unexpected: true }), /unsupported field/);
  assert.throws(
    () => parsePolicyResult({ ...fixture, decision: 'pass' }),
    /may not contain findings/
  );
  assert.throws(
    () => parseBaseline({ ...baseline, findings: [...baseline.findings, baseline.findings[0]] }),
    /duplicate finding_id/
  );
});

test('renders deterministic minimized SARIF, JUnit, JSON, and PR evidence', () => {
  const result = parsePolicyResult(fixture);
  const findings = classify(result, []);
  const normalized = { ...result, findings };
  const renderedSarif = sarif(normalized);
  const renderedJUnit = junit(normalized);
  const renderedEvidence = evidence(normalized, false);
  const renderedMarkdown = markdown(normalized, false);
  assert.equal(renderedSarif.version, '2.1.0');
  assert.equal(
    renderedSarif.runs[0].results[0].partialFingerprints.agentproofEvidenceId,
    'evidence.restricted.write'
  );
  assert.match(renderedJUnit, /AgentProofFinding/);
  assert.equal(renderedEvidence.findings[0].baseline_state, 'new');
  assert.doesNotMatch(JSON.stringify(renderedEvidence), /Synthetic fixture prose/);
  assert.doesNotMatch(renderedMarkdown, /Synthetic fixture prose/);
});
