# AgentProof Action Architecture

## Purpose and boundary

`agentproof-action` is a Node.js GitHub Action that validates and renders a precomputed,
local AgentProof Core `PolicyResult`. It compares deterministic findings to an optional local
baseline, writes SARIF, JUnit, normalized JSON, and pull-request evidence Markdown, then sets
bounded action outputs. It does **not** execute an agent, tool, policy engine, shell command,
Python package, model, remote scanner, or package installation.

The action intentionally separates evidence production from GitHub presentation. A preceding
unprivileged workflow step must create `policy-result.json`; this action only validates the strict
Core contract and renders evidence. This avoids an arbitrary-command input and keeps the action
safe for regular `pull_request` usage.

## GitHub Action interface

GitHub Actions use `action.yml` to declare inputs, outputs, and runtime configuration; JavaScript
actions may use Node.js 20 or 24, and the action metadata output budget is limited per job.[1]
AgentProof Action uses a committed, bundled Node 24 distribution and these inputs:

| Input           | Required | Default              | Contract                                                                               |
| --------------- | -------: | -------------------- | -------------------------------------------------------------------------------------- |
| `policy-result` |      Yes | —                    | Local path to strict Core `PolicyResult` JSON.                                         |
| `baseline`      |       No | —                    | Local path to strict Action baseline JSON. Absence means every current finding is new. |
| `output-dir`    |       No | `.agentproof/action` | Existing or creatable local directory below the workspace.                             |
| `fail-on`       |       No | `new`                | `none`, `new`, or `all`; controls only the Action exit gate.                           |
| `comment-pr`    |       No | `false`              | Explicit opt-in for a compact evidence comment.                                        |
| `github-token`  |       No | —                    | Required only for opt-in same-repository PR commenting.                                |

The action emits `decision`, `gate-passed`, `new-findings`, `existing-findings`, `sarif-file`,
`junit-file`, and `evidence-file`. Output values are short paths, booleans, or counts; raw trace
payloads and finding prose are never set as outputs.

## Input and baseline protocol

### Policy result

The policy-result input is parsed as a strict Core `PolicyResult` with `schema_version: "1.0"`.
Unknown fields, unsupported schema versions, malformed UTC timestamps, invalid finding identities,
and invalid decision/finding combinations fail the action before artifacts are written.

### Baseline

The v1 baseline is a strict, local JSON document:

```json
{
  "schema_version": "1.0",
  "kind": "agentproof-action-baseline",
  "findings": [
    {
      "finding_id": "...",
      "evidence_id": "...",
      "rule_id": "...",
      "severity": "...",
      "event_ids": ["..."]
    }
  ]
}
```

Only deterministic Core identifiers, severity, and event IDs are permitted. The baseline contains
no title, description, remediation, trace attributes, prompts, tool arguments/results, headers,
tokens, or credentials. A baseline finding is _existing_ only when its complete identity tuple
`finding_id`, `evidence_id`, `rule_id`, severity, and ordered event IDs exactly matches a current
finding. This prevents a changed violation from being silently suppressed.

## Evidence artifacts

| Artifact                   | Role                                                    | Data-minimization rule                                                                                                                      |
| -------------------------- | ------------------------------------------------------- | ------------------------------------------------------------------------------------------------------------------------------------------- |
| `agentproof.sarif`         | Code-scanning compatible, locationless policy evidence. | SARIF message may contain the validated policy title; never raw trace or tool payload. Stable `partialFingerprints` use Core `evidence_id`. |
| `agentproof.junit.xml`     | CI-test compatible representation.                      | One policy test or one finding failure; stable IDs and severity only.                                                                       |
| `agentproof.evidence.json` | Machine-readable result/baseline comparison.            | Counts, stable IDs, severity, decision, and new/existing status only.                                                                       |
| `agentproof.pr.md`         | Compact review evidence.                                | Counts, policy ID/version, decision, and gate status only; no raw finding text.                                                             |

GitHub supports uploading third-party SARIF from a workflow with `github/codeql-action/upload-sarif`;
the upload needs an explicit `security-events: write` workflow permission and is deliberately a
**separate consumer workflow step**, not an implicit Action side effect.[2] The Action gives every
run a stable automation category and partial fingerprint to support alert identity handling.

## Pull-request evidence behavior

The action always writes a local review Markdown artifact and GitHub Job Summary. An API comment is
disabled by default. It is attempted only when all of the following are true:

1. `comment-pr: true` and a token input are supplied.
2. The event is exactly `pull_request` (not `pull_request_target` or `workflow_run`).
3. The PR is from the same repository, not a fork.
4. The workflow explicitly grants the minimal `pull-requests: write` permission.

The comment is idempotently upserted using a marker and contains only compact rendered evidence.
The action never checks out code, reads workflow expressions, sends a token elsewhere, or handles
untrusted PR title/body/content as a command. GitHub recommends least-privilege `GITHUB_TOKEN`
permissions, JavaScript Actions for processing context values instead of shell interpolation, and
avoiding `pull_request_target` for untrusted PR code.[3] [4]

## Determinism and failure modes

Input paths must resolve under `GITHUB_WORKSPACE`, be regular UTF-8 files, and remain below bounded
size limits. Output paths are fixed by the Action and always resolve below `output-dir`. The action
sorts findings only by their preserved PolicyResult order; baseline comparison preserves that order.
Malformed input, unsafe paths, unsupported baseline schema, duplicate baseline identities,
unwritable outputs, or an unsafe comment context yields a clear failure. A policy `error` decision
always fails the gate. `fail-on` applies only after valid evidence rendering:

| `fail-on` | Gate behavior                                                          |
| --------- | ---------------------------------------------------------------------- |
| `none`    | Never fails a valid `pass`, `fail`, or `not_applicable` policy result. |
| `new`     | Fails when one or more current findings are absent from the baseline.  |
| `all`     | Fails when any current finding exists.                                 |

## Acceptance criteria

1. Strict Core policy-result and strict local-baseline validation occur before any report output.
2. SARIF, JUnit, JSON, and Markdown outputs are deterministic under identical source bytes.
3. Every current finding is classified as new or existing by the full identity tuple.
4. Action outputs and PR-facing content do not contain raw trace payloads or secrets.
5. PR API comments are off by default and refuse fork/privileged contexts.
6. Node lint, strict TypeScript, deterministic tests, distribution-bundle freshness, action metadata
   validation, and immutable-pinned CI pass.

## References

[1]: https://docs.github.com/en/actions/reference/workflows-and-actions/metadata-syntax 'GitHub Actions metadata syntax reference'
[2]: https://docs.github.com/en/code-security/how-tos/find-and-fix-code-vulnerabilities/integrate-with-existing-tools/upload-sarif-file 'GitHub documentation: uploading SARIF'
[3]: https://docs.github.com/actions/reference/authentication-in-a-workflow 'GitHub documentation: GITHUB_TOKEN permissions'
[4]: https://docs.github.com/en/actions/reference/security/secure-use 'GitHub Actions secure-use reference'
