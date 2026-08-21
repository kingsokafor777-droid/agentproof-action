# AgentProof Action

> **Deterministic AgentProof evidence rendering and baseline gating for GitHub Actions.**

AgentProof Action validates a precomputed, local AgentProof Core `PolicyResult`, compares it to an
optional strict local baseline, and writes SARIF, JUnit, normalized JSON, and compact PR evidence.
It never executes an agent, tool, policy engine, shell command, Python package, model, package
install, or remote scanner.

## What it does

| Capability               | Behavior                                                                                                              |
| ------------------------ | --------------------------------------------------------------------------------------------------------------------- |
| Policy-result validation | Strict Core v1 policy-result shape with no unknown fields.                                                            |
| Baseline comparison      | Exact identity match on finding/evidence/rule/severity/ordered event IDs.                                             |
| Evidence outputs         | Deterministic `agentproof.sarif`, `agentproof.junit.xml`, `agentproof.evidence.json`, and `agentproof.pr.md`.         |
| Gate modes               | `none`, `new` (default), and `all`. A Core `error` decision always fails.                                             |
| PR integration           | Local Markdown evidence always; GitHub comment only through explicit opt-in on same-repository `pull_request` events. |

## Safe workflow usage

```yaml
name: AgentProof evidence
on: [pull_request]

permissions:
  contents: read
  security-events: write # Only needed for the optional SARIF upload step.

jobs:
  evidence:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@11d5960a326750d5838078e36cf38b85af677262

      # An earlier unprivileged step writes .agentproof/policy-result.json.
      - uses: kingsokafor777-droid/agentproof-action@<FULL_RELEASE_COMMIT_SHA>
        id: agentproof
        with:
          policy-result: .agentproof/policy-result.json
          baseline: .agentproof/baseline.json
          fail-on: new
          # comment-pr: true
          # github-token: ${{ secrets.GITHUB_TOKEN }}

      - uses: github/codeql-action/upload-sarif@ff2f1c621b7f889edc0d3c761ac2e6a3f8cdb0dd
        if: always()
        with:
          sarif_file: ${{ steps.agentproof.outputs.sarif-file }}
          category: agentproof-policy
```

Replace `<FULL_RELEASE_COMMIT_SHA>` with a reviewed immutable release commit. The Action does not
upload SARIF itself: GitHub documents SARIF upload as a separate workflow step requiring explicit
`security-events: write` permission.[1]

If maintainers explicitly enable `comment-pr: true`, they must separately add
`pull-requests: write` to the job or workflow permissions. The Action refuses commenting rather
than silently requesting broader access.

## Inputs and outputs

| Input           | Default              | Description                                                 |
| --------------- | -------------------- | ----------------------------------------------------------- |
| `policy-result` | —                    | Required workspace-relative strict Core policy-result JSON. |
| `baseline`      | Empty                | Optional workspace-relative strict Action baseline JSON.    |
| `output-dir`    | `.agentproof/action` | Workspace-relative artifact directory.                      |
| `fail-on`       | `new`                | `none`, `new`, or `all`.                                    |
| `comment-pr`    | `false`              | Explicitly opt in to same-repository PR comment upsert.     |
| `github-token`  | Empty                | Token used only with `comment-pr: true`.                    |

| Output                                        | Description                                 |
| --------------------------------------------- | ------------------------------------------- |
| `decision`                                    | Validated Core policy decision.             |
| `gate-passed`                                 | Boolean gate outcome.                       |
| `new-findings` / `existing-findings`          | Exact baseline comparison counts.           |
| `sarif-file` / `junit-file` / `evidence-file` | Workspace-relative evidence artifact paths. |

## PR-comment safety

`comment-pr` is disabled by default. When enabled, it requires an explicit token and refuses every
context except a non-fork `pull_request` event. It refuses `pull_request_target` and `workflow_run`,
does not check out PR code, and never interpolates PR text into a shell command. Comment content is
limited to policy identity, decision, gate outcome, and counts.

## Development

```bash
npm ci
npm run validate
```

`dist/` is intentionally committed because GitHub Actions execute the bundled JavaScript. The
validation command rebuilds it and fails when the committed bundle is stale.

Read the complete [architecture](docs/architecture.md), [output contract](docs/output-contract.md),
[security model](docs/security.md), and [compatibility policy](docs/compatibility.md).

## References

[1]: https://docs.github.com/en/code-security/how-tos/find-and-fix-code-vulnerabilities/integrate-with-existing-tools/upload-sarif-file 'GitHub documentation: uploading SARIF'
