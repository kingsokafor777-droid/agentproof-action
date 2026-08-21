# Output Contract

All artifacts are UTF-8, deterministic, and written below `output-dir` in the workspace.

| File                       | Contract                                                                                                      |
| -------------------------- | ------------------------------------------------------------------------------------------------------------- |
| `agentproof.sarif`         | SARIF 2.1.0, one AgentProof run, stable rule IDs, `evidence_id` partial fingerprints, and no source location. |
| `agentproof.junit.xml`     | One suite; one passing test for an empty finding list or one failure per finding.                             |
| `agentproof.evidence.json` | Strict Action v1 minimized machine evidence with IDs, severity, baseline state, decision, and counts.         |
| `agentproof.pr.md`         | Compact comment-safe Markdown with policy identity, decision, gate, and counts only.                          |

The Action never includes Core finding titles/descriptions/remediation, raw workflow events,
attributes, prompts, arguments, results, headers, tokens, or credentials in its machine output or
PR-facing Markdown.
