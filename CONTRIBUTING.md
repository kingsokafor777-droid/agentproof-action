# Contributing to AgentProof Action

Do not add arbitrary command execution, dynamic action download, model/tool execution, policy
engine execution, remote baseline fetches, webhook handling, pull-request target workflows, or
implicit GitHub API writes. New inputs must be bounded, workspace-relative where file-based,
documented, and covered by deterministic tests. Keep committed `dist/` fresh with `npm run build`.
