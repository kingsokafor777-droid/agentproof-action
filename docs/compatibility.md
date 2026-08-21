# Compatibility Policy

AgentProof Action v0.1 accepts only Core `PolicyResult` schema version `1.0` and Action baseline
schema version `1.0`. Altering strict input fields, finding identity comparison, gate semantics,
SARIF/JUnit identity mapping, or PR-comment safety checks is a major change. Adding optional
bounded inputs or artifact fields is minor. Fixes that preserve the contract are patch releases.
