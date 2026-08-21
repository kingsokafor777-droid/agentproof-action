# Security Model

The Action operates only on local regular files below `GITHUB_WORKSPACE`, after realpath containment
checks. It rejects unsafe path traversal, symlink escapes, files over 1 MB, malformed JSON, unknown
fields, incompatible versions, and invalid baseline identities before output generation.

Commenting requires `comment-pr: true`, a token, the ordinary `pull_request` event, a non-fork PR,
and a valid repository identity. The recommended workflow grants `pull-requests: write` only when
this narrow optional behavior is used. The Action never uses `pull_request_target`, executes a shell
string, or checks out code.
