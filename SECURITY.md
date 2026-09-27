# Security model

The analyzer treats log bytes and optional analyst text as untrusted. It performs no network enrichment, external messaging, command execution from input, or automatic containment.

## Implemented controls

- Local files explicitly listed by a manifest; traversal, symlink/reparse points and network paths rejected.
- Bounded lines, input size, decompression, nesting, file counts and aggregate group counts.
- Single gzip member with integrity checks; archive formats and concatenated gzip streams rejected.
- Strict YAML with duplicate-key/alias rejection; strict JSON rejects duplicate keys and non-finite numbers.
- Parameterized SQLite values; validated rule fields and operators; no user SQL, eval or templated source code.
- Allowlisted normalized records, session HMAC, query removal and redacted error codes.
- Jinja autoescaping, Markdown escaping, terminal control sanitization and a restrictive HTML CSP.
- Staged result publication, workspace writer lock, foreign-key integrity and explicit unsupported-schema errors.
- Pinned dependency resolution, hashed runtime installation and commit-pinned GitHub Actions.

## Trust and limitations

Input authority, namespaces, proxy ranges and clock corrections are supplied by the operator. The tool does not verify that the source system logged truthfully. Local file checks do not establish protection against a privileged attacker racing filesystem operations. It is a single-user workstation tool, not a multi-tenant web service.

Ordinary normalized exports retain user IDs, addresses and operational metadata. Use access controls and a private workspace. Public exports remove structured identities and notes; manually review arbitrary text fields and metadata before sharing. Hashes establish consistency, not source authenticity or signed chain of custody.

SQLite WAL uses `synchronous=NORMAL`: process-crash consistency is provided by SQLite, but power loss can lose recent commits. Completed reports should be backed up. Runtime resource limits do not replace OS-level quotas for intentionally hostile inputs.

The Docker definition uses UID 10001; the smoke command adds read-only root and disables networking. See the validation report for whether these checks actually ran in the current environment.

## Reporting a problem

For a portfolio deployment, configure a private security contact before publishing. Do not attach real logs, credentials or personal data to public issues. Provide a minimal synthetic reproducer and the program version/error code.
