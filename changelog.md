## What's changed

This release is a stability update for the standalone Keystore path introduced in v1.1.0.

A dirty authorization or maintenance mirror state no longer forces normal keystore traffic back to the system service. Mirror failures are now kept local to the mirror path: later authorization and maintenance mirrors are skipped with a warning, while regular service and security-level routing continue to use the configured OMK/system targets. Mirrored auth tokens also now match the system-success flow more closely by skipping the extra local system KeyMint MAC verification after the platform authorization service has already accepted the token.

Logging and runtime helpers have been cleaned up and shared between keymint and injector. File logging now uses locked rotating appenders, rotates existing logs on startup, removes legacy `.lock` sidecar files, and refreshes ownership/permissions for OMK config, keybox, and log files. Config reload recovery was also deduplicated so replace-save races are retried consistently without treating parse errors as transient.

Legacy P-521 EC private-key serialization now uses the BoringSSL Keymaster-compatible marshal/parse APIs and has round-trip coverage, fixing incompatibilities caused by generic DER encoding.

No config migration is required for this update. Existing `config.toml`, `injector.toml`, and `keybox.xml` files remain compatible, but `keymint.log` and `injector.log` may be rotated to `.1` during startup.

## Attestation 
- https://github.com/qwq233/OhMyKeymint/attestations/28625994

**Full Changelog**: https://github.com/qwq233/OhMyKeymint/compare/v1.1.0-424f7b9...v1.1.1-ef38a44
