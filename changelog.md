## What's changed

This release is a routing and runtime hardening update for the injector-backed OMK path. Scoop-routed calls now treat a reachable OMK backend as the authoritative business path: OMKsuccesses and service-specific failures are returned to the app instead of being masked by a system reply. The system reply is preserved only for OMK-unavailable conditions such as amissing backend, RPC/connect failures, or `DeadObject`-like transport failures.

The injector path has been reworked around direct OMK-owned Binder routing. OMK-routed `getSecurityLevel`, `getKeyEntry`, and `createOperation` flows no longer depend on reusable systemkeystore carrier objects; the injector now synthesizes local security-level and operation binder targets inside `keystore2` and serves their follow-up transactions through OMK. Grant andungrant are also decided before system grant row allocation: OMK grants surface OMK grant descriptors directly, and unknown-package grant readbacks are allowed only when OMK confirms thelive `Domain::GRANT` descriptor for the caller. Denylist and Android package rejection still remain authoritative. This might fixes some issues for TEE broken devices.

The injector backend now uses private rsbinder RPC instead of public service-manager services. When `backend = "injector"` is active, keymint serves OMK keystore, authorization, and maintenance services on `/data/adb/omk/rpc.sock`; the launcher waits for that socket and passes a preconnected fd into the injected payload. Forwarded RPC peers are restricted to local root or keystore, RPC caches are retried and cleared on `DeadObject`, and the diagnostics helper has been updated for the RPC transport.

Keystore state handling was tightened. Authorization and maintenance mirrors now keep separate dirty state and retry independently, with only successful mutating mirrors clearing the matching dirty flag. Auth-bound APP keys keep their original storage flags and require the CredentialEncrypted super key; OMK no longer weakens storage by retrying without cryptographic LSKF binding when CE is unavailable, so locked or uninitialized user state continues to surface `LOCKED` or `UNINITIALIZED`.

Android 12 and older now use the legacy key-attestation application-id provider for both AAID generation and injector package resolution, matching the platform surface on those releases. Android-version detection was shared across keymint and injector, KeyMint fallback profile selection was adjusted around the detected platform version, and the old `IPackageManager` AIDL dependency was removed.

Maintenance and packaging were also cleaned up. The standalone probe/tamper binaries and their tests were removed, while the remaining AOSP smoke test now covers an AES-GCM encrypt/decrypt round trip and the security-level diagnostic reports the RPC path. The injector binary now exports only `entry` instead of using `--export-dynamic`, and dependencies were updated, including `rsbinder`/`rsbinder-aidl` 0.9 with RPC support.

## Attestation

- https://github.com/qwq233/OhMyKeymint/attestations/31448366

**Full Changelog**: https://github.com/qwq233/OhMyKeymint/compare/v1.1.1-ef38a44...v1.2.0-67dc5e7
