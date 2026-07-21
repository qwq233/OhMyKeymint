# OhMyKeymint Agent Guide

## Project Boundaries

- Before adding a method, helper, abstraction, configuration field, or utility, inspect the
  directly relevant modules for equivalent behavior. Reuse or minimally extend existing code.
- Android is the only production and acceptance target. Target-specific build, check, and test
  commands must use `aarch64-linux-android`; host or x86_64 success alone is insufficient.
- Compatibility scope: Android 12-17; Linux kernels 4.14-6.18 and newer LTS kernels. Preserve
  behavior across this range, and do not claim a platform was validated without evidence.
- Do not introduce new non-Rust product or runtime code without explicit approval. Existing Python
  build/deployment scripts and shell packaging assets are tooling, not precedent for new runtime
  components.

## Behavioral Invariants

### OMK Routing

- For requests routed by `scoop`, OMK is authoritative once it is reachable.
- Return OMK business errors as-is. Reachable transport, boundary, or injector failures that are
  not OMK-unavailable must not fall back to a successful system reply; normalize them to the
  existing AOSP-compatible error path, such as `SYSTEM_ERROR` where applicable.
- Only confirmed OMK-unavailable failures may preserve the original system reply. These include a
  missing service/backend, connection failure, and stale or dead RPC transport failures such as
  `DeadObject`, `RpcError`, and `NotEnoughData`. Reuse the existing classifiers instead of
  maintaining another status list.

### Telephony Attestation IDs

- `AttestationIdInfo` is field-wise. A device may legitimately have one IMEI, no IMEI2, no MEID,
  or no telephony identifiers. Empty optional telephony fields, including explicit empty overrides,
  do not invalidate brand, device, product, serial, manufacturer, model, or an available IMEI.
- Runtime discovery is best-effort and one-shot per KeyMint process once the required Binder
  services are registered; TEE and StrongBox share the resolved snapshot. After all applicable
  direct Binder APIs and property fallbacks have been attempted once, cache and return
  `Some(AttestationIdInfo)` even when telephony fields are partial or all empty.
- If an actually attempted `phone`, `iphonesubinfo`, or `package_native` Binder service is not yet
  registered, return `Ok(None)` without updating runtime, persisted, process, or TA caches so a
  later request can retry. Empty values, unsupported APIs, permission failures, and other probe
  errors from registered services still complete the one-shot snapshot.
- `Ok(None)` means the entire ID snapshot is not ready and remains retryable. Do not use it merely
  because IMEI2, MEID, or all telephony fields are absent after one-shot discovery.
- Preserve every valid candidate returned by any slot or API. A failure or unsupported result from
  another probe must not discard successful values or turn the resolved snapshot into an error.
  Individual probe failures are internal discovery failures, not scoop-routed OMK business errors.
- Return `CANNOT_ATTEST_IDS` only when an explicitly requested ID is absent or mismatched. Missing
  unrequested IMEI2 or MEID must not block ordinary attestation or requests for other IDs.
- Use the existing privileged fork helper and direct Binder calls. Do not add shell commands or
  `service call` parsing. Compare platform behavior against `android17-release`, not AOSP `main`;
  Android 12-17 validate only the device-ID tags actually requested.
- Changes to this path must preserve single-IMEI devices, devices with IMEI but no MEID, devices
  with no telephony identifiers, partial probe success, and the existing process/TA cache
  boundaries.

### Auth-Bound APP Key Storage

- The injector must not patch auth-bound APP `generateKey` request flags.
- The key-storage path must pass the original flags unchanged to
  `SUPER_KEY.handle_super_encryption_on_key_init`. Do not add CE-availability probes or retry with
  `KEY_FLAG_AUTH_BOUND_WITHOUT_CRYPTOGRAPHIC_LSKF_BINDING` ORed into the flags.
- `Enforcements::super_encryption_required` is the only place where that flag disables
  cryptographic LSKF binding.
- If `SuperEncryptionType::CredentialEncrypted` has no unlocked CredentialEncrypted super key,
  preserve `LOCKED` or `UNINITIALIZED`. Do not turn that state into successful storage based on
  `sys.user.<id>.ce_available` or similar Android CE-availability signals.

## Repository Conventions

- Use targeted `rg` searches. Keep edits ASCII unless the file already uses non-ASCII.
- Treat `refs/` as non-build reference, probe, and evidence material. It is not part of the main
  Cargo workspace or shipped module. Use it for contract checks, but verify conclusions against the
  compiled Rust path and the relevant Android release. Edit it only when the task includes reference
  documentation, probes, or reports.
- For injector or detector investigations, start from injector-visible routing, state, and fresh
  scooped/plain runtime evidence. Use `refs/keymint` and `refs/keystore2` as final contract checks,
  not as a reason for speculative production rewrites.
- When `src/config.rs` changes the `config.toml` schema, defaults, accepted values, migration, or
  runtime semantics, update the corresponding `README.md` documentation. When
  `injector/src/config.rs` changes `injector.toml`, update both `README.md` and
  `template/injector.toml`.

## Validation and Deployment

- For Rust code changes, run the repository's Android gate before handoff:

  ```sh
  cargo fmt --all -- --check
  cargo clippy --target aarch64-linux-android --workspace --all-targets -- -D warnings
  cargo test --target aarch64-linux-android --workspace --no-run
  ```

- When an authorized aarch64 Android device is available, execute every generated workspace test
  binary on-device. If the device is unavailable, report that the device gate was not run; do not
  present host-side compilation as full validation. Documentation-only changes do not require code
  tests.
- For binary hot updates, prefer:

  ```sh
  python scripts/deploy_hot_update.py --serial <serial> --abi arm64-v8a --restart all
  ```

  It builds, deploys, verifies hashes, and restarts KeyMint and the injector without rebooting.
  Verify the affected runtime path after deployment; a healthy KeyMint listener alone does not
  prove that keystore2 has refreshed a stale injector RPC session.
- Do not add `#[allow(...)]` solely to silence Clippy. Any necessary exception must have a concrete,
  documented reason and direct approval from user.
