## What's changed

This release makes the standalone Keystore path more complete by implementing the Keystore authorization and maintenance services. OMK can now handle user lock/unlock state, auth token localization, shared-secret based auth-token HMAC key setup, and maintenance events such as user and namespace lifecycle.

The injector has also been strengthened. Authorization and maintenance calls are mirrored to OMK after the system service accepts them, routing now falls back to the system service if the mirrored state becomes dirty, and tracked grant readbacks are bridged for isolated callers. This should make auth-bound keys, grants, and operation routing behave much closer to stock AOSP.

KeyMint hardware information is now resolved dynamically from VINTF, device properties, or the system KeyMint service, which should reduce generic AOSP-looking hardware profiles. This release also retires stale attest-key entries when the active keybox changes and fixes AAID encoding for callers with multiple package records.

Additionally, logging and blind KeyMint probes were expanded, the hot-update deployment script was added, dependencies were updated, and the local rsbinder fork was removed because the required patches are now upstream.

Older configs are still accepted, but OMK may add `shared_secret_seed` and `shared_secret_nonce` when rewriting `config.toml`. Keep generated `[crypto]` values stable across updates.

## Attestation 
- https://github.com/qwq233/OhMyKeymint/attestations/28506616

**Full Changelog**: https://github.com/qwq233/OhMyKeymint/compare/v1.0.0-e9fecf0...v1.1.0-424f7b9
