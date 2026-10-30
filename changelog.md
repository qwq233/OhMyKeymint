## What's changed

This release updates the KeyMint and Keystore implementation to Android 17, including KeyMint v5 and ML-DSA support on the TEE path. Compatibility with older Android releases has also been improved through corrected transaction layouts and attestation application-ID resolution. VINTF manifest assembly now follows libvintf more closely, and StrongBox is only exposed when the corresponding system KeyMint HAL is present.

The injector now backs its OMK security-level and operation handles with native Binder objects, and the hooking backend has switched from `lsplt-rs` to `omhook`. Binder replies, interface metadata, one-way transactions, empty key descriptors, and operation cleanup have been corrected. Hook initialization failures no longer panic inside `keystore2`. The injected payload also connects to OMK RPC directly, with separate authentication-token and lifecycle sessions and cached connections to reduce contention and request overhead.

Scoop routing now consistently follows the current caller, filter decision, and per-method intercept settings. Historical `KEY_ID` or `GRANT` ownership no longer overrides that decision, and disabled methods remain on System. OMK business errors are returned unchanged, while transport and reply-boundary failures are normalized to AOSP-compatible errors such as `SYSTEM_ERROR` instead of being hidden by a successful System reply.

Key derivation and compatibility with legacy OMK key and super-key formats were corrected. Stored legacy OS-version metadata is migrated to AOSP encoding, and lowering configured OS or patch levels no longer rejects existing OMK keys solely for carrying newer values. Failed localization discards only the affected mirrored auth token, and the existing `force_skip_system_biometric_hat_verification` switch takes effect correctly.

Attestation trust settings now include independent OS, vendor, and boot patch levels. `os_version = "auto"` follows the current Android major at KeyMint startup, and automatic boot patch detection reads AVB metadata or the boot image header before property fallbacks. Patch-level-only edits can update active TAs without rebuilding them, preserving in-flight operations and per-boot state. When automatic verified-boot key or hash discovery has no usable source, the generated fallback is pinned in `config.toml` so it stays stable across restarts.

Device-ID discovery now runs on demand through the privileged Binder helper with the correct system UID and Android-version-specific telephony transactions. It retries while required services are not registered and shares the resolved snapshot between TEE and StrongBox. Single-IMEI devices, absent MEID or IMEI2, partial probe success, and explicit empty overrides are handled without invalidating unrelated attestation IDs.

Keyboxes containing only a valid EC entry are now supported; RSA-key attestations use the EC signing key and certificate chain when the RSA entry is absent. Keybox rotation only retires keys actually attested by the previous keybox. The new `main.retire_stale_keybox_bound_keys` setting can preserve those client keys when required; retirement remains enabled by default.

Valid older configurations are migrated at startup to `config.toml` version 3 and `injector.toml` version 1. Migration from unversioned or version 1 KeyMint configs resets `os_version` to `"auto"`; keep all generated `[crypto]` values unchanged. The injector is now the only runtime backend, with legacy `backend = "omk"` accepted as an alias for `"injector"`. Malformed files are no longer overwritten with defaults: an invalid KeyMint config prevents startup, an invalid injector config disables routing at startup, and failed live reloads retain the last valid configuration. Log levels now apply correctly, and logs are written under `/data/misc/keystore/omk/logs/`.

Additionally, injector and KeyMint overhead was reduced, module updates no longer create an `omkdata` symlink loop, and the daemon prefers `/system/lib64` over `/vendor/lib64` in its library search path. Dependencies were updated, formatting, Android-targeted Clippy, and `cargo-deny` checks were added to CI, and configuration and troubleshooting documentation was expanded. The project now uses the General License Agreement together with the updated Oh My Keymint License; read both before using or redistributing this release.

## Attestation

- https://github.com/qwq233/OhMyKeymint/attestations/61782379

**Full Changelog**: https://github.com/qwq233/OhMyKeymint/compare/v1.2.0-67dc5e7...1.2.5-17b0eb6

