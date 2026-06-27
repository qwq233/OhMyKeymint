# Guide

- You must always pay absolute attention: has the functionality you want to implement been implemented before? If it has, reuse that method, call that method. Instead of blindly fucking adding methods yourself, writing redundant code, and fucking gilding the lily.
- You are allowed to use web search and subagents to do whatever you want.
- Build & check & test target should be `aarch64-linux-android`
- For scoop-routed applications, OMK is the authoritative business path. If OMK is reachable and
  returns a business error, return that OMK error as-is.
  Do not swallow it, downgrade it, or fallback to a system success reply. Only OMK-unavailable
  failures such as missing backend, connect failure, or `DeadObject` may preserve the system reply.
- For device hot updates, agents may use scripts under `scripts/`, especially
  `python scripts/deploy_hot_update.py --serial <serial> --abi arm64-v8a --restart all`.
  It builds, deploys, verifies hashes, and hot-restarts keymint/injector without rebooting.
- Default to `rg` for searching and keep edits ASCII unless the file already uses non-ASCII.
- Keep it as pure Rust lang project unless you get approval.
- Things in `refs` folder are just references. They will not be complied or sth. Don't take it too serious.
- Preserve current auth-bound APP key storage semantics unless the user explicitly asks to change
  them. The current invariant is:
  - injector must not patch auth-bound APP `generateKey` request flags.
  - `KeystoreSecurityLevel::store_new_key_descriptor` must pass the original flags to
    `SUPER_KEY.handle_super_encryption_on_key_init`; do not add CE-availability probes or a retry
    that ORs in `KEY_FLAG_AUTH_BOUND_WITHOUT_CRYPTOGRAPHIC_LSKF_BINDING`.
  - `Enforcements::super_encryption_required` is the only place where that flag disables
    cryptographic LSKF binding.
  - If `SuperEncryptionType::CredentialEncrypted` has no unlocked CredentialEncrypted super key,
    keep the current `LOCKED` / `UNINITIALIZED` result. Do not convert that state into successful
    key storage based on `sys.user.<id>.ce_available` or similar Android CE-availability signals.
- Any chaneges to the `config` should be reflected to the READMD.md and template
- You must run unit test (scoop: whole workspace aka all packages) on the real Android device after finishing your tasks unless device unavailable or you don't change the code.
- Format code and make clippy happy.
  - Using `[allow]` to bypass clippy is a compromise and should not be allowed unless there is a good reason (You should explain).
