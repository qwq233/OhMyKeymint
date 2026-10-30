# Contributing

Thank you for improving OhMyKeymint. Before submitting a change, read the
[FAQ](FAQ.md), search the existing
[issues](https://github.com/qwq233/OhMyKeymint/issues), and follow the technical
invariants in [AGENTS.md](../AGENTS.md). Discuss substantial features or behavior
changes in an issue first.

## AI-assisted contributions

Before submitting any contribution, read and follow the
[AI-Assisted Contributions Policy](AI-Policy.md). You must disclose every AI
tool and model used (or state that none was used), understand every submitted
change, personally review the complete final diff, and retain full human
responsibility for the contribution.

## Scope and compatibility

- Keep each pull request focused on one problem. Do not include unrelated
  refactors, formatting, dependency updates, or generated files.
- Before adding a method, helper, abstraction, configuration field, or utility,
  inspect the directly relevant modules for equivalent behavior. Reuse or
  minimally extend existing code.
- Android is the only production and acceptance target. Target-specific build,
  check, and test commands must use `aarch64-linux-android`; host or x86_64
  success alone is insufficient.
- Preserve compatibility with Android 12-17, Linux kernels 4.14-6.18, and newer
  LTS kernels. Do not claim that a platform was validated without evidence.
- Do not add a non-Rust product.
- Do not force-add files matched by `.gitignore`.

## Review scope

- Do not report or fix scenarios that require multiple independently abnormal,
  low-probability conditions and cannot occur during normal supported use.
- When excluding such a scenario, state the concrete conditions that must occur
  together and why supported paths cannot reach it. Low frequency or a narrow
  timing window alone does not exclude an issue that supported operation can
  reach.

## Required behavioral invariants

Changes affecting the following paths must preserve every applicable invariant.
State in the pull request what behavior remains unchanged.

### OMK routing

- For every request routed by `scoop` with
  `FilterDecision::allowed == true`, OMK is the only backend during normal
  reachable operation. Per-method intercept settings still determine whether a
  request is routed by `scoop`.
- Choose the backend only from the current caller, filter decision, method, and
  configuration. Do not inspect or infer which backend created a key,
  `KeyDescriptor`, `KEY_ID`, `GRANT`, alias, wrapping key, or attestation key.
- Per-method intercept settings are authoritative. When interception for a
  method is disabled, pass the request to System unchanged even when `scoop`
  allows the caller.
- Do not provide key or descriptor continuity between System and OMK. Pass old,
  externally supplied, and System-created descriptors to the selected backend
  unchanged. An OMK business error for such a descriptor is authoritative.
- Return OMK business errors unchanged. Reachable transport, boundary, or
  injector failures that are not OMK-unavailable must not fall back to a
  successful System reply. Normalize them through the existing AOSP-compatible
  error path, such as `SYSTEM_ERROR` where applicable.
- Only confirmed OMK-unavailable failures may preserve the original System
  reply. These include a missing service or backend, a connection failure, and
  stale or dead RPC transport failures such as `DeadObject`, `RpcError`, and
  `NotEnoughData`. Reuse the existing classifiers instead of maintaining a
  separate status list.

### Persistent and temporary files

- Delete every temporary probe artifact immediately after the probe completes.
- Store new persistent product data under `/data/misc/keystore/omk/data/`.

## Repository conventions

- Use targeted `rg` searches. Keep edits ASCII unless the file already uses
  non-ASCII.
- When `src/config.rs` changes the `config.toml` schema, defaults, accepted
  values, migration, or runtime semantics, update the corresponding
  [README](../README.md) documentation. When `injector/src/config.rs` changes
  `injector.toml`, update both the README and
  [`template/injector.toml`](../template/injector.toml).

## Development, validation, and deployment

The [CI workflow](../.github/workflows/ci.yml) is the source of truth for the
current toolchain and Android build environment. Use Rust nightly, the
`aarch64-linux-android` target, an Android NDK version matching CI, and the
CMake, Ninja, and bindgen tools required to build BoringSSL.

Generate the local Cargo configuration and build with the existing scripts:

```sh
python scripts/setup_cargo_config.py --ndk-root <ANDROID_NDK_ROOT> --force
python build.py --debug
```

Rust changes must pass:

```sh
cargo fmt --all -- --check
cargo clippy --target aarch64-linux-android --workspace --all-targets -- -D warnings
cargo test --target aarch64-linux-android --workspace --no-run
cargo deny --workspace check
```

When an authorized aarch64 Android device is available, run every generated
workspace test binary on the device. If no device is available, state that the
device gate was not run; a host build is not full validation. Documentation-only
changes do not require code tests.

For binary hot updates, prefer:

```sh
python scripts/deploy_hot_update.py --serial <serial> --abi arm64-v8a --restart all
```

This command builds, deploys, verifies hashes, and restarts KeyMint and the
injector without rebooting. Verify the affected runtime path after deployment;
a healthy KeyMint listener alone does not prove that keystore2 refreshed a stale
injector RPC session.

Do not add `#[allow(...)]` only to silence Clippy. Any necessary exception must
have a concrete, documented reason and direct maintainer approval.

## Commits and pull requests

- Target pull requests at `master`.
- Use `type(scope): concise summary` for commit titles; the scope is optional.
  Common types are `fix`, `feat`, `refactor`, `docs`, `test`, `ci`, and `chore`.
- Keep the title concise. Use the body to explain the problem, root cause,
  behavior change, and behavior that must remain unchanged.
- Commits must have a verifiable cryptographic signature and a `Signed-off-by`
  trailer. `git commit -S -s` supplies both; `-S` and `-s` are distinct.
- Link the relevant issue and list the exact validation commands and results.
  Explicitly identify any device validation that was not run.
- Disclose the source and license of any third-party code, documentation, or
  assets, and preserve all required notices.

The maintainers choose the final merge method. The project does not prescribe a
branch naming convention or a single merge strategy.

## Contributor copyright, licenses, and authorization

For this section, a "Contribution" means the original code, documentation,
tests, configuration, assets, or other material that you submit for inclusion
in this project. Separately identified third-party material is not your original
Contribution and must be disclosed with its source and license.

By submitting a commit, patch, pull request, or other Contribution, you
represent, warrant, and agree that:

1. You own the complete copyright in your Contribution and every right required
   to grant the licenses and authorizations below. If an employer, client,
   co-author, or another party may hold any copyright in it, you have obtained
   all required written assignments before submission so that you own the
   complete copyright, together with any other permission required to submit it.
2. Your Contribution, as part of this project, is subject to and complies with
   both licenses current at the time of submission: the
   [GNU Affero General Public License version 3 or any later version](../LICENSE.md)
   and the [Oh My Keymint License](../LICENSE-2). The two licenses apply together;
   they are not alternatives. Properly disclosed third-party material remains
   subject to its original license.
3. To the extent permitted by applicable law, you irrevocably authorize the
   project maintainers to act on your behalf in copyright, infringement, and
   licensing disputes concerning your Contribution. This authorization includes
   notices, complaints, negotiations, settlements, and initiating, joining, or
   responding to legal proceedings. You agree to provide reasonable additional
   authorization if the law requires a separate instrument.
4. You grant the project maintainers a perpetual, irrevocable, worldwide,
   royalty-free, non-exclusive, sublicensable right to use, reproduce, modify,
   publish, distribute, and relicense your Contribution. You also authorize the
   maintainers to amend, replace, add, or remove project license terms and to
   relicense your Contribution under amended or different terms without seeking
   your further consent.
5. These grants do not transfer your ownership of the copyright in your
   Contribution.

Do not submit a Contribution if you do not agree to every term in this section.
