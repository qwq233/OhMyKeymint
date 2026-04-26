# Guide

- Build & check & test target should be `aarch64-linux-android`
- Compile using cargo-ndk with the target ABI set to aarch64
  i.e.: `cargo ndk -t arm64-v8a --platform 24 build`
- Default to `rg` for searching and keep edits ASCII unless the file already uses non-ASCII.
- Keep it as pure Rust lang project unless you get approval.
- Things in `refs` folder are just references. They will not be complied or sth. Don't take it too serious.
