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
- Any chaneges to the `config` should be reflected to the READMD.md and template
- Run unit test on the real Android device after finishing your tasks.
