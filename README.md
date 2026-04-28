# Oh My Keymint

Custom keystore implementation for Android Keystore Spoofer

> [!WARNING]
> The program is still in its early stages of development.
> No ANY guarantees are made regarding performance or stability.

## What is this?

This is a complete implementation of the keystore, which fully implements the AOSP AIDL interface, referencing the official AOSP implementation.

In theory, this would make it harder for detectors to identify behavior inconsistent with AOSP, thus achieving greater stealth than the FOSS branch of TrickyStore.

## Install and configure

1. Install this module.

2. Configure (if you need)

Configuration file is located at `/data/misc/keystore/omk/config.toml` and `/data/misc/keystore/omk/injector.toml`

### /data/misc/keystore/omk/config.toml

```toml
[main]
# We can only use Injector as backend at this point.
backend = "Injector"

# The following values ​​are used to generate the seed for device encryption 
# and verification. Please be sure to save the following values. If you lose
# them for some reason, please clear the module database (/data/misc/keystore/omk/data/)
# DO NOT MODIFY ANY VALUE BELOW IF YOU DO NOT UNDERSTAND WHAT ARE YOU DOING
[crypto]
root_kek_seed = "4b61c4b3bdf72bb700c351e020270846fb67ba3885e5fb67547e626af5cc1a7f"
kak_seed = "d6fa5bb024540928a7d554ab5831a0553dd2f688f5d6cb3cb1645be2ff49e357"

[trust]
os_version = 15
# Accepted values:
# - "auto": read and preserve the original build.prop patch level
# - "latest": use the 5th day of the current month
# - "YYYY-MM-DD": force an exact patch level
security_patch = "auto"
# `vb_key` accepts:
# - "auto": ro.boot.vbmeta.public_key_digest -> computed top-level vbmeta key digest -> random fallback
# - "random": generate a fresh 32-byte value for this boot and push it into ro.boot.vbmeta.public_key_digest
# - "<64 hex chars>": pin an exact 32-byte value
vb_key = "auto"

# `vb_hash` accepts:
# - "auto": ro.boot.vbmeta.digest -> original system attestation verifiedBootHash -> random fallback
# - "random": generate a fresh 32-byte value for this boot and push it into ro.boot.vbmeta.digest
# - "<64 hex chars>": pin an exact 32-byte value
vb_hash = "auto"

verified_boot_state = true
device_locked = true

[device]
brand = "Google"
device = "generic"
product = "generic"
manufacturer = "Google"
model = "generic"
serial = "ABC12345678ABC"
overrideTelephonyProperties = false
meid = ""
imei = ""
imei2 = ""
```

`[trust_record]` is managed by OMK and may be added automatically after startup.
It records stable derived values such as computed `vb_key`, original-system `vb_hash`,
and `original_security_patch`.
Random values are not written back into `config.toml`.

`security_patch` semantics:

1. `auto` resolves from the original `build.prop` value captured at startup.

2. `latest` resolves to the 5th day of the current month.

3. An explicit `YYYY-MM-DD` value forces that exact patch level.

4. Any non-`auto` value overrides `ro.build.version.security_patch` at runtime.

5. Switching back to `auto` restores the saved original patch level.

6. On every start, OMK refreshes the original patch level from `build.prop` again before applying overrides.

Only `security_patch` hot-applies. Other `[trust]` changes still require restarting `keymint`.

If `overrideTelephonyProperties = false` (the default), OMK ignores user-configured
`[device].imei` and `[device].meid` and resolves them from the device at startup instead.

`[device].imei2` keeps the old behavior: OMK only auto-fills it when it is empty.
If it still resolves to empty, OMK leaves `imei2 = ""` in `config.toml` and omits
the second-IMEI attestation field from generated certificates instead of encoding an
empty value.

For startup auto-fill, OMK resolves telephony identifiers in this order:

1. dedicated telephony APIs from `phone`

2. common radio properties

3. generic device-id fallback from `iphonesubinfo`

OMK writes any successful result back into `config.toml` and leaves still-unavailable
fields empty.

If `config.toml` becomes invalid, OMK rewrites a canonical default config, renames the broken
file to `config.toml.bak`, and appends the parse error to the backup.

### /data/misc/keystore/omk/injector.toml

```toml
# Only packages listed in `scoop` are intercepted.
# Optional per-package settings can be added under [scoop.<package>].
# Example:
# [scoop.io.github.vvb2060.keyattestation]
# mode = "strict"

scoop = [
  "io.github.vvb2060.keyattestation",
  "com.google.android.gsf",
  "com.google.android.gms",
  "com.android.vending",
  "com.eltavine.duckdetector",
]

[main]
enabled = true
log_level = "debug"

[filter]
enabled = true
deny_packages = []
block_android_package = true
allow_unknown_package = false

[intercept]
get_security_level = true
get_key_entry = true
update_subcomponent = true
list_entries = true
delete_key = true
grant = true
ungrant = true
get_number_of_entries = true
list_entries_batched = true
get_supplementary_attestation_info = true

```

`allow_unknown_package = true` allows callers whose package name cannot be resolved to pass
the filter instead of being rejected.

On Android, `injector.toml` reload also uses `inotify`, with polling kept only as fallback.
If the system TEE backend is unavailable but OMK is still reachable, injector preserves the
original OMK binder error instead of replacing it with a synthetic fallback failure.

## Restarting keymint and injector

The module ships two background daemons: one for `keymint`, one for `injector`.
The recommended way to request a restart is through the restart system properties.

Restart only `keymint`:

```sh
resetprop persist.sys.omk.restart.keymint 1
```

Restart only `injector`:

```sh
resetprop persist.sys.omk.restart.injector 1
```

Restart both together:

```sh
resetprop persist.sys.omk.restart.all 1
```

If you switch `[trust].vb_key` or `[trust].vb_hash` from `"random"` back to `"auto"`,
restart alone is not enough. `auto` resolves `ro.boot.vbmeta.*` first, so the current
boot keeps using the randomized sysprops until the device reboots and restores the
original boot properties.

Changing `[trust].security_patch` does not require a restart by itself. OMK hot-applies
the new value and rebuilds the active KeyMint wrappers in place.

The daemons also watch these marker files if you prefer the file-based path:

```sh
touch /data/adb/omk/restart.keymint
touch /data/adb/omk/restart.injector
touch /data/adb/omk/restart.all
```

## License

**YOU MUST AGREE TO BOTH OF THE LICENSE BEFORE USING THIS SOFTWARE.**

`AGPL-3.0-or-later`

```plaintext
OhMyKeymint - Custom keymint implementation for Android Keystore Spoofer
Copyright (C) 2025 James Clef <qwq233@qwq2333.top>

This program is free software: you can redistribute it and/or modify
it under the terms of the GNU Affero General Public License as
published by the Free Software Foundation, either version 3 of the
License, or (at your option) any later version.

This program is distributed in the hope that it will be useful,
but WITHOUT ANY WARRANTY; without even the implied warranty of
MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
GNU Affero General Public License for more details.

You should have received a copy of the GNU Affero General Public License
along with this program.  If not, see <https://www.gnu.org/licenses/>.
```

`Oh My Keymint License`

```plaintext
1. 您不得将本软件、本软件的任意部分或将本软件作为依赖的软件用于任何商业用途。该
   商业用途包括但不限于以盈利为目的，将本软件、本软件的任意部分或将本软件作为依
   赖的软件与其他资源、物品或服务捆绑销售。

2. 您不得暗示或明示本软件与其他软件有任何从属关系。

3. 未经本软件作者书面允许，您不得超出合理使用范围或协议许可范围使用本软件的名称。

4. 除非您所在的司法管辖区的适用法律另行规定，您同意将纠纷或争议提交至中国大陆境
   内有管辖权的人民法院管辖。

5. 本协议与GNU Affero General Public License（以下简称AGPL）共同发挥效力，
   当本协议内容与AGPL冲突时，应当优先应用本协议内容，本协议仅覆盖本软件作者拥有
   完全著作权的部分，对于使用其他协议的软件代码不发挥效力。
```

## Credit

Some code from [AOSP](https://source.android.com/)

License: `Apache-2.0`

```plaintext
Copyright 2022, The Android Open Source Project

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at

    http://www.apache.org/licenses/LICENSE-2.0

Unless required by applicable law or agreed to in writing, software
distributed under the License is distributed on an "AS IS" BASIS,
WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
See the License for the specific language governing permissions and
limitations under the License.
```
