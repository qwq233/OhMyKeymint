# Configuration Guide

OhMyKeymint (OMK) uses two active configuration files:

- `/data/misc/keystore/omk/config.toml` controls the KeyMint service, the
  identity it reports, and the secrets used for OMK-created keys.
- `/data/misc/keystore/omk/injector.toml` selects which apps use OMK and which
  KeyStore requests are routed to it.

This guide describes the active configuration used by the current build. The
examples are followed by a separate field-by-field reference so that the short
comments in the examples are not the only explanation.

**Jump to:** [`config.toml`](#configtoml) | [`injector.toml`](#injectortoml)

## Before editing

For ordinary use, the only setting that normally needs changing is `scoop` in
`injector.toml`. Keep the safety filters, all `[intercept]` switches, and the
generated `[crypto]` values unchanged.

Before making a change:

1. Make a private backup of both active files.
2. Edit the files under `/data/misc/keystore/omk/`, not copies in the module ZIP.
3. Keep strings inside quotes, booleans as `true` or `false`, and package names
   inside the `scoop = [...]` array.
4. Change one thing at a time, save the complete file, and check the matching
   log after the change.

Never publish `[crypto]` values, IMEI, IMEI2, MEID, serial numbers, or an
unredacted copy of either active file.

## How changes are loaded

Both components watch their active file for valid changes. Their behavior is
not identical:

- A valid `injector.toml` is applied to new requests without a reboot.
- A valid `config.toml` is read automatically, but only the four patch-level
  fields and the biometric compatibility switch can take full effect without
  restarting keymint. The field reference below states when a restart is
  required.
- A malformed file saved while its component is running is rejected and the
  last valid in-memory configuration remains active.
- A malformed `config.toml` present when keymint starts prevents keymint from
  starting. Fix the file and restart keymint.
- A malformed `injector.toml` present when the injector starts leaves OMK
  request routing disabled. Saving a valid file lets the watcher restore
  routing automatically; restart the injector only if it does not recover.
- If either file is missing when its component starts, OMK creates a new file
  with generated defaults. This is not a safe way to reset a working setup:
  regenerated secrets do not restore keys protected by the previous secrets.
The restart commands are documented in
[Restarting keymint and injector](../README.md#restarting-keymint-and-injector).
A restart file is applied through a directory watch when that is available,
and otherwise within thirty seconds.
After changing app routing, close and reopen the affected app to avoid mixing
an already-open operation with the new route. If a process restart is needed
for a clean boundary, restart the injector only. An injector-only setting
change does not require a keymint restart.

## `config.toml`

### Complete annotated example

The values under `[crypto]` below are deliberately non-working redaction
placeholders. A real active file contains unique generated hexadecimal values.
Never paste the placeholder values into a device and never replace the values
already present in a working file. The `[trust]` and `[device]` values are also
examples; keep the values from the active file unless you intend to change the
reported identity.

```toml
# Configuration format. Keep this at 2.
version = 2

[main]
# The supported service connection. Keep this value unchanged.
backend = "injector"
# KeyMint log detail: off, error, warn, info, debug, or trace.
log_level = "info"
# Insecure biometric compatibility switch. Keep false for normal use.
force_skip_system_biometric_hat_verification = false

[crypto]
# Redacted placeholders only. Keep the generated 64-character values.
root_kek_seed = "KEEP_THE_VALUE_FROM_THE_ACTIVE_FILE"
kak_seed = "KEEP_THE_VALUE_FROM_THE_ACTIVE_FILE"
shared_secret_seed = "KEEP_THE_VALUE_FROM_THE_ACTIVE_FILE"
shared_secret_nonce = "KEEP_THE_VALUE_FROM_THE_ACTIVE_FILE"
# Optional expert override. Normally leave this line absent.
# auth_token_hmac_key = "KEEP_THE_VALUE_FROM_THE_ACTIVE_FILE"

[trust]
# Detect the Android major at each keymint start; use an integer to fix it.
os_version = "auto"
# Use auto, latest, or an exact YYYY-MM-DD date; boot also accepts decimal u32.
security_patch = "auto"
os_patchlevel = "auto"
vendor_patchlevel = "auto"
boot_patchlevel = "auto"
# Use auto, random, or exactly 64 hexadecimal characters.
vb_key = "auto"
vb_hash = "auto"
# Report verified boot and a locked bootloader when true.
verified_boot_state = true
device_locked = true

[device]
# Device identity strings reported when an app requests attestation IDs.
brand = "KEEP_THE_VALUE_FROM_THE_ACTIVE_FILE"
device = "KEEP_THE_VALUE_FROM_THE_ACTIVE_FILE"
product = "KEEP_THE_VALUE_FROM_THE_ACTIVE_FILE"
manufacturer = "KEEP_THE_VALUE_FROM_THE_ACTIVE_FILE"
model = "KEEP_THE_VALUE_FROM_THE_ACTIVE_FILE"
serial = "KEEP_THE_VALUE_FROM_THE_ACTIVE_FILE"
# false fills only empty telephony fields from the device when available.
overrideTelephonyProperties = false
# Empty optional identifiers are valid; do not invent missing values.
meid = ""
imei = ""
imei2 = ""
```

### Top-level field

#### `version`

This identifies the configuration format. The supported value is the integer
`2`. It is not an Android version or an OMK release number. Do not increment it;
the current file should keep this value unchanged. Live reload rejects other
values and keeps the last valid runtime configuration.

At keymint startup, a missing `version` is treated as `0`. Versions `0` and `1`
are migrated in place to `2` before the service starts, and `os_version` is set
to `"auto"` so later Android upgrades are detected on the next keymint start.
Startup also removes the obsolete `trust_record`. For version `0`, missing
patch-level fields inherit the configured `security_patch`. Other configured
and unknown values are preserved. Migration is not performed during live
reload, so restart keymint to migrate an older file. An unsupported future
version is never overwritten.

### `[main]`

#### `backend`

Use `"injector"`. It is the only supported user choice and there is no
alternative runtime backend to select, so this field should be left unchanged.

#### `log_level`

This controls messages written by keymint. Use one of `"off"`, `"error"`,
`"warn"`, `"info"`, `"debug"`, or `"trace"`. `"info"` is the default and
records startup, configuration, and failures. `"debug"` adds per-request
detail and is the most useful level for a bug report. `"trace"` is more
verbose; `"off"` suppresses normal logging.

Changing this field requires a keymint restart. An unrecognized value falls
back to `info`, but relying on that fallback can hide a spelling mistake.

#### `force_skip_system_biometric_hat_verification`

This is an insecure compatibility switch for a device whose System KeyMint
cannot verify biometric authentication tokens correctly. When `true`, OMK
accepts a token whose structure is valid without asking System KeyMint to
verify its authentication code.

Keep it `false` unless a maintainer is diagnosing a confirmed device-specific
problem. It does not hide root and is not a general fix for fingerprint or
lock-screen failures. A valid save applies to new checks without restarting
keymint.

### `[crypto]`

Every value in this section is private. Each value is exactly 32 bytes written
as 64 hexadecimal characters using `0-9` and `a-f`. OMK generates these values
when it creates a new configuration.

Keep all four generated seed and nonce fields present and stable, and back them
up privately with the OMK data. Changing or removing any of them requires a
keymint restart and can make existing keys or authentication-bound operations
unusable. Values from another device and the redacted placeholders in this
guide are not replacements for the active values.

If `shared_secret_seed` or `shared_secret_nonce` is missing, OMK generates a
new random replacement when it reads the file. That is not a stable active
configuration, so make sure both generated values remain present.

#### `root_kek_seed`

This seed is used to derive key material that protects OMK key blobs. If it
changes, OMK may no longer be able to open keys created with the previous
value. It must be present and must remain unchanged.

#### `kak_seed`

This seed is used for OMK's key-agreement protection. It belongs to the same
device-specific secret set as `root_kek_seed`. It must be present and must
remain unchanged.

#### `shared_secret_seed`

This is the seed half of the shared-secret parameters used for authentication
token verification. Preserve it together with `shared_secret_nonce`; changing
only one side still changes the resulting secret.

#### `shared_secret_nonce`

This is the nonce half of the shared-secret parameters. It is also a full
64-character hexadecimal value, not a short counter or a value to regenerate
manually.

#### `auth_token_hmac_key`

This optional field supplies an explicit authentication-token HMAC key.
When it is absent, OMK derives the required key through
`shared_secret_seed` and `shared_secret_nonce`. Ordinary users should leave the
field absent. If it is explicitly present, it must also contain exactly 64
hexadecimal characters and must be kept private and stable.

### `[trust]`

These fields control values reported through key attestation. They do not
repair hardware, renew a certificate, remove a keybox revocation, or hide root.

#### `os_version`

Use `"auto"` to detect the current Android major each time the keymint process
starts, or use an integer from `0` through `99` to keep a fixed major such as
`12`, `16`, or `17`. Do not write a dotted release, SDK number, or security
patch date here. KeyMint encodes the resolved major with the AOSP `MMmmss`
formula, so fixed `16` is reported as `160000`. Changing this field requires a
keymint restart.

#### `security_patch`

This controls `ro.build.version.security_patch`. It accepts:

- `"auto"`: use the current `ro.build.version.security_patch` value without
  writing it;
- `"latest"`: use the fifth day of the current calendar month when the value
  is resolved; or
- an actual date written as `"YYYY-MM-DD"`, including leading zeroes.

`"auto"` first uses a nonempty runtime property, then the exact key from the
standard `build.prop` locations, and finally `2025-06-05` if neither source is
available. A present runtime value is used as-is rather than replaced by a
`build.prop` value. `"latest"` and an exact date intentionally overwrite an
existing runtime property, but OMK never creates or deletes it. `"auto"` never
writes the property. After an explicit or `"latest"` override, switching back
to `"auto"` in the same boot keeps the current runtime value; reboot to restore
the system-provided value.

#### `os_patchlevel`

This controls the KeyMint OS patch level. `"auto"` follows the effective
`security_patch`; `"latest"` and an exact `"YYYY-MM-DD"` date override it for
KeyMint without writing another property. The final value is parsed with the
AOSP `YYYY-MM-DD` parser and encoded as `YYYYMM`.

#### `vendor_patchlevel`

This controls the KeyMint vendor patch level. `"auto"` first reads the nonempty
runtime `ro.vendor.build.security_patch`, then the exact key from the standard
`build.prop` locations, and finally falls back to the effective
`os_patchlevel`. `"latest"` and an exact `"YYYY-MM-DD"` date are also accepted.
The final value is parsed with the AOSP `YYYY-MM-DD` parser and encoded as
`YYYYMMDD`. A present nonempty source is not replaced by a lower-priority source
merely because parsing later fails. OMK does not write the vendor property.

#### `boot_patchlevel`

This controls the KeyMint boot patch level. `"auto"` first reads
`com.android.build.boot.security_patch` from the active top-level vbmeta image.
If the property is absent, OMK reads the same property from the active boot
image's standalone or AVB-footer embedded vbmeta, then falls back to the boot
header. The legacy header field stores a year and month but no day, so its wire
value ends in `00`; an all-zero field therefore becomes `20000000`, but only
after neither vbmeta location supplied the property. If boot-metadata resolution
fails, OMK uses this fallback order: nonempty runtime
`ro.vendor.boot_security_patch`, the exact key from the standard `build.prop`
locations, then the effective `os_patchlevel`.

`"latest"`, an exact `"YYYY-MM-DD"` date, and a decimal `u32` wire value are
also accepted. The decimal form preserves bootloader wire values such as
`"20000000"` without interpreting them as dates. These explicit modes do not
read boot metadata. Boot patch-level resolution does not read the system TEE or
write the boot property. During hot reload, an unchanged `"auto"` keeps the
value resolved before keymint dropped privileges; switching from an override
back to `"auto"` takes effect after keymint restarts. Explicit dates are encoded
as `YYYYMMDD`.
If the selected value cannot be converted, startup fails; a failed hot update
keeps the previous runtime configuration.

The four patch-level fields are resolved and applied together while keymint is
running when no other `[trust]` field changes in the same save. Existing TAs are
updated in place so in-flight operations and per-boot counters remain intact;
equivalent boot representations do not trigger an update. If the matching log
reports that the live update failed, restart keymint.

#### `vb_key`

This controls the 32-byte verified-boot public-key digest:

- `"auto"` first reads `ro.boot.vbmeta.public_key_digest`, then tries to
  calculate the top-level vbmeta key digest, and uses a random fallback only if
  neither source is available;
- `"random"` generates a new value whenever keymint starts; or
- a 64-character hexadecimal string pins an exact value.

Keep `"auto"` unless you understand the attestation profile being configured.
Changing this field requires a keymint restart. If `"random"` was active and
you change it back to `"auto"`, reboot the whole device so Android restores the
original boot property before `"auto"` reads it.

#### `vb_hash`

This controls the 32-byte verified-boot hash:

- `"auto"` first reads `ro.boot.vbmeta.digest`, then tries the original System
  attestation hash, and uses a random fallback only if neither source is
  available;
- `"random"` generates a new value whenever keymint starts; or
- a 64-character hexadecimal string pins an exact value.

The same restart rule applies as for `vb_key`: restart keymint after a normal
change, and reboot the whole device when returning from `"random"` to
`"auto"`.

#### `verified_boot_state`

`true` reports the verified boot state as verified; `false` reports it as
unverified. This is independent of the `device_locked` switch. Changing it
requires a keymint restart.

#### `device_locked`

`true` reports that the device boot state is locked; `false` reports it as
unlocked. This does not actually lock or unlock the bootloader. Changing it
requires a keymint restart.

### `[device]`

This section supplies device identity strings when an app explicitly requests
attestation IDs. These values are personal data. Use the values already
generated for the device, and restart keymint after changing this section so
the one-shot attestation-ID snapshot is rebuilt.

#### `brand`

The product brand reported in an attestation ID request, normally based on
`ro.product.brand` when a new configuration is created.

#### `device`

The device code name reported in an attestation ID request, normally based on
`ro.product.device`.

#### `product`

The product name reported in an attestation ID request, normally based on
`ro.product.name`.

#### `manufacturer`

The manufacturer name reported in an attestation ID request, normally based on
`ro.product.manufacturer`.

#### `model`

The model name reported in an attestation ID request, normally based on
`ro.product.model`.

#### `serial`

The device serial reported in an attestation ID request, normally based on
`ro.serialno`. Treat it as private information and redact it from reports.

#### `overrideTelephonyProperties`

With the recommended value `false`, OMK tries to fill only empty `imei`,
`imei2`, and `meid` fields from the device's telephony services and property
fallbacks. A configured non-empty value is preserved, and OMK attempts to write
each successfully discovered value back to the active `config.toml`.

With `true`, OMK skips telephony discovery and uses the three configured fields
exactly as written, including empty strings. Use this only when intentionally
pinning the values.

#### `imei`

The primary IMEI. Leave it empty when the device has no IMEI or when automatic
discovery should fill it. Do not invent a value to satisfy an app.

#### `imei2`

The second IMEI. Single-SIM and some dual-SIM devices can legitimately leave it
empty. Its absence does not invalidate `imei` or the non-telephony device
fields.

#### `meid`

The MEID used by devices that provide one. Many devices have no MEID, so an
empty value is valid. Its absence does not invalidate an available IMEI.

### `config.toml` apply summary

| Fields | Required action |
| --- | --- |
| `[main].log_level` | Restart keymint. |
| `[main].force_skip_system_biometric_hat_verification` | Applies to new checks after a valid save. |
| All `[crypto]` fields | Restart keymint; changing values can make keys unusable. |
| `[trust].security_patch`, `os_patchlevel`, `vendor_patchlevel`, `boot_patchlevel` | Hot-apply as a group when no other `[trust]` field changes; otherwise restart keymint. |
| `[trust].os_version` | Restart keymint. |
| Other `[trust]` fields | Restart keymint. |
| All `[device]` fields | Restart keymint to rebuild the cached ID snapshot. |
| `vb_key` or `vb_hash` from `"random"` to `"auto"` | Reboot the whole device. |

## `injector.toml`

### Complete annotated example

```toml
# Configuration format. Keep this at 1.
version = 1

# Exact package names allowed to use OMK; no wildcards are supported.
scoop = [
  "io.github.vvb2060.keyattestation",
  "com.google.android.gsf",
  "com.google.android.gms",
  "com.android.vending",
  "com.eltavine.duckdetector",
]

[main]
# Master switch for request routing. Keep true for normal use.
enabled = true
# Injector log detail: off, error, warn, info, debug, or trace.
log_level = "info"

[filter]
# Enforce scoop and the safety rules below.
enabled = true
# Packages that must never use OMK, even if another shared package is in scoop.
deny_packages = []
# Block core Android and system identities. Keep true.
block_android_package = true
# Reject callers whose package name cannot be found. Keep false.
allow_unknown_package = false

[intercept]
# Route each named KeyStore operation to OMK for an allowed caller.
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

### Top-level fields

#### `version`

This identifies the injector configuration format. Keep the integer value `1`.
It is not an Android version or an OMK release number. Live reload rejects
other values and keeps the last valid runtime configuration.

At injector startup, a missing `version` is treated as `0`, and version `0` is
migrated in place to `1` while preserving the rest of the file. Version `0` is
not migrated during live reload, so restart the injector to migrate such a
file. An unsupported future version is never overwritten.

If a documented injector field is omitted, its default value is used. Unknown
fields in the documented top-level and named sections are rejected, so do not
add names that are not described in this guide.

#### `scoop`

This array contains exact Android package names that may use OMK. It does not
accept app labels, partial names, or wildcards. Empty entries are removed,
surrounding spaces are trimmed, and duplicate entries are reduced to one when
the file is loaded.

Android can assign several packages the same identity. In that case, listing
any one of those packages allows the shared identity, unless a filter rule
rejects one of the packages in the group. Adding or removing a package does not
move or convert keys between System and OMK; an app may lose access to keys it
created through the other route.

There is one narrow granted-key exception. An app outside `scoop`, or one whose
package name cannot be resolved, can still use a key-access grant that OMK
confirms belongs to an OMK key. This keeps a key deliberately shared by another
app usable without giving the receiving app general OMK access. Android-blocked
and deny-listed callers do not receive this exception.

### `[main]`

#### `enabled`

This is the injector's master routing switch. `true` lets the filter and
`[intercept]` settings decide each new request. `false` stops new OMK routing so
normal requests continue to System. Keep it `true` for normal OMK use.

Avoid changing this switch while an app has a key operation open. Save the
change, restart the injector, and reopen the app when deliberately switching
routes.

#### `log_level`

This controls injector messages. Accepted values are `"off"`, `"error"`,
`"warn"`, `"warning"`, `"info"`, `"debug"`, and `"trace"`; `"warning"` is an
alias for `"warn"`. Matching is case-insensitive, but lowercase values are
recommended. `"info"` is the default and records startup, injection, and
routing failures. `"debug"` also records each keystore request decision,
Binder transaction preview, and reply rewrite, and is the normal choice
for a bug report.

A valid file change updates the level without restarting the injector. An
unrecognized string does not make the TOML file invalid; the injector uses
`info` instead.

### `[filter]`

With the filter enabled, OMK evaluates a caller in this order:

1. Reject a core Android or system identity when
   `block_android_package = true`.
2. If its package names cannot be resolved, follow `allow_unknown_package`.
3. Reject the whole identity if any resolved package is in `deny_packages`.
4. Reject it if none of its resolved packages is in `scoop`.
5. Otherwise allow it to use the enabled `[intercept]` routes.

This order matters for packages that share an Android identity: a deny rule
wins over a matching entry in `scoop`.

After this normal filter decision, the narrow OMK-owned grant exception
described under `scoop` can preserve access for an unknown or out-of-scope app.
It does not override the Android-package block or `deny_packages`.

#### `enabled`

`true` enforces `scoop`, the deny list, the Android-package block, and the
unknown-package policy. `false` bypasses all four checks and allows every
caller to reach any operation enabled under `[intercept]`.

Disabling the filter can route Android services and unrelated apps to OMK and
can break unlocking, app storage, or the user interface. Keep it `true`.

#### `deny_packages`

This is an array of exact package names that must not use OMK. It is useful
when a selected package shares its Android identity with another package that
must stay on System. If any package resolved for the identity is denied, the
entire identity is rejected even when another package is listed in `scoop`.

An empty array, `[]`, is the default. The list uses the same quoted,
comma-separated TOML format as `scoop`.

#### `block_android_package`

`true` rejects core Android and system identities before `scoop` is considered.
It also rejects resolved package names equal to `android` or beginning with
`android.`. It does not mean that every ordinary app whose name begins with
`com.android.` is automatically blocked.

Keep this setting `true`. Setting it to `false` only removes this safety check;
the remaining filter rules still apply.

#### `allow_unknown_package`

This controls a caller whose Android package name cannot be resolved. `false`
rejects that caller, which is the safe default. `true` allows an unresolved app
identity without requiring a match in `scoop`; core Android identities are
still rejected when `block_android_package = true`.

This setting is not an "all apps" switch. Keep it `false` unless a maintainer
has confirmed that a supported app cannot be resolved normally.

### `[intercept]`

Each switch controls one Android KeyStore service operation. For a caller
allowed by the filter, `true` routes that operation to OMK and `false` leaves
that operation on System. These switches do not migrate existing keys or make
System-created key references usable by OMK.

The OMK-owned grant exception is separate from ordinary package routing. A
request carrying a confirmed OMK grant may return to OMK even when the
receiving app is outside `scoop`, so the granted key remains usable.

Keep all switches `true` for normal use. Mixing System and OMK operations for
the same app can cause missing-key errors, inconsistent lists, or failed
follow-up operations.

#### `get_security_level`

Controls the request for a TEE or StrongBox KeyStore security-level handle.
Apps use this handle for later operations such as creating, importing, and
using keys.

#### `get_key_entry`

Controls retrieval of an existing key entry, including its metadata and the
handle used for later key operations.

#### `update_subcomponent`

Controls replacement of an existing key entry's certificate or certificate
chain components.

#### `list_entries`

Controls listing key aliases in a requested namespace.

#### `delete_key`

Controls deletion of a named key. The selected backend is authoritative; OMK
does not delete a matching System key as a substitute.

#### `grant`

Controls granting another app access to a key.

#### `ungrant`

Controls removal of a previously granted key permission.

#### `get_number_of_entries`

Controls counting the key entries in a namespace.

#### `list_entries_batched`

Controls paged or batched listing of key entries.

#### `get_supplementary_attestation_info`

Controls retrieval of supplementary information used by supported attestation
requests.

### Per-package subtables

Per-package tables such as `[scoop.com.example.app]` and values such as
`mode = "strict"` are not supported routing options. They may be preserved when
the file is parsed, but they do not change which backend handles a request. Do
not add them; use `scoop`, `[filter]`, and `[intercept]` instead.

### `injector.toml` apply summary

Every valid documented field change is loaded for new requests without a
device reboot. For `scoop`, `[main].enabled`, `[filter]`, or `[intercept]`
changes, restart the injector and reopen the affected app when you need a clean
boundary after a route change. A syntax error, an unknown field, or an
unsupported future `version` leaves the last valid runtime configuration
active; if present at injector startup, it leaves OMK request routing disabled
until the file is corrected.
