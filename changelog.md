## What's changed

- feat: allow overwrite attest property
- fix: unable to generate attest certificate for some situation
- fix: wrong vendor patch level format (this should fix integrity issue if you can only get device integrity)

## Known Issues:
- The module hash cannot be calculated properly due to an unknown issue in calling apexservice.
- The createOperation function is still sometimes not available for some apps. But it should work for most of time.

## Some future plan
- Implement independent keystore2 hooking (which means no more Tricky Store needed)

## Attestation 
- https://github.com/qwq233/OhMyKeymint/attestations/13396598
