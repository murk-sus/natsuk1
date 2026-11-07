# Builds

Unsigned IPAs produced by the Theos builds:

- `AGXReconnect-unsigned.ipa` — minimal fast PoC for the AGX reconnect hang.
- `F1OOB-PoC-unsigned.ipa` — F1 IOSurface wrap / AGX/Metal harness.
- `XMLFuzz-unsigned.ipa` — XML/AGX research harness (fuzzing + deterministic tests).

These are **unsigned**.  Sign them with your own development certificate and
provisioning profile before installing on a test device.

Signed IPAs are intentionally not published: they embed the provisioning
profile (device UDID, team ID) and the signing identity.  Keep those private.
