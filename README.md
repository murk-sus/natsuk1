# natsuk1 — iOS 27.2 kernel research archive

This repository is the research archive for the **natsuk1** iOS 27.2
(24B115, iPhone14,7 / T8110) work.  It currently focuses on the IOSurface
F1 compressed-plane 32-bit wrap, the AGX/IOGPU resource paths, and the
AGX user-client reconnect hang.

> Status: **research archive / PoC harnesses**.  No kernel R/W primitive is
> claimed.  The F1 parser wrap is a real kernel bug, but the tested AGX,
> IOSurfaceLock, and IOSurfaceAccelerator paths do not turn it into kernel
> memory access or a DMA length.

## Findings

1. **F1 IOSurface 32-bit wrap** — `IOSurfaceRoot` selector 0 accepts a
   compressed-plane geometry with a 4 GiB + 64 KiB logical region for a
   64 KiB allocation.  The parser check is 32-bit:
   `(dataPerSlice + headerPerSlice) * sliceCount`.
2. **AGX `out+0x20` is not a 4 GiB size** — it is `{flags, status}`.
   The AGX resource length is `out+0x28 = 0x10000`.
3. **Accelerator path is negative** — `IOSurfaceAcceleratorTransferSurface`
   and `TransformSurface` return `0x0`, no panic, no 4 GiB DMA.
4. **AGX sel8 deterministic fields are inert** — on a valid F1 surface,
   `+0x40`, `+0x30`, and `+0x48` accept all tested values and return
   `0x0`; `+0x18/+0x20/+0x28` address mapping returns
   `0xe00002be` / `0xe00002bc`; no kernel mapping.
5. **64-bit `IOSurfacePlaneSize`** — all tested shapes are rejected with
   `0xe00002c2`; huge declared sizes can OOM/Jetsam the app.
6. **AGX reconnect hang (new)** — a loop of
   `IOServiceOpen(AGXAcceleratorG14P, type=1)` → `sel8` type `0x82` on the
   F1 surface → `IOServiceClose` hangs on the 18th open after 17 successful
   cycles.  This is a repeatable DoS/resource-leak candidate; see
   `reports/RECONNECT_HANG.md` and `logs/reconnect-hang.log`.

The SPTM/TTBAT work is in `reports/SPTM_27.2_TTBAT_2026-11-04.md`.

## Layout

```
F1OOB-PoC/      IOSurface F1 wrap -> AGX/Metal same-context GPU OOB harness
XMLFuzz/        IOSurface XML fuzzer + AGX sel8/reconnect harness
FastPoC/        minimal fast AGX reconnect hang (no fuzzing)
builds/         unsigned IPAs for F1OOB, XMLFuzz and FastPoC
reports/        findings, SPTM TTBAT report, reconnect hang writeup
logs/           sanitized evidence logs
crashes/        crash/hang notes (no kernel panic captured)
```

## Fast PoC (no fuzzing)

`FastPoC/` is the short path: it creates the F1 surface and then loops
`IOServiceOpen(AGXAcceleratorG14P, type=1)` → `sel8` type `0x82` on that
surface → `IOServiceClose`.  The first 17 cycles return `0x0`; the 18th
`IOServiceOpen` hangs.  It takes about a second and does not fuzz.  The
unsigned IPA is `builds/AGXReconnect-unsigned.ipa`.

## Build

All projects use Theos:

```sh
cd XMLFuzz && make ipa
cd F1OOB-PoC && make ipa
cd FastPoC && make ipa
```

Sign with your own development certificate and provisioning profile.  The
repository contains only **unsigned** IPAs; it intentionally does not
contain certificates, provisioning profiles, signed IPAs, Apple
kernelcaches, IPSWs, or device identifiers.

## Run

Install a signed IPA with `pymobiledevice3` (or Xcode/devicectl) on a
test device you own.  `AGXReconnect` starts its loop on launch and hangs
at cycle 18; reboot the test device to recover.  `XMLFuzz` starts its
harness on launch and keeps the screen awake.  Logs are written under
`Documents/AGXReconnect/` or `Documents/XMLFuzz/` on the device.

## Responsible disclosure

This is security research against Apple platforms.  Do not use it on
devices you do not own or are not authorized to test.  If you report
these issues to Apple, follow Apple Security Bounty terms: do not
publicly disclose before Apple ships a fix and publishes an advisory.
The maintainers provide this material as-is, without warranty.

## Removed content

The previous public content of this repository (CVE-2026-112611
CoreGraphics PDF shading PoC) was removed at the maintainer's request.
A local archival copy is retained outside this repository; it is not
part of the current tree.
