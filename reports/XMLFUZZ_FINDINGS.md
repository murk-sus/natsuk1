XMLFUZZ — findings so far
=========================

Target: iPhone14,7 / iOS 27.2 (24B115) / T8110.

1. IOSurface 32-bit wrap (F1)
   - Accepted by IOSurfaceRoot sel0: 4 GiB + 64 KiB logical region for
     a 64 KiB allocation.
   - Impact is limited: AGX resource length is 0x10000, not 4 GiB.
   - `out+0x20` in AGX sel8 is {flags, status}, not a size.
   - Accelerator transfer/transform on the F1 surface returns 0x0,
     no panic, no 4 GiB DMA.
   - 64-bit IOSurfacePlaneSize shapes are rejected with 0xe00002c2;
     huge declared sizes can OOM/Jetsam the app.
   => This bug is a low-impact parser bug, not kernel R/W.

2. AGX / IOGPU sel8 (new_resource), valid F1 surface
   - Baseline all-zero input: kr=0x0, gpuVA=0x1500000000,
     span=0x10000. This matches the F1 PoC.
   - `+0x40` (plane/options): values 0..0xffffffffffffffff all return
     0x0; field is ignored for type 0x82. No OOB.
   - `+0x30` mapping count and `+0x48` wire size: all values return 0x0;
     ignored for type 0x82.
   - `+0x18/+0x20/+0x28/+0x40/+0x48` with user VA or kernel VA
     0xfffffff007004000: 0xe00002be / 0xe00002bc; no kernel mapping.
   => Deterministic fields are inert. No kernel R/W here.

3. Pending tests
   - suballocation sweep: parent resource + suballocation flag (+0x15
     bit 3) + parent IDs {parent, parent±1, 0, 1..4, 0xffffffff},
     types 0/0x80/0x82. Looking for UAF/type confusion.
   - targeted IOGPU fuzzer: one mutated field per iteration on a valid
     F1 surface, reconnect every 256 iterations.
   - The device is locked; the morning script waits for unlock, installs
     XMLTarget-signed.ipa, launches it and pulls the new log.

4. Status
   - No kernel R/W primitive and no confirmed kernel panic yet.
   - The old fuzzer stopped at alloc=0x3fffffff (1 GiB surface); that is
     memory pressure/Jetsam, not a confirmed kernel bug.
   - Logs: Documents/XMLFuzz/ on device; copies in this folder.
   - Next result will be in SUMMARY.txt after the morning script runs.
