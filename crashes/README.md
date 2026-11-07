# Crashes / hangs

No kernel panic report was captured for this research.  The confirmed
failure is the **AGX reconnect hang**:

- 17 cycles of `IOServiceOpen(AGXAcceleratorG14P, type=1)` → `sel8` type
  `0x82` on the F1 surface → `IOServiceClose` succeed.
- The 18th `IOServiceOpen` blocks in the kernel; the device remains
  responsive to AFC, so this is a hang, not a panic.
- Evidence: `../logs/reconnect-hang.log` and
  `../reports/RECONNECT_HANG.md`.
- The device was rebooted to recover; no panic log was produced.

If you capture a panic or crash report for this sequence, add it here
(sanitized: remove UDID, container UUIDs, and local paths).
