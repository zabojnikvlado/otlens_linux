# OTLens Phase 3.9.7 — Live Flow Capture Restart Fix

## Fixed

After a PCAP analysis, live packet capture could remain stopped. `Stop()` only requested shutdown, but the analysis workflow immediately called `Start()` again. The previous capture goroutine could still own the running flag, causing the restart to fail with `capture already running`. In addition, a successful direct `Start()` call blocked the analysis worker indefinitely.

## Changes

- Added `capture.Engine.StopAndWait(timeout)`.
- PCAP analysis now waits until the previous capture loop has fully stopped.
- Live capture is restarted asynchronously after analysis.
- Analysis completion and telemetry synchronization continue after capture restart.

This restores ongoing flow/edge discovery in the Central topology after a PCAP analysis.
