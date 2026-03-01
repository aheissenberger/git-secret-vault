---
req_id: SEC-009
timestamp: 2026-03-01T04:20:00Z
event: implemented
summary: >
  Added --shred flag to lock command. Performs best-effort zero-overwrite
  before deletion with prominent warnings about filesystem limitations
  (SSDs, btrfs, APFS, ZFS, network mounts).
files:
  - src/cli/lock.rs
---
