# Evidence Ledger

Keep raw command output and identifiers in a private working directory. The
shareable copy must use resource aliases and redact sensitive values.

| Evidence ID | Requirement | UTC time | Read-only command, API, or UI | Result | Artifact | SHA-256 | Approval ID | Status |
|---|---|---|---|---|---|---|---|---|
| `EVD-001` | `<REQUIREMENT>` | `<UTC>` | `<METHOD>` | `<OBSERVED_RESULT>` | `<PRIVATE_ARTIFACT_REF>` | `<DIGEST_OR_NA>` | `<APR_ID_OR_NA>` | `proved / contradicted / missing / not-applicable` |

## Evidence rules

- Record current evidence from the requested acceptance surface.
- Keep the original timezone and also record UTC.
- Save machine-readable OCI JSON when practical.
- Hash saved artifacts after collection.
- Record command exit status and stderr when relevant.
- Link every mutation result to its exact approval record.
- Do not treat a plan, source file, old report, mock, or local boot test as live
  OCI or guest acceptance.
- Mark absent evidence as `missing`; never infer success.

## Suggested artifact groups

- Signed-in account and billing posture.
- OCI instances, volumes, attachments, backups, IPs, and network rules.
- Direct and DNS SSH checks with host-key fingerprint.
- Guest operating system, CPU, memory, filesystems, UUIDs, and mounts.
- GRUB, kernel/initramfs hashes, and boot-sync status.
- Failed units, required services, timers, metrics, and listeners.
- Authoritative and public DNS results.
- Paired-backup names, sources, sizes, types, states, and timestamps.
- Final post-backup start and live acceptance.
