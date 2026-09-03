# Arch OCI Setup Final Report

## Decision

| Stage | Status | Evidence references |
|---|---|---|
| Implemented | `<COMPLETE_OR_INCOMPLETE>` | `<EVIDENCE_IDS>` |
| Focused checks passed | `<YES_OR_NO>` | `<EVIDENCE_IDS>` |
| Live accepted | `<YES_OR_NO>` | `<EVIDENCE_IDS>` |
| Recovery pair accepted | `<YES_OR_NO>` | `<EVIDENCE_IDS>` |

Overall decision: `<ACCEPTED_OR_BLOCKED>`

Do not mark the setup accepted when any required check is `missing` or
`contradicted`.

## Target

- Execution date: `<UTC_DATE>`
- Machine and guest hostname: `arch`
- Home region: `<REGION_ALIAS>`
- Availability domain: `<AD_ALIAS>`
- Shape: `VM.Standard.A1.Flex`
- Allocation: `<OCPUS>` OCPUs and `<MEMORY_GB>` GB RAM
- Operator: `<ROLE_OR_ALIAS>`

## Account and cost posture

- Signed-in account label: `<OBSERVED_LABEL>`
- Current spend shown: `<REDACTED_AMOUNT_OR_ZERO>`
- Current Oracle policy checked: `<UTC_AND_SOURCE_REF>`
- Continuous-allocation calculation: `<CALCULATION>`
- Live boot plus block storage: `<TOTAL_GB>` GB
- Backup-object count: `<COUNT>` of current verified limit `<LIMIT>`
- Object Storage use: `<TOTAL_GB>` GB of current verified limit `<LIMIT>`
- Paid features, account upgrades, or cross-region copies: `<NONE_OR_DETAILS>`

## Resource state

Use aliases in this shareable report. Keep OCIDs in the private evidence ledger.

| Resource alias | Type | Size or allocation | State | Evidence |
|---|---|---:|---|---|
| `arch` | A1 instance | `<OCPU_AND_RAM>` | `<STATE>` | `<EVIDENCE_ID>` |
| `arch-stage` | Boot volume | `50 GB` | `<STATE>` | `<EVIDENCE_ID>` |
| `arch-root` | Block volume | `150 GB` | `<STATE>` | `<EVIDENCE_ID>` |
| `arch-reserved-ip` | Reserved IPv4 | `<REDACTED>` | `<STATE>` | `<EVIDENCE_ID>` |

## Boot, guest, and storage

- Operating system and architecture: `<OBSERVED_VALUES>`
- Root filesystem and UUID result: `<REDACTED_RESULT>`
- Root partition start-sector result: `<RESULT>`
- EFI mount: `<RESULT>`
- Retired data mount absent: `<RESULT>`
- GRUB Arch default and recovery entry: `<RESULT>`
- Kernel parity and SHA-256: `<REDACTED_DIGEST_OR_ARTIFACT_REF>`
- Initramfs parity and SHA-256: `<REDACTED_DIGEST_OR_ARTIFACT_REF>`
- Final unattended boot: `<RESULT>`

## Network and access

- Reserved IP attachment: `<RESULT>`
- Ingress and egress summary: `<RULE_SUMMARY>`
- Public TCP 9090 absent: `<RESULT>`
- Authoritative DNS: `<RESULT>`
- Public resolver checks: `<RESULT>`
- SSH host-key verification: `<RESULT>`
- Non-root key-based SSH: `<RESULT>`
- Root, password, and keyboard-interactive login disabled: `<RESULT>`

## Services

- Failed system units: `<COUNT>`
- Failed administrative-user units: `<COUNT>`
- Required services and timers: `<RESULT>`
- Metrics run, if enabled: `<RESULT_OR_NOT_APPLICABLE>`
- Repository synchronization: `<RESULT_AND_KNOWN_FAILURES>`
- Unexpected listeners: `<NONE_OR_DETAILS>`

## Paired backups

| Pair role | Shared UTC suffix | Stage name | Root name | Types | Source sizes | States | Evidence |
|---|---|---|---|---|---|---|---|
| Golden | `<SUFFIX>` | `arch-stage-golden-<SUFFIX>` | `arch-root-golden-<SUFFIX>` | `FULL / FULL` | `50 / 150 GB` | `<STATES>` | `<EVIDENCE_IDS>` |
| Latest | `<SUFFIX_OR_NA>` | `<NAME_OR_NA>` | `<NAME_OR_NA>` | `<TYPES>` | `50 / 150 GB` | `<STATES>` | `<EVIDENCE_IDS>` |

If the fifth slot holds a volume-only pre-change backup, state its narrow scope
and state that it is not a complete machine recovery point. Confirm that each
complete pair has matching source aliases, region, suffix, and timestamps.

## Approvals and mutations

| Approval ID | Approved operation | Resource alias | Result | Evidence |
|---|---|---|---|---|
| `<APR_ID>` | `<OPERATION>` | `<ALIAS>` | `<RESULT>` | `<EVIDENCE_ID>` |

## Retained and deleted artifacts

- Retained live resources: `<ALIASES>`
- Retained recovery artifacts: `<ALIASES>`
- Deleted or terminated resources: `<ALIASES_AND_TERMINAL_STATES>`
- Private artifacts excluded from distribution: `<CATEGORIES>`

## Recovery procedure

Restore the matched staging and root backups with the accepted shared suffix.
Launch the staging volume on the current free-safe A1 allocation, attach the
root volume paravirtualized in the same availability domain, verify the root
UUID, assign the reserved IP, and validate the complete checklist after boot.
Reference `04-BACKUP-RECOVERY.md` for the full contract.

## Drift, rough edges, and unmet checks

- `<ITEM_OR_NONE>`

## Redaction statement

This shareable report excludes OCIDs, private and public addresses, personal
domains, usernames, host UUIDs, credentials, keys, console strings, private
paths, raw logs, and restore archives. The private ledgers retain exact targets
and evidence under access control.
