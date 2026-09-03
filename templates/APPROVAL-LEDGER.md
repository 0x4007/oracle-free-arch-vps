# Approval Ledger

Keep the working copy private because it can contain OCIDs and operational
details. Use aliases in the shareable report.

| Approval ID | UTC time | Exact operation | Exact resource alias and private identifier | Expected outage or risk | Recovery point and rollback | Approver's exact text | Evidence artifact | Status |
|---|---|---|---|---|---|---|---|---|
| `APR-001` | `<UTC>` | `<OPERATION>` | `<ALIAS_AND_PRIVATE_ID>` | `<IMPACT>` | `<RECOVERY_AND_ROLLBACK>` | `<VERBATIM_APPROVAL>` | `<PRIVATE_ARTIFACT_REF>` | `approved / used / expired / rejected` |

## Required separate gates

Create separate records for each applicable operation:

- Create or delete an instance, volume, network, image, or backup.
- Format a disk or change a partition table or filesystem UUID.
- Stop, start, or restart the instance or a managed service.
- Use hard `STOP`, `RESET`, forced detach, or another unclean action.
- Grow a volume or resize a live filesystem.
- Delete or replace any backup member.
- Delete an ephemeral IP, assign a reserved IP, or change DNS.
- Change SSH, firewall, users, credentials, or package versions.
- Accept a paid feature or account upgrade.

Approval is valid only for the exact operation and target stated in the record.
Reconcile current state immediately before use. Ask again if the target, state,
impact, or recovery point changes.
