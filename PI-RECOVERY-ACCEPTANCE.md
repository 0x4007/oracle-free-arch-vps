# Pi-orchestrated replacement recovery

Audit started 2026-09-07 against bf70caf210fcbd19b27fde91c36361fa71d4d06c.
The owner-controlled repository-root PROJECT-VISION.md remains the authority.
The owner has prohibited all backup payload transfers through the home network.

## Required path

The Pi must select one accepted recovery point, reconcile Oracle resources,
provision the approved replacement through Oracle's API, direct B2 downloads
onto that remote target, reconstruct the machine, and check real boot and
applications. The Pi carries control/status and limited decryption-agent traffic;
it must not carry archive payloads. The source VPS must not supply missing files.

## What the audit actually found

| Stage | Existing implementation | Evidence and gap |
| --- | --- | --- |
| Pi entry point | `deno task restore` invokes `scripts/oci-restore.ts` | Installed on Pi; restores OCI backup volumes, not B2 archives. |
| OCI provisioning | `oci-restore.ts` creates boot/root volumes, launches A1, attaches root and assigns the reserved IP | Source implementation exists; the new recovery path has not been live proved. It refuses unrecorded live volumes/instances. |
| Guest acceptance | `oci-restore.ts` verify action | Returns `METADATA_PROVED`; delegates live guest checks to a checklist. No automated boot/application acceptance from this action. |
| Backup recovery task | `backup-recovery.ts` | Diagnoses old interrupted backup transactions. It is not replacement-machine recovery. |
| B2 retrieval | `backblaze-recovery.ts` | Reconstructs exact indexed encrypted object versions on its execution host. Does not provision or boot. |
| Decryption and archive verification | `backblaze-verifier.ts`, `makeDecryptArchive` in `backblaze-file-backup.ts` | Existing VPS-side verification with a public-only keyring and Pi decryption-agent access. No payload relay is needed. |
| Disk reconstruction | `backblaze-machine-restore.ts` | Previously bound to dated QEMU target/serial constants. Requires two empty serial-bound disks plus already verified archive files on separate scratch. |
| Previous boot evidence | Retained off-source drill procedures | QEMU-specific procedures with operator repairs; not evidence for the requested Pi/Oracle/B2 sequence. |

## Live cost and drill constraint

Read-only Pi inventory observed at 2026-09-07T00:08:51.877Z:
one instance, 2 OCPUs, 12 GB RAM, 200 GB live disks, three backup members,
one group wrapper, and one public IP. No resource was created or changed.

Oracle's [Always Free documentation](https://docs.oracle.com/en-us/iaas/Content/FreeTier/freetier_topic-Always_Free_Resources.htm)
was fetched again on 2026-09-07. It gives 200 GB combined boot/block storage,
five backup members, and 1,500 OCPU-hours/9,000 GB-hours monthly for A1
(equivalent to continuous 2 OCPUs/12 GB). A second complete 50/150 GB pair
would raise live storage to 400 GB while production remains online. It cannot
be provisioned under the current free-only and uninterrupted-production limits.
Actual loss of compute alone does not prove disks are gone or free: inventory
and exact authority must settle remaining resource ownership before replacement.

## First implementation correction

The machine-restorer target now includes explicit boot/root serials, each bound
into the approval and durable journal alongside the target ID and stable paths.
Serial substitution, duplicate serial matches, source UUID presence, mounted
source disks, and wrong capacity remain refused. New journals use schema 2;
old journals must not be silently replayed against a different target. Historical
kit copies and completed drill evidence remain preserved.

This change removes the dated target restriction; it does not establish an OCI
bootstrap, approve any target, or prove real recovery. Tests validate a different
approved target and refuse stale approvals before commands. Live disk writes
have not been performed.

## Remaining implementation and acceptance

- A Pi entry point joining provisioning, remote B2 restore, boot and application
  acceptance with one bound recovery-point/target journal.
- A verified rescue boot and scratch strategy within the final 200 GB footprint;
  adding a third rescue volume would itself exceed that budget after loss.
- Target identity derived from Oracle attachment data and verified on the guest.
- Clone isolation before restored services can start, and automated acceptance.
- A full live drill consistent with available free capacity and exact authority.
  Neither a synthetic test nor an in-place source-assisted check proves this.
- Post-trial API eligibility mapping remains unverified. The separate earlier
  OCI backup drill was owner-deferred; this document does not erase that history.

The prior schedule-approval finding is tracked in GitHub issue #12. It is not a
reason to extend the completed backup review loop or to claim that defect fixed.
