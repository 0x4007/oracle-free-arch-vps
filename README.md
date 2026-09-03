# Arch on Oracle Always Free: Agent Setup Kit

This kit teaches an agent team to build and operate one Arch Linux ARM VPS on
Oracle Cloud Infrastructure Ampere A1 while staying inside the verified Always
Free resource envelope and keeping a recoverable backup set.

It uses a conservative two-volume design:

```text
50 GB OCI-supported staging boot volume
  UEFI -> GRUB -> copied Arch kernel and initramfs
                    |
                    v
150 GB block volume
  GPT -> optional EFI partition + ext4 Arch root
```

The two volumes are one machine. Back them up and restore them as a matched
pair.

In this design, the durable safety image is the matched OCI boot-volume and
block-volume backup pair. A single custom image or one volume backup does not
capture the complete machine. An optional sanitized QCOW2 is only an additional
artifact.

## Current allowance baseline

Oracle's official Always Free page stated the following when this kit was
written on 2026-09-03:

- 1,500 Ampere A1 OCPU-hours per month.
- 9,000 A1 GB-hours of memory per month.
- For an Always Free tenancy, this is equivalent to 2 OCPUs and 12 GB RAM used
  continuously.
- 200 GB total boot plus block-volume storage in the tenancy home region.
- Five total boot-volume and block-volume backup objects combined.
- 20 GB Object Storage.
- Idle Always Free compute instances may be reclaimed.

These are policy facts, not constants. The first agent action must be to reopen
Oracle's current Free Tier documentation and the signed-in account page. Stop if
the current limits or account type differ.

## Why this layout

OCI does not publish an official Arch Linux ARM image. Custom image import is
possible, but support, firmware, launch-mode, and AArch64 behavior can change.
The staging design keeps an OCI-supported boot path and places the full Arch
system on a separate volume. It also preserves an Oracle Linux recovery entry.

The cost-maximized steady state is:

| Resource                  | Allocation |
| ------------------------- | ---------: |
| A1 instance               |          1 |
| OCPUs                     |          2 |
| RAM                       |      12 GB |
| Staging boot volume       |      50 GB |
| Arch root volume          |     150 GB |
| Total live volume storage |     200 GB |

The recommended steady state uses two of the five backup slots:

- One accepted staging backup.
- One accepted root backup with the same suffix.
- Two slots kept free so agents can create the next complete pair before
  removing the accepted pair.
- The fifth slot left unused. One spare object cannot hold a complete machine
  recovery point.

During rotation, the old and new pairs briefly use four slots. Delete the old
pair only after the new pair is `AVAILABLE` and live acceptance passes.

## Start here

1. Read `AGENTS.md` and accept its safety rules.
2. Read `01-ARCHITECTURE.md` and choose the verified staging design.
3. Complete `02-VARIABLES-AND-PREFLIGHT.md` with fresh account data.
4. Record every required approval in `templates/APPROVAL-LEDGER.md` before
   executing `03-BUILD-RUNBOOK.md`.
5. Create the paired backups in `04-BACKUP-RECOVERY.md`.
6. Pass every item in `05-ACCEPTANCE.md`.
7. Use `06-TROUBLESHOOTING.md` for evidence-first recovery from failures.
8. Configure the restore and weekly audit tools in
   `07-OPERATIONS-AND-DRILLS.md`.
9. Use `templates/FINAL-REPORT.md` for the evidence handoff.

The accepted end state is one running instance and guest named `arch`. A stopped
instance, a completed build, or available backups alone do not satisfy live
acceptance.

`SOURCES.md` lists the official pages that must be checked again at execution
time. `templates/HANDOFF-GOAL.md` provides a one-sentence prompt for the primary
agent.

## Included automation

- `scripts/oci-restore.ts` inventories, performs an exactly approved OCI
  `SOFTSTOP`, waits for `STOPPED`, plans, restores, and verifies the two-volume
  recovery unit. It never performs an immediate stop, reset, or automatic
  cleanup.
- `scripts/oci-weekly-audit.ts` reports the trailing OCI compute metrics and the
  tenancy-wide Object Storage total, including noncurrent object versions when
  bucket versioning is enabled.
- Both tools read ignored mode-`0600` files under `.private/`. The repository
  contains placeholder examples only.

## Package boundaries

This kit contains no credentials, private keys, passwords, personal domains,
tenancy OCIDs, resource OCIDs, SSH public keys, console connection strings, or
private restore archives. Agents must never ask a friend to paste secrets into
chat. Use the local OCI CLI configuration and existing secret stores.

This is an operational reference, not a promise that every OCI region has A1
capacity. A backup does not reserve future A1 capacity.
