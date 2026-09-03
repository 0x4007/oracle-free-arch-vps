# Official Sources

Open these pages again before provisioning. Oracle service limits, eligibility,
CLI syntax, and supported-image requirements can change.

## Oracle Cloud Infrastructure

- [Always Free Resources](https://docs.oracle.com/en-us/iaas/Content/FreeTier/freetier_topic-Always_Free_Resources.htm)
  - Use for the current A1 OCPU-hours, memory-hours, home-region storage,
    backup-object count, Object Storage, and idle-instance policy.
  - Last checked for this kit: 2026-09-03.
- [Creating a Boot Volume Backup](https://docs.oracle.com/en-us/iaas/Content/Block/Tasks/create-bv-boot-volume-backup.htm)
  - Use for current boot-volume backup behavior, lifecycle states, and Console
    or CLI workflow.
  - Last checked for this kit: 2026-09-03.
- [Importing Linux-Based Custom Images](https://docs.oracle.com/en-us/iaas/Content/Compute/Tasks/importingcustomimagelinux.htm)
  - Use for current image formats, Linux preparation requirements, networking,
    and Arm launch-mode requirements.
  - Last checked for this kit: 2026-09-03.

## Distribution source

- [Arch Linux ARM](https://archlinuxarm.org/)
  - Select the current generic AArch64 root filesystem from the official
    download path and verify the digest published for that exact artifact.

## Source-use rules

- Prefer signed-in OCI Console state for account type and current spend.
- Prefer OCI API or CLI JSON for exact resource state and identifiers.
- Prefer Oracle documentation for policy and service behavior.
- Prefer the installed CLI help for exact flags.
- Store raw evidence privately. Put only redacted aliases and conclusions in a
  shareable report.
- Record the URL, access date, relevant statement, and any conflict. Stop when
  current official policy conflicts with the resource plan.

The values in this package are a verified 2026-09-03 baseline. They are not a
substitute for a current policy check.
